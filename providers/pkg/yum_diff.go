package pkg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	yumDiffMaxPaths      = 4096
	yumDiffPathLimit     = 4096
	yumDiffRPMFileLimit  = int64(64 << 20)
	yumDiffArchiveLimit  = runtime.MaxCommandInputBytes
	yumDiffOriginalLimit = runtime.MaxCommandInputBytes
	yumDiffOutputLimit   = runtime.MaxCommandInputBytes
)

// yumDiffFailure retains sentinel causes for callers while keeping command,
// package, and filesystem values out of the public error text.
type yumDiffFailure struct {
	stage string
	cause error
}

func (e *yumDiffFailure) Error() string { return "pkg.diff: " + e.stage + " failed" }
func (e *yumDiffFailure) Unwrap() error { return e.cause }

func newYumDiffFailure(stage string, cause error) error {
	if cause == nil {
		return errors.New("pkg.diff: " + stage + " failed")
	}
	return &yumDiffFailure{stage: stage, cause: cause}
}

// yumDiff mirrors yumpkg.diff and rpm_lowpkg.diff without reconstructing their
// shell pipeline. Package download stays in the existing YUM flow; each helper
// receives argv and bounded bytes through the central Runner.
func yumDiff(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	if manager != "yum" && manager != "dnf" && manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	paths, err := yumDiffPaths(a["paths"])
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return map[string]any{}, nil
	}
	if rt == nil {
		return nil, errors.New("YUM diff requires a runtime")
	}
	if rt.Options.Test {
		// A diff can populate the package cache. Preserve the process-wide test
		// mode boundary before any owner lookup, cache inspection, or runner use.
		return map[string]any{}, nil
	}
	if !RunnerAvailable(rt.Runner) {
		return nil, errors.New("YUM diff requires a runner")
	}
	if rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.diff filesystem"}
	}

	ret := map[string]any{}
	packageOrder := make([]string, 0)
	packagePaths := map[string][]string{}
	for _, currentPath := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ownerValue, ownerErr := yumOwner(ctx, rt, map[string]any{"paths": []string{currentPath}})
		if ownerErr != nil {
			return nil, newYumDiffFailure("owner lookup", ownerErr)
		}
		owner, ownerErr := yumDiffOwner(ownerValue)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if owner == "" {
			if yumDiffPathExists(rt.FS, currentPath) {
				ret[currentPath] = "Not managed"
			} else {
				ret[currentPath] = "N/A"
			}
			continue
		}
		if err := yumDiffSafeCurrentPath(rt.FS, currentPath); err != nil {
			return nil, err
		}
		if _, seen := packagePaths[owner]; !seen {
			packageOrder = append(packageOrder, owner)
		}
		packagePaths[owner] = append(packagePaths[owner], currentPath)
	}
	if len(packageOrder) == 0 {
		return ret, nil
	}
	if err := yumDiffHelpersAvailable(rt.Runner); err != nil {
		return nil, err
	}

	// yumDownload is the provider-safe implementation behind pkg.download. It
	// performs its own yumdownloader availability gate before cache mutation.
	downloaded, err := yumDownload(ctx, rt, manager, map[string]any{"packages": append([]string(nil), packageOrder...)})
	if err != nil {
		return nil, newYumDiffFailure("package download", err)
	}
	rpmPaths, err := yumDiffDownloadedRPMPaths(rt.FS, manager, downloaded, packageOrder)
	if err != nil {
		return nil, err
	}

	for _, packageName := range packageOrder {
		for _, currentPath := range packagePaths[packageName] {
			result, diffErr := yumLowpkgDiff(ctx, rt, rpmPaths[packageName], currentPath)
			if diffErr != nil {
				return nil, diffErr
			}
			ret[currentPath] = result
		}
	}
	return ret, nil
}

func yumDiffPaths(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	paths, ok := value.([]string)
	if !ok {
		return nil, errors.New(`argument "paths" must be a string list`)
	}
	if len(paths) > yumDiffMaxPaths {
		return nil, errors.New("pkg.diff path limit exceeded")
	}
	out := make([]string, len(paths))
	for i, currentPath := range paths {
		if !yumDiffPathToken(currentPath) {
			return nil, errors.New("pkg.diff invalid path")
		}
		out[i] = currentPath
	}
	return out, nil
}

func yumDiffPathToken(currentPath string) bool {
	if currentPath == "" || len(currentPath) > yumDiffPathLimit || !utf8.ValidString(currentPath) ||
		!strings.HasPrefix(currentPath, "/") || path.Clean(currentPath) != currentPath || strings.Contains(currentPath, `\`) {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(currentPath, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	for _, r := range currentPath {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func yumDiffOwner(value any) (string, error) {
	owner, ok := value.(string)
	if !ok {
		return "", errors.New("pkg.diff owner result is invalid")
	}
	if owner == "" {
		return "", nil
	}
	// rpm -qf --queryformat %{name} emits exactly one package token. Reject a
	// malformed or multiple result instead of choosing a package arbitrarily.
	if !yumDownloadPackageToken(owner) {
		return "", errors.New("pkg.diff owner result is invalid")
	}
	return owner, nil
}

// yumDiffPathExists is the no-content equivalent of os.path.exists. Lstat
// records a final symlink without following it; Stat then gives the source
// exists result, including a valid symlink target and excluding a broken one.
func yumDiffPathExists(fsys runtime.FileSystem, currentPath string) bool {
	if fsys == nil {
		return false
	}
	if _, err := fsys.Lstat(currentPath); err != nil {
		return false
	}
	_, err := fsys.Stat(currentPath)
	return err == nil
}

// yumDiffSafeCurrentPath rejects symlinks and non-regular nodes before the
// diff helper receives a live pathname. Each parent is checked through the
// injected filesystem; this prevents source-path traversal through a known
// link before the external helper is invoked.
func yumDiffSafeCurrentPath(fsys runtime.FileSystem, currentPath string) error {
	if fsys == nil {
		return &runtime.UnsupportedError{Kind: "function", Name: "pkg.diff filesystem"}
	}
	components := strings.Split(strings.TrimPrefix(currentPath, "/"), "/")
	candidate := "/"
	for i, component := range components {
		candidate = path.Join(candidate, component)
		info, err := fsys.Lstat(candidate)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return errors.New("pkg.diff current file is unavailable")
		}
		if i < len(components)-1 {
			if !info.IsDir() {
				return errors.New("pkg.diff current file is unavailable")
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return errors.New("pkg.diff current file is unavailable")
		}
	}
	info, err := fsys.Stat(currentPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("pkg.diff current file is unavailable")
	}
	return nil
}

func yumDiffHelpersAvailable(r process.Runner) error {
	available, ok := r.(process.CommandAvailability)
	if !ok {
		return errors.New("'rpm2cpio' command not available")
	}
	for _, helper := range []string{"rpm2cpio", "cpio", "diff"} {
		if !available.CommandAvailable(helper) {
			return fmt.Errorf("'%s' command not available", helper)
		}
	}
	return nil
}

func yumDiffDownloadedRPMPaths(fsys runtime.FileSystem, manager string, value any, packageOrder []string) (map[string]string, error) {
	downloaded, ok := value.(map[string]any)
	if !ok || downloaded == nil {
		return nil, errors.New("pkg.diff package download produced no result")
	}
	if _, partial := downloaded["_error"]; partial {
		return nil, errors.New("pkg.diff package download was incomplete")
	}
	cache := filepath.Join("/var/cache", manager, "packages")
	paths := make(map[string]string, len(packageOrder))
	for _, packageName := range packageOrder {
		rpmPath, err := yumDiffDownloadedRPMPath(fsys, cache, downloaded[packageName])
		if err != nil {
			return nil, err
		}
		paths[packageName] = rpmPath
	}
	return paths, nil
}

func yumDiffDownloadedRPMPath(fsys runtime.FileSystem, cache string, value any) (string, error) {
	rpmPath, ok := value.(string)
	if !ok {
		return "", errors.New("pkg.diff package download produced no result")
	}
	if !strings.HasPrefix(rpmPath, cache+"/") {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	name := strings.TrimPrefix(rpmPath, cache+"/")
	candidate, valid := yumDownloadCandidate(cache, name)
	if !valid || candidate != rpmPath || !strings.HasSuffix(name, ".rpm") {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	info, err := fsys.Lstat(rpmPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > yumDiffRPMFileLimit {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	return rpmPath, nil
}

func yumDiffRun(ctx context.Context, rt *runtime.Runtime, stage string, command process.Command) (process.CommandResult, error) {
	command.Shell = false
	command.MaxStdoutBytes = yumDiffOutputLimit
	command.MaxStderrBytes = yumDiffOutputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return process.CommandResult{}, newYumDiffFailure(stage, result.Err)
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{}, err
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > yumDiffOutputLimit || len(result.Stderr) > yumDiffOutputLimit {
		return process.CommandResult{}, newYumDiffFailure(stage, process.ErrOutputLimit)
	}
	return result, nil
}

func yumDiffInputCommand(argv []string, input []byte, stage string) (process.Command, error) {
	if len(input) > yumDiffArchiveLimit || len(input) > yumDiffOriginalLimit {
		return process.Command{}, newYumDiffFailure(stage, runtime.ErrCommandInputLimit)
	}
	command, err := runtime.CommandWithInputBounded(argv, string(input))
	if err != nil {
		return process.Command{}, newYumDiffFailure(stage, err)
	}
	return command, nil
}

func yumLowpkgDiff(ctx context.Context, rt *runtime.Runtime, rpmPath, currentPath string) (string, error) {
	rpmResult, err := yumDiffRun(ctx, rt, "rpm2cpio", runtime.Command("rpm2cpio", rpmPath))
	if err != nil {
		return "", err
	}
	if rpmResult.ExitCode != 0 {
		return "", newYumDiffFailure("rpm2cpio", nil)
	}

	cpioCommand, err := yumDiffInputCommand([]string{"cpio", "-i", "--quiet", "--to-stdout", "." + currentPath}, rpmResult.Stdout, "cpio")
	if err != nil {
		return "", err
	}
	cpioResult, err := yumDiffRun(ctx, rt, "cpio", cpioCommand)
	if err != nil {
		return "", err
	}
	if cpioResult.ExitCode != 0 {
		return "", newYumDiffFailure("cpio", nil)
	}

	// Recheck immediately before diff so a changed final component cannot be
	// followed by the helper after the earlier pre-download validation.
	if err := yumDiffSafeCurrentPath(rt.FS, currentPath); err != nil {
		return "", err
	}
	diffCommand, err := yumDiffInputCommand([]string{"diff", "-u", "--label", "A " + currentPath, "--from-file=-", "--label", "B " + currentPath, currentPath}, cpioResult.Stdout, "diff")
	if err != nil {
		return "", err
	}
	diffResult, err := yumDiffRun(ctx, rt, "diff", diffCommand)
	if err != nil {
		return "", err
	}
	switch diffResult.ExitCode {
	case 0:
		if len(diffResult.Stdout) == 0 {
			return "Unchanged", nil
		}
		return string(diffResult.Stdout), nil
	case 1:
		if len(diffResult.Stdout) == 0 {
			return "", newYumDiffFailure("diff", nil)
		}
		output := string(diffResult.Stdout)
		if strings.HasPrefix(output, "Binary file") {
			return fmt.Sprintf("File '%s' is binary and its content has been modified.", currentPath), nil
		}
		return output, nil
	default:
		return "", newYumDiffFailure("diff", nil)
	}
}
