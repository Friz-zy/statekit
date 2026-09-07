package pkg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	yumDownloadOutputLimit     = 1 << 20
	yumDownloadMaxEntries      = runtime.MaxBoundedDirEntries
	yumDownloadMaxPackages     = 4096
	yumDownloadMaxPackageBytes = 1024
	yumDownloadMaxArgvBytes    = 64 << 10
	yumDownloadPathLimit       = 4096
	yumDownloadCommandOverhead = 128
)

// yumDownload mirrors yumpkg.download at salt/modules/yumpkg.py:3438-3508.
// The finite target ceiling is deliberate: the pinned source is variadic, but
// this process boundary must not construct an unbounded argv. Raise both
// package and argv limits together only with a compatible bounded Runner.
func yumDownload(ctx context.Context, rt *runtime.Runtime, manager string, a map[string]any) (any, error) {
	if manager != "yum" && manager != "dnf" && manager != "dnf5" {
		return nil, ErrUnsupportedYUM
	}
	if rt == nil {
		return nil, errors.New("YUM download requires a runtime")
	}
	packages, err := yumDownloadPackages(a["packages"])
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rt.Options.Test {
		// Execution functions use an empty result for process-wide test mode;
		// return before cache inspection or any possible filesystem mutation.
		return map[string]any{}, nil
	}
	if !RunnerAvailable(rt.Runner) {
		return nil, errors.New("YUM download requires a runner")
	}
	if !yumDownloadHelperAvailable(rt.Runner) {
		return nil, errors.New("'yumdownloader' command not available")
	}
	if rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.download filesystem"}
	}

	cache := filepath.Join("/var/cache", manager, "packages")
	if err := rt.FS.MkdirAll(cache, 0o755); err != nil {
		return nil, err
	}
	existing, err := runtime.ReadDirBounded(rt.FS, cache, yumDownloadMaxEntries)
	if err != nil {
		return nil, err
	}
	stale, err := yumDownloadRemoveStale(ctx, rt.FS, cache, existing, packages)
	if err != nil {
		return nil, err
	}

	argv := make([]string, 0, len(packages)+3)
	argv = append(argv, "yumdownloader", "-q", "--destdir="+cache)
	argv = append(argv, packages...)
	cmd := runtime.Command(argv...)
	cmd.Shell = false
	cmd.MaxStdoutBytes, cmd.MaxStderrBytes = yumDownloadOutputLimit, yumDownloadOutputLimit
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if res.StdoutTruncated || res.StderrTruncated || len(res.Stdout) > yumDownloadOutputLimit || len(res.Stderr) > yumDownloadOutputLimit {
		return nil, process.ErrOutputLimit
	}
	// cmd.run does not turn a completed nonzero exit into an exception here;
	// scan the cache because yumdownloader may still have produced RPMs.
	return yumDownloadResults(ctx, rt.FS, cache, packages, stale)
}

func yumDownloadHelperAvailable(r process.Runner) bool {
	checker, ok := r.(process.CommandAvailability)
	return ok && checker.CommandAvailable("yumdownloader")
}

func yumDownloadPackages(value any) ([]string, error) {
	if value == nil {
		return nil, errors.New("No packages were specified")
	}
	packages, ok := value.([]string)
	if !ok {
		return nil, errors.New(`argument "packages" must be a string list`)
	}
	if len(packages) == 0 {
		return nil, errors.New("No packages were specified")
	}
	if len(packages) > yumDownloadMaxPackages {
		return nil, errors.New("pkg.download package limit exceeded")
	}

	argvBytes := yumDownloadCommandOverhead
	out := make([]string, len(packages))
	for i, packageName := range packages {
		if !yumDownloadPackageToken(packageName) {
			return nil, errors.New("invalid package token")
		}
		argvBytes += len(packageName)
		if argvBytes > yumDownloadMaxArgvBytes {
			return nil, errors.New("pkg.download command argument limit exceeded")
		}
		out[i] = packageName
	}
	return out, nil
}

func yumDownloadPackageToken(packageName string) bool {
	if packageName == "" || len(packageName) > yumDownloadMaxPackageBytes || !utf8.ValidString(packageName) ||
		strings.TrimSpace(packageName) != packageName || strings.HasPrefix(packageName, "-") ||
		packageName == "." || packageName == ".." || strings.ContainsAny(packageName, `/\\`) {
		return false
	}
	for _, r := range packageName {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func yumDownloadRemoveStale(ctx context.Context, fsys runtime.FileSystem, cache string, entries []fs.DirEntry, packages []string) (map[string]struct{}, error) {
	failed := map[string]struct{}{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rpm") {
			continue
		}
		if _, ok := yumDownloadMatch(name, packages); !ok {
			continue
		}
		candidate, ok := yumDownloadCandidate(cache, name)
		if !ok || !yumDownloadRegular(fsys, entry, candidate) {
			continue
		}
		// The pinned source logs and continues when unlink fails. Keep that
		// behavior without logging package paths from this execution boundary,
		// but never allow an uncleared stale RPM to manufacture a success.
		if err := fsys.Remove(candidate); err != nil {
			failed[candidate] = struct{}{}
		}
	}
	return failed, nil
}

func yumDownloadResults(ctx context.Context, fsys runtime.FileSystem, cache string, packages []string, stale map[string]struct{}) (any, error) {
	entries, err := runtime.ReadDirBounded(fsys, cache, yumDownloadMaxEntries)
	if err != nil {
		return nil, err
	}
	ret := map[string]any{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rpm") {
			continue
		}
		packageName, ok := yumDownloadMatch(name, packages)
		if !ok {
			continue
		}
		candidate, ok := yumDownloadCandidate(cache, name)
		if !ok || !yumDownloadRegular(fsys, entry, candidate) {
			continue
		}
		if _, uncleared := stale[candidate]; uncleared {
			continue
		}
		ret[packageName] = candidate
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("Unable to download any of the following packages: %s", strings.Join(packages, ", "))
	}
	failed := make([]string, 0, len(packages))
	for _, packageName := range packages {
		if _, ok := ret[packageName]; !ok {
			failed = append(failed, packageName)
		}
	}
	if len(failed) > 0 {
		ret["_error"] = "The following package(s) failed to download: " + strings.Join(failed, ", ")
	}
	return ret, nil
}

func yumDownloadMatch(name string, packages []string) (string, bool) {
	for _, packageName := range packages {
		if strings.HasPrefix(name, packageName+"-") {
			return packageName, true
		}
	}
	return "", false
}

func yumDownloadCandidate(cache, name string) (string, bool) {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.TrimSpace(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	candidate := filepath.Join(cache, name)
	return candidate, len(candidate) <= yumDownloadPathLimit
}

func yumDownloadRegular(fsys runtime.FileSystem, entry fs.DirEntry, candidate string) bool {
	if entry.IsDir() || entry.Type()&fs.ModeType != 0 {
		return false
	}
	info, err := fsys.Lstat(candidate)
	return err == nil && info.Mode()&fs.ModeSymlink == 0 && info.Mode().IsRegular()
}
