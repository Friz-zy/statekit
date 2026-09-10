package pkg

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// validateZypperDiffArgs mirrors diff(*paths, root=None). The pinned source
// passes **kwargs straight through to the owner lookup and pkg.download;
// only root is represented at this boundary.
func validateZypperDiffArgs(args map[string]any) error {
	for key := range args {
		if key != "paths" && key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperPathList(args); err != nil {
		return err
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperDiff ports zypperpkg.diff. Each path is resolved through the ported
// zypper lowpkg.owner; unmanaged files report "Not managed" or "N/A" exactly
// like os.path.exists would. Owned paths group by package, the owning
// packages flow through pkg.download, and every downloaded RPM is compared
// with the committed rpm_lowpkg.diff pipeline (rpm2cpio/cpio/diff) whose
// empty output becomes "Unchanged".
func zypperDiff(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	paths, err := zypperPathList(args)
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
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
		return nil, errors.New("Zypper diff requires a runtime")
	}
	if rt.Options.Test {
		// A diff downloads packages into the cache. Preserve the
		// process-wide test mode boundary before any owner lookup, cache
		// inspection, or runner use.
		return map[string]any{}, nil
	}
	if !pkgRunnerAvailable(rt.Runner) {
		return nil, errors.New("Zypper diff requires a runner")
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
		ownerArgs := map[string]any{"paths": []string{currentPath}}
		if root != "" {
			ownerArgs["root"] = root
		}
		ownerValue, ownerErr := zypperOwner(ctx, rt, ownerArgs)
		if ownerErr != nil {
			return nil, newYumDiffFailure("owner lookup", ownerErr)
		}
		owner, ownerErr := zypperDiffOwner(ownerValue)
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

	downloadArgs := map[string]any{"packages": append([]string(nil), packageOrder...)}
	if root != "" {
		downloadArgs["root"] = root
	}
	downloaded, err := zypperDownload(ctx, rt, downloadArgs)
	if err != nil {
		return nil, newYumDiffFailure("package download", err)
	}
	rpmPaths, err := zypperDiffDownloadedRPMPaths(rt.FS, downloaded, packageOrder)
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

func zypperDiffOwner(value any) (string, error) {
	owner, ok := value.(string)
	if !ok {
		return "", errors.New("pkg.diff owner result is invalid")
	}
	if owner == "" {
		return "", nil
	}
	// rpm -qf --queryformat %{name} emits exactly one package token. Reject
	// a malformed or multiple result instead of choosing a package
	// arbitrarily, mirroring the committed YUM diff boundary.
	if !validZypperToken(owner, false) || strings.HasPrefix(owner, "-") {
		return "", errors.New("pkg.diff owner result is invalid")
	}
	return owner, nil
}

// zypperDiffDownloadedRPMPaths projects the zypper download result into one
// validated local RPM path per owning package. A partial download cannot
// back a diff; every path is checked for cleanliness, regularity, and size
// before the rpm2cpio pipeline receives it.
func zypperDiffDownloadedRPMPaths(fsys runtime.FileSystem, value any, packageOrder []string) (map[string]string, error) {
	downloaded, ok := value.(map[string]any)
	if !ok || downloaded == nil {
		return nil, errors.New("pkg.diff package download produced no result")
	}
	if _, partial := downloaded["_error"]; partial {
		return nil, errors.New("pkg.diff package download was incomplete")
	}
	paths := make(map[string]string, len(packageOrder))
	for _, packageName := range packageOrder {
		entry, ok := downloaded[packageName].(map[string]any)
		if !ok {
			return nil, errors.New("pkg.diff package download produced no result")
		}
		rpmPath, _ := entry["path"].(string)
		validated, err := zypperDiffDownloadedRPMPath(fsys, rpmPath)
		if err != nil {
			return nil, err
		}
		paths[packageName] = validated
	}
	return paths, nil
}

// zypperDiffDownloadedRPMPath validates one localfile path from the zypper
// download XML: absolute, lexically clean, .rpm-suffixed, and reached
// without any symlinked component. The zypper cache location is chosen by
// zypper itself, so unlike the YUM flow no cache prefix is assumed.
func zypperDiffDownloadedRPMPath(fsys runtime.FileSystem, rpmPath string) (string, error) {
	if rpmPath == "" || !strings.HasPrefix(rpmPath, "/") || path.Clean(rpmPath) != rpmPath ||
		strings.Contains(rpmPath, `\`) || !strings.HasSuffix(rpmPath, ".rpm") ||
		len(rpmPath) > yumDownloadedPathLimit {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	if err := validateZypperPath(rpmPath, false); err != nil {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	components := strings.Split(strings.TrimPrefix(rpmPath, "/"), "/")
	for i, component := range components {
		if component == "" || component == "." || component == ".." {
			return "", errors.New("pkg.diff downloaded package is unsafe")
		}
		candidate := "/" + strings.Join(components[:i+1], "/")
		info, err := fsys.Lstat(candidate)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return "", errors.New("pkg.diff downloaded package is unsafe")
		}
		if i < len(components)-1 && !info.IsDir() {
			return "", errors.New("pkg.diff downloaded package is unsafe")
		}
	}
	info, err := fsys.Lstat(rpmPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > yumDiffRPMFileLimit {
		return "", errors.New("pkg.diff downloaded package is unsafe")
	}
	return rpmPath, nil
}
