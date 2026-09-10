package pkg

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// validateZypperListDownloadedArgs mirrors list_downloaded(root=None). The
// pinned source accepts **kwargs but consumes only root.
func validateZypperListDownloadedArgs(args map[string]any) error {
	for key := range args {
		if key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperListDownloaded ports zypperpkg.list_downloaded. The cache is rooted
// at /var/cache/zypp/packages (note the "zypp" spelling, unlike the YUM
// provider's manager-named cache) and is walked recursively through the
// bounded Runtime filesystem. Every *.rpm is described through the ported
// lowpkg.bin_pkg_info rpm query; ctime, size, and the UTC isoformat timestamp
// complete the source's nested name -> version mapping.
func zypperListDownloaded(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	if rt == nil || rt.FS == nil {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded filesystem"}
	}
	if rt.Runner == nil {
		return nil, errors.New("pkg.list_downloaded runner is unavailable")
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

	// CACHE_DIR is /var/cache/zypp/packages; a root is prepended through
	// os.path.join(root, os.path.relpath(CACHE_DIR, os.path.sep)).
	base := "/var/cache/zypp/packages"
	if root != "" {
		base = path.Join(root, "var/cache/zypp/packages")
	}

	ret := map[string]any{}
	queue := []string{base}
	seen := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen >= maxDownloadedEntries {
			return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
		}
		dir := queue[0]
		queue = queue[1:]
		entries, err := runtime.ReadDirBounded(rt.FS, dir, maxDownloadedEntries-seen)
		if err != nil {
			if errors.Is(err, runtime.ErrDirReadLimit) {
				return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
			}
			if errors.Is(err, runtime.ErrBoundedDirUnsupported) {
				return nil, err
			}
			// os.walk(..., onerror=None) abandons unreadable directories.
			continue
		}
		seen += len(entries)
		if seen > maxDownloadedEntries {
			return nil, errors.New("pkg.list_downloaded traversal limit exceeded")
		}
		for _, entry := range entries {
			name := entry.Name()
			candidate := path.Join(dir, name)
			if len(candidate) > yumDownloadedPathLimit {
				return nil, errors.New("pkg.list_downloaded path limit exceeded")
			}
			if entry.IsDir() {
				queue = append(queue, candidate)
				continue
			}
			// Reject every known nonregular final candidate before any
			// operation that could follow it.
			if entry.Type()&fs.ModeType != 0 {
				continue
			}
			if !strings.HasSuffix(name, ".rpm") {
				continue
			}
			// Lstat is used for validation and metadata: the package-info
			// command accepts only the path, so there is no descriptor-
			// relative way to close the check-to-query window. Never
			// downgrade to Stat here.
			info, err := rt.FS.Lstat(candidate)
			if err != nil {
				// os.walk(..., onerror=None) skips entries it cannot inspect.
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				continue
			}
			pkgName, pkgVersion, ok, err := zypperDownloadedPkgInfo(ctx, rt, candidate)
			if err != nil {
				return nil, err
			}
			if !ok {
				// bin_pkg_info returns None for malformed headers; the
				// pinned zypperpkg source then fails on the None lookup, so
				// the port reports the failure instead of skipping it.
				return nil, errors.New("Zypper list_downloaded: invalid package metadata")
			}
			ts, ok := fileCTime(info)
			if !ok {
				return nil, &runtime.UnsupportedError{Kind: "function", Name: "pkg.list_downloaded ctime"}
			}
			pkgTimestamp := ts.Unix()
			meta := map[string]any{
				"path": candidate, "size": info.Size(),
				"creation_date_time_t": pkgTimestamp,
				// datetime.datetime.utcfromtimestamp(...).isoformat() is a
				// timezone-naive UTC second-precision timestamp.
				"creation_date_time": time.Unix(pkgTimestamp, 0).UTC().Format("2006-01-02T15:04:05"),
			}
			versions, _ := ret[pkgName].(map[string]any)
			if versions == nil {
				versions = map[string]any{}
				ret[pkgName] = versions
			}
			versions[pkgVersion] = meta // source walk order gives last-wins duplicates.
		}
	}
	return ret, nil
}

// zypperDownloadedPkgInfo is the lowpkg.bin_pkg_info projection used by
// list_downloaded: the pinned QUERYFORMAT with REPOID replaced by "none",
// parsed with the shared resolve_name/EVR semantics.
func zypperDownloadedPkgInfo(ctx context.Context, rt *runtime.Runtime, candidate string) (string, string, bool, error) {
	argv := []string{"rpm", "-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}", candidate}
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return "", "", false, err
	}
	fields := strings.Split(strings.TrimSuffix(string(result.Stdout), "\n"), "_|-")
	osarch := ""
	if rt.Facts != nil {
		osarch = rt.Facts.CPU().Arch
	}
	pkgInfo, valid := yumDownloadedPackage(fields, osarch)
	if !valid {
		return "", "", false, nil
	}
	return pkgInfo.name, pkgInfo.version, true, nil
}
