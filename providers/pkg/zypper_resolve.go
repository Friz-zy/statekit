package pkg

import (
	"context"
	"errors"
	"sort"

	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperResolveTarget struct {
	name    string
	version string
}

func validateZypperResolveArgs(args map[string]any) error {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "pkgs" && key != "refresh" && key != "root" && key != "resolve_capabilities" {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperBool(args, "refresh"); err != nil {
		return err
	}
	if _, err := zypperBool(args, "resolve_capabilities"); err != nil {
		return err
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	_, err := zypperResolveTargets(args)
	return err
}

// zypperResolveTargets converts the pkgs list into targets. Salt accepts
// strings and one-key name→version mappings; multi-key mappings and
// non-string versions are rejected deterministically instead of relying on
// next(iter(pkg)) ambiguity or Python truthiness accidents. A nil or empty
// version keeps the plain-name output path, matching the source's
// if-version check.
func zypperResolveTargets(args map[string]any) ([]zypperResolveTarget, error) {
	value, exists := args["pkgs"]
	if !exists || value == nil {
		return nil, errors.New(`argument "pkgs" is required`)
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New(`argument "pkgs" must be a list`)
	}
	if len(items) > zypperLowpkgMaxItems {
		return nil, zypperUnsupportedArgument("pkgs")
	}
	targets := make([]zypperResolveTarget, 0, len(items))
	for _, item := range items {
		switch typed := item.(type) {
		case string:
			if !validZypperToken(typed, false) {
				return nil, errInvalidZypperPackageName
			}
			targets = append(targets, zypperResolveTarget{name: typed})
		case map[string]any:
			if len(typed) != 1 {
				return nil, errors.New(`argument "pkgs" entries must map exactly one package name to its version`)
			}
			for name, version := range typed {
				if !validZypperToken(name, false) {
					return nil, errInvalidZypperPackageName
				}
				switch typedVersion := version.(type) {
				case nil:
					targets = append(targets, zypperResolveTarget{name: name})
				case string:
					if !validZypperToken(typedVersion, true) {
						return nil, errInvalidZypperPackageVersion
					}
					targets = append(targets, zypperResolveTarget{name: name, version: typedVersion})
				default:
					return nil, errors.New(`argument "pkgs" version values must be strings`)
				}
			}
		default:
			return nil, errors.New(`argument "pkgs" entries must be package names or name-to-version mappings`)
		}
	}
	return targets, nil
}

// zypperResolveCapabilities mirrors zypperpkg.resolve_capabilities. With the
// resolve_capabilities flag unset the package list passes through unchanged;
// when set, each name is proven by an exact search and otherwise renamed to
// the single package that provides it. Ambiguous or failing lookups keep the
// original entry, and version mappings stay attached to the resolved name.
func zypperResolveCapabilities(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	targets, err := zypperResolveTargets(args)
	if err != nil {
		return nil, err
	}
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	resolve := boolDefault(args, "resolve_capabilities", false)

	if boolDefault(args, "refresh", false) {
		// refresh_db(root, **kwargs) with root as a bound named parameter:
		// root travels positionally into refresh_db's force slot only, so
		// the refresh itself carries no --root, like list_products.
		refresh := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refresh = append(refresh, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, "", false, true, refresh); err != nil {
			return nil, err
		}
	}

	ret := make([]any, 0, len(targets))
	for _, target := range targets {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		name := target.name
		if resolve {
			replacement, err := zypperResolveName(ctx, rt, root, name)
			if err != nil {
				return nil, err
			}
			if replacement != "" {
				name = replacement
			}
		}
		if target.version != "" {
			ret = append(ret, map[string]any{name: target.version})
		} else {
			ret = append(ret, name)
		}
	}
	return ret, nil
}

// zypperResolveName ports the per-package lookup. An exact search that finds
// a package proves the name; the CommandExecutionError analog (no results or
// a failed zypper invocation) falls back to an exact provides search whose
// single result renames the target. A second CommandExecutionError keeps the
// original name like the source's debug-logged fallback; runner errors,
// cancellation, bounds, and XML failures propagate.
func zypperResolveName(ctx context.Context, rt *runtime.Runtime, root, name string) (string, error) {
	var noResults *zypperSearchNoResultsError
	var exitCode *zypperExitCodeError
	if _, err := zypperSearch(ctx, rt, zypperResolveSearchArgs(root, name, false)); err != nil {
		if !errors.As(err, &noResults) && !errors.As(err, &exitCode) {
			return "", err
		}
		result, searchErr := zypperSearch(ctx, rt, zypperResolveSearchArgs(root, name, true))
		if searchErr != nil {
			if errors.As(searchErr, &noResults) || errors.As(searchErr, &exitCode) {
				return "", nil
			}
			return "", searchErr
		}
		found, _ := result.(map[string]map[string]string)
		if len(found) != 1 {
			// Zero results cannot occur (search errors first); more than
			// one is the source's ambiguous-match warning path, which also
			// keeps the original name.
			return "", nil
		}
		for key := range found {
			return key, nil
		}
	}
	return "", nil
}

func zypperResolveSearchArgs(root, name string, provides bool) map[string]any {
	searchArgs := map[string]any{"criteria": name, "match": "exact"}
	if provides {
		searchArgs["provides"] = true
	}
	if root != "" {
		searchArgs["root"] = root
	}
	return searchArgs
}
