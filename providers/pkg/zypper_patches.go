package pkg

import (
	"context"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// validateZypperPatchArgs keeps the provider contract identical to the
// pinned zypperpkg signatures: list_patches(refresh=False, root=None) and
// list_installed_patches(root=None).
func validateZypperPatchArgs(function string, args map[string]any) error {
	allowed := map[string]bool{"root": true}
	if function == "list_patches" {
		allowed["refresh"] = true
	}
	for key := range args {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	if function == "list_patches" {
		if _, err := zypperBool(args, "refresh"); err != nil {
			return err
		}
	}
	return nil
}

// zypperPatches ports list_patches and list_installed_patches. Both resolve
// to _get_patches: the zypper XML search over patch solvables keeps the
// name/summary/status attributes, with installed meaning the literal status
// value "installed". The patterns XML parser implements the exact solvable
// contract, so it is reused with installedOnly selecting the variant.
func zypperPatches(ctx context.Context, rt *runtime.Runtime, function string, args map[string]any) (any, error) {
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}

	if function == "list_patches" && boolDefault(args, "refresh", false) {
		// list_patches calls refresh_db(root) positionally in the pinned
		// source: the supplied root becomes refresh_db's force argument while
		// refresh_db's own root stays unset, matching the committed
		// list_patterns precedent for the same call shape.
		refresh := []string{"refresh"}
		if zypperSearchRefreshForce(args) {
			refresh = append(refresh, "--force")
		}
		if _, err := zypperQueryRun(ctx, rt, "", false, true, refresh); err != nil {
			return nil, err
		}
	}

	if function == "list_installed_patches" {
		return zypperInstalledPatches(ctx, rt, root)
	}
	output, err := zypperQueryRun(ctx, rt, root, true, false, []string{"se", "-t", "patch"})
	if err != nil {
		return nil, err
	}
	result, err := zypperParsePatterns(ctx, output, false)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// validateZypperServicesArgs mirrors services_need_restart(root=None). The
// pinned source accepts **kwargs but consumes only root.
func validateZypperServicesArgs(args map[string]any) error {
	for key := range args {
		if key != "root" {
			return zypperUnsupportedArgument(key)
		}
	}
	_, err := zypperLowpkgRoot(args)
	return err
}

// zypperServicesNeedRestart ports services_need_restart: the nolock text call
// `zypper ps -sss` whose whitespace-split output is the service list. Python's
// split() without arguments is strings.Fields; an empty output keeps the
// empty list instead of a nil slice.
func zypperServicesNeedRestart(ctx context.Context, rt *runtime.Runtime, args map[string]any) (any, error) {
	root, err := zypperLowpkgRoot(args)
	if err != nil {
		return nil, err
	}
	output, err := zypperQueryRun(ctx, rt, root, false, false, []string{"ps", "-sss"})
	if err != nil {
		return nil, err
	}
	services := strings.Fields(output)
	if services == nil {
		// Python's "".split() is an empty list, not None.
		services = []string{}
	}
	return services, nil
}
