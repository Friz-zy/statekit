package pkg

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/friz-zy/statekit/internal/runtime"
)

// validateZypperUpgradeMutationArgs rejects unsupported or mistyped
// arguments before any refresh, query, or mutation runs.
func validateZypperUpgradeMutationArgs(function string, args map[string]any) error {
	allowed := map[string]bool{"root": true, "name": true, "pkgs": true}
	if function == "upgrade" {
		for _, key := range []string{"refresh", "dryrun", "dist_upgrade", "fromrepo", "novendorchange", "skip_verify", "no_recommends", "diff_attr"} {
			allowed[key] = true
		}
	}
	for key := range args {
		if !allowed[key] {
			return zypperUnsupportedArgument(key)
		}
	}
	if _, err := zypperLowpkgRoot(args); err != nil {
		return err
	}
	switch args["name"].(type) {
	case nil, string, *string:
	default:
		return errors.New(`argument "name" must be a string`)
	}
	if value, exists := args["pkgs"]; exists && value != nil {
		if _, isList, _ := purgeItems(value); !isList {
			return errors.New(`argument "pkgs" must be a list`)
		}
	}
	if function != "upgrade" {
		return nil
	}
	for _, key := range []string{"refresh", "dryrun", "dist_upgrade", "novendorchange", "skip_verify", "no_recommends"} {
		if _, err := zypperBool(args, key); err != nil {
			return err
		}
	}
	if _, err := zypperUpgradeRepos(args, "fromrepo"); err != nil {
		return err
	}
	_, _, err := zypperUpgradeDiffAttributes(args["diff_attr"])
	return err
}

// zypperUpgrade ports zypperpkg.upgrade at the command boundary. The action
// command is [dist-upgrade|update] + --auto-agree-with-licenses; --no-gpg-checks
// is inserted at index 0; --dry-run, per-repo --from/--repo flags, the
// dist-upgrade-only --no-allow-vendor-change/--no-recommends switches, and
// parse_targets package names are appended in the source's order. The dist
// upgrade dry-run first fires a noraise debug-solver call whose result is
// discarded. The mutation itself is one noraise call; a completed exit code
// outside _Zypper.SUCCESS_EXIT_CODES still produces the old/new comparison
// and then fails with the changes and call result attached.
func zypperUpgrade(ctx context.Context, rt *runtime.Runtime, a map[string]any) (any, error) {
	root, err := zypperLowpkgRoot(a)
	if err != nil {
		return nil, err
	}
	osarch := zypperOSArch(rt)
	name := zypperUpgradeNameArg(a)
	refresh := boolDefault(a, "refresh", true)
	dryrun := boolDefault(a, "dryrun", false)
	distUpgrade := boolDefault(a, "dist_upgrade", false)
	skipVerify := boolDefault(a, "skip_verify", false)
	novendorchange := boolDefault(a, "novendorchange", false)
	noRecommends := boolDefault(a, "no_recommends", false)
	fromrepo, err := zypperUpgradeRepos(a, "fromrepo")
	if err != nil {
		return nil, err
	}
	attributes, allAttributes, err := zypperUpgradeDiffAttributes(a["diff_attr"])
	if err != nil {
		return nil, err
	}
	if rt != nil && rt.Options.Test {
		// Process-wide execution test mode must not refresh or mutate packages.
		return map[string]any{}, nil
	}
	if rt == nil || !pkgRunnerAvailable(rt.Runner) {
		return nil, errors.New("Zypper upgrade requires a runner")
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}

	cmd := []string{"update", "--auto-agree-with-licenses"}
	if distUpgrade {
		cmd[0] = "dist-upgrade"
	}
	if skipVerify {
		// The '--no-gpg-checks' needs to be placed before the Zypper command.
		cmd = append([]string{"--no-gpg-checks"}, cmd...)
	}
	if refresh {
		if err := zypperUpgradeRefreshDB(ctx, rt, zypperRootSupplied(a), root); err != nil {
			return nil, err
		}
	}
	if dryrun {
		cmd = append(cmd, "--dry-run")
	}
	for _, repo := range fromrepo {
		flag := "--repo"
		if distUpgrade {
			flag = "--from"
		}
		cmd = append(cmd, flag, repo)
	}
	if distUpgrade {
		// Grains validation should be moved to Zypper class (upstream TODO):
		// vendor changes are disabled only when osrelease_info[0] > 11.
		if novendorchange && zypperUpgradeVendorChangeSupported(rt) {
			cmd = append(cmd, "--no-allow-vendor-change")
		}
		if noRecommends {
			cmd = append(cmd, "--no-recommends")
		}
		if dryrun {
			// Creates a solver test case for debugging; the result is discarded.
			debug := append(append([]string(nil), cmd...), "--debug-solver")
			if _, err := zypperUpgradeRun(ctx, rt, root, debug); err != nil {
				return nil, err
			}
		}
	} else if zypperPkgsPresent(a, name) {
		targets, err := zypperPurgeTargetsForArch(a, osarch)
		if err != nil {
			return nil, err
		}
		// The mapping values are version pins that zypper's upgrade does not
		// forward: only the parsed keys extend the command.
		for _, target := range targets {
			cmd = append(cmd, target.name)
		}
	}

	oldSnapshot, err := zypperListPkgsSnapshot(ctx, rt, root, osarch, nil)
	if err != nil {
		return nil, err
	}
	result, err := zypperUpgradeRun(ctx, rt, root, cmd)
	if err != nil {
		return nil, err
	}
	newSnapshot, err := zypperListPkgsSnapshot(ctx, rt, root, osarch, nil)
	if err != nil {
		return nil, err
	}

	var changes any
	if len(attributes) == 0 && !allAttributes {
		changes = comparePackages(zypperListPkgsStrings(oldSnapshot), zypperListPkgsStrings(newSnapshot))
	} else {
		changes = yumUpgradeComparePackages(
			zypperFormatPkgListAttrs(oldSnapshot, attributes, allAttributes),
			zypperFormatPkgListAttrs(newSnapshot, attributes, allAttributes),
		)
	}
	if !zypperUpgradeSuccessExitCodes[result.ExitCode] {
		return changes, &zypperUpgradeError{info: map[string]any{
			"changes": changes,
			"result": map[string]any{
				"retcode": result.ExitCode,
				"stdout":  string(result.Stdout),
				"stderr":  string(result.Stderr),
			},
		}}
	}
	if dryrun {
		var ret any = strings.TrimSpace(string(result.Stdout) + "\n" + string(result.Stderr))
		return ret, nil
	}
	return changes, nil
}

func zypperUpgradeNameArg(a map[string]any) string {
	switch typed := a["name"].(type) {
	case string:
		return typed
	case *string:
		if typed != nil {
			return *typed
		}
	}
	return ""
}

// zypperRootSupplied distinguishes an omitted root (None) from an explicitly
// empty one; upgrade's refresh_db(root) call passes root positionally into
// refresh_db's force parameter, so the two differ in argv.
func zypperRootSupplied(a map[string]any) bool {
	switch typed := a["root"].(type) {
	case nil:
		return false
	case *string:
		return typed != nil
	default:
		return true
	}
}

// zypperUpgradeRefreshDB mirrors upgrade's refresh_db(root) call. The root
// value lands in refresh_db's positional force slot while refresh_db's own
// root stays unset, so the refresh never carries --root and --force follows
// root's truthiness (an omitted root keeps the pillar default of true). Exit
// codes outside SUCCESS ∪ WARNING fail the refresh before any mutation.
func zypperUpgradeRefreshDB(ctx context.Context, rt *runtime.Runtime, rootSupplied bool, root string) error {
	refreshArgs := []string{"refresh"}
	force := !rootSupplied || root != ""
	if force {
		refreshArgs = append(refreshArgs, "--force")
	}
	_, err := zypperQueryRun(ctx, rt, "", false, true, refreshArgs)
	return err
}

// zypperUpgradeVendorChangeSupported decides the osrelease_info[0] > 11 gate.
// The Facts API exposes the OS version as a string rather than Salt's
// osrelease_info tuple, so the major release is the leading decimal run of
// that version (15.4 -> 15, 12-SP5 -> 12); an unparsable version is 0 and
// therefore below the gate. Both branches are covered through injected facts.
func zypperUpgradeVendorChangeSupported(rt *runtime.Runtime) bool {
	if rt == nil || rt.Facts == nil {
		return false
	}
	version := rt.Facts.OS().Version
	major := 0
	end := strings.IndexFunc(version, func(r rune) bool { return r < '0' || r > '9' })
	digits := version
	if end >= 0 {
		digits = version[:end]
	}
	for _, r := range digits {
		if r > unicode.MaxASCII || r < '0' || r > '9' {
			return major > 11
		}
		major = major*10 + int(r-'0')
		if major > 1000000 {
			return true
		}
	}
	return major > 11
}

// zypperUpgradeDiffAttributes parses the diff_attr argument the way
// zypperpkg.list_pkgs feeds pkg_resource.format_pkg_list: a bare "all"
// requests every attribute, otherwise a comma string or list names
// attributes. Unknown names are dropped by the source's set intersection, so
// they are accepted here and simply never appear in the rendered diff.
func zypperUpgradeDiffAttributes(raw any) ([]string, bool, error) {
	if raw == nil {
		return nil, false, nil
	}
	var values []string
	switch typed := raw.(type) {
	case string:
		if typed == "" {
			return nil, false, nil
		}
		if typed == "all" {
			return nil, true, nil
		}
		for _, item := range strings.Split(typed, ",") {
			values = append(values, strings.TrimSpace(item))
		}
	case []string:
		values = append(values, typed...)
	case []any:
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false, errors.New(`argument "diff_attr" must be a string or string list`)
			}
			values = append(values, text)
		}
	default:
		return nil, false, errors.New(`argument "diff_attr" must be a string or string list`)
	}
	if len(values) > zypperLowpkgMaxItems {
		return nil, false, zypperUnsupportedArgument("diff_attr")
	}
	for _, value := range values {
		if !validZypperToken(value, true) {
			return nil, false, zypperUnsupportedArgument("diff_attr")
		}
	}
	if len(values) == 0 {
		return nil, false, nil
	}
	return values, false, nil
}
