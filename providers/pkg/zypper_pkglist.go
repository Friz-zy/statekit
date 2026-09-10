package pkg

import (
	"context"

	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// zypperListPkgsSnapshot is the grouped form of zypperpkg.list_pkgs before
// pkg_resource.format_pkg_list renders it: every package name maps to its
// per-version attribute records in first-seen order, each list sorted by the
// bare version attribute like the source's sorted(..., key=lambda d: d["version"]).
type zypperListPkgsView struct {
	grouped map[string][]yumUpgradePackage
	order   []string
}

// zypperFindTypes ports zypperpkg._find_types: the sorted unique type prefixes
// of targets written as "type:name". The source keeps a prefix even when it is
// an empty string (":foo"); only colon-free targets are excluded.
func zypperFindTypes(pkgs []string) []string {
	var types []string
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		prefix, _, ok := strings.Cut(pkg, ":")
		if !ok {
			continue
		}
		if !seen[prefix] {
			seen[prefix] = true
			types = append(types, prefix)
		}
	}
	sort.Strings(types)
	return types
}

// zypperFindPTFPackages ports zypperpkg._find_ptf_packages: rpm is queried for
// the provides of every requested package and each output line naming a
// "ptf()" capability contributes the package name. rpm prints one line per
// provide, so a package can be appended more than once, exactly like the
// source. A completed nonzero rpm result is not an error; missing packages
// report on stderr and contribute no lines.
func zypperFindPTFPackages(ctx context.Context, rt *runtime.Runtime, root string, pkgs []string) ([]string, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "-q", "--qf", "%{NAME}: [%{PROVIDES} ]\\n")
	argv = append(argv, pkgs...)
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return nil, err
	}
	var ptfs []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, provides, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.Contains(provides, "ptf()") {
			ptfs = append(ptfs, name)
		}
	}
	return ptfs, nil
}

// zypperListPkgsSnapshot builds the installed-package view of
// zypperpkg.list_pkgs. The rpm queryformat is the pinned
// salt.utils.pkg.rpm.QUERYFORMAT with %{REPOID} replaced by "(none)" plus the
// trailing newline, which equals the committed yumInstalledQueryFormat.
// zypperpkg additionally drops every gpg-pubkey package. The includes
// extension follows the pinned source: "product" pulls list_products,
// "pattern"/"patch" pull the installed element lists and then resolve
// version/arch through info_available for the extended name.
func zypperListPkgsSnapshot(ctx context.Context, rt *runtime.Runtime, root, osarch string, includes []string) (zypperListPkgsView, error) {
	argv := []string{"rpm"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, "-qa", "--queryformat", yumInstalledQueryFormat)
	result, err := zypperRPMRun(ctx, rt, argv, nil)
	if err != nil {
		return zypperListPkgsView{}, err
	}
	packages, err := yumUpgradePackages(string(result.Stdout), osarch)
	if err != nil {
		return zypperListPkgsView{}, err
	}
	snapshot := zypperListPkgsView{grouped: make(map[string][]yumUpgradePackage)}
	for _, packageInfo := range packages {
		if strings.HasPrefix(packageInfo.name, "gpg-pubkey") {
			continue
		}
		if _, exists := snapshot.grouped[packageInfo.name]; !exists {
			snapshot.order = append(snapshot.order, packageInfo.name)
		}
		snapshot.grouped[packageInfo.name] = append(snapshot.grouped[packageInfo.name], packageInfo)
	}
	for _, name := range snapshot.order {
		versions := snapshot.grouped[name]
		sort.SliceStable(versions, func(i, j int) bool { return versions[i].version < versions[j].version })
		snapshot.grouped[name] = versions
	}
	for _, include := range includes {
		if err := zypperListPkgsInclude(ctx, rt, &snapshot, root, include); err != nil {
			return zypperListPkgsView{}, err
		}
	}
	return snapshot, nil
}

// zypperListPkgsInclude adds the "type:name" entries one include type
// contributes. Products carry their attributes directly; patterns and patches
// resolve version/arch through info_available exactly like the source, whose
// info dict lookup is reproduced here as an explicit error instead of a
// Python KeyError.
func zypperListPkgsInclude(ctx context.Context, rt *runtime.Runtime, snapshot *zypperListPkgsView, root, include string) error {
	switch include {
	case "product":
		products, err := zypperListProducts(ctx, rt, map[string]any{"all": false, "root": root})
		if err != nil {
			return err
		}
		list, _ := products.([]any)
		for _, item := range list {
			product, _ := item.(map[string]any)
			if product == nil {
				continue
			}
			name, _ := product["name"].(string)
			extended := include + ":" + name
			snapshot.grouped[extended] = []yumUpgradePackage{{
				name:    extended,
				epoch:   product["epoch"],
				version: zypperIncludeField(product, "version"),
				release: product["release"],
				arch:    zypperIncludeField(product, "arch"),
			}}
			snapshot.order = append(snapshot.order, extended)
		}
	case "pattern", "patch":
		var elements map[string]any
		var err error
		if include == "pattern" {
			elements, err = zypperInstalledPatterns(ctx, rt, root)
		} else {
			elements, err = zypperInstalledPatches(ctx, rt, root)
		}
		if err != nil {
			return err
		}
		names := make([]string, 0, len(elements))
		for element := range elements {
			names = append(names, element)
		}
		sort.Strings(names)
		for _, element := range names {
			extended := include + ":" + element
			infoValue, err := zypperInfoAvailable(ctx, rt, map[string]any{
				"names":   []string{extended},
				"refresh": false,
				"root":    root,
			})
			if err != nil {
				return err
			}
			info, _ := infoValue.(map[string]any)
			fields, ok := info[element].(map[string]any)
			if !ok {
				return fmt.Errorf("Zypper include %q: no installed info for %q", include, element)
			}
			version, _ := fields["version"].(string)
			arch, _ := fields["arch"].(string)
			snapshot.grouped[extended] = []yumUpgradePackage{{
				name:    extended,
				version: version,
				arch:    arch,
			}}
			snapshot.order = append(snapshot.order, extended)
		}
	}
	return nil
}

func zypperIncludeField(product map[string]any, key string) string {
	value, _ := product[key].(string)
	return value
}

// zypperInstalledPatches ports _get_patches(installed_only=True): the zypper
// XML search over patch solvables keeps only status="installed" entries. The
// patterns XML parser already implements the exact solvable/attribute
// contract, so it is reused with installedOnly set.
func zypperInstalledPatches(ctx context.Context, rt *runtime.Runtime, root string) (map[string]any, error) {
	output, err := zypperQueryRun(ctx, rt, root, true, false, []string{"se", "-t", "patch"})
	if err != nil {
		return nil, err
	}
	return zypperParsePatterns(ctx, output, true)
}

// zypperListPkgsStrings renders the snapshot through pkg_resource.stringify:
// per package the sorted full versions joined with commas.
func zypperListPkgsStrings(snapshot zypperListPkgsView) map[string]string {
	ret := make(map[string]string, len(snapshot.grouped))
	for name, versions := range snapshot.grouped {
		formatted := make([]string, len(versions))
		for i, packageInfo := range versions {
			formatted[i] = yumUpgradeVersion(packageInfo)
		}
		ret[name] = strings.Join(formatted, ",")
	}
	return ret
}

// zypperFormatPkgListAttrs ports pkg_resource.format_pkg_list with attr
// present. Unknown attributes are dropped rather than rejected, matching the
// source's set intersection; version and arch are always requested. The
// pkg.parse_arch key rename keeps the source's pkgname-or-name semantics.
func zypperFormatPkgListAttrs(snapshot zypperListPkgsView, attributes []string, all bool) map[string]any {
	requested := map[string]bool{"version": true, "arch": true}
	if all {
		for _, attribute := range []string{"epoch", "version", "release", "arch", "install_date", "install_date_time_t"} {
			requested[attribute] = true
		}
	} else {
		for _, attribute := range attributes {
			requested[attribute] = true
		}
	}
	ret := map[string]any{}
	for _, name := range snapshot.order {
		parsed := zypperParseArch(name)
		parsedName, _ := parsed["name"].(string)
		pkgname := ""
		entries := make([]any, 0, len(snapshot.grouped[name]))
		for _, packageInfo := range snapshot.grouped[name] {
			filtered := yumUpgradePackageAttributes(packageInfo, requested)
			entries = append(entries, filtered)
			if parsedName != "" && filtered["arch"] == parsed["arch"] {
				pkgname = parsedName
			}
		}
		key := name
		if pkgname != "" {
			key = pkgname
		}
		prior, _ := ret[key].([]any)
		ret[key] = append(prior, entries...)
	}
	return ret
}

// zypperUpgradeSuccessExitCodes is _Zypper.SUCCESS_EXIT_CODES.
var zypperUpgradeSuccessExitCodes = map[int]bool{0: true, 100: true, 101: true, 102: true, 103: true}

// zypperUpgradeError preserves zypperpkg.upgrade's completed-call details.
// Runner failures, cancellation, and clipped streams are returned directly
// and never reach the package comparison. The source also includes the call's
// pid; the bounded StateKit Runner does not expose process ids, so the ported
// result carries retcode, stdout, and stderr only.
type zypperUpgradeError struct{ info map[string]any }

func (e *zypperUpgradeError) Error() string { return "Problem encountered upgrading packages" }

func (e *zypperUpgradeError) Info() map[string]any { return e.info }

// zypperUpgradeRun is the bounded noraise mutation boundary shared by
// pkg.upgrade and pkg.purge batches: plain --non-interactive --no-refresh
// zypper calls (never --xmlout, never ZYPP_READONLY_HACK) with the optional
// --root. A completed result is returned whatever its exit code is; only
// runner failures, cancellation, and clipped streams are errors. Exit code 7
// (zypper lock) fails promptly instead of reproducing Salt's unbounded lock
// retry loop, matching the committed zypper runner boundary. StateKit has no
// systemd-run scope isolation; the Runner executes zypper directly.
func zypperUpgradeRun(ctx context.Context, rt *runtime.Runtime, root string, args []string) (process.CommandResult, error) {
	argv := []string{"zypper", "--non-interactive", "--no-refresh"}
	if root != "" {
		argv = append(argv, "--root", root)
	}
	argv = append(argv, args...)
	result, err := zypperRPMRun(ctx, rt, argv, []string{"LC_ALL=C"})
	if err != nil {
		return process.CommandResult{}, err
	}
	if result.ExitCode == 7 {
		return process.CommandResult{}, &zypperExitCodeError{exitCode: result.ExitCode}
	}
	return result, nil
}

// zypperPurgeCall mirrors the non-noraise __zypper__.call used by the remove
// batches: a completed exit outside SUCCESS ∪ WARNING raises the ported
// zypper exit-code error. The error message deliberately does not embed raw
// command output, matching the committed zypper error boundary; Salt's
// CommandExecutionError text ("Zypper command failure: ...") is therefore
// represented by the typed exit-code error.
func zypperPurgeCall(ctx context.Context, rt *runtime.Runtime, root string, args []string) error {
	result, err := zypperUpgradeRun(ctx, rt, root, args)
	if err != nil {
		return err
	}
	switch result.ExitCode {
	case 0, 6, 100, 101, 102, 103, 106, 107:
		return nil
	}
	return &zypperExitCodeError{exitCode: result.ExitCode}
}
