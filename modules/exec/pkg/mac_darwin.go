//go:build darwin

package pkg

// Darwin virtual pkg implementation for Homebrew and MacPorts. The existing
// pkg.Register selects this file on Darwin, keeping the Linux provider
// functions out of the virtual registry while exposing the Salt `pkg.*`
// names shared by mac_brew_pkg and mac_portspkg.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const homebrewTrustTypeList = "tap, formula, cask, command"

func validHomebrewTrustType(value string) bool {
	switch value {
	case "tap", "formula", "cask", "command":
		return true
	default:
		return false
	}
}

func registerMac(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		macHomebrewPrefixFunc{}, macListPkgsFunc{}, macVersionFunc{}, macLatestVersionFunc{},
		macRemoveFunc{}, macRefreshDBFunc{}, macInstallFunc{}, macListUpgradesFunc{},
		macUpgradeAvailableFunc{}, macUpgradeFunc{}, macInfoInstalledFunc{}, macHoldFunc{},
		macUnholdFunc{}, macListTrustedFunc{}, macTrustFunc{}, macUntrustFunc{},
		macIsTrustedFunc{}, macAvailableVersionFunc{}, macPinFunc{}, macUnpinFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func macManager(rt *runtime.Runtime) string {
	if rt != nil && rt.Facts != nil {
		manager := rt.Facts.PackageManager()
		if manager == "brew" || manager == "port" {
			return manager
		}
	}
	return "brew"
}

func macCommand(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}

func commandResultMap(result process.CommandResult) map[string]any {
	code := result.ExitCode
	if result.Err != nil && code == 0 {
		code = -1
	}
	return map[string]any{
		"retcode": code,
		"stdout":  string(result.Stdout),
		"stderr":  string(result.Stderr),
	}
}

func homebrewPrefix(rt *runtime.Runtime) string {
	if prefix := strings.TrimSpace(os.Getenv("HOMEBREW_PREFIX")); prefix != "" {
		return prefix
	}
	result := macCommand(context.Background(), rt, "brew", "--prefix")
	if result.Err != nil || result.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(string(result.Stdout))
}

func brewPath(rt *runtime.Runtime) string {
	if prefix := homebrewPrefix(rt); prefix != "" {
		return prefix + "/bin/brew"
	}
	return "brew"
}

func brewRun(ctx context.Context, rt *runtime.Runtime, failhard bool, args ...string) (process.CommandResult, error) {
	argv := append([]string{brewPath(rt)}, args...)
	result := macCommand(ctx, rt, argv...)
	if result.Err != nil && result.ExitCode == -1 {
		return result, result.Err
	}
	if failhard && result.ExitCode != 0 {
		return result, fmt.Errorf("Brew command failed")
	}
	return result, nil
}

func portRun(ctx context.Context, rt *runtime.Runtime, args ...string) (process.CommandResult, error) {
	result := macCommand(ctx, rt, append([]string{"port"}, args...)...)
	if result.Err != nil && result.ExitCode == -1 {
		return result, result.Err
	}
	return result, nil
}

func packageValue(value any) string {
	switch item := value.(type) {
	case string:
		return item
	case []string:
		return strings.Join(item, ", ")
	case []any:
		var values []string
		for _, entry := range item {
			values = append(values, fmt.Sprint(entry))
		}
		return strings.Join(values, ", ")
	default:
		return fmt.Sprint(value)
	}
}

func packageList(ctx context.Context, rt *runtime.Runtime, versionsAsList bool, kwargs map[string]any) (map[string]any, error) {
	if boolOption(kwargs, "removed") || boolOption(kwargs, "purge_desired") {
		return map[string]any{}, nil
	}
	if macManager(rt) == "port" {
		result, err := portRun(ctx, rt, "installed")
		if err != nil {
			return nil, err
		}
		out := map[string]any{}
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] != "(active)" {
				continue
			}
			version := strings.TrimPrefix(fields[1], "@")
			if versionsAsList {
				out[fields[0]] = []string{version}
			} else {
				out[fields[0]] = version
			}
		}
		return out, nil
	}
	result, err := brewRun(ctx, rt, true, "info", "--json=v2", "--installed")
	if err != nil {
		return nil, err
	}
	var payload struct {
		Formulae []struct {
			Name      string   `json:"name"`
			FullName  string   `json:"full_name"`
			Aliases   []string `json:"aliases"`
			Installed []struct {
				Version string `json:"version"`
			} `json:"installed"`
		} `json:"formulae"`
		Casks []struct {
			Token     string  `json:"token"`
			FullToken string  `json:"full_token"`
			Tap       string  `json:"tap"`
			Installed *string `json:"installed"`
		} `json:"casks"`
	}
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, formula := range payload.Formulae {
		var versions []string
		for _, installed := range formula.Installed {
			versions = append(versions, installed.Version)
		}
		if len(versions) == 0 {
			continue
		}
		names := append(append(append([]string{}, formula.Aliases...), formula.Name), formula.FullName)
		for _, name := range names {
			if versionsAsList {
				out[name] = append([]string(nil), versions...)
			} else {
				out[name] = strings.Join(versions, ", ")
			}
		}
	}
	for _, cask := range payload.Casks {
		version := ""
		if cask.Installed != nil {
			version = *cask.Installed
		}
		names := []string{cask.Token, cask.FullToken}
		if cask.Tap == "" {
			cask.Tap = "homebrew/cask"
		}
		names = append(names, cask.Tap+"/"+cask.Token)
		for _, name := range names {
			if name != "" {
				out[name] = version
			}
		}
	}
	return out, nil
}

func boolOption(options map[string]any, key string) bool {
	value, ok := options[key]
	if !ok {
		return false
	}
	switch item := value.(type) {
	case bool:
		return item
	case string:
		return strings.EqualFold(item, "true")
	default:
		return false
	}
}

func packageTargets(name *string, pkgs []string) []string {
	if len(pkgs) > 0 {
		return append([]string(nil), pkgs...)
	}
	if name != nil && *name != "" {
		return []string{*name}
	}
	return nil
}

func comparePackages(old, current map[string]any) map[string]any {
	changes := map[string]any{}
	for name, value := range old {
		if _, ok := current[name]; !ok {
			changes[name] = map[string]any{"old": packageValue(value), "new": ""}
			continue
		}
		if packageValue(value) != packageValue(current[name]) {
			changes[name] = map[string]any{"old": packageValue(value), "new": packageValue(current[name])}
		}
	}
	for name, value := range current {
		if _, ok := old[name]; !ok {
			changes[name] = map[string]any{"old": "", "new": packageValue(value)}
		}
	}
	return changes
}

func refreshMac(ctx context.Context, rt *runtime.Runtime) bool {
	var result process.CommandResult
	if macManager(rt) == "port" {
		result, _ = portRun(ctx, rt, "selfupdate")
	} else {
		result, _ = brewRun(ctx, rt, false, "update")
	}
	return result.Err == nil && result.ExitCode == 0
}

// ---------------------------------------------------------------------------
// homebrew_prefix

type macHomebrewPrefixArgs struct{}
type macHomebrewPrefixFunc struct{}

func (macHomebrewPrefixFunc) Name() string        { return "pkg.homebrew_prefix" }
func (macHomebrewPrefixFunc) Args() any           { return macHomebrewPrefixArgs{} }
func (macHomebrewPrefixFunc) Platforms() []string { return []string{"darwin"} }
func (macHomebrewPrefixFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	if macManager(rt) != "brew" {
		return nil, nil
	}
	prefix := homebrewPrefix(rt)
	if prefix == "" {
		return nil, nil
	}
	return prefix, nil
}

// ---------------------------------------------------------------------------
// list/version/latest

type macListPkgsArgs struct {
	VersionsAsList bool           `statekit:"name=versions_as_list"`
	Kwargs         map[string]any `statekit:"name=kwargs"`
}
type macListPkgsFunc struct{}

func (macListPkgsFunc) Name() string        { return "pkg.list_pkgs" }
func (macListPkgsFunc) Args() any           { return macListPkgsArgs{} }
func (macListPkgsFunc) Platforms() []string { return []string{"darwin"} }
func (macListPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macListPkgsArgs)
	return packageList(ctx, rt, a.VersionsAsList, a.Kwargs)
}

type macVersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type macVersionFunc struct{}

func (macVersionFunc) Name() string        { return "pkg.version" }
func (macVersionFunc) Args() any           { return macVersionArgs{} }
func (macVersionFunc) Platforms() []string { return []string{"darwin"} }
func (macVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macVersionArgs)
	listed, err := packageList(ctx, rt, false, a.Kwargs)
	if err != nil {
		return nil, err
	}
	if len(a.Names) == 1 {
		return packageValue(listed[a.Names[0]]), nil
	}
	out := map[string]string{}
	for _, name := range a.Names {
		out[name] = packageValue(listed[name])
	}
	return out, nil
}

type macLatestVersionArgs struct {
	Names   []string `statekit:"name=names"`
	Options []string `statekit:"name=options"`
	Refresh *bool    `statekit:"name=refresh"`
}
type macLatestVersionFunc struct{}

func (macLatestVersionFunc) Name() string        { return "pkg.latest_version" }
func (macLatestVersionFunc) Args() any           { return macLatestVersionArgs{} }
func (macLatestVersionFunc) Platforms() []string { return []string{"darwin"} }
func (macLatestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macLatestVersionArgs)
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		refreshMac(ctx, rt)
	}
	versions := map[string]string{}
	if macManager(rt) == "port" {
		query := ""
		if len(a.Names) > 0 {
			query = strings.Join(a.Names, " ")
		}
		result, rerr := portRun(ctx, rt, "list", query)
		if rerr != nil {
			return nil, rerr
		}
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				versions[fields[0]] = strings.TrimPrefix(fields[1], "@")
			}
		}
	} else {
		info, ierr := brewInfo(ctx, rt, a.Names, a.Options)
		if ierr != nil {
			return nil, ierr
		}
		for name, raw := range info {
			versions[name] = brewInfoVersion(raw)
		}
	}
	if len(a.Names) == 1 {
		return versions[a.Names[0]], nil
	}
	out := map[string]string{}
	for _, name := range a.Names {
		out[name] = versions[name]
	}
	return out, nil
}

func brewInfo(ctx context.Context, rt *runtime.Runtime, names, options []string) (map[string]any, error) {
	args := []string{"info", "--json=v2"}
	args = append(args, options...)
	args = append(args, names...)
	result, err := brewRun(ctx, rt, true, args...)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Formulae []map[string]any `json:"formulae"`
		Casks    []map[string]any `json:"casks"`
	}
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, item := range payload.Formulae {
		for _, key := range []string{"name", "full_name"} {
			if name, ok := item[key].(string); ok {
				out[name] = item
			}
		}
		if aliases, ok := item["aliases"].([]any); ok {
			for _, alias := range aliases {
				if name, ok := alias.(string); ok {
					out[name] = item
				}
			}
		}
	}
	for _, item := range payload.Casks {
		for _, key := range []string{"token", "full_token"} {
			if name, ok := item[key].(string); ok {
				out[name] = item
			}
		}
	}
	return out, nil
}

func brewInfoVersion(raw any) string {
	item, _ := raw.(map[string]any)
	if versions, ok := item["versions"].(map[string]any); ok {
		stable, _ := versions["stable"].(string)
		if stable == "" {
			stable, _ = versions["devel"].(string)
		}
		if revision, ok := item["revision"].(float64); ok && revision >= 1 {
			stable = fmt.Sprintf("%s_%d", stable, int(revision))
		}
		return stable
	}
	version, _ := item["version"].(string)
	return version
}

// ---------------------------------------------------------------------------
// remove/install/refresh

type macRemoveArgs struct {
	Name    *string  `statekit:"name=name"`
	Pkgs    []string `statekit:"name=pkgs"`
	Options []string `statekit:"name=options"`
}
type macRemoveFunc struct{}

func (macRemoveFunc) Name() string        { return "pkg.remove" }
func (macRemoveFunc) Args() any           { return macRemoveArgs{} }
func (macRemoveFunc) Platforms() []string { return []string{"darwin"} }
func (macRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macRemoveArgs)
	targets := packageTargets(a.Name, a.Pkgs)
	old, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	var installed []string
	for _, target := range targets {
		if _, ok := old[target]; ok {
			installed = append(installed, target)
		}
	}
	if len(installed) == 0 {
		return map[string]any{}, nil
	}
	var result process.CommandResult
	if macManager(rt) == "port" {
		result, err = portRun(ctx, rt, append([]string{"uninstall"}, installed...)...)
	} else {
		argv := append([]string{"uninstall"}, a.Options...)
		result, err = brewRun(ctx, rt, false, append(argv, installed...)...)
	}
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 && len(result.Stderr) > 0 {
		return nil, fmt.Errorf("Problem encountered removing package(s): %s", result.Stderr)
	}
	newPackages, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	return comparePackages(old, newPackages), nil
}

type macRefreshDBArgs struct{}
type macRefreshDBFunc struct{}

func (macRefreshDBFunc) Name() string        { return "pkg.refresh_db" }
func (macRefreshDBFunc) Args() any           { return macRefreshDBArgs{} }
func (macRefreshDBFunc) Platforms() []string { return []string{"darwin"} }
func (macRefreshDBFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return refreshMac(ctx, rt), nil
}

type macInstallArgs struct {
	Name    *string  `statekit:"name=name"`
	Pkgs    []string `statekit:"name=pkgs"`
	Taps    []string `statekit:"name=taps"`
	Options []string `statekit:"name=options"`
	Refresh *bool    `statekit:"name=refresh"`
	Version *string  `statekit:"name=version"`
	Variant *string  `statekit:"name=variant"`
}
type macInstallFunc struct{}

func (macInstallFunc) Name() string        { return "pkg.install" }
func (macInstallFunc) Args() any           { return macInstallArgs{} }
func (macInstallFunc) Platforms() []string { return []string{"darwin"} }
func (macInstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macInstallArgs)
	targets := packageTargets(a.Name, a.Pkgs)
	if len(targets) == 0 {
		return map[string]any{}, nil
	}
	refresh := false
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		refreshMac(ctx, rt)
	}
	old, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	if macManager(rt) == "port" {
		if len(a.Pkgs) == 0 && a.Version != nil && *a.Version != "" {
			targets[0] += "@" + *a.Version
		}
		if len(a.Pkgs) == 0 && a.Variant != nil && *a.Variant != "" {
			targets = append(targets, *a.Variant)
		}
		result, perr := portRun(ctx, rt, append([]string{"install"}, targets...)...)
		if perr != nil {
			return nil, perr
		}
		if result.ExitCode != 0 && len(result.Stderr) > 0 {
			return nil, fmt.Errorf("Problem encountered installing package(s): %s", result.Stderr)
		}
	} else {
		for _, tap := range a.Taps {
			if !macTap(ctx, rt, tap) {
				continue
			}
		}
		argv := append([]string{"install"}, targets...)
		argv = append(argv, a.Options...)
		result, berr := brewRun(ctx, rt, false, argv...)
		if berr != nil {
			return nil, berr
		}
		if result.ExitCode != 0 && len(result.Stderr) > 0 {
			return nil, fmt.Errorf("Problem encountered installing package(s): %s", result.Stderr)
		}
	}
	newPackages, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	return comparePackages(old, newPackages), nil
}

func macTap(ctx context.Context, rt *runtime.Runtime, tap string) bool {
	result, err := brewRun(ctx, rt, false, "tap")
	if err != nil {
		return false
	}
	for _, installed := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(installed) == tap {
			return true
		}
	}
	result, err = brewRun(ctx, rt, false, "tap", tap)
	return err == nil && result.ExitCode == 0
}

// ---------------------------------------------------------------------------
// upgrades/upgrade/info

type macListUpgradesArgs struct {
	Refresh      *bool    `statekit:"name=refresh"`
	IncludeCasks bool     `statekit:"name=include_casks"`
	Options      []string `statekit:"name=options"`
}
type macListUpgradesFunc struct{}

func (macListUpgradesFunc) Name() string        { return "pkg.list_upgrades" }
func (macListUpgradesFunc) Args() any           { return macListUpgradesArgs{} }
func (macListUpgradesFunc) Platforms() []string { return []string{"darwin"} }
func (macListUpgradesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macListUpgradesArgs)
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		refreshMac(ctx, rt)
	}
	if macManager(rt) == "port" {
		result, perr := portRun(ctx, rt, "list", "outdated")
		if perr != nil {
			return nil, perr
		}
		out := map[string]string{}
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				out[fields[0]] = strings.TrimPrefix(fields[1], "@")
			}
		}
		return out, nil
	}
	argv := append([]string{"outdated", "--json=v2"}, a.Options...)
	result, berr := brewRun(ctx, rt, false, argv...)
	if berr != nil {
		return nil, berr
	}
	var payload struct {
		Formulae []struct {
			Name           string `json:"name"`
			CurrentVersion string `json:"current_version"`
		} `json:"formulae"`
		Casks []struct {
			Name           string `json:"name"`
			CurrentVersion string `json:"current_version"`
		} `json:"casks"`
	}
	if err := json.Unmarshal(result.Stdout, &payload); err != nil {
		return nil, fmt.Errorf(`unable to interpret output from "brew outdated": %w`, err)
	}
	out := map[string]string{}
	for _, item := range payload.Formulae {
		out[item.Name] = item.CurrentVersion
	}
	if a.IncludeCasks {
		for _, item := range payload.Casks {
			out[item.Name] = item.CurrentVersion
		}
	}
	return out, nil
}

type macUpgradeAvailableArgs struct {
	Pkg     string `statekit:"required,name=pkg"`
	Refresh *bool  `statekit:"name=refresh"`
}
type macUpgradeAvailableFunc struct{}

func (macUpgradeAvailableFunc) Name() string        { return "pkg.upgrade_available" }
func (macUpgradeAvailableFunc) Args() any           { return macUpgradeAvailableArgs{} }
func (macUpgradeAvailableFunc) Platforms() []string { return []string{"darwin"} }
func (macUpgradeAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macUpgradeAvailableArgs)
	value, err := macListUpgradesFunc{}.Execute(ctx, rt, &macListUpgradesArgs{Refresh: a.Refresh})
	if err != nil {
		return nil, err
	}
	if upgrades, ok := value.(map[string]string); ok {
		_, exists := upgrades[a.Pkg]
		return exists, nil
	}
	return false, nil
}

type macUpgradeArgs struct {
	Refresh *bool `statekit:"name=refresh"`
}
type macUpgradeFunc struct{}

func (macUpgradeFunc) Name() string        { return "pkg.upgrade" }
func (macUpgradeFunc) Args() any           { return macUpgradeArgs{} }
func (macUpgradeFunc) Platforms() []string { return []string{"darwin"} }
func (macUpgradeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macUpgradeArgs)
	old, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		refreshMac(ctx, rt)
	}
	var result process.CommandResult
	if macManager(rt) == "port" {
		result, err = portRun(ctx, rt, "upgrade", "outdated")
	} else {
		result, err = brewRun(ctx, rt, false, "upgrade")
	}
	if err != nil {
		return nil, err
	}
	newPackages, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	changes := comparePackages(old, newPackages)
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("Problem encountered upgrading packages")
	}
	return changes, nil
}

type macInfoInstalledArgs struct {
	Names   []string `statekit:"name=names"`
	Options []string `statekit:"name=options"`
}
type macInfoInstalledFunc struct{}

func (macInfoInstalledFunc) Name() string        { return "pkg.info_installed" }
func (macInfoInstalledFunc) Args() any           { return macInfoInstalledArgs{} }
func (macInfoInstalledFunc) Platforms() []string { return []string{"darwin"} }
func (macInfoInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macInfoInstalledArgs)
	if macManager(rt) != "brew" {
		return map[string]any{}, nil
	}
	return brewInfo(ctx, rt, a.Names, a.Options)
}

// ---------------------------------------------------------------------------
// Homebrew hold/unhold

type macHoldArgs struct {
	Name    *string  `statekit:"name=name"`
	Pkgs    []string `statekit:"name=pkgs"`
	Sources []any    `statekit:"name=sources"`
	Test    bool     `statekit:"name=test"`
}
type macHoldFunc struct{}

type macUnholdFunc struct{}

func (macHoldFunc) Name() string        { return "pkg.hold" }
func (macHoldFunc) Args() any           { return macHoldArgs{} }
func (macHoldFunc) Platforms() []string { return []string{"darwin"} }
func (macHoldFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	return holdImpl(ctx, rt, args.(*macHoldArgs), true)
}
func (macUnholdFunc) Name() string        { return "pkg.unhold" }
func (macUnholdFunc) Args() any           { return macHoldArgs{} }
func (macUnholdFunc) Platforms() []string { return []string{"darwin"} }
func (macUnholdFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	return holdImpl(ctx, rt, args.(*macHoldArgs), false)
}

func holdImpl(ctx context.Context, rt *runtime.Runtime, a *macHoldArgs, hold bool) (map[string]any, error) {
	if macManager(rt) != "brew" {
		return nil, fmt.Errorf("pkg.%s is only supported by Homebrew", map[bool]string{true: "hold", false: "unhold"}[hold])
	}
	targets := packageTargets(a.Name, a.Pkgs)
	if len(targets) == 0 && len(a.Sources) > 0 {
		for _, source := range a.Sources {
			if values := asMap(source); len(values) > 0 {
				for name := range values {
					targets = append(targets, name)
					break
				}
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("One of name, pkgs, or sources must be specified.")
	}
	pinnedResult, err := brewRun(ctx, rt, false, "list", "--pinned")
	if err != nil {
		return nil, err
	}
	pinned := map[string]bool{}
	for _, name := range strings.Split(string(pinnedResult.Stdout), "\n") {
		pinned[strings.TrimSpace(name)] = true
	}
	installed, err := packageList(ctx, rt, false, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, target := range targets {
		entry := map[string]any{"name": target, "changes": map[string]any{}, "result": false, "comment": ""}
		if _, ok := installed[target]; !ok {
			entry["comment"] = fmt.Sprintf("Package %s does not have a state.", target)
		} else if (hold && !pinned[target]) || (!hold && pinned[target]) {
			if a.Test {
				entry["result"] = nil
				if hold {
					entry["comment"] = fmt.Sprintf("Package %s is set to be held.", target)
				} else {
					entry["comment"] = fmt.Sprintf("Package %s is set to be unheld.", target)
				}
			} else {
				verb := "unpin"
				if hold {
					verb = "pin"
				}
				result, rerr := brewRun(ctx, rt, false, verb, target)
				if rerr == nil && result.ExitCode == 0 {
					entry["result"] = true
					if hold {
						entry["changes"] = map[string]any{"old": "install", "new": "hold"}
						entry["comment"] = fmt.Sprintf("Package %s is now being held.", target)
					} else {
						entry["changes"] = map[string]any{"old": "hold", "new": "install"}
						entry["comment"] = fmt.Sprintf("Package %s is no longer being held.", target)
					}
				} else if hold {
					entry["comment"] = fmt.Sprintf("Unable to hold package %s.", target)
				} else {
					entry["comment"] = fmt.Sprintf("Unable to unhold package %s.", target)
				}
			}
		} else {
			entry["result"] = true
			if hold {
				entry["comment"] = fmt.Sprintf("Package %s is already set to be held.", target)
			} else {
				entry["comment"] = fmt.Sprintf("Package %s is already set not to be held.", target)
			}
		}
		out[target] = entry
	}
	return out, nil
}

func asMap(value any) map[string]any {
	if item, ok := value.(map[string]any); ok {
		return item
	}
	if item, ok := value.(map[string]string); ok {
		out := map[string]any{}
		for key, value := range item {
			out[key] = value
		}
		return out
	}
	return nil
}

// ---------------------------------------------------------------------------
// Homebrew trust

type macListTrustedArgs struct {
	Type *string `statekit:"name=type"`
}
type macListTrustedFunc struct{}

type macTrustArgs struct {
	Name string  `statekit:"required,name=name"`
	Type *string `statekit:"name=type"`
}
type macTrustFunc struct{}
type macUntrustFunc struct{}
type macIsTrustedFunc struct{}

func (macListTrustedFunc) Name() string        { return "pkg.list_trusted" }
func (macListTrustedFunc) Args() any           { return macListTrustedArgs{} }
func (macListTrustedFunc) Platforms() []string { return []string{"darwin"} }
func (macListTrustedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	if macManager(rt) != "brew" {
		return nil, fmt.Errorf("pkg.list_trusted is only supported by Homebrew")
	}
	a := args.(*macListTrustedArgs)
	if a.Type != nil && !validHomebrewTrustType(*a.Type) {
		return nil, fmt.Errorf("Invalid type '%s'. Valid values: %s", *a.Type, homebrewTrustTypeList)
	}
	argv := []string{"trust", "--json=v1"}
	if a.Type != nil && *a.Type != "" {
		argv = append(argv, "--"+*a.Type)
	}
	result, berr := brewRun(ctx, rt, false, argv...)
	if berr != nil {
		return nil, berr
	}
	var value any
	if err := json.Unmarshal(result.Stdout, &value); err != nil {
		return nil, fmt.Errorf(`Unable to interpret output from "brew trust": %w`, err)
	}
	return value, nil
}

func (macTrustFunc) Name() string        { return "pkg.trust" }
func (macTrustFunc) Args() any           { return macTrustArgs{} }
func (macTrustFunc) Platforms() []string { return []string{"darwin"} }
func (macTrustFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	return trustImpl(ctx, rt, args.(*macTrustArgs), true)
}
func (macUntrustFunc) Name() string        { return "pkg.untrust" }
func (macUntrustFunc) Args() any           { return macTrustArgs{} }
func (macUntrustFunc) Platforms() []string { return []string{"darwin"} }
func (macUntrustFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	return trustImpl(ctx, rt, args.(*macTrustArgs), false)
}
func (macIsTrustedFunc) Name() string        { return "pkg.is_trusted" }
func (macIsTrustedFunc) Args() any           { return macTrustArgs{} }
func (macIsTrustedFunc) Platforms() []string { return []string{"darwin"} }
func (macIsTrustedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPkg(&res, &err)
	a := args.(*macTrustArgs)
	trusted, err := macListTrustedFunc{}.Execute(ctx, rt, &macListTrustedArgs{Type: a.Type})
	if err != nil {
		return nil, err
	}
	if list, ok := trusted.([]any); ok {
		for _, value := range list {
			if value == a.Name {
				return true, nil
			}
		}
		return false, nil
	}
	if groups, ok := trusted.(map[string]any); ok {
		for _, value := range groups {
			if list, ok := value.([]any); ok {
				for _, item := range list {
					if item == a.Name {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func trustImpl(ctx context.Context, rt *runtime.Runtime, a *macTrustArgs, trust bool) (bool, error) {
	if macManager(rt) != "brew" {
		return false, fmt.Errorf("pkg trust operations are only supported by Homebrew")
	}
	if a.Type != nil && !validHomebrewTrustType(*a.Type) {
		return false, fmt.Errorf("Invalid type '%s'. Valid values: %s", *a.Type, homebrewTrustTypeList)
	}
	verb := "untrust"
	if trust {
		verb = "trust"
	}
	argv := []string{verb}
	if a.Type != nil && *a.Type != "" {
		argv = append(argv, "--"+*a.Type)
	}
	argv = append(argv, a.Name)
	result, err := brewRun(ctx, rt, false, argv...)
	return err == nil && result.ExitCode == 0, nil
}

// ---------------------------------------------------------------------------
// aliases and recovery

type macAvailableVersionFunc struct{}

func (macAvailableVersionFunc) Name() string        { return "pkg.available_version" }
func (macAvailableVersionFunc) Args() any           { return macLatestVersionArgs{} }
func (macAvailableVersionFunc) Platforms() []string { return []string{"darwin"} }
func (macAvailableVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return macLatestVersionFunc{}.Execute(ctx, rt, args)
}

type macPinFunc struct{}

func (macPinFunc) Name() string        { return "pkg.pin" }
func (macPinFunc) Args() any           { return macHoldArgs{} }
func (macPinFunc) Platforms() []string { return []string{"darwin"} }
func (macPinFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return macHoldFunc{}.Execute(ctx, rt, args)
}

type macUnpinFunc struct{}

func (macUnpinFunc) Name() string        { return "pkg.unpin" }
func (macUnpinFunc) Args() any           { return macHoldArgs{} }
func (macUnpinFunc) Platforms() []string { return []string{"darwin"} }
func (macUnpinFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return macUnholdFunc{}.Execute(ctx, rt, args)
}

func recoverMacPkg(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
