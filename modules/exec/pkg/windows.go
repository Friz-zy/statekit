//go:build windows

package pkg

// Windows package surface for win_pkg.py. Installed-package inspection uses
// PowerShell's PackageManagement projection; install/remove/version discovery
// dispatches to an available winget/choco/scoop manager. The Salt winrepo
// (master/cp.cache_file/SLS) metadata layer is explicitly bounded because the
// local-only runtime has no fileserver or master peer.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func registerWindows(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		winLatestVersionFunc{}, winUpgradeAvailableFunc{}, winListUpgradesFunc{},
		winListAvailableFunc{}, winListRepoPkgsFunc{}, winVersionFunc{}, winListPkgsFunc{},
		winRefreshDBFunc{}, winGenRepoFunc{}, winInstallFunc{}, winUpgradeFunc{},
		winRemoveFunc{}, winPurgeFunc{}, winGetRepoDataFunc{}, winGetPackageInfoFunc{},
		winNormalizeNameFunc{}, winCompareVersionsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func packageManager(rt *runtime.Runtime) string {
	if rt != nil && rt.Facts != nil {
		manager := rt.Facts.PackageManager()
		if manager == "winget" || manager == "choco" || manager == "scoop" {
			return manager
		}
	}
	return "winget"
}

func packageRun(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}

func packageUTF16(value string) []uint16 {
	out := make([]uint16, 0, len(value))
	for _, r := range value {
		if r <= 0xffff {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	return out
}

func packagePowerShell(script string) process.Command {
	units := packageUTF16(script + "\x00")
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)},
	}
}

func packageJSON(ctx context.Context, rt *runtime.Runtime, script string) (any, error) {
	result := rt.Runner.Run(ctx, packagePowerShell(script))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("PowerShell command failed (exit code %d): %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	if strings.TrimSpace(string(result.Stdout)) == "" || strings.TrimSpace(string(result.Stdout)) == "null" {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(result.Stdout, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func packageRecords(ctx context.Context, rt *runtime.Runtime) ([]map[string]any, error) {
	value, err := packageJSON(ctx, rt, "@(Get-Package | Select-Object Name,Version,ProviderName,Source) | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	var values []any
	switch item := value.(type) {
	case []any:
		values = item
	case map[string]any:
		values = []any{item}
	case nil:
		return []map[string]any{}, nil
	default:
		return nil, fmt.Errorf("unexpected Get-Package response")
	}
	out := make([]map[string]any, 0, len(values))
	for _, item := range values {
		if record, ok := item.(map[string]any); ok {
			out = append(out, record)
		}
	}
	return out, nil
}

func recordString(record map[string]any, names ...string) string {
	for _, name := range names {
		for key, value := range record {
			if strings.EqualFold(key, name) && value != nil {
				return fmt.Sprint(value)
			}
		}
	}
	return ""
}

func listPackages(ctx context.Context, rt *runtime.Runtime, versionsAsList bool, kwargs map[string]any) (map[string]any, error) {
	if boolOptionWin(kwargs, "removed") || boolOptionWin(kwargs, "purge_desired") {
		return map[string]any{}, nil
	}
	records, err := packageRecords(ctx, rt)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, record := range records {
		name := recordString(record, "Name")
		if name == "" {
			continue
		}
		version := recordString(record, "Version")
		if version == "" {
			version = "Not Found"
		}
		if versionsAsList {
			if old, ok := out[name].([]string); ok {
				out[name] = append(old, version)
			} else {
				out[name] = []string{version}
			}
		} else if old, ok := out[name].(string); ok && old != "" {
			out[name] = old + ", " + version
		} else {
			out[name] = version
		}
	}
	return out, nil
}

func boolOptionWin(kwargs map[string]any, key string) bool {
	if kwargs == nil {
		return false
	}
	value, ok := kwargs[key]
	if !ok {
		return false
	}
	if b, ok := value.(bool); ok {
		return b
	}
	return strings.EqualFold(fmt.Sprint(value), "true")
}

func targetNamesWin(name *string, pkgs []any) []string {
	if len(pkgs) > 0 {
		out := make([]string, 0, len(pkgs))
		for _, item := range pkgs {
			switch value := item.(type) {
			case string:
				out = append(out, value)
			case map[string]any:
				if value, ok := value["name"].(string); ok && value != "" {
					out = append(out, value)
					continue
				}
				for key := range value {
					out = append(out, key)
					break
				}
			}
		}
		return out
	}
	if name != nil && *name != "" {
		return strings.Split(*name, ",")
	}
	return nil
}

func comparePackageMapsWin(old, current map[string]any) map[string]any {
	changes := map[string]any{}
	for name, value := range old {
		if _, ok := current[name]; !ok {
			changes[name] = map[string]any{"old": fmt.Sprint(value), "new": ""}
		} else if fmt.Sprint(value) != fmt.Sprint(current[name]) {
			changes[name] = map[string]any{"old": fmt.Sprint(value), "new": fmt.Sprint(current[name])}
		}
	}
	for name, value := range current {
		if _, ok := old[name]; !ok {
			changes[name] = map[string]any{"old": "", "new": fmt.Sprint(value)}
		}
	}
	return changes
}

func packageVersionStringWin(value any) string {
	switch item := value.(type) {
	case []string:
		if len(item) > 0 {
			return item[len(item)-1]
		}
		return ""
	case []any:
		if len(item) > 0 {
			return fmt.Sprint(item[len(item)-1])
		}
		return ""
	default:
		return fmt.Sprint(value)
	}
}

func managerVersion(ctx context.Context, rt *runtime.Runtime, name string) string {
	manager := packageManager(rt)
	var result process.CommandResult
	switch manager {
	case "winget":
		result = packageRun(ctx, rt, "winget", "show", "--id", name, "--accept-source-agreements")
	case "choco":
		result = packageRun(ctx, rt, "choco", "info", name, "--limit-output")
	case "scoop":
		result = packageRun(ctx, rt, "scoop", "info", name)
	}
	if result.Err != nil || result.ExitCode != 0 {
		return ""
	}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "version:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
		fields := strings.Split(line, "|")
		if manager == "choco" && len(fields) >= 3 {
			return strings.TrimSpace(fields[2])
		}
	}
	return ""
}

func managerInstall(ctx context.Context, rt *runtime.Runtime, name string, version string) error {
	manager := packageManager(rt)
	var result process.CommandResult
	switch manager {
	case "winget":
		args := []string{"winget", "install", "--id", name, "--silent", "--accept-package-agreements", "--accept-source-agreements"}
		if version != "" && version != "latest" {
			args = append(args, "--version", version)
		}
		result = packageRun(ctx, rt, args...)
	case "choco":
		args := []string{"choco", "install", name, "-y"}
		if version != "" && version != "latest" {
			args = append(args, "--version", version)
		}
		result = packageRun(ctx, rt, args...)
	case "scoop":
		result = packageRun(ctx, rt, "scoop", "install", name)
	}
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("package install failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

func managerRemove(ctx context.Context, rt *runtime.Runtime, name string) error {
	var result process.CommandResult
	switch packageManager(rt) {
	case "winget":
		result = packageRun(ctx, rt, "winget", "uninstall", "--id", name, "--silent", "--accept-source-agreements")
	case "choco":
		result = packageRun(ctx, rt, "choco", "uninstall", name, "-y")
	case "scoop":
		result = packageRun(ctx, rt, "scoop", "uninstall", name)
	}
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("package removal failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

func refreshManager(ctx context.Context, rt *runtime.Runtime) error {
	var result process.CommandResult
	switch packageManager(rt) {
	case "winget":
		result = packageRun(ctx, rt, "winget", "source", "update")
	case "choco":
		result = packageRun(ctx, rt, "choco", "outdated", "--limit-output")
	case "scoop":
		result = packageRun(ctx, rt, "scoop", "update")
	}
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("package metadata refresh failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

// ---------------------------------------------------------------------------
// versions/list

type winLatestVersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winLatestVersionFunc struct{}

func (winLatestVersionFunc) Name() string        { return "pkg.latest_version" }
func (winLatestVersionFunc) Args() any           { return winLatestVersionArgs{} }
func (winLatestVersionFunc) Platforms() []string { return []string{"windows"} }
func (winLatestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winLatestVersionArgs)
	if len(a.Names) == 0 {
		return "", nil
	}
	refresh := true
	if _, ok := a.Kwargs["refresh"]; ok {
		refresh = boolOptionWin(a.Kwargs, "refresh")
	}
	if refresh {
		_ = refreshManager(ctx, rt)
	}
	installed, e := listPackages(ctx, rt, true, a.Kwargs)
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, name := range a.Names {
		available := managerVersion(ctx, rt, name)
		current := packageVersionStringWin(installed[name])
		if available != "" && compareVersionStrings(current, available) < 0 {
			out[name] = available
		} else {
			out[name] = ""
		}
	}
	if len(a.Names) == 1 {
		return out[a.Names[0]], nil
	}
	return out, nil
}

type winUpgradeAvailableArgs struct {
	Name   string         `statekit:"required"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winUpgradeAvailableFunc struct{}

func (winUpgradeAvailableFunc) Name() string        { return "pkg.upgrade_available" }
func (winUpgradeAvailableFunc) Args() any           { return winUpgradeAvailableArgs{} }
func (winUpgradeAvailableFunc) Platforms() []string { return []string{"windows"} }
func (winUpgradeAvailableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*winUpgradeAvailableArgs)
	v, err := winLatestVersionFunc{}.Execute(ctx, rt, &winLatestVersionArgs{Names: []string{a.Name}, Kwargs: a.Kwargs})
	if err != nil {
		return nil, err
	}
	return v.(string) != "", nil
}

type winListUpgradesArgs struct {
	Refresh *bool          `statekit:"name=refresh"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}
type winListUpgradesFunc struct{}

func (winListUpgradesFunc) Name() string        { return "pkg.list_upgrades" }
func (winListUpgradesFunc) Args() any           { return winListUpgradesArgs{} }
func (winListUpgradesFunc) Platforms() []string { return []string{"windows"} }
func (winListUpgradesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winListUpgradesArgs)
	refresh := true
	if a.Refresh != nil {
		refresh = *a.Refresh
	}
	if refresh {
		_ = refreshManager(ctx, rt)
	}
	out := map[string]string{}
	switch packageManager(rt) {
	case "choco":
		r := packageRun(ctx, rt, "choco", "outdated", "--limit-output")
		if r.Err != nil {
			return nil, r.Err
		}
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			f := strings.Split(line, "|")
			if len(f) >= 3 {
				out[strings.TrimSpace(f[0])] = strings.TrimSpace(f[2])
			}
		}
	case "winget":
		r := packageRun(ctx, rt, "winget", "upgrade", "--accept-source-agreements", "--accept-package-agreements")
		if r.Err != nil {
			return nil, r.Err
		}
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[0] != "Name" {
				out[f[0]] = f[len(f)-1]
			}
		}
	case "scoop":
		r := packageRun(ctx, rt, "scoop", "status")
		if r.Err != nil {
			return nil, r.Err
		}
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				out[f[0]] = f[len(f)-1]
			}
		}
	}
	return out, nil
}

type winListAvailableArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winListAvailableFunc struct{}

func (winListAvailableFunc) Name() string        { return "pkg.list_available" }
func (winListAvailableFunc) Args() any           { return winListAvailableArgs{} }
func (winListAvailableFunc) Platforms() []string { return []string{"windows"} }
func (winListAvailableFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg repository metadata requires the Salt winrepo/fileserver boundary")
}

type winVersionArgs struct {
	Names  []string       `statekit:"name=names"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winVersionFunc struct{}

func (winVersionFunc) Name() string        { return "pkg.version" }
func (winVersionFunc) Args() any           { return winVersionArgs{} }
func (winVersionFunc) Platforms() []string { return []string{"windows"} }
func (winVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winVersionArgs)
	listed, e := listPackages(ctx, rt, false, a.Kwargs)
	if e != nil {
		return nil, e
	}
	if len(a.Names) == 1 {
		return fmt.Sprint(listed[a.Names[0]]), nil
	}
	out := map[string]string{}
	for _, name := range a.Names {
		out[name] = fmt.Sprint(listed[name])
	}
	return out, nil
}

type winListPkgsArgs struct {
	VersionsAsList    bool           `statekit:"name=versions_as_list"`
	IncludeComponents *bool          `statekit:"name=include_components"`
	IncludeUpdates    *bool          `statekit:"name=include_updates"`
	Kwargs            map[string]any `statekit:"name=kwargs"`
}
type winListPkgsFunc struct{}

func (winListPkgsFunc) Name() string        { return "pkg.list_pkgs" }
func (winListPkgsFunc) Args() any           { return winListPkgsArgs{} }
func (winListPkgsFunc) Platforms() []string { return []string{"windows"} }
func (winListPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winListPkgsArgs)
	return listPackages(ctx, rt, a.VersionsAsList, a.Kwargs)
}

// ---------------------------------------------------------------------------
// repository boundary/refresh/no-op

type winRefreshDBArgs struct {
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winRefreshDBFunc struct{}

func (winRefreshDBFunc) Name() string        { return "pkg.refresh_db" }
func (winRefreshDBFunc) Args() any           { return winRefreshDBArgs{} }
func (winRefreshDBFunc) Platforms() []string { return []string{"windows"} }
func (winRefreshDBFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg.refresh_db requires the Salt winrepo/fileserver boundary")
}

type winGenRepoFunc struct{}

func (winGenRepoFunc) Name() string        { return "pkg.genrepo" }
func (winGenRepoFunc) Args() any           { return winRefreshDBArgs{} }
func (winGenRepoFunc) Platforms() []string { return []string{"windows"} }
func (winGenRepoFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg.genrepo requires the Salt winrepo/fileserver boundary")
}

type winListRepoPkgsArgs struct {
	Args    []string       `statekit:"name=args"`
	Saltenv *string        `statekit:"name=saltenv"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}
type winListRepoPkgsFunc struct{}

func (winListRepoPkgsFunc) Name() string        { return "pkg.list_repo_pkgs" }
func (winListRepoPkgsFunc) Args() any           { return winListRepoPkgsArgs{} }
func (winListRepoPkgsFunc) Platforms() []string { return []string{"windows"} }
func (winListRepoPkgsFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg.list_repo_pkgs requires the Salt winrepo/fileserver boundary")
}

type winGetRepoDataArgs struct {
	Saltenv *string `statekit:"name=saltenv"`
}
type winGetRepoDataFunc struct{}

func (winGetRepoDataFunc) Name() string        { return "pkg.get_repo_data" }
func (winGetRepoDataFunc) Args() any           { return winGetRepoDataArgs{} }
func (winGetRepoDataFunc) Platforms() []string { return []string{"windows"} }
func (winGetRepoDataFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg.get_repo_data requires the Salt winrepo/fileserver boundary")
}

type winGetPackageInfoArgs struct {
	Name    string  `statekit:"required"`
	Saltenv *string `statekit:"name=saltenv"`
}
type winGetPackageInfoFunc struct{}

func (winGetPackageInfoFunc) Name() string        { return "pkg.get_package_info" }
func (winGetPackageInfoFunc) Args() any           { return winGetPackageInfoArgs{} }
func (winGetPackageInfoFunc) Platforms() []string { return []string{"windows"} }
func (winGetPackageInfoFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return nil, fmt.Errorf("win_pkg.get_package_info requires the Salt winrepo/fileserver boundary")
}

// ---------------------------------------------------------------------------
// install/remove/upgrade

type winInstallArgs struct {
	Name    *string        `statekit:"name=name"`
	Refresh bool           `statekit:"name=refresh"`
	Pkgs    []any          `statekit:"name=pkgs"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}
type winInstallFunc struct{}

func (winInstallFunc) Name() string        { return "pkg.install" }
func (winInstallFunc) Args() any           { return winInstallArgs{} }
func (winInstallFunc) Platforms() []string { return []string{"windows"} }
func (winInstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winInstallArgs)
	if a.Refresh {
		if e := refreshManager(ctx, rt); e != nil {
			return nil, e
		}
	}
	targets := targetNamesWin(a.Name, a.Pkgs)
	old, e := listPackages(ctx, rt, false, nil)
	if e != nil {
		return nil, e
	}
	for _, name := range targets {
		version := ""
		if raw, ok := a.Kwargs["version"]; ok {
			version = fmt.Sprint(raw)
		}
		if e := managerInstall(ctx, rt, strings.TrimSpace(name), version); e != nil {
			return nil, e
		}
	}
	newPackages, e := listPackages(ctx, rt, false, nil)
	if e != nil {
		return nil, e
	}
	return comparePackageMapsWin(old, newPackages), nil
}

type winRemoveArgs struct {
	Name   *string        `statekit:"name=name"`
	Pkgs   []any          `statekit:"name=pkgs"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type winRemoveFunc struct{}

func (winRemoveFunc) Name() string        { return "pkg.remove" }
func (winRemoveFunc) Args() any           { return winRemoveArgs{} }
func (winRemoveFunc) Platforms() []string { return []string{"windows"} }
func (winRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWinPkg(&res, &err)
	a := args.(*winRemoveArgs)
	targets := targetNamesWin(a.Name, a.Pkgs)
	old, e := listPackages(ctx, rt, false, nil)
	if e != nil {
		return nil, e
	}
	for _, name := range targets {
		if _, ok := old[name]; !ok {
			continue
		}
		if e := managerRemove(ctx, rt, strings.TrimSpace(name)); e != nil {
			return nil, e
		}
	}
	newPackages, e := listPackages(ctx, rt, false, nil)
	if e != nil {
		return nil, e
	}
	return comparePackageMapsWin(old, newPackages), nil
}

type winPurgeFunc struct{}

func (winPurgeFunc) Name() string        { return "pkg.purge" }
func (winPurgeFunc) Args() any           { return winRemoveArgs{} }
func (winPurgeFunc) Platforms() []string { return []string{"windows"} }
func (winPurgeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return winRemoveFunc{}.Execute(ctx, rt, args)
}

type winUpgradeFunc struct{}

func (winUpgradeFunc) Name() string        { return "pkg.upgrade" }
func (winUpgradeFunc) Args() any           { return winRefreshDBArgs{} }
func (winUpgradeFunc) Platforms() []string { return []string{"windows"} }
func (winUpgradeFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return map[string]any{}, nil
}

// ---------------------------------------------------------------------------
// normalize/compare

type winNormalizeNameArgs struct {
	Name string `statekit:"required"`
}
type winNormalizeNameFunc struct{}

func (winNormalizeNameFunc) Name() string        { return "pkg.normalize_name" }
func (winNormalizeNameFunc) Args() any           { return winNormalizeNameArgs{} }
func (winNormalizeNameFunc) Platforms() []string { return []string{"windows"} }
func (winNormalizeNameFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	return args.(*winNormalizeNameArgs).Name, nil
}

type winCompareVersionsArgs struct {
	Ver1 string `statekit:"name=ver1"`
	Oper string `statekit:"name=oper"`
	Ver2 string `statekit:"name=ver2"`
}
type winCompareVersionsFunc struct{}

func (winCompareVersionsFunc) Name() string        { return "pkg.compare_versions" }
func (winCompareVersionsFunc) Args() any           { return winCompareVersionsArgs{} }
func (winCompareVersionsFunc) Platforms() []string { return []string{"windows"} }
func (winCompareVersionsFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*winCompareVersionsArgs)
	if a.Ver1 == "" {
		return nil, fmt.Errorf("compare_version, ver1 is blank")
	}
	if a.Ver2 == "" {
		return nil, fmt.Errorf("compare_version, ver2 is blank")
	}
	return compareVersionStringsOp(a.Ver1, a.Oper, a.Ver2), nil
}
func compareVersionStrings(a, b string) int {
	if a == "latest" && b == "latest" {
		return 0
	}
	if a == "latest" {
		return 1
	}
	if b == "latest" {
		return -1
	}
	if a == "" || a == "Not Found" {
		a = "0.0.0"
	}
	if b == "" || b == "Not Found" {
		b = "0.0.0"
	}
	aa := strings.Split(a, ".")
	bb := strings.Split(b, ".")
	n := len(aa)
	if len(bb) > n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(aa) {
			x = versionNumberPart(aa[i])
		}
		if i < len(bb) {
			y = versionNumberPart(bb[i])
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func versionNumberPart(value string) int {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r < '0' || r > '9' })
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}
func compareVersionStringsOp(a, op, b string) bool {
	cmp := compareVersionStrings(a, b)
	switch op {
	case "==":
		return cmp == 0
	case "!=":
		return cmp != 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	default:
		return false
	}
}
func recoverWinPkg(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
