//go:build windows

package pkg

// R7.5 mock tests for the Windows pkg virtual module, mapped onto
// saltstack/salt/modules/win_pkg.py @ pinned revision 8b63e700637e and
// tests/pytests/unit/modules/test_win_pkg.py: Get-Package record
// parsing (array, single object, null), versions_as_list vs joined
// string shapes with the "Not Found" default, the target diff shape
// {"old","new"} used by the pinned install/rollback pytests, winget/
// choco/scoop argv for show/install/uninstall/refresh, latest_version
// comparisons with the "latest"/"Not Found" special versions pinned in
// win_pkg.compare_versions, list_upgrades output parsing per manager,
// the winrepo/fileserver boundary errors, the documented upgrade no-op
// and the registry matrix. PowerShell scripts are asserted after
// UTF-16LE/base64 decoding; no real package manager runs. This file
// compiles and runs only on Windows (verified off-platform via
// GOOS=windows go test -c).

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func mustDecodeWinPkgScript(command process.Command) string {
	raw, err := base64.StdEncoding.DecodeString(command.Args[3])
	if err != nil {
		panic(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return strings.TrimSuffix(string(utf16.Decode(units)), "\x00")
}

func winStrPtr(value string) *string { return &value }

func winBoolPtr(value bool) *bool { return &value }

// winPkgStoreRunner scripts the PowerShell Get-Package projection and
// the winget/choco/scoop CLI against a live installed-records store.
// after* pointers swap the store view so before/after list diffs
// behave like a real package database.
type winPkgStoreRunner struct {
	records        string // Get-Package JSON (array | object | null)
	afterInstall   *string
	afterUninstall *string
	showOut        string // winget show / scoop info text output
	chocoInfo      string // choco info --limit-output pipe row
	upgradeOut     string // list_upgrades output for the active manager
	failSubstr     string // argv substring forced to retcode 1
	failStderr     string
	launchErr      error
	calls          []process.Command
	scripts        []string
}

func (r *winPkgStoreRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if r.launchErr != nil {
		return process.CommandResult{ExitCode: -1, Err: r.launchErr}
	}
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if r.failSubstr != "" && strings.Contains(joined, r.failSubstr) {
		return process.CommandResult{ExitCode: 1, Stderr: []byte(r.failStderr)}
	}
	if command.Name == "powershell.exe" {
		script := mustDecodeWinPkgScript(command)
		r.scripts = append(r.scripts, script)
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.records)}
	}
	if len(command.Args) > 0 {
		switch command.Args[0] {
		case "show", "info":
			if command.Name == "choco" {
				return process.CommandResult{ExitCode: 0, Stdout: []byte(r.chocoInfo)}
			}
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.showOut)}
		case "install":
			if r.afterInstall != nil {
				r.records = *r.afterInstall
			}
		case "uninstall":
			if r.afterUninstall != nil {
				r.records = *r.afterUninstall
			}
		case "outdated", "upgrade", "status", "update", "source":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.upgradeOut)}
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func winPkgRT(t *testing.T, manager string, runner *winPkgStoreRunner) *runtime.Runtime {
	t.Helper()
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: manager}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
}

func winPkgArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

// winPkgManagerArgvs filters out the PowerShell Get-Package queries so
// assertions see only the package-manager traffic.
func winPkgManagerArgvs(runner *winPkgStoreRunner) []string {
	out := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		if call.Name != "powershell.exe" {
			out = append(out, winPkgArgv(call))
		}
	}
	return out
}

func winPkgArgvs(runner *winPkgStoreRunner) []string {
	out := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		out = append(out, winPkgArgv(call))
	}
	return out
}

// Pinned pytest fixture shape (test_win_pkg.py pkg_info/install tests):
// two installed records plus a versionless one.
const winPkgRecordsJSON = `[{"Name":"Git.Git","Version":"2.45.0","ProviderName":"winget","Source":"winget"},` +
	`{"Name":"7zip","Version":"24.1","ProviderName":"winget","Source":"winget"},` +
	`{"Name":"python","ProviderName":"msi"}]`

const winPkgSingleRecordJSON = `{"Name":"Git.Git","Version":"2.45.0","ProviderName":"winget"}`

var winPkgUpgradedJSON = `[{"Name":"Git.Git","Version":"2.46.0","ProviderName":"winget"},` +
	`{"Name":"7zip","Version":"24.1","ProviderName":"winget"}]`

var winPkgRemovedJSON = `[{"Name":"7zip","Version":"24.1","ProviderName":"winget"}]`

func TestWinPkgListPkgsShapes(t *testing.T) {
	runner := &winPkgStoreRunner{records: winPkgRecordsJSON}
	rt := winPkgRT(t, "winget", runner)
	listed, err := listPackages(context.Background(), rt, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Versionless records report "Not Found" (win_pkg list_pkgs contract).
	want := map[string]any{"Git.Git": "2.45.0", "7zip": "24.1", "python": "Not Found"}
	if !reflect.DeepEqual(listed, want) {
		t.Fatalf("listed = %#v", listed)
	}
	if got := runner.scripts[0]; got != "@(Get-Package | Select-Object Name,Version,ProviderName,Source) | ConvertTo-Json -Compress" {
		t.Fatalf("records script = %q", got)
	}
	// versions_as_list keeps per-version slices (pytest se_list_pkgs shapes).
	listed, err = listPackages(context.Background(), rt, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listed["Git.Git"].([]string); len(got) != 1 || got[0] != "2.45.0" {
		t.Fatalf("version list = %#v", listed)
	}
	// A single record arrives as a JSON object, not an array.
	single := &winPkgStoreRunner{records: winPkgSingleRecordJSON}
	singleListed, err := listPackages(context.Background(), winPkgRT(t, "winget", single), false, nil)
	if err != nil || singleListed["Git.Git"] != "2.45.0" {
		t.Fatalf("single = %#v %v", singleListed, err)
	}
	// null → empty map; removed/purge_desired kwargs stay empty without
	// touching the manager.
	null := &winPkgStoreRunner{records: "null"}
	nullListed, err := listPackages(context.Background(), winPkgRT(t, "winget", null), false, nil)
	if err != nil || len(nullListed) != 0 || len(null.calls) != 1 {
		t.Fatalf("null = %#v %v", nullListed, err)
	}
	kwargs := &winPkgStoreRunner{records: winPkgRecordsJSON}
	kwListed, err := listPackages(context.Background(), winPkgRT(t, "winget", kwargs), false, map[string]any{"removed": true})
	if err != nil || len(kwListed) != 0 || len(kwargs.calls) != 0 {
		t.Fatalf("removed kwarg = %#v %v", kwListed, err)
	}
	// A non-record payload keeps the unexpected response error.
	bad := &winPkgStoreRunner{records: `"just a string"`}
	if _, err := listPackages(context.Background(), winPkgRT(t, "winget", bad), false, nil); err == nil || err.Error() != "unexpected Get-Package response" {
		t.Fatalf("bad payload = %v", err)
	}
	// A failing PowerShell query surfaces the retcode/stderr shape.
	failing := &winPkgStoreRunner{failSubstr: "powershell.exe", failStderr: "PackageManagement: denied"}
	if _, err := listPackages(context.Background(), winPkgRT(t, "winget", failing), false, nil); err == nil ||
		!strings.Contains(err.Error(), "PowerShell command failed (exit code 1)") {
		t.Fatalf("ps failure = %v", err)
	}
	// Missing powershell.exe surfaces the launch error.
	missing := &winPkgStoreRunner{launchErr: errors.New("exec: \"powershell.exe\": executable file not found in %PATH%")}
	if _, err := listPackages(context.Background(), winPkgRT(t, "winget", missing), false, nil); err == nil ||
		!strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing powershell = %v", err)
	}
	// Two records for one name join as a comma string in scalar mode.
	dup := &winPkgStoreRunner{records: `[{"Name":"nsis","Version":"3.03"},{"Name":"nsis","Version":"3.02"}]`}
	dupListed, err := listPackages(context.Background(), winPkgRT(t, "winget", dup), false, nil)
	if err != nil || dupListed["nsis"] != "3.03, 3.02" {
		t.Fatalf("dup = %#v %v", dupListed, err)
	}
}

func TestWinPkgManagerVersionPerManager(t *testing.T) {
	// winget show parses the "Version:" row.
	winget := &winPkgStoreRunner{showOut: "Found Git [Git.Git]\r\nVersion: 2.46.0\r\nChannel: stable"}
	if got := managerVersion(context.Background(), winPkgRT(t, "winget", winget), "Git.Git"); got != "2.46.0" {
		t.Fatalf("winget version = %q", got)
	}
	if argvs := winPkgArgvs(winget); argvs[0] != "winget show --id Git.Git --accept-source-agreements" {
		t.Fatalf("winget show argv = %v", argvs)
	}
	// choco info --limit-output parses the third pipe field.
	choco := &winPkgStoreRunner{chocoInfo: "7zip|7zip|24.1|this package is in semver:0.0.0"}
	if got := managerVersion(context.Background(), winPkgRT(t, "choco", choco), "7zip"); got != "24.1" {
		t.Fatalf("choco version = %q", got)
	}
	if argvs := winPkgArgvs(choco); argvs[0] != "choco info 7zip --limit-output" {
		t.Fatalf("choco info argv = %v", argvs)
	}
	// scoop info parses the same "Version:" row shape.
	scoop := &winPkgStoreRunner{showOut: "Name: git\r\nVersion: 2.46.0\r\n"}
	if got := managerVersion(context.Background(), winPkgRT(t, "scoop", scoop), "git"); got != "2.46.0" {
		t.Fatalf("scoop version = %q", got)
	}
	if argvs := winPkgArgvs(scoop); argvs[0] != "scoop info git" {
		t.Fatalf("scoop info argv = %v", argvs)
	}
	// A failing lookup collapses to the empty string.
	failed := &winPkgStoreRunner{failSubstr: "winget show", failStderr: "winget: not found"}
	if got := managerVersion(context.Background(), winPkgRT(t, "winget", failed), "Missing.App"); got != "" {
		t.Fatalf("missing version = %q", got)
	}
}

func TestWinPkgInstallArgvAndDiff(t *testing.T) {
	// winget install with a pinned version (pytest test_pkg_install_latest
	// old/new diff shape).
	runner := &winPkgStoreRunner{records: winPkgRecordsJSON, afterInstall: &winPkgUpgradedJSON,
		showOut: "Version: 2.46.0"}
	rt := winPkgRT(t, "winget", runner)
	res, err := (winInstallFunc{}).Execute(context.Background(), rt, &winInstallArgs{
		Name: winStrPtr("Git.Git"), Refresh: true, Kwargs: map[string]any{"version": "2.46.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["Git.Git"]; !reflect.DeepEqual(got, map[string]any{"old": "2.45.0", "new": "2.46.0"}) {
		t.Fatalf("install diff = %#v", res)
	}
	want := []string{
		"winget source update",
		"winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements --version 2.46.0",
	}
	if !reflect.DeepEqual(winPkgManagerArgvs(runner), want) {
		t.Fatalf("install argvs = %v", winPkgManagerArgvs(runner))
	}
	// Unpinned install omits --version; "latest" also omits it.
	noVersion := &winPkgStoreRunner{records: winPkgRecordsJSON, afterInstall: &winPkgUpgradedJSON}
	if _, err := (winInstallFunc{}).Execute(context.Background(), winPkgRT(t, "winget", noVersion), &winInstallArgs{Name: winStrPtr("Git.Git")}); err != nil {
		t.Fatal(err)
	}
	latest := &winPkgStoreRunner{records: winPkgRecordsJSON, afterInstall: &winPkgUpgradedJSON}
	if _, err := (winInstallFunc{}).Execute(context.Background(), winPkgRT(t, "winget", latest), &winInstallArgs{
		Name: winStrPtr("Git.Git"), Refresh: true, Kwargs: map[string]any{"version": "latest"},
	}); err != nil {
		t.Fatal(err)
	}
	latestArgvs := winPkgManagerArgvs(latest)
	if len(latestArgvs) != 2 || strings.Contains(strings.Join(latestArgvs, "\n"), "--version") {
		t.Fatalf("latest argvs = %v", latestArgvs)
	}
	if argvs := winPkgManagerArgvs(noVersion); len(argvs) != 1 || argvs[0] != "winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements" {
		t.Fatalf("unversioned argvs = %v", argvs)
	}
	// choco carries -y and --version; scoop takes bare names.
	chocoAfter := `[{"Name":"7zip","Version":"24.1"}]`
	choco := &winPkgStoreRunner{records: "[]", afterInstall: &chocoAfter}
	if _, err := (winInstallFunc{}).Execute(context.Background(), winPkgRT(t, "choco", choco), &winInstallArgs{
		Name: winStrPtr("7zip"), Kwargs: map[string]any{"version": "24.1"},
	}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(choco); argvs[0] != "choco install 7zip -y --version 24.1" {
		t.Fatalf("choco argvs = %v", argvs)
	}
	scoopAfter := `[{"Name":"git","Version":"2.46.0"}]`
	scoop := &winPkgStoreRunner{records: "[]", afterInstall: &scoopAfter}
	if _, err := (winInstallFunc{}).Execute(context.Background(), winPkgRT(t, "scoop", scoop), &winInstallArgs{Name: winStrPtr("git")}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(scoop); argvs[0] != "scoop install git" {
		t.Fatalf("scoop argvs = %v", argvs)
	}
	// A failing install surfaces the manager stderr (exit-code semantics).
	failing := &winPkgStoreRunner{failSubstr: "winget install", failStderr: "winget: exit 1"}
	_, err = (winInstallFunc{}).Execute(context.Background(), winPkgRT(t, "winget", failing), &winInstallArgs{Name: winStrPtr("Git.Git")})
	if err == nil || err.Error() != "package install failed: winget: exit 1" {
		t.Fatalf("install failure = %v", err)
	}
	// A missing manager binary surfaces the launch error verbatim.
	missingBinary := &winPkgStoreRunner{launchErr: errors.New("exec: \"winget\": executable file not found in %PATH%")}
	err = managerInstall(context.Background(), winPkgRT(t, "winget", missingBinary), "Git.Git", "")
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing winget = %v", err)
	}
}

func TestWinPkgRemoveArgvAndDiff(t *testing.T) {
	// Removal diff keeps the pytest {"old": ..., "new": ""} shape.
	runner := &winPkgStoreRunner{records: winPkgRecordsJSON, afterUninstall: &winPkgRemovedJSON}
	res, err := (winRemoveFunc{}).Execute(context.Background(), winPkgRT(t, "winget", runner), &winRemoveArgs{Name: winStrPtr("Git.Git")})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any)["Git.Git"]; !reflect.DeepEqual(got, map[string]any{"old": "2.45.0", "new": ""}) {
		t.Fatalf("remove diff = %#v", res)
	}
	if argvs := winPkgManagerArgvs(runner); argvs[0] != "winget uninstall --id Git.Git --silent --accept-source-agreements" {
		t.Fatalf("uninstall argvs = %v", argvs)
	}
	// Not-installed targets are skipped without any manager call.
	skipped := &winPkgStoreRunner{records: winPkgRecordsJSON}
	if _, err := (winRemoveFunc{}).Execute(context.Background(), winPkgRT(t, "winget", skipped), &winRemoveArgs{Name: winStrPtr("missing.app")}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(skipped); len(argvs) != 0 { // only the pre-list Get-Package query ran
		t.Fatalf("skip argvs = %v", argvs)
	}
	// choco/scoop uninstall argv and purge == remove.
	choco := &winPkgStoreRunner{records: winPkgRecordsJSON, afterUninstall: &winPkgRemovedJSON}
	if _, err := (winPurgeFunc{}).Execute(context.Background(), winPkgRT(t, "choco", choco), &winRemoveArgs{Name: winStrPtr("Git.Git")}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(choco); argvs[0] != "choco uninstall Git.Git -y" {
		t.Fatalf("choco uninstall argvs = %v", argvs)
	}
	scoop := &winPkgStoreRunner{records: winPkgRecordsJSON, afterUninstall: &winPkgRemovedJSON}
	if _, err := (winRemoveFunc{}).Execute(context.Background(), winPkgRT(t, "scoop", scoop), &winRemoveArgs{Name: winStrPtr("Git.Git")}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(scoop); argvs[0] != "scoop uninstall Git.Git" {
		t.Fatalf("scoop uninstall argvs = %v", argvs)
	}
	// A failing removal surfaces the manager stderr.
	failing := &winPkgStoreRunner{records: winPkgRecordsJSON, failSubstr: "winget uninstall", failStderr: "locked"}
	_, err = (winRemoveFunc{}).Execute(context.Background(), winPkgRT(t, "winget", failing), &winRemoveArgs{Name: winStrPtr("Git.Git")})
	if err == nil || err.Error() != "package removal failed: locked" {
		t.Fatalf("remove failure = %v", err)
	}
}

func TestWinPkgLatestVersionAndUpgradeAvailable(t *testing.T) {
	runner := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: "Version: 2.46.0"}
	rt := winPkgRT(t, "winget", runner)
	res, err := (winLatestVersionFunc{}).Execute(context.Background(), rt, &winLatestVersionArgs{Names: []string{"Git.Git"}, Kwargs: map[string]any{"refresh": false}})
	if err != nil {
		t.Fatal(err)
	}
	if res != "2.46.0" {
		t.Fatalf("latest = %v", res)
	}
	// refresh=false must not run the metadata refresh command.
	for _, argv := range winPkgManagerArgvs(runner) {
		if strings.Contains(argv, "source update") {
			t.Fatalf("refresh leaked: %v", winPkgManagerArgvs(runner))
		}
	}
	// Default refresh runs winget source update first.
	refreshing := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: "Version: 2.46.0"}
	res, err = (winLatestVersionFunc{}).Execute(context.Background(), winPkgRT(t, "winget", refreshing), &winLatestVersionArgs{Names: []string{"Git.Git"}})
	if err != nil || res != "2.46.0" {
		t.Fatalf("latest with refresh = %v %v", res, err)
	}
	if winPkgManagerArgvs(refreshing)[0] != "winget source update" {
		t.Fatalf("refresh argv = %v", winPkgManagerArgvs(refreshing))
	}
	// Already current → empty string; multiple names → per-name map.
	current := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: "Version: 2.45.0"}
	res, err = (winLatestVersionFunc{}).Execute(context.Background(), winPkgRT(t, "winget", current), &winLatestVersionArgs{Names: []string{"Git.Git"}, Kwargs: map[string]any{"refresh": false}})
	if err != nil || res != "" {
		t.Fatalf("current latest = %v %v", res, err)
	}
	multi := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: "Version: 99.0"}
	res, err = (winLatestVersionFunc{}).Execute(context.Background(), winPkgRT(t, "winget", multi), &winLatestVersionArgs{Names: []string{"Git.Git", "7zip"}, Kwargs: map[string]any{"refresh": false}})
	if err != nil {
		t.Fatal(err)
	}
	// The same show fixture answers both lookups: both report the
	// available 99.0 (per-name map, single-name callers get a string).
	got := res.(map[string]string)
	if got["Git.Git"] != "99.0" || got["7zip"] != "99.0" {
		t.Fatalf("multi latest = %#v", got)
	}
	// Empty names → empty string without any manager traffic.
	empty := &winPkgStoreRunner{records: winPkgRecordsJSON}
	res, err = (winLatestVersionFunc{}).Execute(context.Background(), winPkgRT(t, "winget", empty), &winLatestVersionArgs{})
	if err != nil || res != "" || len(empty.calls) != 0 {
		t.Fatalf("empty latest = %v %v %v", res, err, winPkgManagerArgvs(empty))
	}
	// upgrade_available derives from latest_version.
	available := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: "Version: 2.46.0"}
	res, err = (winUpgradeAvailableFunc{}).Execute(context.Background(), winPkgRT(t, "winget", available), &winUpgradeAvailableArgs{Name: "Git.Git", Kwargs: map[string]any{"refresh": false}})
	if err != nil || res != true {
		t.Fatalf("upgrade available = %v %v", res, err)
	}
	absent := &winPkgStoreRunner{records: winPkgRecordsJSON, showOut: ""}
	res, err = (winUpgradeAvailableFunc{}).Execute(context.Background(), winPkgRT(t, "winget", absent), &winUpgradeAvailableArgs{Name: "Missing.App", Kwargs: map[string]any{"refresh": false}})
	if err != nil || res != false {
		t.Fatalf("upgrade unavailable = %v %v", res, err)
	}
}

func TestWinPkgListUpgradesPerManager(t *testing.T) {
	// choco outdated --limit-output: name|current|available|pinned.
	choco := &winPkgStoreRunner{upgradeOut: "7zip|24.1|24.6|false\r\ngit|2.45|2.46|false\r\n"}
	res, err := (winListUpgradesFunc{}).Execute(context.Background(), winPkgRT(t, "choco", choco), &winListUpgradesArgs{Refresh: winBoolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); got["7zip"] != "24.6" || got["git"] != "2.46" {
		t.Fatalf("choco upgrades = %#v", got)
	}
	if argvs := winPkgManagerArgvs(choco); argvs[0] != "choco outdated --limit-output" {
		t.Fatalf("choco upgrades argv = %v", argvs)
	}
	// winget upgrade table: skip the header row, map name → last column.
	winget := &winPkgStoreRunner{upgradeOut: "Name    Id       Version Available\r\nGit     Git.Git  2.45.0  2.46.0\r\n7zip    7zip     24.1    24.6\r\n"}
	res, err = (winListUpgradesFunc{}).Execute(context.Background(), winPkgRT(t, "winget", winget), &winListUpgradesArgs{Refresh: winBoolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]string)
	if len(got) != 2 || got["Git"] != "2.46.0" || got["7zip"] != "24.6" {
		t.Fatalf("winget upgrades = %#v", got)
	}
	if argvs := winPkgManagerArgvs(winget); argvs[0] != "winget upgrade --accept-source-agreements --accept-package-agreements" {
		t.Fatalf("winget upgrades argv = %v", argvs)
	}
	// scoop status rows parse the same field shape.
	scoop := &winPkgStoreRunner{upgradeOut: "git 2.45.0 available 2.46.0\r\n"}
	res, err = (winListUpgradesFunc{}).Execute(context.Background(), winPkgRT(t, "scoop", scoop), &winListUpgradesArgs{Refresh: winBoolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); got["git"] != "2.46.0" {
		t.Fatalf("scoop upgrades = %#v", got)
	}
	if argvs := winPkgManagerArgvs(scoop); argvs[0] != "scoop status" {
		t.Fatalf("scoop upgrades argv = %v", argvs)
	}
	// Default refresh runs the manager metadata refresh first.
	refreshing := &winPkgStoreRunner{upgradeOut: ""}
	if _, err := (winListUpgradesFunc{}).Execute(context.Background(), winPkgRT(t, "winget", refreshing), &winListUpgradesArgs{}); err != nil {
		t.Fatal(err)
	}
	if argvs := winPkgManagerArgvs(refreshing); argvs[0] != "winget source update" {
		t.Fatalf("refresh argv = %v", argvs)
	}
}

func TestWinPkgVersionBoundariesAndCompare(t *testing.T) {
	runner := &winPkgStoreRunner{records: winPkgRecordsJSON}
	rt := winPkgRT(t, "winget", runner)
	res, err := (winVersionFunc{}).Execute(context.Background(), rt, &winVersionArgs{Names: []string{"Git.Git"}})
	if err != nil || res != "2.45.0" {
		t.Fatalf("version single = %v %v", res, err)
	}
	res, err = (winVersionFunc{}).Execute(context.Background(), rt, &winVersionArgs{Names: []string{"Git.Git", "7zip"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); got["Git.Git"] != "2.45.0" || got["7zip"] != "24.1" {
		t.Fatalf("version multi = %#v", got)
	}
	// Boundary pin: a name missing from the listing stringifies through
	// fmt.Sprint(nil) as "<nil>" (Salt's win_pkg returns ""), pinned as
	// the current port contract in both response shapes.
	res, err = (winVersionFunc{}).Execute(context.Background(), rt, &winVersionArgs{Names: []string{"Not.Installed"}})
	if err != nil || res != "<nil>" {
		t.Fatalf("version missing single = %v %v", res, err)
	}
	res, err = (winVersionFunc{}).Execute(context.Background(), rt, &winVersionArgs{Names: []string{"Git.Git", "Not.Installed"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); got["Not.Installed"] != "<nil>" {
		t.Fatalf("version missing multi = %#v", got)
	}
	// winrepo/fileserver boundary errors keep their exact texts.
	for _, tc := range []struct {
		label string
		exec  runtime.ExecFunction
		args  any
		want  string
	}{
		{"list_available", winListAvailableFunc{}, &winListAvailableArgs{}, "win_pkg repository metadata requires the Salt winrepo/fileserver boundary"},
		{"refresh_db", winRefreshDBFunc{}, &winRefreshDBArgs{}, "win_pkg.refresh_db requires the Salt winrepo/fileserver boundary"},
		{"genrepo", winGenRepoFunc{}, &winRefreshDBArgs{}, "win_pkg.genrepo requires the Salt winrepo/fileserver boundary"},
		{"list_repo_pkgs", winListRepoPkgsFunc{}, &winListRepoPkgsArgs{}, "win_pkg.list_repo_pkgs requires the Salt winrepo/fileserver boundary"},
		{"get_repo_data", winGetRepoDataFunc{}, &winGetRepoDataArgs{}, "win_pkg.get_repo_data requires the Salt winrepo/fileserver boundary"},
		{"get_package_info", winGetPackageInfoFunc{}, &winGetPackageInfoArgs{Name: "nsis"}, "win_pkg.get_package_info requires the Salt winrepo/fileserver boundary"},
	} {
		_, err := tc.exec.Execute(context.Background(), rt, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s boundary = %v", tc.label, err)
		}
	}
	// upgrade is a documented no-op returning an empty change set.
	noop := &winPkgStoreRunner{}
	res, err = (winUpgradeFunc{}).Execute(context.Background(), winPkgRT(t, "winget", noop), &winRefreshDBArgs{})
	if err != nil || !reflect.DeepEqual(res, map[string]any{}) || len(noop.calls) != 0 {
		t.Fatalf("upgrade no-op = %v %v %v", res, err, winPkgManagerArgvs(noop))
	}
	// normalize_name is identity on Windows.
	res, err = (winNormalizeNameFunc{}).Execute(context.Background(), rt, &winNormalizeNameArgs{Name: "Git.Git"})
	if err != nil || res != "Git.Git" {
		t.Fatalf("normalize = %v %v", res, err)
	}
	// compare_versions pins Salt's special versions: blank operands
	// raise; "latest" beats everything except "latest"; "Not Found"
	// compares as 0.0.0.
	if _, err := (winCompareVersionsFunc{}).Execute(context.Background(), rt, &winCompareVersionsArgs{Oper: "==", Ver2: "1"}); err == nil || err.Error() != "compare_version, ver1 is blank" {
		t.Fatalf("blank ver1 = %v", err)
	}
	if _, err := (winCompareVersionsFunc{}).Execute(context.Background(), rt, &winCompareVersionsArgs{Ver1: "1", Oper: "=="}); err == nil || err.Error() != "compare_version, ver2 is blank" {
		t.Fatalf("blank ver2 = %v", err)
	}
	for _, tc := range []struct {
		ver1, oper, ver2 string
		want             bool
	}{
		{"1.2", "==", "1.2", true},
		{"1.2", "!=", "1.3", true},
		{"1.2", ">", "1.1", true},
		{"1.2", ">=", "1.2", true},
		{"1.2", "<", "1.3", true},
		{"1.2", "<=", "1.1", false},
		{"latest", ">", "999.0", true},
		{"latest", "==", "latest", true},
		{"Not Found", "==", "0.0.0", true},
		{"1.2", "~=", "1.0", false}, // unknown operator stays False
	} {
		res, err := (winCompareVersionsFunc{}).Execute(context.Background(), rt, &winCompareVersionsArgs{Ver1: tc.ver1, Oper: tc.oper, Ver2: tc.ver2})
		if err != nil || res != tc.want {
			t.Fatalf("compare(%q %s %q) = %v %v want %v", tc.ver1, tc.oper, tc.ver2, res, err, tc.want)
		}
	}
}

func TestWinPkgManagerSelectionAndRegistryMatrix(t *testing.T) {
	// Facts select winget/choco/scoop; anything else falls back to winget.
	if got := packageManager(winPkgRT(t, "choco", &winPkgStoreRunner{})); got != "choco" {
		t.Fatalf("choco facts = %q", got)
	}
	if got := packageManager(winPkgRT(t, "scoop", &winPkgStoreRunner{})); got != "scoop" {
		t.Fatalf("scoop facts = %q", got)
	}
	if got := packageManager(nil); got != "winget" {
		t.Fatalf("nil facts = %q", got)
	}
	unknown := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "apt"}), Runner: &winPkgStoreRunner{}, FS: runtime.NewMemoryFS()}
	if got := packageManager(unknown); got != "winget" {
		t.Fatalf("unknown facts = %q", got)
	}
	reg := runtime.NewExecRegistry()
	if err := registerWindows(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	sort.Strings(names)
	want := []string{
		"pkg.compare_versions", "pkg.genrepo", "pkg.get_package_info", "pkg.get_repo_data",
		"pkg.install", "pkg.latest_version", "pkg.list_available", "pkg.list_pkgs",
		"pkg.list_repo_pkgs", "pkg.list_upgrades", "pkg.normalize_name", "pkg.purge",
		"pkg.refresh_db", "pkg.remove", "pkg.upgrade", "pkg.upgrade_available", "pkg.version",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registry = %v", names)
	}
	if platforms := (winListPkgsFunc{}).Platforms(); len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
