package softwareupdate

// R6.11 mock tests for the mac_softwareupdate surface, mapped onto
// saltstack/salt/modules/mac_softwareupdate.py @ pinned revision
// 8b63e700637e and tests/pytests/unit/modules/test_mac_softwareupdate.py:
// exact softwareupdate/defaults argv, the pinned Mojave/Catalina list
// fixtures across the osrelease parser gate, ignore/reset flows, the
// schedule and catalog branches, install/download state machines and
// the registry matrix. All Runner output is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Pinned pytest fixtures (MOJAVE_LIST_OUTPUT / CATALINA_LIST_OUTPUT).
const mockMojaveList = `Software Update Tool

Finding available software
Software Update found the following new or updated software:
   * Command Line Tools (macOS Mojave version 10.14) for Xcode-10.3
    Command Line Tools (macOS Mojave version 10.14) for Xcode (10.3), 199140K [recommended]
   * macOS 10.14.1 Update
    macOS 10.14.1 Update (10.14.1), 199140K [recommended] [restart]
   * BridgeOSUpdateCustomer
    BridgeOSUpdateCustomer (10.14.4.1.1.1555388607), 328394K, [recommended] [shut down]
   - iCal-1.0.2
    iCal, (1.0.2), 6520K`

const mockCatalinaList = `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: Command Line Tools beta 5 for Xcode-11.0
    Title: Command Line Tools beta 5 for Xcode, Version: 11.0, Size: 224804K, Recommended: YES,
* Label: macOS Catalina Developer Beta-6
    Title: macOS Catalina Public Beta, Version: 5, Size: 3084292K, Recommended: YES, Action: restart,
* Label: BridgeOSUpdateCustomer
    Title: BridgeOSUpdateCustomer, Version: 10.15.0.1.1.1560926689, Size: 390674K, Recommended: YES, Action: shut down,
- Label: iCal-1.0.2
    Title: iCal, Version: 1.0.2, Size: 6520K,`

// softwareMockRunner scripts softwareupdate/defaults. Installs flip the
// available list and downloads materialize .dist payloads so the
// list_downloads walker observes them like the real daemon.
type softwareMockRunner struct {
	fs         runtime.FileSystem
	listOut    string
	afterInst  string // listOut swap after any --install
	ignoredOut string
	schedule   string
	catalogOut string
	catalogKey string
	installErr bool
	calls      []process.Command
}

func (r *softwareMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	argv := append([]string{command.Name}, command.Args...)
	switch {
	case argv[0] == "softwareupdate":
		switch {
		case len(argv) >= 3 && argv[1] == "--list" && argv[2] == "--ignore":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.ignoredOut)}
		case len(argv) >= 1 && argv[1] == "--list":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.listOut)}
		case len(argv) >= 2 && argv[1] == "--schedule" && len(argv) == 2:
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.schedule)}
		case len(argv) >= 2 && argv[1] == "--schedule":
			r.schedule = "Automatic checking is " + argv[2] + "\n"
			return process.CommandResult{ExitCode: 0}
		case len(argv) >= 2 && argv[1] == "--install":
			if r.installErr {
				return process.CommandResult{ExitCode: 1, Stderr: []byte("softwareupdate: install failed")}
			}
			if r.afterInst != "" {
				r.listOut = r.afterInst
			} else {
				r.listOut = ""
			}
			return process.CommandResult{ExitCode: 0}
		case len(argv) >= 2 && argv[1] == "--download":
			if err := r.fs.MkdirAll("/Library/Updates/099-1234", 0o755); err != nil {
				return process.CommandResult{ExitCode: 1, Stderr: []byte(err.Error())}
			}
			if err := r.fs.WriteFile("/Library/Updates/099-1234/iCal.dist", []byte("iCal download"), 0o644); err != nil {
				return process.CommandResult{ExitCode: 1, Stderr: []byte(err.Error())}
			}
			return process.CommandResult{ExitCode: 0}
		}
		return process.CommandResult{ExitCode: 0}
	case argv[0] == "defaults":
		if len(argv) >= 4 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.catalogKey)}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.catalogOut)}
	}
	return process.CommandResult{ExitCode: 0}
}

func softwareMockRuntime(t *testing.T, version, updates string) (*runtime.Runtime, *softwareMockRunner) {
	t.Helper()
	runner := &softwareMockRunner{
		fs:         runtime.NewMemoryFS(),
		listOut:    updates,
		schedule:   "Automatic checking is on\n",
		catalogOut: "AppleCatalogURL = http://catalog.example;\n",
		catalogKey: "http://catalog.example",
	}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: version}}),
		Runner: runner,
		FS:     runner.fs,
	}
	return rt, runner
}

func softwareMockArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestSoftwareUpdateMojavePinnedFixture(t *testing.T) {
	// pytest test_mojave_list_available: 10.14 uses the legacy parser
	// and the four pinned updates include the non-recommended iCal.
	rt, runner := softwareMockRuntime(t, "10.14.6", mockMojaveList)
	res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Command Line Tools (macOS Mojave version 10.14) for Xcode-10.3": "10.3",
		"macOS 10.14.1 Update":   "10.14.1",
		"BridgeOSUpdateCustomer": "10.14.4.1.1.1555388607",
		"iCal-1.0.2":             "1.0.2",
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("mojave available = %#v", res)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --list" {
		t.Fatalf("argv = %q", got)
	}
	// pytest test_mojave_list_recommended/_restart/_shut_down filters.
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Recommended: true})
	if err != nil || len(res.(map[string]string)) != 3 {
		t.Fatalf("recommended = %#v %v", res, err)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Restart: true})
	if want := map[string]string{"macOS 10.14.1 Update": "10.14.1"}; err != nil || !reflect.DeepEqual(res, want) {
		t.Fatalf("restart = %#v %v", res, err)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{ShutDown: true})
	if want := map[string]string{"BridgeOSUpdateCustomer": "10.14.4.1.1.1555388607"}; err != nil || !reflect.DeepEqual(res, want) {
		t.Fatalf("shut down = %#v %v", res, err)
	}
}

func TestSoftwareUpdateLegacyTrailingWhitespace(t *testing.T) {
	// pytest test_mojave_list_available_trailing_ws: Salt keeps the
	// trailing-space label with an empty "( )" version. The port's
	// legacy parser trims label whitespace and requires a non-empty
	// version token inside the parens, so the entry is dropped; this
	// pins the port behavior and documents the divergence.
	out := "Software Update Tool\n\nFinding available software\n" +
		"Software Update found the following new or updated software:\n" +
		"   * macOS Mojave 10.14.6 Supplemental Update- \n" +
		"    macOS Mojave 10.14.6 Supplemental Update ( ), 1581834K [recommended] [restart]"
	rt, _ := softwareMockRuntime(t, "10.14.6", out)
	res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); len(got) != 0 {
		t.Fatalf("trailing-ws available = %#v; want empty (port drops it)", got)
	}
	// a non-empty paren version on the same shape keeps the entry.
	out = strings.Replace(out, "( )", "(1.2)", 1)
	rt, _ = softwareMockRuntime(t, "10.14.6", out)
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string); got["macOS Mojave 10.14.6 Supplemental Update-"] != "1.2" {
		t.Fatalf("non-empty paren = %#v", got)
	}
}

func TestSoftwareUpdateModernPinnedFixtureAndGate(t *testing.T) {
	// pytest test_catalina_list_* on 10.15 and test_bigsur_list_* on
	// 11.0: both route through the modern parser.
	for _, version := range []string{"10.15", "11.0", "14.6"} {
		rt, _ := softwareMockRuntime(t, version, mockCatalinaList)
		res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"Command Line Tools beta 5 for Xcode-11.0": "11.0",
			"macOS Catalina Developer Beta-6":          "5",
			"BridgeOSUpdateCustomer":                   "10.15.0.1.1.1560926689",
			"iCal-1.0.2":                               "1.0.2",
		}
		if !reflect.DeepEqual(res, want) {
			t.Fatalf("version %s modern available = %#v", version, res)
		}
	}
	// modern filters mirror the pytest expectations.
	rt, _ := softwareMockRuntime(t, "11.0", mockCatalinaList)
	res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Recommended: true})
	if err != nil || len(res.(map[string]string)) != 3 {
		t.Fatalf("modern recommended = %#v %v", res, err)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Restart: true})
	if want := map[string]string{"macOS Catalina Developer Beta-6": "5"}; err != nil || !reflect.DeepEqual(res, want) {
		t.Fatalf("modern restart = %#v %v", res, err)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{ShutDown: true})
	if want := map[string]string{"BridgeOSUpdateCustomer": "10.15.0.1.1.1560926689"}; err != nil || !reflect.DeepEqual(res, want) {
		t.Fatalf("modern shut down = %#v %v", res, err)
	}
}

func TestSoftwareUpdateVersionGateBoundaries(t *testing.T) {
	// osrelease_info gate: >10 or 10.15+ is modern; unparseable
	// versions default to modern (fail-open like Salt's grain math).
	for _, tc := range []struct {
		version string
		modern  bool
	}{
		{"10.14.6", false},
		{"10.15", true},
		{"11.0", true},
		{"14.6", true},
		{"", true},
		{"garbage", true},
		{"10", true}, // no minor component: defaults to modern
	} {
		rt, _ := softwareMockRuntime(t, tc.version, mockMojaveList)
		if got := darwinVersionModern(rt); got != tc.modern {
			t.Fatalf("darwinVersionModern(%q) = %v; want %v", tc.version, got, tc.modern)
		}
	}
}

func TestSoftwareUpdateIgnoreAndListIgnored(t *testing.T) {
	// Salt list_ignored regex fixture: quoted, comma-terminated lines
	// with headers filtered out.
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.ignoredOut = "Software Update Tool\n\nFinding available software\n" +
		"    \"SecUpd2014-001\",\n    \"Safari6.1.2MountainLion-6.1.2\",\n"
	res, err := listIgnoredFunc{}.Execute(context.Background(), rt, listIgnoredArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); !reflect.DeepEqual(got, []string{"SecUpd2014-001", "Safari6.1.2MountainLion-6.1.2"}) {
		t.Fatalf("ignored = %#v", got)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --list --ignore" {
		t.Fatalf("ignored argv = %q", got)
	}

	// Salt ignore(): trailing "-version" is stripped before --ignore and
	// membership in list_ignored decides the result.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.ignoredOut = "    SecUpd2014-001\n"
	res, err = ignoreFunc{}.Execute(context.Background(), rt, &ignoreArgs{Name: "SecUpd2014-001-1.0"})
	if err != nil || res != true {
		t.Fatalf("ignore = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --ignore SecUpd2014-001" {
		t.Fatalf("ignore argv = %q", got)
	}
	// not in the ignored list -> False.
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = ignoreFunc{}.Execute(context.Background(), rt, &ignoreArgs{Name: "macOS 10.14.1 Update-10.14.1"})
	if err != nil || res != false {
		t.Fatalf("ignore miss = %v %v", res, err)
	}
}

func TestSoftwareUpdateResetIgnored(t *testing.T) {
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.ignoredOut = ""
	res, err := resetIgnoredFunc{}.Execute(context.Background(), rt, resetIgnoredArgs{})
	if err != nil || res != true {
		t.Fatalf("reset_ignored empty = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --reset-ignored" {
		t.Fatalf("reset argv = %q", got)
	}
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	// ignoredOut default is empty; force a non-empty list by scripting
	// the runner directly.
	runner = &softwareMockRunner{fs: runtime.NewMemoryFS(), listOut: mockCatalinaList, ignoredOut: "    LeftOver\n"}
	rt = &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: "14.6"}}),
		Runner: runner, FS: runner.fs,
	}
	res, err = resetIgnoredFunc{}.Execute(context.Background(), rt, resetIgnoredArgs{})
	if err != nil || res != false {
		t.Fatalf("reset_ignored leftover = %v %v", res, err)
	}
}

func TestSoftwareUpdateScheduleFlows(t *testing.T) {
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err := scheduleEnabledFunc{}.Execute(context.Background(), rt, scheduleEnabledArgs{})
	if err != nil || res != true {
		t.Fatalf("schedule_enabled = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --schedule" {
		t.Fatalf("schedule argv = %q", got)
	}

	// schedule_enable off: set argv then read-back comparison.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = scheduleEnableFunc{}.Execute(context.Background(), rt, &scheduleEnableArgs{Enable: "off"})
	if err != nil || res != true {
		t.Fatalf("schedule_enable off = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --schedule off" {
		t.Fatalf("schedule set argv = %q", got)
	}

	// invalid value surfaces Salt's validate_enabled error text.
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	_, err = scheduleEnableFunc{}.Execute(context.Background(), rt, &scheduleEnableArgs{Enable: "maybe"})
	if err == nil || err.Error() != "Invalid value for enabled: maybe" {
		t.Fatalf("invalid enable = %v", err)
	}

	// empty value returns the current status instead of mutating.
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = scheduleEnableFunc{}.Execute(context.Background(), rt, &scheduleEnableArgs{})
	if err != nil || res != true {
		t.Fatalf("empty enable = %v %v", res, err)
	}
	// "off" status parses as disabled.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.schedule = "Automatic checking is off\n"
	res, err = scheduleEnabledFunc{}.Execute(context.Background(), rt, scheduleEnabledArgs{})
	if err != nil || res != false {
		t.Fatalf("schedule off = %v %v", res, err)
	}
}

func TestSoftwareUpdateUpdateFlows(t *testing.T) {
	// update(): unavailable updates are rejected before any install.
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	_, err := updateFunc{}.Execute(context.Background(), rt, &updateArgs{Name: "missing"})
	if err == nil || err.Error() != "Update not available: missing" {
		t.Fatalf("update guard = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("guard calls = %d", len(runner.calls))
	}

	// update(): install then disappear from the list -> True.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err := updateFunc{}.Execute(context.Background(), rt, &updateArgs{Name: "iCal-1.0.2"})
	if err != nil || res != true {
		t.Fatalf("update = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[1]); got != "softwareupdate --install iCal-1.0.2" {
		t.Fatalf("install argv = %q", got)
	}

	// update_available(): membership over the parsed list.
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = updateAvailableFunc{}.Execute(context.Background(), rt, &updateAvailableArgs{Name: "iCal-1.0.2"})
	if err != nil || res != true {
		t.Fatalf("update_available hit = %v %v", res, err)
	}
	res, err = updateAvailableFunc{}.Execute(context.Background(), rt, &updateAvailableArgs{Name: "nope"})
	if err != nil || res != false {
		t.Fatalf("update_available miss = %v %v", res, err)
	}

	// update_all(): every update installed; statuses all true when the
	// list drains. Install failures surface through runSuccess errors.
	// restart defaults to true (Salt signature), so pin it false to
	// install the whole list.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.afterInst = ""
	noRestart := false
	res, err = updateAllFunc{}.Execute(context.Background(), rt, &updateAllArgs{Restart: &noRestart})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]bool)
	if len(got) != 4 {
		t.Fatalf("update_all = %#v", got)
	}
	for name, ok := range got {
		if !ok {
			t.Fatalf("update_all %s = %v", name, ok)
		}
	}
	installs := 0
	for _, call := range runner.calls {
		if strings.HasPrefix(softwareMockArgv(call), "softwareupdate --install ") {
			installs++
		}
	}
	if installs != 4 {
		t.Fatalf("install calls = %d", installs)
	}
	// empty list short-circuits to an empty dict without installs.
	rt, runner = softwareMockRuntime(t, "14.6", "Software Update Tool\n\nFinding available software\n")
	res, err = updateAllFunc{}.Execute(context.Background(), rt, &updateAllArgs{})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("update_all empty = %#v %v", res, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("empty update_all calls = %d", len(runner.calls))
	}
}

func TestSoftwareUpdateDownloadFlows(t *testing.T) {
	// unavailable updates never reach --download.
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	_, err := downloadFunc{}.Execute(context.Background(), rt, &downloadArgs{Name: "missing"})
	if err == nil || err.Error() != "Update not available: missing" {
		t.Fatalf("download guard = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("guard calls = %d", len(runner.calls))
	}

	// download(): no local payload -> --download materializes a .dist
	// whose content carries the label prefix -> True.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err := downloadFunc{}.Execute(context.Background(), rt, &downloadArgs{Name: "iCal-1.0.2"})
	if err != nil || res != true {
		t.Fatalf("download = %v %v", res, err)
	}
	found := false
	for _, call := range runner.calls {
		if softwareMockArgv(call) == "softwareupdate --download iCal-1.0.2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("download argv missing: %+v", runner.calls)
	}

	// already-downloaded short-circuit: no second --download.
	downloads := 0
	for _, call := range runner.calls {
		if strings.HasPrefix(softwareMockArgv(call), "softwareupdate --download ") {
			downloads++
		}
	}
	res, err = downloadFunc{}.Execute(context.Background(), rt, &downloadArgs{Name: "iCal-1.0.2"})
	if err != nil || res != true {
		t.Fatalf("second download = %v %v", res, err)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(softwareMockArgv(call), "softwareupdate --download ") {
			downloads--
		}
	}
	if downloads != 0 {
		t.Fatalf("short-circuit issued extra downloads (%d left)", downloads)
	}

	// list_downloads surfaces the materialized payload for the update.
	res, err = listDownloadsFunc{}.Execute(context.Background(), rt, listDownloadsArgs{})
	if err != nil || !reflect.DeepEqual(res, []string{"iCal-1.0.2"}) {
		t.Fatalf("list_downloads = %#v %v", res, err)
	}
}

func TestSoftwareUpdateCatalogBranches(t *testing.T) {
	// AppleCatalogURL branch: the key read argv targets that key.
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err := getCatalogFunc{}.Execute(context.Background(), rt, getCatalogArgs{})
	if err != nil || res != "http://catalog.example" {
		t.Fatalf("catalog = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[1]); got != "defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist AppleCatalogURL" {
		t.Fatalf("catalog key argv = %q", got)
	}

	// CatalogURL fallback branch.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.catalogOut = "CatalogURL = http://fallback.example;\n"
	runner.catalogKey = "http://fallback.example"
	res, err = getCatalogFunc{}.Execute(context.Background(), rt, getCatalogArgs{})
	if err != nil || res != "http://fallback.example" {
		t.Fatalf("fallback catalog = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[1]); got != "defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL" {
		t.Fatalf("fallback argv = %q", got)
	}

	// no known key -> the literal "Default".
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.catalogOut = "SomeOtherKey = 1;\n"
	res, err = getCatalogFunc{}.Execute(context.Background(), rt, getCatalogArgs{})
	if err != nil || res != "Default" {
		t.Fatalf("default catalog = %v %v", res, err)
	}

	// set_catalog compares the written URL against the read-back value.
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = setCatalogFunc{}.Execute(context.Background(), rt, &setCatalogArgs{URL: "http://catalog.example"})
	if err != nil || res != true {
		t.Fatalf("set_catalog = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --set-catalog http://catalog.example" {
		t.Fatalf("set argv = %q", got)
	}
	rt, _ = softwareMockRuntime(t, "14.6", mockCatalinaList)
	res, err = setCatalogFunc{}.Execute(context.Background(), rt, &setCatalogArgs{URL: "http://other"})
	if err != nil || res != false {
		t.Fatalf("set_catalog mismatch = %v %v", res, err)
	}

	// reset_catalog clears and lands back on "Default".
	rt, runner = softwareMockRuntime(t, "14.6", mockCatalinaList)
	runner.catalogOut = ""
	runner.catalogKey = ""
	res, err = resetCatalogFunc{}.Execute(context.Background(), rt, resetCatalogArgs{})
	if err != nil || res != true {
		t.Fatalf("reset_catalog = %v %v", res, err)
	}
	if got := softwareMockArgv(runner.calls[0]); got != "softwareupdate --clear-catalog" {
		t.Fatalf("reset argv = %q", got)
	}
}

func TestSoftwareUpdateRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"softwareupdate.download",
		"softwareupdate.download_all",
		"softwareupdate.get_catalog",
		"softwareupdate.ignore",
		"softwareupdate.list_available",
		"softwareupdate.list_downloads",
		"softwareupdate.list_ignored",
		"softwareupdate.reset_catalog",
		"softwareupdate.reset_ignored",
		"softwareupdate.schedule_enable",
		"softwareupdate.schedule_enabled",
		"softwareupdate.set_catalog",
		"softwareupdate.update",
		"softwareupdate.update_all",
		"softwareupdate.update_available",
	}
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, runner := softwareMockRuntime(t, "14.6", mockCatalinaList)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "softwareupdate.update_available", &updateAvailableArgs{Name: "iCal-1.0.2"})
		if err != nil || res != true {
			t.Fatalf("dispatch = %v %v", res, err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("dispatch calls = %d", len(runner.calls))
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "softwareupdate.update_available", &updateAvailableArgs{Name: "iCal-1.0.2"}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
