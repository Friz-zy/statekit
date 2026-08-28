package softwareupdate

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const modernUpdates = `Software Update found the following new or updated software:
* Label: Command Line Tools beta 5 for Xcode-11.0
    Title: Command Line Tools beta 5 for Xcode, Version: 11.0, Size: 224804K, Recommended: YES,
* Label: macOS Catalina Developer Beta-6
    Title: macOS Catalina Public Beta, Version: 5, Size: 3084292K, Recommended: YES, Action: restart,
* Label: BridgeOSUpdateCustomer
    Title: BridgeOSUpdateCustomer, Version: 10.15.0.1.1, Size: 390674K, Recommended: YES, Action: shut down,
- Label: iCal-1.0.2
    Title: iCal, Version: 1.0.2, Size: 6520K,
`

const legacyUpdates = `Software Update found the following new or updated software:
    * Command Line Tools (macOS Mojave version 10.14) for Xcode-10.3
        Command Line Tools (macOS Mojave version 10.14) for Xcode (10.3), 199140K [recommended]
    * macOS 10.14.1 Update
        macOS 10.14.1 Update (10.14.1), 199140K [recommended] [restart]
    * BridgeOSUpdateCustomer
        BridgeOSUpdateCustomer (10.14.4.1.1.1555388607), 328394K, [recommended] [shut down]
`

type softwareRunner struct {
	listOut    string
	ignoredOut string
	schedule   string
	catalogOut string
	calls      []process.Command
}

func (r *softwareRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "softwareupdate" && command.Name != "defaults" {
		return process.CommandResult{ExitCode: 0}
	}
	if command.Name == "softwareupdate" {
		switch {
		case len(command.Args) >= 2 && command.Args[0] == "--list" && command.Args[1] == "--ignore":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.ignoredOut)}
		case len(command.Args) >= 1 && command.Args[0] == "--list":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.listOut)}
		case len(command.Args) >= 1 && command.Args[0] == "--schedule":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.schedule)}
		default:
			return process.CommandResult{ExitCode: 0}
		}
	}
	if len(command.Args) >= 3 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("http://catalog.example")}
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte(r.catalogOut)}
}

func softwareRuntime(t *testing.T, version, updates string) (*runtime.Runtime, *softwareRunner) {
	t.Helper()
	runner := &softwareRunner{listOut: updates, ignoredOut: "    Ignored-1\n", schedule: "Automatic checking is on\n", catalogOut: "AppleCatalogURL = http://catalog.example;\n"}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: version}}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	return rt, runner
}

func TestAvailableModernAndFilters(t *testing.T) {
	rt, _ := softwareRuntime(t, "14.6", modernUpdates)
	res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Command Line Tools beta 5 for Xcode-11.0": "11.0",
		"macOS Catalina Developer Beta-6":          "5",
		"BridgeOSUpdateCustomer":                   "10.15.0.1.1",
		"iCal-1.0.2":                               "1.0.2",
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("modern = %#v, want %#v", res, want)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Restart: true})
	if err != nil || !reflect.DeepEqual(res, map[string]string{"macOS Catalina Developer Beta-6": "5"}) {
		t.Fatalf("restart filter = %#v %v", res, err)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{ShutDown: true})
	if err != nil || !reflect.DeepEqual(res, map[string]string{"BridgeOSUpdateCustomer": "10.15.0.1.1"}) {
		t.Fatalf("shutdown filter = %#v %v", res, err)
	}
}

func TestAvailableLegacyAndIgnored(t *testing.T) {
	rt, runner := softwareRuntime(t, "10.14.6", legacyUpdates)
	res, err := listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string)["macOS 10.14.1 Update"]; got != "10.14.1" {
		t.Fatalf("legacy version = %q", got)
	}
	res, err = listAvailableFunc{}.Execute(context.Background(), rt, &listAvailableArgs{Recommended: true})
	if err != nil || len(res.(map[string]string)) != 3 {
		t.Fatalf("legacy recommended = %#v %v", res, err)
	}
	res, err = listIgnoredFunc{}.Execute(context.Background(), rt, listIgnoredArgs{})
	if err != nil || !reflect.DeepEqual(res, []string{"Ignored-1"}) {
		t.Fatalf("ignored = %#v %v", res, err)
	}
	if len(runner.calls) < 3 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestScheduleAndCatalog(t *testing.T) {
	rt, runner := softwareRuntime(t, "14.6", modernUpdates)
	res, err := scheduleEnabledFunc{}.Execute(context.Background(), rt, scheduleEnabledArgs{})
	if err != nil || res != true {
		t.Fatalf("schedule = %#v %v", res, err)
	}
	res, err = scheduleEnableFunc{}.Execute(context.Background(), rt, &scheduleEnableArgs{Enable: "off"})
	if err != nil || res != false {
		t.Fatalf("schedule disable = %#v %v", res, err)
	}
	res, err = scheduleEnableFunc{}.Execute(context.Background(), rt, &scheduleEnableArgs{})
	if err != nil || res != true {
		t.Fatalf("empty schedule value = %#v %v", res, err)
	}
	res, err = getCatalogFunc{}.Execute(context.Background(), rt, getCatalogArgs{})
	if err != nil || res != "http://catalog.example" {
		t.Fatalf("catalog = %#v %v", res, err)
	}
	if len(runner.calls) < 4 {
		t.Fatalf("catalog calls = %+v", runner.calls)
	}
}

func TestDownloadsAndUpdateGuards(t *testing.T) {
	rt, _ := softwareRuntime(t, "14.6", modernUpdates)
	if err := rt.FS.MkdirAll("/Library/Updates/Sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/Library/Updates/Sub/Catalog.dist", []byte("macOS Catalina Developer Beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := listDownloadsFunc{}.Execute(context.Background(), rt, listDownloadsArgs{})
	if err != nil || !reflect.DeepEqual(res, []string{"macOS Catalina Developer Beta-6"}) {
		t.Fatalf("downloads = %#v %v", res, err)
	}
	_, err = updateFunc{}.Execute(context.Background(), rt, &updateArgs{Name: "missing"})
	if err == nil || !strings.Contains(err.Error(), "Update not available: missing") {
		t.Fatalf("update guard = %v", err)
	}
	_, err = downloadFunc{}.Execute(context.Background(), rt, &downloadArgs{Name: "missing"})
	if err == nil || !strings.Contains(err.Error(), "Update not available: missing") {
		t.Fatalf("download guard = %v", err)
	}
}

func TestSoftwareUpdatePlatform(t *testing.T) {
	platforms := (listAvailableFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
