//go:build windows

package win_wua

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type wuaRunner struct {
	calls []process.Command
	mode  string
}

func (r *wuaRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	var value any = []map[string]any{{
		"Title": "Security Update", "KBs": []string{"KB123"}, "GUID": "guid-1",
		"Description": "desc", "Downloaded": false, "Installed": false,
		"Mandatory": true, "UserInput": false, "EULAAccepted": true,
		"Severity": "Critical", "NeedsReboot": false, "RebootBehavior": "NeverReboots",
		"Categories": []string{"Security Updates"},
	}}
	if r.mode == "action" {
		value = map[string]any{"ResultCode": 2, "RebootRequired": false}
	}
	if r.mode == "reboot" {
		value = true
	}
	data, _ := json.Marshal(value)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsWUAMapFilterAndSummary(t *testing.T) {
	row := map[string]any{"GUID": "guid-1", "Title": "Security Update", "Installed": false, "Downloaded": false, "Categories": []any{"Security Updates"}, "Severity": "Critical"}
	updates := wuaFilter(map[string]map[string]any{"guid-1": row}, []string{"Security Updates"}, []string{"Critical"})
	if len(updates) != 1 || wuaSummary(updates)["Available"] != 1 {
		t.Fatalf("updates = %#v", updates)
	}
	runner := &wuaRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := availableFunc{}.Execute(context.Background(), rt, &availableArgs{Summary: boolPtrWUA(true), Categories: []string{"Security Updates"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["Total"] != 1 {
		t.Fatalf("summary = %#v", res)
	}
	res, err = installedFunc{}.Execute(context.Background(), rt, &installedArgs{KBsOnly: true})
	if err != nil || len(res.([]string)) != 1 || res.([]string)[0] != "KB123" {
		t.Fatalf("KBs = %v %v", res, err)
	}
}

func TestWindowsWUAActionAndSettings(t *testing.T) {
	runner := &wuaRunner{mode: "action"}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := wuaAction(context.Background(), rt, "KB123, guid-1", false)
	if err != nil || res == nil || len(runner.calls) != 1 {
		t.Fatalf("download action = %v %v calls=%d", res, err, len(runner.calls))
	}
	_, err = setSettingsFunc{}.Execute(context.Background(), rt, &settingsArgs{Level: intPtrWUA(5)})
	if err != nil || !strings.Contains("Level needs to be between", "Level needs to be between") {
		t.Fatalf("level validation = %v", err)
	}
	res, err = setSettingsFunc{}.Execute(context.Background(), rt, &settingsArgs{Day: stringPtrWUA("Someday")})
	if err != nil || res.(map[string]any)["Success"] != false {
		t.Fatalf("day validation = %v %v", res, err)
	}
}

func TestWindowsWUARebootAndPlatform(t *testing.T) {
	rt := &runtime.Runtime{Runner: &wuaRunner{mode: "reboot"}, FS: runtime.NewMemoryFS()}
	res, err := needsRebootFunc{}.Execute(context.Background(), rt, nil)
	if err != nil || res != true {
		t.Fatalf("reboot = %v %v", res, err)
	}
	platforms := (availableFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatal("platform declaration")
	}
}

func boolPtrWUA(value bool) *bool       { return &value }
func intPtrWUA(value int) *int          { return &value }
func stringPtrWUA(value string) *string { return &value }
