//go:build windows

package win_snmp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type snmpRunner struct {
	calls []process.Command
	mode  string
}

func (r *snmpRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	var value any = map[string]any{"contact": "ops", "location": "lab", "services": float64(5)}
	if r.mode == "auth" {
		value = float64(1)
	}
	if len(r.calls) == 2 {
		value = true
	}
	data, _ := json.Marshal(value)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsSNMPMapsAndAgent(t *testing.T) {
	services := snmpServices(5)
	if len(services) != 2 || services[0] != "Internet" || services[1] != "Physical" {
		t.Fatalf("services = %v", services)
	}
	if got := snmpServices(0); len(got) != 1 || got[0] != "None" {
		t.Fatalf("zero services = %v", got)
	}
	runner := &snmpRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getAgentSettingsFunc{}.Execute(context.Background(), rt, noArgs{})
	if err != nil {
		t.Fatal(err)
	}
	settings := res.(map[string]any)
	if settings["contact"] != "ops" || settings["location"] != "lab" {
		t.Fatalf("settings = %#v", settings)
	}
	if _, err := (setAgentSettingsFunc{}).Execute(context.Background(), rt, &setAgentArgs{Services: []string{"bad"}}); err == nil || !strings.Contains(err.Error(), "Invalid service") {
		t.Fatalf("bad service = %v", err)
	}
}

func TestWindowsSNMPAuthAndPlatform(t *testing.T) {
	runner := &snmpRunner{mode: "auth"}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getAuthTrapsFunc{}.Execute(context.Background(), rt, noArgs{})
	if err != nil || res != true {
		t.Fatalf("auth = %v %v", res, err)
	}
	res, err = setAuthTrapsFunc{}.Execute(context.Background(), rt, &setAuthTrapsArgs{Status: boolPtrSNMP(false)})
	if err != nil || res != true {
		t.Fatalf("set auth = %v %v", res, err)
	}
	platforms := (getCommunityNamesFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatal("platform declaration")
	}
}

func boolPtrSNMP(value bool) *bool { return &value }
