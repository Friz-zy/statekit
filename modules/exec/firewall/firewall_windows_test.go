//go:build windows

package firewall

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type firewallRunner struct{ calls []process.Command }

func (r *firewallRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "netsh" && len(command.Args) >= 3 && command.Args[1] == "show" && command.Args[2] == "allprofiles" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Domain Profile Settings:\nState ON\nPrivate Profile Settings:\nState OFF\n")}
	}
	if command.Name == "powershell.exe" {
		data, _ := json.Marshal(map[string]any{
			"Enabled": true, "AllowInboundRules": 1, "DefaultInboundAction": 4,
			"DefaultOutboundAction": 2, "LogFileName": "C:\\firewall.log",
			"LogAllowed": 1, "LogBlocked": 0, "LogMaxSizeKilobytes": 4096,
			"NotifyOnListen": 1, "AllowLocalIPsecRules": 0,
			"AllowLocalFirewallRules": 1, "AllowUnicastResponseToMulticast": 0,
		})
		return process.CommandResult{ExitCode: 0, Stdout: data}
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte("rule output")}
}

func TestFirewallProfileAndRuleCommands(t *testing.T) {
	runner := &firewallRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getConfigFunc{}.Execute(context.Background(), rt, getConfigArgs{})
	if err != nil {
		t.Fatal(err)
	}
	profiles := res.(map[string]bool)
	if profiles["Domain"] != true || profiles["Private"] != false {
		t.Fatalf("profiles = %#v", profiles)
	}
	res, err = addRuleFunc{}.Execute(context.Background(), rt, &addRuleArgs{Name: "Allow", LocalPort: "443"})
	if err != nil || res != true {
		t.Fatalf("add rule = %v %v", res, err)
	}
	res, err = addRuleFunc{}.Execute(context.Background(), rt, &addRuleArgs{Name: "Ping", LocalPort: "", Protocol: stringPtrFirewall("icmpv4")})
	if err != nil || res != true {
		t.Fatalf("icmp rule = %v %v", res, err)
	}
	res, err = deleteRuleFunc{}.Execute(context.Background(), rt, &deleteRuleArgs{Name: stringPtrFirewall("Allow"), LocalPort: stringPtrFirewall("443")})
	if err != nil || res != true {
		t.Fatalf("delete rule = %v %v", res, err)
	}
	if len(runner.calls) < 4 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestFirewallSettingsAndValidation(t *testing.T) {
	runner := &firewallRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getSettingsFunc{}.Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "state"})
	if err != nil || res.(map[string]any)["State"] != "ON" {
		t.Fatalf("state settings = %#v %v", res, err)
	}
	res, err = getAllProfilesFunc{}.Execute(context.Background(), rt, &getAllProfilesArgs{})
	if err != nil || res == nil {
		t.Fatalf("all profiles = %#v %v", res, err)
	}
	_, err = setFirewallSettingsFunc{}.Execute(context.Background(), rt, &setFirewallSettingsArgs{Profile: "domain", Inbound: stringPtrFirewall("bad")})
	if err == nil || !strings.Contains(err.Error(), "Incorrect inbound value") {
		t.Fatalf("bad inbound = %v", err)
	}
	_, err = setStateFunc{}.Execute(context.Background(), rt, &setStateArgs{Profile: "domain", State: "notconfigured"})
	if err == nil || !strings.Contains(err.Error(), "group policy") {
		t.Fatalf("local notconfigured = %v", err)
	}
	_, err = setLoggingSettingsFunc{}.Execute(context.Background(), rt, &setLoggingSettingsArgs{
		Profile: "domain", Setting: "allowedconnections", Value: "notconfigured",
	})
	if err == nil || !strings.Contains(err.Error(), "Group Policy") {
		t.Fatalf("local logging notconfigured = %v", err)
	}
	platforms := (getConfigFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}

func stringPtrFirewall(value string) *string { return &value }
