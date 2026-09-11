//go:build windows

package firewall

// R7.5 mock tests for the Windows firewall module, mapped onto
// saltstack/salt/modules/win_firewall.py @ pinned revision 8b63e700637e
// and tests/integration/modules/test_win_firewall.py: the netsh
// advfirewall argv for get_config/enable/disable/get_rule/add_rule/
// delete_rule (including the icmpv4/icmpv6 localport suppression and
// the delete_rule protocol=tcp default), the localized-profile text
// parser, rule_exists' CommandExecutionError-only semantics, the
// NetSecurity Get/Set-NetFirewallProfile PowerShell contracts
// (local vs lgpo PolicyStore), the settings validation ladders with
// Salt's exact error strings and the registry matrix. PowerShell
// scripts are asserted after UTF-16LE/base64 decoding; no real
// netsh or powershell.exe runs. This file compiles and runs only on
// Windows (verified off-platform via GOOS=windows go test -c).

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

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// mustDecodeEncodedScript reverses psFirewall: base64 → UTF-16LE → the
// original script (with the appended NUL terminator stripped). It
// panics on malformed input, which every psFirewall-produced command
// satisfies, so the runner can decode outside a *testing.T context.
func mustDecodeEncodedScript(command process.Command) string {
	if command.Name != "powershell.exe" || len(command.Args) != 4 || command.Args[0] != "-NoProfile" || command.Args[1] != "-NonInteractive" || command.Args[2] != "-EncodedCommand" {
		panic("unexpected powershell argv: " + strings.Join(command.Args, " "))
	}
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

// winFwMockRunner scripts the netsh + NetSecurity toolchain against a
// live per-profile settings store. launchErr simulates a missing
// powershell.exe/netsh (Runner launch failure: Err set, ExitCode -1).
type winFwMockRunner struct {
	netshProfiles string // `netsh advfirewall show allprofiles` text
	profileJSON   string // Get-NetFirewallProfile JSON response
	ruleText      string // `netsh ... show rule` stdout
	netshRetcode  int    // forced retcode for netsh set/rule ops
	psRetcode     int    // forced retcode for PowerShell ops
	launchName    string // binary name that fails to launch
	launchErr     error  // launch error surfaced with ExitCode -1
	calls         []process.Command
	scripts       []string // decoded PowerShell scripts
}

func (r *winFwMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if r.launchName != "" && command.Name == r.launchName {
		return process.CommandResult{ExitCode: -1, Err: r.launchErr}
	}
	if command.Name == "netsh" {
		if len(command.Args) >= 3 && command.Args[1] == "show" && command.Args[2] == "allprofiles" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.netshProfiles)}
		}
		if len(command.Args) >= 3 && command.Args[1] == "firewall" && command.Args[2] == "show" {
			if r.netshRetcode != 0 {
				return process.CommandResult{ExitCode: r.netshRetcode, Stdout: []byte("No rules match the specified criteria.")}
			}
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.ruleText)}
		}
		if r.netshRetcode != 0 {
			return process.CommandResult{ExitCode: r.netshRetcode, Stdout: []byte("The requested operation requires elevation")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Ok.")}
	}
	if command.Name == "powershell.exe" {
		script := mustDecodeEncodedScript(command)
		r.scripts = append(r.scripts, script)
		if r.psRetcode != 0 {
			return process.CommandResult{ExitCode: r.psRetcode, Stderr: []byte("NetSecurity: refused")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.profileJSON)}
	}
	return process.CommandResult{ExitCode: 0}
}

func winFwRT(runner *winFwMockRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func winFwArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func winFwArgvs(runner *winFwMockRunner) []string {
	out := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		out = append(out, winFwArgv(call))
	}
	return out
}

func winFwPtr(value string) *string { return &value }

// Integration-test fixture shape (test_win_firewall.py): netsh emits
// CRLF lines with "<Name> Profile Settings:" headers followed by a
// "State ON|OFF" row per profile.
const winFwNetshProfiles = "Domain Profile Settings:\r\n" +
	"-------------------------------------------------------------------\r\n" +
	"State                                 ON\r\n" +
	"\r\n" +
	"Private Profile Settings:\r\n" +
	"-------------------------------------------------------------------\r\n" +
	"State                                 OFF\r\n" +
	"\r\n" +
	"Public Profile Settings:\r\n" +
	"-------------------------------------------------------------------\r\n" +
	"State                                 ON\r\n"

// Get-NetFirewallProfile projection covering every settings mapping:
// state, firewallpolicy (BlockInboundAlways + Allow/Block outbound),
// logging and the four notification switches.
const winFwProfileJSON = `{"Enabled":true,` +
	`"AllowInboundRules":0,"DefaultInboundAction":4,"DefaultOutboundAction":2,` +
	`"LogFileName":"C:\\windows\\logs\\firewall.log","LogAllowed":1,"LogBlocked":0,"LogMaxSizeKilobytes":4096,` +
	`"NotifyOnListen":1,"AllowLocalIPsecRules":0,"AllowLocalFirewallRules":1,"AllowUnicastResponseToMulticast":0}`

func TestWinFirewallGetConfigParsesLocalizedNetshText(t *testing.T) {
	runner := &winFwMockRunner{netshProfiles: winFwNetshProfiles}
	res, err := (getConfigFunc{}).Execute(context.Background(), winFwRT(runner), getConfigArgs{})
	if err != nil {
		t.Fatal(err)
	}
	profiles := res.(map[string]bool)
	if len(profiles) != 3 || !profiles["Domain"] || profiles["Private"] || !profiles["Public"] {
		t.Fatalf("profiles = %#v", profiles)
	}
	if argvs := winFwArgvs(runner); len(argvs) != 1 || argvs[0] != "netsh advfirewall show allprofiles" {
		t.Fatalf("argvs = %v", argvs)
	}
}

func TestWinFirewallGetConfigErrorAndMissingBinary(t *testing.T) {
	// Salt raises CommandExecutionError(ret["stdout"]) on nonzero retcode;
	// the shared firewallSuccess path carries netsh stdout into the error.
	runner := &winFwMockRunner{netshRetcode: 1}
	_, err := (disableFunc{}).Execute(context.Background(), winFwRT(runner), &profileArgs{Profile: "domain"})
	if err == nil || !strings.Contains(err.Error(), "The requested operation requires elevation") {
		t.Fatalf("netsh failure = %v", err)
	}
	// Missing netsh (launch failure) surfaces the Runner error verbatim.
	launch := errors.New("exec: \"netsh\": executable file not found in %PATH%")
	missing := &winFwMockRunner{launchName: "netsh", launchErr: launch}
	_, err = (getConfigFunc{}).Execute(context.Background(), winFwRT(missing), getConfigArgs{})
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing netsh = %v", err)
	}
}

func TestWinFirewallEnableDisableArgvAndValidation(t *testing.T) {
	runner := &winFwMockRunner{}
	if _, err := (disableFunc{}).Execute(context.Background(), winFwRT(runner), &profileArgs{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (disableFunc{}).Execute(context.Background(), winFwRT(runner), &profileArgs{Profile: "domainprofile"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (enableFunc{}).Execute(context.Background(), winFwRT(runner), &profileArgs{Profile: "private"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"netsh advfirewall set allprofiles state off",
		"netsh advfirewall set domainprofile state off",
		"netsh advfirewall set private state on",
	}
	if got := winFwArgvs(runner); !reflect.DeepEqual(got, want) {
		t.Fatalf("argvs = %v", got)
	}
	_, err := (disableFunc{}).Execute(context.Background(), winFwRT(runner), &profileArgs{Profile: "nope"})
	if err == nil || err.Error() != "Invalid profile: nope" {
		t.Fatalf("invalid profile = %v", err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("validation must not spawn commands: %+v", runner.calls)
	}
}

func TestWinFirewallRuleArgv(t *testing.T) {
	runner := &winFwMockRunner{ruleText: "Rule Name:\ttest\r\nLocalPort:\t8080\r\n"}
	// add_rule defaults: protocol=tcp dir=in action=allow remoteip=any.
	if _, err := (addRuleFunc{}).Execute(context.Background(), winFwRT(runner), &addRuleArgs{Name: "test", LocalPort: "8080"}); err != nil {
		t.Fatal(err)
	}
	// Explicit args keep Salt's argv order name/protocol/dir/action/remoteip.
	if _, err := (addRuleFunc{}).Execute(context.Background(), winFwRT(runner), &addRuleArgs{
		Name: "test_remote_ip", LocalPort: "8000", Protocol: winFwPtr("tcp"),
		Action: winFwPtr("allow"), Dir: winFwPtr("in"), RemoteIP: winFwPtr("192.168.0.1"),
	}); err != nil {
		t.Fatal(err)
	}
	// icmpv4 suppresses localport (Salt add_rule CLI example 2).
	if _, err := (addRuleFunc{}).Execute(context.Background(), winFwRT(runner), &addRuleArgs{Name: "Ping", LocalPort: "1", Protocol: winFwPtr("icmpv4")}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"netsh advfirewall firewall add rule name=test protocol=tcp dir=in action=allow remoteip=any localport=8080",
		"netsh advfirewall firewall add rule name=test_remote_ip protocol=tcp dir=in action=allow remoteip=192.168.0.1 localport=8000",
		"netsh advfirewall firewall add rule name=Ping protocol=icmpv4 dir=in action=allow remoteip=any",
	}
	if got := winFwArgvs(runner); !reflect.DeepEqual(got, want) {
		t.Fatalf("add argvs = %v", got)
	}
	// delete_rule: localport without protocol injects protocol=tcp
	// (Salt: "If protocol is not specified, protocol will be set to tcp").
	runner2 := &winFwMockRunner{}
	if _, err := (deleteRuleFunc{}).Execute(context.Background(), winFwRT(runner2), &deleteRuleArgs{Name: winFwPtr("test"), LocalPort: winFwPtr("8080")}); err != nil {
		t.Fatal(err)
	}
	if _, err := (deleteRuleFunc{}).Execute(context.Background(), winFwRT(runner2), &deleteRuleArgs{
		Name: winFwPtr("test_remote_ip"), Protocol: winFwPtr("tcp"),
		Dir: winFwPtr("in"), RemoteIP: winFwPtr("192.168.0.1"), LocalPort: winFwPtr("8000"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (deleteRuleFunc{}).Execute(context.Background(), winFwRT(runner2), &deleteRuleArgs{Name: winFwPtr("allow80")}); err != nil {
		t.Fatal(err)
	}
	want2 := []string{
		"netsh advfirewall firewall delete rule name=test protocol=tcp localport=8080",
		"netsh advfirewall firewall delete rule name=test_remote_ip protocol=tcp dir=in remoteip=192.168.0.1 localport=8000",
		"netsh advfirewall firewall delete rule name=allow80",
	}
	if got := winFwArgvs(runner2); !reflect.DeepEqual(got, want2) {
		t.Fatalf("delete argvs = %v", got)
	}
	// get_rule defaults to name=all and maps stdout under the rule name.
	runner3 := &winFwMockRunner{ruleText: "Remote Event Log Management (NP-In)\r\nLocalPort: 445\r\n"}
	res, err := (getRuleFunc{}).Execute(context.Background(), winFwRT(runner3), &getRuleArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]string)["all"]; !strings.Contains(got, "LocalPort: 445") {
		t.Fatalf("get_rule all = %q", got)
	}
	res, err = (getRuleFunc{}).Execute(context.Background(), winFwRT(runner3), &getRuleArgs{Name: "Remote Event Log Management (NP-In)"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.(map[string]string)["Remote Event Log Management (NP-In)"]; !ok {
		t.Fatalf("named get_rule = %#v", res)
	}
	if argvs := winFwArgvs(runner3); argvs[0] != "netsh advfirewall firewall show rule name=all" ||
		argvs[1] != "netsh advfirewall firewall show rule name=Remote Event Log Management (NP-In)" {
		t.Fatalf("show argvs = %v", argvs)
	}
	// Nonzero retcode surfaces stdout as the error (Salt
	// CommandExecutionError(ret["stdout"])).
	runner4 := &winFwMockRunner{netshRetcode: 1}
	_, err = (getRuleFunc{}).Execute(context.Background(), winFwRT(runner4), &getRuleArgs{Name: "test"})
	if err == nil || !strings.Contains(err.Error(), "No rules match the specified criteria.") {
		t.Fatalf("get_rule failure = %v", err)
	}
}

func TestWinFirewallRuleExistsSwallowsOnlyExecutionErrors(t *testing.T) {
	// Salt rule_exists: any CommandExecutionError → False; a retcode-0
	// netsh answer (even "No rules match") stays True.
	ok := &winFwMockRunner{}
	res, err := (ruleExistsFunc{}).Execute(context.Background(), winFwRT(ok), &ruleExistsArgs{Name: "RemoteDesktop"})
	if err != nil || res != true {
		t.Fatalf("rule exists = %v %v", res, err)
	}
	failing := &winFwMockRunner{netshRetcode: 1}
	res, err = (ruleExistsFunc{}).Execute(context.Background(), winFwRT(failing), &ruleExistsArgs{Name: "RemoteDesktop"})
	if err != nil || res != false {
		t.Fatalf("rule missing = %v %v", res, err)
	}
}

func TestWinFirewallGetSettingsSectionsAndStores(t *testing.T) {
	runner := &winFwMockRunner{profileJSON: winFwProfileJSON}
	rt := winFwRT(runner)
	res, err := (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "state"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any); got["State"] != "ON" {
		t.Fatalf("state section = %#v", got)
	}
	res, err = (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "firewallpolicy"})
	if err != nil {
		t.Fatal(err)
	}
	policy := res.(map[string]any)
	// AllowInboundRules=0 + DefaultInboundAction=4 → BlockInboundAlways;
	// DefaultOutboundAction=2 → AllowOutbound.
	if policy["Inbound"] != "BlockInboundAlways" || policy["Outbound"] != "AllowOutbound" {
		t.Fatalf("firewallpolicy section = %#v", policy)
	}
	res, err = (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "logging"})
	if err != nil {
		t.Fatal(err)
	}
	logging := res.(map[string]any)
	if logging["FileName"] != "C:\\windows\\logs\\firewall.log" || logging["LogAllowedConnections"] != "Enable" ||
		logging["LogDroppedConnections"] != "Disable" || logging["MaxFileSize"] != float64(4096) {
		t.Fatalf("logging section = %#v", logging)
	}
	res, err = (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "settings"})
	if err != nil {
		t.Fatal(err)
	}
	settings := res.(map[string]any)
	if settings["InboundUserNotification"] != "Enable" || settings["LocalConSecRules"] != "Disable" ||
		settings["LocalFirewallRules"] != "Enable" || settings["UnicastResponseToMulticast"] != "Disable" {
		t.Fatalf("settings section = %#v", settings)
	}
	wantScript := "$p=Get-NetFirewallProfile -Name 'domain'|Select-Object *|ConvertTo-Json -Compress"
	for _, script := range runner.scripts {
		if script != wantScript {
			t.Fatalf("local store script = %q", script)
		}
	}
	// lgpo store targets the localhost PolicyStore.
	runnerLGPO := &winFwMockRunner{profileJSON: winFwProfileJSON}
	if _, err := (getSettingsFunc{}).Execute(context.Background(), winFwRT(runnerLGPO), &getSettingsArgs{Profile: "domain", Section: "state", Store: winFwPtr("lgpo")}); err != nil {
		t.Fatal(err)
	}
	wantLGPO := "$p=Get-NetFirewallProfile -Name 'domain' -PolicyStore 'localhost'|Select-Object *|ConvertTo-Json -Compress"
	if runnerLGPO.scripts[0] != wantLGPO {
		t.Fatalf("lgpo script = %q", runnerLGPO.scripts[0])
	}
	// Inbound action mapping matrix (netsh enum: 0/2/4).
	for _, tc := range []struct{ rules, action, want any }{
		{1, 0, "NotConfigured"},
		{1, 2, "AllowInbound"},
		{1, 4, "BlockInbound"},
		{0, 4, "BlockInboundAlways"},
	} {
		got := inboundTextFirewall(tc.rules, tc.action)
		if got != tc.want {
			t.Fatalf("inbound(%v,%v) = %q want %q", tc.rules, tc.action, got, tc.want)
		}
	}
	if got := outboundTextFirewall(4); got != "BlockOutbound" {
		t.Fatalf("outbound(4) = %q", got)
	}
	if got := outboundTextFirewall(0); got != "NotConfigured" {
		t.Fatalf("outbound(0) = %q", got)
	}
}

func TestWinFirewallGetSettingsValidationAndMissingPowerShell(t *testing.T) {
	rt := winFwRT(&winFwMockRunner{profileJSON: winFwProfileJSON})
	if _, err := (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "bogus"}); err == nil || err.Error() != "Incorrect section: bogus" {
		t.Fatalf("section validation = %v", err)
	}
	if _, err := (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "allprofiles", Section: "state"}); err == nil || err.Error() != "Incorrect profile: allprofiles" {
		t.Fatalf("profile validation = %v", err)
	}
	if _, err := (getSettingsFunc{}).Execute(context.Background(), rt, &getSettingsArgs{Profile: "domain", Section: "state", Store: winFwPtr("cache")}); err == nil || err.Error() != "Incorrect store: cache" {
		t.Fatalf("store validation = %v", err)
	}
	// A non-object profile response (LGPO corruption) keeps Salt's error.
	bad := &winFwMockRunner{profileJSON: `"null"`}
	if _, err := (getSettingsFunc{}).Execute(context.Background(), winFwRT(bad), &getSettingsArgs{Profile: "domain", Section: "state"}); err == nil || err.Error() != "LGPO NETSH: An unknown error occurred" {
		t.Fatalf("lgpo corruption = %v", err)
	}
	// Missing powershell.exe surfaces the launch error (ExitCode -1).
	launch := errors.New("exec: \"powershell.exe\": executable file not found in %PATH%")
	missing := &winFwMockRunner{launchName: "powershell.exe", launchErr: launch}
	_, err := (getSettingsFunc{}).Execute(context.Background(), winFwRT(missing), &getSettingsArgs{Profile: "domain", Section: "state"})
	if err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("missing powershell = %v", err)
	}
	// A failed query (retcode 1) keeps the PowerShell error shape.
	failing := &winFwMockRunner{psRetcode: 1}
	_, err = (getSettingsFunc{}).Execute(context.Background(), winFwRT(failing), &getSettingsArgs{Profile: "domain", Section: "state"})
	if err == nil || !strings.Contains(err.Error(), "PowerShell command failed (exit code 1)") || !strings.Contains(err.Error(), "NetSecurity: refused") {
		t.Fatalf("ps failure = %v", err)
	}
}

func TestWinFirewallGetAllSettingsAndProfiles(t *testing.T) {
	runner := &winFwMockRunner{profileJSON: winFwProfileJSON}
	res, err := (getAllSettingsFunc{}).Execute(context.Background(), winFwRT(runner), &getAllSettingsArgs{Domain: "private"})
	if err != nil {
		t.Fatal(err)
	}
	merged := res.(map[string]any)
	wantKeys := []string{"State", "Inbound", "Outbound", "FileName", "LogAllowedConnections", "LogDroppedConnections", "MaxFileSize",
		"InboundUserNotification", "LocalConSecRules", "LocalFirewallRules", "UnicastResponseToMulticast"}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("merged keys = %v", keys)
	}
	profilesRes, err := (getAllProfilesFunc{}).Execute(context.Background(), winFwRT(runner), &getAllProfilesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profilesRes.(map[string]any)
	if len(profiles) != 3 || profiles["Domain Profile"] == nil || profiles["Private Profile"] == nil || profiles["Public Profile"] == nil {
		t.Fatalf("all profiles = %#v", profiles)
	}
	if len(runner.scripts) != 4 {
		t.Fatalf("scripts = %v", runner.scripts)
	}
	if !strings.Contains(runner.scripts[1], "-Name 'domain'") || !strings.Contains(runner.scripts[2], "-Name 'private'") || !strings.Contains(runner.scripts[3], "-Name 'public'") {
		t.Fatalf("per-profile scripts = %v", runner.scripts)
	}
}

func TestWinFirewallSetFirewallSettingsScripts(t *testing.T) {
	runner := &winFwMockRunner{}
	rt := winFwRT(runner)
	// allowinbound maps to the Salt lgpo_netsh pair.
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), rt, &setFirewallSettingsArgs{Profile: "domain", Inbound: winFwPtr("allowinbound")}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), rt, &setFirewallSettingsArgs{Profile: "domain", Inbound: winFwPtr("blockinboundalways"), Outbound: winFwPtr("allowoutbound")}); err != nil {
		t.Fatal(err)
	}
	// lgpo store switches the splat prefix.
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), rt, &setFirewallSettingsArgs{Profile: "domain", Outbound: winFwPtr("blockoutbound"), Store: winFwPtr("lgpo")}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"$p=@{Name='domain'};$p.AllowInboundRules='NotConfigured';$p.DefaultInboundAction='Allow';Set-NetFirewallProfile @p",
		"$p=@{Name='domain'};$p.DefaultInboundAction='Block';$p.DefaultOutboundAction='Allow';Set-NetFirewallProfile @p",
		"$p=@{PolicyStore='localhost';Name='domain'};$p.DefaultOutboundAction='Block';Set-NetFirewallProfile @p",
	}
	if !reflect.DeepEqual(runner.scripts, want) {
		t.Fatalf("scripts = %q", runner.scripts)
	}
	// Validation ladder with Salt's exact ValueError texts.
	empty := &winFwMockRunner{}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(empty), &setFirewallSettingsArgs{Profile: "domain"}); err == nil || err.Error() != "Must set inbound or outbound" {
		t.Fatalf("empty = %v", err)
	}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(empty), &setFirewallSettingsArgs{Profile: "domain", Inbound: winFwPtr("sideways")}); err == nil || err.Error() != "Incorrect inbound value: sideways" {
		t.Fatalf("inbound value = %v", err)
	}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(empty), &setFirewallSettingsArgs{Profile: "domain", Outbound: winFwPtr("sideways")}); err == nil || err.Error() != "Incorrect outbound value: sideways" {
		t.Fatalf("outbound value = %v", err)
	}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(empty), &setFirewallSettingsArgs{Profile: "domain", Inbound: winFwPtr("notconfigured")}); err == nil || err.Error() != "Cannot set local inbound policies as NotConfigured" {
		t.Fatalf("local notconfigured inbound = %v", err)
	}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(empty), &setFirewallSettingsArgs{Profile: "domain", Outbound: winFwPtr("notconfigured")}); err == nil || err.Error() != "Cannot set local outbound policies as NotConfigured" {
		t.Fatalf("local notconfigured outbound = %v", err)
	}
	if len(empty.calls) != 0 {
		t.Fatalf("validation must not spawn commands: %+v", empty.calls)
	}
	// Boundary pin: unlike set_settings/set_logging_settings (which
	// reject bad profiles via settingStoreArgs → "Incorrect profile"),
	// set_firewall_settings does not validate the profile name — Salt's
	// ValueError branch is not ported — so an invalid profile still
	// emits a Set-NetFirewallProfile script. Pinned as current
	// behavior, not Salt parity.
	pin := &winFwMockRunner{}
	if _, err := (setFirewallSettingsFunc{}).Execute(context.Background(), winFwRT(pin), &setFirewallSettingsArgs{Profile: "badprofile", Inbound: winFwPtr("blockinbound")}); err != nil {
		t.Fatal(err)
	}
	wantPin := []string{"$p=@{Name='badprofile'};$p.DefaultInboundAction='Block';Set-NetFirewallProfile @p"}
	if !reflect.DeepEqual(pin.scripts, wantPin) {
		t.Fatalf("invalid-profile pin scripts = %q", pin.scripts)
	}
}

func TestWinFirewallSetLoggingSettingsScripts(t *testing.T) {
	runner := &winFwMockRunner{}
	rt := winFwRT(runner)
	if _, err := (setLoggingSettingsFunc{}).Execute(context.Background(), rt, &setLoggingSettingsArgs{Profile: "domain", Setting: "allowedconnections", Value: "enable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setLoggingSettingsFunc{}).Execute(context.Background(), rt, &setLoggingSettingsArgs{Profile: "private", Setting: "droppedconnections", Value: "disable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setLoggingSettingsFunc{}).Execute(context.Background(), rt, &setLoggingSettingsArgs{Profile: "domain", Setting: "filename", Value: `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setLoggingSettingsFunc{}).Execute(context.Background(), rt, &setLoggingSettingsArgs{Profile: "domain", Setting: "maxfilesize", Value: "2048"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"$p=@{Name='domain'};$p.LogAllowed=true;Set-NetFirewallProfile @p",
		"$p=@{Name='private'};$p.LogBlocked=false;Set-NetFirewallProfile @p",
		`$p=@{Name='domain'};$p.LogFileName='%systemroot%\system32\LogFiles\Firewall\pfirewall.log';Set-NetFirewallProfile @p`,
		"$p=@{Name='domain'};$p.LogMaxSizeKilobytes=2048;Set-NetFirewallProfile @p",
	}
	if !reflect.DeepEqual(runner.scripts, want) {
		t.Fatalf("scripts = %q", runner.scripts)
	}
	// Range/validation ladder (Salt: 1..32767, NotConfigured lgpo-only).
	bad := &winFwMockRunner{}
	badRT := winFwRT(bad)
	for _, tc := range []struct {
		setting, value, wantErr string
	}{
		{"maxfilesize", "0", "Incorrect value: 0"},
		{"maxfilesize", "32768", "Incorrect value: 32768"},
		{"maxfilesize", "big", "Incorrect value: big"},
		{"allowedconnections", "sometimes", "Incorrect value: sometimes"},
		{"allowedconnections", "notconfigured", "NotConfigured only valid when setting Group Policy"},
		{"droppedconnections", "notconfigured", "NotConfigured only valid when setting Group Policy"},
		{"zoom", "enable", "Incorrect setting: zoom"},
	} {
		_, err := (setLoggingSettingsFunc{}).Execute(context.Background(), badRT, &setLoggingSettingsArgs{Profile: "domain", Setting: tc.setting, Value: tc.value})
		if err == nil || err.Error() != tc.wantErr {
			t.Fatalf("%s/%s = %v want %q", tc.setting, tc.value, err, tc.wantErr)
		}
	}
	if len(bad.calls) != 0 {
		t.Fatalf("validation must not spawn commands: %+v", bad.calls)
	}
	// Quote escaping inside the filename literal.
	quoted := &winFwMockRunner{}
	if _, err := (setLoggingSettingsFunc{}).Execute(context.Background(), winFwRT(quoted), &setLoggingSettingsArgs{Profile: "domain", Setting: "filename", Value: "it's.log"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quoted.scripts[0], "$p.LogFileName='it''s.log';") {
		t.Fatalf("escaped filename = %q", quoted.scripts[0])
	}
}

func TestWinFirewallSetSettingsAndStateScripts(t *testing.T) {
	runner := &winFwMockRunner{}
	rt := winFwRT(runner)
	if _, err := (setSettingsFunc{}).Execute(context.Background(), rt, &setSettingsArgs{Profile: "domain", Setting: "localfirewallrules", Value: "enable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setSettingsFunc{}).Execute(context.Background(), rt, &setSettingsArgs{Profile: "domain", Setting: "localconsecrules", Value: "disable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setSettingsFunc{}).Execute(context.Background(), rt, &setSettingsArgs{Profile: "domain", Setting: "unicastresponsetomulticast", Value: "enable", Store: winFwPtr("lgpo")}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"$p=@{Name='domain'};$p.AllowLocalFirewallRules=true;Set-NetFirewallProfile @p",
		"$p=@{Name='domain'};$p.AllowLocalIPsecRules=false;Set-NetFirewallProfile @p",
		"$p=@{PolicyStore='localhost';Name='domain'};$p.AllowUnicastResponseToMulticast=true;Set-NetFirewallProfile @p",
	}
	if !reflect.DeepEqual(runner.scripts, want) {
		t.Fatalf("scripts = %q", runner.scripts)
	}
	if _, err := (setStateFunc{}).Execute(context.Background(), rt, &setStateArgs{Profile: "public", State: "on"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setStateFunc{}).Execute(context.Background(), rt, &setStateArgs{Profile: "public", State: "off"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setStateFunc{}).Execute(context.Background(), rt, &setStateArgs{Profile: "public", State: "notconfigured", Store: winFwPtr("lgpo")}); err != nil {
		t.Fatal(err)
	}
	wantState := append(want,
		"$p=@{Name='public'};$p.Enabled=$true;Set-NetFirewallProfile @p",
		"$p=@{Name='public'};$p.Enabled=$false;Set-NetFirewallProfile @p",
		"$p=@{PolicyStore='localhost';Name='public'};$p.Enabled='NotConfigured';Set-NetFirewallProfile @p",
	)
	if !reflect.DeepEqual(runner.scripts, wantState) {
		t.Fatalf("state scripts = %q", runner.scripts)
	}
	// Validation ladder.
	empty := &winFwMockRunner{}
	emptyRT := winFwRT(empty)
	if _, err := (setSettingsFunc{}).Execute(context.Background(), emptyRT, &setSettingsArgs{Profile: "domain", Setting: "inboundusernotification", Value: "maybe"}); err == nil || err.Error() != "Incorrect value: maybe" {
		t.Fatalf("value validation = %v", err)
	}
	if _, err := (setSettingsFunc{}).Execute(context.Background(), emptyRT, &setSettingsArgs{Profile: "domain", Setting: "remotemanagement", Value: "enable"}); err == nil || err.Error() != "Incorrect setting: remotemanagement" {
		t.Fatalf("setting validation = %v", err)
	}
	if _, err := (setSettingsFunc{}).Execute(context.Background(), emptyRT, &setSettingsArgs{Profile: "domain", Setting: "localfirewallrules", Value: "notconfigured"}); err == nil || err.Error() != "NotConfigured is only valid when setting group policy" {
		t.Fatalf("local notconfigured = %v", err)
	}
	if _, err := (setStateFunc{}).Execute(context.Background(), emptyRT, &setStateArgs{Profile: "domain", State: "sleeping"}); err == nil || err.Error() != "Incorrect state: sleeping" {
		t.Fatalf("state validation = %v", err)
	}
	if _, err := (setStateFunc{}).Execute(context.Background(), emptyRT, &setStateArgs{Profile: "domain", State: "notconfigured"}); err == nil || err.Error() != "NotConfigured is only valid when setting group policy" {
		t.Fatalf("local state notconfigured = %v", err)
	}
	if len(empty.calls) != 0 {
		t.Fatalf("validation must not spawn commands: %+v", empty.calls)
	}
}

func TestWinFirewallTypedBridgeAndRegistryMatrix(t *testing.T) {
	runner := &winFwMockRunner{netshProfiles: winFwNetshProfiles, ruleText: "x"}
	rt := winFwRT(runner)
	// Typed bridges used by the win_firewall state wrapper.
	config, err := GetConfig(context.Background(), rt)
	if err != nil || !config["Domain"] {
		t.Fatalf("GetConfig = %v %v", config, err)
	}
	if _, err := Disable(context.Background(), rt, "domainprofile"); err != nil {
		t.Fatal(err)
	}
	if _, err := Enable(context.Background(), rt, "domainprofile"); err != nil {
		t.Fatal(err)
	}
	exists, err := RuleExists(context.Background(), rt, "any")
	if err != nil || !exists {
		t.Fatalf("RuleExists = %v %v", exists, err)
	}
	if _, err := AddRule(context.Background(), rt, "test", "8080", "tcp", "allow", "in", "any"); err != nil {
		t.Fatal(err)
	}
	argvs := winFwArgvs(runner)
	if got := argvs[len(argvs)-1]; got != "netsh advfirewall firewall add rule name=test protocol=tcp dir=in action=allow remoteip=any localport=8080" {
		t.Fatalf("AddRule argv = %q", got)
	}
	// Registry matrix: every win_firewall public name registers once.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	names := reg.Names()
	sort.Strings(names)
	want := []string{
		"firewall.add_rule", "firewall.delete_rule", "firewall.disable", "firewall.enable",
		"firewall.get_all_profiles", "firewall.get_all_settings", "firewall.get_config", "firewall.get_rule",
		"firewall.get_settings", "firewall.rule_exists", "firewall.set_firewall_settings",
		"firewall.set_logging_settings", "firewall.set_settings", "firewall.set_state",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registry = %v", names)
	}
	if platforms := (setStateFunc{}).Platforms(); len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
