//go:build darwin

package service

// R6.11 mock tests for the mac_service surface, mapped onto
// saltstack/salt/modules/mac_service.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_service.py: launchctl
// print-disabled parsing (including uppercase and near-miss names),
// status semantics for always-running services, KeepAlive PathState
// variants, salt-* alias resolution, restart bootstrap/bootout
// sequences, the launchctl failure shape, LaunchAgent gui domains and
// the plist parser. All Runner output is scripted; this file compiles
// and runs only on Darwin (verified off-platform via GOOS=darwin
// go test -c).

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// macServiceMockRunner scripts launchctl subcommands.
type macServiceMockRunner struct {
	listNamedOut     string // launchctl list <label>
	listAllOut       string
	printDisabledOut string
	failSub          string // subcommand forced to a nonzero retcode
	failCode         int
	calls            []process.Command
}

func (r *macServiceMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "launchctl" || len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	if command.Args[0] == r.failSub {
		return process.CommandResult{ExitCode: r.failCode, Stderr: []byte("launchctl: boom")}
	}
	switch command.Args[0] {
	case "list":
		if len(command.Args) > 1 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.listNamedOut)}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.listAllOut)}
	case "print-disabled":
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.printDisabledOut)}
	}
	return process.CommandResult{ExitCode: 0}
}

func macServiceMockRuntime(t *testing.T) (*runtime.Runtime, *macServiceMockRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/Library/LaunchDaemons", 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &macServiceMockRunner{}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func macServiceWritePlist(t *testing.T, rt *runtime.Runtime, path, body string) {
	t.Helper()
	if err := rt.FS.MkdirAll(dirName(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dirName(path string) string {
	if index := strings.LastIndex(path, "/"); index > 0 {
		return path[:index]
	}
	return "/"
}

func macServiceArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

const atrunPlist = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>` +
	`<key>Label</key><string>com.apple.atrun</string>` +
	`<key>ProgramArguments</key><array><string>/usr/libexec/atrun</string></array>` +
	`</dict></plist>`

const listWithPID = `{
	"LimitLoadToSessionType" = "System";
	"Label" = "com.apple.atrun";
	"OnDemand" = false;
	"LastExitStatus" = 0;
	"PID" = 218;
	"Program" = "/usr/libexec/atrun";
};`

const listWithoutPID = `{
	"LimitLoadToSessionType" = "System";
	"Label" = "com.apple.atrun";
	"OnDemand" = false;
	"LastExitStatus" = 19968;
	"Program" = "/usr/libexec/atrun";
};`

func TestMacServiceDisabledParsingMatrix(t *testing.T) {
	// pytest test_service_disabled_when_enabled/_when_disabled/
	// _status_upper_case/_srvname_wrong over launchctl print-disabled.
	// Near-miss queries get their own plist label so the line-matching
	// (not the service lookup) is what fails, mirroring the pytest's
	// mocked _get_domain_target.
	cases := []struct {
		name     string
		query    string // existing service label used as the query
		upper    bool   // render the state keyword capitalized
		disabled bool   // state recorded for com.apple.atrun
		want     bool
	}{
		{"enabled", "com.apple.atrun", false, false, false},
		{"disabled", "com.apple.atrun", false, true, true},
		{"upper case status", "com.apple.atrun", true, true, true},
		{"near miss", "com.apple.atru", false, true, false},
		{"short name", "com", false, true, false},
		{"tail name", "apple", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := macServiceMockRuntime(t)
			plist := `<?xml version="1.0"?><plist version="1.0"><dict>` +
				`<key>Label</key><string>` + tc.query + `</string></dict></plist>`
			macServiceWritePlist(t, rt, "/Library/LaunchDaemons/"+tc.query+".plist", plist)
			state := boolText(tc.disabled)
			if tc.upper {
				state = "True"
			}
			runner.printDisabledOut = "disabled services = {\n" +
				"\t\"com.saltstack.salt.minion\" => false\n" +
				"\t\"com.apple.atrun\" => " + state + "\n" +
				"}"
			res, err := macDisabledFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: tc.query})
			if err != nil || res != tc.want {
				t.Fatalf("disabled(%s) = %v %v; want %v", tc.query, res, err, tc.want)
			}
			// enabled is the complement.
			res, err = macEnabledFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: tc.query})
			if err != nil || res != !tc.want {
				t.Fatalf("enabled(%s) = %v %v; want %v", tc.query, res, err, !tc.want)
			}
			// argv targets the full service domain of the query label.
			if got := macServiceArgv(runner.calls[0]); got != "launchctl print-disabled system/"+tc.query {
				t.Fatalf("argv = %q", got)
			}
		})
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestMacServiceStatusSemantics(t *testing.T) {
	// pytest test_service_status_no_service: unknown services report
	// false without touching launchctl.
	rt, runner := macServiceMockRuntime(t)
	res, err := macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "missing"})
	if err != nil || res != false {
		t.Fatalf("missing status = %v %v", res, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("missing status calls = %+v", runner.calls)
	}

	// pytest test_service_status_on_daemon_with_pid: always-running
	// daemon reporting a PID is running.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist",
		strings.Replace(atrunPlist, "<key>ProgramArguments</key>",
			"<key>KeepAlive</key><true/><key>ProgramArguments</key>", 1))
	runner.listNamedOut = listWithPID
	res, err = macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("pid status = %v %v", res, err)
	}

	// always-running daemon with no PID is not running.
	runner.listNamedOut = listWithoutPID
	res, err = macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "com.apple.atrun"})
	if err != nil || res != false {
		t.Fatalf("no-pid keepalive status = %v %v", res, err)
	}

	// pytest test_service_status_on_daemon_with_no_pid_and_not_always_
	// running: a loaded on-demand service is considered running.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.listNamedOut = listWithoutPID
	res, err = macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("on-demand status = %v %v", res, err)
	}

	// pytest test_service_status_on_daemon_with_failing_list_check: a
	// failing launchctl list reports false.
	runner.failSub = "list"
	runner.failCode = 1
	res, err = macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "com.apple.atrun"})
	if err != nil || res != false {
		t.Fatalf("failing list status = %v %v", res, err)
	}

	// the sig lookup stays an explicit port boundary.
	rt, _ = macServiceMockRuntime(t)
	sig := "TERM"
	if _, err := (macStatusFunc{}).Execute(context.Background(), rt, &macStatusArgs{Name: "com.apple.atrun", Sig: &sig}); err == nil ||
		!strings.Contains(err.Error(), "sig lookup is not supported") {
		t.Fatalf("sig boundary = %v", err)
	}
}

func TestMacServiceKeepAliveVariants(t *testing.T) {
	// pytest test_service_keep_alive_* matrix against _always_running.
	plistFor := func(keepAlive string) string {
		return `<?xml version="1.0"?><plist version="1.0"><dict>` +
			`<key>Label</key><string>org.ntp.ntpd</string>` +
			`<key>ProgramArguments</key><array><string>/usr/libexec/ntpd-wrapper</string></array>` +
			keepAlive +
			`</dict></plist>`
	}
	pathState := func(value string) string {
		return `<key>KeepAlive</key><dict><key>PathState</key><dict>` +
			`<key>/private/etc/ntp.conf</key><` + value + `/></dict></dict>`
	}
	cases := []struct {
		name      string
		keepAlive string
		file      bool
		want      bool
	}{
		{"pathstate file present", pathState("true"), true, true},
		{"pathstate file removed", pathState("true"), false, false},
		{"pathstate false file missing", pathState("false"), false, true},
		{"pathstate false file present", pathState("false"), true, false},
		{"empty dict", `<key>KeepAlive</key><dict/>`, false, false},
		{"unknown setting", `<key>KeepAlive</key><dict><key>Doesnotexist</key><dict><key>x</key><true/></dict></dict>`, false, false},
		{"bool true", `<key>KeepAlive</key><true/>`, false, true},
		{"bool false", `<key>KeepAlive</key><false/>`, false, false},
		{"missing", ``, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := macServiceMockRuntime(t)
			macServiceWritePlist(t, rt, "/Library/LaunchDaemons/org.ntp.ntpd.plist", plistFor(tc.keepAlive))
			if tc.file {
				if err := rt.FS.MkdirAll("/private/etc", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := rt.FS.WriteFile("/private/etc/ntp.conf", []byte("server x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := alwaysRunning(rt, "org.ntp.ntpd"); got != tc.want {
				t.Fatalf("alwaysRunning = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestMacServiceSaltAliasResolution(t *testing.T) {
	// pytest test_service_name_change_salt_{minion,master,api,syndic}:
	// salt-* aliases resolve to their com.saltstack.salt labels.
	rt, runner := macServiceMockRuntime(t)
	aliases := map[string]string{
		"salt-minion": "com.saltstack.salt.minion",
		"salt-master": "com.saltstack.salt.master",
		"salt-api":    "com.saltstack.salt.api",
		"salt-syndic": "com.saltstack.salt.syndic",
	}
	for alias, label := range aliases {
		plist := `<?xml version="1.0"?><plist version="1.0"><dict>` +
			`<key>Label</key><string>` + label + `</string>` +
			`<key>KeepAlive</key><true/>` +
			`<key>ProgramArguments</key><array><string>/opt/salt/bin/start-` + alias + `.sh</string></array>` +
			`</dict></plist>`
		macServiceWritePlist(t, rt, "/Library/LaunchDaemons/"+label+".plist", plist)
	}
	runner.listNamedOut = listWithPID
	for alias, label := range aliases {
		res, err := macShowFunc{}.Execute(context.Background(), rt, &macShowArgs{Name: alias})
		if err != nil {
			t.Fatal(err)
		}
		service := res.(map[string]any)
		if got := service["file_path"]; got != "/Library/LaunchDaemons/"+label+".plist" {
			t.Fatalf("show(%s) = %v", alias, got)
		}
		res, err = macAvailableFunc{}.Execute(context.Background(), rt, &macAvailableArgs{Name: alias})
		if err != nil || res != true {
			t.Fatalf("available(%s) = %v %v", alias, res, err)
		}
	}
	// status flows through the alias to launchctl list with the label.
	res, err := macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "salt-minion"})
	if err != nil || res != true {
		t.Fatalf("alias status = %v %v", res, err)
	}
	if got := macServiceArgv(runner.calls[len(runner.calls)-1]); got != "launchctl list com.saltstack.salt.minion" {
		t.Fatalf("alias list argv = %q", got)
	}
}

func TestMacServiceRestartSequences(t *testing.T) {
	// pytest test_service_restart_already_loaded: loaded -> stop+start.
	rt, runner := macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.listNamedOut = listWithPID
	res, err := macRestartFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("loaded restart = %v %v", res, err)
	}
	want := []string{
		"launchctl list com.apple.atrun",
		"launchctl bootout system /Library/LaunchDaemons/com.apple.atrun.plist",
		"launchctl bootstrap system /Library/LaunchDaemons/com.apple.atrun.plist",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("loaded restart calls = %+v", runner.calls)
	}
	for i, argv := range want {
		if got := macServiceArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}

	// pytest test_service_restart_not_loaded: no bootout when unloaded.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.failSub = "list"
	runner.failCode = 1
	res, err = macRestartFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("unloaded restart = %v %v", res, err)
	}
	want = []string{
		"launchctl list com.apple.atrun",
		"launchctl bootstrap system /Library/LaunchDaemons/com.apple.atrun.plist",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("unloaded restart calls = %+v", runner.calls)
	}
	for i, argv := range want {
		if got := macServiceArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}

	// pytest test_service_restart_failed_stop: a failing bootout errors.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.listNamedOut = listWithPID
	runner.failSub = "bootout"
	runner.failCode = 1
	if _, err := (macRestartFunc{}).Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.apple.atrun"}); err == nil {
		t.Fatal("failed bootout must error")
	}
}

func TestMacServiceLaunchctlFailureShapeAndBootout36(t *testing.T) {
	rt, runner := macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.failSub = "list"
	runner.failCode = 2
	_, err := macListFunc{}.Execute(context.Background(), rt, &macListArgs{Name: stringPtr("com.apple.atrun")})
	if err == nil {
		t.Fatal("failing list must error")
	}
	// Salt mac_service.launchctl error shape: subcommand, stdout,
	// stderr and retcode all rendered.
	want := "Failed to list service:\nstdout: \nstderr: launchctl: boom\nretcode: 2"
	if err.Error() != want {
		t.Fatalf("error = %q; want %q", err.Error(), want)
	}
	// sub_cmd passthrough with return_stdout keeps stdout on success.
	runner.failSub = ""
	runner.listNamedOut = listWithPID
	res, err := macLaunchctlFunc{}.Execute(context.Background(), rt, &macLaunchctlArgs{
		SubCmd: "list", Args: []string{"com.apple.atrun"}, ReturnStdout: true,
	})
	if err != nil || res != listWithPID {
		t.Fatalf("launchctl passthrough = %v %v", res, err)
	}
	// a runas request is refused before any launchctl call.
	user := "alice"
	if _, err := (macLaunchctlFunc{}).Execute(context.Background(), rt, &macLaunchctlArgs{SubCmd: "list", Runas: &user}); err == nil ||
		!strings.Contains(err.Error(), "runas is not supported") {
		t.Fatalf("runas = %v", err)
	}

	// bootout retcode 36 (already unloaded) is tolerated as success.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.failSub = "bootout"
	runner.failCode = 36
	res, err = macStopFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("bootout 36 = %v %v", res, err)
	}
}

func TestMacServiceDomainTargets(t *testing.T) {
	// LaunchDaemons use the system domain; enable/disable target the
	// label-suffixed domain, start/stop the path form.
	rt, runner := macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	if _, err := (macEnableFunc{}).Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.apple.atrun"}); err != nil {
		t.Fatal(err)
	}
	if got := macServiceArgv(runner.calls[0]); got != "launchctl enable system/com.apple.atrun" {
		t.Fatalf("daemon enable argv = %q", got)
	}

	// LaunchAgents use gui/<console uid>; without a config.option
	// provider the uid defaults to 0.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Users/alice/Library/LaunchAgents/com.example.agent.plist",
		`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.example.agent</string></dict></plist>`)
	if _, err := (macStartFunc{}).Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.agent"}); err != nil {
		t.Fatal(err)
	}
	want := "launchctl bootstrap gui/0 /Users/alice/Library/LaunchAgents/com.example.agent.plist"
	if got := macServiceArgv(runner.calls[0]); got != want {
		t.Fatalf("agent start argv = %q; want %q", got, want)
	}

	// a config.option provider feeds the console uid.
	rt, runner = macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Users/alice/Library/LaunchAgents/com.example.agent.plist",
		`<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.example.agent</string></dict></plist>`)
	reg := runtime.NewExecRegistry()
	if err := reg.Register(macServiceConfigStub{value: "501"}); err != nil {
		t.Fatal(err)
	}
	rt.Exec = reg
	if _, err := (macStartFunc{}).Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.agent"}); err != nil {
		t.Fatal(err)
	}
	want = "launchctl bootstrap gui/501 /Users/alice/Library/LaunchAgents/com.example.agent.plist"
	if got := macServiceArgv(runner.calls[0]); got != want {
		t.Fatalf("agent uid argv = %q; want %q", got, want)
	}
}

type macServiceConfigStub struct{ value string }

func (macServiceConfigStub) Name() string { return "config.option" }
func (macServiceConfigStub) Args() any    { return nil }
func (s macServiceConfigStub) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return s.value, nil
}

func TestMacServiceGetEnabledParsing(t *testing.T) {
	rt, runner := macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	runner.listAllOut = "PID\tStatus\tLabel\n" +
		"218\t0\tcom.apple.atrun\n" +
		"-\t0\tcom.apple.atrun\n" +
		"-\t0\tcom.example.other\n" +
		"\n"
	res, err := macGetEnabledFunc{}.Execute(context.Background(), rt, &macGetEnabledArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// header skipped, duplicates deduped, output sorted.
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.atrun", "com.example.other"}) {
		t.Fatalf("get_enabled = %#v", got)
	}
	if got := macServiceArgv(runner.calls[0]); got != "launchctl list" {
		t.Fatalf("list argv = %q", got)
	}
	// get_all merges the launchctl list with discovered plist labels.
	res, err = macGetAllFunc{}.Execute(context.Background(), rt, &macGetAllArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.atrun", "com.example.other"}) {
		t.Fatalf("get_all = %#v", got)
	}
	// service.list without a name passes through the raw output.
	res, err = macListFunc{}.Execute(context.Background(), rt, &macListArgs{})
	if err != nil || !strings.HasPrefix(res.(string), "PID\tStatus\tLabel") {
		t.Fatalf("raw list = %v %v", res, err)
	}
}

func TestMacServicePlistParserUnits(t *testing.T) {
	full := `<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>Label</key><string>com.example.full</string>` +
		`<key>NumberOfFiles</key><integer>100000</integer>` +
		`<key>RunAtLoad</key><true/>` +
		`<key>Disabled</key><false/>` +
		`<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string></array>` +
		`<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>` +
		`</dict></plist>`
	root, err := parseServicePlist([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if root["Label"] != "com.example.full" || root["NumberOfFiles"] != int64(100000) {
		t.Fatalf("scalars = %#v", root)
	}
	if root["RunAtLoad"] != true || root["Disabled"] != false {
		t.Fatalf("bools = %#v", root)
	}
	args, ok := root["ProgramArguments"].([]any)
	if !ok || len(args) != 2 || args[0] != "/bin/sh" {
		t.Fatalf("array = %#v", root["ProgramArguments"])
	}
	keepAlive, ok := root["KeepAlive"].(map[string]any)
	if !ok || keepAlive["SuccessfulExit"] != false {
		t.Fatalf("nested dict = %#v", root["KeepAlive"])
	}

	// unknown elements are rejected with Salt's error text.
	_, err = parseServicePlist([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>k</key><foo>bar</foo></dict></plist>`))
	if err == nil || !strings.Contains(err.Error(), "unsupported service plist element <foo>") {
		t.Fatalf("unsupported element = %v", err)
	}
	// a value without a preceding key is malformed.
	_, err = parseServicePlist([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><string>orphan</string></dict></plist>`))
	if err == nil || !strings.Contains(err.Error(), "value has no key") {
		t.Fatalf("orphan value = %v", err)
	}
	// a non-dict root is rejected.
	_, err = parseServicePlist([]byte(`<?xml version="1.0"?><plist version="1.0"><array><string>x</string></array></plist>`))
	if err == nil || !strings.Contains(err.Error(), "root is not a dictionary") {
		t.Fatalf("array root = %v", err)
	}
}

func TestMacServiceRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"service.available",
		"service.disable",
		"service.disabled",
		"service.enable",
		"service.enabled",
		"service.get_all",
		"service.get_enabled",
		"service.launchctl",
		"service.list",
		"service.loaded",
		"service.missing",
		"service.restart",
		"service.show",
		"service.start",
		"service.stop",
	}
	// This file is darwin-only, so Names() must list the mac surface.
	if !reflect.DeepEqual(reg.Names(), want) {
		t.Fatalf("darwin names = %v", reg.Names())
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
	rt, runner := macServiceMockRuntime(t)
	macServiceWritePlist(t, rt, "/Library/LaunchDaemons/com.apple.atrun.plist", atrunPlist)
	rt.Exec = reg
	res, err := rt.Exec.Call(context.Background(), rt, "service.available", &macAvailableArgs{Name: "com.apple.atrun"})
	if err != nil || res != true {
		t.Fatalf("dispatch = %v %v", res, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("available must not call launchctl, got %+v", runner.calls)
	}
}
