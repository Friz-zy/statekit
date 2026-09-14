package zoneadm

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zoneadmRecordingRunner struct {
	results []*process.CommandResult
	calls   []process.Command
	cancel  context.CancelFunc
}

func (r *zoneadmRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	r.calls = append(r.calls, command)
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := *r.results[0]
	r.results = r.results[1:]
	return result
}

func zoneadmRuntime(runner *zoneadmRecordingRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner}
}

func zoneadmArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertZoneadmBounds(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != zoneadmCommandTimeout ||
		command.MaxStdoutBytes != zoneadmOutputLimit ||
		command.MaxStderrBytes != zoneadmOutputLimit ||
		len(command.Stdin) > runtime.MaxCommandInputBytes {
		t.Fatalf("unsafe zoneadm command: %#v", command)
	}
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }

func TestZoneadmDirectSurfaceAndExactArgv(t *testing.T) {
	tests := []struct {
		name string
		fn   runtime.ExecFunction
		args any
		argv []string
	}{
		{"boot", bootFunc{}, &BootArgs{Zone: "12345678-1234-1234-1234-123456789012", Single: true, Altinit: stringPtr("/sbin/init"), SmfOptions: stringPtr("svc")}, []string{"zoneadm", "-u", "12345678-1234-1234-1234-123456789012", "boot", "--", "-m", "svc", "-i", "/sbin/init", "-s"}},
		{"halt early-hyphen UUID-shaped", haltFunc{}, &HaltArgs{Zone: "1234567-81234-1234-1234-123456789012"}, []string{"zoneadm", "-z", "1234567-81234-1234-1234-123456789012", "halt"}},
		{"reboot", rebootFunc{}, &RebootArgs{Zone: "web", Single: true, Altinit: stringPtr("/sbin/init"), SmfOptions: stringPtr("svc")}, []string{"zoneadm", "-z", "web", "reboot", "--", "-m", "svc", "-i", "/sbin/init", "-s"}},
		{"halt", haltFunc{}, &HaltArgs{Zone: "web"}, []string{"zoneadm", "-z", "web", "halt"}},
		{"shutdown", shutdownFunc{}, &ShutdownArgs{Zone: "web", Reboot: true, Single: true, Altinit: stringPtr("/sbin/init"), SmfOptions: stringPtr("svc")}, []string{"zoneadm", "-z", "web", "shutdown", "-r", "--", "-m", "svc", "-i", "/sbin/init", "-s"}},
		{"detach", detachFunc{}, &DetachArgs{Zone: "web"}, []string{"zoneadm", "-z", "web", "detach"}},
		{"attach", attachFunc{}, &AttachArgs{Zone: "web", Force: true, BrandOpts: stringPtr("-x attr=foo")}, []string{"zoneadm", "-z", "web", "attach", "-F", "-x", "attr=foo"}},
		{"ready", readyFunc{}, &ReadyArgs{Zone: "web"}, []string{"zoneadm", "-z", "web", "ready"}},
		{"verify", verifyFunc{}, &VerifyArgs{Zone: "12345678-1234-1234-1234-123456789012"}, []string{"zoneadm", "-z", "12345678-1234-1234-1234-123456789012", "verify"}},
		{"move", moveFunc{}, &MoveArgs{Zone: "web", Zonepath: "/zones/new-web"}, []string{"zoneadm", "-z", "web", "move", "/zones/new-web"}},
		{"uninstall", uninstallFunc{}, &UninstallArgs{Zone: "12345678-1234-1234-1234-123456789012"}, []string{"zoneadm", "-u", "12345678-1234-1234-1234-123456789012", "uninstall", "-F"}},
		{"install", installFunc{}, &InstallArgs{Zone: "web", Nodataset: true, BrandOpts: stringPtr("-x attr=foo")}, []string{"zoneadm", "-z", "web", "install", "-x", "nodataset", "-x", "attr=foo"}},
		{"clone", cloneFunc{}, &CloneArgs{Zone: "web", Source: "base", Snapshot: stringPtr("snap1")}, []string{"zoneadm", "-z", "web", "clone", "-s", "snap1", "base"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte("zoneadm: done")}}}
			got, err := tc.fn.Execute(context.Background(), zoneadmRuntime(runner), tc.args)
			if err != nil || !reflect.DeepEqual(got, map[string]any{"status": true, "message": "done"}) {
				t.Fatalf("result=%#v err=%v", got, err)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(zoneadmArgv(runner.calls[0]), tc.argv) {
				t.Fatalf("argv=%#v want=%#v", zoneadmArgv(runner.calls[0]), tc.argv)
			}
			assertZoneadmBounds(t, runner.calls[0])
		})
	}
}

func TestZoneadmListDefaultsFiltersAndParses(t *testing.T) {
	output := strings.Join([]string{
		"0:global:running:/zones/global:00000000-0000-0000-0000-000000000000:solaris:shared",
		"1:web:installed:/zones/web:11111111-1111-1111-1111-111111111111:solaris:shared",
		"2:configured:configured:/zones/configured:22222222-2222-2222-2222-222222222222:solaris:shared",
		"3:down:shutting_down:/zones/down:33333333-3333-3333-3333-333333333333:solaris:exclusive",
	}, "\n")
	runner := &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
	got, err := (listFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &ListZonesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"down": map[string]any{"zoneid": "3", "state": "shutting_down", "zonepath": "/zones/down", "uuid": "33333333-3333-3333-3333-333333333333", "brand": "solaris", "ip-type": "exclusive"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default list=%#v want=%#v", got, want)
	}

	runner = &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
	got, err = (listFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &ListZonesArgs{
		Verbose: boolPtr(false), Installed: true, Configured: true, HideGlobal: boolPtr(false),
	})
	if err != nil || !reflect.DeepEqual(got, []string{"configured", "down", "global", "web"}) {
		t.Fatalf("expanded list=%#v err=%v", got, err)
	}
	if !reflect.DeepEqual(zoneadmArgv(runner.calls[0]), []string{"zoneadm", "list", "-p", "-c"}) {
		t.Fatalf("list argv=%#v", zoneadmArgv(runner.calls[0]))
	}
}

func TestZoneadmBuildersAndUUIDBoundary(t *testing.T) {
	if got, err := uuidTarget("12345678-1234-1234-1234-123456789012", true); err != nil ||
		!reflect.DeepEqual(got, []string{"-u", "12345678-1234-1234-1234-123456789012"}) {
		t.Fatalf("uuid target=%v err=%v", got, err)
	}
	if got, err := uuidTarget("12345678-1234-1234-1234-123456789012", false); err != nil ||
		!reflect.DeepEqual(got, []string{"-z", "12345678-1234-1234-1234-123456789012"}) {
		t.Fatalf("non-uuid-aware target=%v err=%v", got, err)
	}
	if got, err := bootOptions(true, stringPtr("/sbin/init"), stringPtr("recover verbose")); err != nil ||
		!reflect.DeepEqual(got, []string{"--", "-m", "recover", "verbose", "-i", "/sbin/init", "-s"}) {
		t.Fatalf("boot options=%v err=%v", got, err)
	}
	if got, err := bootOptions(false, nil, nil); err != nil || got != nil {
		t.Fatalf("empty boot options=%v err=%v", got, err)
	}
	if _, err := safeWords("--brand;touch"); !errors.Is(err, errZoneadmInvalidArgument) {
		t.Fatalf("unsafe option error=%v", err)
	}
}

func TestZoneadmRetcodesErrorsAndCancellation(t *testing.T) {
	runner := &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 2, Stderr: []byte("zoneadm: denied")}}}
	got, err := (haltFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &HaltArgs{Zone: "web"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"status": false, "message": "denied"}) {
		t.Fatalf("nonzero result=%#v err=%v", got, err)
	}

	runner = &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 7, Stdout: []byte("ignored")}}}
	got, err = (listFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &ListZonesArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("list failure=%#v err=%v", got, err)
	}

	runner = &zoneadmRecordingRunner{results: []*process.CommandResult{{Err: errors.New("runner failed"), ExitCode: -1}}}
	got, err = (haltFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &HaltArgs{Zone: "web"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "runner failed") {
		t.Fatalf("runner error result=%#v err=%v", got, err)
	}

	runner = &zoneadmRecordingRunner{results: []*process.CommandResult{{StdoutTruncated: true}}}
	got, err = (haltFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &HaltArgs{Zone: "web"})
	if got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit result=%#v err=%v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &zoneadmRecordingRunner{}
	got, err = (haltFunc{}).Execute(ctx, zoneadmRuntime(runner), &HaltArgs{Zone: "web"})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("pre-cancel result=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	ctx, cancel = context.WithCancel(context.Background())
	runner = &zoneadmRecordingRunner{cancel: cancel, results: []*process.CommandResult{{ExitCode: 0}}}
	got, err = (haltFunc{}).Execute(ctx, zoneadmRuntime(runner), &HaltArgs{Zone: "web"})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-cancel result=%#v err=%v", got, err)
	}
}

func TestZoneadmValidationAndMalformedOutputDoNotRun(t *testing.T) {
	cases := []struct {
		name string
		fn   runtime.ExecFunction
		args any
	}{
		{"zone injection", haltFunc{}, &HaltArgs{Zone: "web;touch"}},
		{"path injection", moveFunc{}, &MoveArgs{Zone: "web", Zonepath: "/zones/a;touch"}},
		{"brand injection", attachFunc{}, &AttachArgs{Zone: "web", BrandOpts: stringPtr("-x;touch")}},
		{"snapshot injection", cloneFunc{}, &CloneArgs{Zone: "web", Source: "base", Snapshot: stringPtr("snap;touch")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zoneadmRecordingRunner{}
			got, err := tc.fn.Execute(context.Background(), zoneadmRuntime(runner), tc.args)
			if got != nil || !errors.Is(err, errZoneadmInvalidArgument) || len(runner.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
		})
	}
	runner := &zoneadmRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte("bad:list")}}}
	got, err := (listFunc{}).Execute(context.Background(), zoneadmRuntime(runner), &ListZonesArgs{})
	if got != nil || !errors.Is(err, errZoneadmMalformedList) || len(runner.calls) != 1 {
		t.Fatalf("malformed=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestZoneadmRegistryArgumentsPlatformAndLinuxCLI(t *testing.T) {
	want := map[string]struct {
		prototype any
		arguments []string
	}{
		"zoneadm.list":      {ListZonesArgs{}, []string{"configured", "hide_global", "installed", "verbose"}},
		"zoneadm.boot":      {BootArgs{}, []string{"altinit", "single", "smf_options", "zone"}},
		"zoneadm.reboot":    {RebootArgs{}, []string{"altinit", "single", "smf_options", "zone"}},
		"zoneadm.halt":      {HaltArgs{}, []string{"zone"}},
		"zoneadm.shutdown":  {ShutdownArgs{}, []string{"altinit", "reboot", "single", "smf_options", "zone"}},
		"zoneadm.detach":    {DetachArgs{}, []string{"zone"}},
		"zoneadm.attach":    {AttachArgs{}, []string{"brand_opts", "force", "zone"}},
		"zoneadm.ready":     {ReadyArgs{}, []string{"zone"}},
		"zoneadm.verify":    {VerifyArgs{}, []string{"zone"}},
		"zoneadm.move":      {MoveArgs{}, []string{"zone", "zonepath"}},
		"zoneadm.uninstall": {UninstallArgs{}, []string{"zone"}},
		"zoneadm.install":   {InstallArgs{}, []string{"brand_opts", "nodataset", "zone"}},
		"zoneadm.clone":     {CloneArgs{}, []string{"snapshot", "source", "zone"}},
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(want) {
		t.Fatalf("registry len=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s args=%T want=%T", name, fn.Args(), row.prototype)
		}
		args, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(args, row.arguments) {
			t.Fatalf("%s arguments=%v err=%v want=%v", name, args, err, row.arguments)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) ||
			runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s platform constraint invalid", name)
		}
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}

	if runtime.CurrentGOOS() == "solaris" {
		return
	}
	runner := &zoneadmRecordingRunner{}
	rt := zoneadmRuntime(runner)
	for name := range want {
		if _, err := reg.Call(context.Background(), rt, name, fnArgsForZoneadm(name)); err == nil {
			t.Fatalf("%s unexpectedly ran on Linux", name)
		} else {
			var unsupported *runtime.UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Kind != "function" || unsupported.Name != name {
				t.Fatalf("%s error=%v, want UnsupportedError", name, err)
			}
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Linux unsupported calls reached runner: %#v", runner.calls)
	}
	if len(reg.Names()) != 0 {
		t.Fatalf("Linux registry names=%v", reg.Names())
	}
	app := cli.NewApp("zoneadm-test", func() (*runtime.Runtime, error) {
		rt.Exec = reg
		return rt, nil
	})
	for name := range want {
		if code := app.Run([]string{"exec", name}); code != cli.ExitUnsupported {
			t.Fatalf("CLI %s exit=%d want=%d", name, code, cli.ExitUnsupported)
		}
	}
}

func fnArgsForZoneadm(name string) any {
	switch name {
	case "zoneadm.list":
		return &ListZonesArgs{}
	case "zoneadm.boot":
		return &BootArgs{}
	case "zoneadm.reboot":
		return &RebootArgs{}
	case "zoneadm.halt":
		return &HaltArgs{}
	case "zoneadm.shutdown":
		return &ShutdownArgs{}
	case "zoneadm.detach":
		return &DetachArgs{}
	case "zoneadm.attach":
		return &AttachArgs{}
	case "zoneadm.ready":
		return &ReadyArgs{}
	case "zoneadm.verify":
		return &VerifyArgs{}
	case "zoneadm.move":
		return &MoveArgs{}
	case "zoneadm.uninstall":
		return &UninstallArgs{}
	case "zoneadm.install":
		return &InstallArgs{}
	case "zoneadm.clone":
		return &CloneArgs{}
	default:
		panic("unknown zoneadm test function")
	}
}
