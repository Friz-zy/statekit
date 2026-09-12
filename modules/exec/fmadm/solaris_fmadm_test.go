package fmadm

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fmadmFakeRunner struct {
	results         map[string]process.CommandResult
	defaultResult   process.CommandResult
	available       map[string]bool
	availabilityLog []string
	calls           []process.Command
}

func (r *fmadmFakeRunner) CommandAvailable(name string) bool {
	r.availabilityLog = append(r.availabilityLog, name)
	if r.available == nil {
		return true
	}
	return r.available[name]
}

func (r *fmadmFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if result, ok := r.results[key]; ok {
		return result
	}
	return r.defaultResult
}

func newFmadmRuntime(results map[string]process.CommandResult) (*runtime.Runtime, *fmadmFakeRunner) {
	runner := &fmadmFakeRunner{results: results, defaultResult: process.CommandResult{ExitCode: 0}}
	return &runtime.Runtime{Runner: runner}, runner
}

func commandArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func strPtr(value string) *string { return &value }

func TestFmadmRegistrySurfaceAndArgumentContracts(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name  string
		proto any
		names []string
	}{
		{"fmadm.list", ListArgs{}, []string{"after", "before"}},
		{"fmadm.show", ShowArgs{}, []string{"uuid"}},
		{"fmadm.config", ConfigArgs{}, []string{}},
		{"fmadm.load", LoadArgs{}, []string{"path"}},
		{"fmadm.unload", UnloadArgs{}, []string{"module"}},
		{"fmadm.reset", ResetArgs{}, []string{"module", "serd"}},
		{"fmadm.flush", FmriArgs{}, []string{"fmri"}},
		{"fmadm.repaired", FmriArgs{}, []string{"fmri"}},
		{"fmadm.replaced", FmriArgs{}, []string{"fmri"}},
		{"fmadm.acquit", FmriArgs{}, []string{"fmri"}},
		{"fmadm.faulty", FaultyArgs{}, []string{}},
		{"fmadm.healthy", HealthyArgs{}, []string{}},
	}
	for _, row := range want {
		fn, ok := reg.Get(row.name)
		if !ok {
			t.Fatalf("%s is not registered", row.name)
		}
		if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(row.proto) {
			t.Fatalf("%s prototype=%v want=%v", row.name, got, reflect.TypeOf(row.proto))
		}
		gotNames, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(gotNames, row.names) {
			t.Fatalf("%s argument names=%v err=%v want=%v", row.name, gotNames, err, row.names)
		}
		platform, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(platform.Platforms(), []string{"solaris"}) {
			t.Fatalf("%s platforms=%v constrained=%t", row.name, platform, ok)
		}
	}
	if _, ok := reg.Get("fmadm.list_records"); ok {
		t.Fatal("source alias must expose only canonical fmadm.list")
	}
}

func TestFmadmRegistryUnsupportedOnLinux(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux gating assertion does not apply on Solaris")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &fmadmFakeRunner{}
	rt := &runtime.Runtime{Runner: runner}
	_, err := reg.Call(context.Background(), rt, "fmadm.config", &ConfigArgs{})
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Kind != "function" || unsupported.Name != "fmadm.config" {
		t.Fatalf("error=%v, want UnsupportedError", err)
	}
	if len(runner.calls) != 0 || len(runner.availabilityLog) != 0 {
		t.Fatalf("unsupported call reached runner: calls=%v availability=%v", runner.calls, runner.availabilityLog)
	}
}

func assertBoundedShellFree(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell {
		t.Fatal("fmadm command enabled shell execution")
	}
	if command.Timeout <= 0 || command.Timeout > fmadmCommandTimeout {
		t.Fatalf("timeout=%s, want bounded timeout", command.Timeout)
	}
	if command.MaxStdoutBytes <= 0 || command.MaxStdoutBytes > process.MaxCaptureLimit ||
		command.MaxStderrBytes <= 0 || command.MaxStderrBytes > process.MaxCaptureLimit {
		t.Fatalf("output bounds=%d/%d", command.MaxStdoutBytes, command.MaxStderrBytes)
	}
}

func TestFmadmListRecordsExactArgvAndParser(t *testing.T) {
	result := process.CommandResult{ExitCode: 0, Stdout: []byte(
		"TIME UUID EVENT-ID\n" +
			"Jan 01 00:00:00 event-uuid event-id\n" +
			"Jan 02 00:00:00 event-uuid-2 event-id-2\n")}
	rt, runner := newFmadmRuntime(map[string]process.CommandResult{
		"fmdump -t 2024-01-01T00:00:00 -T 2024-01-03T00:00:00": result,
	})
	after, before := "2024-01-01T00:00:00", "2024-01-03T00:00:00"
	args := &ListArgs{After: &after, Before: &before}
	beforeArgs := *args
	got, err := (listFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"time": "Jan 01 00:00:00", "uuid": "event-uuid", "event-id": "event-id"},
		{"time": "Jan 02 00:00:00", "uuid": "event-uuid-2", "event-id": "event-id-2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list=%#v want=%#v", got, want)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{
		"fmdump", "-t", "2024-01-01T00:00:00", "-T", "2024-01-03T00:00:00",
	}) {
		t.Fatalf("argv=%v", commandArgv(runner.calls[0]))
	}
	assertBoundedShellFree(t, runner.calls[0])
	if !reflect.DeepEqual(*args, beforeArgs) {
		t.Fatalf("args mutated: before=%#v after=%#v", beforeArgs, *args)
	}
	if !reflect.DeepEqual(runner.availabilityLog, []string{"fmadm", "fmdump"}) {
		t.Fatalf("which calls=%v", runner.availabilityLog)
	}
}

func TestFmadmShowVerboseFixture(t *testing.T) {
	fixture := "TIME UUID EVENT-ID\n" +
		"Jan 01 00:00:00 event-uuid event-id\n" +
		"  class: fault\n" +
		"  additional detail\n" +
		"TIME UUID EVENT-ID\n" +
		"Jan 02 00:00:00 event-uuid-2 event-id-2\n" +
		"  class: second\n"
	rt, runner := newFmadmRuntime(map[string]process.CommandResult{
		"fmdump -u event-uuid -V": {ExitCode: 0, Stdout: []byte(fixture)},
	})
	got, err := (showFunc{}).Execute(context.Background(), rt, &ShowArgs{UUID: "event-uuid"})
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{
			"time":     "Jan 01 00:00:00",
			"uuid":     "event-uuid",
			"event-id": "event-id",
			"details":  "  class: fault\n  additional detail\n",
		},
		{
			"time":     "Jan 02 00:00:00",
			"uuid":     "event-uuid-2",
			"event-id": "event-id-2",
			"details":  "  class: second\n",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("show=%#v want=%#v", got, want)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{
		"fmdump", "-u", "event-uuid", "-V",
	}) {
		t.Fatalf("argv=%v", commandArgv(runner.calls[0]))
	}
	assertBoundedShellFree(t, runner.calls[0])
}

func TestFmadmConfigExactParserAndRetcode(t *testing.T) {
	fixture := "MODULE VERSION STATE DESCRIPTION\n" +
		"event-management 1.0 online Event management component\n" +
		"software-response 2.0 offline Software response component\n"
	rt, runner := newFmadmRuntime(map[string]process.CommandResult{
		"fmadm config": {ExitCode: 0, Stdout: []byte(fixture)},
	})
	got, err := (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"event-management":  map[string]any{"version": "1.0", "state": "online", "description": "Event management component"},
		"software-response": map[string]any{"version": "2.0", "state": "offline", "description": "Software response component"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config=%#v want=%#v", got, want)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{"fmadm", "config"}) {
		t.Fatalf("argv=%v", commandArgv(runner.calls[0]))
	}
	assertBoundedShellFree(t, runner.calls[0])

	rt, _ = newFmadmRuntime(map[string]process.CommandResult{
		"fmadm config": {ExitCode: 1, Stderr: []byte("permission denied\n")},
	})
	got, err = (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"Error": "error executing fmadm config"}) {
		t.Fatalf("config retcode got=%#v err=%v", got, err)
	}
}

func TestFmadmLoadUnloadResetAndActions(t *testing.T) {
	tests := []struct {
		name string
		args any
		argv []string
	}{
		{"load", &LoadArgs{Path: "/usr/lib/fm/fmd/plugins/demo.so"}, []string{"fmadm", "load", "/usr/lib/fm/fmd/plugins/demo.so"}},
		{"unload", &UnloadArgs{Module: "software-response"}, []string{"fmadm", "unload", "software-response"}},
		{"reset", &ResetArgs{Module: "software-response"}, []string{"fmadm", "reset", "software-response"}},
		{"reset-serd", &ResetArgs{Module: "software-response", Serd: strPtr("serd0")}, []string{"fmadm", "reset", "-s", "serd0", "software-response"}},
		{"flush", &FmriArgs{Fmri: "fmri://demo"}, []string{"fmadm", "flush", "fmri://demo"}},
		{"repaired", &FmriArgs{Fmri: "fmri://demo"}, []string{"fmadm", "repaired", "fmri://demo"}},
		{"replaced", &FmriArgs{Fmri: "fmri://demo"}, []string{"fmadm", "replaced", "fmri://demo"}},
		{"acquit", &FmriArgs{Fmri: "fmri://demo"}, []string{"fmadm", "acquit", "fmri://demo"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := strings.Join(tc.argv, " ")
			rt, runner := newFmadmRuntime(map[string]process.CommandResult{key: {ExitCode: 0}})
			var got any
			var err error
			switch tc.name {
			case "load":
				got, err = (loadFunc{}).Execute(context.Background(), rt, tc.args)
			case "unload":
				got, err = (unloadFunc{}).Execute(context.Background(), rt, tc.args)
			case "reset", "reset-serd":
				got, err = (resetFunc{}).Execute(context.Background(), rt, tc.args)
			case "flush":
				got, err = (flushFunc{}).Execute(context.Background(), rt, tc.args)
			case "repaired":
				got, err = (repairedFunc{}).Execute(context.Background(), rt, tc.args)
			case "replaced":
				got, err = (replacedFunc{}).Execute(context.Background(), rt, tc.args)
			case "acquit":
				got, err = (acquitFunc{}).Execute(context.Background(), rt, tc.args)
			}
			if err != nil || got != true {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), tc.argv) {
				t.Fatalf("argv=%v want=%v", commandArgv(runner.calls[0]), tc.argv)
			}
			assertBoundedShellFree(t, runner.calls[0])

			rt, _ = newFmadmRuntime(map[string]process.CommandResult{key: {ExitCode: 2, Stderr: []byte("operation failed")}})
			switch tc.name {
			case "load":
				got, err = (loadFunc{}).Execute(context.Background(), rt, tc.args)
			case "unload":
				got, err = (unloadFunc{}).Execute(context.Background(), rt, tc.args)
			case "reset", "reset-serd":
				got, err = (resetFunc{}).Execute(context.Background(), rt, tc.args)
			case "flush":
				got, err = (flushFunc{}).Execute(context.Background(), rt, tc.args)
			case "repaired":
				got, err = (repairedFunc{}).Execute(context.Background(), rt, tc.args)
			case "replaced":
				got, err = (replacedFunc{}).Execute(context.Background(), rt, tc.args)
			case "acquit":
				got, err = (acquitFunc{}).Execute(context.Background(), rt, tc.args)
			}
			if err != nil || !reflect.DeepEqual(got, map[string]any{"Error": "operation failed"}) {
				t.Fatalf("retcode got=%#v err=%v", got, err)
			}
		})
	}
}

const faultyFixture = "TIME UUID EVENT-ID\n" +
	"Jan 01 00:00:00 event-uuid event-id-1\n" +
	"Platform: SUNW,Sun-Fire-V240 Chassis_id: chassis-1\n" +
	"ASRU: hc://:product=Sun-Fire-V240\n" +
	"-\n" +
	"TIME UUID EVENT-ID\n" +
	"Jan 02 00:00:00 event-uuid-2 event-id-2\n" +
	"Platform: SUNW,Sun-Fire-V440 Chassis_id: chassis-2\n" +
	"ASRU: hc://:product=Sun-Fire-V440\n"

func TestFmadmFaultyAndHealthySourceQuirks(t *testing.T) {
	rt, runner := newFmadmRuntime(map[string]process.CommandResult{
		"fmadm faulty": {ExitCode: 7, Stdout: []byte(faultyFixture)},
	})
	got, err := (faultyFunc{}).Execute(context.Background(), rt, &FaultyArgs{})
	if err != nil {
		t.Fatal(err)
	}
	faults, ok := got.(map[string]any)
	if !ok || len(faults) != 2 {
		t.Fatalf("faulty=%#v", got)
	}
	first, ok := faults["event-id-1"].(map[string]any)
	if !ok {
		t.Fatalf("first faulty=%#v", faults["event-id-1"])
	}
	if _, present := first["summary"].(map[string]any)["event-id"]; present {
		t.Fatal("event-id leaked into summary")
	}
	fault, ok := first["fault"].(map[string]any)
	if !ok || fault["Platform"] != "SUNW,Sun-Fire-V240" || fault["Chassis_id"] != "chassis-1" {
		t.Fatalf("fault fields=%#v", first["fault"])
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{"fmadm", "faulty"}) {
		t.Fatalf("faulty argv=%v", commandArgv(runner.calls[0]))
	}
	assertBoundedShellFree(t, runner.calls[0])

	rt, _ = newFmadmRuntime(map[string]process.CommandResult{
		"fmadm faulty": {ExitCode: 1},
	})
	got, err = (faultyFunc{}).Execute(context.Background(), rt, &FaultyArgs{})
	if err != nil || got != false {
		t.Fatalf("empty stdout got=%#v err=%v", got, err)
	}

	rt, _ = newFmadmRuntime(map[string]process.CommandResult{"fmadm faulty": {ExitCode: 0}})
	got, err = (healthyFunc{}).Execute(context.Background(), rt, &HealthyArgs{})
	if err != nil || got != true {
		t.Fatalf("healthy empty=%#v err=%v", got, err)
	}
	rt, _ = newFmadmRuntime(map[string]process.CommandResult{"fmadm faulty": {Stdout: []byte(faultyFixture)}})
	got, err = (healthyFunc{}).Execute(context.Background(), rt, &HealthyArgs{})
	if err != nil || got != false {
		t.Fatalf("healthy fault=%#v err=%v", got, err)
	}
}

func TestFmadmParserErrorsAndRunnerBoundaries(t *testing.T) {
	if _, err := parseFmdump("TIME UUID\nshort\n"); err == nil {
		t.Fatal("short fmdump row accepted")
	}
	if _, err := parseFmdumpVerbose("TIME UUID EVENT-ID\nshort\n"); err == nil {
		t.Fatal("short verbose record accepted")
	}
	if _, err := parseFmadmConfig("VERSION STATE DESCRIPTION\n1 online text\n"); err == nil {
		t.Fatal("config without module accepted")
	}
	if _, err := parseFmadmFaulty("TIME UUID EVENT-ID\nJan 01 00:00:00 uuid\nASRU: x\n"); err == nil {
		t.Fatal("faulty record without event-id accepted")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newFmadmRuntime(nil)
	_, err := (configFunc{}).Execute(cancelled, rt, &ConfigArgs{})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 || len(runner.availabilityLog) != 0 {
		t.Fatalf("cancel err=%v calls=%v availability=%v", err, runner.calls, runner.availabilityLog)
	}

	rt, runner = newFmadmRuntime(map[string]process.CommandResult{
		"fmadm config": {ExitCode: 0, Stdout: []byte("x"), StdoutTruncated: true},
	})
	_, err = (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("output limit err=%v calls=%d", err, len(runner.calls))
	}

	runnerErr := errors.New("runner failed")
	rt, runner = newFmadmRuntime(map[string]process.CommandResult{
		"fmadm config": {ExitCode: -1, Err: runnerErr},
	})
	_, err = (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if !errors.Is(err, runnerErr) || len(runner.calls) != 1 {
		t.Fatalf("runner err=%v calls=%d", err, len(runner.calls))
	}
}

func TestFmadmWhichGuardMatchesVirtualGate(t *testing.T) {
	rt, runner := newFmadmRuntime(nil)
	runner.available = map[string]bool{"fmadm": false, "fmdump": true}
	_, err := (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if !errors.Is(err, errFmadmToolsUnavailable) || len(runner.calls) != 0 || !reflect.DeepEqual(runner.availabilityLog, []string{"fmadm"}) {
		t.Fatalf("fmadm missing err=%v calls=%v which=%v", err, runner.calls, runner.availabilityLog)
	}

	rt, runner = newFmadmRuntime(nil)
	runner.available = map[string]bool{"fmadm": true, "fmdump": false}
	_, err = (configFunc{}).Execute(context.Background(), rt, &ConfigArgs{})
	if !errors.Is(err, errFmadmToolsUnavailable) || len(runner.calls) != 0 || !reflect.DeepEqual(runner.availabilityLog, []string{"fmadm", "fmdump"}) {
		t.Fatalf("fmdump missing err=%v calls=%v which=%v", err, runner.calls, runner.availabilityLog)
	}
}

func TestFmadmOutputLimitConstantsRemainFinite(t *testing.T) {
	if fmadmCommandTimeout != 30*time.Second || fmadmOutputLimit != 4<<20 {
		t.Fatalf("bounds changed unexpectedly: timeout=%s output=%d", fmadmCommandTimeout, fmadmOutputLimit)
	}
}
