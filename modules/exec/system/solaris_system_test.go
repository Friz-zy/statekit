package system

// R8.2 mock tests for the Solaris solaris_system virtual system
// surface, mapped onto saltstack/salt/modules/solaris_system.py @
// pinned revision 8b63e700637e: the shutdown argv forms (halt and
// poweroff alias init state 5; reboot uses state 6; delay and message
// map to -g and the trailing broadcast argument), the cmd.run result
// contract (stdout string, completed non-zero retcode remains data), cancellation and
// runner-error boundaries, and the solaris registry matrix. The runner
// only records commands; no real binary runs.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type sunRecordingRunner struct {
	calls   []process.Command
	results []process.CommandResult
}

func (r *sunRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("shutdown: system going down\n")}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func sunSysTestRuntime(runner *sunRecordingRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func sunArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func TestSunSystemArgv(t *testing.T) {
	ctx := context.Background()

	// halt and poweroff alias shutdown (init state 5, no delay).
	runner := &sunRecordingRunner{}
	rt := sunSysTestRuntime(runner)
	got, err := sunHaltFunc{}.Execute(ctx, rt, &sunHaltArgs{})
	if err != nil || got != "shutdown: system going down\n" {
		t.Fatalf("halt = %v err=%v", got, err)
	}
	want := []string{"shutdown", "-i", "5", "-g", "0", "-y"}
	if !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("halt argv = %v, want %v", sunArgv(runner.calls[0]), want)
	}

	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunPoweroffFunc{}).Execute(ctx, rt, &sunPoweroffArgs{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("poweroff argv = %v", sunArgv(runner.calls[0]))
	}

	// init maps the requested runlevel with -g 0.
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunInitFunc{}).Execute(ctx, rt, &sunInitArgs{State: "3"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"shutdown", "-i", "3", "-g", "0", "-y"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("init argv = %v", sunArgv(runner.calls[0]))
	}
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunInitFunc{}).Execute(ctx, rt, &sunInitArgs{State: "s"}); err != nil {
		t.Fatal(err)
	}
	if got := sunArgv(runner.calls[0]); got[2] != "s" {
		t.Fatalf("init s argv = %v", got)
	}

	// reboot: default delay 0, optional delay and broadcast message.
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	got, err = sunRebootFunc{}.Execute(ctx, rt, &sunRebootArgs{})
	if err != nil || got != "shutdown: system going down\n" {
		t.Fatalf("reboot = %v err=%v", got, err)
	}
	if want := []string{"shutdown", "-i", "6", "-g", "0", "-y"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("reboot argv = %v", sunArgv(runner.calls[0]))
	}
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunRebootFunc{}).Execute(ctx, rt, &sunRebootArgs{Delay: "60", Message: "=== system upgraded ==="}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"shutdown", "-i", "6", "-g", "60", "-y", "=== system upgraded ==="}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("reboot delayed argv = %v", sunArgv(runner.calls[0]))
	}

	// shutdown: init state 5 with the same delay/message mapping.
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunShutdownFunc{}).Execute(ctx, rt, &sunShutdownArgs{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"shutdown", "-i", "5", "-g", "0", "-y"}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("shutdown argv = %v", sunArgv(runner.calls[0]))
	}
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunShutdownFunc{}).Execute(ctx, rt, &sunShutdownArgs{Delay: "30", Message: "=== disk replacement ==="}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"shutdown", "-i", "5", "-g", "30", "-y", "=== disk replacement ==="}; !reflect.DeepEqual(sunArgv(runner.calls[0]), want) {
		t.Fatalf("shutdown delayed argv = %v", sunArgv(runner.calls[0]))
	}
}

func TestSunSystemFailureBoundaries(t *testing.T) {
	ctx := context.Background()

	// cmd.run uses raise_err=False: every system verb returns stdout even
	// when the completed command has a non-zero exit and no stderr.
	verbs := []struct {
		name string
		run  func(context.Context, *runtime.Runtime) (any, error)
	}{
		{"halt", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (sunHaltFunc{}).Execute(ctx, rt, &sunHaltArgs{})
		}},
		{"init", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (sunInitFunc{}).Execute(ctx, rt, &sunInitArgs{State: "3"})
		}},
		{"poweroff", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (sunPoweroffFunc{}).Execute(ctx, rt, &sunPoweroffArgs{})
		}},
		{"reboot", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (sunRebootFunc{}).Execute(ctx, rt, &sunRebootArgs{})
		}},
		{"shutdown", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (sunShutdownFunc{}).Execute(ctx, rt, &sunShutdownArgs{})
		}},
	}
	for _, verb := range verbs {
		runner := &sunRecordingRunner{results: []process.CommandResult{{
			ExitCode: 1,
			Stdout:   []byte("not super-user\n"),
		}}}
		rt := sunSysTestRuntime(runner)
		got, err := verb.run(ctx, rt)
		if err != nil || got != "not super-user\n" {
			t.Fatalf("%s non-zero = %v err=%v, want stdout data", verb.name, got, err)
		}
	}

	// Runner errors propagate.
	runner := &sunRecordingRunner{results: []process.CommandResult{{Err: errors.New("exec: shutdown not found"), ExitCode: -1}}}
	rt := sunSysTestRuntime(runner)
	if _, err := (sunHaltFunc{}).Execute(ctx, rt, &sunHaltArgs{}); err == nil {
		t.Fatal("runner error must propagate")
	}

	// Cancellation is checked before the Runner starts.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &sunRecordingRunner{}
	rt = sunSysTestRuntime(runner)
	if _, err := (sunShutdownFunc{}).Execute(canceled, rt, &sunShutdownArgs{}); err == nil {
		t.Fatal("canceled context must error")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled context spawned %#v", runner.calls)
	}
}

// ---------------------------------------------------------------------------
// registry matrix

var sunSystemRegistryNames = []string{
	"system.halt",
	"system.init",
	"system.poweroff",
	"system.reboot",
	"system.shutdown",
}

func TestSunSystemRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(sunSystemRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(sunSystemRegistryNames))
	}
	for _, name := range sunSystemRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from solaris registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "solaris" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s does not support solaris", name)
		}
		if runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}
	if runtime.CurrentGOOS() != "solaris" && len(reg.Names()) != 0 {
		t.Fatalf("host registry leaked solaris system names: %v", reg.Names())
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatalf("duplicate solaris registration accepted")
	}

	// The linux Register path stays canonical: the unconstrained linux
	// surface registers the same five names without solaris gating.
	if runtime.CurrentGOOS() != "solaris" {
		linux := runtime.NewExecRegistry()
		if err := Register(linux); err != nil {
			t.Fatal(err)
		}
		names := linux.Names()
		if !reflect.DeepEqual(names, sunSystemRegistryNames) {
			t.Fatalf("linux system names = %v", names)
		}
	}
}
