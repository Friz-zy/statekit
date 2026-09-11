// Package tests hosts plan-level porting-debt regression tests
// (plans/porting.md §7: PTD-TEST-0001 and PTD-TEST-0002).
package tests

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/process"
)

type recordingRunner struct {
	calls [][]string
}

func (r *recordingRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.calls = append(r.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: 0}
}

// TestBuildRuntimeRegistersSystemPowerFunctions is the PTD-TEST-0001
// regression: BuildRuntime Names contains exactly the five system.*
// functions from system.Register, lookup-only enumeration spawns no
// processes, and default system.reboot runs `shutdown -r now` once.
func TestBuildRuntimeRegistersSystemPowerFunctions(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingRunner{}
	rt.Runner = rec

	var systemNames []string
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "system.") {
			systemNames = append(systemNames, name)
		}
	}
	want := []string{"system.halt", "system.init", "system.poweroff", "system.reboot", "system.shutdown"}
	if !reflect.DeepEqual(systemNames, want) {
		t.Fatalf("system.* names = %v, want %v", systemNames, want)
	}

	if len(rec.calls) != 0 {
		t.Fatalf("lookup-only enumeration spawned %d processes: %v", len(rec.calls), rec.calls)
	}

	proto, err := rt.Exec.ResolveArgs(rt, "system.reboot")
	if err != nil {
		t.Fatal(err)
	}
	value, err := rt.Exec.Call(context.Background(), rt, "system.reboot",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("system.reboot = %v, want true", value)
	}
	if len(rec.calls) != 1 || !reflect.DeepEqual(rec.calls[0], []string{"shutdown", "-r", "now"}) {
		t.Fatalf("runner calls = %v, want one `shutdown -r now`", rec.calls)
	}
}

// TestBuildRuntimeRegistersTestSleepFromOwningPackage is the PTD-TEST-0002
// regression: BuildRuntime resolves test.sleep from the owning
// modules/exec/test registration, invoking length 0 returns success once,
// and no status.test_sleep or duplicate registration exists.
func TestBuildRuntimeRegistersTestSleepFromOwningPackage(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	var testNames []string
	sleepCount := 0
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "test.") {
			testNames = append(testNames, name)
		}
		if name == "test.sleep" {
			sleepCount++
		}
		if strings.HasPrefix(name, "status.test") {
			t.Fatalf("status package leaked test-namespace name %q", name)
		}
	}
	want := []string{"test.echo", "test.ping", "test.sleep"}
	if !reflect.DeepEqual(testNames, want) {
		t.Fatalf("test.* names = %v, want %v", testNames, want)
	}
	if sleepCount != 1 {
		t.Fatalf("test.sleep registered %d times, want exactly 1", sleepCount)
	}

	proto, err := rt.Exec.ResolveArgs(rt, "test.sleep")
	if err != nil {
		t.Fatal(err)
	}
	// Zero-value args mean length 0: the wait fires immediately and the
	// call returns success exactly once.
	value, err := rt.Exec.Call(context.Background(), rt, "test.sleep",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("test.sleep length 0 = %v, want true", value)
	}
}
