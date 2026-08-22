package service

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
	serviceprovider "github.com/friz-zy/statekit/providers/service"
)

// scriptRunner drives systemctl-style exit codes in order.
type scriptRunner struct {
	script []process.CommandResult
	calls  [][]string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func newRT() (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{Init: "systemd"}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	if err := serviceprovider.Register(rt.Providers); err != nil {
		panic(err)
	}
	if err := execservice.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

func TestRunningStates(t *testing.T) {
	rt, runner := newRT()

	// Already running: systemctl is-active exits 0.
	runner.script = []process.CommandResult{{ExitCode: 0}}
	res := runningFunc{}.Apply(context.Background(), rt, &runningArgs{Name: "nginx"})
	if !res.Succeeded() || res.Changed() {
		t.Fatalf("already running wrong: %+v", res)
	}
	if res.Comment != "The service nginx is already running" {
		t.Fatalf("comment = %q", res.Comment)
	}

	// Stopped + test mode: pending start, no systemctl start issued.
	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{
		{ExitCode: 3}, // is-active -> not running
	}
	pending := runningFunc{}.Apply(context.Background(), rt2, &runningArgs{Name: "nginx", Test: true})
	if pending.Result != nil {
		t.Fatal("test mode must pend")
	}
	if pending.Comment != "Service nginx is set to start" {
		t.Fatalf("Salt test comment mismatch: %q", pending.Comment)
	}
	delta := pending.Changes["service"].(map[string]any)
	if delta["old"] != "stopped" || delta["new"] != "running" {
		t.Fatalf("plan section 9 delta shape wrong: %+v", delta)
	}
	for _, call := range runner2.calls {
		if strings.Contains(strings.Join(call, " "), "start") {
			t.Fatal("test mode started the service")
		}
	}

	// Stopped for real: start runs and is verified.
	rt3, runner3 := newRT()
	runner3.script = []process.CommandResult{
		{ExitCode: 3}, // is-active before
		{ExitCode: 0}, // start
		{ExitCode: 0}, // is-active verify
	}
	applied := runningFunc{}.Apply(context.Background(), rt3, &runningArgs{Name: "nginx"})
	if !applied.Succeeded() || !applied.Changed() {
		t.Fatalf("start result wrong: %+v", applied)
	}
	if applied.Comment != "Service nginx was started" {
		t.Fatalf("started comment = %q", applied.Comment)
	}

	// Start verification failure -> result false.
	rt4, runner4 := newRT()
	runner4.script = []process.CommandResult{
		{ExitCode: 3},
		{ExitCode: 1}, // start fails
	}
	failed := runningFunc{}.Apply(context.Background(), rt4, &runningArgs{Name: "nginx"})
	if failed.Succeeded() {
		t.Fatal("failed start must report result false")
	}
}

func TestDeadEnabledDisabled(t *testing.T) {
	rt, runner := newRT()
	runner.script = []process.CommandResult{{ExitCode: 3}} // not running
	dead := deadFunc{}.Apply(context.Background(), rt, &deadArgs{Name: "nginx"})
	if !dead.Succeeded() || dead.Changed() {
		t.Fatalf("already dead wrong: %+v", dead)
	}

	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{
		{ExitCode: 0}, // is-active -> running
		{ExitCode: 1}, // is-enabled -> disabled already? used by nothing here
	}
	stopPending := deadFunc{}.Apply(context.Background(), rt2, &deadArgs{Name: "nginx", Test: true})
	if stopPending.Result != nil {
		t.Fatal("dead test mode must pend")
	}
	delta := stopPending.Changes["service"].(map[string]any)
	if delta["old"] != "running" || delta["new"] != "stopped" {
		t.Fatalf("dead delta wrong: %+v", delta)
	}

	rt3, runner3 := newRT()
	runner3.script = []process.CommandResult{
		{ExitCode: 1}, // is-enabled -> disabled
	}
	enablePending := enabledFunc{}.Apply(context.Background(), rt3, &enabledArgs{Name: "nginx", Test: true})
	if enablePending.Result != nil {
		t.Fatal("enable test mode must pend")
	}
	runner3.script = []process.CommandResult{
		{ExitCode: 1}, // is-enabled -> disabled
		{ExitCode: 0}, // enable
	}
	enabledApplied := enabledFunc{}.Apply(context.Background(), rt3, &enabledArgs{Name: "nginx"})
	if !enabledApplied.Succeeded() || !enabledApplied.Changed() {
		t.Fatalf("enable applied wrong: %+v", enabledApplied)
	}
}
