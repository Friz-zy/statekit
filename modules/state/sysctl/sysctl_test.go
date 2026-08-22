package sysctl

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
)

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
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.MkdirAll("/proc/sys/net/ipv4", 0o755)
	rt.FS.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0o644)
	if err := execsysctl.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

func TestSysctlPresentSemantics(t *testing.T) {
	rt, runner := newRT()

	satisfied := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		Name: "net.ipv4.ip_forward", Value: "0",
	})
	if !satisfied.Succeeded() || satisfied.Changed() {
		t.Fatalf("satisfied wrong: %+v", satisfied)
	}

	pending := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		Name: "net.ipv4.ip_forward", Value: "1", Test: true,
	})
	if pending.Result != nil || pending.Comment != "Sysctl net.ipv4.ip_forward would be set to 1" {
		t.Fatalf("pending wrong: %+v", pending)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "sysctl -w") {
			t.Fatal("test mode assigned the value")
		}
	}

	applied := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		Name: "net.ipv4.ip_forward", Value: "1",
	})
	if !applied.Succeeded() || !applied.Changed() {
		t.Fatalf("apply wrong: %+v", applied)
	}
	found := false
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "ip_forward=1") {
			found = true
		}
	}
	if !found {
		t.Fatal("assign was not executed")
	}
}
