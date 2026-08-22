package service

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
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

func newRT(initSystem string) (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Facts:     facts.ForTesting(facts.Overrides{Init: initSystem}),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
		Providers: runtime.NewProviderRegistry(),
	}
	if err := Register(rt.Providers); err != nil {
		panic(err)
	}
	return rt, runner
}

func TestSelectByInitSystem(t *testing.T) {
	rt, _ := newRT("systemd")
	name, err := Select(rt.Facts)
	if err != nil || name != "systemd" {
		t.Fatalf("systemd select = %q, %v", name, err)
	}
	rt, _ = newRT("openrc")
	if name, _ := Select(rt.Facts); name != "openrc" {
		t.Fatalf("openrc select = %q", name)
	}
	rt, _ = newRT("sysvinit")
	if _, err := Select(rt.Facts); err == nil {
		t.Fatal("unsupported init must fail")
	}
}

func TestSystemdUnitSuffix(t *testing.T) {
	rt, runner := newRT("systemd")
	provider, err := Resolve(rt)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := provider.Start(context.Background(), rt, "nginx"); err != nil {
		t.Fatalf("start: %v", err)
	}
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "systemctl start nginx.service" {
		t.Fatalf("start argv = %q", got)
	}
	if err := provider.Start(context.Background(), rt, "custom.service"); err != nil {
		t.Fatalf("start custom: %v", err)
	}
	got = strings.Join(runner.calls[len(runner.calls)-1], " ")
	if !strings.HasSuffix(got, "custom.service") || strings.Contains(got, "service.service") {
		t.Fatalf("existing suffix must be preserved: %q", got)
	}
}

func TestSystemdStatusAndEnabledExitCodes(t *testing.T) {
	rt, runner := newRT("systemd")
	provider, _ := Resolve(rt)

	runner.script = []process.CommandResult{{ExitCode: 0}}
	running, err := provider.Status(context.Background(), rt, "nginx")
	if err != nil || !running {
		t.Fatalf("active status = %v, %v", running, err)
	}

	runner.script = []process.CommandResult{{ExitCode: 3}}
	running, err = provider.Status(context.Background(), rt, "nginx")
	if err != nil || running {
		t.Fatalf("inactive status = %v, %v", running, err)
	}

	runner.script = []process.CommandResult{{ExitCode: 1}}
	enabled, err := provider.Enabled(context.Background(), rt, "nginx")
	if err != nil || enabled {
		t.Fatalf("disabled enabled() = %v, %v", enabled, err)
	}
}

func TestOpenRCEnabledParsing(t *testing.T) {
	rt, runner := newRT("openrc")
	provider, _ := Resolve(rt)
	runner.script = []process.CommandResult{
		{Stdout: []byte(" nginx | default\n sshd | default boot\n"), ExitCode: 0},
	}
	enabled, err := provider.Enabled(context.Background(), rt, "sshd")
	if err != nil || !enabled {
		t.Fatalf("openrc enabled = %v, %v", enabled, err)
	}
	runner.script = []process.CommandResult{
		{Stdout: []byte(" nginx | default\n"), ExitCode: 0},
	}
	enabled, _ = provider.Enabled(context.Background(), rt, "sshd")
	if enabled {
		t.Fatal("absent service must report disabled")
	}
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "rc-update show" {
		t.Fatalf("argv = %q", got)
	}
}
