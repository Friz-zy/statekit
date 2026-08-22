package sysctl

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

func newRT() (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/proc/sys/net/ipv4", 0o755)
	rt.FS.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0o644)
	return rt, runner
}

func TestShowMapsDotsToProcPath(t *testing.T) {
	rt, _ := newRT()
	value, err := showFunc{}.Execute(context.Background(), rt, &showArgs{Name: "net.ipv4.ip_forward"})
	if err != nil || value != "0" {
		t.Fatalf("show = %v, %v", value, err)
	}
}

func TestAssignRunsAndPersists(t *testing.T) {
	rt, runner := newRT()
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/sysctl.conf", []byte("net.core.somaxconn = 128\n# keep me\n"), 0o644)

	_, err := assignFunc{}.Execute(context.Background(), rt, &assignArgs{
		Name: "net.ipv4.ip_forward", Value: "1", Persist: true,
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	want := "sysctl -w net.ipv4.ip_forward=1"
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != want {
		t.Fatalf("argv = %q want %q", got, want)
	}
	data, _ := rt.FS.ReadFile("/etc/sysctl.conf")
	rendered := string(data)
	if !strings.Contains(rendered, "net.ipv4.ip_forward = 1") {
		t.Fatalf("persist missing new key:\n%s", rendered)
	}
	if !strings.Contains(rendered, "net.core.somaxconn = 128") || !strings.Contains(rendered, "# keep me") {
		t.Fatalf("persist damaged existing content:\n%s", rendered)
	}
}

func TestPersistUpsertsExistingKey(t *testing.T) {
	rt, _ := newRT()
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/sysctl.conf", []byte("net.ipv4.ip_forward = 0\n"), 0o644)
	assignFunc{}.Execute(context.Background(), rt, &assignArgs{
		Name: "net.ipv4.ip_forward", Value: "2", Persist: true,
	})
	data, _ := rt.FS.ReadFile("/etc/sysctl.conf")
	rendered := string(data)
	if strings.Count(rendered, "ip_forward") != 1 || !strings.Contains(rendered, "= 2") {
		t.Fatalf("upsert broken:\n%s", rendered)
	}
}
