package selinux

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
	rt.FS.MkdirAll("/etc/selinux", 0o755)
	rt.FS.WriteFile(configPath, []byte("# config\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"), 0o644)
	return rt, runner
}

func TestGetenforceFallsBackToDisabled(t *testing.T) {
	rt, _ := newRT()
	value, err := (getenforceFunc{}).Execute(context.Background(), rt, &GetenforceArgs{})
	if err != nil || value != "Disabled" {
		t.Fatalf("getenforce = %v, %v", value, err)
	}
}

func TestSetenforceArgvAndValidation(t *testing.T) {
	rt, runner := newRT()
	mode, err := (setenforceFunc{}).Execute(context.Background(), rt, &SetenforceArgs{Mode: "permissive"})
	if err != nil || mode != "Permissive" {
		t.Fatalf("setenforce = %v, %v", mode, err)
	}
	last := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if last != "setenforce 0" {
		t.Fatalf("argv = %q", last)
	}
	(setenforceFunc{}).Execute(context.Background(), rt, &SetenforceArgs{Mode: "1"})
	last = strings.Join(runner.calls[len(runner.calls)-1], " ")
	if last != "setenforce 1" {
		t.Fatalf("numeric argv = %q", last)
	}
	if _, err := (setenforceFunc{}).Execute(context.Background(), rt, &SetenforceArgs{Mode: "Disabled"}); err == nil {
		t.Fatal("runtime switch to Disabled must fail")
	}
	if _, err := (setenforceFunc{}).Execute(context.Background(), rt, &SetenforceArgs{Mode: "banana"}); err == nil {
		t.Fatal("invalid mode must fail")
	}
}

func TestNormalizeMode(t *testing.T) {
	for input, want := range map[string]string{
		"Enforcing": "Enforcing", "permissive": "Permissive",
		"1": "Enforcing", "0": "Permissive", "disabled": "Disabled",
	} {
		got, err := NormalizeMode(input)
		if err != nil || got != want {
			t.Fatalf("NormalizeMode(%q) = %q, %v", input, got, err)
		}
	}
}
