package at

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
	calls  []process.Command
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, cmd)
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func TestAtSchedulesViaStdin(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	if _, err := (atFunc{}).Execute(context.Background(), rt, &atArgs{
		Command: "/usr/bin/backup", TimeSpec: "+1min",
	}); err != nil {
		t.Fatalf("at.at: %v", err)
	}
	cmd := runner.calls[len(runner.calls)-1]
	if cmd.Name != "at" || strings.Join(cmd.Args, " ") != "+1min" {
		t.Fatalf("argv wrong: %+v", cmd)
	}
	if string(cmd.Stdin) != "/usr/bin/backup" {
		t.Fatalf("command must be piped via stdin, got %q", cmd.Stdin)
	}
	if _, err := (atFunc{}).Execute(context.Background(), rt, &atArgs{Command: "x"}); err == nil {
		t.Fatal("missing timespec must error")
	}
}

func TestAtqParsesJobs(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	runner.script = []process.CommandResult{
		{Stdout: []byte("12\tSat Aug 22 20:00:00 2026 a vscode\n13\tSun Aug 23 09:00:00 2026 a root\n"), ExitCode: 0},
	}
	jobs, err := (atqFunc{}).Execute(context.Background(), rt, &atqArgs{})
	if err != nil {
		t.Fatalf("atq: %v", err)
	}
	list := jobs.([]any)
	if len(list) != 2 || list[0].(map[string]any)["job"] != "12" {
		t.Fatalf("jobs parsed wrong: %+v", list)
	}
}

func TestAtrm(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	(atrmFunc{}).Execute(context.Background(), rt, &atrmArgs{JobID: "12"})
	if got := runner.calls[len(runner.calls)-1]; got.Name != "atrm" || got.Args[0] != "12" {
		t.Fatalf("atrm argv wrong: %+v", got)
	}
	runner.script = []process.CommandResult{{ExitCode: 1}}
	value, _ := (atrmFunc{}).Execute(context.Background(), rt, &atrmArgs{JobID: "99"})
	if value != false {
		t.Fatal("failed removal must report false")
	}
}
