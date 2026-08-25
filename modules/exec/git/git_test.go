package git

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
	dirs   []string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	s.dirs = append(s.dirs, cmd.Dir)
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func newRT() (*runtime.Runtime, *scriptRunner) {
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: &scriptRunner{},
		FS:     runtime.NewMemoryFS(),
	}, nil
}

func TestCloneArgvAssembly(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	(cloneFunc{}).Execute(context.Background(), rt, &CloneArgs{
		URL: "https://example.org/r.git", Path: "/srv/r", Depth: 1, Branch: "main",
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	want := "git clone --depth 1 --branch main https://example.org/r.git /srv/r"
	if got != want {
		t.Fatalf("clone argv = %q", got)
	}
}

func TestCurrentRevision(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	runner.script = []process.CommandResult{{Stdout: []byte("abc123\n"), ExitCode: 0}}
	value, err := (currentRevisionFunc{}).Execute(context.Background(), rt, &CurrentRevisionArgs{
		Cwd: "/repo", Short: true,
	})
	if err != nil || value != "abc123" {
		t.Fatalf("revision = %v, %v", value, err)
	}
	last := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if last != "git rev-parse --short HEAD" {
		t.Fatalf("argv = %q", last)
	}
}

func TestCommitNothingToCommitIsFalse(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	runner.script = []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("nothing to commit, working tree clean")},
	}
	result, err := (commitFunc{}).Execute(context.Background(), rt, &CommitArgs{
		Cwd: "/repo", Message: "msg",
	})
	if err != nil || result != false {
		t.Fatalf("nothing-to-commit must return false without error: %v, %v", result, err)
	}
}

func TestFetchDefaultsToOrigin(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptRunner)
	(fetchFunc{}).Execute(context.Background(), rt, &FetchArgs{Cwd: "/repo"})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "git fetch origin" {
		t.Fatalf("fetch argv = %q", got)
	}
}
