package rsync

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct{ calls [][]string }

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: 0}
}

func TestRsyncArgv(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*fakeRunner)
	syncFunc{}.Execute(context.Background(), rt, &SyncArgs{
		Src: "/src/", Dst: "/dst", Delete: true, Opts: []string{"-z"},
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "rsync --delete -z /src/ /dst" {
		t.Fatalf("argv = %q", got)
	}
	syncFunc{}.Execute(context.Background(), rt, &SyncArgs{Src: "/a", Dst: "/b"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "rsync -a /a /b" {
		t.Fatalf("default archive argv = %q", got)
	}
}
