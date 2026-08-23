package npm

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	script []process.CommandResult
	calls  [][]string
	dirs   []string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	f.dirs = append(f.dirs, cmd.Dir)
	if len(f.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := f.script[0]
	f.script = f.script[1:]
	return next
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	return rt, rt.Runner.(*fakeRunner)
}

func TestNpmInstallLocal(t *testing.T) {
	rt, runner := newRT()
	installFunc{}.Execute(context.Background(), rt, &InstallArgs{
		Pkg: "left-pad@1.0.0", Cwd: "/app",
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "npm install left-pad@1.0.0" {
		t.Fatalf("argv = %q", got)
	}
	if runner.dirs[len(runner.dirs)-1] != "/app" {
		t.Fatalf("cwd not applied")
	}
}

func TestNpmListParses(t *testing.T) {
	rt, runner := newRT()
	runner.script = []process.CommandResult{
		{Stdout: []byte(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`), ExitCode: 0},
	}
	out, err := listFunc{}.Execute(context.Background(), rt, &ListArgs{})
	if err != nil || !strings.Contains(out.(string), "lodash") {
		t.Fatalf("list = %v, %v", out, err)
	}
}
