package virtualenv

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

func TestVirtualenvCreate(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*fakeRunner)
	createFunc{}.Execute(context.Background(), rt, &CreateArgs{Path: "/venvs/app"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "python3 -m venv /venvs/app" {
		t.Fatalf("argv = %q", got)
	}
	createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/sys", Bin: "python3.12", SystemSitePackages: true,
	})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "python3.12 -m venv --system-site-packages /venvs/sys" {
		t.Fatalf("custom argv = %q", got)
	}
}
