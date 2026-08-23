package pip

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
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
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

func TestPipListFreezeParsing(t *testing.T) {
	rt, _ := newRT()
	runner := rt.Runner.(*fakeRunner)
	runner.script = []process.CommandResult{
		{Stdout: []byte("requests==2.31.0\nurllib3==2.0.7\n"), ExitCode: 0},
	}
	value, err := listFunc{}.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	packages := value.(map[string]string)
	if packages["requests"] != "2.31.0" || packages["urllib3"] != "2.0.7" {
		t.Fatalf("parsed wrong: %+v", packages)
	}
}

func TestPipInstallUpgradeArgv(t *testing.T) {
	rt, runner := newRT()
	installFunc{}.Execute(context.Background(), rt, &InstallArgs{
		Pkg: "requests==2.32.0", Upgrade: true,
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "pip3 install --upgrade requests==2.32.0" {
		t.Fatalf("argv = %q", got)
	}
}
