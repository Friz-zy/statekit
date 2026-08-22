package group

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const groupFixture = `root:x:0:
devs:x:2000:alice,bob
`

type fakeRunner struct {
	calls [][]string
	code  int
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: f.code}
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/group", []byte(groupFixture), 0o644)
	return rt, runner
}

func TestGroupInfo(t *testing.T) {
	rt, _ := newRT()
	value, err := infoFunc{}.Execute(context.Background(), rt, &infoArgs{Name: "devs"})
	if err != nil {
		t.Fatalf("group.info: %v", err)
	}
	info := value.(map[string]any)
	if info["gid"] != "2000" {
		t.Fatalf("gid wrong: %+v", info)
	}
	members := info["members"].([]string)
	if strings.Join(members, ",") != "alice,bob" {
		t.Fatalf("members = %v", members)
	}
}

func TestAddAndDelete(t *testing.T) {
	rt, runner := newRT()
	addFunc{}.Execute(context.Background(), rt, &addArgs{Name: "ops", GID: "3000"})
	if got := strings.Join(runner.calls[0], " "); got != "groupadd -g 3000 ops" {
		t.Fatalf("groupadd argv = %q", got)
	}
	deleteFunc{}.Execute(context.Background(), rt, &deleteArgs{Name: "ops"})
	if got := strings.Join(runner.calls[1], " "); got != "groupdel ops" {
		t.Fatalf("groupdel argv = %q", got)
	}
	chGIDFunc{}.Execute(context.Background(), rt, &chGIDArgs{Name: "ops", GID: "3100"})
	if got := strings.Join(runner.calls[2], " "); got != "groupmod -g 3100 ops" {
		t.Fatalf("groupmod argv = %q", got)
	}
}
