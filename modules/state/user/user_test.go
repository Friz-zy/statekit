package user

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
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
	rt.FS.WriteFile("/etc/passwd", []byte(passwdFixture), 0o644)
	if err := execuser.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

func TestPresentCreateUpdateNoop(t *testing.T) {
	rt, runner := newRT()

	pending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "bob", UID: "1001", Shell: "/bin/sh", Test: true,
	})
	if pending.Result != nil || pending.Changes["new"] != "bob" {
		t.Fatalf("create test mode wrong: %+v", pending)
	}

	applied := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "bob", UID: "1001", Shell: "/bin/sh",
	})
	if !applied.Succeeded() || applied.Changes["new"] != "bob" {
		t.Fatalf("create wrong: %+v", applied)
	}
	// Simulate useradd having persisted the account.
	rt.FS.WriteFile("/etc/passwd", []byte(
		passwdFixture+"bob:x:1001:1001::/home/bob:/bin/sh\n"), 0o644)

	noOp := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "bob"})
	if !noOp.Succeeded() || noOp.Changed() {
		t.Fatalf("no-op wrong: %+v", noOp)
	}

	updatePending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "alice", Shell: "/bin/bash", Test: true,
	})
	if updatePending.Result != nil {
		t.Fatal("update test mode must pend")
	}
	delta := updatePending.Changes["shell"].(map[string]any)
	if delta["old"] != "/bin/zsh" || delta["new"] != "/bin/bash" {
		t.Fatalf("shell delta wrong: %+v", delta)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "usermod") && len(updatePending.Changes) > 0 {
			continue
		}
	}
	updated := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "alice", Shell: "/bin/bash",
	})
	if !updated.Succeeded() || !updated.Changed() {
		t.Fatalf("update wrong: %+v", updated)
	}
	lastCall := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if lastCall != "usermod -s /bin/bash alice" {
		t.Fatalf("chshell argv = %q", lastCall)
	}
}

func TestAbsentSemantics(t *testing.T) {
	rt, runner := newRT()
	gone := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "ghost"})
	if !gone.Succeeded() || gone.Changed() {
		t.Fatalf("already-absent wrong: %+v", gone)
	}

	testRes := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "alice", Test: true})
	if testRes.Result != nil || testRes.Changes["removed"] != "alice" {
		t.Fatalf("test removal wrong: %+v", testRes)
	}
	data, _ := rt.FS.ReadFile("/etc/passwd")
	if !strings.Contains(string(data), "alice") {
		t.Fatal("test mode removed the user")
	}

	applied := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "alice"})
	if !applied.Succeeded() {
		t.Fatalf("removal failed: %+v", applied)
	}
	lastCall := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if lastCall != "userdel alice" {
		t.Fatalf("userdel argv = %q", lastCall)
	}
}
