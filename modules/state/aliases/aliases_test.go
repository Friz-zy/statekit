package aliases

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execaliases "github.com/friz-zy/statekit/modules/exec/aliases"
)

const fixture = "postmaster: root\n"

func newRT(initial string) *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	if initial != "" {
		rt.FS.MkdirAll("/etc", 0o755)
		rt.FS.WriteFile("/etc/aliases", []byte(initial), 0o644)
	}
	if err := execaliases.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt
}

func TestPresentLifecycle(t *testing.T) {
	rt := newRT(fixture)
	before, _ := rt.FS.ReadFile("/etc/aliases")

	pending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "abuse", Target: "root", Test: true,
	})
	if pending.Result != nil {
		t.Fatal("test mode must pend")
	}
	after, _ := rt.FS.ReadFile("/etc/aliases")
	if string(before) != string(after) {
		t.Fatal("test mode mutated the aliases file")
	}

	applied := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "abuse", Target: "root"})
	if !applied.Succeeded() || applied.Changes["abuse"] == nil {
		t.Fatalf("apply wrong: %+v", applied)
	}

	noOp := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "abuse", Target: "root"})
	if !noOp.Succeeded() || noOp.Changed() {
		t.Fatalf("noop wrong: %+v", noOp)
	}

	appendPending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "postmaster", Target: "alice", Test: true,
	})
	delta := appendPending.Changes["postmaster"].(map[string]any)
	if delta["old"] != "root" || delta["new"] != "root,alice" {
		t.Fatalf("append delta wrong: %+v", delta)
	}
}

func TestAbsentSemantics(t *testing.T) {
	rt := newRT(fixture)
	gone := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "ghost"})
	if !gone.Succeeded() || gone.Changed() {
		t.Fatalf("already-absent wrong: %+v", gone)
	}

	testRes := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "postmaster", Test: true})
	if testRes.Result != nil || strings.Contains(strings.ToLower(testRes.Comment), "would") == false && testRes.Comment == "" {
		t.Fatalf("test removal wrong: %+v", testRes)
	}
	data, _ := rt.FS.ReadFile("/etc/aliases")
	if !strings.Contains(string(data), "postmaster") {
		t.Fatal("test mode removed alias")
	}
	applied := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "postmaster"})
	if !applied.Succeeded() {
		t.Fatalf("removal failed: %+v", applied)
	}
}
