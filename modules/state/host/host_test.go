package host

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
)

const hostsFixture = "127.0.0.1 localhost\n"

func newRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/hosts", []byte(hostsFixture), 0o644)
	if err := exechosts.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt
}

func TestHostPresentLifecycle(t *testing.T) {
	rt := newRT()
	applied := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		IP: "10.0.0.7", Names: []string{"db", "db.local"},
	})
	if !applied.Succeeded() || !applied.Changed() {
		t.Fatalf("apply wrong: %+v", applied)
	}
	data, _ := rt.FS.ReadFile("/etc/hosts")
	if !strings.Contains(string(data), "10.0.0.7") {
		t.Fatalf("entry missing:\n%s", data)
	}

	idempotent := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		IP: "10.0.0.7", Names: []string{"db", "db.local"},
	})
	if !idempotent.Succeeded() || idempotent.Changed() {
		t.Fatalf("idempotent wrong: %+v", idempotent)
	}

	satisfied := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		IP: "10.0.0.7", Names: []string{"db"}, Test: true,
	})
	if !satisfied.Succeeded() || satisfied.Changed() {
		t.Fatalf("satisfied host must succeed without changes: %+v", satisfied)
	}

	addPending := (presentFunc{}).Apply(context.Background(), rt, &presentArgs{
		IP: "10.0.0.8", Names: []string{"cache"}, Test: true,
	})
	if addPending.Result != nil || addPending.Changes["10.0.0.8"] == nil {
		t.Fatalf("new-host test mode must pend with delta: %+v", addPending)
	}
	if _, err := rt.FS.ReadFile("/etc/hosts"); err != nil {
		t.Fatal("hosts vanished")
	}
}

func TestHostAbsent(t *testing.T) {
	rt := newRT()
	gone := (absentFunc{}).Apply(context.Background(), rt, &absentArgs{Name: "nothing"})
	if !gone.Succeeded() {
		t.Fatalf("already-absent wrong: %+v", gone)
	}
}
