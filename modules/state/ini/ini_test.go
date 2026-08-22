package ini

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execini "github.com/friz-zy/statekit/modules/exec/ini"
)

const fixture = "[main]\nhost = old\nport = 5432\n"

func newRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc/app", 0o755)
	rt.FS.WriteFile("/etc/app/conf.ini", []byte(fixture), 0o644)
	if err := execini.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt
}

func TestOptionsPresentLifecycle(t *testing.T) {
	rt := newRT()

	pending := optionsPresentFunc{}.Apply(context.Background(), rt, &optionsPresentArgs{
		Name: "/etc/app/conf.ini",
		Data: map[string]any{"main": map[string]any{"host": "new", "port": 5432}},
		Test: true,
	})
	if pending.Result != nil || len(pending.Changes) != 1 {
		// Only "host" differs: port is already 5432 in the fixture.
		t.Fatalf("test mode wrong: %+v", pending)
	}

	applied := optionsPresentFunc{}.Apply(context.Background(), rt, &optionsPresentArgs{
		Name: "/etc/app/conf.ini",
		Data: map[string]any{"main": map[string]any{"host": "new", "port": 5432}},
	})
	if !applied.Succeeded() || len(applied.Changes) != 1 {
		t.Fatalf("apply wrong: %+v", applied)
	}

	noOp := optionsPresentFunc{}.Apply(context.Background(), rt, &optionsPresentArgs{
		Name: "/etc/app/conf.ini",
		Data: map[string]any{"main": map[string]any{"host": "new", "port": 5432}},
	})
	if !noOp.Succeeded() || noOp.Changed() {
		t.Fatalf("noop wrong: %+v", noOp)
	}
	data, _ := rt.FS.ReadFile("/etc/app/conf.ini")
	rendered := string(data)
	for _, want := range []string{"[main]", "host = new", "port = 5432"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in:\n%s", want, rendered)
		}
	}
}

func TestOptionsAbsent(t *testing.T) {
	rt := newRT()
	pending := optionsAbsentFunc{}.Apply(context.Background(), rt, &optionsAbsentArgs{
		Name: "/etc/app/conf.ini", Sections: []string{"main.port"}, Test: true,
	})
	if pending.Result != nil {
		t.Fatal("absent test mode must pend")
	}
	applied := optionsAbsentFunc{}.Apply(context.Background(), rt, &optionsAbsentArgs{
		Name: "/etc/app/conf.ini", Sections: []string{"main.port"},
	})
	if !applied.Succeeded() || applied.Changes["main.port"] == nil {
		t.Fatalf("apply wrong: %+v", applied)
	}
	data, _ := rt.FS.ReadFile("/etc/app/conf.ini")
	if strings.Contains(string(data), "5432") && !strings.Contains(string(data), "old") {
		t.Fatalf("wrong option removed:\n%s", data)
	}
}
