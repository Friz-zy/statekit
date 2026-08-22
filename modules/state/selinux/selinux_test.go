package selinux

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execselinux "github.com/friz-zy/statekit/modules/exec/selinux"
)

func newRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	if err := execselinux.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt
}

// On hosts without SELinux tooling getenforce resolves to Disabled; the
// state must refuse runtime transitions involving Disabled (Salt parity).
func TestModeRefusesDisabledTransitions(t *testing.T) {
	rt := newRT()
	res := modeFunc{}.Apply(context.Background(), rt, &modeArgs{Name: "enforcing"})
	if res.Succeeded() {
		t.Fatalf("Disabled->Enforcing must fail at runtime: %+v", res)
	}
	if !strings.Contains(res.Comment, "Disabled") {
		t.Fatalf("comment should explain the boot-config constraint: %q", res.Comment)
	}

	invalid := modeFunc{}.Apply(context.Background(), rt, &modeArgs{Name: "banana"})
	if invalid.Succeeded() || !strings.Contains(invalid.Comment, "invalid mode") {
		t.Fatalf("invalid mode handling wrong: %+v", invalid)
	}
}
