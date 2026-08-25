package environ

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func newRT(initial string) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	if initial != "" {
		rt.FS.MkdirAll("/etc", 0o755)
		rt.FS.WriteFile(etcEnvironment, []byte(initial), 0o644)
	}
	return rt
}

func TestGetAndSetRoundtrip(t *testing.T) {
	rt := newRT("# comment\nLANG=\"en_US.UTF-8\"\nEDITOR=vim\n")

	value, _ := (getFunc{}).Execute(context.Background(), rt, &getArgs{Name: "LANG"})
	if value != "en_US.UTF-8" {
		t.Fatalf("LANG = %v", value)
	}
	value, _ = (getFunc{}).Execute(context.Background(), rt, &getArgs{Name: "MISSING"})
	if value != "" {
		t.Fatalf("missing var = %v", value)
	}

	(setFunc{}).Execute(context.Background(), rt, &setArgs{Name: "LANG", Value: "de_DE.UTF-8"})
	(setFunc{}).Execute(context.Background(), rt, &setArgs{Name: "NEW", Value: "yes"})

	data, _ := rt.FS.ReadFile(etcEnvironment)
	rendered := string(data)
	if strings.Count(rendered, "LANG=") != 1 || !strings.Contains(rendered, `LANG="de_DE.UTF-8"`) {
		t.Fatalf("LANG not upserted:\n%s", rendered)
	}
	if !strings.Contains(rendered, `NEW="yes"`) {
		t.Fatalf("new var missing:\n%s", rendered)
	}
	if !strings.Contains(rendered, "EDITOR=vim") || !strings.Contains(rendered, "# comment") {
		t.Fatalf("existing content damaged:\n%s", rendered)
	}
}
