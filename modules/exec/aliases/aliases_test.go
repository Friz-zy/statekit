package aliases

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const aliasesFixture = `# system aliases
postmaster: root
support: alice, bob
`

func newRT(initial string) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	if initial != "" {
		rt.FS.MkdirAll("/etc", 0o755)
		rt.FS.WriteFile(aliasesPath, []byte(initial), 0o644)
	}
	return rt
}

func TestParseAndList(t *testing.T) {
	value, err := listFunc{}.Execute(context.Background(), newRT(aliasesFixture), &ListAliasesArgs{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	m := value.(map[string]any)
	if m["postmaster"] != "root" || m["support"] != "alice,bob" {
		t.Fatalf("list wrong: %+v", m)
	}
}

func TestGetTargetMissingIsEmpty(t *testing.T) {
	value, _ := getTargetFunc{}.Execute(context.Background(), newRT(""), &GetTargetArgs{Alias: "nope"})
	if value != "" {
		t.Fatalf("missing target = %v", value)
	}
}

func TestHasTarget(t *testing.T) {
	rt := newRT(aliasesFixture)
	value, _ := hasTargetFunc{}.Execute(context.Background(), rt, &HasTargetArgs{Alias: "support", Target: "alice"})
	if value != true {
		t.Fatal("alice must be a support target")
	}
	value, _ = hasTargetFunc{}.Execute(context.Background(), rt, &HasTargetArgs{Alias: "support", Target: "carol"})
	if value != false {
		t.Fatal("carol must not be listed")
	}
}

func TestSetTargetAppendAndIdempotent(t *testing.T) {
	rt := newRT(aliasesFixture)

	changed, err := setTargetFunc{}.Execute(context.Background(), rt, &SetTargetArgs{Alias: "support", Target: "carol"})
	if err != nil || changed != true {
		t.Fatalf("set = %v, %v", changed, err)
	}
	data, _ := rt.FS.ReadFile(aliasesPath)
	rendered := string(data)
	if !strings.Contains(rendered, "# system aliases") {
		t.Fatal("comment must survive rewriting")
	}
	if !strings.Contains(rendered, "support: alice, bob, carol") {
		t.Fatalf("target not appended:\n%s", rendered)
	}

	changed, _ = setTargetFunc{}.Execute(context.Background(), rt, &SetTargetArgs{Alias: "support", Target: "carol"})
	if changed != false {
		t.Fatalf("duplicate set must report false, got %v", changed)
	}

	changed, _ = setTargetFunc{}.Execute(context.Background(), rt, &SetTargetArgs{Alias: "abuse", Target: "root"})
	if changed != true {
		t.Fatal("new alias creation failed")
	}
	data, _ = rt.FS.ReadFile(aliasesPath)
	if !strings.Contains(string(data), "abuse: root") {
		t.Fatalf("new alias missing:\n%s", data)
	}
}

func TestRmAlias(t *testing.T) {
	rt := newRT(aliasesFixture)
	removed, _ := rmAliasFunc{}.Execute(context.Background(), rt, &RmAliasArgs{Alias: "postmaster"})
	if removed != true {
		t.Fatal("rm must report removal")
	}
	data, _ := rt.FS.ReadFile(aliasesPath)
	if strings.Contains(string(data), "postmaster") {
		t.Fatalf("alias still present:\n%s", data)
	}
	removed, _ = rmAliasFunc{}.Execute(context.Background(), rt, &RmAliasArgs{Alias: "postmaster"})
	if removed != false {
		t.Fatal("second rm must report false")
	}
}
