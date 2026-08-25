package ini

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const iniFixture = `# top comment
global=keep

[main]
host = old.example.org
port = 5432

[empty]
`

func newRT(initial string) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	if initial != "" {
		rt.FS.MkdirAll("/etc/app", 0o755)
		rt.FS.WriteFile("/etc/app/conf.ini", []byte(initial), 0o644)
	}
	return rt
}

func TestGetOption(t *testing.T) {
	rt := newRT(iniFixture)
	value, err := (getOptionFunc{}).Execute(context.Background(), rt, &GetOptionArgs{
		FileName: "/etc/app/conf.ini", Section: "main", Option: "host",
	})
	if err != nil || value != "old.example.org" {
		t.Fatalf("get_option = %v, %v", value, err)
	}
	value, _ = (getOptionFunc{}).Execute(context.Background(), rt, &GetOptionArgs{
		FileName: "/etc/app/conf.ini", Section: "missing", Option: "host",
	})
	if value != "" {
		t.Fatalf("missing section = %q", value)
	}
}

func TestSetOptionChangesAndIdempotence(t *testing.T) {
	rt := newRT(iniFixture)
	changes, err := (setOptionFunc{}).Execute(context.Background(), rt, &SetOptionArgs{
		FileName: "/etc/app/conf.ini",
		Sections: map[string]any{"main": map[string]any{"host": "new.example.org", "timeout": 30}},
	})
	if err != nil {
		t.Fatalf("set_option: %v", err)
	}
	changeMap := changes.(map[string]any)
	if len(changeMap) != 2 {
		t.Fatalf("changes = %+v", changeMap)
	}
	data, _ := rt.FS.ReadFile("/etc/app/conf.ini")
	rendered := string(data)
	for _, want := range []string{"# top comment", "global = keep", "[main]",
		"host = new.example.org", "port = 5432", "timeout = 30"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered missing %q:\n%s", want, rendered)
		}
	}

	repeat, _ := (setOptionFunc{}).Execute(context.Background(), rt, &SetOptionArgs{
		FileName: "/etc/app/conf.ini",
		Sections: map[string]any{"main": map[string]any{"host": "new.example.org", "timeout": 30}},
	})
	if len(repeat.(map[string]any)) != 0 {
		t.Fatalf("second run must be empty changes: %+v", repeat)
	}
}

func TestRemoveOptionPreservesOthers(t *testing.T) {
	rt := newRT(iniFixture)
	removed, err := (removeOptionFunc{}).Execute(context.Background(), rt, &RemoveOptionArgs{
		FileName: "/etc/app/conf.ini", Section: "main", Options: []string{"port"},
	})
	if err != nil || removed.(map[string]any)["port"] != "5432" {
		t.Fatalf("remove = %v, %v", removed, err)
	}
	data, _ := rt.FS.ReadFile("/etc/app/conf.ini")
	rendered := string(data)
	if strings.Contains(rendered, "5432") || !strings.Contains(rendered, "host = old.example.org") {
		t.Fatalf("remove damaged file:\n%s", rendered)
	}
}

func TestGetIniWholeTree(t *testing.T) {
	value, err := (getIniFunc{}).Execute(context.Background(), newRT(iniFixture), &GetIniArgs{
		FileName: "/etc/app/conf.ini",
	})
	if err != nil {
		t.Fatalf("get_ini: %v", err)
	}
	tree := value.(map[string]map[string]string)
	if tree["main"]["port"] != "5432" {
		t.Fatalf("tree wrong: %+v", tree)
	}
}
