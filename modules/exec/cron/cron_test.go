package cron

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func testRT(initial string) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/var/spool/cron/crontabs", 0o755)
	if initial != "" {
		rt.FS.WriteFile("/var/spool/cron/crontabs/root", []byte(initial), 0o600)
	}
	return rt
}

func TestListTabClassification(t *testing.T) {
	tab := "# c\nMAILTO=admin@example.org\n0 2 * * * /usr/bin/backup\n@reboot /usr/bin/boot-job\n"
	value, err := (listTabFunc{}).Execute(context.Background(), testRT(tab), &ListTabArgs{User: "root"})
	if err != nil {
		t.Fatalf("list_tab: %v", err)
	}
	grouped := value.(map[string]any)
	crons := strings.Join(toStrings(grouped["crons"]), "|")
	if crons != "0 2 * * * /usr/bin/backup" {
		t.Fatalf("crons = %q", crons)
	}
	if strings.Join(toStrings(grouped["special"]), ",") != "@reboot /usr/bin/boot-job" {
		t.Fatalf("special = %v", grouped["special"])
	}
	if strings.Join(toStrings(grouped["env"]), ",") != "MAILTO=admin@example.org" {
		t.Fatalf("env = %v", grouped["env"])
	}
}

func TestAddAndRmJob(t *testing.T) {
	rt := testRT("")
	(addJobFunc{}).Execute(context.Background(), rt, &AddJobArgs{
		User: "root", Minute: "30", Hour: "4", Command: "/usr/bin/task",
	})
	raw, _ := (rawFunc{}).Execute(context.Background(), rt, &RawArgs{User: "root"})
	if !strings.Contains(raw.(string), "30 4 * * * /usr/bin/task") {
		t.Fatalf("job not written: %q", raw)
	}

	// Duplicate add is a no-op returning the same marker.
	status, _ := (addJobFunc{}).Execute(context.Background(), rt, &AddJobArgs{
		User: "root", Minute: "30", Hour: "4", Command: "/usr/bin/task",
	})
	if status != "new" {
		t.Fatalf("duplicate add status = %v", status)
	}
	raw, _ = (rawFunc{}).Execute(context.Background(), rt, &RawArgs{User: "root"})
	if strings.Count(raw.(string), "/usr/bin/task") != 1 {
		t.Fatalf("duplicate job appended:\n%s", raw)
	}

	(rmJobFunc{}).Execute(context.Background(), rt, &RmJobArgs{
		User: "root", Minute: "30", Hour: "4", Command: "/usr/bin/task",
	})
	raw, _ = (rawFunc{}).Execute(context.Background(), rt, &RawArgs{User: "root"})
	if strings.Contains(raw.(string), "/usr/bin/task") {
		t.Fatalf("job not removed: %q", raw)
	}
	found, _ := (rmJobFunc{}).Execute(context.Background(), rt, &RmJobArgs{
		User: "root", Minute: "0", Hour: "0", Command: "/no/such",
	})
	if found != false {
		t.Fatalf("removing absent job must report false, got %v", found)
	}
}

func TestMissingTabIsEmpty(t *testing.T) {
	value, err := (listTabFunc{}).Execute(context.Background(), testRT(""), &ListTabArgs{User: "nobody"})
	if err != nil {
		t.Fatalf("list on missing tab: %v", err)
	}
	crons := value.(map[string]any)["crons"].([]any)
	if len(crons) != 0 {
		t.Fatalf("crons = %v", crons)
	}
}

func toStrings(v any) []string {
	items := v.([]any)
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.(string)
	}
	return out
}
