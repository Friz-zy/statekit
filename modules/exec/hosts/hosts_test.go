package hosts

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const hostsFixture = `127.0.0.1 localhost
# comment
10.0.0.5 web web.local
`

func testRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/hosts", []byte(hostsFixture), 0o644)
	return rt
}

func TestListHosts(t *testing.T) {
	value, err := listFunc{}.Execute(context.Background(), testRT(), &listArgs{})
	if err != nil {
		t.Fatalf("list_hosts: %v", err)
	}
	m := value.(map[string]any)
	if strings.Join(m["10.0.0.5"].([]string), ",") != "web,web.local" {
		t.Fatalf("hosts map wrong: %+v", m)
	}
}

func TestAddAndHasPair(t *testing.T) {
	rt := testRT()
	if _, err := (addFunc{}).Execute(context.Background(), rt, &addArgs{
		IP: "10.0.0.9", Aliases: []string{"db", "db.local"},
	}); err != nil {
		t.Fatalf("add_host: %v", err)
	}
	value, _ := hasPairFunc{}.Execute(context.Background(), rt, &hasPairArgs{IP: "10.0.0.9", Alias: "db"})
	if value != true {
		t.Fatal("has_pair must find new entry")
	}
	data, _ := rt.FS.ReadFile("/etc/hosts")
	rendered := string(data)
	if !strings.Contains(rendered, "10.0.0.9\tdb\tdb.local") {
		t.Fatalf("rendered hosts missing entry:\n%s", rendered)
	}
	if !strings.Contains(rendered, "# comment") {
		t.Fatal("comments must survive rewriting")
	}
}

func TestRmHost(t *testing.T) {
	rt := testRT()
	rmFunc{}.Execute(context.Background(), rt, &rmArgs{IP: "10.0.0.5"})
	data, _ := rt.FS.ReadFile("/etc/hosts")
	if strings.Contains(string(data), "10.0.0.5") {
		t.Fatalf("entry not removed:\n%s", data)
	}
	found, _ := rmFunc{}.Execute(context.Background(), rt, &rmArgs{IP: "10.9.9.9"})
	if found != false {
		t.Fatal("removing absent ip must report false")
	}
}

func TestGetIP(t *testing.T) {
	rt := testRT()
	value, _ := getIPFunc{}.Execute(context.Background(), rt, &getIPArgs{Name: "web"})
	if value != "10.0.0.5" {
		t.Fatalf("get_ip = %v", value)
	}
	value, _ = getIPFunc{}.Execute(context.Background(), rt, &getIPArgs{Name: "missing"})
	if value != "" {
		t.Fatalf("unknown name must be empty, got %v", value)
	}
}
