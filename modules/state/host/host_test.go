package host

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
)

// only() tests mapped onto saltstack/tests/unit/states/test_host.py's
// TestOnly battery.

const hostsFixture = `127.0.0.1 localhost
10.0.0.1 web web.example.com
`

func onlyRT(t *testing.T, content string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
	}
	if err := exechosts.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		if err := rt.FS.WriteFile("/etc/hosts", []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func mustRead(t *testing.T, rt *runtime.Runtime) string {
	t.Helper()
	data, err := rt.FS.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestOnlyAlreadySet(t *testing.T) {
	rt := onlyRT(t, "10.0.0.1 web web.example.com\n")
	ret := onlyFunc{}.Apply(context.Background(), rt, &onlyArgs{
		Name:      "10.0.0.1",
		Hostnames: []any{"web", "web.example.com"},
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("only failed: %s", ret.Comment)
	}
	want := `IP address 10.0.0.1 already set to "web web.example.com"`
	if ret.Comment != want {
		t.Fatalf("comment = %q", ret.Comment)
	}
}

func TestOnlyReplacesExtraHostnames(t *testing.T) {
	rt := onlyRT(t, hostsFixture)
	ret := onlyFunc{}.Apply(context.Background(), rt, &onlyArgs{
		Name:      "10.0.0.1",
		Hostnames: []any{"web"},
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("only failed: %s", ret.Comment)
	}
	content := mustRead(t, rt)
	if strings.Contains(content, "web.example.com") {
		t.Fatalf("stale alias survived:\n%s", content)
	}
	if !strings.Contains(content, "10.0.0.1\t\tweb") {
		t.Fatalf("replacement line missing:\n%s", content)
	}
	if !strings.Contains(content, "127.0.0.1 localhost") {
		t.Fatalf("unrelated entry damaged:\n%s", content)
	}
}

func TestOnlyClearsWhenEmpty(t *testing.T) {
	rt := onlyRT(t, hostsFixture)
	ret := onlyFunc{}.Apply(context.Background(), rt, &onlyArgs{Name: "10.0.0.1"})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("only failed: %s", ret.Comment)
	}
	content := mustRead(t, rt)
	if strings.Contains(content, "10.0.0.1\t") {
		t.Fatalf("entry not cleared:\n%s", content)
	}
	if !strings.Contains(content, "127.0.0.1 localhost") {
		t.Fatalf("unrelated entry damaged:\n%s", content)
	}
}

func TestOnlyTestModeLeavesFileUntouched(t *testing.T) {
	rt := onlyRT(t, hostsFixture)
	ret := onlyFunc{}.Apply(context.Background(), rt, &onlyArgs{
		Name:      "10.0.0.1",
		Hostnames: []any{"web"},
		Test:      true,
	})
	if ret.Result != nil {
		t.Fatalf("test result = %#v; want nil", ret.Result)
	}
	want := `Would change 10.0.0.1 from "web web.example.com" to "web"`
	if ret.Comment != want {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if got := mustRead(t, rt); got != hostsFixture {
		t.Fatalf("test mode mutated the file:\n%s", got)
	}
}
