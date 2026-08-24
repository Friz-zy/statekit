package debconfmod

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdebconf "github.com/friz-zy/statekit/modules/exec/debconfmod"
)

// State tests mapped onto saltstack/tests/pytests/unit/states/test_debconfmod.py,
// running against the fully registered exec surface over MemoryFS.

const selectionsFixture = "nullmailer\tshared/mailname\tstring\tserver.domain.tld\n"

type fakeRunner struct {
	calls  [][]string
	stdout map[string]string
	exit   map[string]int
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	key := strings.Join(argv, "\x00")
	if code, ok := f.exit[key]; ok {
		return process.CommandResult{ExitCode: code}
	}
	if out, ok := f.stdout[key]; ok {
		return process.CommandResult{Stdout: []byte(out)}
	}
	return process.CommandResult{}
}

func stateRT(t *testing.T, selectionsOut string) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "debian", Name: "Debian GNU/Linux", Family: facts.FamilyDebian,
		}}),
	}
	if err := execdebconf.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}
	saved := execdebconf.ExportWhichBin()
	execdebconf.SetWhichBin(func(name string) string {
		if name == "debconf-get-selections" {
			return "/usr/bin/debconf-get-selections"
		}
		return ""
	})
	t.Cleanup(func() { execdebconf.SetWhichBin(saved) })

	runner := &fakeRunner{stdout: map[string]string{
		"debconf-get-selections": selectionsOut,
	}}
	rt.Runner = runner
	return rt, runner
}

func TestSetFileTestModeAndFlow(t *testing.T) {
	fn := setFileFunc{}

	rt, _ := stateRT(t, "")
	ret := fn.Apply(context.Background(), rt, &setFileArgs{
		Name: "nullmailer", Source: "salt://pkg.selections", Test: true,
	})
	if ret.Result != nil || ret.Comment != "Debconf selections would have been set." {
		t.Fatalf("test mode = %#v %q", ret.Result, ret.Comment)
	}

	// salt:// source hits the cp.cache_file boundary and fails the flow.
	ret = fn.Apply(context.Background(), rt, &setFileArgs{
		Name: "nullmailer", Source: "salt://pkg.selections",
	})
	if ret.Result == nil || *ret.Result != false {
		t.Fatalf("remote source result = %#v", ret.Result)
	}
	want := `unsupported function "cp.cache_file"`
	if ret.Comment != want {
		t.Fatalf("comment = %q; want %q", ret.Comment, want)
	}

	// Local file flows through to success.
	rt, _ = stateRT(t, "")
	if err := writeFile(rt, "/testbed/in/pkg.selections", "pkg\tq\tstring\tv"); err != nil {
		t.Fatal(err)
	}
	ret = fn.Apply(context.Background(), rt, &setFileArgs{
		Name: "nullmailer", Source: "/testbed/in/pkg.selections",
	})
	if ret.Result == nil || *ret.Result != true ||
		ret.Comment != "Debconf selections were set." {
		t.Fatalf("local flow = %#v %q", ret.Result, ret.Comment)
	}
}

func TestSetStateFlow(t *testing.T) {
	// All answers unchanged.
	rt, _ := stateRT(t, selectionsFixture)
	ret := setFunc{}.Apply(context.Background(), rt, &setArgs{
		Name: "nullmailer",
		Data: map[string]any{
			"shared/mailname": map[string]any{"type": "string", "value": "server.domain.tld"},
		},
	})
	if ret.Result == nil || *ret.Result != true ||
		ret.Comment != "All specified answers are already set" {
		t.Fatalf("unchanged flow = %#v %q", ret.Result, ret.Comment)
	}

	// New answer in test mode records the pending change with result nil;
	// booleans serialize lowercase.
	rt, _ = stateRT(t, "")
	ret = setFunc{}.Apply(context.Background(), rt, &setArgs{
		Name: "dash",
		Data: map[string]any{
			"dash/sh": map[string]any{"type": "boolean", "value": false},
		},
		Test: true,
	})
	if ret.Result != nil {
		t.Fatalf("test result = %#v; want nil", ret.Result)
	}
	if got := ret.Changes["dash/sh"]; got != "New value: false" {
		t.Fatalf("boolean coercion failed: %#v", ret.Changes)
	}

	// Applied change with password hiding.
	rt, _ = stateRT(t, "")
	ret = setFunc{}.Apply(context.Background(), rt, &setArgs{
		Name: "mysql-server",
		Data: map[string]any{
			"mysql/root": map[string]any{"type": "password", "value": "hunter2"},
		},
	})
	if ret.Result == nil || *ret.Result != true {
		t.Fatalf("password flow failed: %s", ret.Comment)
	}
	if ret.Changes["mysql/root"] != "(password hidden)" {
		t.Fatalf("password change = %#v", ret.Changes["mysql/root"])
	}

	// Applied string change records the raw value.
	rt, _ = stateRT(t, "")
	ret = setFunc{}.Apply(context.Background(), rt, &setArgs{
		Name: "nullmailer",
		Data: map[string]any{
			"shared/mailname": map[string]any{"type": "string", "value": "server.domain.tld"},
		},
	})
	if ret.Result == nil || *ret.Result != true ||
		ret.Changes["shared/mailname"] != "server.domain.tld" {
		t.Fatalf("string flow = %#v %#v", ret.Result, ret.Changes)
	}
}

func writeFile(rt *runtime.Runtime, path, content string) error {
	if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
		return err
	}
	return rt.FS.WriteFile(path, []byte(content), 0o644)
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}
