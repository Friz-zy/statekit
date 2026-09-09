package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperHoldRegistryRuntime(t *testing.T, manager string, runner *zypperLowpkgExecRunner, lockContent string) *runtime.Runtime {
	t.Helper()
	rt := zypperRegistryRuntime(manager, runner)
	if lockContent != "" {
		memory := runtime.NewMemoryFS()
		lockPath := "/target/etc/zypp/locks"
		if err := memory.MkdirAll(path.Dir(lockPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := memory.WriteFile(lockPath, []byte(lockContent), 0o600); err != nil {
			t.Fatal(err)
		}
		rt.FS = memory
	}
	return rt
}

// zypperHoldPlain converts the provider's ordered result into plain maps so
// table comparisons stay shape-exact like the list_locks registry contract.
func zypperHoldPlain(t *testing.T, got any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var plain map[string]any
	if err := json.Unmarshal(encoded, &plain); err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestZypperHoldUnholdProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pkg.hold", "pkg.unhold"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registration count=%d", name, count)
		}
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		strict, ok := fn.(runtime.ProviderArgsStrict)
		if !ok || !strict.ProviderArgsStrict() {
			t.Fatalf("%s is not strict", name)
		}
		if got := reg.ProviderCapabilities(name); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg", "zypperpkg"}) {
			t.Fatalf("%s capabilities=%v", name, got)
		}
	}

	root := "/target"
	rows := []struct {
		name     string
		args     any
		want     map[string]any
		wantArgv []string
		locks    string
	}{
		{
			name:     "pkg.hold",
			args:     &ZypperHoldArgs{Name: zypperRegistryStringPtr("fresh"), Root: zypperRegistryStringPtr(root)},
			want:     map[string]any{"fresh": map[string]any{"name": "fresh", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package fresh is now being held."}},
			wantArgv: []string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "al", "fresh"},
		},
		{
			name:     "pkg.unhold",
			args:     &ZypperHoldArgs{Name: zypperRegistryStringPtr("demo"), Root: zypperRegistryStringPtr(root)},
			want:     map[string]any{"demo": map[string]any{"name": "demo", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package demo is no longer held."}},
			wantArgv: []string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "rl", "demo=1-1"},
			locks:    "solvable_name: demo\nversion: = 1-1\n",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &zypperLowpkgExecRunner{results: []process.CommandResult{{}}}
			rt := zypperHoldRegistryRuntime(t, "zypper", runner, row.locks)
			prototype, err := reg.ResolveArgs(rt, row.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperHoldArgs{}) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"name", "pkgs", "root"}) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			got, err := reg.Call(context.Background(), rt, row.name, row.args)
			if err != nil || !reflect.DeepEqual(zypperHoldPlain(t, got), row.want) {
				t.Fatalf("got=%#v err=%v want=%#v", zypperHoldPlain(t, got), err, row.want)
			}
			if len(runner.commands) != 1 || !reflect.DeepEqual(append([]string{runner.commands[0].Name}, runner.commands[0].Args...), row.wantArgv) {
				t.Fatalf("argv=%#v want=%#v", runner.commands, row.wantArgv)
			}
		})
	}
}

func TestZypperHoldUnholdRegistryStructuredPkgsAndMismatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	root := "/target"
	locked := "solvable_name: pinned\nversion: = 2.0\n"

	runner := &zypperLowpkgExecRunner{results: []process.CommandResult{{}}}
	rt := zypperHoldRegistryRuntime(t, "zypper", runner, locked)
	got, err := reg.Call(context.Background(), rt, "pkg.hold", &ZypperHoldArgs{
		Root: &root,
		Pkgs: []any{map[string]any{"pinned": "9.9"}, map[string]any{"fresh": "1.1"}},
	})
	want := map[string]any{
		"pinned": map[string]any{"name": "pinned", "changes": map[string]any{}, "result": true, "comment": "Package pinned is already set to be held."},
		"fresh":  map[string]any{"name": "fresh", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package fresh is now being held."},
	}
	if err != nil || !reflect.DeepEqual(zypperHoldPlain(t, got), want) {
		t.Fatalf("hold got=%#v err=%v want=%#v", zypperHoldPlain(t, got), err, want)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(append([]string{runner.commands[0].Name}, runner.commands[0].Args...),
		[]string{"zypper", "--non-interactive", "--no-refresh", "--root", root, "al", "fresh=1.1"}) {
		t.Fatalf("argv=%#v", runner.commands)
	}

	mismatchRunner := &zypperLowpkgExecRunner{}
	mismatchRT := zypperHoldRegistryRuntime(t, "zypper", mismatchRunner, locked)
	got, err = reg.Call(context.Background(), mismatchRT, "pkg.unhold", &ZypperHoldArgs{
		Root: &root,
		Pkgs: []any{map[string]any{"pinned": "9.9"}, "fresh"},
	})
	want = map[string]any{
		"pinned": map[string]any{"name": "pinned", "changes": map[string]any{}, "result": false, "comment": "Unable to unhold package pinned as it is held with the other version."},
		"fresh":  map[string]any{"name": "fresh", "changes": map[string]any{}, "result": true, "comment": "Package fresh was already unheld."},
	}
	if err != nil || !reflect.DeepEqual(zypperHoldPlain(t, got), want) || len(mismatchRunner.commands) != 0 {
		t.Fatalf("unhold got=%#v err=%v calls=%d", zypperHoldPlain(t, got), err, len(mismatchRunner.commands))
	}
}

func TestZypperHoldUnholdRegistryBoundaries(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	// Empty targets surface the exact source error before any Runner call.
	runner := &zypperLowpkgExecRunner{}
	rt := zypperHoldRegistryRuntime(t, "zypper", runner, "")
	got, err := reg.Call(context.Background(), rt, "pkg.hold", &ZypperHoldArgs{})
	if got != nil || err == nil || err.Error() != "Name or packages must be specified." || len(runner.commands) != 0 {
		t.Fatalf("empty hold got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	runner = &zypperLowpkgExecRunner{}
	rt = zypperHoldRegistryRuntime(t, "zypper", runner, "")
	got, err = reg.Call(context.Background(), rt, "pkg.unhold", &ZypperHoldArgs{Name: zypperRegistryStringPtr(""), Pkgs: []any{}})
	if got != nil || err == nil || err.Error() != "Name or packages must be specified." || len(runner.commands) != 0 {
		t.Fatalf("empty unhold got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A wrong provider pointer is rejected at the strict registry boundary.
	for _, manager := range []string{"apt", "yum", "dnf", "dnf5"} {
		wrongRunner := &zypperLowpkgExecRunner{}
		wrongRT := zypperHoldRegistryRuntime(t, manager, wrongRunner, "")
		if prototype, err := reg.ResolveArgs(wrongRT, "pkg.hold"); err == nil && reflect.TypeOf(prototype) == reflect.TypeOf(ZypperHoldArgs{}) {
			t.Fatalf("manager=%s unexpectedly resolved zypper shape", manager)
		}
		if got, err := reg.Call(context.Background(), wrongRT, "pkg.hold", &ZypperHoldArgs{Name: zypperRegistryStringPtr("demo")}); got != nil || err == nil || len(wrongRunner.commands) != 0 {
			t.Fatalf("manager=%s got=%#v err=%v calls=%d", manager, got, err, len(wrongRunner.commands))
		}
	}

	// Cancellation propagates before the Runner is touched.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &zypperLowpkgExecRunner{}
	rt = zypperHoldRegistryRuntime(t, "zypper", runner, "")
	if got, err := reg.Call(ctx, rt, "pkg.unhold", &ZypperHoldArgs{Name: zypperRegistryStringPtr("demo")}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Runner failures after the batch abort without fabricated results.
	failing := &zypperLowpkgExecRunner{results: []process.CommandResult{{Err: errors.New("runner failed"), ExitCode: -1}}}
	rt = zypperHoldRegistryRuntime(t, "zypper", failing, "")
	if got, err := reg.Call(context.Background(), rt, "pkg.hold", &ZypperHoldArgs{Name: zypperRegistryStringPtr("demo")}); got != nil || err == nil || len(failing.commands) != 1 {
		t.Fatalf("runner error got=%#v err=%v calls=%d", got, err, len(failing.commands))
	}
}
