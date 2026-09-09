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

func TestZypperLocksProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name      string
		prototype any
		args      any
		want      any
		result    process.CommandResult
		wantArgv  []string
	}{
		{
			name:      "pkg.list_locks",
			prototype: ZypperListLocksArgs{},
			args:      &ZypperListLocksArgs{Root: zypperRegistryStringPtr("/target")},
			want:      map[string]any{"demo": map[string]any{"case_sensitive": "yes"}},
			result:    process.CommandResult{},
		},
		{
			name:      "pkg.clean_locks",
			prototype: ZypperCleanLocksArgs{},
			args:      &ZypperCleanLocksArgs{Root: zypperRegistryStringPtr("/target")},
			want:      map[string]any{"removed": "3"},
			result:    process.CommandResult{Stdout: []byte(`<stream xmlns:p="urn:probe"><p:message>Removed prefixed</p:message><message><?probe Removed 3?></message></stream>`)},
			wantArgv:  []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "cl"},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			fn, ok := reg.Get(row.name)
			if !ok {
				t.Fatalf("missing %s", row.name)
			}
			if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
				t.Fatalf("Args=%T want=%T", fn.Args(), row.prototype)
			}
			strict, ok := fn.(runtime.ProviderArgsStrict)
			if !ok || !strict.ProviderArgsStrict() {
				t.Fatalf("%s is not strict", row.name)
			}
			if got := reg.ProviderCapabilities(row.name); !reflect.DeepEqual(got, []string{"zypperpkg"}) {
				t.Fatalf("capabilities=%v", got)
			}
			if got, err := config.ArgumentNames(row.prototype); err != nil || !reflect.DeepEqual(got, []string{"root"}) {
				t.Fatalf("argument names=%v err=%v", got, err)
			}

			for _, manager := range []string{"apt", "yum"} {
				runner := &zypperLowpkgExecRunner{}
				rt := zypperRegistryRuntime(manager, runner)
				if prototype, err := reg.ResolveArgs(rt, row.name); prototype != nil || err == nil {
					t.Fatalf("manager=%s resolved prototype=%#v err=%v", manager, prototype, err)
				}
				if got, err := reg.Call(context.Background(), rt, row.name, row.args); got != nil || err == nil || len(runner.commands) != 0 {
					t.Fatalf("manager=%s got=%#v err=%v calls=%d", manager, got, err, len(runner.commands))
				}
			}

			runner := &zypperLowpkgExecRunner{results: []process.CommandResult{row.result}}
			rt := zypperRegistryRuntime("zypper", runner)
			memory := runtime.NewMemoryFS()
			lockPath := "/target/etc/zypp/locks"
			if err := memory.MkdirAll(path.Dir(lockPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := memory.WriteFile(lockPath, []byte("solvable_name: demo\ncase_sensitive: yes\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rt.FS = memory
			prototype, err := reg.ResolveArgs(rt, row.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(row.prototype) {
				t.Fatalf("resolved prototype=%T err=%v", prototype, err)
			}
			got, err := reg.Call(context.Background(), rt, row.name, row.args)
			matches := reflect.DeepEqual(got, row.want)
			if row.name == "pkg.list_locks" {
				var gotJSON, wantJSON map[string]any
				gotBytes, gotErr := json.Marshal(got)
				wantBytes, wantErr := json.Marshal(row.want)
				matches = gotErr == nil && wantErr == nil && json.Unmarshal(gotBytes, &gotJSON) == nil && json.Unmarshal(wantBytes, &wantJSON) == nil && reflect.DeepEqual(gotJSON, wantJSON)
			}
			if err != nil || !matches {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, row.want)
			}
			if row.wantArgv != nil {
				if len(runner.commands) != 1 || !reflect.DeepEqual(append([]string{runner.commands[0].Name}, runner.commands[0].Args...), row.wantArgv) {
					t.Fatalf("argv=%#v want=%#v", runner.commands, row.wantArgv)
				}
			} else if len(runner.commands) != 0 {
				t.Fatalf("list_locks unexpectedly called Runner: %#v", runner.commands)
			}
		})
	}

	for _, name := range []string{"pkg.list_locks", "pkg.clean_locks"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registration count=%d", name, count)
		}
	}
}

func TestZypperLocksRegistryRejectsWrongArgsAndCancellation(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &zypperLowpkgExecRunner{}
	rt := zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(context.Background(), rt, "pkg.list_locks", &ZypperCleanLocksArgs{}); got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("wrong list args got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := reg.Call(ctx, rt, "pkg.clean_locks", &ZypperCleanLocksArgs{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("canceled clean args got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	var unsupported *runtime.UnsupportedError
	if _, err := reg.ResolveArgs(zypperRegistryRuntime("apt", &zypperLowpkgExecRunner{}), "pkg.clean_locks"); !errors.As(err, &unsupported) || unsupported.Kind != "provider" {
		t.Fatalf("wrong provider error=%v", err)
	}
}
