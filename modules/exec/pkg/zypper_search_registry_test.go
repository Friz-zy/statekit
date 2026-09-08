package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestZypperSearchRegistryPrototypeCapabilityAndCall(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("pkg.search")
	if !ok {
		t.Fatal("pkg.search is not registered")
	}
	if !reflect.DeepEqual(fn.Args(), ZypperSearchArgs{}) {
		t.Fatalf("Args=%#v", fn.Args())
	}
	strict, ok := fn.(runtime.ProviderArgsStrict)
	if !ok || !strict.ProviderArgsStrict() {
		t.Fatal("search must use strict provider arguments")
	}
	if got := reg.ProviderCapabilities("pkg.search"); !reflect.DeepEqual(got, []string{"zypperpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}
	count := 0
	for _, name := range reg.Names() {
		if name == "pkg.search" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("pkg.search registrations=%d", count)
	}

	runner := &zypperLowpkgExecRunner{results: []process.CommandResult{{Stdout: []byte(`<stream><solvable name="demo" edition="1"/></stream>`)}}}
	rt := zypperRegistryRuntime("zypper", runner)
	prototype, err := reg.ResolveArgs(rt, "pkg.search")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperSearchArgs{}) {
		t.Fatalf("prototype=%T err=%v", prototype, err)
	}
	wantNames := []string{"case_sensitive", "conflicts", "criteria", "details", "file_list", "installed_only", "match", "not_installed_only", "obsoletes", "provides", "recommends", "refresh", "requires", "root", "search_descriptions", "suggests"}
	if got, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("argument names=%v err=%v want=%v", got, err, wantNames)
	}

	if got, err := reg.Call(context.Background(), rt, "pkg.search", &YumListUpgradesArgs{}); got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("wrong args got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	got, err := reg.Call(context.Background(), rt, "pkg.search", &ZypperSearchArgs{Criteria: "demo"})
	if err != nil || !reflect.DeepEqual(got, map[string]map[string]string{"demo": {"name": "demo", "edition": "1"}}) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "search", "demo"}
	if got := append([]string{runner.commands[0].Name}, runner.commands[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%#v want=%#v", got, wantArgv)
	}
}

func TestZypperSearchRegistryRejectsAPTAndYUMBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt", "yum"} {
		t.Run(manager, func(t *testing.T) {
			runner := &zypperLowpkgExecRunner{}
			rt := zypperRegistryRuntime(manager, runner)
			prototype, err := reg.ResolveArgs(rt, "pkg.search")
			var unsupported *runtime.UnsupportedError
			if prototype != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" {
				t.Fatalf("resolve prototype=%T err=%v", prototype, err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.search", &ZypperSearchArgs{Criteria: "demo"})
			if got != nil || !errors.As(err, &unsupported) || len(runner.commands) != 0 {
				t.Fatalf("call got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
}
