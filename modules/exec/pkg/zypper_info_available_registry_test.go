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

func TestZypperInfoAvailableRegistryPrototypeCapabilityAndCall(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("pkg.info_available")
	if !ok {
		t.Fatal("pkg.info_available is not registered")
	}
	if reflect.TypeOf(fn.Args()) != reflect.TypeOf(ZypperInfoAvailableArgs{}) {
		t.Fatalf("canonical Args type=%T", fn.Args())
	}
	strict, ok := fn.(runtime.ProviderArgsStrict)
	if !ok || !strict.ProviderArgsStrict() {
		t.Fatal("info_available must use strict provider arguments")
	}
	registered := 0
	for _, name := range reg.Names() {
		if name == "pkg.info_available" {
			registered++
		}
	}
	if registered != 1 {
		t.Fatalf("pkg.info_available registrations=%d", registered)
	}
	if got := reg.ProviderCapabilities("pkg.info_available"); !reflect.DeepEqual(got, []string{"zypperpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}

	runner := &zypperLowpkgExecRunner{results: []process.CommandResult{{Stdout: []byte(
		"Information for package demo:\nName: demo\nInstalled: Yes\nStatus: up-to-date\n",
	)}}}
	rt := zypperRegistryRuntime("zypper", runner)
	prototype, err := reg.ResolveArgs(rt, "pkg.info_available")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperInfoAvailableArgs{}) {
		t.Fatalf("prototype=%T err=%v", prototype, err)
	}
	wantNames := []string{"gpgautoimport", "names", "refresh", "repos", "root"}
	if got, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("argument names=%v err=%v want=%v", got, err, wantNames)
	}
	if got, err := reg.Call(context.Background(), rt, "pkg.info_available", &InfoArgs{}); got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("wrong prototype got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	refresh := false
	args := &ZypperInfoAvailableArgs{Names: []string{"demo", "demo"}, Refresh: &refresh}
	got, err := reg.Call(context.Background(), rt, "pkg.info_available", args)
	want := map[string]any{"demo": map[string]any{"installed": true, "status": "up-to-date"}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "info", "-t", "package", "demo"}
	if got := append([]string{runner.commands[0].Name}, runner.commands[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%#v want=%#v", got, wantArgv)
	}
}

func TestZypperInfoAvailableRegistryRejectsAPTAndYUMBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt", "yum"} {
		t.Run(manager, func(t *testing.T) {
			runner := &zypperLowpkgExecRunner{}
			rt := zypperRegistryRuntime(manager, runner)
			prototype, err := reg.ResolveArgs(rt, "pkg.info_available")
			var unsupported *runtime.UnsupportedError
			if prototype != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != manager {
				t.Fatalf("resolve prototype=%T err=%v", prototype, err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.info_available", &ZypperInfoAvailableArgs{
				Names: []string{"demo"},
			})
			if got != nil || !errors.As(err, &unsupported) || len(runner.commands) != 0 {
				t.Fatalf("call got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
}
