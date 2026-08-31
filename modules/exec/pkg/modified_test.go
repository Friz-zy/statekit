package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func modifiedBool(v bool) *bool { return &v }

func modifiedRuntime(manager string, result process.CommandResult) (*runtime.Runtime, *verifyExecRunner) {
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		panic(err)
	}
	runner := &verifyExecRunner{result: result}
	return &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}, runner
}

func TestModifiedRegistryProviderContract(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		rt, runner := modifiedRuntime(manager, process.CommandResult{ExitCode: 0})
		prototype, err := reg.ResolveArgs(rt, "pkg.modified")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ModifiedArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"capabilities", "checksum", "device", "group", "mode", "names", "owner", "root", "size", "symlink", "time"}) {
			t.Fatalf("%s argument names=%v err=%v", manager, names, err)
		}
		if !reflect.DeepEqual(reg.ProviderCapabilities("pkg.modified"), []string{"yumpkg"}) {
			t.Fatal("modified capability metadata changed")
		}
		got, err := reg.Call(context.Background(), rt, "pkg.modified", &ModifiedArgs{Names: []string{"a", "b"}})
		if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
			t.Fatalf("%s result=%#v err=%v calls=%d", manager, got, err, len(runner.commands))
		}
		if !reflect.DeepEqual(append([]string{runner.commands[0].Name}, runner.commands[0].Args...), []string{"rpm", "-Va", "a", "b"}) || runner.commands[0].Shell || runner.commands[0].MaxStdoutBytes != 1<<20 || runner.commands[0].MaxStderrBytes != 1<<20 {
			t.Fatalf("%s command=%#v", manager, runner.commands[0])
		}
	}
	for _, manager := range []string{"apt", "zypper"} {
		reg := runtime.NewExecRegistry()
		_ = Register(reg)
		rt, runner := modifiedRuntime(manager, process.CommandResult{})
		if _, err := reg.ResolveArgs(rt, "pkg.modified"); err == nil || !errors.As(err, new(*runtime.UnsupportedError)) {
			t.Fatalf("%s unexpectedly resolved", manager)
		}
		if _, err := reg.Call(context.Background(), rt, "pkg.modified", &ModifiedArgs{}); err == nil || !errors.As(err, new(*runtime.UnsupportedError)) || len(runner.commands) != 0 {
			t.Fatalf("%s err=%v calls=%d", manager, err, len(runner.commands))
		}
	}
}

func TestModifiedParserFiltersAndReturnCodes(t *testing.T) {
	output := "SM5DLUGTP  c /config\n......... /clean\nX........ /unknown\n"
	for _, tc := range []struct {
		name string
		args ModifiedArgs
		want map[string]any
	}{
		{"all", ModifiedArgs{}, map[string]any{"/config": []string{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities", "config"}, "/clean": []string{}, "/unknown": []string{"size"}}},
		{"size true", ModifiedArgs{Size: modifiedBool(true)}, map[string]any{"/config": []string{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities", "config"}, "/unknown": []string{"size"}}},
		{"size false", ModifiedArgs{Size: modifiedBool(false)}, map[string]any{"/clean": []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := modifiedRuntime("yum", process.CommandResult{ExitCode: 1, Stdout: []byte(output)})
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.modified", &tc.args)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
	rt, _ := modifiedRuntime("yum", process.CommandResult{ExitCode: 2, Stdout: []byte("not parsed"), Stderr: []byte("failure")})
	reg := runtime.NewExecRegistry()
	_ = Register(reg)
	got, err := reg.Call(context.Background(), rt, "pkg.modified", &ModifiedArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"retcode": 2, "stderr": "failure"}) {
		t.Fatalf("failure result=%#v err=%v", got, err)
	}
}

func TestModifiedMalformedRecordsAbortWithoutSyntheticResult(t *testing.T) {
	for _, output := range []string{"malformed\n......... /clean\n", " ......... /leading\n", "......... /clean\n\n......... /later\n"} {
		rt, runner := modifiedRuntime("yum", process.CommandResult{ExitCode: 1, Stdout: []byte(output)})
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.modified", &ModifiedArgs{})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v calls=%d", output, got, err, len(runner.commands))
		}
	}
}

func TestModifiedCallPropagatesCancellationAfterRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := modifiedRuntime("dnf5", process.CommandResult{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := reg.Call(ctx, rt, "pkg.modified", &ModifiedArgs{})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestModifiedErrorsAndArgumentValidationBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	_ = Register(reg)
	rt, runner := modifiedRuntime("yum", process.CommandResult{Err: errors.New("runner failure")})
	if _, err := reg.Call(context.Background(), rt, "pkg.modified", &ModifiedArgs{}); err == nil || len(runner.commands) != 1 {
		t.Fatalf("runner error=%v calls=%d", err, len(runner.commands))
	}
	rt, runner = modifiedRuntime("yum", process.CommandResult{})
	if _, err := reg.Call(context.Background(), rt, "pkg.modified", &struct{}{}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("wrong argument err=%v calls=%d", err, len(runner.commands))
	}
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.(pkgprovider.YumProvider).Yum(context.Background(), rt, "modified", map[string]any{"unknown": true}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("unknown argument err=%v calls=%d", err, len(runner.commands))
	}
}
