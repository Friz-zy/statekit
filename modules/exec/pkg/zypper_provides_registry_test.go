package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperProvidesRegistryRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

func (r *zypperProvidesRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperListProvidesProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	fn, ok := reg.Get("pkg.list_provides")
	if !ok {
		t.Fatal("missing pkg.list_provides")
	}
	strict, ok := fn.(runtime.ProviderArgsStrict)
	if !ok || !strict.ProviderArgsStrict() {
		t.Fatal("pkg.list_provides is not strict")
	}
	if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(ZypperListProvidesArgs{}) {
		t.Fatalf("canonical Args type=%v", got)
	}
	if got, err := config.ArgumentNames(ZypperListProvidesArgs{}); err != nil || !reflect.DeepEqual(got, []string{"root"}) {
		t.Fatalf("arg names=%v err=%v", got, err)
	}
	if !reflect.DeepEqual(reg.ProviderCapabilities("pkg.list_provides"), []string{"zypperpkg"}) {
		t.Fatalf("capabilities=%v", reg.ProviderCapabilities("pkg.list_provides"))
	}

	args := &ZypperListProvidesArgs{Root: zypperRegistryStringPtr("/target")}
	for _, manager := range []string{"apt", "yum"} {
		runner := &zypperProvidesRegistryRunner{}
		rt := zypperRegistryRuntime(manager, runner)
		if _, err := reg.ResolveArgs(rt, "pkg.list_provides"); err == nil {
			t.Fatalf("unexpectedly resolved for %s", manager)
		}
		if got, err := reg.Call(context.Background(), rt, "pkg.list_provides", args); got != nil || err == nil || len(runner.calls) != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", manager, got, err, len(runner.calls))
		}
	}

	runner := &zypperProvidesRegistryRunner{results: []process.CommandResult{
		{Stdout: []byte("perl(Button)_|-perl-Wx\npython3-futures_|-python3\nperl(Button)_|-perl-Tk\n")},
	}}
	rt := zypperRegistryRuntime("zypper", runner)
	prototype, err := reg.ResolveArgs(rt, "pkg.list_provides")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperListProvidesArgs{}) || !reflect.DeepEqual(prototype, ZypperListProvidesArgs{}) {
		t.Fatalf("prototype=%#v err=%v", prototype, err)
	}
	got, err := reg.Call(context.Background(), rt, "pkg.list_provides", args)
	want := map[string]any{
		"perl(Button)":    []string{"perl-Wx", "perl-Tk"},
		"python3-futures": []string{"python3"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{"rpm", "--root", "/target", "-qa", "--queryformat", "%{PROVIDES}_|-%{NAME}\\n"}) {
		t.Fatalf("argv=%v", argv)
	}
	if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes != 1<<20 {
		t.Fatalf("unsafe command=%#v", runner.calls[0])
	}
	if fs := rt.FS.(*execZypperNoCallFS); fs.calls != 0 {
		t.Fatalf("filesystem calls=%d", fs.calls)
	}

	// A nonzero rpm retcode fails the call like Salt's cmd.run boundary.
	runner = &zypperProvidesRegistryRunner{results: []process.CommandResult{{ExitCode: 1}}}
	rt = zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(context.Background(), rt, "pkg.list_provides", &ZypperListProvidesArgs{}); got != nil || err == nil || len(runner.calls) != 1 {
		t.Fatalf("retcode got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	if got := countExecName(reg.Names(), "pkg.list_provides"); got != 1 {
		t.Fatalf("list_provides registration count=%d", got)
	}
}
