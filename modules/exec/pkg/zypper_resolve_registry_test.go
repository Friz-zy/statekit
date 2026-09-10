package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperResolveRegistryRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

func (r *zypperResolveRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperResolveCapabilitiesProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	fn, ok := reg.Get("pkg.resolve_capabilities")
	if !ok {
		t.Fatal("missing pkg.resolve_capabilities")
	}
	strict, ok := fn.(runtime.ProviderArgsStrict)
	if !ok || !strict.ProviderArgsStrict() {
		t.Fatal("pkg.resolve_capabilities is not strict")
	}
	if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(ZypperResolveCapabilitiesArgs{}) {
		t.Fatalf("canonical Args type=%v", got)
	}
	// ArgumentNames returns the union of argument names in canonical order.
	if got, err := config.ArgumentNames(ZypperResolveCapabilitiesArgs{}); err != nil || !reflect.DeepEqual(got, []string{"pkgs", "refresh", "resolve_capabilities", "root"}) {
		t.Fatalf("arg names=%v err=%v", got, err)
	}
	if !reflect.DeepEqual(reg.ProviderCapabilities("pkg.resolve_capabilities"), []string{"zypperpkg"}) {
		t.Fatalf("capabilities=%v", reg.ProviderCapabilities("pkg.resolve_capabilities"))
	}

	passThrough := &ZypperResolveCapabilitiesArgs{Pkgs: []any{"w3m_ssl", map[string]any{"vim": "9.0"}}}
	for _, manager := range []string{"apt", "yum"} {
		runner := &zypperResolveRegistryRunner{}
		rt := zypperRegistryRuntime(manager, runner)
		if _, err := reg.ResolveArgs(rt, "pkg.resolve_capabilities"); err == nil {
			t.Fatalf("unexpectedly resolved for %s", manager)
		}
		if got, err := reg.Call(context.Background(), rt, "pkg.resolve_capabilities", passThrough); got != nil || err == nil || len(runner.calls) != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", manager, got, err, len(runner.calls))
		}
	}

	runner := &zypperResolveRegistryRunner{}
	rt := zypperRegistryRuntime("zypper", runner)
	prototype, err := reg.ResolveArgs(rt, "pkg.resolve_capabilities")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperResolveCapabilitiesArgs{}) || !reflect.DeepEqual(prototype, ZypperResolveCapabilitiesArgs{}) {
		t.Fatalf("prototype=%#v err=%v", prototype, err)
	}
	got, err := reg.Call(context.Background(), rt, "pkg.resolve_capabilities", passThrough)
	if err != nil || !reflect.DeepEqual(got, []any{"w3m_ssl", map[string]any{"vim": "9.0"}}) || len(runner.calls) != 0 {
		t.Fatalf("pass-through got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	// resolve_capabilities=true: exact miss, single provides hit renames.
	runner = &zypperResolveRegistryRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream/>`)},
		{Stdout: []byte(`<stream><solvable name="openssl"/></stream>`)},
		{Stdout: []byte(`<stream/>`)},
		{Stdout: []byte(`<stream><solvable name="openssl"/></stream>`)},
		{Stdout: []byte(`<stream><solvable name="w3m"/></stream>`)},
	}}
	rt = zypperRegistryRuntime("zypper", runner)
	got, err = reg.Call(context.Background(), rt, "pkg.resolve_capabilities", &ZypperResolveCapabilitiesArgs{
		Pkgs:                []any{"libssl.so.1.1()(64bit)", map[string]any{"libssl.so.1.1()(64bit)": "1.1"}, "w3m"},
		ResolveCapabilities: zypperRegistryBoolPtr(true),
		Root:                zypperRegistryStringPtr("/target"),
	})
	want := []any{"openssl", map[string]any{"openssl": "1.1"}, "w3m"}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 5 {
		t.Fatalf("resolve got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	wantArgv := [][]string{
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "--provides", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "--provides", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "w3m"},
	}
	for i, command := range runner.calls {
		if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, argv, wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes == 0 {
			t.Fatalf("unsafe command=%#v", command)
		}
	}
	if fs := rt.FS.(*execZypperNoCallFS); fs.calls != 0 {
		t.Fatalf("filesystem calls=%d", fs.calls)
	}

	// A missing pkgs list is invalid input, and a pkgs CLI flag cannot be
	// expressed: the field is list-of-any, so only structured input supplies it.
	runner = &zypperResolveRegistryRunner{}
	rt = zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(context.Background(), rt, "pkg.resolve_capabilities", &ZypperResolveCapabilitiesArgs{}); got != nil || err == nil || len(runner.calls) != 0 {
		t.Fatalf("missing pkgs got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	fs, err := config.NewFlagSet("resolve", ZypperResolveCapabilitiesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("pkgs") != nil {
		t.Fatal("[]any pkgs field must not generate a CLI flag")
	}

	if got := countExecName(reg.Names(), "pkg.resolve_capabilities"); got != 1 {
		t.Fatalf("resolve_capabilities registration count=%d", got)
	}
}
