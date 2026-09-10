package pkg

import (
	"context"
	"errors"
	"path"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperHoldsRegistryRuntime(t *testing.T, manager string, runner *zypperLowpkgExecRunner, lockContent string) *runtime.Runtime {
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

// TestZypperListHoldsProviderAwareRegistryContract pins the one canonical
// pkg.list_holds registration: YUM keeps its committed shape, Zypper resolves
// the provider-specific prototype, and APT stays unsupported with no call.
func TestZypperListHoldsProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range reg.Names() {
		if name == "pkg.list_holds" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("pkg.list_holds registration count=%d", count)
	}
	fn, ok := reg.Get("pkg.list_holds")
	if !ok {
		t.Fatal("pkg.list_holds is not registered")
	}
	strict, ok := fn.(runtime.ProviderArgsStrict)
	if !ok || !strict.ProviderArgsStrict() {
		t.Fatal("pkg.list_holds must use strict provider arguments")
	}
	if got := reg.ProviderCapabilities("pkg.list_holds"); !reflect.DeepEqual(got, []string{"yumpkg", "zypperpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}

	// YUM/DNF/DNF5 keep the committed prototype and argument names.
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		runner := &zypperLowpkgExecRunner{}
		rt := zypperHoldsRegistryRuntime(t, manager, runner, "")
		prototype, err := reg.ResolveArgs(rt, "pkg.list_holds")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumListHoldsArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"full", "pattern"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
	}

	// APT stays UnsupportedError with no Runner call.
	aptRunner := &zypperLowpkgExecRunner{}
	aptRT := zypperHoldsRegistryRuntime(t, "apt", aptRunner, "")
	var unsupported *runtime.UnsupportedError
	if prototype, err := reg.ResolveArgs(aptRT, "pkg.list_holds"); prototype != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" {
		t.Fatalf("apt prototype=%T err=%v", prototype, err)
	}
	if got, err := reg.Call(context.Background(), aptRT, "pkg.list_holds", &YumListHoldsArgs{}); got != nil || !errors.As(err, &unsupported) || len(aptRunner.commands) != 0 {
		t.Fatalf("apt got=%#v err=%v calls=%d", got, err, len(aptRunner.commands))
	}

	// Zypper resolves its own prototype and argument surface.
	zypperRunner := &zypperLowpkgExecRunner{}
	zypperRT := zypperHoldsRegistryRuntime(t, "zypper", zypperRunner, "")
	prototype, err := reg.ResolveArgs(zypperRT, "pkg.list_holds")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperListHoldsArgs{}) {
		t.Fatalf("zypper prototype=%T err=%v", prototype, err)
	}
	if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"full", "pattern", "root"}) {
		t.Fatalf("zypper names=%v err=%v", names, err)
	}

	// A YUM pointer under the resolved Zypper shape fails at the strict
	// boundary before any Runner or filesystem activity.
	wrongRunner := &zypperLowpkgExecRunner{}
	wrongRT := zypperHoldsRegistryRuntime(t, "zypper", wrongRunner, "")
	if got, err := reg.Call(context.Background(), wrongRT, "pkg.list_holds", &YumListHoldsArgs{}); got != nil || err == nil || len(wrongRunner.commands) != 0 {
		t.Fatalf("wrong pointer got=%#v err=%v calls=%d", got, err, len(wrongRunner.commands))
	}
}

func TestZypperListHoldsRegistryEndToEnd(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	root := "/target"
	locks := "solvable_name: demo\n\nsolvable_name: gone\n"
	runner := &zypperLowpkgExecRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)},
		{Stdout: []byte("SIZE\n")},
		{Stdout: []byte("edition: 2.0-1\nname: demo\n-----\nedition: 1.0-1\nname: demo\n-----\n")},
		{Stdout: []byte(`<stream/>`)},
	}}
	rt := zypperHoldsRegistryRuntime(t, "zypper", runner, locks)
	args := &ZypperListHoldsArgs{Root: zypperRegistryStringPtr(root)}
	before := *args
	got, err := reg.Call(context.Background(), rt, "pkg.list_holds", args)
	if err != nil || !reflect.DeepEqual(got, []string{"demo-0:2.0-1.*", "demo-0:1.0-1.*"}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatal("registry call mutated arguments")
	}
	wantArgv := [][]string{
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "search", "--match-exact", "--case-sensitive", "--installed-only", "--details", "demo"},
		{"rpm", "--querytags"},
	}
	if len(runner.commands) != 4 {
		t.Fatalf("calls=%d commands=%#v", len(runner.commands), runner.commands)
	}
	for i, want := range wantArgv {
		if got := append([]string{runner.commands[i].Name}, runner.commands[i].Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("argv[%d]=%v want=%v", i, got, want)
		}
	}
	infoArgv := append([]string{runner.commands[2].Name}, runner.commands[2].Args...)
	if len(infoArgv) != 7 || infoArgv[0] != "rpm" || infoArgv[1] != "--root" || infoArgv[2] != root || infoArgv[3] != "-q" || infoArgv[4] != "demo" || infoArgv[5] != "--queryformat" {
		t.Fatalf("info argv=%v", infoArgv)
	}

	// full=false returns bare names and tolerates per-lock search misses.
	runner = &zypperLowpkgExecRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)},
		{Stdout: []byte("SIZE\n")},
		{Stdout: []byte("edition: 1.0-1\nname: demo\n-----\n")},
		{Stdout: []byte(`<stream/>`)},
	}}
	rt = zypperHoldsRegistryRuntime(t, "zypper", runner, locks)
	full := false
	got, err = reg.Call(context.Background(), rt, "pkg.list_holds", &ZypperListHoldsArgs{Full: &full, Root: zypperRegistryStringPtr(root)})
	if err != nil || !reflect.DeepEqual(got, []string{"demo"}) {
		t.Fatalf("bare got=%#v err=%v", got, err)
	}
}

func TestZypperListHoldsRegistryPureRejection(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	// An invalid pattern is rejected before any Runner or filesystem access;
	// zypperRegistryRuntime's filesystem panics on first touch.
	runner := &zypperLowpkgExecRunner{}
	rt := zypperRegistryRuntime("zypper", runner)
	got, err := reg.Call(context.Background(), rt, "pkg.list_holds", &ZypperListHoldsArgs{Pattern: zypperRegistryStringPtr("[")})
	if got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("invalid pattern got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Cancellation propagates before the lock file is read.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &zypperLowpkgExecRunner{}
	rt = zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(ctx, rt, "pkg.list_holds", &ZypperListHoldsArgs{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A search Runner failure propagates rather than fabricating holds.
	runner = &zypperLowpkgExecRunner{results: []process.CommandResult{{Err: errors.New("runner failed")}}}
	rt = zypperHoldsRegistryRuntime(t, "zypper", runner, "solvable_name: demo\n")
	if got, err := reg.Call(context.Background(), rt, "pkg.list_holds", &ZypperListHoldsArgs{Root: zypperRegistryStringPtr("/target")}); got != nil || err == nil || len(runner.commands) != 1 {
		t.Fatalf("runner failure got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}
