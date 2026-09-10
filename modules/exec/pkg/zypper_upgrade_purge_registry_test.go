package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func zypperUpgradePurgeRuntime(t *testing.T, osVersion string, runner process.Runner) *runtime.Runtime {
	t.Helper()
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: "zypper",
			OS:      &facts.OSFacts{Family: facts.FamilySuse, Version: osVersion},
			CPU:     &facts.CPUFacts{Arch: "x86_64"},
		}),
		Providers: providers,
		Runner:    runner,
		FS:        &execZypperNoCallFS{},
	}
}

func TestZypperUpgradePurgeRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pkg.upgrade", "pkg.purge"} {
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

	runner := &zypperResolveRegistryRunner{}
	rt := zypperUpgradePurgeRuntime(t, "15", runner)
	upgrade, err := reg.ResolveArgs(rt, "pkg.upgrade")
	if err != nil || reflect.TypeOf(upgrade) != reflect.TypeOf(ZypperUpgradeArgs{}) {
		t.Fatalf("upgrade prototype=%T err=%v", upgrade, err)
	}
	if names, err := config.ArgumentNames(ZypperUpgradeArgs{}); err != nil || !reflect.DeepEqual(names, []string{
		"diff_attr", "dist_upgrade", "dryrun", "fromrepo", "name", "no_recommends", "novendorchange", "pkgs", "refresh", "root", "skip_verify",
	}) {
		t.Fatalf("upgrade argument names=%v err=%v", names, err)
	}
	purge, err := reg.ResolveArgs(rt, "pkg.purge")
	if err != nil || reflect.TypeOf(purge) != reflect.TypeOf(ZypperPurgeArgs{}) {
		t.Fatalf("purge prototype=%T err=%v", purge, err)
	}
	if names, err := config.ArgumentNames(ZypperPurgeArgs{}); err != nil || !reflect.DeepEqual(names, []string{"name", "pkgs", "root"}) {
		t.Fatalf("purge argument names=%v err=%v", names, err)
	}

	// Other providers keep their own shapes; a zypper pointer is wrong there.
	for _, manager := range []string{"apt", "yum"} {
		otherRT := zypperRegistryRuntime(manager, &zypperResolveRegistryRunner{})
		if _, err := reg.ResolveArgs(otherRT, "pkg.upgrade"); err != nil {
			t.Fatalf("%s upgrade resolve: %v", manager, err)
		}
		if got, err := reg.Call(context.Background(), otherRT, "pkg.upgrade", &ZypperUpgradeArgs{}); got != nil || err == nil {
			t.Fatalf("%s accepted zypper upgrade pointer: %#v %v", manager, got, err)
		}
		if got, err := reg.Call(context.Background(), otherRT, "pkg.purge", &ZypperPurgeArgs{}); got != nil || err == nil {
			t.Fatalf("%s accepted zypper purge pointer: %#v %v", manager, got, err)
		}
	}
}

func TestZypperUpgradeRegistryCallFlow(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	refreshFalse, dist, novendor := false, true, true
	runner := &zypperResolveRegistryRunner{results: []process.CommandResult{
		{Stdout: []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")},
		{},
		{Stdout: []byte("")},
	}}
	rt := zypperUpgradePurgeRuntime(t, "15", runner)
	got, err := reg.Call(context.Background(), rt, "pkg.upgrade", &ZypperUpgradeArgs{
		Refresh:        &refreshFalse,
		DistUpgrade:    &dist,
		Novendorchange: &novendor,
		SkipVerify:     nil,
	})
	want := map[string]any{"foo": map[string]any{"old": "1-1", "new": ""}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("calls=%d", len(runner.calls))
	}
	mutation := append([]string{runner.calls[1].Name}, runner.calls[1].Args...)
	wantMutation := []string{"zypper", "--non-interactive", "--no-refresh", "dist-upgrade", "--auto-agree-with-licenses", "--no-allow-vendor-change"}
	if !reflect.DeepEqual(mutation, wantMutation) {
		t.Fatalf("mutation=%v want=%v", mutation, wantMutation)
	}

	// Omitted refresh keeps the source default: the refresh runs first.
	runner = &zypperResolveRegistryRunner{results: []process.CommandResult{
		{}, {Stdout: []byte("foo_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")}, {}, {Stdout: []byte("")},
	}}
	rt = zypperUpgradePurgeRuntime(t, "15", runner)
	if _, err := reg.Call(context.Background(), rt, "pkg.upgrade", &ZypperUpgradeArgs{}); err != nil {
		t.Fatal(err)
	}
	refreshArgv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	if !reflect.DeepEqual(refreshArgv, []string{"zypper", "--non-interactive", "refresh", "--force"}) {
		t.Fatalf("refresh=%v", refreshArgv)
	}
}

func TestZypperPurgeRegistryCallFlow(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	root := "/target"
	runner := &zypperResolveRegistryRunner{results: []process.CommandResult{
		{Stdout: []byte("")},
		{Stdout: []byte("vim_|-0_|-7_|-4_|-x86_64_|-(none)_|-0\n")},
		{},
		{Stdout: []byte("")},
	}}
	rt := zypperUpgradePurgeRuntime(t, "15", runner)
	got, err := reg.Call(context.Background(), rt, "pkg.purge", &ZypperPurgeArgs{Root: &root, Pkgs: []string{"vim"}})
	want := map[string]any{"vim": map[string]any{"old": "7-4", "new": ""}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	wantArgv := [][]string{
		{"rpm", "--root", root, "-q", "--qf", "%{NAME}: [%{PROVIDES} ]\\n", "vim"},
		{"rpm", "--root", root, "-qa", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", root, "remove", "vim"},
		{"rpm", "--root", root, "-qa", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"},
	}
	if len(runner.calls) != len(wantArgv) {
		t.Fatalf("calls=%d", len(runner.calls))
	}
	for i, command := range runner.calls {
		if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, argv, wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes == 0 || command.MaxStderrBytes == 0 {
			t.Fatalf("unsafe command[%d]=%#v", i, command)
		}
	}
	if fs := rt.FS.(*execZypperNoCallFS); fs.calls != 0 {
		t.Fatalf("filesystem calls=%d", fs.calls)
	}
}

func TestZypperUpgradePurgeCLIFlags(t *testing.T) {
	upgradeFlags, err := config.NewFlagSet("upgrade", ZypperUpgradeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := upgradeFlags.Parse([]string{
		"--dist_upgrade", "--dryrun", "--skip_verify", "--novendorchange", "--no_recommends",
		"--name", "vim", "--pkgs", "vim,emacs", "--fromrepo", "RepoA,RepoB", "--diff_attr", "version,arch", "--root", "/target",
	}); err != nil {
		t.Fatalf("upgrade flags: %v", err)
	}
	for _, name := range []string{"name", "pkgs", "refresh", "dryrun", "dist_upgrade", "fromrepo", "novendorchange", "skip_verify", "no_recommends", "root", "diff_attr"} {
		if upgradeFlags.Lookup(name) == nil {
			t.Fatalf("upgrade flag %q missing", name)
		}
	}
	purgeFlags, err := config.NewFlagSet("purge", ZypperPurgeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := purgeFlags.Parse([]string{"--name", "vim", "--root", "/target"}); err != nil {
		t.Fatalf("purge flags: %v", err)
	}
	for _, name := range []string{"name", "pkgs", "root"} {
		if purgeFlags.Lookup(name) == nil {
			t.Fatalf("purge flag %q missing", name)
		}
	}
}

func TestZypperUpgradePurgeWrongProviderBoundary(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt", "yum", "dnf", "dnf5"} {
		runner := &zypperResolveRegistryRunner{}
		rt := zypperRegistryRuntime(manager, runner)
		for _, call := range []struct {
			name string
			args any
		}{
			{"pkg.upgrade", &ZypperUpgradeArgs{}},
			{"pkg.purge", &ZypperPurgeArgs{}},
		} {
			got, err := reg.Call(context.Background(), rt, call.name, call.args)
			if got != nil || err == nil || len(runner.calls) != 0 {
				t.Fatalf("%s %s got=%#v err=%v calls=%d", manager, call.name, got, err, len(runner.calls))
			}
		}
	}
}
