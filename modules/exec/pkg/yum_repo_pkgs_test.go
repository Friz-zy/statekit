package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgrepo "github.com/friz-zy/statekit/modules/exec/pkgrepo"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func listRepoPkgsRegistryRuntime(t *testing.T, manager string, runner *aptFakeRunner) (*runtime.Runtime, *runtime.ExecRegistry) {
	t.Helper()
	registry := runtime.NewExecRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	// This is the real shared pkg.list_repos registration used by the provider
	// flow, not a direct helper or a host repository read.
	if err := pkgrepo.Register(registry); err != nil {
		t.Fatal(err)
	}
	fsys := runtime.NewMemoryFS()
	if err := fsys.MkdirAll("/etc/yum/repos.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/etc/yum/yum.conf", []byte("[main]\nreposdir=/etc/yum/repos.d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/etc/yum/repos.d/statekit.repo", []byte("[base]\nname=Base\nenabled=1\n\n[disabled]\nname=Disabled\nenabled=0\n\n[updates]\nname=Updates\nenabled=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	family := facts.FamilyRedHat
	if manager == "apt" {
		family = facts.FamilyDebian
	}
	rt := &runtime.Runtime{
		Exec: registry, Runner: runner, FS: fsys,
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager, CPU: &facts.CPUFacts{Arch: "x86_64"}, OS: &facts.OSFacts{Family: family},
		}),
		Providers: runtime.NewProviderRegistry(),
	}
	if err := pkgprovider.Register(rt.Providers); err != nil {
		t.Fatal(err)
	}
	return rt, registry
}

func TestListRepoPkgsRegistryActualProviderMatrix(t *testing.T) {
	boolp := func(value bool) *bool { return &value }
	yumNames := []string{"branch", "byrepo", "cacheonly", "disableexcludes", "disablerepo", "enablerepo", "fromrepo", "packages", "repo", "setopt"}
	type row struct {
		provider  string
		prototype reflect.Type
		argNames  []string
		call      any
		results   []process.CommandResult
		argv      [][]string
		want      any
	}
	rows := []row{
		{
			provider: "apt", prototype: reflect.TypeOf(FilePackagesArgs{}), argNames: []string{"packages"},
			call:    &FilePackagesArgs{Packages: []string{"demo"}},
			results: []process.CommandResult{{Stdout: []byte("Package: demo\nVersion: 1.0\n\n")}},
			argv:    [][]string{{"apt-cache", "show", "demo"}}, want: map[string][]string{"demo": {"1.0"}},
		},
	}
	for _, provider := range []string{"yum", "dnf", "dnf5"} {
		results := []process.CommandResult{}
		argv := [][]string{}
		if provider == "yum" {
			results = append(results, process.CommandResult{Stdout: []byte("3.4.3\n")})
			argv = append(argv, []string{"yum", "--version"})
		}
		results = append(results,
			process.CommandResult{Stdout: []byte("demo.x86_64 1.0-1 base\n")},
			process.CommandResult{Stdout: []byte("demo.x86_64 2.0-1 disabled\n")},
		)
		argv = append(argv,
			[]string{provider, "--quiet", "--setopt=best=True", "--setopt=exclude=skip", "--showduplicates", "repository-packages", "base", "list", "demo*"},
			[]string{provider, "--quiet", "--setopt=best=True", "--setopt=exclude=skip", "--showduplicates", "repository-packages", "disabled", "list", "demo*"},
		)
		rows = append(rows, row{
			provider: provider, prototype: reflect.TypeOf(YumListRepoPkgsArgs{}), argNames: yumNames,
			call: &YumListRepoPkgsArgs{
				Packages: []string{"demo*"}, Enablerepo: []string{"disabled", "*"}, Disablerepo: "updates,*",
				Cacheonly: boolp(false), Setopt: "best=True,exclude=skip",
			},
			results: results, argv: argv, want: map[string][]string{"demo": {"2.0-1", "1.0-1"}},
		})
	}

	for _, tc := range rows {
		t.Run(tc.provider, func(t *testing.T) {
			runner := &aptFakeRunner{results: tc.results}
			rt, registry := listRepoPkgsRegistryRuntime(t, tc.provider, runner)
			prototype, err := registry.ResolveArgs(rt, "pkg.list_repo_pkgs")
			if err != nil || reflect.TypeOf(prototype) != tc.prototype {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, tc.argNames) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			if caps := registry.ProviderCapabilities("pkg.list_repo_pkgs"); !reflect.DeepEqual(caps, []string{"aptpkg", "yumpkg", "zypperpkg"}) {
				t.Fatalf("capabilities=%v", caps)
			}
			before, err := rt.FS.ReadFile("/etc/yum/repos.d/statekit.repo")
			if err != nil {
				t.Fatal(err)
			}
			got, err := registry.Call(context.Background(), rt, "pkg.list_repo_pkgs", tc.call)
			if err != nil || !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(commandArgv(runner.calls), tc.argv) {
				t.Fatalf("got=%#v err=%v argv=%#v", got, err, commandArgv(runner.calls))
			}
			after, err := rt.FS.ReadFile("/etc/yum/repos.d/statekit.repo")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("repository fixture mutated before=%q after=%q err=%v", before, after, err)
			}

			wrong := any(&FilePackagesArgs{})
			if tc.provider == "apt" {
				wrong = &YumListRepoPkgsArgs{}
			}
			calls := len(runner.calls)
			if got, callErr := registry.Call(context.Background(), rt, "pkg.list_repo_pkgs", wrong); got != nil || callErr == nil || len(runner.calls) != calls {
				t.Fatalf("wrong pointer got=%#v err=%v calls=%d", got, callErr, len(runner.calls))
			}
		})
	}

	zypperRunner := &aptFakeRunner{}
	zypper, registry := listRepoPkgsRegistryRuntime(t, "zypper", zypperRunner)
	zypper.FS = nil // ResolveArgs and the capability gate must not require FS.
	prototype, err := registry.ResolveArgs(zypper, "pkg.list_repo_pkgs")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperListRepoPkgsArgs{}) {
		t.Fatalf("zypper resolve prototype=%T err=%v", prototype, err)
	}
	if got, err := registry.Call(context.Background(), zypper, "pkg.list_repo_pkgs", &YumListRepoPkgsArgs{}); got != nil || err == nil || len(zypperRunner.calls) != 0 {
		t.Fatalf("zypper call got=%#v err=%v calls=%d", got, err, len(zypperRunner.calls))
	}
}

func TestYumListRepoPkgsRegistryDefaultsRemainOmitted(t *testing.T) {
	runner := &aptFakeRunner{results: []process.CommandResult{
		{Stdout: []byte("demo.x86_64 1-1 base\n")},
		{Stdout: []byte("demo.x86_64 2-1 updates\n")},
	}}
	rt, registry := listRepoPkgsRegistryRuntime(t, "dnf", runner)
	prototype, err := registry.ResolveArgs(rt, "pkg.list_repo_pkgs")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumListRepoPkgsArgs{}) {
		t.Fatalf("prototype=%T err=%v", prototype, err)
	}
	typ := reflect.TypeOf(YumListRepoPkgsArgs{})
	for _, field := range []string{"Byrepo", "Cacheonly"} {
		value, ok := typ.FieldByName(field)
		if !ok || value.Type.Kind() != reflect.Pointer || value.Type.Elem().Kind() != reflect.Bool {
			t.Fatalf("%s field=%#v", field, value)
		}
	}
	argMap, err := mapArgs("pkg.list_repo_pkgs", &YumListRepoPkgsArgs{}, YumListRepoPkgsArgs{})
	if err != nil || len(argMap) != 0 {
		t.Fatalf("omitted args=%#v err=%v", argMap, err)
	}
	got, err := registry.Call(context.Background(), rt, "pkg.list_repo_pkgs", &YumListRepoPkgsArgs{})
	want := map[string][]string{"demo": {"2-1", "1-1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	wantArgv := [][]string{
		{"dnf", "--quiet", "--showduplicates", "repository-packages", "base", "list"},
		{"dnf", "--quiet", "--showduplicates", "repository-packages", "updates", "list"},
	}
	if gotArgv := commandArgv(runner.calls); !reflect.DeepEqual(gotArgv, wantArgv) {
		t.Fatalf("argv=%#v want=%#v", gotArgv, wantArgv)
	}
}
