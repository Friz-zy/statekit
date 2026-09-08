package pkg

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type aptFakeRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

type registryBoundedDirErrorFS struct {
	runtime.FileSystem
	err error
}

func (f registryBoundedDirErrorFS) ReadDirBounded(string, int) ([]fs.DirEntry, error) {
	return nil, f.err
}

type registryYumSpecialEntry struct{ name string }

func (e registryYumSpecialEntry) Name() string               { return e.name }
func (e registryYumSpecialEntry) IsDir() bool                { return false }
func (e registryYumSpecialEntry) Type() fs.FileMode          { return 0 }
func (e registryYumSpecialEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e registryYumSpecialEntry) Size() int64                { return 0 }
func (e registryYumSpecialEntry) Mode() fs.FileMode          { return 0 }
func (e registryYumSpecialEntry) ModTime() time.Time         { return time.Time{} }
func (e registryYumSpecialEntry) IsDirInfo() bool            { return false }
func (e registryYumSpecialEntry) Sys() any                   { return nil }

type registryYumSpecialFS struct {
	*runtime.MemoryFS
	root   string
	info   map[string]fs.FileInfo
	writes int
}

func (f *registryYumSpecialFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	entries, err := f.MemoryFS.ReadDirBounded(name, max)
	if err != nil || name != f.root {
		return entries, err
	}
	return append(entries, registryYumSpecialEntry{name: "redirected.rpm"}, registryYumSpecialEntry{name: "special.rpm"}), nil
}

func (f *registryYumSpecialFS) Lstat(name string) (fs.FileInfo, error) {
	if info, ok := f.info[name]; ok {
		return info, nil
	}
	return f.MemoryFS.Lstat(name)
}

func (f *registryYumSpecialFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	f.writes++
	return f.MemoryFS.WriteFile(name, data, perm)
}

type registryYumSpecialInfo struct {
	mode fs.FileMode
}

func (i registryYumSpecialInfo) Name() string       { return "special.rpm" }
func (i registryYumSpecialInfo) Size() int64        { return 0 }
func (i registryYumSpecialInfo) Mode() fs.FileMode  { return i.mode }
func (i registryYumSpecialInfo) ModTime() time.Time { return time.Time{} }
func (i registryYumSpecialInfo) IsDir() bool        { return i.mode.IsDir() }
func (i registryYumSpecialInfo) Sys() any           { return nil }

func strptr(s string) *string { return &s }

func (r *aptFakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.calls = append(r.calls, cmd)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func aptExecRuntime(manager string, runner *aptFakeRunner) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
		Runner: runner, FS: runtime.NewMemoryFS(), Providers: runtime.NewProviderRegistry(),
	}
	if err := pkgprovider.Register(rt.Providers); err != nil {
		panic(err)
	}
	return rt
}

func TestLongtailCanonicalPackagesAndDispatch(t *testing.T) {
	runner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: a\nVersion: 1\n\n"), ExitCode: 0}}}
	rt := aptExecRuntime("apt", runner)
	fn := aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}
	got, err := fn.Execute(context.Background(), rt, &FilePackagesArgs{Packages: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls[0].Args, []string{"show", "a", "b"}) || runner.calls[0].Name != "apt-cache" {
		t.Fatalf("argv = %#v", runner.calls[0])
	}
	if got == nil {
		t.Fatal("expected result")
	}
}

func TestAPTUpgradeFunctionsRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Conf z (2.0 Ubuntu:1)\n")}}}
	rt := aptExecRuntime("apt", r)
	for _, tc := range []struct {
		name      string
		wantType  reflect.Type
		wantNames []string
	}{
		{"pkg.list_upgrades", reflect.TypeOf(ListUpgradesArgs{}), []string{"cache_valid_time", "dist_upgrade", "refresh"}},
		{"pkg.upgrade_available", reflect.TypeOf(NormalizeNameArgs{}), []string{"name"}},
	} {
		prototype, err := reg.ResolveArgs(rt, tc.name)
		if err != nil || reflect.TypeOf(prototype) != tc.wantType {
			t.Fatalf("%s prototype=%T err=%v", tc.name, prototype, err)
		}
		if tc.name == "pkg.upgrade_available" {
			names, err := config.ArgumentNames(prototype)
			if err != nil || !reflect.DeepEqual(names, tc.wantNames) {
				t.Fatalf("%s argument names=%v err=%v", tc.name, names, err)
			}
		}
	}
	if got := reg.ProviderCapabilities("pkg.list_upgrades"); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg", "zypperpkg"}) {
		t.Fatalf("list_upgrades capabilities=%v", got)
	}
	if got := reg.ProviderCapabilities("pkg.upgrade_available"); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg", "zypperpkg"}) {
		t.Fatalf("upgrade_available capabilities=%v", got)
	}
	refresh, dist := false, false
	got, err := reg.Call(context.Background(), rt, "pkg.list_upgrades", &ListUpgradesArgs{Refresh: &refresh, DistUpgrade: &dist})
	if err != nil || !reflect.DeepEqual(got, map[string]string{"z": "2.0"}) || !reflect.DeepEqual(r.calls[0].Args, []string{"--just-print", "upgrade"}) {
		t.Fatalf("list_upgrades got=%#v err=%v calls=%#v", got, err, r.calls)
	}
	if _, err := reg.Call(context.Background(), rt, "pkg.list_upgrades", &YumListUpgradesArgs{}); err == nil {
		t.Fatal("list_upgrades accepted YUM pointer for APT")
	}
}

func TestLongtailCapabilityGateBeforeRunner(t *testing.T) {
	runner := &aptFakeRunner{}
	rt := aptExecRuntime("dnf", runner)
	fn := aptLongtailFunc{"purge", PackagesArgs{}}
	_, err := fn.Execute(context.Background(), rt, &PackagesArgs{Pkgs: []string{"pkg"}})
	if !errors.As(err, new(*runtime.UnsupportedError)) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("non-APT capability constructed a command")
	}
}

func TestPurgeRegistryActualProviderMatrix(t *testing.T) {
	const aptQuery = "${Status} ${Package} ${Version} ${Architecture}\n"
	const rpmQuery = "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if got := reg.ProviderCapabilities("pkg.purge"); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(PurgeArgs{}), reflect.TypeOf(YumPurgeArgs{})} {
		if typ.NumField() != 2 || typ.Field(0).Name != "Name" || typ.Field(0).Type != reflect.TypeOf((*string)(nil)) || typ.Field(1).Name != "Pkgs" || typ.Field(1).Type != reflect.TypeOf([]any{}) {
			t.Fatalf("purge prototype fields=%v", typ)
		}
		if _, exists := typ.FieldByName("SplitArch"); exists {
			t.Fatalf("%v unexpectedly exposes split_arch", typ)
		}
	}

	type row struct {
		provider  string
		prototype reflect.Type
		call      any
		results   []process.CommandResult
		argv      [][]string
		want      any
	}
	aptResult := map[string]any{
		"removed":   map[string]any{"safe-name": map[string]any{"old": "", "new": "1"}},
		"installed": map[string]any{"safe-name": map[string]any{"old": "1", "new": ""}},
	}
	rows := []row{
		{
			provider: "apt", prototype: reflect.TypeOf(PurgeArgs{}), call: &PurgeArgs{Pkgs: []any{"safe-name"}},
			results: []process.CommandResult{{Stdout: []byte("install ok installed safe-name 1 amd64\n")}, {}, {Stdout: []byte("deinstall ok config-files safe-name 1 amd64\n")}},
			argv:    [][]string{{"dpkg-query", "--showformat", aptQuery, "-W"}, {"apt-get", "-q", "-y", "purge", "safe-name"}, {"dpkg-query", "--showformat", aptQuery, "-W"}},
			want:    aptResult,
		},
	}
	for _, provider := range []string{"yum", "dnf", "dnf5"} {
		rows = append(rows, row{
			provider: provider, prototype: reflect.TypeOf(YumPurgeArgs{}), call: &YumPurgeArgs{Name: strptr("bad\nname"), Pkgs: []any{"safe-name"}},
			results: []process.CommandResult{{Stdout: []byte("safe-name_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")}, {}, {}},
			argv:    [][]string{{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", rpmQuery}, {provider, "-y", "remove", "safe-name"}, {"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", rpmQuery}},
			want:    map[string]any{"safe-name": map[string]any{"old": "1-1", "new": ""}},
		})
	}
	for _, tc := range rows {
		t.Run(tc.provider, func(t *testing.T) {
			r := &aptFakeRunner{results: tc.results}
			rt := aptExecRuntime(tc.provider, r)
			family := facts.FamilyRedHat
			if tc.provider == "apt" {
				family = facts.FamilyDebian
			}
			rt.Facts = facts.ForTesting(facts.Overrides{Package: tc.provider, CPU: &facts.CPUFacts{Arch: "x86_64"}, OS: &facts.OSFacts{Family: family}})
			prototype, err := reg.ResolveArgs(rt, "pkg.purge")
			if err != nil || reflect.TypeOf(prototype) != tc.prototype {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"name", "pkgs"}) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.purge", tc.call)
			if err != nil || !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(commandArgv(r.calls), tc.argv) {
				t.Fatalf("got=%#v err=%v argv=%#v", got, err, commandArgv(r.calls))
			}
			for i, command := range r.calls {
				if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
					t.Fatalf("command[%d]=%#v", i, command)
				}
			}
			wrong := any(&PurgeArgs{})
			if tc.provider == "apt" {
				wrong = &YumPurgeArgs{}
			}
			before := len(r.calls)
			if got, callErr := reg.Call(context.Background(), rt, "pkg.purge", wrong); got != nil || callErr == nil || len(r.calls) != before {
				t.Fatalf("wrong pointer got=%#v err=%v calls=%d", got, callErr, len(r.calls))
			}
			if got, callErr := reg.Call(context.Background(), rt, "pkg.purge", map[string]any{"pkgs": []any{"safe-name"}}); got != nil || callErr == nil || len(r.calls) != before {
				t.Fatalf("untyped args got=%#v err=%v calls=%d", got, callErr, len(r.calls))
			}
		})
	}

	zypperRunner := &aptFakeRunner{}
	zypper := aptExecRuntime("zypper", zypperRunner)
	if _, err := reg.ResolveArgs(zypper, "pkg.purge"); !errors.As(err, new(*runtime.UnsupportedError)) || len(zypperRunner.calls) != 0 {
		t.Fatalf("zypper resolve err=%v calls=%d", err, len(zypperRunner.calls))
	}
	if got, err := reg.Call(context.Background(), zypper, "pkg.purge", &PurgeArgs{}); got != nil || !errors.As(err, new(*runtime.UnsupportedError)) || len(zypperRunner.calls) != 0 {
		t.Fatalf("zypper call got=%#v err=%v calls=%d", got, err, len(zypperRunner.calls))
	}
}

func TestPurgeRegistryFailureBoundaries(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("purge runner failure")
	for _, provider := range []string{"apt", "yum", "dnf", "dnf5"} {
		t.Run(provider, func(t *testing.T) {
			r := &aptFakeRunner{}
			rt := aptExecRuntime(provider, r)
			family := facts.FamilyRedHat
			if provider == "apt" {
				family = facts.FamilyDebian
			}
			rt.Facts = facts.ForTesting(facts.Overrides{Package: provider, CPU: &facts.CPUFacts{Arch: "x86_64"}, OS: &facts.OSFacts{Family: family}})
			args := any(&PurgeArgs{Pkgs: []any{"safe-name"}})
			old := []byte("install ok installed safe-name 1 amd64\n")
			post := []byte("deinstall ok config-files safe-name 1 amd64\n")
			if provider != "apt" {
				args = &YumPurgeArgs{Pkgs: []any{"safe-name"}}
				old = []byte("safe-name_|-0_|-1_|-1_|-x86_64_|-(none)_|-0\n")
			}

			for _, tc := range []struct {
				name      string
				mutation  process.CommandResult
				wantCalls int
				wantErr   error
				postQuery bool
			}{
				{"runner", process.CommandResult{Err: sentinel}, 2, sentinel, false},
				{"canceled", process.CommandResult{Err: context.Canceled}, 2, context.Canceled, false},
				{"output-limit", process.CommandResult{Err: process.ErrOutputLimit}, 2, process.ErrOutputLimit, false},
				{"nonzero", process.CommandResult{ExitCode: 9, Stderr: []byte("remove failed")}, map[bool]int{true: 3, false: 2}[provider == "apt"], nil, provider == "apt"},
				{"nonzero-empty-stderr", process.CommandResult{ExitCode: 9}, map[bool]int{true: 3, false: 2}[provider == "apt"], nil, provider == "apt"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r.calls = nil
					r.results = []process.CommandResult{{Stdout: old}, tc.mutation, {Stdout: post}}
					got, err := reg.Call(context.Background(), rt, "pkg.purge", args)
					if tc.postQuery {
						if got == nil || len(r.calls) != tc.wantCalls {
							t.Fatalf("postquery got=%#v err=%v calls=%d", got, err, len(r.calls))
						}
						if tc.name == "nonzero" && err == nil {
							t.Fatalf("stderr-bearing apt failure lost error")
						}
						if tc.name == "nonzero-empty-stderr" && err != nil {
							t.Fatalf("empty-stderr apt status invented error: %v", err)
						}
						return
					}
					if tc.name == "nonzero" || tc.name == "nonzero-empty-stderr" {
						if got != nil || err == nil || len(r.calls) != tc.wantCalls {
							t.Fatalf("nonzero got=%#v err=%v calls=%d", got, err, len(r.calls))
						}
						return
					}
					if got != nil || !errors.Is(err, tc.wantErr) || len(r.calls) != tc.wantCalls {
						t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
					}
				})
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r.calls = nil
			if got, err := reg.Call(ctx, rt, "pkg.purge", args); got != nil || !errors.Is(err, context.Canceled) || len(r.calls) != 0 {
				t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		})
	}
}

func TestHoldRegistryProviderMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if got := reg.ProviderCapabilities("pkg.hold"); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}
	aptRunner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p install\n")}, {}}}
	aptRT := aptExecRuntime("apt", aptRunner)
	prototype, err := reg.ResolveArgs(aptRT, "pkg.hold")
	if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(PackagesArgs{}) {
		t.Fatalf("apt prototype=%T err=%v", prototype, err)
	}
	name := "p"
	got, err := reg.Call(context.Background(), aptRT, "pkg.hold", &PackagesArgs{Name: &name})
	want := map[string]any{"p": map[string]any{"name": "p", "changes": map[string]any{"old": "install", "new": "hold"}, "result": true, "comment": "Package p is now being held."}}
	if err != nil || !reflect.DeepEqual(got, want) || len(aptRunner.calls) != 2 || string(aptRunner.calls[1].Stdin) != "p hold\n" {
		t.Fatalf("apt got=%#v err=%v calls=%#v", got, err, aptRunner.calls)
	}
	emptyRunner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte{}}}}
	emptyRT := aptExecRuntime("apt", emptyRunner)
	got, err = reg.Call(context.Background(), emptyRT, "pkg.hold", &PackagesArgs{Name: strptr("empty")})
	emptyWant := map[string]any{"empty": map[string]any{"name": "empty", "changes": map[string]any{}, "result": false, "comment": "Package empty not currently held."}}
	if err != nil || !reflect.DeepEqual(got, emptyWant) || len(emptyRunner.calls) != 1 {
		t.Fatalf("apt empty got=%#v err=%v calls=%#v", got, err, emptyRunner.calls)
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		plugin := "yum-plugin-versionlock"
		if manager != "yum" {
			plugin = "python2-dnf-plugin-versionlock"
		}
		r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte{}}, {}}}
		rt := aptExecRuntime(manager, r)
		if manager == "dnf5" {
			if err := rt.FS.MkdirAll("/etc/dnf", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := rt.FS.WriteFile("/etc/dnf/versionlock.toml", []byte("[[packages]]\nname = \"demo\"\n[[packages.conditions]]\nkey = \"evr\"\ncomparator = \"=\"\nvalue = \"1-1\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		prototype, err := reg.ResolveArgs(rt, "pkg.hold")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumHoldArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"name", "normalize", "pkgs", "sources"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		name := "demo"
		got, err := reg.Call(context.Background(), rt, "pkg.hold", &YumHoldArgs{Name: &name})
		wantCalls := 4
		if manager == "dnf5" {
			wantCalls = 2
		}
		if err != nil || got == nil || len(r.calls) != wantCalls {
			t.Fatalf("%s got=%#v err=%v calls=%d", manager, got, err, len(r.calls))
		}
		for _, command := range r.calls {
			if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
				t.Fatalf("%s unbounded command=%#v", manager, command)
			}
		}
	}
	zypperRunner := &aptFakeRunner{}
	if _, err := reg.ResolveArgs(aptExecRuntime("zypper", zypperRunner), "pkg.hold"); !errors.As(err, new(*runtime.UnsupportedError)) || len(zypperRunner.calls) != 0 {
		t.Fatalf("zypper err=%v calls=%d", err, len(zypperRunner.calls))
	}
	yumRunner := &aptFakeRunner{}
	yumRT := aptExecRuntime("yum", yumRunner)
	if _, err := reg.Call(context.Background(), yumRT, "pkg.hold", &PackagesArgs{Pkgs: []string{"demo"}}); err == nil || len(yumRunner.calls) != 0 {
		t.Fatalf("wrong yum pointer err=%v calls=%d", err, len(yumRunner.calls))
	}
}

func TestUnholdRegistryActualProviderMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if got := reg.ProviderCapabilities("pkg.unhold"); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}
	for _, provider := range []string{"apt", "yum", "dnf", "dnf5", "zypper"} {
		t.Run(provider, func(t *testing.T) {
			r := &aptFakeRunner{}
			family := facts.FamilyRedHat
			if provider == "apt" {
				family = facts.FamilyDebian
			}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: provider, OS: &facts.OSFacts{Family: family}}), Providers: runtime.NewProviderRegistry(), Runner: r, FS: runtime.NewMemoryFS()}
			if err := pkgprovider.Register(rt.Providers); err != nil {
				t.Fatal(err)
			}
			prototype, err := reg.ResolveArgs(rt, "pkg.unhold")
			if provider == "zypper" {
				var unsupported *runtime.UnsupportedError
				if err == nil || !errors.As(err, &unsupported) || len(r.calls) != 0 {
					t.Fatalf("resolve err=%v calls=%d", err, len(r.calls))
				}
				got, callErr := reg.Call(context.Background(), rt, "pkg.unhold", &PackagesArgs{})
				if got != nil || !errors.As(callErr, &unsupported) || len(r.calls) != 0 {
					t.Fatalf("call got=%#v err=%v calls=%d", got, callErr, len(r.calls))
				}
				return
			}
			wantType := reflect.TypeOf(PackagesArgs{})
			if provider != "apt" {
				wantType = reflect.TypeOf(YumHoldArgs{})
			}
			if err != nil || reflect.TypeOf(prototype) != wantType {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			names, err := config.ArgumentNames(prototype)
			wantNames := []string{"name", "pkgs", "sources"}
			if provider != "apt" {
				wantNames = []string{"name", "normalize", "pkgs", "sources"}
			}
			if err != nil || !reflect.DeepEqual(names, wantNames) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			if provider == "apt" {
				r.results = []process.CommandResult{{Stdout: []byte("demo hold\n")}, {}}
				got, callErr := reg.Call(context.Background(), rt, "pkg.unhold", &PackagesArgs{Name: strptr("demo")})
				want := map[string]any{"demo": map[string]any{"name": "demo", "changes": map[string]any{"old": "hold", "new": "install"}, "result": true, "comment": "Package demo is no longer being held."}}
				if callErr != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(commandArgv(r.calls), [][]string{{"dpkg", "--get-selections", "demo"}, {"dpkg", "--set-selections"}}) {
					t.Fatalf("APT got=%#v err=%v argv=%#v", got, callErr, commandArgv(r.calls))
				}
			} else {
				plugin := "python2-dnf-plugin-versionlock"
				if provider == "yum" {
					plugin = "yum-plugin-versionlock"
				}
				results := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}}
				if provider == "dnf5" {
					results = append(results, process.CommandResult{Stdout: []byte(plugin + " 1\n")})
					if err := rt.FS.(*runtime.MemoryFS).MkdirAll("/etc/dnf", 0o755); err != nil {
						t.Fatal(err)
					}
					if err := rt.FS.WriteFile("/etc/dnf/versionlock.toml", []byte("[[packages]]\nname = \"demo\"\n[[packages.conditions]]\nkey = \"evr\"\ncomparator = \"=\"\nvalue = \"1-2\"\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				} else {
					results = append(results, process.CommandResult{Stdout: []byte(plugin + " 1\n")})
					if provider == "yum" {
						results = append(results, process.CommandResult{Stdout: []byte("0:demo-1-2.x86_64.*\n")})
					} else {
						results = append(results, process.CommandResult{Stdout: []byte("demo-1-2.x86_64.*\n")})
					}
				}
				results = append(results, process.CommandResult{})
				r.results = results
				got, callErr := reg.Call(context.Background(), rt, "pkg.unhold", &YumHoldArgs{Name: strptr("demo")})
				want := map[string]any{"demo": map[string]any{"name": "demo", "changes": map[string]any{"old": "hold", "new": ""}, "result": true, "comment": "Package demo is no longer held."}}
				deleteArg := "demo"
				if provider == "yum" {
					deleteArg = "0:demo-1-2.x86_64.*"
				}
				wantArgv := [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {provider, "versionlock", "delete", deleteArg}}
				if provider != "dnf5" {
					wantArgv = append([][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {provider, "versionlock", "list"}}, wantArgv[2:]...)
				}
				if callErr != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(commandArgv(r.calls), wantArgv) {
					t.Fatalf("%s got=%#v err=%v calls=%#v", provider, got, callErr, r.calls)
				}
				for i, command := range r.calls {
					if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
						t.Fatalf("%s command[%d]=%#v", provider, i, command)
					}
				}
			}
			var wrong any = &YumHoldArgs{Name: strptr("demo")}
			if provider != "apt" {
				wrong = &PackagesArgs{Pkgs: []string{"demo"}}
			}
			before := len(r.calls)
			if got, callErr := reg.Call(context.Background(), rt, "pkg.unhold", wrong); got != nil || callErr == nil || len(r.calls) != before {
				t.Fatalf("accepted wrong pointer provider=%s got=%#v err=%v calls=%d", provider, got, callErr, len(r.calls))
			}
			if provider != "apt" {
				plugin := "python2-dnf-plugin-versionlock"
				if provider == "yum" {
					plugin = "yum-plugin-versionlock"
				}
				failResults := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}}
				if provider != "dnf5" {
					lock := "demo-1-2.x86_64.*"
					if provider == "yum" {
						lock = "0:" + lock
					}
					failResults = append(failResults, process.CommandResult{Stdout: []byte(lock + "\n")})
				}
				failResults = append(failResults, process.CommandResult{Err: errors.New("runner failure")})
				failRunner := &aptFakeRunner{results: failResults}
				rt.Runner = failRunner
				got, callErr := reg.Call(context.Background(), rt, "pkg.unhold", &YumHoldArgs{Name: strptr("demo")})
				if got != nil || callErr == nil || len(failRunner.calls) != len(failResults) {
					t.Fatalf("runner failure got=%#v err=%v calls=%#v", got, callErr, failRunner.calls)
				}
				cancelRunner := &aptFakeRunner{results: append(failResults[:len(failResults)-1], process.CommandResult{Err: context.Canceled})}
				rt.Runner = cancelRunner
				got, callErr = reg.Call(context.Background(), rt, "pkg.unhold", &YumHoldArgs{Name: strptr("demo")})
				if got != nil || !errors.Is(callErr, context.Canceled) || len(cancelRunner.calls) != len(failResults) {
					t.Fatalf("cancel got=%#v err=%v calls=%#v", got, callErr, cancelRunner.calls)
				}
			}
		})
	}
}

func TestListHoldsDNF5RegistryQuotedTOMLKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("[[packages]]\n\"name\" = \"quoted\"\n[[packages.conditions]]\n'key' = 'evr'\n\"comparator\" = \"=\"\n'value' = '1:2-3' # inline comment\n")
	if err := fs.WriteFile("/etc/dnf/versionlock.toml", data, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "dnf5"}), Providers: providers, Runner: runner, FS: fs}
	full := true
	got, err := reg.Call(context.Background(), rt, "pkg.list_holds", &YumListHoldsArgs{Full: &full, Pattern: strptr("[ignored")})
	if err != nil || !reflect.DeepEqual(got, []string{"quoted-1:2-3.*"}) || len(runner.calls) != 1 {
		t.Fatalf("got=%#v err=%v commands=%#v", got, err, runner.calls)
	}
	if got := commandArgv(runner.calls); !reflect.DeepEqual(got, [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}}) {
		t.Fatalf("argv=%#v", got)
	}
}

func TestYumHoldRegistryPinnedCallMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			plugin := "yum-plugin-versionlock"
			if manager != "yum" {
				plugin = "python2-dnf-plugin-versionlock"
			}
			makeRT := func(r *aptFakeRunner) *runtime.Runtime {
				rt := aptExecRuntime(manager, r)
				if manager == "dnf5" {
					if err := rt.FS.MkdirAll("/etc/dnf", 0o755); err != nil {
						t.Fatal(err)
					}
					if err := rt.FS.WriteFile("/etc/dnf/versionlock.toml", []byte("[[packages]]\nname = \"other\"\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return rt
			}
			prototype, err := reg.ResolveArgs(makeRT(&aptFakeRunner{}), "pkg.hold")
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumHoldArgs{}) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			for _, tc := range []struct {
				name   string
				args   YumHoldArgs
				target string
			}{
				{"pkgs", YumHoldArgs{Pkgs: []any{map[string]any{"pkg-a": "1-1"}}}, "pkg-a"},
				{"sources", YumHoldArgs{Sources: []any{map[string]string{"pkg-b": "file.rpm"}}}, "pkg-b"},
			} {
				t.Run("test-"+tc.name, func(t *testing.T) {
					r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}}}
					rt := makeRT(r)
					rt.Options.Test = true
					got, err := reg.Call(context.Background(), rt, "pkg.hold", &tc.args)
					entry := map[string]any{"name": tc.target, "changes": map[string]any{}, "result": nil, "comment": "Package " + tc.target + " is set to be held."}
					want := map[string]any{tc.target: entry}
					wantCalls := 3
					if manager == "dnf5" {
						wantCalls = 2
					}
					if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != wantCalls {
						t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
					}
					for i, c := range r.calls {
						if c.Shell || c.MaxStdoutBytes != 1<<20 || c.MaxStderrBytes != 1<<20 {
							t.Fatalf("command[%d]=%#v", i, c)
						}
						want := []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
						if i == 2 {
							want = []string{manager, "versionlock", "list"}
						}
						if !reflect.DeepEqual(append([]string{c.Name}, c.Args...), want) {
							t.Fatalf("command[%d]=%v want %v", i, c, want)
						}
					}
				})
			}
			failureResults := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}, {ExitCode: 11}, {}}
			if manager == "dnf5" {
				failureResults = []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {ExitCode: 11}, {}}
			}
			r := &aptFakeRunner{results: failureResults}
			rt := makeRT(r)
			got, err := reg.Call(context.Background(), rt, "pkg.hold", &YumHoldArgs{Pkgs: []any{"first", "second"}})
			want := map[string]any{
				"first":  map[string]any{"name": "first", "changes": map[string]any{}, "result": false, "comment": "Package first was unable to be held."},
				"second": map[string]any{"name": "second", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package second is now being held."},
			}
			wantCalls := 5
			if manager == "dnf5" {
				wantCalls = 4
			}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != wantCalls {
				t.Fatalf("failure got=%#v err=%v calls=%#v", got, err, r.calls)
			}
			ctx := context.Background()
			cancelResults := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}, {Err: context.Canceled}}
			if manager == "dnf5" {
				cancelResults = []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {Err: context.Canceled}}
			}
			r = &aptFakeRunner{results: cancelResults}
			rt = makeRT(r)
			got, err = reg.Call(ctx, rt, "pkg.hold", &YumHoldArgs{Pkgs: []any{"first", "second"}})
			wantCalls = 4
			if manager == "dnf5" {
				wantCalls = 3
			}
			if got != nil || !errors.Is(err, context.Canceled) || len(r.calls) != wantCalls {
				t.Fatalf("cancel got=%#v err=%v calls=%#v", got, err, r.calls)
			}

			r = &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}}}
			rt = makeRT(r)
			got, err = reg.Call(context.Background(), rt, "pkg.hold", &YumHoldArgs{Pkgs: []any{map[string]any{"a": "1", "b": "2"}}})
			var unsupported *runtime.UnsupportedError
			if got != nil || !errors.As(err, &unsupported) || unsupported.Name != "pkg.hold pkgs multi-key mapping" || len(r.calls) != 1 {
				t.Fatalf("validation got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		})
	}
}

func TestLongtailMalformedAndEmptyPackages(t *testing.T) {
	for _, args := range []any{map[string]any{"packages": "not-a-list"}} {
		runner := &aptFakeRunner{}
		rt := aptExecRuntime("apt", runner)
		fn := aptLongtailFunc{"purge", PackagesArgs{}}
		if _, err := fn.Execute(context.Background(), rt, args); err == nil {
			t.Fatal("malformed/empty package input must fail")
		}
		if len(runner.calls) != 0 {
			t.Fatal("invalid input reached Runner")
		}
	}
	r := &aptFakeRunner{}
	if got, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{}); err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("empty purge: got=%#v err=%v", got, err)
	}
}

func TestLongtailProviderPreservesRunnerFailures(t *testing.T) {
	for _, result := range []process.CommandResult{
		{ExitCode: 7, Stderr: []byte("apt failed")},
		{ExitCode: -1, Err: context.Canceled},
	} {
		runner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed safe-name 1 amd64\n")}, result}}
		rt := aptExecRuntime("apt", runner)
		fn := aptLongtailFunc{"purge", PackagesArgs{}}
		if _, err := fn.Execute(context.Background(), rt, &PackagesArgs{Pkgs: []string{"safe-name"}}); err == nil {
			t.Fatal("runner failure must be returned")
		} else if len(runner.calls) == 0 {
			t.Fatalf("runner failure before command: %v", err)
		}
		if got, want := runner.calls[1].Name, "apt-get"; got != want || !reflect.DeepEqual(runner.calls[1].Args, []string{"-q", "-y", "purge", "safe-name"}) {
			t.Fatalf("command = %#v", runner.calls[1])
		}
	}
}

func TestLongtailSelectionValidationAndDeterministicInput(t *testing.T) {
	runner := &aptFakeRunner{}
	rt := aptExecRuntime("apt", runner)
	fn := aptLongtailFunc{"set_selections", SetSelectionsArgs{}}
	_, err := fn.Execute(context.Background(), rt, &SetSelectionsArgs{Selection: map[string][]string{
		"hold": {"z"}, "install": {"a"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(runner.calls[1].Stdin), "z hold\n"; got != want {
		t.Fatalf("stdin = %q, want %q", got, want)
	}
	before := len(runner.calls)
	_, err = fn.Execute(context.Background(), rt, &SetSelectionsArgs{Selection: map[string][]string{"hold": {"bad\nname"}}})
	if err == nil || len(runner.calls) != before {
		t.Fatal("control input must be rejected before Runner")
	}
}

// The expected argv and result shapes below are pinned to Salt's aptpkg
// execution contracts (saltstack/salt/modules/aptpkg.py and
// saltstack/salt/tests/unit/modules/test_aptpkg.py @ pinned revision).
// and deliberately use only the fake Runner; no package manager is invoked.
func TestAPTLongtailNamedRunnerContractMatrix(t *testing.T) {
	type matrixCase struct {
		name     string
		positive func(*testing.T)
		negative func(*testing.T)
	}
	boolptr := func(v bool) *bool { return &v }
	cases := []matrixCase{
		{"normalize_name", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 0}, {ExitCode: 1}, {ExitCode: 1}}}
			got, err := (aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "curl:all"})
			if err != nil || got != "curl" || len(r.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 1}, {ExitCode: 1}}}
			_, err := (aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "bad name"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed normalize_name: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"parse_arch", func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"parse_arch", ParseArchArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ParseArchArgs{Name: "curl:arm64"})
			want := map[string]any{"name": "curl", "arch": "arm64"}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"parse_arch", ParseArchArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ParseArchArgs{Name: "bad\nname"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed parse_arch: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"version_cmp", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 0}}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1.0~rc1", Pkg2: "1.0"})
			if err != nil || got != -1 || len(r.calls) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 1}, {ExitCode: 1}}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "bad version", Pkg2: "1"})
			if err != nil || got != nil || len(r.calls) != 3 {
				t.Fatalf("malformed version_cmp: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"get_selections", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("z hold\na install\na install\n")}}}
			got, err := (aptLongtailFunc{"get_selections", SelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SelectionsArgs{})
			want := map[string][]string{"hold": {"z"}, "install": {"a", "a"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "*"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9}}}
			_, err := (aptLongtailFunc{"get_selections", SelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SelectionsArgs{Pattern: strptr("bad pattern")})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid get_selections: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"set_selections", func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {"z", "a"}, "install": {"b"}}, Clear: boolptr(true)})
			if err != nil || len(r.calls) != 5 || !reflect.DeepEqual(r.calls[2].Stdin, []byte("a hold\n")) || !reflect.DeepEqual(got.(map[string]any)["a"], map[string]any{"old": "", "new": "hold"}) {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {"x\ty"}}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid set_selections: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"hold", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p install\n")}, {}}}
			got, err := (aptLongtailFunc{"hold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Name: strptr("p")})
			want := map[string]any{"p": map[string]any{"name": "p", "changes": map[string]any{"old": "install", "new": "hold"}, "result": true, "comment": "Package p is now being held."}}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != 2 {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"hold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Pkgs: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid hold: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"unhold", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p hold\n")}}}
			got, err := (aptLongtailFunc{"unhold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Pkgs: []string{"p"}})
			if err != nil || len(r.calls) != 2 || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "p"}) {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}}}
			_, err := (aptLongtailFunc{"unhold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("empty unhold: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"autoremove", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}}}
			got, err := (aptLongtailFunc{"autoremove", AutoremoveArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &AutoremoveArgs{})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || !reflect.DeepEqual(r.calls[1].Args, []string{"--assume-yes", "autoremove"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 2}}}
			_, err := (aptLongtailFunc{"autoremove", AutoremoveArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &AutoremoveArgs{ListOnly: boolptr(true)})
			if err != nil || len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0].Args, []string{"--assume-no", "autoremove"}) {
				t.Fatalf("autoremove failure: err=%v calls=%#v", err, r.calls)
			}
		}},
		{"purge", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed a 1 amd64\ninstall ok installed b 1 amd64\n")}, {}, {Stdout: []byte("deinstall ok config-files a 1 amd64\ndeinstall ok config-files b 1 amd64\n")}}}
			got, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{Pkgs: []any{"a", "b"}})
			want := map[string]any{"removed": map[string]any{"a": map[string]any{"old": "", "new": "1"}, "b": map[string]any{"old": "", "new": "1"}}, "installed": map[string]any{"a": map[string]any{"old": "1", "new": ""}, "b": map[string]any{"old": "1", "new": ""}}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "purge", "a", "b"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{})
			if err != nil || len(r.calls) != 0 {
				t.Fatalf("empty purge: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"upgrade", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}, {}}}
			got, err := (aptLongtailFunc{"upgrade", UpgradeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &UpgradeArgs{Refresh: boolptr(false), DownloadOnly: boolptr(true), DistUpgrade: boolptr(true)})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "-o", "DPkg::Options::=--force-confold", "-o", "DPkg::Options::=--force-confdef", "--download-only", "dist-upgrade"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"upgrade", UpgradeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &UpgradeArgs{Refresh: boolptr(false)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("upgrade failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_upgrades", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Conf z (2.0 Ubuntu:1)\nConf a (1.2 Ubuntu:2)\n")}}}
			got, err := (aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ListUpgradesArgs{Refresh: boolptr(false), DistUpgrade: boolptr(false)})
			want := map[string]string{"z": "2.0", "a": "1.2"}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"--just-print", "upgrade"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 3}}}
			_, err := (aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ListUpgradesArgs{Refresh: boolptr(false)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("list_upgrades failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"upgrade_available", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("1.0\n")}, {Stdout: []byte("Candidate: 2.0\n")}, {ExitCode: 1}, {ExitCode: 1}, {ExitCode: 0}}}
			got, err := (aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "p"})
			if err != nil || got != true || !reflect.DeepEqual(r.calls[1].Args, []string{"policy", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "bad name"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid upgrade_available: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"show", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: p\nVersion: 1\nDescription: d\n\n")}}}
			got, err := (aptLongtailFunc{"show", ShowArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ShowArgs{Names: []string{"p"}})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"p": map[string]any{"1": map[string]string{"Description": "d"}}}) || !reflect.DeepEqual(r.calls[0].Args, []string{"show", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"show", ShowArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ShowArgs{Names: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid show: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_repo_pkgs", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: p\nVersion: 1\n\nPackage: p\nVersion: 1\n\nPackage: q\nVersion: 2\n")}}}
			got, err := (aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"p"}})
			want := map[string][]string{"p": {"1", "1"}, "q": {"2"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"show", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid list_repo_pkgs: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"owner", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("pkg: /x\n")}}}
			got, err := (aptLongtailFunc{"owner", struct {
				Paths []string `statekit:"name=paths"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), &struct {
				Paths []string `statekit:"name=paths"`
			}{Paths: []string{"/x"}})
			if err != nil || got != "pkg" || !reflect.DeepEqual(r.calls[0].Args, []string{"-S", "/x"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"owner", struct {
				Paths []string `statekit:"name=paths"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"paths": "bad"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed owner: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"which", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("pkg: /x\n")}}}
			rt := aptExecRuntime("apt", r)
			if err := rt.FS.WriteFile("/x", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := (aptLongtailFunc{"which", PathArgs{}}).Execute(context.Background(), rt, &PathArgs{Path: "/x"})
			if err != nil || got != "pkg" || !reflect.DeepEqual(r.calls[0].Args, []string{"-S", "/x"}) {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"which", PathArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PathArgs{Path: "relative"})
			if err != nil || got != false || len(r.calls) != 0 {
				t.Fatalf("invalid which: got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}},
		{"file_list", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\tp\n")}, {Stdout: []byte("/a\n\n/a\n")}}}
			got, err := (aptLongtailFunc{"file_list", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"p"}})
			want := map[string]any{"errors": []string{}, "files": []string{"/a"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[1].Args, []string{"-L", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\tp\n")}, {Stdout: []byte("/a\n")}}}
			got, err := (aptLongtailFunc{"file_list", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{"/a"}}) || len(r.calls) != 2 {
				t.Fatalf("empty file_list: got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}},
		{"file_dict", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\ta\ninstalled\tb\n")}, {Stdout: []byte("/a\n")}, {Stdout: []byte("/b\n")}}}
			got, err := (aptLongtailFunc{"file_dict", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"a", "b"}})
			want := map[string]any{"errors": []string{}, "packages": map[string]any{"a": []string{"/a"}, "b": []string{"/b"}}}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != 3 {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"file_dict", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid file_dict: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"info_installed", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p\t1\tinstall ok installed\n")}}}
			got, err := (aptLongtailFunc{"info_installed", InfoArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &InfoArgs{Failhard: boolptr(false)})
			want := map[string]any{"p": map[string]any{"name": "p", "version": "1"}}
			if err != nil || !reflect.DeepEqual(got, want) || r.calls[0].Name != "dpkg-query" {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"info_installed", InfoArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &InfoArgs{Failhard: boolptr(true)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("failhard info_installed: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_downloaded", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("a 1\n")}}}
			rt := aptExecRuntime("apt", r)
			if err := rt.FS.MkdirAll("/root/var/cache/apt/archives", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := rt.FS.WriteFile("/root/var/cache/apt/archives/a.deb", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := (aptLongtailFunc{"list_downloaded", struct {
				Root string `statekit:"name=root"`
			}{}}).Execute(context.Background(), rt, &struct {
				Root string `statekit:"name=root"`
			}{Root: "/root"})
			meta := got.(map[string]any)["a"].(map[string]any)["1"].(map[string]any)
			if err != nil || !reflect.DeepEqual(meta["path"], "/root/var/cache/apt/archives/a.deb") || !reflect.DeepEqual(meta["size"], int64(1)) || meta["creation_date_time_t"] == nil || meta["creation_date_time"] == nil || len(r.calls) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"list_downloaded", struct {
				Root string `statekit:"name=root"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"root": 7})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed list_downloaded: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"services_need_restart", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("SERVICE:sshd,123\nSERVICE:cron,4\n")}}}
			got, err := (aptLongtailFunc{"services_need_restart", struct{}{}}).Execute(context.Background(), aptExecRuntime("apt", r), struct{}{})
			if err != nil || !reflect.DeepEqual(got, []string{"sshd", "cron"}) || !reflect.DeepEqual(r.calls[0].Args, []string{"--machine", "--package"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Err: context.Canceled, ExitCode: -1}}}
			_, err := (aptLongtailFunc{"services_need_restart", struct{}{}}).Execute(context.Background(), aptExecRuntime("apt", r), struct{}{})
			if !errors.Is(err, context.Canceled) || len(r.calls) != 1 {
				t.Fatalf("services failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.positive(t); tc.negative(t) })
	}
	if len(cases) != 21 {
		t.Fatalf("contract matrix has %d functions, want 21", len(cases))
	}
}

func TestAPTLongtailCapabilityRejectsYumOnlyFunctionsBeforeRunner(t *testing.T) {
	cases := []struct {
		name string
		args any
	}{
		{"normalize_name", &NormalizeNameArgs{}}, {"parse_arch", &ParseArchArgs{}}, {"version_cmp", &VersionCmpArgs{}},
		{"get_selections", &SelectionsArgs{}}, {"set_selections", &SetSelectionsArgs{}}, {"unhold", &PackagesArgs{}},
		{"autoremove", &AutoremoveArgs{}}, {"purge", &PackagesArgs{}}, {"upgrade", &UpgradeArgs{}}, {"list_upgrades", &ListUpgradesArgs{}},
		{"upgrade_available", &NormalizeNameArgs{}}, {"show", &ShowArgs{}}, {"list_repo_pkgs", &FilePackagesArgs{}},
		{"owner", &struct {
			Paths []string `statekit:"name=paths"`
		}{}}, {"which", &PathArgs{}}, {"file_list", &FilePackagesArgs{}},
		{"file_dict", &FilePackagesArgs{}}, {"info_installed", &InfoArgs{}}, {"list_downloaded", &struct {
			Root string `statekit:"name=root"`
		}{}},
		{"services_need_restart", &struct{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "normalize_name" || tc.name == "parse_arch" || tc.name == "version_cmp" || tc.name == "file_list" || tc.name == "file_dict" || tc.name == "info_installed" || tc.name == "owner" || tc.name == "list_repo_pkgs" || tc.name == "upgrade" || tc.name == "list_upgrades" || tc.name == "upgrade_available" || tc.name == "list_downloaded" || tc.name == "unhold" {
				t.Skip("shared provider-aware function")
			}
			r := &aptFakeRunner{}
			if tc.name == "services_need_restart" {
				t.Skip("provider-aware function")
			}
			_, err := (aptLongtailFunc{tc.name, tc.args}).Execute(context.Background(), aptExecRuntime("dnf", r), tc.args)
			if errors.As(err, new(*runtime.UnsupportedError)) == false || len(r.calls) != 0 {
				t.Fatalf("err=%v calls=%d", err, len(r.calls))
			}
		})
	}
}

func TestAPTSetSelectionsBoundedInputRejectsBeforeRunner(t *testing.T) {
	r := &aptFakeRunner{}
	name := strings.Repeat("x", 1<<20)
	_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {name}}})
	if err == nil || len(r.calls) != 0 {
		t.Fatalf("oversized selection: err=%v calls=%d", err, len(r.calls))
	}
}

func TestAPTArgsExposeSaltNamesAndRejectLegacyPackages(t *testing.T) {
	for _, tc := range []struct {
		name string
		args any
		want []string
	}{
		{"hold", PackagesArgs{}, []string{"name", "pkgs", "sources"}},
		{"unhold", PackagesArgs{}, []string{"name", "pkgs", "sources"}},
		{"purge", PurgeArgs{}, []string{"name", "pkgs"}},
	} {
		got, err := config.ArgumentNames(tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s args = %#v, %v; want %#v", tc.name, got, err, tc.want)
		}
	}
	r := &aptFakeRunner{}
	_, err := (aptLongtailFunc{"purge", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"packages": []string{"legacy"}})
	if err == nil || len(r.calls) != 0 {
		t.Fatalf("legacy packages must be rejected before Runner: %v, calls=%d", err, len(r.calls))
	}
}

func TestAPTFileFunctionsUseRegisteredPackagesPrototype(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pkg.file_list", "pkg.file_dict", "pkg.list_repo_pkgs"} {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if _, ok := fn.Args().(FilePackagesArgs); !ok {
			t.Fatalf("%s prototype = %T, want FilePackagesArgs", name, fn.Args())
		}
		keys, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(keys, []string{"packages"}) {
			t.Fatalf("%s prototype keys = %#v, %v", name, keys, err)
		}
	}
	for _, name := range []string{"file_list", "file_dict", "list_repo_pkgs"} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				label string
				args  any
			}{
				{"malformed", map[string]any{"packages": "not-a-list"}},
				{"legacy", map[string]any{"pkgs": []string{"p"}}},
				{"conflict", map[string]any{"packages": []string{"p"}, "pkgs": []string{"q"}}},
			} {
				r := &aptFakeRunner{}
				_, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), name, tc.args)
				if err == nil || len(r.calls) != 0 {
					t.Fatalf("%s %s: err=%v calls=%d", name, tc.label, err, len(r.calls))
				}
			}
		})
	}
}

func TestAPTVersionCmpPropagatesRunnerErrorsAndInvalidStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want error
	}{
		{"cancel", process.CommandResult{Err: context.Canceled, ExitCode: -1}, context.Canceled},
		{"output-limit", process.CommandResult{Err: process.ErrOutputLimit, ExitCode: -1}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{tc.res}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1", Pkg2: "2"})
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
	r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 2}}}
	got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "bad", Pkg2: "also-bad"})
	if err != nil || got != nil {
		t.Fatalf("invalid comparison status: got=%#v err=%v", got, err)
	}
	r = &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9, Stderr: []byte("failed")}}}
	if _, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1", Pkg2: "2"}); err == nil {
		t.Fatal("unexpected child status must be returned")
	}
}

func TestAPTExplicitEmptyAndConflictingPkgsAreNotIgnored(t *testing.T) {
	for _, args := range []any{
		map[string]any{"name": "one", "pkgs": []string{}},
		map[string]any{"name": "one", "pkgs": []string{"two"}},
	} {
		r := &aptFakeRunner{}
		_, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "purge", args)
		if err != nil {
			t.Fatalf("package selection: err=%v calls=%d", err, len(r.calls))
		}
	}
}

// pkgproviderTestAPT keeps this test focused on the public execution boundary.
type pkgproviderTestAPT struct{}

func (*pkgproviderTestAPT) execute(ctx context.Context, rt *runtime.Runtime, name string, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	return p.(pkgprovider.AptProvider).Apt(ctx, rt, name, args.(map[string]any))
}

func TestAPTSetSelectionsFailedQueryNeverClears(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9}}}
	_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{
		Selection: map[string][]string{"hold": {"pkg"}}, Clear: func() *bool { v := true; return &v }(),
	})
	if err == nil || len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "*"}) {
		t.Fatalf("failed prerequisite mutated selections: err=%v calls=%#v", err, r.calls)
	}
}

func TestAPTTargetPrecedenceAndSources(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed two 1 amd64\n")}, {}, {Stdout: []byte("install ok installed two 1 amd64\n")}}}
	got, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "purge", map[string]any{"name": "one", "pkgs": []string{"two"}})
	if err != nil || got == nil || len(r.calls) != 3 || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "purge", "two"}) {
		t.Fatalf("pkgs precedence: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
	r = &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p install\n")}, {}}}
	got, err = (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "hold", map[string]any{"sources": []any{map[string]any{"p": "file.deb"}}})
	if err != nil || got == nil || len(r.calls) != 2 || string(r.calls[1].Stdin) != "p hold\n" {
		t.Fatalf("source target extraction: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
}

func TestAPTDownloadedRecursiveAndNilFS(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("a 1\n")}, {Stdout: []byte("b 2\n")}}}
	rt := aptExecRuntime("apt", r)
	if err := rt.FS.MkdirAll("/root/var/cache/apt/archives/nested", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/root/var/cache/apt/archives/nested/b.deb", []byte("bb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/root/var/cache/apt/archives/a.deb", []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (aptLongtailFunc{"list_downloaded", DownloadedArgs{}}).Execute(context.Background(), rt, &DownloadedArgs{Root: strptr("/root")})
	if err != nil || len(got.(map[string]any)) != 2 || !reflect.DeepEqual(r.calls[0].Args, []string{"-f", "/root/var/cache/apt/archives/a.deb", "Package", "Version"}) {
		t.Fatalf("recursive downloaded: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
	rt = aptExecRuntime("apt", &aptFakeRunner{})
	rt.FS = nil
	_, err = (aptLongtailFunc{"list_downloaded", DownloadedArgs{}}).Execute(context.Background(), rt, &DownloadedArgs{})
	if err == nil {
		t.Fatal("nil filesystem must be unsupported")
	}
}

// This is deliberately an actual ExecRegistry matrix, rather than direct
// provider calls: the registry contract includes provider-specific prototypes
// and the no-side-effect capability gate.
func TestUpgradeRegistryActualProviderMatrix(t *testing.T) {
	boolp := func(v bool) *bool { return &v }
	type row struct {
		provider string
		name     string
		proto    reflect.Type
		args     []string
		call     any
		result   []process.CommandResult
		argv     [][]string
		want     any
	}
	rows := []row{
		{"apt", "pkg.list_upgrades", reflect.TypeOf(ListUpgradesArgs{}), []string{"cache_valid_time", "dist_upgrade", "refresh"}, &ListUpgradesArgs{Refresh: boolp(false), DistUpgrade: boolp(false)}, []process.CommandResult{{Stdout: []byte("Conf foo (2.0 Ubuntu:1)\n")}}, [][]string{{"apt-get", "--just-print", "upgrade"}}, map[string]string{"foo": "2.0"}},
		{"apt", "pkg.upgrade_available", reflect.TypeOf(NormalizeNameArgs{}), []string{"name"}, &NormalizeNameArgs{Name: "foo"}, []process.CommandResult{{Stdout: []byte("1.0\n")}, {Stdout: []byte("Candidate: 2.0\n")}, {ExitCode: 1}, {ExitCode: 1}, {}}, [][]string{{"dpkg-query", "-W", "-f=${Version}\n", "foo"}, {"apt-cache", "policy", "foo"}, {"dpkg", "--compare-versions", "1.0", "lt", "2.0"}, {"dpkg", "--compare-versions", "1.0", "eq", "2.0"}, {"dpkg", "--compare-versions", "1.0", "gt", "2.0"}}, true},
		{"yum", "pkg.list_upgrades", reflect.TypeOf(YumListUpgradesArgs{}), []string{"branch", "disableexcludes", "disablerepo", "enablerepo", "fromrepo", "refresh", "repo", "setopt"}, &YumListUpgradesArgs{Refresh: boolp(false), Fromrepo: strptr("base"), Setopt: []string{"a=1"}}, []process.CommandResult{{Stdout: []byte("foo.x86_64 2.0-1 @base\n")}}, [][]string{{"yum", "--quiet", "--disablerepo=*", "--enablerepo=base", "--setopt=a=1", "list", "updates"}}, map[string]string{"foo": "2.0-1"}},
		{"yum", "pkg.upgrade_available", reflect.TypeOf(YumUpgradeAvailableArgs{}), []string{"branch", "disableexcludes", "disablerepo", "enablerepo", "fromrepo", "name", "refresh", "repo", "setopt"}, &YumUpgradeAvailableArgs{Name: "foo", Refresh: boolp(false)}, []process.CommandResult{{Stdout: []byte("installed packages\n")}, {Stdout: []byte("foo.noarch 2.0-1 @base\n")}}, [][]string{{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"}, {"yum", "--quiet", "list", "available", "foo"}}, true},
	}
	for _, tc := range rows {
		t.Run(tc.provider+"/"+tc.name, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			r := &aptFakeRunner{results: tc.result}
			family := facts.FamilyRedHat
			if tc.provider == "apt" {
				family = facts.FamilyDebian
			}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: tc.provider, OS: &facts.OSFacts{Family: family}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: runtime.NewProviderRegistry(), Runner: r}
			if err := pkgprovider.Register(rt.Providers); err != nil {
				t.Fatal(err)
			}
			prototype, err := reg.ResolveArgs(rt, tc.name)
			if err != nil || reflect.TypeOf(prototype) != tc.proto {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			names, err := config.ArgumentNames(prototype)
			if tc.provider == "apt" && tc.name == "pkg.list_upgrades" {
				if err != nil || !reflect.DeepEqual(names, tc.args) {
					t.Fatalf("arg names=%v err=%v", names, err)
				}
			} else if err != nil || !reflect.DeepEqual(names, tc.args) {
				t.Fatalf("arg names=%v err=%v", names, err)
			}
			wantCaps := []string{"aptpkg", "yumpkg"}
			if tc.name == "pkg.file_list" || tc.name == "pkg.file_dict" || tc.name == "pkg.info_installed" || tc.name == "pkg.owner" || tc.name == "pkg.list_upgrades" || tc.name == "pkg.upgrade_available" {
				wantCaps = []string{"aptpkg", "yumpkg", "zypperpkg"}
			}
			if got := reg.ProviderCapabilities(tc.name); !reflect.DeepEqual(got, wantCaps) {
				t.Fatalf("capabilities=%v", got)
			}
			before := reflect.ValueOf(tc.call).Elem().Interface()
			got, err := reg.Call(context.Background(), rt, tc.name, tc.call)
			if err != nil || !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(commandArgv(r.calls), tc.argv) {
				t.Fatalf("got=%#v err=%v argv=%#v", got, err, commandArgv(r.calls))
			}
			if !reflect.DeepEqual(reflect.ValueOf(tc.call).Elem().Interface(), before) {
				t.Fatal("registry call mutated arguments")
			}
			for _, bad := range []any{nil, 1, &AutoremoveArgs{}} {
				badRunner := &aptFakeRunner{}
				rt.Runner = badRunner
				if got, err := reg.Call(context.Background(), rt, tc.name, bad); got != nil || err == nil || len(badRunner.calls) != 0 {
					t.Fatalf("bad args=%T got=%#v err=%v calls=%d", bad, got, err, len(badRunner.calls))
				}
			}
		})
	}

	for _, provider := range []string{"dnf", "dnf5"} {
		for _, name := range []string{"pkg.list_upgrades", "pkg.upgrade_available"} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				reg := runtime.NewExecRegistry()
				if err := Register(reg); err != nil {
					t.Fatal(err)
				}
				r := &aptFakeRunner{}
				rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: provider, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: runtime.NewProviderRegistry(), Runner: r}
				if err := pkgprovider.Register(rt.Providers); err != nil {
					t.Fatal(err)
				}
				prototype, err := reg.ResolveArgs(rt, name)
				if err != nil {
					t.Fatal(err)
				}
				args := any(&YumListUpgradesArgs{})
				if name == "pkg.upgrade_available" {
					args = &YumUpgradeAvailableArgs{Name: "foo", Refresh: boolp(false)}
				}
				if name == "pkg.list_upgrades" {
					r.results = []process.CommandResult{{Stdout: []byte("foo.x86_64 2.0-1 @repo\n")}}
				} else {
					r.results = []process.CommandResult{{}, {Stdout: []byte("foo.noarch 2.0-1 @repo\n")}}
				}
				got, err := reg.Call(context.Background(), rt, name, args)
				if err != nil || got == nil || reflect.TypeOf(prototype) == nil || len(r.calls) == 0 {
					t.Fatalf("got=%#v err=%v prototype=%T calls=%d", got, err, prototype, len(r.calls))
				}
			})
		}
	}

	for _, provider := range []string{"zypper"} {
		for _, name := range []string{"pkg.list_upgrades", "pkg.upgrade_available"} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				reg := runtime.NewExecRegistry()
				if err := Register(reg); err != nil {
					t.Fatal(err)
				}
				r := &aptFakeRunner{}
				rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: provider}), Providers: runtime.NewProviderRegistry(), Runner: r}
				if err := pkgprovider.Register(rt.Providers); err != nil {
					t.Fatal(err)
				}
				if _, err := reg.ResolveArgs(rt, name); err != nil {
					t.Fatalf("resolve err=%v", err)
				}
				if got, err := reg.Call(context.Background(), rt, name, &YumListUpgradesArgs{}); got != nil || err == nil || len(r.calls) != 0 {
					t.Fatalf("call got=%#v err=%v calls=%d", got, err, len(r.calls))
				}
			})
		}
	}
	for _, tc := range []struct {
		provider string
		results  []process.CommandResult
		want     [][]string
	}{
		{"apt", []process.CommandResult{{}, {Stdout: []byte("Conf foo (2.0 Ubuntu:1)\n")}}, [][]string{{"apt-get", "update"}, {"apt-get", "--just-print", "dist-upgrade"}}},
		{"yum", []process.CommandResult{{}, {Stdout: []byte("foo.x86_64 2.0-1 @repo\n")}}, [][]string{{"yum", "--quiet", "--assumeyes", "clean", "expire-cache"}, {"yum", "--quiet", "list", "updates"}}},
	} {
		t.Run(tc.provider+"/refresh-default", func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			r := &aptFakeRunner{results: tc.results}
			family := facts.FamilyRedHat
			if tc.provider == "apt" {
				family = facts.FamilyDebian
			}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: tc.provider, OS: &facts.OSFacts{Family: family}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: runtime.NewProviderRegistry(), Runner: r}
			if err := pkgprovider.Register(rt.Providers); err != nil {
				t.Fatal(err)
			}
			var args any = &ListUpgradesArgs{}
			if tc.provider != "apt" {
				args = &YumListUpgradesArgs{}
			}
			got, err := reg.Call(context.Background(), rt, "pkg.list_upgrades", args)
			if err != nil || got == nil || !reflect.DeepEqual(commandArgv(r.calls), tc.want) {
				t.Fatalf("got=%#v err=%v argv=%#v", got, err, commandArgv(r.calls))
			}
		})
	}
}

func TestListDownloadedRegistryActualProviderMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"apt", "yum", "dnf", "dnf5", "zypper"} {
		t.Run(provider, func(t *testing.T) {
			r := &aptFakeRunner{}
			family := facts.FamilyRedHat
			if provider == "apt" {
				family = facts.FamilyDebian
			}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: provider, OS: &facts.OSFacts{Family: family}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: runtime.NewProviderRegistry(), Runner: r, FS: runtime.NewMemoryFS()}
			if err := pkgprovider.Register(rt.Providers); err != nil {
				t.Fatal(err)
			}
			prototype, err := reg.ResolveArgs(rt, "pkg.list_downloaded")
			if provider == "zypper" {
				if err == nil || !errors.As(err, new(*runtime.UnsupportedError)) {
					t.Fatalf("zypper resolve err=%v", err)
				}
				if got, callErr := reg.Call(context.Background(), rt, "pkg.list_downloaded", &DownloadedArgs{}); got != nil || callErr == nil || !errors.As(callErr, new(*runtime.UnsupportedError)) || len(r.calls) != 0 {
					t.Fatalf("zypper call got=%#v err=%v calls=%d", got, callErr, len(r.calls))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if provider == "apt" {
				if reflect.TypeOf(prototype) != reflect.TypeOf(DownloadedArgs{}) {
					t.Fatalf("APT prototype=%T", prototype)
				}
				if err := rt.FS.MkdirAll("/root/var/cache/apt/archives", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := rt.FS.WriteFile("/root/var/cache/apt/archives/a.deb", []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				r.results = []process.CommandResult{{Stdout: []byte("a 1\n")}}
				got, callErr := reg.Call(context.Background(), rt, "pkg.list_downloaded", &DownloadedArgs{Root: strptr("/root")})
				if callErr != nil || got == nil || len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0].Args, []string{"-f", "/root/var/cache/apt/archives/a.deb", "Package", "Version"}) {
					t.Fatalf("APT call got=%#v err=%v calls=%#v", got, callErr, r.calls)
				}
				return
			}
			if reflect.TypeOf(prototype) != reflect.TypeOf(struct{}{}) {
				t.Fatalf("YUM prototype=%T", prototype)
			}
			root := "/var/cache/" + provider
			for _, dir := range []string{root + "/nested/deeper"} {
				if err := rt.FS.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				root + "/first.rpm":               "one",
				root + "/nested/duplicate.rpm":    "two-two",
				root + "/nested/deeper/other.rpm": "three",
				root + "/ignored.txt":             "no",
			}
			for path, body := range files {
				if err := rt.FS.WriteFile(path, []byte(body), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if err := rt.FS.MkdirAll(root+"/nonregular.rpm", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := rt.FS.Symlink(root+"/first.rpm", root+"/final-symlink.rpm"); err != nil {
				t.Fatal(err)
			}
			baseFS := rt.FS.(*runtime.MemoryFS)
			fsys := &registryYumSpecialFS{MemoryFS: baseFS, root: root, info: map[string]fs.FileInfo{
				root + "/redirected.rpm": registryYumSpecialInfo{mode: fs.ModeSymlink},
				root + "/special.rpm":    registryYumSpecialInfo{mode: fs.ModeNamedPipe},
			}}
			rt.FS = fsys
			format := "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}"
			r.results = []process.CommandResult{
				{Stdout: []byte("demo_|-1_|-1.0_|-1_|-x86_64_|-none_|-0")},
				{Stdout: []byte("demo_|-1_|-1.0_|-1_|-x86_64_|-none_|-0")},
				{Stdout: []byte("other_|-(none)_|-2.0_|-(none)_|-x86_64_|-none_|-0")},
			}
			before := map[string]any{"root": "/ignored", "extra": map[string]any{"keep": true}}
			args := &struct{}{}
			beforeArgs := *args
			got, callErr := reg.Call(context.Background(), rt, "pkg.list_downloaded", args)
			if callErr != nil {
				t.Fatalf("%s call err=%v", provider, callErr)
			}
			result := got.(map[string]any)
			duplicate := result["demo"].(map[string]any)["1:1.0-1"].(map[string]any)
			info, statErr := rt.FS.Stat(root + "/nested/duplicate.rpm")
			if statErr != nil || info.Size() != 7 || duplicate["path"] != root+"/nested/duplicate.rpm" || duplicate["size"] != int64(7) || duplicate["creation_date_time_t"] != info.ModTime().Unix() || duplicate["creation_date_time"] != info.ModTime().Local().Format("2006-01-02T15:04:05") {
				t.Fatalf("%s metadata=%#v stat=%v", provider, duplicate, statErr)
			}
			wantArgs := [][]string{{"rpm", "-qp", "--queryformat", format, root + "/first.rpm"}, {"rpm", "-qp", "--queryformat", format, root + "/nested/duplicate.rpm"}, {"rpm", "-qp", "--queryformat", format, root + "/nested/deeper/other.rpm"}}
			if !reflect.DeepEqual(commandArgv(r.calls), wantArgs) {
				t.Fatalf("%s argv=%#v", provider, commandArgv(r.calls))
			}
			for _, cmd := range r.calls {
				if cmd.MaxStdoutBytes != 4096 || cmd.MaxStderrBytes != 4096 {
					t.Fatalf("%s bounds=%#v", provider, cmd)
				}
			}
			if !reflect.DeepEqual(before, map[string]any{"root": "/ignored", "extra": map[string]any{"keep": true}}) || *args != beforeArgs || fsys.writes != 0 {
				t.Fatal("registry arguments mutated")
			}
		})
	}
	for _, bad := range []any{nil, 1, &DownloadedArgs{}} {
		r := &aptFakeRunner{}
		rt := aptExecRuntime("yum", r)
		if got, err := reg.Call(context.Background(), rt, "pkg.list_downloaded", bad); got != nil || err == nil || len(r.calls) != 0 {
			t.Fatalf("wrong YUM args=%T got=%#v err=%v calls=%d", bad, got, err, len(r.calls))
		}
	}
}

func TestListDownloadedRegistryActualProviderFailures(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"yum", "dnf", "dnf5"} {
		t.Run(provider, func(t *testing.T) {
			managerFS := runtime.NewMemoryFS()
			root := "/var/cache/" + provider
			if err := managerFS.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := managerFS.WriteFile(root+"/one.rpm", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			newRuntime := func(fsys runtime.FileSystem, results ...process.CommandResult) (*runtime.Runtime, *aptFakeRunner) {
				r := &aptFakeRunner{results: results}
				rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: provider, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: runtime.NewProviderRegistry(), Runner: r, FS: fsys}
				if err := pkgprovider.Register(rt.Providers); err != nil {
					t.Fatal(err)
				}
				return rt, r
			}
			cases := []struct {
				name string
				fsys runtime.FileSystem
				ctx  context.Context
				res  process.CommandResult
				want error
			}{
				{"missing", runtime.NewMemoryFS(), context.Background(), process.CommandResult{}, nil},
				{"unsupported", registryBoundedDirErrorFS{FileSystem: managerFS, err: runtime.ErrBoundedDirUnsupported}, context.Background(), process.CommandResult{}, runtime.ErrBoundedDirUnsupported},
				{"overflow", registryBoundedDirErrorFS{FileSystem: managerFS, err: runtime.ErrDirReadLimit}, context.Background(), process.CommandResult{}, runtime.ErrDirReadLimit},
				{"runner-error", managerFS, context.Background(), process.CommandResult{Err: context.Canceled}, context.Canceled},
				{"output-limit", managerFS, context.Background(), process.CommandResult{Err: process.ErrOutputLimit}, process.ErrOutputLimit},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					rt, r := newRuntime(tc.fsys, tc.res)
					ctx := tc.ctx
					if tc.name == "runner-error" || tc.name == "output-limit" {
						// The shared fixture is intentionally reused; registry dispatch must not mutate it.
					}
					got, err := reg.Call(ctx, rt, "pkg.list_downloaded", &struct{}{})
					if tc.want == nil {
						if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(r.calls) != 0 {
							t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
						}
					} else if got != nil || (tc.name == "overflow" && err == nil) || (tc.name != "overflow" && !errors.Is(err, tc.want)) || len(r.calls) > 1 {
						t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
					}
				})
			}
		})
	}
}
