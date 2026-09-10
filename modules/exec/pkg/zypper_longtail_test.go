package pkg

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type execZypperNoCallFS struct{ calls int }

func (f *execZypperNoCallFS) fail()                                       { f.calls++; panic("zypper registry pure function invoked FS") }
func (f *execZypperNoCallFS) Stat(string) (fs.FileInfo, error)            { f.fail(); return nil, nil }
func (f *execZypperNoCallFS) Lstat(string) (fs.FileInfo, error)           { f.fail(); return nil, nil }
func (f *execZypperNoCallFS) ReadFile(string) ([]byte, error)             { f.fail(); return nil, nil }
func (f *execZypperNoCallFS) WriteFile(string, []byte, fs.FileMode) error { f.fail(); return nil }
func (f *execZypperNoCallFS) MkdirAll(string, fs.FileMode) error          { f.fail(); return nil }
func (f *execZypperNoCallFS) MkdirTemp(string, string) (string, error)    { f.fail(); return "", nil }
func (f *execZypperNoCallFS) Remove(string) error                         { f.fail(); return nil }
func (f *execZypperNoCallFS) RemoveAll(string) error                      { f.fail(); return nil }
func (f *execZypperNoCallFS) Rename(string, string) error                 { f.fail(); return nil }
func (f *execZypperNoCallFS) Symlink(string, string) error                { f.fail(); return nil }
func (f *execZypperNoCallFS) Link(string, string) error                   { f.fail(); return nil }
func (f *execZypperNoCallFS) Glob(string) ([]string, error)               { f.fail(); return nil, nil }
func (f *execZypperNoCallFS) Readlink(string) (string, error)             { f.fail(); return "", nil }
func (f *execZypperNoCallFS) ReadDir(string) ([]fs.DirEntry, error)       { f.fail(); return nil, nil }
func (f *execZypperNoCallFS) Chmod(string, fs.FileMode) error             { f.fail(); return nil }
func (f *execZypperNoCallFS) Chown(string, int, int) error                { f.fail(); return nil }
func (f *execZypperNoCallFS) Lchown(string, int, int) error               { f.fail(); return nil }

func zypperRegistryRuntime(manager string, runner process.Runner) *runtime.Runtime {
	return zypperRegistryRuntimeWithArch(manager, "x86_64", runner)
}

func zypperRegistryRuntimeWithArch(manager, arch string, runner process.Runner) *runtime.Runtime {
	family := facts.FamilyRedHat
	if manager == "apt" {
		family = facts.FamilyDebian
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		panic(err)
	}
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: family},
			CPU:     &facts.CPUFacts{Arch: arch},
		}),
		Providers: providers,
		Runner:    runner,
		FS:        &execZypperNoCallFS{},
	}
}

type execZypperRunner struct {
	calls []process.Command
}

func (r *execZypperRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	return process.CommandResult{ExitCode: 0}
}

func TestZypperRegistryMapsGoArchitectureFactsToRPMWithoutSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name, factArch, suffix, want string
	}{
		{"go-amd64", "amd64", "x86_64", "pkg"},
		{"rpm-x86_64", "x86_64", "x86_64", "pkg"},
		{"go-arm64", "arm64", "aarch64", "pkg"},
		{"rpm-aarch64", "aarch64", "aarch64", "pkg"},
		{"go-386", "386", "i686", "pkg"},
		{"rpm-i686", "i686", "i686", "pkg"},
		{"go-arm", "arm", "armv7l", "pkg"},
		{"rpm-armv7l", "armv7l", "armv7l", "pkg"},
		{"foreign-32-bit", "amd64", "i686", "pkg.i686"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			runner := &execZypperRunner{}
			rt := zypperRegistryRuntimeWithArch("zypper", tc.factArch, runner)
			fs := rt.FS.(*execZypperNoCallFS)
			requested := "pkg." + tc.suffix
			calls := []struct {
				name string
				args any
				want any
			}{
				{"pkg.normalize_name", &NormalizeNameArgs{Name: requested}, tc.want},
				{"pkg.parse_arch", &ParseArchArgs{Name: requested}, map[string]any{"name": "pkg", "arch": tc.suffix}},
				{"pkg.version_cmp", &ZypperVersionCmpArgs{Ver1: "1_0:1", Ver2: "2:1"}, 1},
			}
			for _, call := range calls {
				got, err := reg.Call(context.Background(), rt, call.name, call.args)
				if err != nil || !reflect.DeepEqual(got, call.want) {
					t.Fatalf("%s got=%#v err=%v want=%#v", call.name, got, err, call.want)
				}
				if len(runner.calls) != 0 || fs.calls != 0 {
					t.Fatalf("%s side effects: runner=%d fs=%d", call.name, len(runner.calls), fs.calls)
				}
			}
		})
	}
}

func TestZypperRegistryRejectsUnsafeTokensWithoutSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name, function, want string
		args                 func() any
	}{
		{"nul-name", "pkg.normalize_name", "invalid package name", func() any {
			return &NormalizeNameArgs{Name: "pkg.\x00secret"}
		}},
		{"empty-name", "pkg.parse_arch", "invalid package name", func() any {
			return &ParseArchArgs{Name: ""}
		}},
		{"control-version", "pkg.version_cmp", "invalid package version", func() any {
			return &ZypperVersionCmpArgs{Ver1: "1.0\nsecret", Ver2: "1"}
		}},
		{"oversized-version", "pkg.version_cmp", "invalid package version", func() any {
			return &ZypperVersionCmpArgs{Ver1: strings.Repeat("v", 4097), Ver2: "1"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &execZypperRunner{}
			rt := zypperRegistryRuntime("zypper", runner)
			fs := rt.FS.(*execZypperNoCallFS)
			got, err := func() (any, error) {
				reg := runtime.NewExecRegistry()
				if registerErr := Register(reg); registerErr != nil {
					t.Fatal(registerErr)
				}
				return reg.Call(context.Background(), rt, tc.function, tc.args())
			}()
			if got != nil || err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "secret") {
				t.Fatalf("got=%#v err=%v want=%q", got, err, tc.want)
			}
			if len(runner.calls) != 0 || fs.calls != 0 {
				t.Fatalf("side effects: runner=%d fs=%d", len(runner.calls), fs.calls)
			}
		})
	}
}

func TestZypperProviderAwareRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	functions := []struct {
		name        string
		aptType     reflect.Type
		zypperType  reflect.Type
		aptNames    []string
		zypperNames []string
	}{
		{"pkg.normalize_name", reflect.TypeOf(NormalizeNameArgs{}), reflect.TypeOf(NormalizeNameArgs{}), []string{"name"}, []string{"name"}},
		{"pkg.parse_arch", reflect.TypeOf(ParseArchArgs{}), reflect.TypeOf(ParseArchArgs{}), []string{"name"}, []string{"name"}},
		{"pkg.version_cmp", reflect.TypeOf(VersionCmpArgs{}), reflect.TypeOf(ZypperVersionCmpArgs{}), []string{"ignore_epoch", "pkg1", "pkg2"}, []string{"ignore_epoch", "ver1", "ver2"}},
	}
	for _, manager := range []string{"apt", "yum", "dnf", "zypper"} {
		t.Run(manager, func(t *testing.T) {
			runner := &execZypperRunner{}
			rt := zypperRegistryRuntime(manager, runner)
			fs := rt.FS.(*execZypperNoCallFS)
			for _, tc := range functions {
				fn, ok := reg.Get(tc.name)
				if !ok {
					t.Fatalf("missing %s", tc.name)
				}
				strict, ok := fn.(runtime.ProviderArgsStrict)
				if !ok || !strict.ProviderArgsStrict() {
					t.Fatalf("%s is not strict", tc.name)
				}
				prototype, err := reg.ResolveArgs(rt, tc.name)
				if err != nil {
					t.Fatalf("%s resolve: %v", tc.name, err)
				}
				wantType, wantNames := tc.aptType, tc.aptNames
				if manager == "zypper" {
					wantType, wantNames = tc.zypperType, tc.zypperNames
				}
				if reflect.TypeOf(prototype) != wantType {
					t.Fatalf("%s prototype=%T want=%v", tc.name, prototype, wantType)
				}
				if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, wantNames) {
					t.Fatalf("%s names=%v err=%v want=%v", tc.name, names, err, wantNames)
				}
				if tc.name == "pkg.version_cmp" {
					if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(VersionCmpArgs{}) {
						t.Fatalf("canonical Args type=%v", got)
					}
					if manager == "zypper" && !reflect.DeepEqual(prototype, ZypperVersionCmpArgs{}) {
						t.Fatalf("zypper defaults=%#v", prototype)
					}
				}
				wantCaps := []string{"aptpkg", "yumpkg", "zypperpkg"}
				if got := reg.ProviderCapabilities(tc.name); !reflect.DeepEqual(got, wantCaps) {
					t.Fatalf("%s capabilities=%v want=%v", tc.name, got, wantCaps)
				}
			}

			for _, tc := range functions {
				var args any
				switch tc.name {
				case "pkg.normalize_name":
					args = &NormalizeNameArgs{Name: "pkg.x86_64"}
				case "pkg.parse_arch":
					args = &ParseArchArgs{Name: "pkg.x86_64"}
				case "pkg.version_cmp":
					if manager == "zypper" {
						args = &ZypperVersionCmpArgs{Ver1: "1:1.0", Ver2: "0:1.0"}
					} else {
						args = &VersionCmpArgs{Pkg1: "1", Pkg2: "2"}
					}
				}
				got, err := reg.Call(context.Background(), rt, tc.name, args)
				if err != nil {
					t.Fatalf("%s call: %v", tc.name, err)
				}
				if tc.name == "pkg.version_cmp" && manager != "zypper" && got != -1 {
					t.Fatalf("%s result=%#v", manager, got)
				}
				if tc.name == "pkg.version_cmp" && manager == "zypper" && got != 1 {
					t.Fatalf("zypper result=%#v", got)
				}
				if manager == "zypper" {
					var want any
					switch tc.name {
					case "pkg.normalize_name":
						want = "pkg"
					case "pkg.parse_arch":
						want = map[string]any{"name": "pkg", "arch": "x86_64"}
					case "pkg.version_cmp":
						want = 1
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%s exact result=%#v want=%#v", tc.name, got, want)
					}
					if len(runner.calls) != 0 || fs.calls != 0 {
						t.Fatalf("%s side effects: runner=%d fs=%d", tc.name, len(runner.calls), fs.calls)
					}
				}
			}
			callsBefore := len(runner.calls)
			for _, tc := range functions {
				if got, err := reg.Call(context.Background(), rt, tc.name, &AutoremoveArgs{}); got != nil || err == nil || len(runner.calls) != callsBefore {
					t.Fatalf("%s wrong pointer got=%#v err=%v calls=%d", tc.name, got, err, len(runner.calls))
				}
			}
			if manager == "zypper" {
				// Purge gained a zypper prototype; the shared APT pointer is the
				// wrong shape and stops at the strict registry boundary.
				if _, err := reg.ResolveArgs(rt, "pkg.purge"); err != nil {
					t.Fatalf("zypper purge resolve: %v", err)
				}
				if got, err := reg.Call(context.Background(), rt, "pkg.purge", &PurgeArgs{}); got != nil || err == nil || len(runner.calls) != callsBefore {
					t.Fatalf("shared purge pointer got=%#v err=%v calls=%d", got, err, len(runner.calls))
				}
			}
		})
	}

	counts := map[string]int{}
	for _, name := range reg.Names() {
		if name == "pkg.normalize_name" || name == "pkg.parse_arch" || name == "pkg.version_cmp" {
			counts[name]++
		}
	}
	for _, name := range []string{"pkg.normalize_name", "pkg.parse_arch", "pkg.version_cmp"} {
		if counts[name] != 1 {
			t.Fatalf("%s registrations=%d", name, counts[name])
		}
	}
}
