package pkg

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type downloadRegistryRunner struct {
	available         bool
	availabilityCalls int
	commands          []process.Command
	onRun             func(process.Command)
}

func (r *downloadRegistryRunner) CommandAvailable(name string) bool {
	r.availabilityCalls++
	return r.available && name == "yumdownloader"
}

func (r *downloadRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.onRun != nil {
		r.onRun(command)
	}
	return process.CommandResult{}
}

type downloadRegistryFS struct {
	*runtime.MemoryFS
	mkdirPaths []string
	mkdirModes []fs.FileMode
	readPaths  []string
	readLimits []int
	removes    []string
}

func newDownloadRegistryFS() *downloadRegistryFS {
	return &downloadRegistryFS{MemoryFS: runtime.NewMemoryFS()}
}

func (f *downloadRegistryFS) MkdirAll(name string, perm fs.FileMode) error {
	f.mkdirPaths = append(f.mkdirPaths, name)
	f.mkdirModes = append(f.mkdirModes, perm)
	return f.MemoryFS.MkdirAll(name, perm)
}

func (f *downloadRegistryFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	f.readPaths = append(f.readPaths, name)
	f.readLimits = append(f.readLimits, max)
	return f.MemoryFS.ReadDirBounded(name, max)
}

func (f *downloadRegistryFS) ReadDir(string) ([]fs.DirEntry, error) {
	panic("pkg.download used unbounded ReadDir")
}

func (f *downloadRegistryFS) Remove(name string) error {
	f.removes = append(f.removes, name)
	return f.MemoryFS.Remove(name)
}

func newDownloadRegistryRuntime(t *testing.T, manager string) (*runtime.Runtime, *downloadRegistryFS, *downloadRegistryRunner) {
	t.Helper()
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	fsys := newDownloadRegistryFS()
	runner := &downloadRegistryRunner{available: true}
	rt := &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: facts.FamilyRedHat},
		}),
		Providers: providers,
		FS:        fsys,
		Runner:    runner,
	}
	return rt, fsys, runner
}

func writeDownloadRegistryRPM(t *testing.T, fsys *downloadRegistryFS, path string) {
	t.Helper()
	if err := fsys.MemoryFS.WriteFile(path, []byte("rpm"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadRegistryYUMProviderMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	registered := 0
	for _, name := range reg.Names() {
		if name == "pkg.download" {
			registered++
		}
	}
	if registered != 1 {
		t.Fatalf("pkg.download registrations=%d", registered)
	}
	fn, ok := reg.Get("pkg.download")
	if !ok || reflect.TypeOf(fn.Args()) != reflect.TypeOf(DownloadArgs{}) {
		t.Fatalf("function=%T args=%T", fn, fn.Args())
	}
	if caps := reg.ProviderCapabilities("pkg.download"); !reflect.DeepEqual(caps, []string{"yumpkg"}) {
		t.Fatalf("capabilities=%v", caps)
	}

	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			rt, fsys, runner := newDownloadRegistryRuntime(t, manager)
			cache := "/var/cache/" + manager + "/packages"
			prototype, err := reg.ResolveArgs(rt, "pkg.download")
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(DownloadArgs{}) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			names, err := config.ArgumentNames(prototype)
			if err != nil || !reflect.DeepEqual(names, []string{"packages"}) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			packages := []string{"alpha", "beta"}
			before := append([]string(nil), packages...)
			runner.onRun = func(process.Command) {
				writeDownloadRegistryRPM(t, fsys, cache+"/alpha-1.rpm")
				writeDownloadRegistryRPM(t, fsys, cache+"/beta-2.rpm")
			}
			got, err := reg.Call(context.Background(), rt, "pkg.download", &DownloadArgs{Packages: packages})
			want := map[string]any{"alpha": cache + "/alpha-1.rpm", "beta": cache + "/beta-2.rpm"}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			if !reflect.DeepEqual(packages, before) {
				t.Fatalf("input mutated: %v", packages)
			}
			if len(runner.commands) != 1 {
				t.Fatalf("commands=%#v", runner.commands)
			}
			command := runner.commands[0]
			wantArgs := []string{"-q", "--destdir=" + cache, "alpha", "beta"}
			if command.Name != "yumdownloader" || !reflect.DeepEqual(command.Args, wantArgs) || command.Shell ||
				command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
				t.Fatalf("command=%#v", command)
			}
			if !reflect.DeepEqual(fsys.mkdirPaths, []string{cache}) || !reflect.DeepEqual(fsys.mkdirModes, []fs.FileMode{0o755}) ||
				!reflect.DeepEqual(fsys.readPaths, []string{cache, cache}) || len(fsys.readLimits) != 2 || fsys.readLimits[0] != runtime.MaxBoundedDirEntries || fsys.readLimits[1] != runtime.MaxBoundedDirEntries {
				t.Fatalf("fs mkdir=%v/%v reads=%v/%v", fsys.mkdirPaths, fsys.mkdirModes, fsys.readPaths, fsys.readLimits)
			}
		})
	}
}

func TestDownloadRegistryRejectsUnsupportedProvidersBeforeWork(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt", "zypper"} {
		t.Run(manager, func(t *testing.T) {
			rt, fsys, runner := newDownloadRegistryRuntime(t, manager)
			prototype, err := reg.ResolveArgs(rt, "pkg.download")
			var unsupported *runtime.UnsupportedError
			if prototype != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != manager {
				t.Fatalf("resolve prototype=%#v err=%T %v", prototype, err, err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.download", &DownloadArgs{Packages: []string{"alpha"}})
			unsupported = nil
			if got != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != manager {
				t.Fatalf("call got=%#v err=%T %v", got, err, err)
			}
			if len(fsys.mkdirPaths) != 0 || len(fsys.readPaths) != 0 || len(fsys.removes) != 0 || len(runner.commands) != 0 || runner.availabilityCalls != 0 {
				t.Fatalf("unsupported provider touched runtime: mkdir=%v reads=%v removes=%v commands=%v availability=%d", fsys.mkdirPaths, fsys.readPaths, fsys.removes, runner.commands, runner.availabilityCalls)
			}
		})
	}
}

func TestDownloadRegistryStrictArgsAndTestModeDoNotMutate(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, fsys, runner := newDownloadRegistryRuntime(t, "yum")
	got, err := reg.Call(context.Background(), rt, "pkg.download", &struct{}{})
	if got != nil || err == nil || len(fsys.mkdirPaths) != 0 || len(runner.commands) != 0 {
		t.Fatalf("malformed args got=%#v err=%v mkdir=%v commands=%v", got, err, fsys.mkdirPaths, runner.commands)
	}

	rt, fsys, runner = newDownloadRegistryRuntime(t, "yum")
	rt.Options.Test = true
	got, err = reg.Call(context.Background(), rt, "pkg.download", &DownloadArgs{Packages: []string{"alpha"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("test mode got=%#v err=%v", got, err)
	}
	if len(fsys.mkdirPaths) != 0 || len(fsys.readPaths) != 0 || len(fsys.removes) != 0 || len(runner.commands) != 0 || runner.availabilityCalls != 0 {
		t.Fatalf("test mode touched runtime: mkdir=%v reads=%v removes=%v commands=%v availability=%d", fsys.mkdirPaths, fsys.readPaths, fsys.removes, runner.commands, runner.availabilityCalls)
	}
}
