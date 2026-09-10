package pkg

import (
	"bytes"
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

type diffRegistryRunner struct {
	available         map[string]bool
	availabilityCalls []string
	commands          []process.Command
	cache             string
	fsys              *diffRegistryFS
}

func (r *diffRegistryRunner) CommandAvailable(name string) bool {
	r.availabilityCalls = append(r.availabilityCalls, name)
	return r.available[name]
}

func (r *diffRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	switch command.Name {
	case "rpm":
		return process.CommandResult{Stdout: []byte("alpha")}
	case "yumdownloader":
		if err := r.fsys.MemoryFS.WriteFile(r.cache+"/alpha-1.rpm", []byte("rpm"), 0o600); err != nil {
			panic(err)
		}
		return process.CommandResult{}
	case "rpm2cpio":
		return process.CommandResult{Stdout: []byte("archive")}
	case "cpio":
		if !bytes.Equal(command.Stdin, []byte("archive")) {
			panic("unexpected cpio stdin")
		}
		return process.CommandResult{Stdout: []byte("original")}
	case "diff":
		if !bytes.Equal(command.Stdin, []byte("original")) {
			panic("unexpected diff stdin")
		}
		return process.CommandResult{ExitCode: 1, Stdout: []byte("--- source\n+++ current\n")}
	default:
		panic("unexpected command: " + command.Name)
	}
}

type diffRegistryFS struct {
	*runtime.MemoryFS
	operations []string
}

func newDiffRegistryFS() *diffRegistryFS { return &diffRegistryFS{MemoryFS: runtime.NewMemoryFS()} }

func (f *diffRegistryFS) Stat(name string) (fs.FileInfo, error) {
	f.operations = append(f.operations, "stat:"+name)
	return f.MemoryFS.Stat(name)
}
func (f *diffRegistryFS) Lstat(name string) (fs.FileInfo, error) {
	f.operations = append(f.operations, "lstat:"+name)
	return f.MemoryFS.Lstat(name)
}
func (f *diffRegistryFS) MkdirAll(name string, perm fs.FileMode) error {
	f.operations = append(f.operations, "mkdir:"+name)
	return f.MemoryFS.MkdirAll(name, perm)
}
func (f *diffRegistryFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	f.operations = append(f.operations, "readdir:"+name)
	return f.MemoryFS.ReadDirBounded(name, max)
}
func (f *diffRegistryFS) ReadFile(string) ([]byte, error) { panic("pkg.diff direct file read") }

func setupDiffRegistryRuntime(t *testing.T, manager string) (*runtime.Runtime, *diffRegistryFS, *diffRegistryRunner) {
	t.Helper()
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	fsys := newDiffRegistryFS()
	if err := fsys.MemoryFS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.MemoryFS.WriteFile("/etc/file", []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := "/var/cache/" + manager + "/packages"
	runner := &diffRegistryRunner{available: map[string]bool{"yumdownloader": true, "rpm2cpio": true, "cpio": true, "diff": true}, cache: cache, fsys: fsys}
	rt := &runtime.Runtime{
		Facts:     facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}}),
		Providers: providers,
		Runner:    runner,
		FS:        fsys,
	}
	return rt, fsys, runner
}

func registryDiffArgv(commands []process.Command) [][]string {
	out := make([][]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, append([]string{command.Name}, command.Args...))
	}
	return out
}

func TestDiffRegistryProviderMatrixAndCanonicalRegistration(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range reg.Names() {
		if name == "pkg.diff" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("pkg.diff registrations=%d", count)
	}
	if got := reg.ProviderCapabilities("pkg.diff"); !reflect.DeepEqual(got, []string{"yumpkg", "zypperpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}

	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			rt, _, runner := setupDiffRegistryRuntime(t, manager)
			prototype, err := reg.ResolveArgs(rt, "pkg.diff")
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(DiffArgs{}) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"paths"}) {
				t.Fatalf("argument names=%v err=%v", names, err)
			}
			paths := []string{"/etc/file"}
			before := append([]string(nil), paths...)
			got, err := reg.Call(context.Background(), rt, "pkg.diff", &DiffArgs{Paths: paths})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/file": "--- source\n+++ current\n"}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if !reflect.DeepEqual(paths, before) {
				t.Fatalf("input mutated: %v", paths)
			}
			cache := "/var/cache/" + manager + "/packages/alpha-1.rpm"
			want := [][]string{
				{"rpm", "-qf", "--queryformat", "%{name}", "/etc/file"},
				{"yumdownloader", "-q", "--destdir=/var/cache/" + manager + "/packages", "alpha"},
				{"rpm2cpio", cache},
				{"cpio", "-i", "--quiet", "--to-stdout", "./etc/file"},
				{"diff", "-u", "--label", "A /etc/file", "--from-file=-", "--label", "B /etc/file", "/etc/file"},
			}
			if gotArgv := registryDiffArgv(runner.commands); !reflect.DeepEqual(gotArgv, want) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, want)
			}
			for _, command := range runner.commands {
				if command.Shell {
					t.Fatalf("shell command=%#v", command)
				}
				if command.Name == "rpm2cpio" || command.Name == "cpio" || command.Name == "diff" {
					if command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
						t.Fatalf("bounds=%#v", command)
					}
				}
			}
		})
	}

	for _, manager := range []string{"apt"} {
		t.Run(manager, func(t *testing.T) {
			rt, fsys, runner := setupDiffRegistryRuntime(t, manager)
			prototype, err := reg.ResolveArgs(rt, "pkg.diff")
			var unsupported *runtime.UnsupportedError
			if prototype != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != manager {
				t.Fatalf("resolve prototype=%#v err=%T %v", prototype, err, err)
			}
			got, err := reg.Call(context.Background(), rt, "pkg.diff", &DiffArgs{Paths: []string{"/etc/file"}})
			unsupported = nil
			if got != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != manager || len(runner.commands) != 0 || len(runner.availabilityCalls) != 0 || len(fsys.operations) != 0 {
				t.Fatalf("call got=%#v err=%T %v commands=%d availability=%d fs=%v", got, err, err, len(runner.commands), len(runner.availabilityCalls), fsys.operations)
			}
		})
	}
}

func TestDiffRegistryStrictArgsAndTestModeAvoidRunnerAndFilesystem(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, fsys, runner := setupDiffRegistryRuntime(t, "yum")
	if got, err := reg.Call(context.Background(), rt, "pkg.diff", &struct{}{}); got != nil || err == nil || len(runner.commands) != 0 || len(fsys.operations) != 0 {
		t.Fatalf("wrong type got=%#v err=%v commands=%d fs=%v", got, err, len(runner.commands), fsys.operations)
	}

	rt, fsys, runner = setupDiffRegistryRuntime(t, "dnf5")
	rt.Options.Test = true
	got, err := reg.Call(context.Background(), rt, "pkg.diff", &DiffArgs{Paths: []string{"/etc/file"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 || len(runner.availabilityCalls) != 0 || len(fsys.operations) != 0 {
		t.Fatalf("test mode got=%#v err=%v commands=%d availability=%d fs=%v", got, err, len(runner.commands), len(runner.availabilityCalls), fsys.operations)
	}
}

func TestDiffArgsForProviderRejectsNonYumFamilies(t *testing.T) {
	for _, provider := range []string{"apt"} {
		prototype, err := (diffFunc{}).ArgsForProvider(provider)
		var unsupported *runtime.UnsupportedError
		if prototype != nil || !errors.As(err, &unsupported) || unsupported.Name != provider {
			t.Fatalf("provider=%s prototype=%#v err=%v", provider, prototype, err)
		}
	}
	if prototype, err := (diffFunc{}).ArgsForProvider("zypper"); err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperDiffArgs{}) {
		t.Fatalf("zypper prototype=%#v err=%v", prototype, err)
	}
}
