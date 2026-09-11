package pkgutil

// R6.10 mock tests for the Darwin pkgutil surface, mapped onto
// saltstack/salt/modules/mac_pkgutil.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_pkgutil.py: exact
// pkgutil/installer argv, the already-installed short-circuit
// (pytest test_install_already_there asserts the installer never runs),
// installer failure mapping and the registry matrix. All Runner output
// is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// argvPkgutilRunner keeps a live receipt store so install/forget change
// observable state like the real pkgutil database.
type argvPkgutilRunner struct {
	pkgs     []string
	install  string // package id added by a successful installer run
	failInst bool
	calls    []process.Command
}

func (r *argvPkgutilRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	switch command.Name {
	case "pkgutil":
		if len(command.Args) > 0 && command.Args[0] == "--pkgs" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(r.pkgs, "\n"))}
		}
		if len(command.Args) > 1 && command.Args[0] == "--forget" {
			var kept []string
			for _, id := range r.pkgs {
				if id != command.Args[1] {
					kept = append(kept, id)
				}
			}
			r.pkgs = kept
		}
	case "installer":
		if r.failInst {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("installer: cannot open")}
		}
		if r.install != "" {
			r.pkgs = append(r.pkgs, r.install)
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func pkgutilArgvRT(t *testing.T) (*runtime.Runtime, *argvPkgutilRunner) {
	t.Helper()
	runner := &argvPkgutilRunner{pkgs: []string{"com.apple.base", "com.example.old"}}
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: runner}
	if err := rt.FS.WriteFile("/tmp/example.pkg", []byte("pkg"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

func pkgArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestListArgvAndFixture(t *testing.T) {
	rt, runner := pkgutilArgvRT(t)
	res, err := (listFunc{}).Execute(context.Background(), rt, listArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// pkgutil.list is splitlines: the fixture splits as-is.
	want := []string{"com.apple.base", "com.example.old"}
	if !reflect.DeepEqual(res.([]string), want) {
		t.Fatalf("list = %#v", res)
	}
	if len(runner.calls) != 1 || pkgArgv(runner.calls[0]) != "pkgutil --pkgs" {
		t.Fatalf("argv = %+v", runner.calls)
	}
	if runner.calls[0].Shell {
		t.Fatal("pkgutil list must stay shell-free")
	}
}

func TestIsInstalledExactMatch(t *testing.T) {
	rt, _ := pkgutilArgvRT(t)
	res, err := (isInstalledFunc{}).Execute(context.Background(), rt, &isInstalledArgs{PackageID: "com.example.old"})
	if err != nil || res != true {
		t.Fatalf("is_installed = %v %v", res, err)
	}
	// prefixes do not count as installed ids
	res, err = (isInstalledFunc{}).Execute(context.Background(), rt, &isInstalledArgs{PackageID: "com.example"})
	if err != nil || res != false {
		t.Fatalf("prefix is_installed = %v %v", res, err)
	}
}

func TestInstallAlreadyThereShortCircuit(t *testing.T) {
	// pytest test_install_already_there: _install_from_path is never
	// invoked when the receipt already exists.
	rt, runner := pkgutilArgvRT(t)
	res, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/example.pkg", PackageID: "com.apple.base",
	})
	if err != nil || res != true {
		t.Fatalf("already installed = %v %v", res, err)
	}
	if len(runner.calls) != 1 || pkgArgv(runner.calls[0]) != "pkgutil --pkgs" {
		t.Fatalf("short-circuit calls = %+v", runner.calls)
	}
}

func TestInstallArgvSequenceAndFixture(t *testing.T) {
	rt, runner := pkgutilArgvRT(t)
	runner.install = "com.example.new"
	res, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/example.pkg", PackageID: "com.example.new",
	})
	if err != nil || res != true {
		t.Fatalf("install = %v %v", res, err)
	}
	want := []string{
		"pkgutil --pkgs",
		"installer -pkg /tmp/example.pkg -target /",
		"pkgutil --pkgs",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	for i, argv := range want {
		if got := pkgArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}
	if runner.calls[1].Shell {
		t.Fatal("installer must stay shell-free")
	}
}

func TestInstallFailureReturnsFalseNotError(t *testing.T) {
	// Salt's _install_from_path raises on installer failure; the port
	// maps a failed installer onto the documented False return instead.
	rt, runner := pkgutilArgvRT(t)
	runner.failInst = true
	res, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/example.pkg", PackageID: "com.example.new",
	})
	if err != nil || res != false {
		t.Fatalf("failed install = %v %v", res, err)
	}
	if pkgArgv(runner.calls[1]) != "installer -pkg /tmp/example.pkg -target /" {
		t.Fatalf("installer argv = %q", pkgArgv(runner.calls[1]))
	}
}

func TestInstallGuards(t *testing.T) {
	rt, _ := pkgutilArgvRT(t)
	_, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Source: "file:///tmp/example.pkg", PackageID: "x",
	})
	if err == nil || err.Error() != "Unsupported scheme for source uri: file" {
		t.Fatalf("file scheme = %v", err)
	}
	// a directory is not a package file
	if err := rt.FS.MkdirAll("/tmp/dir.pkg", 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Source: "/tmp/dir.pkg", PackageID: "x",
	})
	if err == nil || err.Error() != "File not found: /tmp/dir.pkg" {
		t.Fatalf("directory guard = %v", err)
	}
}

func TestForgetArgvAndResult(t *testing.T) {
	rt, runner := pkgutilArgvRT(t)
	res, err := (forgetFunc{}).Execute(context.Background(), rt, &forgetArgs{PackageID: "com.example.old"})
	if err != nil || res != true {
		t.Fatalf("forget = %v %v", res, err)
	}
	want := []string{"pkgutil --forget com.example.old", "pkgutil --pkgs"}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	for i, argv := range want {
		if got := pkgArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}
	if !runner.failInst && len(runner.pkgs) != 1 {
		t.Fatalf("receipts after forget = %v", runner.pkgs)
	}
}

func TestPkgutilRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkgutil.forget",
		"pkgutil.install",
		"pkgutil.is_installed",
		"pkgutil.list",
	}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, runner := pkgutilArgvRT(t)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "pkgutil.is_installed", &isInstalledArgs{PackageID: "com.example.old"})
		if err != nil || res != true {
			t.Fatalf("dispatch = %v %v", res, err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("dispatch calls = %d", len(runner.calls))
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "pkgutil.is_installed", &isInstalledArgs{PackageID: "com.example.old"}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
