package pyenv

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpyenv "github.com/friz-zy/statekit/modules/exec/pyenv"
)

// State tests mapped onto saltstack/tests/pytests/unit/states/test_pyenv.py,
// running against the fully registered exec surface.

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func stateRT(t *testing.T, pyenvBin bool) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "linux", Name: "Linux",
		}}),
	}
	if err := execpyenv.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	if pyenvBin {
		files["/usr/local/pyenv/bin/pyenv"] = "#!/bin/sh\n"
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt.Runner = runner
	return rt, runner
}

const installKey = "env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00install\x003.11.4"
const versionsKey = "env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00versions\x00--bare"
const defaultKey = "env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00global"

// Mirrors test_installed.
func TestInstalled(t *testing.T) {
	rt, _ := stateRT(t, true)

	// test mode comment uses the stripped name.
	ret := installedFunc{}.Apply(context.Background(), rt, &InstalledArgs{
		Name: "python-3.11.4", Test: true,
	})
	if ret.Comment != "python 3.11.4 is set to be installed" {
		t.Fatalf("test comment = %q", ret.Comment)
	}

	runner, _ := rt.Runner.(*fakeRunner)

	// Version unknown → install attempted, empty stderr counts as failure
	// upstream (falsy string).
	runner.results[versionsKey] = process.CommandResult{}
	ret = installedFunc{}.Apply(context.Background(), rt, &InstalledArgs{Name: "3.11.4"})
	if ret.Result == nil || *ret.Result != false || ret.Comment != "Could not install python." {
		t.Fatalf("no-version flow = %#v %q", ret.Result, ret.Comment)
	}

	// Version present → already exists with default flag.
	runner.results[versionsKey] = process.CommandResult{Stdout: []byte("3.11.4\n")}
	runner.results[defaultKey] = process.CommandResult{Stdout: []byte("3.11.4\n")}
	ret = installedFunc{}.Apply(context.Background(), rt, &InstalledArgs{Name: "3.11.4"})
	if ret.Result == nil || *ret.Result != true ||
		ret.Comment != "Requested python exists." {
		t.Fatalf("exists flow = %#v %q", ret.Result, ret.Comment)
	}
	metaDefault, _ := ret.Meta.Extra["default"].(bool)
	if !metaDefault {
		t.Fatalf("meta default = %#v", ret.Meta.Extra)
	}
}

// Mirrors test_absent.
func TestAbsent(t *testing.T) {
	rt, _ := stateRT(t, true)

	// test mode.
	ret := absentFunc{}.Apply(context.Background(), rt, &AbsentArgs{
		Name: "python-3.11.4", Test: true,
	})
	if ret.Comment != "python 3.11.4 is set to be uninstalled" {
		t.Fatalf("test comment = %q", ret.Comment)
	}

	// pyenv absent → already absent without calls.
	rtNoPyenv, _ := stateRT(t, false)
	got := absentFunc{}.Apply(context.Background(), rtNoPyenv, &AbsentArgs{Name: "3.11.4"})
	if got.Result == nil || *got.Result != true ||
		got.Comment != "pyenv not installed, 3.11.4 not either" {
		t.Fatalf("absent-no-pyenv = %#v %q", got.Result, got.Comment)
	}

	// pyenv present but version absent → already absent.
	rt2, _ := stateRT(t, true)
	got = absentFunc{}.Apply(context.Background(), rt2, &AbsentArgs{Name: "3.11.4"})
	if got.Result == nil || *got.Result != true ||
		got.Comment != "python 3.11.4 is already absent" {
		t.Fatalf("version-absent = %#v %q", got.Result, got.Comment)
	}

	// Version present → uninstall succeeds and records the change.
	rt3, _ := stateRT(t, true)
	runner3 := rt3.Runner.(*fakeRunner)
	runner3.results[versionsKey] = process.CommandResult{Stdout: []byte("3.11.4\n")}
	runner3.results[defaultKey] = process.CommandResult{Stdout: []byte("3.11.4\n")}
	uninstallKey := "env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00uninstall\x00--force\x003.11.4"
	runner3.results[uninstallKey] = process.CommandResult{ExitCode: 1} // exit code ignored upstream
	got = absentFunc{}.Apply(context.Background(), rt3, &AbsentArgs{Name: "3.11.4"})
	if got.Result == nil || *got.Result != true ||
		got.Changes["3.11.4"] != "Uninstalled" ||
		got.Comment != "Successfully removed python" {
		t.Fatalf("uninstall flow = %#v %q %#v", got.Result, got.Comment, got.Changes)
	}
}

// Mirrors test_install_pyenv including the pinned user-as-python quirk.
func TestInstallPyenv(t *testing.T) {
	rt, _ := stateRT(t, true)

	ret := installPyenvFunc{}.Apply(context.Background(), rt, &InstallPyenvArgs{
		Name: "pyenv-setup", Test: true,
	})
	if ret.Comment != "pyenv is set to be installed" {
		t.Fatalf("test comment = %q", ret.Comment)
	}

	// The user's own pyenv must exist for the exec gate to pass (upstream
	// mocks cmd.has_exec True here).
	if err := rt.FS.MkdirAll("/home/deploy/.pyenv/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/home/deploy/.pyenv/bin/pyenv", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// With no versions output the install attempt for the user string fails.
	ret = installPyenvFunc{}.Apply(context.Background(), rt, &InstallPyenvArgs{
		Name: "pyenv-setup", User: strPtr("deploy"),
	})
	if ret.Result == nil || *ret.Result != false ||
		ret.Comment != "Could not install python." {
		t.Fatalf("quirk flow = %#v %q", ret.Result, ret.Comment)
	}
	foundUserAsPython := false
	for _, call := range rt.Runner.(*fakeRunner).calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "install deploy") {
			foundUserAsPython = true
		}
	}
	if !foundUserAsPython {
		t.Fatalf("user-as-python quirk not observable")
	}
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}
