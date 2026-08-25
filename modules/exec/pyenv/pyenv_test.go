package pyenv

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests mapped onto saltstack/tests/pytests/unit/modules/test_pyenv.py.
//
// The fakeRunner keys results on the shlex-split argv, so the
// "env PYENV_ROOT=... bin" shell strings appear as multi-token calls.

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

func envRT(t *testing.T, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "linux", Name: "Linux",
		}}),
		Runner: runner,
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

// Mirrors test_install: clone runs and success returns true.
func TestInstall(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, nil)
	got, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{})
	if err != nil || got != true {
		t.Fatalf("install = %#v, %v", got, err)
	}
	want := []string{"git", "clone", "https://github.com/yyuu/pyenv.git", "/usr/local/pyenv"}
	if len(runner.calls) != 1 || !equalSlice(runner.calls[0], want) {
		t.Fatalf("argv = %#v", runner.calls)
	}
}

// Mirrors test_update: missing tree yields false without a git call.
func TestUpdate(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, nil)
	got, err := (updateFunc{}).Execute(context.Background(), rt, &UpdateArgs{})
	if err != nil || got != false {
		t.Fatalf("update = %#v, %v", got, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unexpected git calls: %#v", runner.calls)
	}
}

func TestIsInstalled(t *testing.T) {
	rt := envRT(t, &fakeRunner{results: map[string]process.CommandResult{}}, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	got, _ := (isInstalledFunc{}).Execute(context.Background(), rt, &IsInstalledArgs{})
	if got != true {
		t.Fatalf("is_installed = %#v", got)
	}

	rt = envRT(t, &fakeRunner{results: map[string]process.CommandResult{}}, nil)
	got, _ = (isInstalledFunc{}).Execute(context.Background(), rt, &IsInstalledArgs{})
	if got != false {
		t.Fatalf("missing is_installed = %#v", got)
	}
}

// Mirrors test_install_python: stderr returned on success, False with the
// uninstall cleanup on failure.
func TestInstallPython(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})

	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00install\x002.0.0-p0"] =
		process.CommandResult{Stdout: []byte("salt"), Stderr: []byte("error")}
	got, err := (installPythonFunc{}).Execute(context.Background(), rt,
		&InstallPythonArgs{Python: "2.0.0-p0"})
	if err != nil || got != "error" {
		t.Fatalf("success install_python = %#v, %v", got, err)
	}

	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00install\x002.0.0-p0"] =
		process.CommandResult{ExitCode: 1, Stdout: []byte("salt"), Stderr: []byte("error")}
	got, err = (installPythonFunc{}).Execute(context.Background(), rt,
		&InstallPythonArgs{Python: "2.0.0-p0"})
	if err != nil || got != false {
		t.Fatalf("failed install_python = %#v, %v", got, err)
	}
	foundCleanup := false
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "uninstall --force 2.0.0-p0") {
			foundCleanup = true
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup uninstall missing: %#v", joined(runner.calls))
	}
}

// Mirrors test_versions: failed exec degrades to an empty list.
func TestVersions(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00versions\x00--bare"] =
		process.CommandResult{ExitCode: 1}
	got, _ := (versionsFunc{}).Execute(context.Background(), rt, &VersionsArgs{})
	if list := got.([]string); len(list) != 0 {
		t.Fatalf("versions = %#v", list)
	}

	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00versions\x00--bare"] =
		process.CommandResult{Stdout: []byte("3.11.4\n3.12.1\n")}
	got, _ = (versionsFunc{}).Execute(context.Background(), rt, &VersionsArgs{})
	list := got.([]string)
	if !equalSlice(list, []string{"3.11.4", "3.12.1"}) {
		t.Fatalf("versions = %#v", list)
	}
}

// Mirrors test_default: empty read on failure, true on set.
func TestDefault(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00global"] =
		process.CommandResult{ExitCode: 1}
	got, _ := (defaultFunc{}).Execute(context.Background(), rt, &DefaultArgs{})
	if got != "" {
		t.Fatalf("default read = %#v", got)
	}

	got, _ = (defaultFunc{}).Execute(context.Background(), rt,
		&DefaultArgs{Python: strPtr("2.0.0-p0")})
	if got != true {
		t.Fatalf("default set = %#v", got)
	}
	found := false
	for _, call := range runner.calls {
		last := call[len(call)-3:]
		if equalSlice(last, []string{"global", "", ""}) {
			continue
		}
		if len(call) >= 2 && call[len(call)-2] == "global" && call[len(call)-1] == "2.0.0-p0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("global set argv missing: %#v", joined(runner.calls))
	}
}

// Mirrors test_list: failed exec yields an empty list; header skipped.
func TestList(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00install\x00--list"] =
		process.CommandResult{ExitCode: 1}
	got, _ := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if list := got.([]string); len(list) != 0 {
		t.Fatalf("list = %#v", list)
	}

	runner.results["env\x00PYENV_ROOT=/usr/local/pyenv\x00/usr/local/pyenv/bin/pyenv\x00install\x00--list"] =
		process.CommandResult{Stdout: []byte("Available versions:\n  2.0.0-p0\n  3.11.4\n")}
	got, _ = (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
	list := got.([]string)
	if !equalSlice(list, []string{"2.0.0-p0", "3.11.4"}) {
		t.Fatalf("list = %#v", list)
	}
}

// Mirrors test_rehash.
func TestRehash(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	got, _ := (rehashFunc{}).Execute(context.Background(), rt, &RehashArgs{})
	if got != true {
		t.Fatalf("rehash = %#v", got)
	}
}

// Mirrors test_do: failure yields False; success returns stdout after rehash.
func TestDo(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})

	// No matching result → exit 0 by default in fakeRunner... pin explicit:
	runner.results["env\x00PATH=/usr/local/pyenv/shims:/usr/bin:/bin\x00gem\x00list\x00bundler"] =
		process.CommandResult{ExitCode: 1, Stdout: []byte("salt"), Stderr: []byte("error")}
	t.Setenv("PATH", "/usr/bin:/bin")
	got, _ := (doFunc{}).Execute(context.Background(), rt, &DoArgs{Cmdline: "gem list bundler"})
	if got != false {
		t.Fatalf("failed do = %#v", got)
	}

	runner.results["env\x00PATH=/usr/local/pyenv/shims:/usr/bin:/bin\x00gem\x00list\x00bundler"] =
		process.CommandResult{Stdout: []byte("salt"), Stderr: []byte("error")}
	got, _ = (doFunc{}).Execute(context.Background(), rt, &DoArgs{Cmdline: "gem list bundler"})
	if got != "salt" {
		t.Fatalf("do = %#v", got)
	}
}

// Mirrors test_do_with_python: PYENV_VERSION prefixes the cmdline.
func TestDoWithPython(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/usr/local/pyenv/bin/pyenv": "#!/bin/sh\n",
	})
	t.Setenv("PATH", "/usr/bin:/bin")
	runner.results["env\x00PATH=/usr/local/pyenv/shims:/usr/bin:/bin\x00PYENV_VERSION=2.0.0-p0\x00gem\x00list\x00bundler"] =
		process.CommandResult{ExitCode: 1, Stdout: []byte("salt"), Stderr: []byte("error")}
	got, _ := (doWithPythonFunc{}).Execute(context.Background(), rt,
		&DoWithPythonArgs{Python: "2.0.0-p0", Cmdline: "gem list bundler"})
	if got != false {
		t.Fatalf("do_with_python = %#v", got)
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func strPtr(s string) *string { return &s }

func joined(calls [][]string) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, strings.Join(call, " "))
	}
	return out
}
