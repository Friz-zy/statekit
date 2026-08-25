package virtualenv

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests pinning the create kwargs machinery and the introspection surface
// read from saltstack/salt/modules/virtualenv_mod.py @ pinned revision.

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
		Facts:  facts.ForTesting(facts.Overrides{}),
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

func stubBins(t *testing.T) {
	t.Helper()
	savedWhich := whichBin
	savedExe := pythonExecutable
	whichBin = func(name string) string {
		switch name {
		case "virtualenv":
			return "/usr/bin/virtualenv"
		case "venv", "python", "python3.12", "python3":
			return "/usr/bin/" + name
		}
		return ""
	}
	pythonExecutable = func() string { return "/usr/bin/python3" }
	t.Cleanup(func() { whichBin = savedWhich; pythonExecutable = savedExe })
}

func TestCreateVenvBranch(t *testing.T) {
	// Neither toolchain binary on PATH: the default falls back to "venv".
	savedWhich := whichBin
	savedExe := pythonExecutable
	whichBin = func(string) string { return "" }
	pythonExecutable = func() string { return "/usr/bin/python3" }
	t.Cleanup(func() { whichBin = savedWhich; pythonExecutable = savedExe })
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, nil)

	ret, err := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/app",
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["retcode"] != 0 {
		t.Fatalf("result = %#v", dict)
	}
	want := []string{"/usr/bin/python3", "-m", "venv", "/venvs/app"}
	if !equalSlice(runner.calls[0], want) {
		t.Fatalf("argv = %#v", runner.calls[0])
	}

	upgradeTrue, symlinksTrue := true, true
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/full", VenvBin: strPtr("venv"),
		Upgrade:            &upgradeTrue,
		Symlinks:           &symlinksTrue,
		Clear:              true,
		SystemSitePackages: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	last := runner.calls[len(runner.calls)-1]
	wantFull := []string{"/usr/bin/python3", "-m", "venv",
		"--upgrade", "--symlinks", "--clear", "--system-site-packages", "/venvs/full"}
	if !equalSlice(last, wantFull) {
		t.Fatalf("full argv = %#v", last)
	}
}

// Mirrors the venv-only option guards.
func TestCreateVenvOnlyGuards(t *testing.T) {
	stubBins(t)
	rt := envRT(t, &fakeRunner{results: map[string]process.CommandResult{}}, nil)

	python := "python3.12"
	_, err := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("venv"), Python: &python,
	})
	if err == nil || !strings.Contains(err.Error(), "not supported by 'venv'") ||
		!strings.Contains(err.Error(), "`python`") {
		t.Fatalf("python guard = %v", err)
	}

	extra := "/opt/pyvenvs"
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("venv"), ExtraSearchDir: &extra,
	})
	if err == nil || !strings.Contains(err.Error(), "`extra_search_dir`") {
		t.Fatalf("extra guard = %v", err)
	}

	noDownload := true
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("venv"), NeverDownload: &noDownload,
	})
	if err == nil || !strings.Contains(err.Error(), "`never_download`") {
		t.Fatalf("never_download guard = %v", err)
	}

	prompt := "env"
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("venv"), Prompt: &prompt,
	})
	if err == nil || !strings.Contains(err.Error(), "`prompt`") {
		t.Fatalf("prompt guard = %v", err)
	}
}

// Mirrors the virtualenv-tool branch including version windows and guards.
func TestCreateVirtualenvTool(t *testing.T) {
	stubBins(t)
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, nil)
	verKey := "virtualenv\x00--version"
	runner.results[verKey] = process.CommandResult{Stdout: []byte("20.23.0\n")}

	upgrade := true
	_, err := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("virtualenv"), Upgrade: &upgrade,
	})
	if err == nil || !strings.Contains(err.Error(),
		"The `upgrade`(`--upgrade`) option is not supported by 'virtualenv'") {
		t.Fatalf("upgrade guard = %v", err)
	}
	symlinks := true
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("virtualenv"), Symlinks: &symlinks,
	})
	if err == nil || !strings.Contains(err.Error(), "`symlinks`") {
		t.Fatalf("symlinks guard = %v", err)
	}

	// never_download=False on >=20 emits --download; prompt keeps literal
	// quoting inside a single argv token.
	prompt := "my env"
	noDownload := false
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path:          "/venvs/x",
		VenvBin:       strPtr("virtualenv"),
		Prompt:        &prompt,
		NeverDownload: &noDownload,
	})
	if err != nil {
		t.Fatal(err)
	}
	foundDownload, foundPrompt := false, false
	for _, call := range runner.calls {
		if call[0] != "virtualenv" {
			continue
		}
		for _, arg := range call {
			if arg == "--download" {
				foundDownload = true
			}
			if arg == "--prompt='my env'" {
				foundPrompt = true
			}
		}
	}
	if !foundDownload || !foundPrompt {
		t.Fatalf("download/prompt flags missing: %#v", joined(runner.calls))
	}

	// --python resolution guard.
	missingPython := "/nonexistent/python"
	_, err = createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("virtualenv"), Python: &missingPython,
	})
	if err == nil || err.Error() != "Cannot find requested python (/nonexistent/python)." {
		t.Fatalf("python guard = %v", err)
	}

	// Failure return keeps the full result dict instead of an error.
	failKey := strings.Join([]string{"virtualenv", "/venvs/fail"}, "\x00")
	runner.results[failKey] = process.CommandResult{ExitCode: 2, Stderr: []byte("cannot create")}
	ret, cerr := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/fail", VenvBin: strPtr("virtualenv"),
	})
	if cerr != nil {
		t.Fatalf("failure returned error: %v", cerr)
	}
	dict := ret.(map[string]any)
	if dict["retcode"] != 2 {
		t.Fatalf("failure dict = %#v", dict)
	}
}

func TestVirtualenvVerParsing(t *testing.T) {
	stubBins(t)
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, nil)

	verKey := "/usr/bin/virtualenv\x00--version"

	// Version token extraction from mixed output.
	runner.results[verKey] = process.CommandResult{
		Stdout: []byte("20.23.0 (from pip)\n"),
	}
	got, err := virtualenvVerFunc{}.Execute(context.Background(), rt,
		&VirtualenvVerArgs{VenvBin: "/usr/bin/virtualenv"})
	if err != nil {
		t.Fatal(err)
	}
	list := got.([]int)
	if len(list) != 3 || list[0] != 20 || list[2] != 0 {
		t.Fatalf("version = %#v", list)
	}

	// rc suffix stripping.
	runner.results[verKey] = process.CommandResult{Stdout: []byte("1.9rc1\n")}
	got, _ = virtualenvVerFunc{}.Execute(context.Background(), rt,
		&VirtualenvVerArgs{VenvBin: "/usr/bin/virtualenv"})
	list = got.([]int)
	if len(list) != 2 || list[0] != 1 || list[1] != 9 {
		t.Fatalf("rc version = %#v", list)
	}

	// Empty output raises the verbatim error with rendered cmd and dict.
	runner.results[verKey] = process.CommandResult{}
	_, err = virtualenvVerFunc{}.Execute(context.Background(), rt,
		&VirtualenvVerArgs{VenvBin: "/usr/bin/virtualenv"})
	if err == nil || !strings.HasPrefix(err.Error(),
		"Unable to get the virtualenv version output using '['/usr/bin/virtualenv', '--version']'. Returned data: ") {
		t.Fatalf("empty-output error = %v", err)
	}
	if !strings.Contains(err.Error(), "'retcode': 0") ||
		!strings.Contains(err.Error(), "'stdout': ''") {
		t.Fatalf("error missing rendered dict: %v", err)
	}
}

func TestGetSitePackagesAndVerify(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	files := map[string]string{}
	rt := envRT(t, runner, files)

	binPath := "/venvs/app/bin/python"
	if err := writeFile(rt, binPath, "#!/bin/sh\n"); err != nil {
		t.Fatal(err)
	}

	sitePkgKey := strings.Join([]string{binPath, "-c",
		`import sysconfig; print(sysconfig.get_path("purelib"))`}, "\x00")
	runner.results[sitePkgKey] = process.CommandResult{Stdout: []byte("/venvs/app/lib/python3.12/site-packages\n")}

	got, err := getSitePackagesFunc{}.Execute(context.Background(), rt,
		&GetSitePackagesArgs{Venv: "/venvs/app"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "/venvs/app/lib/python3.12/site-packages\n" {
		t.Fatalf("site-packages = %#v", got)
	}

	// Non-venv path raises the verbatim verification error.
	_, err = getSitePackagesFunc{}.Execute(context.Background(), rt,
		&GetSitePackagesArgs{Venv: "/not/a/venv"})
	if err == nil || err.Error() !=
		"Path '/not/a/venv' does not appear to be a virtualenv: '/not/a/venv/bin/python' not found." {
		t.Fatalf("verify error = %v", err)
	}

	// Failing exec surfaces stdout+stderr combined.
	runner.results[sitePkgKey] = process.CommandResult{ExitCode: 1,
		Stdout: []byte("out-line"), Stderr: []byte("err-line")}
	_, err = getSitePackagesFunc{}.Execute(context.Background(), rt,
		&GetSitePackagesArgs{Venv: "/venvs/app"})
	if err == nil || err.Error() != "out-line\nerr-line" {
		t.Fatalf("exec failure = %v", err)
	}
}

// Mirrors the safe_py_code guard over embedded code arguments.
func TestSafePyCodeGuard(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{
		"/venvs/app/bin/python": "#!/bin/sh\n",
	})
	evil := "os; system"
	distFn := getDistributionPathFunc{}
	_, distErr := distFn.Execute(context.Background(), rt,
		&GetDistributionPathArgs{Venv: "/venvs/app", Distribution: evil})
	if distErr == nil || distErr.Error() != "Unsafe python code detected in '"+evil+"'" {
		t.Fatalf("safe-py-code guard = %v", distErr)
	}
}

// Pins the pip bootstrap boundary: fresh venvs without pip surface the
// cp.cache_file UnsupportedError.
func TestCreatePipBootstrapBoundary(t *testing.T) {
	stubBins(t)
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := envRT(t, runner, map[string]string{})
	runner.results["virtualenv\x00--version"] =
		process.CommandResult{Stdout: []byte("20.23.0\n")}

	_, err := createFunc{}.Execute(context.Background(), rt, &CreateArgs{
		Path: "/venvs/x", VenvBin: strPtr("virtualenv"), Pip: true,
	})
	var unsupported *runtime.UnsupportedError
	found := false
	for e := err; e != nil && !found; {
		if ue, is := e.(*runtime.UnsupportedError); is {
			unsupported = ue
			found = true
			break
		}
		type unwrapper interface{ Unwrap() error }
		if w, is := e.(unwrapper); is {
			e = w.Unwrap()
			continue
		}
		break
	}
	if !found || unsupported.Name != "cp.cache_file" {
		t.Fatalf("bootstrap boundary error = %v", err)
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

func writeFile(rt *runtime.Runtime, path, content string) error {
	if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
		return err
	}
	return rt.FS.WriteFile(path, []byte(content), 0o644)
}

func joined(calls [][]string) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, strings.Join(call, " "))
	}
	return out
}
