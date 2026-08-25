package python

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests pinning the interpreter-selection hook, the argv contracts of
// run/script, and the cache-error result shape (upstream ships no unit
// battery for this module).

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
	onRun   func(argv []string) process.CommandResult
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if f.onRun != nil {
		return f.onRun(argv)
	}
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func pyRT(t *testing.T, exe string, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	saved := pythonExecutable
	pythonExecutable = func() string { return exe }
	t.Cleanup(func() { pythonExecutable = saved })

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

func TestRunCommand(t *testing.T) {
	runner := &fakeRunner{}
	rt := pyRT(t, "/usr/bin/python3", runner, nil)

	ret, err := (runFunc{}).Execute(context.Background(), rt, &RunArgs{
		Command: strPtr("print('hello world')"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !equalSlice(runner.calls[0],
		[]string{"/usr/bin/python3", "-c", "print('hello world')"}) {
		t.Fatalf("argv = %#v", runner.calls)
	}
	dict := ret.(runResult)
	if dict["retcode"] != 0 {
		t.Fatalf("result = %#v", dict)
	}
}

func TestRunArgsStringSplit(t *testing.T) {
	runner := &fakeRunner{}
	rt := pyRT(t, "/usr/bin/python3", runner, nil)
	_, err := (runFunc{}).Execute(context.Background(), rt, &RunArgs{
		Args: `-m json.tool "some file.json"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/python3", "-m", "json.tool", "some file.json"}
	if !equalSlice(runner.calls[0], want) {
		t.Fatalf("argv = %#v; want %#v", runner.calls[0], want)
	}
}

func TestRunRequiresInput(t *testing.T) {
	rt := pyRT(t, "/usr/bin/python3", &fakeRunner{}, nil)
	_, err := (runFunc{}).Execute(context.Background(), rt, &RunArgs{})
	if err == nil || err.Error() != "Must specify either 'command' or 'args'" {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRstripAndSuccessOverrides(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"/usr/bin/python3\x00-c\x00x": {ExitCode: 2, Stdout: []byte("out\n\n")},
	}}
	rt := pyRT(t, "/usr/bin/python3", runner, nil)

	ret, _ := (runFunc{}).Execute(context.Background(), rt, &RunArgs{
		Command:         strPtr("x"),
		Rstrip:          boolPtr(true),
		SuccessRetcodes: []int{2},
	})
	dict := ret.(runResult)
	if dict["stdout"] != "out" || dict["retcode"] != 0 {
		t.Fatalf("rstrip/override = %#v", dict)
	}
}

func TestScriptLocalFlow(t *testing.T) {
	var rt *runtime.Runtime
	runner := &fakeRunner{}
	rt = pyRT(t, "/usr/bin/python3", runner, map[string]string{
		"/testbed/scripts/runme.py": "print('hi')",
	})
	runner.onRun = func(argv []string) process.CommandResult {
		// The script must exist at invocation time and be cleaned after.
		if argv[0] == "/usr/bin/python3" {
			if _, err := rt.FS.Stat(argv[1]); err != nil {
				t.Errorf("script missing at run time: %v", err)
			}
		}
		return process.CommandResult{Stdout: []byte("script-out\n")}
	}

	ret, err := (scriptFunc{}).Execute(context.Background(), rt, &ScriptArgs{
		Source: "/testbed/scripts/runme.py",
		Cwd:    strPtr("/testbed"),
		Args:   `arg1 "arg 2"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(runResult)
	if dict["stdout"] != "script-out\n" {
		t.Fatalf("stdout = %#v", dict["stdout"])
	}
	if len(runner.calls) != 1 ||
		runnersArg0(runner.calls[0]) != "/usr/bin/python3" ||
		!strings.HasSuffix(runner.calls[0][1], ".py") {
		t.Fatalf("argv = %#v", runner.calls)
	}
	if !equalSlice(runner.calls[0][2:], []string{"arg1", "arg 2"}) {
		t.Fatalf("args not split: %#v", runner.calls[0])
	}
	// Tempfile cleaned up.
	entries, _ := rt.FS.ReadDir("/testbed")
	if len(entries) != 1 || entries[0].Name() != "scripts" {
		t.Fatalf("tempfiles survived: %#v", entries)
	}
}

func runnersArg0(argv []string) string { return argv[0] }

func TestScriptCacheErrorShape(t *testing.T) {
	rt := pyRT(t, "/usr/bin/python3", &fakeRunner{}, map[string]string{})
	ret, err := (scriptFunc{}).Execute(context.Background(), rt, &ScriptArgs{
		Source: "/testbed/missing.py",
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(runResult)
	if dict["retcode"] != 1 || dict["cache_error"] != true || dict["pid"] != nil {
		t.Fatalf("cache_error shape = %#v", dict)
	}
}

func TestScriptRemoteSchemeRejected(t *testing.T) {
	rt := pyRT(t, "/usr/bin/python3", &fakeRunner{}, nil)
	ret, err := (scriptFunc{}).Execute(context.Background(), rt, &ScriptArgs{
		Source: "salt://scripts/runme.py",
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
		t.Fatalf("error = %v", err)
	}
	dict := ret.(runResult)
	if dict["cache_error"] != true {
		t.Fatalf("cache_error missing: %#v", dict)
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

func boolPtr(b bool) *bool { return &b }

type onRunHook func(argv []string) process.CommandResult

func (f *fakeRunner) setHook(hook onRunHook) {}
