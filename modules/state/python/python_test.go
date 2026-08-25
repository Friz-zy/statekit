package python

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpython "github.com/friz-zy/statekit/modules/exec/python"
)

// Tests pinning the state flows read from saltstack/salt/states/python.py.

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

func stateRT(t *testing.T, files map[string]string) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	savedExe := execpython.ExportInterpreter()
	execpython.SetInterpreter(func() string { return "/usr/bin/python3" })
	t.Cleanup(func() { execpython.SetInterpreter(savedExe) })

	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
	}
	if err := execpython.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt.Runner = runner
	return rt, runner
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func TestRunStateSuccess(t *testing.T) {
	rt, _ := stateRT(t, nil)
	if err := rt.FS.MkdirAll("/testbed/cwd", 0o755); err != nil {
		t.Fatal(err)
	}

	ret := runFunc{}.Apply(context.Background(), rt, &runArgs{
		Name: "print('hello')",
		Cwd:  strPtr("/testbed/cwd"),
	})
	if ret.Result == nil || *ret.Result != true {
		t.Fatalf("run result = %#v (%s)", ret.Result, ret.Comment)
	}
	if ret.Comment != `Python code "print('hello')" run` {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if ret.Changes["retcode"] != 0 {
		t.Fatalf("changes = %#v", ret.Changes)
	}
}

func TestRunTestModeAndCwdGuard(t *testing.T) {
	rt, _ := stateRT(t, nil)
	ret := runFunc{}.Apply(context.Background(), rt, &runArgs{
		Name: "print('hello')", Test: true,
	})
	if ret.Result != nil ||
		ret.Comment != `Python code "print('hello')" would have been executed` {
		t.Fatalf("test mode = %#v %q", ret.Result, ret.Comment)
	}

	missing := "/no/such/dir"
	ret = runFunc{}.Apply(context.Background(), rt, &runArgs{
		Name: "print('hello')", Cwd: &missing,
	})
	if ret.Result == nil || *ret.Result != false ||
		ret.Comment != `Desired working directory "/no/such/dir" is not available` {
		t.Fatalf("cwd guard = %#v %q", ret.Result, ret.Comment)
	}
}

func TestScriptStateCacheError(t *testing.T) {
	rt, _ := stateRT(t, nil)

	// test mode.
	ret := scriptFunc{}.Apply(context.Background(), rt, &scriptArgs{
		Name: "/testbed/scripts/runme.py arg1", Test: true,
	})
	if ret.Result != nil ||
		ret.Comment != "Python script '/testbed/scripts/runme.py arg1' would have been executed" {
		t.Fatalf("test mode = %#v %q", ret.Result, ret.Comment)
	}

	// Missing local script surfaces the cache_error comment.
	ret = scriptFunc{}.Apply(context.Background(), rt, &scriptArgs{
		Name:   "/testbed/scripts/runme.py",
		Source: strPtr("/testbed/scripts/missing.py"),
	})
	if ret.Result == nil || *ret.Result != false {
		t.Fatalf("cache-error result = %#v", ret.Result)
	}
	want := "Unable to cache script /testbed/scripts/missing.py from saltenv 'base'"
	if ret.Comment != want {
		t.Fatalf("cache comment = %q", ret.Comment)
	}
}

func TestScriptStateSuccess(t *testing.T) {
	scriptBody := "print('hi')\n"
	rt, _ := stateRT(t, map[string]string{
		"/testbed/scripts/runme.py": scriptBody,
	})

	ret := scriptFunc{}.Apply(context.Background(), rt, &scriptArgs{
		Name:   "runme.py arg1 arg2",
		Source: strPtr("/testbed/scripts/runme.py"),
		Cwd:    strPtr("/testbed"),
	})
	if ret.Result == nil || *ret.Result != true {
		t.Fatalf("script result = %#v (%s)", ret.Result, ret.Comment)
	}
	if ret.Comment != "Python script 'runme.py arg1 arg2' run" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if ret.Changes["retcode"] != 0 {
		t.Fatalf("changes = %#v", ret.Changes)
	}
	// Tempfile cleaned from cwd (the fake runner does not execute scripts).
	entries, _ := rt.FS.ReadDir("/testbed")
	if len(entries) != 1 || entries[0].Name() != "scripts" {
		t.Fatalf("tempfiles survived: %#v", entries)
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
