package cli

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperHoldCLIWriteFS(t *testing.T, content string) *cliLocksFS {
	t.Helper()
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/target/etc/zypp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile("/target/etc/zypp/locks", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return &cliLocksFS{MemoryFS: memory}
}

func TestZypperHoldCLIUsesExactArgsAndProviderBoundary(t *testing.T) {
	fsys := zypperHoldCLIWriteFS(t, "")
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.hold", "--name", "alpha,beta", "--root", "/target", "-o", "json")
	var held map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &held) != nil ||
		!reflect.DeepEqual(held, map[string]map[string]any{"alpha,beta": {"name": "alpha,beta", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package alpha,beta is now being held."}}) {
		t.Fatalf("hold code=%d out=%q err=%q result=%#v", code, out, errS, held)
	}
	// The pinned source performs no comma splitting: the whole name string
	// is one zypper target.
	wantArgv := []string{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "al", "alpha,beta"}
	if len(runner.calls) != 1 || !reflect.DeepEqual(append([]string{runner.calls[0].Name}, runner.calls[0].Args...), wantArgv) {
		t.Fatalf("argv=%#v want=%v", runner.calls, wantArgv)
	}
	command := runner.calls[0]
	if command.Shell || command.MaxStdoutBytes == 0 || command.MaxStderrBytes == 0 || !reflect.DeepEqual(command.Env, []string{"LC_ALL=C"}) {
		t.Fatalf("unsafe command=%#v", command)
	}
	if fsys.writes != 0 {
		t.Fatalf("hold wrote through FS: %d", fsys.writes)
	}

	fsys = zypperHoldCLIWriteFS(t, "solvable_name: demo\nversion: = 1-1\n")
	runner = &cliRecordingRunner{}
	code, out, errS = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.unhold", "--name", "demo", "--root", "/target", "-o", "json")
	var unheld map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &unheld) != nil ||
		!reflect.DeepEqual(unheld, map[string]map[string]any{"demo": {"name": "demo", "changes": map[string]any{"new": "", "old": "hold"}, "result": true, "comment": "Package demo is no longer held."}}) {
		t.Fatalf("unhold code=%d out=%q err=%q result=%#v", code, out, errS, unheld)
	}
	wantArgv = []string{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "rl", "demo=1-1"}
	if len(runner.calls) != 1 || !reflect.DeepEqual(append([]string{runner.calls[0].Name}, runner.calls[0].Args...), wantArgv) {
		t.Fatalf("argv=%#v want=%v", runner.calls, wantArgv)
	}
	if fsys.writes != 0 {
		t.Fatalf("unhold wrote through FS: %d", fsys.writes)
	}
}

func TestZypperHoldCLISettledStatesMakeNoCall(t *testing.T) {
	fsys := zypperHoldCLIWriteFS(t, "solvable_name: demo\nmatch_type: exact\n")
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.hold", "--name", "demo", "--root", "/target", "-o", "json")
	var held map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &held) != nil ||
		held["demo"]["comment"] != "Package demo is already set to be held." || len(runner.calls) != 0 {
		t.Fatalf("already-held code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	fsys = zypperHoldCLIWriteFS(t, "solvable_name: demo\nmatch_type: exact\n")
	runner = &cliRecordingRunner{}
	code, out, errS = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.unhold", "--name", "missing", "--root", "/target", "-o", "json")
	var unheld map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &unheld) != nil ||
		unheld["missing"]["comment"] != "Package missing was already unheld." || len(runner.calls) != 0 {
		t.Fatalf("already-unheld code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}

func TestZypperHoldCLIEmptyInputAndStrictFlags(t *testing.T) {
	for _, function := range []string{"pkg.hold", "pkg.unhold"} {
		runner := &cliRecordingRunner{}
		code, _, errS := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", function)
		if code != ExitFailed || !strings.Contains(errS, "Name or packages must be specified.") || len(runner.calls) != 0 {
			t.Fatalf("%s empty code=%d err=%q calls=%d", function, code, errS, len(runner.calls))
		}

		runner = &cliRecordingRunner{}
		code, _, errS = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", function, "--sources", "x.rpm")
		if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("%s sources code=%d err=%q calls=%d", function, code, errS, len(runner.calls))
		}

		runner = &cliRecordingRunner{}
		code, _, errS = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", function, "--name", "--evil")
		if code == ExitOK || len(runner.calls) != 0 || strings.Contains(errS, "evil") {
			t.Fatalf("%s option-like name code=%d err=%q calls=%d", function, code, errS, len(runner.calls))
		}
	}
}

func TestZypperHoldCLIRunnerFailureIsNotFabricatedSuccess(t *testing.T) {
	fsys := zypperHoldCLIWriteFS(t, "")
	runner := &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("zypper runner failed"), ExitCode: -1}}}
	code, _, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.hold", "--name", "demo")
	if code != ExitFailed || errS == "" || len(runner.calls) != 1 {
		t.Fatalf("failure code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}
