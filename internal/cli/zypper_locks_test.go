package cli

import (
	"encoding/json"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestZypperLocksCLIUsesExactArgsAndProviderBoundary(t *testing.T) {
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/target/etc/zypp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile("/target/etc/zypp/locks", []byte("solvable_name: demo\ncase_sensitive: yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys := &cliLocksFS{MemoryFS: memory}

	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_locks", "--root", "/target", "-o", "json")
	var listed map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &listed) != nil || !reflect.DeepEqual(listed, map[string]map[string]string{"demo": {"case_sensitive": "yes"}}) || len(runner.calls) != 0 || fsys.writes != 0 {
		t.Fatalf("list code=%d out=%q err=%q calls=%d writes=%d result=%#v", code, out, errS, len(runner.calls), fsys.writes, listed)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(`<stream><message>Removed demo</message></stream>`)}}}
	code, out, errS = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.clean_locks", "--root", "/target", "-o", "json")
	var cleaned map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &cleaned) != nil || !reflect.DeepEqual(cleaned, map[string]any{"removed": "demo"}) || len(runner.calls) != 1 || fsys.writes != 0 {
		t.Fatalf("clean code=%d out=%q err=%q calls=%d writes=%d result=%#v", code, out, errS, len(runner.calls), fsys.writes, cleaned)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "cl"}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%v want=%v", got, wantArgv)
	}
	if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes == 0 || runner.calls[0].MaxStderrBytes == 0 || !reflect.DeepEqual(runner.calls[0].Env, []string{"LC_ALL=C"}) {
		t.Fatalf("unsafe command=%#v", runner.calls[0])
	}

	for _, manager := range []string{"apt", "yum"} {
		for _, function := range []string{"pkg.list_locks", "pkg.clean_locks"} {
			runner := &cliRecordingRunner{}
			code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", function)
			if code != ExitUnsupported || len(runner.calls) != 0 {
				t.Fatalf("manager=%s function=%s code=%d calls=%d", manager, function, code, len(runner.calls))
			}
		}
	}
}

func TestZypperLocksCLIJSONPreservesFirstInsertionOrder(t *testing.T) {
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/target/etc/zypp", 0o755); err != nil {
		t.Fatal(err)
	}
	content := "solvable_name: beta\nvalue: old\n\n" +
		"solvable_name: alpha\nvalue: alpha\n\n" +
		"solvable_name: beta\nvalue: last\n"
	if err := memory.WriteFile("/target/etc/zypp/locks", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, &cliLocksFS{MemoryFS: memory}), "exec", "pkg.list_locks", "--root", "/target", "-o", "json")
	if code != ExitOK || errS != "" || len(runner.calls) != 0 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if beta, alpha := strings.Index(out, `"beta"`), strings.Index(out, `"alpha"`); beta < 0 || alpha < 0 || beta > alpha {
		t.Fatalf("out=%q", out)
	}
	var listed map[string]map[string]string
	if err := json.Unmarshal([]byte(out), &listed); err != nil || !reflect.DeepEqual(listed, map[string]map[string]string{
		"alpha": {"value": "alpha"},
		"beta":  {"value": "last"},
	}) {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestZypperLocksCLIRejectsUnsafeRootWithoutCall(t *testing.T) {
	for _, root := range []string{"../escape", "/target/../escape", "/target\\..\\escape"} {
		runner := &cliRecordingRunner{}
		code, _, errS := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_locks", "--root", root)
		if code == ExitOK || len(runner.calls) != 0 || strings.Contains(errS, root) {
			t.Fatalf("root=%q code=%d err=%q calls=%d", root, code, errS, len(runner.calls))
		}
	}
}

type cliLocksFS struct {
	*runtime.MemoryFS
	writes int
}

func (f *cliLocksFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	f.writes++
	return f.MemoryFS.WriteFile(name, data, perm)
}

// TestZypperLocksCLIIgnoresPrefixedAndReadsProcInstFirstChild pins the
// zypperpkg.py:2302-2305 minidom semantics at the CLI layer: only an
// unprefixed lexical <message> matches, and a processing instruction is
// the first child whose data (nodeValue) provides the payload.
func TestZypperLocksCLIIgnoresPrefixedAndReadsProcInstFirstChild(t *testing.T) {
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/target/etc/zypp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile("/target/etc/zypp/locks", []byte("solvable_name: demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(`<stream xmlns:p="urn:probe"><p:message>Removed 9</p:message><message><?probe Removed 3?>Removed 4</message></stream>`)}}}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, &cliLocksFS{MemoryFS: memory}), "exec", "pkg.clean_locks", "--root", "/target", "-o", "json")
	var cleaned map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &cleaned) != nil || !reflect.DeepEqual(cleaned, map[string]any{"removed": "3"}) || len(runner.calls) != 1 {
		t.Fatalf("code=%d out=%q err=%q calls=%d result=%#v", code, out, errS, len(runner.calls), cleaned)
	}
}
