package cli

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperListHoldsCLIWriteFS(t *testing.T, content string) *cliLocksFS {
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

func TestZypperListHoldsCLIProviderAwareEndToEnd(t *testing.T) {
	fsys := zypperListHoldsCLIWriteFS(t, "solvable_name: demo\ntype: package\n\nsolvable_name: gone\n")
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)},
		{Stdout: []byte("SIZE\n")},
		{Stdout: []byte("edition: 1.0-1\nname: demo\n-----\nedition: 2.0-1\nname: demo\n-----\n")},
		{Stdout: []byte(`<stream/>`)},
	}}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_holds", "--root", "/target", "--full=false", "-o", "json")
	var holds []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &holds) != nil ||
		!reflect.DeepEqual(holds, []string{"demo"}) || len(runner.calls) != 4 || fsys.writes != 0 {
		t.Fatalf("code=%d out=%q err=%q holds=%#v calls=%d writes=%d", code, out, errS, holds, len(runner.calls), fsys.writes)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "--case-sensitive", "--installed-only", "--details", "demo"}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%v want=%v", got, wantArgv)
	}
	if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, []string{"rpm", "--querytags"}) {
		t.Fatalf("querytags argv=%v", got)
	}
	infoArgv := append([]string{runner.calls[2].Name}, runner.calls[2].Args...)
	if len(infoArgv) != 7 || infoArgv[0] != "rpm" || infoArgv[3] != "-q" || infoArgv[4] != "demo" || infoArgv[5] != "--queryformat" {
		t.Fatalf("info argv=%v", infoArgv)
	}
	if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes == 0 || runner.calls[0].MaxStderrBytes == 0 {
		t.Fatalf("unsafe command=%#v", runner.calls[0])
	}

	// The full definition keeps epoch and edition per installed version.
	fsys = zypperListHoldsCLIWriteFS(t, "solvable_name: demo\n")
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><solvable name="demo"/></stream>`)},
		{Stdout: []byte("SIZE\n")},
		{Stdout: []byte("edition: 2:1.0-1\nepoch: 2\nname: demo\n-----\n")},
	}}
	code, out, errS = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_holds", "--root", "/target", "-o", "json")
	var full []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &full) != nil ||
		!reflect.DeepEqual(full, []string{"demo-2:2:1.0-1.*"}) || len(runner.calls) != 3 {
		t.Fatalf("full code=%d out=%q err=%q holds=%#v calls=%d", code, out, errS, full, len(runner.calls))
	}
}

func TestZypperListHoldsCLIProviderBoundary(t *testing.T) {
	// APT keeps the unsupported exit code without calling the Runner.
	for _, manager := range []string{"apt"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.list_holds", "--full=false")
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}

	// YUM keeps its committed CLI surface: pattern/full only, no root flag.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("yum-plugin-versionlock 1\n")},
		{Stdout: []byte("\n")},
	}}
	code, out, errS := captureCode(t, providerCLIApp(t, "yum", runner), "exec", "pkg.list_holds", "--full=false", "-o", "json")
	var holds []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &holds) != nil || len(holds) != 0 || len(runner.calls) != 2 {
		t.Fatalf("yum code=%d out=%q err=%q holds=%#v calls=%d", code, out, errS, holds, len(runner.calls))
	}

	// A Zypper-only root flag is invalid input for YUM before any call.
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIApp(t, "yum", runner), "exec", "pkg.list_holds", "--root", "/target")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("yum root code=%d calls=%d", code, len(runner.calls))
	}

	// Invalid pattern and unknown flags are rejected without Runner calls.
	fsys := zypperListHoldsCLIWriteFS(t, "solvable_name: demo\n")
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_holds", "--pattern", "[")
	if code == ExitOK || len(runner.calls) != 0 {
		t.Fatalf("invalid pattern code=%d calls=%d", code, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_holds", "--unknown", "x")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("unknown flag code=%d calls=%d", code, len(runner.calls))
	}
}
