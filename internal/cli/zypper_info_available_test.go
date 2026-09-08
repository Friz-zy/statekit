package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperInfoAvailableCLIUsesListArgsRefreshAndRoot(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{},
		{Stdout: []byte("Information for package alpha:\nName: alpha\nInstalled: No\nStatus: not installed\n")},
	}}
	fsys := &cliCountingFS{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys),
		"exec", "pkg.info_available", "--names", "zeta,alpha,zeta", "--root", "/target",
		"--repos", "base", "--gpgautoimport", "-o", "json")
	var got map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil || len(runner.calls) != 2 || fsys.calls != 0 {
		t.Fatalf("code=%d out=%q err=%q calls=%d fs=%d", code, out, errS, len(runner.calls), fsys.calls)
	}
	wantObject := map[string]map[string]any{
		"alpha": {"installed": false, "status": "not installed"},
	}
	if !reflect.DeepEqual(got, wantObject) {
		t.Fatalf("object=%#v want=%#v", got, wantObject)
	}
	want := [][]string{
		{"zypper", "--non-interactive", "--root", "/target", "--gpg-auto-import-keys", "refresh", "--force", "base"},
		{"zypper", "--non-interactive", "--no-refresh", "--root", "/target", "info", "-t", "package", "alpha", "zeta"},
	}
	for i, command := range runner.calls {
		got := append([]string{command.Name}, command.Args...)
		if !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("argv[%d]=%#v want=%#v", i, got, want[i])
		}
	}
}

func TestZypperInfoAvailableCLINoNamesAndUnsupportedProvidersNoCall(t *testing.T) {
	runner := &cliRecordingRunner{}
	fsys := &cliCountingFS{}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys),
		"exec", "pkg.info_available", "--refresh=false", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "{}" || len(runner.calls) != 0 || fsys.calls != 0 {
		t.Fatalf("empty code=%d out=%q err=%q calls=%d fs=%d", code, out, errS, len(runner.calls), fsys.calls)
	}
	for _, manager := range []string{"apt", "yum"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIAppWithFS(t, manager, runner, &cliCountingFS{}),
			"exec", "pkg.info_available", "--names", "demo")
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}
}
