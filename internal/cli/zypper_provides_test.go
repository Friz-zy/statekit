package cli

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperListProvidesCLIProviderAwareEndToEnd(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("perl(Button)_|-perl-Wx\npython3-futures_|-python3\nperl(Button)_|-perl-Tk\nbroken line\n")},
	}}
	code, out, errS := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_provides", "--root", "/target", "-o", "json")
	var provides map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &provides) != nil ||
		!reflect.DeepEqual(provides, map[string]any{
			"perl(Button)":    []any{"perl-Wx", "perl-Tk"},
			"python3-futures": []any{"python3"},
		}) || len(runner.calls) != 1 {
		t.Fatalf("code=%d out=%q err=%q provides=%#v calls=%d", code, out, errS, provides, len(runner.calls))
	}
	wantArgv := []string{"rpm", "--root", "/target", "-qa", "--queryformat", "%{PROVIDES}_|-%{NAME}\\n"}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%v want=%v", got, wantArgv)
	}
	if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes == 0 || runner.calls[0].MaxStderrBytes == 0 {
		t.Fatalf("unsafe command=%#v", runner.calls[0])
	}

	// A nonzero rpm retcode surfaces as a failed call, never as fabricated
	// output.
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("rpm boom")}}}
	code, _, errS = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_provides")
	if code != ExitFailed || errS == "" || len(runner.calls) != 1 {
		t.Fatalf("retcode code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

func TestZypperListProvidesCLIProviderBoundary(t *testing.T) {
	for _, manager := range []string{"apt", "yum"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.list_provides")
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}

	// list_provides has only root; search-like flags are invalid input.
	runner := &cliRecordingRunner{}
	code, _, _ := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_provides", "--refresh")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("unknown flag code=%d calls=%d", code, len(runner.calls))
	}
}
