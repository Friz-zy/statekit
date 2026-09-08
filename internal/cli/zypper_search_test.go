package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperSearchCLIUsesCanonicalFlagsAndArgv(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(`<stream><solvable name="demo" edition="1"/></stream>`)}}}
	code, out, errS := captureCode(t, providerCLIApp(t, "zypper", runner),
		"exec", "pkg.search", "--criteria", "demo", "--refresh=false", "--root", "/target",
		"--match", "exact", "--provides", "--recommends", "--requires", "--suggests", "--conflicts",
		"--obsoletes", "--file_list", "--search_descriptions", "--case_sensitive", "--installed_only",
		"--not_installed_only", "--details", "-o", "json")
	var got map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil || len(runner.calls) != 1 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if want := map[string]map[string]string{"demo": {"name": "demo", "edition": "1"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("result=%#v want=%#v", got, want)
	}
	wantArgv := []string{
		"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search",
		"--match-exact", "--provides", "--recommends", "--requires", "--suggests", "--conflicts",
		"--obsoletes", "--file-list", "--search-descriptions", "--case-sensitive", "--installed-only", "-u", "--details", "demo",
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%#v want=%#v", got, wantArgv)
	}
}

func TestZypperSearchCLINoCallForInvalidOrUnsupportedRequests(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "pkg.search"},
		{"exec", "pkg.search", "--criteria", "bad\nsecret"},
		{"exec", "pkg.search", "--criteria", "demo", "--match", "invalid"},
		{"exec", "pkg.search", "--criteria", "demo", "--unknown", "x"},
	} {
		runner := &cliRecordingRunner{}
		code, _, errS := captureCode(t, providerCLIApp(t, "zypper", runner), args...)
		if code == ExitOK || len(runner.calls) != 0 || strings.Contains(errS, "secret") {
			t.Fatalf("args=%v code=%d err=%q calls=%d", args, code, errS, len(runner.calls))
		}
	}
	for _, manager := range []string{"apt", "yum"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.search", "--criteria", "demo")
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}
}
