package cli

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

func TestZypperResolveCapabilitiesCLIProviderAwareEndToEnd(t *testing.T) {
	// resolve_capabilities defaults to false: pkgs pass through with no call.
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.resolve_capabilities", "--config", `{"pkgs":["w3m_ssl",{"vim":"9.0"},{"curl":null}]}`, "-o", "json")
	var passthrough []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &passthrough) != nil ||
		!reflect.DeepEqual(passthrough, []any{"w3m_ssl", map[string]any{"vim": "9.0"}, "curl"}) || len(runner.calls) != 0 {
		t.Fatalf("pass-through code=%d out=%q err=%q result=%#v calls=%d", code, out, errS, passthrough, len(runner.calls))
	}

	// resolve_capabilities=true resolves via exact search and, on a miss,
	// a single exact provides match renames the entry.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><solvable name="w3m"/></stream>`)},
		{Stdout: []byte(`<stream/>`)},
		{Stdout: []byte(`<stream><solvable name="openssl"/></stream>`)},
	}}
	code, out, errS = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.resolve_capabilities",
		"--config", `{"pkgs":["w3m",{"libssl.so.1.1()(64bit)":"1.1"}],"resolve_capabilities":true,"root":"/target"}`, "-o", "json")
	var resolved []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &resolved) != nil ||
		!reflect.DeepEqual(resolved, []any{"w3m", map[string]any{"openssl": "1.1"}}) || len(runner.calls) != 3 {
		t.Fatalf("resolve code=%d out=%q err=%q result=%#v calls=%d", code, out, errS, resolved, len(runner.calls))
	}
	wantArgv := [][]string{
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "w3m"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "libssl.so.1.1()(64bit)"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "search", "--match-exact", "--provides", "libssl.so.1.1()(64bit)"},
	}
	for i, command := range runner.calls {
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, got, wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes == 0 || command.MaxStderrBytes == 0 {
			t.Fatalf("unsafe command=%#v", command)
		}
	}
}

func TestZypperResolveCapabilitiesCLIProviderBoundary(t *testing.T) {
	for _, manager := range []string{"apt", "yum"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.resolve_capabilities", "--config", `{"pkgs":["demo"]}`)
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}

	// A missing pkgs list is invalid input before any call, and a pkgs CLI
	// flag cannot be expressed for a list-of-any field.
	runner := &cliRecordingRunner{}
	code, _, _ := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.resolve_capabilities")
	if code != ExitFailed || len(runner.calls) != 0 {
		t.Fatalf("missing pkgs code=%d calls=%d", code, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.resolve_capabilities", "--pkgs", "demo")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("pkgs flag code=%d calls=%d", code, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.resolve_capabilities", "--config", `{"pkgs":[1]}`)
	if code != ExitFailed || len(runner.calls) != 0 {
		t.Fatalf("invalid entry code=%d calls=%d", code, len(runner.calls))
	}
}
