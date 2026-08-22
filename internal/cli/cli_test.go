package cli

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	statetest "github.com/friz-zy/statekit/modules/state/test"
)

func capture(t *testing.T, fn func()) (string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()
	fn()
	outW.Close()
	errW.Close()
	outData, _ := io.ReadAll(outR)
	errData, _ := io.ReadAll(errR)
	return string(outData), string(errData)
}

func testRuntime() (*runtime.Runtime, error) {
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts: facts.ForTesting(facts.Overrides{
			OS: &facts.OSFacts{ID: "alpine", Family: facts.FamilyAlpine},
		}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	if err := exectest.Register(rt.Exec); err != nil {
		return nil, err
	}
	if err := statetest.Register(rt.States); err != nil {
		return nil, err
	}
	return rt, nil
}

func runApp(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var code int
	var out, errS string
	app := NewApp("test-version", testRuntime)
	out, errS = capture(t, func() { code = app.Run(argv) })
	return code, out, errS
}

func TestVersionCommand(t *testing.T) {
	code, out, _ := runApp(t, "version")
	if code != ExitOK || !strings.Contains(out, "test-version") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	code, out, _ = runApp(t, "version", "-o", "json")
	var parsed map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &parsed) != nil || parsed["version"] != "test-version" {
		t.Fatalf("version json: code=%d out=%q", code, out)
	}
}

func TestExecEchoChannels(t *testing.T) {
	code, out, _ := runApp(t, "exec", "test.echo", "--text", "hello")
	if code != ExitOK || strings.TrimSpace(out) != "hello" {
		t.Fatalf("flag channel: code=%d out=%q", code, out)
	}

	code, out, _ = runApp(t, "exec", "test.echo", "--config", `{"text":"hi"}`)
	if code != ExitOK || strings.TrimSpace(out) != "hi" {
		t.Fatalf("config channel: code=%d out=%q", code, out)
	}

	code, _, _ = runApp(t, "exec", "test.echo", "--stdin", "--file", "x.yaml")
	if code != ExitInvalidInput {
		t.Fatalf("stdin+file must conflict, got %d", code)
	}

	dir := t.TempDir()
	path := dir + "/req.json"
	os.WriteFile(path, []byte(`{"text":"from-file"}`), 0o600)
	code, out, _ = runApp(t, "exec", "test.echo", "--file", path)
	if code != ExitOK || strings.TrimSpace(out) != "from-file" {
		t.Fatalf("file channel: code=%d out=%q", code, out)
	}

	code, out, _ = runApp(t, "exec", "test.echo", "--config", `{"text":"x"}`, "--text", "override")
	if code != ExitOK || strings.TrimSpace(out) != "override" {
		t.Fatalf("flag precedence over config broken: code=%d out=%q", code, out)
	}

	code, _, errS := runApp(t, "exec", "test.echo")
	if code != ExitInvalidInput || !strings.Contains(errS, "required") {
		t.Fatalf("missing required text: code=%d err=%q", code, errS)
	}
}

func TestExecUnknownFunctionExitThree(t *testing.T) {
	code, _, errS := runApp(t, "exec", "nosuchmod.nofun", "--name", "curl")
	if code != ExitUnsupported || !strings.Contains(errS, "unsupported") {
		t.Fatalf("unknown function: code=%d err=%q", code, errS)
	}
}

func TestStateNopJSONShape(t *testing.T) {
	code, out, _ := runApp(t, "state", "test.nop", "--name", "example", "-o", "json")
	var res map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil {
		t.Fatalf("state nop json: code=%d out=%q", code, out)
	}
	if res["name"] != "example" || res["result"] != true || res["comment"] != "Success!" {
		t.Fatalf("salt-compatible fields wrong: %v", res)
	}
	changes, ok := res["changes"].(map[string]any)
	if !ok || len(changes) != 0 {
		t.Fatalf("changes must be empty object: %v", res["changes"])
	}
	meta, ok := res["meta"].(map[string]any)
	if !ok || meta["type"] != "state" || meta["module"] != "test" || meta["function"] != "nop" {
		t.Fatalf("meta missing or wrong: %v", res["meta"])
	}
}

func TestStateSingle(t *testing.T) {
	code, out, _ := runApp(t, "state", "single", "test.nop", "--name", "example", "-o", "json")
	var res map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || res["result"] != true {
		t.Fatalf("single positional form: code=%d out=%q", code, out)
	}
	meta := res["meta"].(map[string]any)
	if meta["module"] != "test" || meta["function"] != "nop" {
		t.Fatalf("meta wrong: %v", meta)
	}

	code, out, _ = runApp(t, "state", "single", "--config",
		`{"fun":"test.nop","name":"via-fun-key"}`, "-o", "json")
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || res["name"] != "via-fun-key" {
		t.Fatalf("single fun-key form: code=%d out=%q", code, out)
	}

	code, _, errS := runApp(t, "state", "single")
	if code != ExitInvalidInput {
		t.Fatalf("bare single must fail, got %d (%q)", code, errS)
	}

	code, _, errS = runApp(t, "exec", "single", "test.echo")
	if code != ExitInvalidInput && code != ExitUnsupported {
		t.Fatalf("single is state-only, got %d (%q)", code, errS)
	}
}

func TestListCommands(t *testing.T) {
	code, out, _ := runApp(t, "exec", "--list")
	if code != ExitOK || !strings.Contains(out, "test.echo") || !strings.Contains(out, "test.ping") {
		t.Fatalf("exec --list: %q", out)
	}
	code, out, _ = runApp(t, "state", "--list")
	if code != ExitOK || !strings.Contains(out, "test.nop") {
		t.Fatalf("state --list: %q", out)
	}
	code, out, _ = runApp(t, "exec", "--list", "nomodule")
	if code != ExitOK || strings.TrimSpace(out) != "" {
		t.Fatalf("filtered list must be empty for unknown prefix: %q", out)
	}
	code, out, _ = runApp(t, "state", "--list", "test")
	if code != ExitOK || !strings.Contains(out, "test.nop") {
		t.Fatalf("module-filtered state list: %q", out)
	}
}

func TestFactsCommand(t *testing.T) {
	code, out, _ := runApp(t, "facts", "-o", "json")
	var parsed map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &parsed) != nil {
		t.Fatalf("facts: code=%d out=%q", code, out)
	}
	osMap, ok := parsed["os"].(map[string]any)
	if !ok || osMap["id"] != "alpine" {
		t.Fatalf("facts payload wrong: %v", parsed["os"])
	}
}

func TestErrorPathsAndCodes(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"no args", nil, ExitInvalidInput},
		{"unknown command", []string{"bogus"}, ExitInvalidInput},
		{"bad target form", []string{"exec", "noDot"}, ExitInvalidInput},
		{"unknown flag", []string{"exec", "test.echo", "--bogus", "x"}, ExitInvalidInput},
		{"missing required", []string{"exec", "test.echo"}, ExitInvalidInput},
		{"unknown arg structured", []string{"exec", "test.echo", "--config", `{"nmae":"x"}`}, ExitInvalidInput},
		{"invalid format", []string{"exec", "test.echo", "--text", "x", "-o", "xml"}, ExitInvalidInput},
		{"unknown state", []string{"state", "pkg.installed", "--name", "x"}, ExitUnsupported},
	}
	for _, tc := range cases {
		code, _, errS := runApp(t, tc.argv...)
		if code != tc.want {
			t.Fatalf("%s: exit=%d want=%d err=%q", tc.name, code, tc.want, errS)
		}
	}
}

func TestHelpExitsZero(t *testing.T) {
	for _, h := range []string{"help", "-h", "--help"} {
		code, out, _ := runApp(t, h)
		if code != ExitOK || !strings.Contains(out, "Usage:") {
			t.Fatalf("%s: code=%d", h, code)
		}
	}
}

func TestStdinDashChannel(t *testing.T) {
	// "-" positional is validated at parse level; full stdin piping covered by
	// the integration harness which spawns the real binary.
	code, _, _ := runApp(t, "exec", "test.echo", "-", "extra-positional")
	if code != ExitInvalidInput {
		t.Fatalf("unexpected positionals must fail, got %d", code)
	}
}
