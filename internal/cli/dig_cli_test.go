//go:build dns_contract

package cli

// dig CLI contract tests (dns_contract build tag): every vector runs
// against a scripted fake Runner — no dig execution, no DNS, no network.

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
)

// digCLIRunner scripts CommandResults by joined argv. It deliberately
// exposes no resolver capability of its own; scripted tests wrap it in
// digCLIResolverRunner so the trusted-resolution gate opens against a
// synthetic absolute path, and TestDigCLICheckIP pins that a bare
// capability-less Runner fails closed (no LookPath, no bare-name PATH
// fallback).
type digCLIRunner struct {
	script   map[string][]process.CommandResult
	commands []process.Command
}

func (r *digCLIRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.commands = append(r.commands, cmd)
	key := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
	queue := r.script[key]
	if len(queue) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := queue[0]
	r.script[key] = queue[1:]
	return result
}

// digCLIResolverRunner adds the test TrustedCommandResolver seam to a
// CLI fake Runner: path drives ResolveTrustedCommand ("dig" only).
type digCLIResolverRunner struct {
	inner interface {
		Run(context.Context, process.Command) process.CommandResult
	}
	path string
	err  error
}

func (r *digCLIResolverRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	return r.inner.Run(ctx, cmd)
}

func (r *digCLIResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

func digCLIResult(stdout string, exitCode int) process.CommandResult {
	return process.CommandResult{Stdout: []byte(stdout), ExitCode: exitCode}
}

// digCLIApp builds the App over a scripted runner wrapped in the test
// trusted resolver (the synthetic absolute path opens the gate without
// any real binary).
func digCLIApp(t *testing.T, runner *digCLIRunner) *App {
	t.Helper()
	return digCLIAppRaw(t, &digCLIResolverRunner{inner: runner, path: "/usr/bin/dig"})
}

// digCLIAppRaw builds the App over an arbitrary process.Runner (the
// resolver-less fail-closed vectors pass the bare runner).
func digCLIAppRaw(t *testing.T, runner process.Runner) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
		Runner: runner,
	}
	if err := execdig.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestDigCLIRunsAAndAlias drives dig.A and the dig.a alias end to end:
// the exact shell-free argv reaches the Runner and the pinned list
// shape reaches stdout.
func TestDigCLIRunsAAndAlias(t *testing.T) {
	runner := &digCLIRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {
			digCLIResult("74.125.193.104\n74.125.193.105\n", 0),
			digCLIResult("74.125.193.104\n74.125.193.105\n", 0),
		},
	}}
	app := digCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.A", "--host", "www.google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.A code=%d out=%q err=%q", code, out, errS)
	}
	var rows []string
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("dig.A json: %v (%q)", err, out)
	}
	if fmt.Sprint(rows) != "[74.125.193.104 74.125.193.105]" {
		t.Fatalf("dig.A rows = %#v", rows)
	}

	code, out, errS = captureCode(t, app, "exec", "dig.a", "--host", "www.google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.a code=%d out=%q err=%q", code, out, errS)
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("dig.a json: %v (%q)", err, out)
	}
	if fmt.Sprint(rows) != "[74.125.193.104 74.125.193.105]" {
		t.Fatalf("dig.a rows = %#v", rows)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
	for i, cmd := range runner.commands {
		joined := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
		if joined != "/usr/bin/dig -r +short -q www.google.com -t A" {
			t.Fatalf("call %d argv = %q", i, joined)
		}
		if cmd.Shell {
			t.Fatalf("call %d ran through a shell", i)
		}
	}
}

// TestDigCLICheckIP keeps check_ip's boolean surface and its
// availability gating, including the resolver-less fail-closed class.
func TestDigCLICheckIP(t *testing.T) {
	runner := &digCLIRunner{}
	app := digCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.check_ip", "--addr", "127.0.0.1", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("check_ip true code=%d out=%q err=%q", code, out, errS)
	}
	code, out, errS = captureCode(t, app, "exec", "dig.check_ip", "--addr", "-127.0.0.1", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("check_ip false code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("check_ip dispatches = %d", len(runner.commands))
	}

	gated := &digCLIResolverRunner{inner: &digCLIRunner{}, err: fmt.Errorf("no trusted dig")}
	gatedApp := digCLIAppRaw(t, gated)
	code, _, errS = captureCode(t, gatedApp, "exec", "dig.check_ip", "--addr", "127.0.0.1", "-o", "json")
	if code == ExitOK || errS == "" {
		t.Fatalf("check_ip gated code=%d err=%q", code, errS)
	}
	if !strings.Contains(errS, "dig module cannot be loaded") {
		t.Fatalf("check_ip gated err = %q", errS)
	}
	if len(gated.inner.(*digCLIRunner).commands) != 0 {
		t.Fatalf("gated dispatches = %d", len(gated.inner.(*digCLIRunner).commands))
	}

	// A CLI Runner without the resolver capability cannot verify the
	// executable: every dig.* target fails closed with the fixed
	// unverified-executable error and zero dispatch — no LookPath, no
	// bare-name PATH fallback.
	capless := &digCLIRunner{}
	caplessApp := digCLIAppRaw(t, capless)
	code, out, errS = captureCode(t, caplessApp, "exec", "dig.check_ip", "--addr", "127.0.0.1", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("check_ip capability-less code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dig: unverified executable") {
		t.Fatalf("check_ip capability-less err = %q", errS)
	}
	if len(capless.commands) != 0 {
		t.Fatalf("capability-less dispatches = %d", len(capless.commands))
	}
}

// TestDigCLITrustedResolutionBoundary pins the trusted native boundary at
// the CLI surface: the resolved absolute path is argv[0] of every
// dispatch and the child environment is exactly the fixed allowlist.
func TestDigCLITrustedResolutionBoundary(t *testing.T) {
	const synthetic = "/usr/bin/dig"
	inner := &digCLIRunner{script: map[string][]process.CommandResult{
		synthetic + " -r +short -q www.google.com -t A": {
			digCLIResult("74.125.193.104\n", 0),
		},
	}}
	runner := &digCLIResolverRunner{inner: inner, path: synthetic}
	app := digCLIAppRaw(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.A", "--host", "www.google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.A trusted code=%d out=%q err=%q", code, out, errS)
	}
	if len(inner.commands) != 1 {
		t.Fatalf("dispatches = %d", len(inner.commands))
	}
	cmd := inner.commands[0]
	if cmd.Name != synthetic {
		t.Fatalf("argv[0] = %q, want %q", cmd.Name, synthetic)
	}
	if cmd.Shell {
		t.Fatal("trusted dispatch ran through a shell")
	}
	wantEnv := []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
	if !reflect.DeepEqual(cmd.Env, wantEnv) {
		t.Fatalf("env = %q, want the exact allowlist %q", cmd.Env, wantEnv)
	}
	for _, env := range cmd.Env {
		for _, forbidden := range []string{"RES_OPTIONS", "LOCALDOMAIN", "HOSTALIASES", "LD_"} {
			if strings.HasPrefix(env, forbidden+"=") {
				t.Fatalf("forbidden inherited variable %q", env)
			}
		}
	}
}

// TestDigCLISPFInclude drives the include recursion end to end through
// the registered name, asserting both dispatches and the collected
// ranges.
func TestDigCLISPFInclude(t *testing.T) {
	runner := &digCLIRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q xmission.com -t SPF":      {digCLIResult("", 0)},
		"/usr/bin/dig -r +short -q xmission.com -t TXT":      {digCLIResult(`"v=spf1 a mx include:_spf.xmission.com ?all"`, 0)},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t SPF": {digCLIResult("", 0)},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t TXT": {digCLIResult(`"v=spf1 a mx ip4:198.60.22.0/24 ip4:166.70.13.0/24 ~all"`, 0)},
	}}
	app := digCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.SPF", "--domain", "xmission.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.SPF code=%d out=%q err=%q", code, out, errS)
	}
	var ranges []string
	if err := json.Unmarshal([]byte(out), &ranges); err != nil {
		t.Fatalf("dig.SPF json: %v (%q)", err, out)
	}
	if fmt.Sprint(ranges) != "[198.60.22.0/24 166.70.13.0/24]" {
		t.Fatalf("dig.SPF ranges = %#v", ranges)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

// TestDigCLIMXRawAndResolve pins both MX shapes through the CLI.
func TestDigCLIMXRawAndResolve(t *testing.T) {
	runner := &digCLIRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t MX": {
			digCLIResult("10 aspmx.l.google.com.\n", 0),
			digCLIResult("10 aspmx.l.google.com.\n", 0),
		},
		"/usr/bin/dig -r +short -q aspmx.l.google.com. -t A": {digCLIResult("64.233.162.27\n64.233.162.28\n", 0)},
	}}
	app := digCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.MX", "--domain", "google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.MX code=%d out=%q err=%q", code, out, errS)
	}
	var rawRows [][]string
	if err := json.Unmarshal([]byte(out), &rawRows); err != nil {
		t.Fatalf("dig.MX raw json: %v (%q)", err, out)
	}
	if fmt.Sprint(rawRows) != "[[10 aspmx.l.google.com.]]" {
		t.Fatalf("dig.MX raw rows = %#v", rawRows)
	}

	code, out, errS = captureCode(t, app, "exec", "dig.MX", "--domain", "google.com", "--resolve", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.MX resolve code=%d out=%q err=%q", code, out, errS)
	}
	var resolveRows [][]string
	if err := json.Unmarshal([]byte(out), &resolveRows); err != nil {
		t.Fatalf("dig.MX resolve json: %v (%q)", err, out)
	}
	if fmt.Sprint(resolveRows) != "[[10 64.233.162.27]]" {
		t.Fatalf("dig.MX resolve rows = %#v", resolveRows)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

// TestDigCLIMXEmptyStdoutJSONShape pins the MX JSON shape at the CLI
// surface (R102-FINAL-01): Salt answers line.split() rows and a Python
// list is never null, so an empty successful MX stdout renders [[]] —
// the JSON decoder sees exactly one empty row, not [null] — and
// interior blank/whitespace rows render [] the same way.
func TestDigCLIMXEmptyStdoutJSONShape(t *testing.T) {
	runner := &digCLIRunner{
		script: map[string][]process.CommandResult{
			"/usr/bin/dig -r +short -q empty.example -t MX": {digCLIResult("", 0)},
		},
	}
	app := digCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dig.MX", "--domain", "empty.example", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.MX empty code=%d out=%q err=%q", code, out, errS)
	}
	var rows [][]string
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("dig.MX empty json: %v (%q)", err, out)
	}
	if len(rows) != 1 || rows[0] == nil || len(rows[0]) != 0 {
		t.Fatalf("dig.MX empty rows = %#v; want one empty (non-null) row", rows)
	}
	// The literal rendering distinguishes [[]] from [null].
	if strings.Contains(out, "null") {
		t.Fatalf("dig.MX empty json contains null: %q", out)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("dig.MX empty dispatches = %d", len(runner.commands))
	}

	// Interior blank/whitespace rows are [] — never null — and the
	// trailing whitespace run is rstripped once like cmd.run_all.
	blank := &digCLIRunner{
		script: map[string][]process.CommandResult{
			"/usr/bin/dig -r +short -q blank.example -t MX": {digCLIResult("10 a.example.\n \n\t\n20 b.example.\n\n \t", 0)},
		},
	}
	blankApp := digCLIApp(t, blank)
	code, out, errS = captureCode(t, blankApp, "exec", "dig.MX", "--domain", "blank.example", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dig.MX blank code=%d out=%q err=%q", code, out, errS)
	}
	rows = nil
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("dig.MX blank json: %v (%q)", err, out)
	}
	if len(rows) != 4 {
		t.Fatalf("dig.MX blank rows = %#v", rows)
	}
	for i, row := range rows {
		if row == nil {
			t.Fatalf("dig.MX blank row %d is null", i)
		}
	}
	if strings.Contains(out, "null") {
		t.Fatalf("dig.MX blank json contains null: %q", out)
	}
}

// TestDigCLIZeroDispatchOnInvalidInput keeps the module's validation
// boundary at the CLI surface: invalid inputs fail with the fixed
// value-free module errors and never dispatch.
func TestDigCLIZeroDispatchOnInvalidInput(t *testing.T) {
	runner := &digCLIRunner{}
	app := digCLIApp(t, runner)

	vectors := []struct {
		argv []string
	}{
		{[]string{"exec", "dig.A", "--host=-flag.example", "-o", "json"}},
		{[]string{"exec", "dig.A", "--host", "ok.example", "--nameserver", "1.2.3.4:53", "-o", "json"}},
		{[]string{"exec", "dig.PTR", "--host", "not-an-ip", "-o", "json"}},
		{[]string{"exec", "dig.SPF", "--domain", "ok.example", "--record", "MX", "-o", "json"}},
	}
	for _, v := range vectors {
		code, out, errS := captureCode(t, app, v.argv...)
		if code == ExitOK || errS == "" || out != "" {
			t.Fatalf("%v code=%d out=%q err=%q", v.argv, code, out, errS)
		}
		for _, needle := range []string{"-flag.example", "1.2.3.4:53", "not-an-ip", "ok.example"} {
			if strings.Contains(errS, needle) {
				t.Fatalf("%v error leaks %q: %q", v.argv, needle, errS)
			}
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid-input dispatches = %d", len(runner.commands))
	}
}

// TestDigCLIRunnerFailuresAreValueFree pins the fixed Runner failure
// classes at the CLI surface.
func TestDigCLIRunnerFailuresAreValueFree(t *testing.T) {
	failing := &digCLIFailingRunner{err: fmt.Errorf("dig -r +short -q leak.example -t A timed out: %w", context.DeadlineExceeded)}
	failApp := digCLIAppRaw(t, &digCLIResolverRunner{inner: failing, path: "/usr/bin/dig"})
	code, out, errS := captureCode(t, failApp, "exec", "dig.A", "--host", "leak.example", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("timeout code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(errS, "leak.example") || strings.Contains(errS, "dig -r") {
		t.Fatalf("timeout error leaks argv/domain: %q", errS)
	}
	if !strings.Contains(errS, "dig: command timed out") {
		t.Fatalf("timeout err = %q", errS)
	}
}

type digCLIFailingRunner struct{ err error }

func (r *digCLIFailingRunner) Run(context.Context, process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: -1, Err: r.err}
}
