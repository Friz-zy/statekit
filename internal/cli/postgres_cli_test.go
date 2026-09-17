package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpostgres "github.com/friz-zy/statekit/modules/exec/postgres"
)

// postgresCLIApp builds a CLI app whose runtime carries only the postgres
// module and a recording fake Runner: the R9.2b surface is mock-only and
// must never reach a real psql or database.
func postgresCLIApp(t *testing.T, runner *cliRecordingRunner) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := execpostgres.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestPostgresCLIVersion drives postgres.version end to end with the pinned
// test's arguments: exact argv and environment through the fake Runner, the
// JSON string rendering of the first stdout line, and no password anywhere
// in the rendered command or CLI output.
func TestPostgresCLIVersion(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1.9\n")},
	}}
	app := postgresCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "postgres.version",
		"--user", "test_user", "--host", "test_host", "--port", "test_port",
		"--maintenance-db", "test_maint", "--password", "test_pass", "-o", "json")
	var version string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &version) != nil || version != "9.1.9" {
		t.Fatalf("version code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 16 || argv[5] != "--username" || argv[6] != "test_user" ||
		argv[14] != "SELECT setting FROM pg_catalog.pg_settings WHERE name = 'server_version'" ||
		argv[15] != "-t" {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=test_pass" ||
		command.Env[1] != "PGUSER=test_user" || command.Env[2] != "PGHOST=test_host" ||
		command.Env[3] != "PGPORT=test_port" {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "test_pass" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}
}

// TestPostgresCLIVersionShapes pins the empty-stdout None rendering, the
// empty-first-line string rendering, the nonzero-exit compatibility data
// path, and the hyphenated maintenance_db flag spelling.
func TestPostgresCLIVersionShapes(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("\n16.2\n")},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.version", "--maintenance_db", "test_maint", "-o", "json")
	var empty string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &empty) != nil || empty != "" {
		t.Fatalf("empty first line code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.version", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("empty stdout code=%d out=%q err=%q, want null", code, out, errS)
	}

	// A failed psql connection keeps Salt's shape: no exception, an empty
	// (None) return.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.version", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want null", code, out, errS)
	}
}

// TestPostgresCLIVersionFailures pins the failure modes: runas rejection,
// redacted Runner errors, and the unregistered internal helper.
func TestPostgresCLIVersionFailures(t *testing.T) {
	runner := &cliRecordingRunner{}
	app := postgresCLIApp(t, runner)
	code, _, errS := captureCode(t, app, "exec", "postgres.version", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || strings.Contains(errS, "password") {
		t.Fatalf("runas code=%d err=%q", code, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: -1, Err: errors.New("exec psql: secret test_pass rejected")},
	}}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.version", "--password", "test_pass", "-o", "json")
	if code != ExitFailed {
		t.Fatalf("runner error code=%d, want ExitFailed", code)
	}
	if strings.Contains(errS, "test_pass") {
		t.Fatalf("CLI error leaks password: %q", errS)
	}

	// The internal parsed-version helper has no public registration.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres._parsed_version", "-o", "json")
	if code != ExitUnsupported {
		t.Fatalf("_parsed_version code=%d err=%q, want ExitUnsupported", code, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("_parsed_version executed %d commands", len(runner.calls))
	}
}
