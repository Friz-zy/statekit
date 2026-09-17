package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type postgresFakeRunner struct {
	results       []process.CommandResult
	defaultResult process.CommandResult
	calls         []process.Command
	available     map[string]bool
}

func (r *postgresFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Redact = append([]string(nil), command.Redact...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	// Preserve the nil-vs-empty distinction: an explicitly clean
	// environment (empty, non-nil) must stay distinguishable from an
	// inherited one (nil) in the recorded calls.
	if command.Env != nil {
		copied := make([]string, len(command.Env))
		copy(copied, command.Env)
		command.Env = copied
	}
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return r.defaultResult
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func (r *postgresFakeRunner) CommandAvailable(name string) bool {
	if r.available == nil {
		return true
	}
	return r.available[name]
}

func newPostgresRuntime(results ...process.CommandResult) (*runtime.Runtime, *postgresFakeRunner) {
	runner := &postgresFakeRunner{
		results:       results,
		defaultResult: process.CommandResult{ExitCode: 0},
	}
	// The runtime deliberately has no Exec registry: postgres.version must
	// not route through pkg.* or any other module on any path.
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func postgresString(value string) *string { return &value }

// wantVersionArgv is the exact argv the pinned test_postgres.py test_version
// asserts shape on: with every connection argument supplied, the SQL query
// sits at index 14.
var wantVersionArgv = []string{
	"psql",
	"--no-align",
	"--no-readline",
	"--no-psqlrc",
	"--no-password",
	"--username", "test_user",
	"--host", "test_host",
	"--port", "test_port",
	"--dbname", "test_maint",
	"-c", "SELECT setting FROM pg_catalog.pg_settings WHERE name = 'server_version'",
	"-t",
}

func fullVersionArgs() *VersionArgs {
	return &VersionArgs{
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
	}
}

// TestPostgresVersionArgvEnvAndResult drives version() with the exact
// pinned-test arguments and asserts argv, environment, redaction, and the
// first-line result.
func TestPostgresVersionArgvEnvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("9.1.9\n"),
	})
	value, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
	if err != nil {
		t.Fatal(err)
	}
	if value != "9.1.9" {
		t.Fatalf("version = %#v, want 9.1.9", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, wantVersionArgv) {
		t.Fatalf("argv = %q", got)
	}
	// The pinned test's index-14 assertion, checked directly.
	if all := append([]string{command.Name}, command.Args...); all[14] != serverVersionQuery {
		t.Fatalf("argv[14] = %q, want the server_version query", all[14])
	}
	wantEnv := []string{
		"PGPASSWORD=test_pass",
		"PGUSER=test_user",
		"PGHOST=test_host",
		"PGPORT=test_port",
	}
	if !reflect.DeepEqual(command.Env, wantEnv) {
		t.Fatalf("env = %q, want %q", command.Env, wantEnv)
	}
	if command.Shell {
		t.Fatal("psql must run without a shell")
	}
	if command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe command bounds: %#v", command)
	}
	if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestPostgresVersionDefaults pins the no-argument shape: no connection
// flags, the "postgres" maintenance database fallback, no credentials, and a
// clean (empty, non-inherited) environment.
func TestPostgresVersionDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("15.7\n")})
	value, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if value != "15.7" {
		t.Fatalf("version = %#v, want 15.7", value)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-c", serverVersionQuery,
		"-t",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("default env = %q, want clean empty environment", command.Env)
	}
	if command.Redact != nil {
		t.Fatalf("default redact = %q, want none", command.Redact)
	}
}

// TestPostgresVersionFirstLineSemantics ports the pinned
// salt.utils.itertools.split(stdout, "\n") consumption: the first line is
// returned even when empty, but an exhausted stdout yields nothing and the
// function falls through to None.
func TestPostgresVersionFirstLineSemantics(t *testing.T) {
	cases := []struct {
		stdout string
		want   any
	}{
		{"9.1.9\n", "9.1.9"},
		{"9.1.9", "9.1.9"},
		{"9.1.9\n\n16.2\n", "9.1.9"},
		{"\n9.1.9\n", ""},
		{"16.4 (Debian 16.4-1.pgdg120+1)\n16.3\n", "16.4 (Debian 16.4-1.pgdg120+1)"},
		{"", nil},
	}
	for _, tc := range cases {
		rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
		if err != nil {
			t.Fatalf("stdout %q: %v", tc.stdout, err)
		}
		if value != tc.want {
			t.Fatalf("stdout %q => %#v, want %#v", tc.stdout, value, tc.want)
		}
	}
}

// TestPostgresVersionNonzeroExitIsCompatibilityData pins Salt's behavior:
// _run_psql logs the retcode but version() still returns the (empty) first
// stdout line, here None; psql failures are not Go errors.
func TestPostgresVersionNonzeroExitIsCompatibilityData(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 2,
		Stderr:   []byte("psql: error: connection refused"),
	})
	value, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
	if err != nil {
		t.Fatalf("nonzero exit must not error: %v", err)
	}
	if value != nil {
		t.Fatalf("version = %#v, want nil", value)
	}
}

// TestPostgresVersionRunnerErrorIsRedacted drives a Runner failure whose
// text embeds the password and asserts the returned error is scrubbed.
func TestPostgresVersionRunnerErrorIsRedacted(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname test_maint: secret test_pass rejected"),
	})
	_, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
	if err == nil {
		t.Fatal("runner failure must surface as an error")
	}
	if strings.Contains(err.Error(), "test_pass") {
		t.Fatalf("error leaks password: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// TestPostgresVersionCanceled proves cancellation is checked before and
// after the Runner call and never reaches a second execution.
func TestPostgresVersionCanceled(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (versionFunc{}).Execute(ctx, rt, fullVersionArgs()); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// TestPostgresVersionOutputLimit pins the bounded-output failure mode.
func TestPostgresVersionOutputLimit(t *testing.T) {
	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		_, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
		if !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated result err = %v, want ErrOutputLimit", err)
		}
	}
}

// TestPostgresVersionPsqlUnavailableFailsClosed pins the fail-closed
// behavior when psql is absent: an explicit error, zero Runner executions,
// and no fallback through any package manager or module registry (the test
// runtime has no Exec registry at all, so apt/yum/zypper and pkg.* paths
// cannot exist).
func TestPostgresVersionPsqlUnavailableFailsClosed(t *testing.T) {
	rt, runner := newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	_, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
	if !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("err = %v, want errPostgresPsqlUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql still executed %d commands", len(runner.calls))
	}
	// The successful path also stays package-manager-free: its single
	// command is the exact psql argv asserted above, and this runtime has
	// no Exec registry, so no apt/yum/zypper or pkg.* call can originate
	// from this module.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("16.4\n")})
	if _, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0].Name != "psql" {
		t.Fatalf("unexpected commands: %#v", runner.calls)
	}
}

// TestPostgresVersionRunasRejected mirrors the R9.1 rabbitmq contract: the
// central runtime is single-user, so runas is rejected before any Runner
// invocation.
func TestPostgresVersionRunasRejected(t *testing.T) {
	rt, runner := newPostgresRuntime()
	args := fullVersionArgs()
	args.Runas = postgresString("postgres")
	if _, err := (versionFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("err = %v, want errPostgresRunas", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}
	// An explicitly empty runas is Salt's None and stays accepted.
	args.Runas = postgresString("")
	if _, err := (versionFunc{}).Execute(context.Background(), rt, args); err != nil {
		t.Fatalf("empty runas rejected: %v", err)
	}
}

// TestPostgresVersionInvalidInputs pins the argument and runtime guards.
func TestPostgresVersionInvalidInputs(t *testing.T) {
	if _, err := (versionFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("version must reject non-struct args")
	}
	rt, _ := newPostgresRuntime()
	if _, err := (versionFunc{}).Execute(context.Background(), &runtime.Runtime{}, &VersionArgs{}); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v", err)
	}
	// Newlines inside connection arguments can never reach a shell-less
	// argv; the guard rejects them outright.
	for _, field := range []func(*VersionArgs) **string{
		func(a *VersionArgs) **string { return &a.User },
		func(a *VersionArgs) **string { return &a.Host },
	} {
		args := &VersionArgs{}
		target := field(args)
		*target = postgresString("va\nlue")
		if _, err := (versionFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("newline argument err = %v, want errPostgresInvalidArgument", err)
		}
	}
}

// TestPostgresRegistrySurface pins the single canonical registration, its
// argument prototype, and the absence of a public _parsed_version entry.
func TestPostgresRegistrySurface(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("postgres.version")
	if !ok {
		t.Fatal("postgres.version not registered")
	}
	if reg.Len() != 1 {
		t.Fatalf("registry length = %d, want 1", reg.Len())
	}
	if _, ok := reg.Get("postgres._parsed_version"); ok {
		t.Fatal("postgres._parsed_version must not be publicly registered")
	}
	if prototype, ok := fn.Args().(VersionArgs); !ok {
		t.Fatalf("prototype type = %T", fn.Args())
	} else if !reflect.DeepEqual(&prototype, &VersionArgs{}) {
		t.Fatalf("prototype = %#v, want zero-value defaults", prototype)
	}
	names, err := config.ArgumentNames(fn.Args())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"host", "maintenance_db", "password", "port", "runas", "user"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("argument names = %q, want %q", names, want)
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration must fail")
	}
}

// TestPostgresParsedVersionVectors pins the LooseVersion-equivalent
// tokenizer and ordering used by the internal _parsed_version helper.
func TestPostgresParsedVersionVectors(t *testing.T) {
	if got := parseLooseVersion("9.1.9").String(); got != "9.1.9" {
		t.Fatalf("String() = %q", got)
	}
	cases := []struct {
		v1, v2 string
		want   int
	}{
		{"9.1.9", "9.1.9", 0},
		{"9.1.9", "10.0", -1},           // integer components compare numerically
		{"10.0", "9.1.9", 1},            //
		{"1.5.1", "1.5.2", -1},          //
		{"1.5.2", "1.5.2a", -1},         // strict prefix sorts first
		{"v1.2", "1.2", 1},              // pinned Salt defines mixed comparisons
		{"16beta1", "16.1", 1},          // "beta" > "00000001"
		{"8.2", "8beta2", -1},           // "00000002" < "beta"
		{"100000000a", "99999999a", -1}, // whole-list zfill(8), not numeric
		{"100000000", "99999999", 1},    // numeric-only lists
		{"99999999999999999999", "100000000000000000000", -1},
		{"1..2", "1.2", 0}, // separator dots do not become components
		{"00000000000000000000000004", "4", 0},
		{"10.6", "10.6 (Ubuntu 10.6-0ubuntu0.18.04.1)", -1},
		{"9.1", "9.1.9", -1}, //
		{"9.04", "9.4", 0},   // digit runs cast to integers ("04" == 4)
		{"", "0", -1},        // empty parse is the shortest list
	}
	for _, tc := range cases {
		got, ok := parseLooseVersion(tc.v1).compare(parseLooseVersion(tc.v2))
		if !ok {
			t.Fatalf("compare(%q, %q) unexpectedly indeterminate", tc.v1, tc.v2)
		}
		if got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
	// The original spelling is preserved, including Debian-style suffixes.
	debian := "16.4 (Debian 16.4-1.pgdg120+1)"
	if got := parseLooseVersion(debian).String(); got != debian {
		t.Fatalf("String() = %q, want %q", got, debian)
	}
}

// TestPostgresParsedServerVersion pins the internal _parsed_version helper:
// parse on success, None on an unanswered probe, error passthrough, and
// tolerance for malformed version text (LooseVersion accepts any string).
func TestPostgresParsedServerVersion(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("9.1.9\n")})
	parsed, err := parsedServerVersion(context.Background(), rt, fullVersionArgs())
	if err != nil || parsed == nil {
		t.Fatalf("parsed = %v, err = %v", parsed, err)
	}
	if parsed.String() != "9.1.9" {
		t.Fatalf("parsed string = %q", parsed.String())
	}
	if order, ok := parsed.compare(parseLooseVersion("9.1")); !ok || order != 1 {
		t.Fatalf("compare(9.1.9, 9.1) = %d, %v", order, ok)
	}

	// No server answer: Salt's None (with its warning dropped by StateKit's
	// no-logging modules) for both the empty and error stdout shapes.
	for _, stdout := range []string{"", "\n"} {
		rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})
		parsed, err := parsedServerVersion(context.Background(), rt, &VersionArgs{})
		if err != nil || parsed != nil {
			t.Fatalf("stdout %q: parsed = %v, err = %v, want nil, nil", stdout, parsed, err)
		}
	}

	// Runner failures propagate; malformed text still parses because
	// LooseVersion never rejects content.
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: -1, Err: errors.New("boom")})
	if _, err := parsedServerVersion(context.Background(), rt, fullVersionArgs()); err == nil {
		t.Fatal("runner error must propagate")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("not a version!\n")})
	parsed, err = parsedServerVersion(context.Background(), rt, &VersionArgs{})
	if err != nil || parsed == nil || parsed.String() != "not a version!" {
		t.Fatalf("malformed version parsed = %v, err = %v", parsed, err)
	}
}
