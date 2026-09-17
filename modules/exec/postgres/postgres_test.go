package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

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

// TestPostgresRegistrySurface pins the six canonical registrations, their
// argument prototypes, and the absence of public psql_query and
// _parsed_version entries.
func TestPostgresRegistrySurface(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"postgres.db_exists",
		"postgres.db_list",
		"postgres.tablespace_exists",
		"postgres.tablespace_list",
		"postgres.user_list",
		"postgres.version",
	}
	if reg.Len() != len(wantNames) {
		t.Fatalf("registry length = %d, want %d", reg.Len(), len(wantNames))
	}
	for _, name := range wantNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		var want any
		switch name {
		case "postgres.version":
			want = VersionArgs{}
		case "postgres.user_list":
			want = UserListArgs{}
		case "postgres.db_exists", "postgres.tablespace_exists":
			want = ExistsArgs{}
		default:
			want = ListArgs{}
		}
		if fn.Args() != want {
			t.Fatalf("%s prototype = %#v, want zero-value defaults %#v", name, fn.Args(), want)
		}
	}
	// The generic query surface and the private helper stay unregistered.
	if _, ok := reg.Get("postgres.psql_query"); ok {
		t.Fatal("postgres.psql_query must not be publicly registered")
	}
	if _, ok := reg.Get("postgres._parsed_version"); ok {
		t.Fatal("postgres._parsed_version must not be publicly registered")
	}
	connection := []string{"host", "maintenance_db", "password", "port", "runas", "user"}
	cases := []struct {
		fn   runtime.ExecFunction
		want []string
	}{
		{versionFunc{}, connection},
		{dbListFunc{}, connection},
		{dbExistsFunc{}, append([]string{"name"}, connection...)},
		{tablespaceListFunc{}, connection},
		{tablespaceExistsFunc{}, append([]string{"name"}, connection...)},
		{userListFunc{}, append(connection, "return_password")},
	}
	for _, tc := range cases {
		names, err := config.ArgumentNames(tc.fn.Args())
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(tc.want)
		if !reflect.DeepEqual(names, tc.want) {
			t.Fatalf("%s argument names = %q, want %q", tc.fn.Name(), names, tc.want)
		}
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
	parsed, err := parsedServerVersion(context.Background(), rt, fullVersionArgs().connection())
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
		parsed, err := parsedServerVersion(context.Background(), rt, (&VersionArgs{}).connection())
		if err != nil || parsed != nil {
			t.Fatalf("stdout %q: parsed = %v, err = %v, want nil, nil", stdout, parsed, err)
		}
	}

	// Runner failures propagate; malformed text still parses because
	// LooseVersion never rejects content.
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: -1, Err: errors.New("boom")})
	if _, err := parsedServerVersion(context.Background(), rt, fullVersionArgs().connection()); err == nil {
		t.Fatal("runner error must propagate")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("not a version!\n")})
	parsed, err = parsedServerVersion(context.Background(), rt, (&VersionArgs{}).connection())
	if err != nil || parsed == nil || parsed.String() != "not a version!" {
		t.Fatalf("malformed version parsed = %v, err = %v", parsed, err)
	}
}

// ---------------------------------------------------------------------------
// R9.2c read-only catalog primitives.

// pinnedListDBCSV is the get_test_list_db_csv fixture from the pinned
// test_postgres.py, verbatim.
const pinnedListDBCSV = `Name,Owner,Encoding,Collate,Ctype,Access privileges,Tablespace
template1,postgres,LATIN1,en_US,en_US,"{=c/postgres,postgres=CTc/postgres}",pg_default
template0,postgres,LATIN1,en_US,en_US,"{=c/postgres,postgres=CTc/postgres}",pg_default
postgres,postgres,LATIN1,en_US,en_US,,pg_default
test_db,postgres,LATIN1,en_US,en_US,,pg_default
`

// wantPinnedDBList is the pinned test_db_list expected dictionary.
var wantPinnedDBList = map[string]map[string]string{
	"test_db": {
		"Encoding":          "LATIN1",
		"Ctype":             "en_US",
		"Tablespace":        "pg_default",
		"Collate":           "en_US",
		"Owner":             "postgres",
		"Access privileges": "",
	},
	"template1": {
		"Encoding":          "LATIN1",
		"Ctype":             "en_US",
		"Tablespace":        "pg_default",
		"Collate":           "en_US",
		"Owner":             "postgres",
		"Access privileges": "{=c/postgres,postgres=CTc/postgres}",
	},
	"template0": {
		"Encoding":          "LATIN1",
		"Ctype":             "en_US",
		"Tablespace":        "pg_default",
		"Collate":           "en_US",
		"Owner":             "postgres",
		"Access privileges": "{=c/postgres,postgres=CTc/postgres}",
	},
	"postgres": {
		"Encoding":          "LATIN1",
		"Ctype":             "en_US",
		"Tablespace":        "pg_default",
		"Collate":           "en_US",
		"Owner":             "postgres",
		"Access privileges": "",
	},
}

// TestPostgresDbListArgvAndParse ports the pinned test_db_list: the pinned
// fixture CSV parses to the exact expected dictionary, and the psql argv
// carries the fixed catalog SQL inside the pinned COPY-to-CSV transport
// with the datestyle variable.
func TestPostgresDbListArgvAndParse(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedListDBCSV),
	})
	value, err := (dbListFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err != nil {
		t.Fatal(err)
	}
	databases, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("db_list type = %T", value)
	}
	if !reflect.DeepEqual(databases, wantPinnedDBList) {
		t.Fatalf("db_list = %#v", databases)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := append([]string(nil), wantVersionArgv[:13]...)
	want = append(want, "-v", "datestyle=ISO,MDY", "-c",
		"COPY ("+dbListQuery+") TO STDOUT WITH CSV HEADER")
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q", got)
	}
	if !reflect.DeepEqual(command.Env, []string{
		"PGPASSWORD=test_pass",
		"PGUSER=test_user",
		"PGHOST=test_host",
		"PGPORT=test_port",
	}) {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
		t.Fatalf("unsafe command: %#v", command)
	}
	if command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe command bounds: %#v", command)
	}
	if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

func fullListArgs() *ListArgs {
	return &ListArgs{
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
	}
}

// TestPostgresDbListDefaults pins the no-argument argv: no connection
// flags, the "postgres" maintenance database fallback, a clean environment,
// and no redaction.
func TestPostgresDbListDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Name,Owner\n")})
	if _, err := (dbListFunc{}).Execute(context.Background(), rt, &ListArgs{}); err != nil {
		t.Fatal(err)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-v", "datestyle=ISO,MDY", "-c",
		"COPY (" + dbListQuery + ") TO STDOUT WITH CSV HEADER",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q", got)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("default env = %q", command.Env)
	}
	if command.Redact != nil {
		t.Fatalf("default redact = %q", command.Redact)
	}
}

// TestPostgresDbExists ports the pinned test_db_exists truth table against
// the pinned fixture: an existing database is true, an absent one false,
// and the lookup never sends the name to the server.
func TestPostgresDbExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"test_db", true},
		{"missing_db", false},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedListDBCSV),
		})
		value, err := (dbExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: tc.name})
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("db_exists(%q) = %#v, want %v", tc.name, value, tc.want)
		}
		command := runner.calls[0]
		joined := strings.Join(command.Args, "\x00")
		if !strings.Contains(joined, dbListQuery) {
			t.Fatalf("db_exists argv lacks the fixed db_list SQL")
		}
		if tc.name == "missing_db" && strings.Contains(joined, tc.name) {
			t.Fatalf("db_exists leaked the lookup name into argv: %q", command.Args)
		}
	}
}

// TestPostgresDbListNonzeroExitKeepsCompatibilityData pins Salt's shape: a
// failed psql query is not an exception; db_list returns the empty catalog
// and db_exists answers false.
func TestPostgresDbListNonzeroExitKeepsCompatibilityData(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 2,
		Stderr:   []byte("psql: error: connection refused"),
	})
	value, err := (dbListFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatalf("nonzero exit must not error: %v", err)
	}
	if !reflect.DeepEqual(value, map[string]map[string]string{}) {
		t.Fatalf("db_list = %#v, want empty catalog", value)
	}
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 2,
		Stderr:   []byte("psql: error: connection refused"),
	})
	value, err = (dbExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "test_db"})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("db_exists on failed query = %#v, want false", value)
	}
}

// pinnedTablespaceCSV is the tablespace row set of the pinned
// test_tablespace_list fixture rendered as COPY-to-CSV output.
const pinnedTablespaceCSV = `Name,Owner,ACL,Opts,Location
pg_global,postgres,,,
pg_default,postgres,,,
test_tablespace,testuser,,,/tmp/posgrest_test_tablespace
`

// wantPinnedTablespaces is the pinned test_tablespace_list expected
// dictionary.
var wantPinnedTablespaces = map[string]map[string]string{
	"pg_global":       {"Owner": "postgres", "ACL": "", "Opts": "", "Location": ""},
	"pg_default":      {"Owner": "postgres", "ACL": "", "Opts": "", "Location": ""},
	"test_tablespace": {"Owner": "testuser", "ACL": "", "Opts": "", "Location": "/tmp/posgrest_test_tablespace"},
}

// TestPostgresTablespaceListAndExists ports the pinned
// test_tablespace_list / test_tablespace_exists_true /
// test_tablespace_exists_false fixtures.
func TestPostgresTablespaceListAndExists(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedTablespaceCSV),
	})
	value, err := (tablespaceListFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err != nil {
		t.Fatal(err)
	}
	tablespaces, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("tablespace_list type = %T", value)
	}
	if !reflect.DeepEqual(tablespaces, wantPinnedTablespaces) {
		t.Fatalf("tablespace_list = %#v", tablespaces)
	}
	command := runner.calls[0]
	joined := strings.Join(command.Args, "\x00")
	if !strings.Contains(joined, tablespaceListQuery) {
		t.Fatalf("argv lacks the fixed tablespace_list SQL: %q", command.Args)
	}

	for name, want := range map[string]bool{"test_tablespace": true, "bad_test_tablespace": false} {
		rt, _ := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedTablespaceCSV),
		})
		value, err := (tablespaceExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if value != want {
			t.Fatalf("tablespace_exists(%q) = %#v, want %v", name, value, want)
		}
	}
}

// TestPostgresPsqlQueryCSVRows pins the pinned psql_query CSV semantics
// against vectors derived from the pinned Python csv.reader itself: quoted
// commas, doubled quotes, empty rows skipped, short rows zipped, long rows
// truncated at the header, and the non-strict leniency (unterminated quotes
// and bare quotes stay data instead of erroring).
func TestPostgresPsqlQueryCSVRows(t *testing.T) {
	stdout := "Name,Owner,Note\n" +
		"\n" +
		"db1,postgres,\"quoted, comma\"\n" +
		"db2\n" +
		"db3,postgres,extra,value,columns\n" +
		"db4,postgres,\"say \"\"hi\"\"\"\n" +
		"db5,\"multi\nline\",\"b\"\"both,quoted\"\n"
	rows, err := parseCSVRows(stdout)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"Name": "db1", "Owner": "postgres", "Note": "quoted, comma"},
		{"Name": "db2"},
		{"Name": "db3", "Owner": "postgres", "Note": "extra"},
		{"Name": "db4", "Owner": "postgres", "Note": `say "hi"`},
		{"Name": "db5", "Owner": "multi\nline", "Note": `b"both,quoted`},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %#v", rows)
	}
	// Non-strict leniency, byte-for-byte from the pinned reader: an
	// unterminated quote at end of input keeps its pending field and bare
	// quotes in a non-quoted field stay literal.
	if rows, err := parseCSVRows("Name\n\"unterminated"); err != nil ||
		!reflect.DeepEqual(rows, []map[string]string{{"Name": "unterminated"}}) {
		t.Fatalf("unterminated quote rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name\npost\"\"gres\n"); err != nil ||
		!reflect.DeepEqual(rows, []map[string]string{{"Name": `post""gres`}}) {
		t.Fatalf("bare quotes rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name,Note\n\"a\"b,c\n"); err != nil ||
		!reflect.DeepEqual(rows, []map[string]string{{"Name": "ab", "Note": "c"}}) {
		t.Fatalf("junk after closing quote rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name,Note\n\"a\" ,c\n"); err != nil ||
		!reflect.DeepEqual(rows, []map[string]string{{"Name": "a ", "Note": "c"}}) {
		t.Fatalf("space after closing quote rows = %#v err = %v", rows, err)
	}
	// Trailing/leading comma shapes: the newline after a delimiter saves the
	// empty field, and so does end of input.
	for _, tc := range []struct {
		stdout string
		want   map[string]string
	}{
		{"N1,N2\ndb1,\n", map[string]string{"N1": "db1", "N2": ""}},
		{"N1,N2\ndb1,", map[string]string{"N1": "db1", "N2": ""}},
		{"N1,N2\r\ndb1,\r\n", map[string]string{"N1": "db1", "N2": ""}},
		{"N1,N2\n,x\n", map[string]string{"N1": "", "N2": "x"}},
		{"N1,N2\n\"\",x\n", map[string]string{"N1": "", "N2": "x"}},
	} {
		if rows, err := parseCSVRows(tc.stdout); err != nil ||
			!reflect.DeepEqual(rows, []map[string]string{tc.want}) {
			t.Fatalf("stdout %q: rows = %#v err = %v", tc.stdout, rows, err)
		}
	}
	// Header-only and empty stdout yield no rows.
	for _, stdout := range []string{"", "Name,Owner\n", "Name,Owner\n\n", "\r\n"} {
		rows, err := parseCSVRows(stdout)
		if err != nil || len(rows) != 0 {
			t.Fatalf("stdout %q: rows = %#v err = %v, want empty", stdout, rows, err)
		}
	}
}

// TestPostgresPsqlQueryCSVRowCRLF pins the CRLF contract of the pinned
// Python csv.reader that Go's encoding/csv cannot provide: a \r\n inside a
// quoted field stays byte-exact instead of being normalized to LF, CRLF and
// LF row terminators both work, and a lone \r outside a quoted field is the
// pinned csv.Error.
func TestPostgresPsqlQueryCSVRowCRLF(t *testing.T) {
	if rows, err := parseCSVRows("Name,Note\ndb5,\"a\r\nb\"\n"); err != nil ||
		rows[0]["Note"] != "a\r\nb" {
		t.Fatalf("CRLF in quoted field rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name,Note\r\ndb5,\"a\r\nb\"\r\n"); err != nil ||
		rows[0]["Note"] != "a\r\nb" {
		t.Fatalf("CRLF-terminated rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name,Note\r\ndb1,x\ndb2,\"y\r\nz\"\n"); err != nil ||
		len(rows) != 2 || rows[0]["Note"] != "x" || rows[1]["Note"] != "y\r\nz" {
		t.Fatalf("mixed CRLF/LF rows = %#v err = %v", rows, err)
	}
	// A header column itself may carry an embedded CRLF.
	if rows, err := parseCSVRows("\"N\r\name\",Owner\ndb1,alice\n"); err != nil ||
		rows[0]["N\r\name"] != "db1" || rows[0]["Owner"] != "alice" {
		t.Fatalf("CRLF header rows = %#v err = %v", rows, err)
	}
	// A record ending in a lone \r at end of input is still returned.
	if rows, err := parseCSVRows("Name,Owner\ndb1\r"); err != nil ||
		!reflect.DeepEqual(rows, []map[string]string{{"Name": "db1"}}) {
		t.Fatalf("lone-CR final row = %#v err = %v", rows, err)
	}
	// A \r anywhere else outside a quoted field is Salt's csv.Error.
	for _, stdout := range []string{
		"Name,Owner\rdb1,alice\r",
		"Name\ndb1\rx\n",
		"a\r\rb\n",
	} {
		if _, err := parseCSVRows(stdout); err == nil {
			t.Fatalf("stdout %q: bare CR outside quotes must error", stdout)
		}
	}
}

// TestPostgresPsqlQueryCSVBoundsAndNUL pins the pinned bounds and byte
// handling: the 131072-character field limit on quoted and unquoted fields
// alike, NUL bytes as ordinary data, and the secret-free error surface.
func TestPostgresPsqlQueryCSVBoundsAndNUL(t *testing.T) {
	exact := "N\n" + strings.Repeat("x", pyCSVFieldLimit) + "\n"
	over := "N\n" + strings.Repeat("x", pyCSVFieldLimit+1) + "\n"
	if rows, err := parseCSVRows(exact); err != nil || len(rows) != 1 || len(rows[0]["N"]) != pyCSVFieldLimit {
		t.Fatalf("exact-limit rows = %#v err = %v", rows, err)
	}
	for _, stdout := range []string{over, "N\n\"" + strings.Repeat("x", pyCSVFieldLimit+1) + "\"\n"} {
		_, err := parseCSVRows(stdout)
		if err == nil || !strings.Contains(err.Error(), "field larger than field limit") {
			t.Fatalf("over-limit err = %v, want pinned field limit error", err)
		}
		if strings.Contains(err.Error(), "xxxx") {
			t.Fatalf("field limit error leaks field content: %v", err)
		}
	}
	if rows, err := parseCSVRows("Name,Note\n\"a\x00b\"\n"); err != nil ||
		rows[0]["Name"] != "a\x00b" {
		t.Fatalf("NUL in quoted field rows = %#v err = %v", rows, err)
	}
	if rows, err := parseCSVRows("Name,Note\nab\x00c\n"); err != nil ||
		rows[0]["Name"] != "ab\x00c" {
		t.Fatalf("NUL in unquoted field rows = %#v err = %v", rows, err)
	}
}

// TestPostgresNameKeyedCatalogMissingColumn pins the KeyError mapping when
// a row is shorter than the Name column itself.
func TestPostgresNameKeyedCatalogMissingColumn(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Owner\npostgres\n")})
	_, err := (dbListFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err == nil || !strings.Contains(err.Error(), `"Name"`) {
		t.Fatalf("short row err = %v, want missing Name column", err)
	}
}

// pinnedUserListCSV renders the pinned test_user_list psql_query mock as
// COPY-to-CSV output (NULLs as empty fields, version 9.1 columns).
const pinnedUserListCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_user,t,t,t,t,t,t,,-1,,2017-08-16 08:57:46,
`

// wantPinnedUserList is the pinned test_user_list expected dictionary with
// CSV-decoded None shapes ("" rather than the mock's Python None).
var wantPinnedUserList = map[string]any{
	"superuser":                  true,
	"defaults variables":         "",
	"can create databases":       true,
	"can create roles":           true,
	"connections":                nil,
	"replication":                nil,
	"expiry time":                time.Date(2017, 8, 16, 8, 57, 46, 0, time.UTC),
	"can login":                  true,
	"can update system catalogs": true,
	"groups":                     []string{},
	"inherits privileges":        true,
}

// TestPostgresUserListArgvAndResult ports the pinned test_user_list: the
// version probe runs first (9.1), the role query carries the
// 9.1 pg_roles.rolreplication and pre-9.5 pg_roles.rolcatupdate columns,
// and the parsed row matches the pinned shape with CSV-decoded NULLs.
func TestPostgresUserListArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedUserListCSV)},
	)
	value, err := (userListFunc{}).Execute(context.Background(), rt, fullUserListArgs())
	if err != nil {
		t.Fatal(err)
	}
	users, ok := value.(map[string]map[string]any)
	if !ok {
		t.Fatalf("user_list type = %T", value)
	}
	if len(users) != 1 {
		t.Fatalf("user_list = %#v", users)
	}
	if !reflect.DeepEqual(users["test_user"], wantPinnedUserList) {
		t.Fatalf("user_list entry = %#v, want %#v", users["test_user"], wantPinnedUserList)
	}
	if _, hasPassword := users["test_user"]["password"]; hasPassword {
		t.Fatal("user_list without return_password must not expose the password column")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (version probe + role query)", len(runner.calls))
	}
	joined := strings.Join(runner.calls[1].Args, "\x00")
	if !strings.Contains(joined, "pg_roles.rolreplication as \"replication\"") {
		t.Fatalf("9.1 query lacks rolreplication column: %q", joined)
	}
	if !strings.Contains(joined, "pg_roles.rolcatupdate as \"can update system catalogs\"") {
		t.Fatalf("pre-9.5 query lacks rolcatupdate column: %q", joined)
	}
	if strings.Contains(joined, "pg_authid") || strings.Contains(joined, "pg_shadow") {
		t.Fatalf("query without return_password must not join password tables: %q", joined)
	}
	if !strings.Contains(joined, "COPY (SELECT pg_roles.rolname") {
		t.Fatalf("role query lacks COPY transport: %q", joined)
	}
}

func fullUserListArgs() *UserListArgs {
	return &UserListArgs{
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
	}
}

// TestPostgresUserListVersionColumns pins the version-dependent column
// selection: >=9.5 NULLs rolcatupdate, and a server that does not answer
// the version probe returns Salt's False after exactly one Runner call.
func TestPostgresUserListVersionColumns(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("16.4\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedUserListCSV)},
	)
	if _, err := (userListFunc{}).Execute(context.Background(), rt, fullUserListArgs()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls[1].Args, "\x00")
	if !strings.Contains(joined, `NULL as "can update system catalogs"`) ||
		!strings.Contains(joined, `pg_roles.rolreplication as "replication"`) {
		t.Fatalf(">=9.5 query columns = %q", joined)
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.0\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedUserListCSV)},
	)
	if _, err := (userListFunc{}).Execute(context.Background(), rt, fullUserListArgs()); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(runner.calls[1].Args, "\x00")
	if !strings.Contains(joined, `NULL as "replication"`) ||
		!strings.Contains(joined, `pg_roles.rolcatupdate as "can update system catalogs"`) {
		t.Fatalf("9.0 query columns = %q", joined)
	}

	// No server answer: Salt's logged-error-then-False shape, with no
	// second psql execution.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("")})
	value, err := (userListFunc{}).Execute(context.Background(), rt, fullUserListArgs())
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("unanswered version user_list = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unanswered version executed %d commands, want 1", len(runner.calls))
	}
}

// TestPostgresUserListReturnPassword pins the return_password=True shape:
// the COALESCE password select and both LEFT JOINs are appended, and the
// password column is returned.
func TestPostgresUserListReturnPassword(t *testing.T) {
	csv := `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables,password
test_user,f,f,f,f,f,t,t,5,"{role one,role2}",invalid-date,"search_path=public",md5abc123
`
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("15.7\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(csv)},
	)
	args := fullUserListArgs()
	args.ReturnPassword = true
	value, err := (userListFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	users := value.(map[string]map[string]any)
	entry := users["test_user"]
	if entry["password"] != "md5abc123" {
		t.Fatalf("password = %#v", entry["password"])
	}
	if entry["superuser"] != false || entry["can login"] != true || entry["connections"] != nil {
		t.Fatalf("bool columns = %#v", entry)
	}
	if !reflect.DeepEqual(entry["groups"], []string{"role one", "role2"}) {
		t.Fatalf("groups = %#v", entry["groups"])
	}
	if entry["expiry time"] != nil {
		t.Fatalf("invalid expiry = %#v, want nil", entry["expiry time"])
	}
	if entry["defaults variables"] != "search_path=public" {
		t.Fatalf("defaults variables = %#v", entry["defaults variables"])
	}
	joined := strings.Join(runner.calls[1].Args, "\x00")
	for _, fragment := range []string{
		`, COALESCE(pg_shadow.passwd, pg_authid.rolpassword) as "password" `,
		"LEFT JOIN pg_authid ON pg_roles.oid = pg_authid.oid ",
		"LEFT JOIN pg_shadow ON pg_roles.oid = pg_shadow.usesysid",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("return_password query lacks %q: %q", fragment, joined)
		}
	}
}

// TestPostgresUserListMissingColumns pins the KeyError mapping for rows
// missing required columns.
func TestPostgresUserListMissingColumns(t *testing.T) {
	rt, _ := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,superuser\ntest_user,t\n")},
	)
	_, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
	if err == nil || !strings.Contains(err.Error(), `"inherits privileges"`) {
		t.Fatalf("short user row err = %v", err)
	}
}

// TestPostgresCatalogGuards pins the shared failure modes across the five
// new functions: pre-canceled context, runas rejection, redacted Runner
// errors, output-limit violations, and psql-unavailable fail-closed, each
// with zero Runner executions where the guard precedes the call.
func TestPostgresCatalogGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (dbListFunc{}).Execute(ctx, rt, fullListArgs()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled db_list err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled db_list executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	args := fullUserListArgs()
	args.Runas = postgresString("postgres")
	if _, err := (userListFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas user_list err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas user_list executed %d commands", len(runner.calls))
	}
	exists := &ExistsArgs{Name: "test_db"}
	exists.Runas = postgresString("postgres")
	if _, err := (tablespaceExistsFunc{}).Execute(context.Background(), rt, exists); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas tablespace_exists err = %v", err)
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname test_maint: secret test_pass rejected"),
	})
	_, err := (dbListFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err == nil || strings.Contains(err.Error(), "test_pass") {
		t.Fatalf("db_list runner error = %v, want redacted", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("db_list error lacks redaction placeholder: %v", err)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (tablespaceListFunc{}).Execute(context.Background(), rt, fullListArgs()); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated tablespace_list err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	for _, exec := range []struct {
		name string
		run  func() error
	}{
		{"db_list", func() error {
			_, err := (dbListFunc{}).Execute(context.Background(), rt, fullListArgs())
			return err
		}},
		{"db_exists", func() error {
			_, err := (dbExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "x"})
			return err
		}},
		{"tablespace_list", func() error {
			_, err := (tablespaceListFunc{}).Execute(context.Background(), rt, fullListArgs())
			return err
		}},
		{"user_list", func() error {
			_, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
			return err
		}},
	} {
		if err := exec.run(); !errors.Is(err, errPostgresPsqlUnavailable) {
			t.Fatalf("%s psql-unavailable err = %v", exec.name, err)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	// Wrong argument types are rejected like the pinned TypeError.
	if _, err := (dbListFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("db_list must reject non-struct args")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (userListFunc{}).Execute(context.Background(), rtEmpty, &UserListArgs{}); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner user_list err = %v", err)
	}
}

// TestPostgresGroupsVectors pins the pinned groups decode against vectors
// generated from the pinned Python expression itself
// (list(csv.reader([row["groups"].strip("{}")]))[0] on python:3.12): array
// braces stripped, CSV-quoted role names, the empty literal, and PostgreSQL
// backslash-escaped array text decoded with the non-strict Python rules.
func TestPostgresGroupsVectors(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"{}", []string{}},
		{"{role1}", []string{"role1"}},
		{"{role1,role2}", []string{"role1", "role2"}},
		{`{"role one",role2}`, []string{"role one", "role2"}},
		{`{"a,b",c}`, []string{"a,b", "c"}},
		// str.strip("{}") removes every leading/trailing brace, exactly
		// like the pinned row["groups"].strip("{}").
		{"{{a},{b}}", []string{"a}", "{b"}},
		{"{{}}", []string{}},
		// PostgreSQL array text with backslash escaping inside quoted
		// elements: the backslash is an ordinary csv character (no
		// escapechar), the quote after it closes the field non-strictly,
		// and the remaining characters keep accumulating.
		{`{"a\"b","x\\y"}`, []string{`a\b"`, `x\\y`}},
		{`{"a\"b"}`, []string{`a\b"`}},
		{`{"a\\b"}`, []string{`a\\b`}},
		{`{"r\"ol\\e",plain}`, []string{`r\ol\\e"`, "plain"}},
		{`{"a\`, []string{`a\`}},
		// CSV double-quote escaping still collapses.
		{`{"a""b",c}`, []string{`a"b`, "c"}},
		// NULL stays the literal unquoted token; the empty quoted element
		// is the empty string.
		{"{NULL}", []string{"NULL"}},
		{`{""}`, []string{""}},
		{"{,}", []string{"", ""}},
		{"{a,}", []string{"a", ""}},
		{"{ role1 ,role2}", []string{" role1 ", "role2"}},
		{`{"}`, []string{""}},
		{`{a"b}`, []string{`a"b`}},
		{"{a\\b}", []string{`a\b`}},
		// Quoted elements keep newlines and carriage returns verbatim.
		{"{\"a\nb\",c}", []string{"a\nb", "c"}},
		{"{\"a\rb\",c}", []string{"a\rb", "c"}},
		// NUL is data for the pinned reader.
		{"{\x00a}", []string{"\x00a"}},
	}
	for _, tc := range cases {
		got, err := parseGroups(tc.in)
		if err != nil {
			t.Fatalf("parseGroups(%q): %v", tc.in, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseGroups(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A CR/LF outside a quoted element is the pinned csv.Error, with a
	// secret-free message that never embeds the input.
	for _, in := range []string{"{a\nb}", "{a\nb,c}", "a,b\nc,d"} {
		_, err := parseGroups(in)
		if err == nil || !strings.Contains(err.Error(), "new-line character seen in unquoted field") {
			t.Fatalf("parseGroups(%q) err = %v, want pinned newline error", in, err)
		}
		if strings.Contains(err.Error(), "{a") {
			t.Fatalf("parseGroups(%q) error leaks input: %v", in, err)
		}
	}
}

// crlfListDBCSV is a db_list COPY CSV whose second Name carries an embedded
// CRLF, exactly as psql emits it: the field is quoted and the CRLF stays
// literal inside the quotes. Mixed CRLF/LF row terminators keep the fixture
// honest about both.
const crlfListDBCSV = "Name,Owner,Encoding,Collate,Ctype,Access privileges,Tablespace\r\n" +
	"db1,postgres,UTF8,C,C,,pg_default\r\n" +
	"\"r\r\ndb\",postgres,UTF8,C,C,,pg_default\n"

// TestPostgresCatalogCRLFRegistryKeys drives the embedded-CRLF contract
// through the registry surface: the pinned Python reader keeps CRLF inside
// quoted fields byte-exact, so a database/tablespace/user named with CRLF
// becomes a catalog key with the original bytes, exists() matches the
// original name client-side, and the lookup name never reaches argv.
func TestPostgresCatalogCRLFRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	list, ok := reg.Get("postgres.db_list")
	if !ok {
		t.Fatal("postgres.db_list not registered")
	}
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(crlfListDBCSV)})
	value, err := list.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	databases, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("db_list type = %T", value)
	}
	if _, has := databases["r\r\ndb"]; !has || databases["r\r\ndb"]["Owner"] != "postgres" {
		t.Fatalf("db_list keys = %#v, want byte-exact embedded-CRLF key", databases)
	}
	if _, has := databases["db1"]; !has {
		t.Fatalf("db_list keys = %#v, want db1 too", databases)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); !strings.Contains(joined, dbListQuery) {
		t.Fatalf("db_list argv lacks the fixed SQL")
	}

	exists, ok := reg.Get("postgres.db_exists")
	if !ok {
		t.Fatal("postgres.db_exists not registered")
	}
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(crlfListDBCSV)})
	value, err = exists.Execute(context.Background(), rt, &ExistsArgs{Name: "r\r\ndb"})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_exists(CRLF name) = %#v, want true", value)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "r\r\ndb") {
		t.Fatalf("db_exists leaked the lookup name into argv: %q", runner.calls[0].Args)
	}

	tsCSV := "Name,Owner,ACL,Opts,Location\r\nts1,postgres,,,/tmp/x\n\"t\r\ns\",postgres,,,/tmp/y\r\n"
	tsList, ok := reg.Get("postgres.tablespace_list")
	if !ok {
		t.Fatal("postgres.tablespace_list not registered")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tsCSV)})
	value, err = tsList.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	tablespaces := value.(map[string]map[string]string)
	if _, has := tablespaces["t\r\ns"]; !has || tablespaces["t\r\ns"]["Location"] != "/tmp/y" {
		t.Fatalf("tablespace_list = %#v, want embedded-CRLF key", tablespaces)
	}
	tsExists, ok := reg.Get("postgres.tablespace_exists")
	if !ok {
		t.Fatal("postgres.tablespace_exists not registered")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tsCSV)})
	value, err = tsExists.Execute(context.Background(), rt, &ExistsArgs{Name: "t\r\ns"})
	if err != nil || value != true {
		t.Fatalf("tablespace_exists(CRLF name) = %#v err = %v, want true", value, err)
	}

	// user_list: the row key comes from a CRLF-bearing name column and the
	// groups array text survives both CSV layers (COPY CSV quoting, then
	// the pinned groups decode).
	userCSV := "name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\r\n" +
		"\"u\r\nser\",t,t,t,t,t,t,t,-1,\"{role1,role2}\",2017-08-16 08:57:46,\n"
	userList, ok := reg.Get("postgres.user_list")
	if !ok {
		t.Fatal("postgres.user_list not registered")
	}
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(userCSV)},
	)
	value, err = userList.Execute(context.Background(), rt, &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	users := value.(map[string]map[string]any)
	entry, has := users["u\r\nser"]
	if !has {
		t.Fatalf("user_list keys = %#v, want embedded-CRLF key", users)
	}
	if !reflect.DeepEqual(entry["groups"], []string{"role1", "role2"}) {
		t.Fatalf("CRLF-name groups = %#v", entry["groups"])
	}
	if len(runner.calls) != 2 {
		t.Fatalf("user_list runner calls = %d, want 2", len(runner.calls))
	}
}

// TestPostgresUserListCRLFGroups pins the groups decode against a groups
// array whose element itself contains a CRLF: COPY CSV quotes the field,
// the pinned reader keeps the CRLF byte-exact, and the array decode then
// preserves it inside the element.
func TestPostgresUserListCRLFGroups(t *testing.T) {
	groupsCell := `"{""a` + "\r\n" + `b"",c}"`
	userCSV := "name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\n" +
		"test_user,t,t,t,t,t,t,t,-1," + groupsCell + ",,\n"
	rt, _ := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(userCSV)},
	)
	value, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	users := value.(map[string]map[string]any)
	if !reflect.DeepEqual(users["test_user"]["groups"], []string{"a\r\nb", "c"}) {
		t.Fatalf("groups = %#v, want [a<CR><LF>b c]", users["test_user"]["groups"])
	}
}
