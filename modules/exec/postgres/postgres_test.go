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

// TestPostgresRegistrySurface pins the twenty canonical registrations,
// their argument prototypes, and the absence of public psql_query and
// _parsed_version entries.
func TestPostgresRegistrySurface(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"postgres.available_extensions",
		"postgres.db_exists",
		"postgres.db_list",
		"postgres.get_available_extension",
		"postgres.get_installed_extension",
		"postgres.has_privileges",
		"postgres.installed_extensions",
		"postgres.is_available_extension",
		"postgres.is_installed_extension",
		"postgres.language_exists",
		"postgres.language_list",
		"postgres.privileges_list",
		"postgres.role_get",
		"postgres.schema_exists",
		"postgres.schema_get",
		"postgres.schema_list",
		"postgres.tablespace_exists",
		"postgres.tablespace_list",
		"postgres.user_exists",
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
		case "postgres.role_get":
			want = RoleGetArgs{}
		case "postgres.has_privileges":
			want = HasPrivilegesArgs{}
		case "postgres.privileges_list":
			want = PrivilegesListArgs{}
		case "postgres.db_exists", "postgres.tablespace_exists",
			"postgres.user_exists",
			"postgres.get_available_extension", "postgres.get_installed_extension",
			"postgres.is_available_extension", "postgres.is_installed_extension":
			want = ExistsArgs{}
		case "postgres.language_list":
			want = LanguageListArgs{}
		case "postgres.language_exists":
			want = LanguageExistsArgs{}
		case "postgres.schema_list":
			want = SchemaListArgs{}
		case "postgres.schema_get", "postgres.schema_exists":
			want = SchemaArgs{}
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
	schemaConnection := []string{"db_host", "db_password", "db_port", "db_user", "dbname", "user"}
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
		{availableExtensionsFunc{}, connection},
		{installedExtensionsFunc{}, connection},
		{getAvailableExtensionFunc{}, append([]string{"name"}, connection...)},
		{getInstalledExtensionFunc{}, append([]string{"name"}, connection...)},
		{isAvailableExtensionFunc{}, append([]string{"name"}, connection...)},
		{isInstalledExtensionFunc{}, append([]string{"name"}, connection...)},
		{languageListFunc{}, connection},
		{languageExistsFunc{}, append([]string{"name"}, connection...)},
		{schemaListFunc{}, schemaConnection},
		{schemaGetFunc{}, append([]string{"name"}, schemaConnection...)},
		{schemaExistsFunc{}, append([]string{"name"}, schemaConnection...)},
		{roleGetFunc{}, append(append([]string{"name"}, connection...), "return_password")},
		{userExistsFunc{}, append([]string{"name"}, connection...)},
		{hasPrivilegesFunc{}, append([]string{
			"name", "object_name", "object_type", "privileges",
			"grant_option", "prepend",
		}, connection...)},
		{privilegesListFunc{}, append([]string{"name", "object_type", "prepend"}, connection...)},
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

// ---------------------------------------------------------------------------
// R9.2d extension and language catalog functions.

// pinnedAvailableExtensionsCSV renders a pg_available_extensions catalog as
// COPY-to-CSV output: the name, default_version, installed_version, and
// comment columns with NULLs as empty fields and a comma-bearing comment
// quoted exactly as psql emits it.
const pinnedAvailableExtensionsCSV = `name,default_version,installed_version,comment
cube,1.2,,"geometric data type for points, lines, and boxes"
plpgsql,1.0,1.0,PL/pgSQL procedural language
unpacked,<none>,,
`

// wantPinnedAvailableExtensions is the extension dictionary the pinned
// available_extensions loop produces for that CSV: the whole row is stored
// under its name, no column removed.
var wantPinnedAvailableExtensions = map[string]map[string]string{
	"cube": {
		"name":              "cube",
		"default_version":   "1.2",
		"installed_version": "",
		"comment":           "geometric data type for points, lines, and boxes",
	},
	"plpgsql": {
		"name":              "plpgsql",
		"default_version":   "1.0",
		"installed_version": "1.0",
		"comment":           "PL/pgSQL procedural language",
	},
	"unpacked": {
		"name":              "unpacked",
		"default_version":   "<none>",
		"installed_version": "",
		"comment":           "",
	},
}

// TestPostgresAvailableExtensionsArgvAndParse ports the pinned
// test_available_extensions row shape through the full transport: the CSV
// parses to the name-keyed dictionary and the psql argv carries the pinned
// select * from pg_available_extensions() SQL inside the COPY-to-CSV
// wrapper.
func TestPostgresAvailableExtensionsArgvAndParse(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedAvailableExtensionsCSV),
	})
	value, err := (availableExtensionsFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err != nil {
		t.Fatal(err)
	}
	extensions, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("available_extensions type = %T", value)
	}
	if !reflect.DeepEqual(extensions, wantPinnedAvailableExtensions) {
		t.Fatalf("available_extensions = %#v", extensions)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := append([]string(nil), wantVersionArgv[:13]...)
	want = append(want, "-v", "datestyle=ISO,MDY", "-c",
		"COPY ("+availableExtensionsQuery[:len(availableExtensionsQuery)-1]+") TO STDOUT WITH CSV HEADER")
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

// TestPostgresAvailableExtensionsPinnedRow pins the exact pinned
// test_available_extensions mock shape: a two-column catalog row becomes
// {"foo": {"name": "foo", "default_version": "1"}}.
func TestPostgresAvailableExtensionsPinnedRow(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("name,default_version\nfoo,1\n"),
	})
	value, err := (availableExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{"foo": {"name": "foo", "default_version": "1"}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("available_extensions = %#v, want %#v", value, want)
	}
}

// pinnedInstalledExtensionsCSV renders a pg_extension catalog joined with
// pg_namespace as COPY-to-CSV output: a.* columns plus the schema_name
// projection of the pinned installed_extensions query.
const pinnedInstalledExtensionsCSV = `oid,extname,extowner,extnamespace,extrelocatable,extversion,extconfig,extcondition,schema_name
16386,plpgsql,10,11,f,1.0,,,pg_catalog
16402,cube,10,2200,t,1.2,,,public
`

// wantPinnedInstalledExtensions is the extension dictionary the pinned
// installed_extensions loop produces for that CSV.
var wantPinnedInstalledExtensions = map[string]map[string]string{
	"plpgsql": {
		"oid":            "16386",
		"extname":        "plpgsql",
		"extowner":       "10",
		"extnamespace":   "11",
		"extrelocatable": "f",
		"extversion":     "1.0",
		"extconfig":      "",
		"extcondition":   "",
		"schema_name":    "pg_catalog",
	},
	"cube": {
		"oid":            "16402",
		"extname":        "cube",
		"extowner":       "10",
		"extnamespace":   "2200",
		"extrelocatable": "t",
		"extversion":     "1.2",
		"extconfig":      "",
		"extcondition":   "",
		"schema_name":    "public",
	},
}

// TestPostgresInstalledExtensionsArgvAndParse ports the pinned
// test_installed_extensions row shape and pins the exact pinned SQL —
// including its double space after "pg_extension a," — inside the COPY
// transport.
func TestPostgresInstalledExtensionsArgvAndParse(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedInstalledExtensionsCSV),
	})
	value, err := (installedExtensionsFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err != nil {
		t.Fatal(err)
	}
	installed, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("installed_extensions type = %T", value)
	}
	if !reflect.DeepEqual(installed, wantPinnedInstalledExtensions) {
		t.Fatalf("installed_extensions = %#v", installed)
	}
	command := runner.calls[0]
	want := append([]string(nil), wantVersionArgv[:13]...)
	want = append(want, "-v", "datestyle=ISO,MDY", "-c",
		"COPY ("+installedExtensionsQuery[:len(installedExtensionsQuery)-1]+") TO STDOUT WITH CSV HEADER")
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q", got)
	}
	if !strings.Contains(installedExtensionsQuery, "pg_extension a,  pg_namespace") {
		t.Fatalf("installed SQL lost the pinned double space: %q", installedExtensionsQuery)
	}
}

// TestPostgresInstalledExtensionsPinnedRow pins the exact pinned
// test_installed_extensions mock shape.
func TestPostgresInstalledExtensionsPinnedRow(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("extname,extversion\nfoo,1\n"),
	})
	value, err := (installedExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{"foo": {"extname": "foo", "extversion": "1"}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("installed_extensions = %#v, want %#v", value, want)
	}
}

// TestPostgresExtensionShortRowFilter pins the pinned column guard: rows
// whose zipped prefix lacks the name or version column are skipped instead
// of keyed or errored.
func TestPostgresExtensionShortRowFilter(t *testing.T) {
	// "foo" zips to {"name": "foo"} (no default_version) and "1.0" to
	// {"name": "1.0"}; only the full row survives.
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("name,default_version,installed_version,comment\nfoo\n1.0\nplpgsql,1.0,1.0,x\n"),
	})
	value, err := (availableExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"plpgsql": {"name": "plpgsql", "default_version": "1.0", "installed_version": "1.0", "comment": "x"},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("available_extensions = %#v, want %#v", value, want)
	}

	// The installed loop's guard behaves identically: a two-field row zips
	// to oid/extname and carries no extversion.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("oid,extname,extowner,extnamespace,extrelocatable,extversion,extconfig,extcondition,schema_name\nfoo\nplpgsql,10\n"),
	})
	value, err = (installedExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string]map[string]string{}) {
		t.Fatalf("installed_extensions = %#v, want empty catalog", value)
	}
}

// fullExtensionArgs is the ExistsArgs shape with every connection argument
// supplied, mirroring fullListArgs for the name-bearing functions.
func fullExtensionArgs(name string) *ExistsArgs {
	return &ExistsArgs{
		Name:          name,
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
	}
}

// TestPostgresGetExtensions ports the pinned get_available_extension /
// get_installed_extension contract: an exact-case hit returns the stored
// row and a miss returns None, with a single catalog query each.
func TestPostgresGetExtensions(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedAvailableExtensionsCSV),
	})
	value, err := (getAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedAvailableExtensions["cube"]) {
		t.Fatalf("get_available_extension(cube) = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "cube") {
		t.Fatalf("get_available_extension leaked the lookup name into argv: %q", joined)
	}

	// Misses and case mismatches are None, exactly like dict.get.
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedAvailableExtensionsCSV)})
	value, err = (getAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("missing"))
	if err != nil || value != nil {
		t.Fatalf("get_available_extension(missing) = %#v err = %v, want nil, nil", value, err)
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedAvailableExtensionsCSV)})
	value, err = (getAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("CUBE"))
	if err != nil || value != nil {
		t.Fatalf("get_available_extension(CUBE) = %#v err = %v, want nil (exact-case), nil", value, err)
	}

	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedInstalledExtensionsCSV)})
	value, err = (getInstalledExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("plpgsql"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedInstalledExtensions["plpgsql"]) {
		t.Fatalf("get_installed_extension(plpgsql) = %#v", value)
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedInstalledExtensionsCSV)})
	value, err = (getInstalledExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("PLPGSQL"))
	if err != nil || value != nil {
		t.Fatalf("get_installed_extension(PLPGSQL) = %#v err = %v, want nil (exact-case), nil", value, err)
	}
}

// TestPostgresIsExtensions pins the two membership predicates:
// is_available_extension lowercases both sides (the pinned
// name.lower() in [...] test) while is_installed_extension keeps
// bool(get_installed_extension(...)) exact-case truthiness.
func TestPostgresIsExtensions(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"cube", true},
		{"PLPGSQL", true},
		{"UnPacked", true},
		{"missing", false},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedAvailableExtensionsCSV),
		})
		value, err := (isAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs(tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("is_available_extension(%q) = %#v, want %v", tc.name, value, tc.want)
		}
		// The lookup never reaches SQL: the query argument stays the exact
		// fixed catalog query.
		args := runner.calls[0].Args
		if got := args[len(args)-1]; got != "COPY (select * from pg_available_extensions()) TO STDOUT WITH CSV HEADER" {
			t.Fatalf("is_available_extension(%q) SQL arg = %q, want the fixed catalog query", tc.name, got)
		}
	}

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"plpgsql", true},
		{"cube", true},
		{"PLPGSQL", false},
		{"missing", false},
	} {
		rt, _ := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedInstalledExtensionsCSV),
		})
		value, err := (isInstalledExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs(tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("is_installed_extension(%q) = %#v, want %v", tc.name, value, tc.want)
		}
	}
}

// pinnedLanguageListCSV is the get_test_list_language_csv fixture from the
// pinned test_postgres.py, verbatim.
const pinnedLanguageListCSV = "Name\ninternal\nc\nsql\nplpgsql\n"

// wantPinnedLanguageList is the pinned test_language_list expected
// dictionary: each Name maps to itself.
var wantPinnedLanguageList = map[string]string{
	"c":        "c",
	"internal": "internal",
	"plpgsql":  "plpgsql",
	"sql":      "sql",
}

// fullLanguageArgs supplies every language_list connection argument with
// the pinned test's testdb maintenance database.
func fullLanguageArgs() *LanguageListArgs {
	return &LanguageListArgs{
		MaintenanceDB: "testdb",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("foo"),
	}
}

// TestPostgresLanguageListArgvAndParse ports the pinned test_language_list:
// the pinned fixture CSV parses to the name→name dictionary, and the psql
// argv carries the pinned SELECT lanname AS "Name" FROM pg_language SQL
// inside the COPY-to-CSV transport with the pinned connection arguments.
func TestPostgresLanguageListArgvAndParse(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedLanguageListCSV),
	})
	value, err := (languageListFunc{}).Execute(context.Background(), rt, fullLanguageArgs())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedLanguageList) {
		t.Fatalf("language_list = %#v, want %#v", value, wantPinnedLanguageList)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "testdb",
		"-v", "datestyle=ISO,MDY", "-c",
		`COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Env, []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
	}) {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("unsafe command: %#v", command)
	}
	if command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe command bounds: %#v", command)
	}
	if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestPostgresLanguageListDefaults pins the no-connection argv: an empty
// maintenance_db keeps Salt's _psql_cmd "postgres" fallback — the pinned
// language_list(None) shape — with a clean environment.
func TestPostgresLanguageListDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedLanguageListCSV)})
	value, err := (languageListFunc{}).Execute(context.Background(), rt, &LanguageListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedLanguageList) {
		t.Fatalf("language_list = %#v", value)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-v", "datestyle=ISO,MDY", "-c",
		`COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER`,
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

// TestPostgresLanguageExists ports the pinned language_exists contract:
// `name in languages` is an exact-case membership against the name→name
// dictionary.
func TestPostgresLanguageExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"sql", true},
		{"plpgsql", true},
		{"c", true},
		{"SQL", false},
		{"missing", false},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedLanguageListCSV),
		})
		value, err := (languageExistsFunc{}).Execute(context.Background(), rt, &LanguageExistsArgs{
			Name:          tc.name,
			MaintenanceDB: "testdb",
		})
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("language_exists(%q) = %#v, want %v", tc.name, value, tc.want)
		}
		// The lookup never reaches SQL: the query argument stays the exact
		// fixed catalog query.
		args := runner.calls[0].Args
		if got := args[len(args)-1]; got != `COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER` {
			t.Fatalf("language_exists(%q) SQL arg = %q, want the fixed catalog query", tc.name, got)
		}
	}
}

// TestPostgresLanguageListMissingColumn pins the KeyError mapping when a
// row lacks the Name column.
func TestPostgresLanguageListMissingColumn(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Owner\npostgres\n")})
	_, err := (languageListFunc{}).Execute(context.Background(), rt, &LanguageListArgs{MaintenanceDB: "testdb"})
	if err == nil || !strings.Contains(err.Error(), `"Name"`) {
		t.Fatalf("short row err = %v, want missing Name column", err)
	}
}

// TestPostgresExtensionLanguageCompatibilityData pins Salt's nonzero-exit
// shape across all eight new functions: a failed query is not an
// exception; the list catalogs empty, the get_* views return None, and the
// predicates answer false.
func TestPostgresExtensionLanguageCompatibilityData(t *testing.T) {
	failed := process.CommandResult{
		ExitCode: 2,
		Stderr:   []byte("psql: error: connection refused"),
	}
	cases := []struct {
		name string
		run  func(rt *runtime.Runtime) (any, error)
		want any
	}{
		{"available_extensions", func(rt *runtime.Runtime) (any, error) {
			return (availableExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
		}, map[string]map[string]string{}},
		{"installed_extensions", func(rt *runtime.Runtime) (any, error) {
			return (installedExtensionsFunc{}).Execute(context.Background(), rt, &ListArgs{})
		}, map[string]map[string]string{}},
		{"get_available_extension", func(rt *runtime.Runtime) (any, error) {
			return (getAvailableExtensionFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "cube"})
		}, nil},
		{"get_installed_extension", func(rt *runtime.Runtime) (any, error) {
			return (getInstalledExtensionFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "cube"})
		}, nil},
		{"is_available_extension", func(rt *runtime.Runtime) (any, error) {
			return (isAvailableExtensionFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "cube"})
		}, false},
		{"is_installed_extension", func(rt *runtime.Runtime) (any, error) {
			return (isInstalledExtensionFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "cube"})
		}, false},
		{"language_list", func(rt *runtime.Runtime) (any, error) {
			return (languageListFunc{}).Execute(context.Background(), rt, &LanguageListArgs{MaintenanceDB: "testdb"})
		}, map[string]string{}},
		{"language_exists", func(rt *runtime.Runtime) (any, error) {
			return (languageExistsFunc{}).Execute(context.Background(), rt, &LanguageExistsArgs{Name: "sql", MaintenanceDB: "testdb"})
		}, false},
	}
	for _, tc := range cases {
		rt, _ := newPostgresRuntime(failed)
		value, err := tc.run(rt)
		if err != nil {
			t.Fatalf("%s nonzero exit must not error: %v", tc.name, err)
		}
		if !reflect.DeepEqual(value, tc.want) {
			t.Fatalf("%s nonzero exit = %#v, want %#v", tc.name, value, tc.want)
		}
	}
}

// TestPostgresExtensionLanguageGuards pins the shared failure modes across
// the eight new functions: pre-canceled context, runas rejection, redacted
// Runner errors, output-limit violations, psql-unavailable fail-closed,
// and the argument guards, each with zero Runner executions where the
// guard precedes the call.
func TestPostgresExtensionLanguageGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (availableExtensionsFunc{}).Execute(ctx, rt, fullListArgs()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled available_extensions err = %v", err)
	}
	if _, err := (languageListFunc{}).Execute(ctx, rt, fullLanguageArgs()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled language_list err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled runs executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	langArgs := fullLanguageArgs()
	langArgs.Runas = postgresString("postgres")
	if _, err := (languageListFunc{}).Execute(context.Background(), rt, langArgs); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas language_list err = %v", err)
	}
	extArgs := fullExtensionArgs("cube")
	extArgs.Runas = postgresString("postgres")
	if _, err := (isInstalledExtensionFunc{}).Execute(context.Background(), rt, extArgs); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas is_installed_extension err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas runs executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname test_maint: secret test_pass rejected"),
	})
	_, err := (installedExtensionsFunc{}).Execute(context.Background(), rt, fullListArgs())
	if err == nil || strings.Contains(err.Error(), "test_pass") {
		t.Fatalf("installed_extensions runner error = %v, want redacted", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("installed_extensions error lacks redaction placeholder: %v", err)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (languageListFunc{}).Execute(context.Background(), rt, fullLanguageArgs()); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated language_list err = %v, want ErrOutputLimit", err)
		}
		rt, _ = newPostgresRuntime(truncated)
		if _, err := (getAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated get_available_extension err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	for _, exec := range []struct {
		name string
		run  func() error
	}{
		{"available_extensions", func() error {
			_, err := (availableExtensionsFunc{}).Execute(context.Background(), rt, fullListArgs())
			return err
		}},
		{"installed_extensions", func() error {
			_, err := (installedExtensionsFunc{}).Execute(context.Background(), rt, fullListArgs())
			return err
		}},
		{"get_available_extension", func() error {
			_, err := (getAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube"))
			return err
		}},
		{"get_installed_extension", func() error {
			_, err := (getInstalledExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube"))
			return err
		}},
		{"is_available_extension", func() error {
			_, err := (isAvailableExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube"))
			return err
		}},
		{"is_installed_extension", func() error {
			_, err := (isInstalledExtensionFunc{}).Execute(context.Background(), rt, fullExtensionArgs("cube"))
			return err
		}},
		{"language_list", func() error {
			_, err := (languageListFunc{}).Execute(context.Background(), rt, fullLanguageArgs())
			return err
		}},
		{"language_exists", func() error {
			_, err := (languageExistsFunc{}).Execute(context.Background(), rt, &LanguageExistsArgs{Name: "sql", MaintenanceDB: "testdb"})
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

	// Wrong argument types are rejected like the pinned TypeError, and a
	// nil Runner fails closed.
	if _, err := (availableExtensionsFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("available_extensions must reject non-struct args")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (languageExistsFunc{}).Execute(context.Background(), rtEmpty, &LanguageExistsArgs{Name: "sql", MaintenanceDB: "testdb"}); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner language_exists err = %v", err)
	}
}

// TestPostgresExtensionLanguageRegistryKeys drives the new functions
// through the registry surface with CRLF-bearing catalog keys: the pinned
// CSV reader keeps the embedded CRLF byte-exact, the get_* views return
// the row dictionary, and no lookup name ever reaches argv.
func TestPostgresExtensionLanguageRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	availableCSV := "name,default_version,installed_version,comment\r\n" +
		"cube,1.2,,cube data\r\n" +
		"\"p\r\nlpgsql\",1.0,1.0,procedural\r\n"
	list, ok := reg.Get("postgres.available_extensions")
	if !ok {
		t.Fatal("postgres.available_extensions not registered")
	}
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(availableCSV)})
	value, err := list.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	extensions := value.(map[string]map[string]string)
	if _, has := extensions["p\r\nlpgsql"]; !has || extensions["p\r\nlpgsql"]["comment"] != "procedural" {
		t.Fatalf("available_extensions keys = %#v, want byte-exact embedded-CRLF key", extensions)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); !strings.Contains(joined, availableExtensionsQuery[:len(availableExtensionsQuery)-1]) {
		t.Fatalf("available_extensions argv lacks the fixed SQL")
	}

	get, ok := reg.Get("postgres.get_available_extension")
	if !ok {
		t.Fatal("postgres.get_available_extension not registered")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(availableCSV)})
	value, err = get.Execute(context.Background(), rt, &ExistsArgs{Name: "p\r\nlpgsql"})
	if err != nil {
		t.Fatal(err)
	}
	row, ok := value.(map[string]string)
	if !ok || row["default_version"] != "1.0" {
		t.Fatalf("get_available_extension(CRLF name) = %#v", value)
	}
	if joined := strings.Join(runner.calls[len(runner.calls)-1].Args, "\x00"); strings.Contains(joined, "p\r\nlpgsql") {
		t.Fatalf("get_available_extension leaked the lookup name into argv")
	}

	languageCSV := "Name\r\ninternal\r\n\"p\r\nlpgsql\"\r\nsql\n"
	langList, ok := reg.Get("postgres.language_list")
	if !ok {
		t.Fatal("postgres.language_list not registered")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(languageCSV)})
	value, err = langList.Execute(context.Background(), rt, &LanguageListArgs{MaintenanceDB: "testdb"})
	if err != nil {
		t.Fatal(err)
	}
	languages := value.(map[string]string)
	if _, has := languages["p\r\nlpgsql"]; !has || languages["p\r\nlpgsql"] != "p\r\nlpgsql" {
		t.Fatalf("language_list = %#v, want embedded-CRLF name→name entry", languages)
	}

	langExists, ok := reg.Get("postgres.language_exists")
	if !ok {
		t.Fatal("postgres.language_exists not registered")
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(languageCSV)})
	value, err = langExists.Execute(context.Background(), rt, &LanguageExistsArgs{Name: "p\r\nlpgsql", MaintenanceDB: "testdb"})
	if err != nil || value != true {
		t.Fatalf("language_exists(CRLF name) = %#v err = %v, want true", value, err)
	}
}

// ---------------------------------------------------------------------------
// R9.2e schema_list / schema_exists / schema_get — pinned
// salt/modules/postgres.py:2444-2599.

// pinnedSchemaListCSV is the get_test_list_schema_csv fixture from the
// pinned test_postgres.py, verbatim.
const pinnedSchemaListCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n" +
	"pg_toast,postgres,\"\"\n"

// wantPinnedSchemaList is the pinned test_schema_list expected dictionary:
// each schema name maps to exactly the owner and acl pair.
var wantPinnedSchemaList = map[string]map[string]string{
	"public": {
		"acl":   "{postgres=UC/postgres,=UC/postgres}",
		"owner": "postgres",
	},
	"pg_toast": {
		"acl":   "",
		"owner": "postgres",
	},
}

// fullSchemaListArgs supplies every schema_list connection argument with
// the pinned test_schema_list values.
func fullSchemaListArgs() *SchemaListArgs {
	return &SchemaListArgs{
		DBName:     "maint_db",
		User:       nil,
		DBUser:     postgresString("testuser"),
		DBHost:     postgresString("testhost"),
		DBPort:     postgresString("testport"),
		DBPassword: postgresString("foo"),
	}
}

// fullSchemaArgs supplies every schema_get/schema_exists argument with the
// pinned test_schema_get values.
func fullSchemaArgs(name string) *SchemaArgs {
	return &SchemaArgs{
		DBName:     "template1",
		Name:       name,
		DBUser:     postgresString("testuser"),
		DBHost:     postgresString("testhost"),
		DBPort:     postgresString("testport"),
		DBPassword: postgresString("foo"),
	}
}

// TestPostgresSchemaListArgvAndParse ports the pinned test_schema_list: the
// pinned fixture CSV parses to the owner/acl dictionary, and the psql argv
// carries the pinned pg_namespace × pg_roles SQL inside the COPY-to-CSV
// transport with the pinned schema-family connection arguments.
func TestPostgresSchemaListArgvAndParse(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedSchemaListCSV),
	})
	value, err := (schemaListFunc{}).Execute(context.Background(), rt, fullSchemaListArgs())
	if err != nil {
		t.Fatal(err)
	}
	schemas, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("schema_list type = %T", value)
	}
	if !reflect.DeepEqual(schemas, wantPinnedSchemaList) {
		t.Fatalf("schema_list = %#v, want %#v", schemas, wantPinnedSchemaList)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-v", "datestyle=ISO,MDY", "-c",
		`COPY (SELECT pg_namespace.nspname as "name",pg_namespace.nspacl as "acl", ` +
			`pg_roles.rolname as "owner" FROM pg_namespace LEFT JOIN ` +
			`pg_roles ON pg_roles.oid = pg_namespace.nspowner) TO STDOUT WITH CSV HEADER`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Env, []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
	}) {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("unsafe command: %#v", command)
	}
	if command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe command bounds: %#v", command)
	}
	if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestPostgresSchemaListDefaults pins the minimal argv: the required dbname
// positional reaches --dbname directly with a clean environment and no
// redaction.
func TestPostgresSchemaListDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedSchemaListCSV)})
	value, err := (schemaListFunc{}).Execute(context.Background(), rt, &SchemaListArgs{DBName: "testdb"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedSchemaList) {
		t.Fatalf("schema_list = %#v", value)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "testdb",
		"-v", "datestyle=ISO,MDY", "-c",
		`COPY (SELECT pg_namespace.nspname as "name",pg_namespace.nspacl as "acl", ` +
			`pg_roles.rolname as "owner" FROM pg_namespace LEFT JOIN ` +
			`pg_roles ON pg_roles.oid = pg_namespace.nspowner) TO STDOUT WITH CSV HEADER`,
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

// TestPostgresSchemaListMissingColumn pins the KeyError mapping when a row
// lacks the owner, acl, or name column, in the pinned iteration order.
func TestPostgresSchemaListMissingColumn(t *testing.T) {
	for _, tc := range []struct {
		csv  string
		want string
	}{
		{"name,owner\npublic,postgres\n", `"acl"`},
		{"name,acl\npublic,x\n", `"owner"`},
		{"owner,acl\npostgres,x\n", `"name"`},
	} {
		rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.csv)})
		_, err := (schemaListFunc{}).Execute(context.Background(), rt, &SchemaListArgs{DBName: "testdb"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("short row %q err = %v, want missing %s column", tc.csv, err, tc.want)
		}
	}
}

// TestPostgresSchemaGet ports the pinned test_schema_get and
// test_schema_get_again contract: an exact-case hit returns the owner/acl
// row and a miss returns None, with a single catalog query whose SQL never
// mentions the lookup name.
func TestPostgresSchemaGet(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(pinnedSchemaListCSV),
	})
	value, err := (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedSchemaList["public"]) {
		t.Fatalf("schema_get(public) = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "public") {
		t.Fatalf("schema_get leaked the lookup name into argv: %q", joined)
	}

	// A schema absent from the catalog is None, and so is a case
	// mismatch — the pinned .get is exact-case.
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedSchemaListCSV)})
	value, err = (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("absent"))
	if err != nil || value != nil {
		t.Fatalf("schema_get(absent) = %#v err = %v, want nil, nil", value, err)
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedSchemaListCSV)})
	value, err = (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("Public"))
	if err != nil || value != nil {
		t.Fatalf("schema_get(Public) = %#v err = %v, want nil (exact-case), nil", value, err)
	}
	// An empty-acl row is still a hit: the pinned pg_toast fixture row.
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pinnedSchemaListCSV)})
	value, err = (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("pg_toast"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string]string{"acl": "", "owner": "postgres"}) {
		t.Fatalf("schema_get(pg_toast) = %#v, want empty-acl row", value)
	}
}

// TestPostgresSchemaExists ports the pinned test_schema_exists contract:
// bool(schema_get(...)) is the exact-case row truthiness — both pinned
// fixture schemas exist, an empty-acl row still exists, and absent or
// case-mismatched names do not.
func TestPostgresSchemaExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"public", true},
		{"pg_toast", true},
		{"absent", false},
		{"PUBLIC", false},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(pinnedSchemaListCSV),
		})
		value, err := (schemaExistsFunc{}).Execute(context.Background(), rt, fullSchemaArgs(tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("schema_exists(%q) = %#v, want %v", tc.name, value, tc.want)
		}
		// The lookup never reaches SQL: the query argument stays the
		// exact fixed catalog query.
		args := runner.calls[0].Args
		if got := args[len(args)-1]; !strings.HasPrefix(got, "COPY (SELECT pg_namespace.nspname") {
			t.Fatalf("schema_exists(%q) SQL arg = %q, want the fixed catalog query", tc.name, got)
		}
		if strings.Contains(strings.Join(args, "\x00"), tc.name) {
			t.Fatalf("schema_exists(%q) leaked the lookup name into argv", tc.name)
		}
	}
}

// TestPostgresSchemaCompatibilityData pins Salt's nonzero-exit shape across
// the three schema functions: a failed query is not an exception; the list
// is empty and the views degrade to None and false.
func TestPostgresSchemaCompatibilityData(t *testing.T) {
	failed := process.CommandResult{
		ExitCode: 2,
		Stderr:   []byte("psql: error: connection refused"),
	}
	rt, _ := newPostgresRuntime(failed)
	value, err := (schemaListFunc{}).Execute(context.Background(), rt, &SchemaListArgs{DBName: "testdb"})
	if err != nil || !reflect.DeepEqual(value, map[string]map[string]string{}) {
		t.Fatalf("schema_list nonzero exit = %#v err = %v, want empty catalog", value, err)
	}
	rt, _ = newPostgresRuntime(failed)
	value, err = (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public"))
	if err != nil || value != nil {
		t.Fatalf("schema_get nonzero exit = %#v err = %v, want nil", value, err)
	}
	rt, _ = newPostgresRuntime(failed)
	value, err = (schemaExistsFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public"))
	if err != nil || value != false {
		t.Fatalf("schema_exists nonzero exit = %#v err = %v, want false", value, err)
	}
}

// TestPostgresSchemaGuards pins the shared failure modes across the three
// schema functions: pre-canceled context, the pinned system-user argument
// rejected as runas, redacted Runner errors, output-limit violations,
// psql-unavailable fail-closed, and the argument guards, each with zero
// Runner executions where the guard precedes the call.
func TestPostgresSchemaGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (schemaListFunc{}).Execute(ctx, rt, fullSchemaListArgs()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schema_list err = %v", err)
	}
	if _, err := (schemaGetFunc{}).Execute(ctx, rt, fullSchemaArgs("public")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schema_get err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled runs executed %d commands", len(runner.calls))
	}

	// The pinned user argument is the system user: like every runas
	// surface it is rejected before any Runner invocation.
	rt, runner = newPostgresRuntime()
	userArgs := fullSchemaListArgs()
	userArgs.User = postgresString("postgres")
	if _, err := (schemaListFunc{}).Execute(context.Background(), rt, userArgs); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user schema_list err = %v, want runas rejection", err)
	}
	existsArgs := fullSchemaArgs("public")
	existsArgs.User = postgresString("postgres")
	if _, err := (schemaExistsFunc{}).Execute(context.Background(), rt, existsArgs); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user schema_exists err = %v, want runas rejection", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas runs executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname maint_db: secret foo rejected"),
	})
	_, err := (schemaListFunc{}).Execute(context.Background(), rt, fullSchemaListArgs())
	if err == nil || strings.Contains(err.Error(), "foo") {
		t.Fatalf("schema_list runner error = %v, want redacted", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("schema_list error lacks redaction placeholder: %v", err)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated schema_get err = %v, want ErrOutputLimit", err)
		}
		rt, _ = newPostgresRuntime(truncated)
		if _, err := (schemaExistsFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated schema_exists err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	for _, exec := range []struct {
		name string
		run  func() error
	}{
		{"schema_list", func() error {
			_, err := (schemaListFunc{}).Execute(context.Background(), rt, fullSchemaListArgs())
			return err
		}},
		{"schema_get", func() error {
			_, err := (schemaGetFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public"))
			return err
		}},
		{"schema_exists", func() error {
			_, err := (schemaExistsFunc{}).Execute(context.Background(), rt, fullSchemaArgs("public"))
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

	// Wrong argument types are rejected like the pinned TypeError, and a
	// nil Runner fails closed.
	if _, err := (schemaListFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("schema_list must reject non-struct args")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (schemaExistsFunc{}).Execute(context.Background(), rtEmpty, fullSchemaArgs("public")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner schema_exists err = %v", err)
	}
}

// TestPostgresSchemaRegistryKeys drives the three schema functions through
// the registry ResolveArgs+Call surface with CRLF-bearing schema names: the
// pinned CSV reader keeps the embedded CRLF byte-exact, each invocation runs
// on its own Runner whose single recorded command is the exact fixed catalog
// argv, and no lookup name ever reaches argv. The guard block pins zero
// Runner executions for the required, malformed, runas, oversize, and
// canceled paths.
func TestPostgresSchemaRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	schemaCSV := "name,owner,acl\r\n" +
		"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\r\n" +
		"\"p\r\ng_toast\",postgres,\r\n"
	// wantSchemaArgv is the exact fixed argv every schema invocation runs:
	// the pinned never-prompt flags, the required dbname positional, and the
	// pinned pg_namespace × pg_roles SQL inside the COPY-to-CSV transport.
	wantSchemaArgv := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "testdb",
		"-v", "datestyle=ISO,MDY", "-c",
		`COPY (SELECT pg_namespace.nspname as "name",pg_namespace.nspacl as "acl", ` +
			`pg_roles.rolname as "owner" FROM pg_namespace LEFT JOIN ` +
			`pg_roles ON pg_roles.oid = pg_namespace.nspowner) TO STDOUT WITH CSV HEADER`,
	}
	// checkRunner asserts the runner's actual recorded commands: exactly one
	// execution with the exact fixed SQL argv and no lookup name in it.
	checkRunner := func(runner *postgresFakeRunner, lookup string) {
		t.Helper()
		if len(runner.calls) != 1 {
			t.Fatalf("runner calls = %d, want exactly 1", len(runner.calls))
		}
		command := runner.calls[0]
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, wantSchemaArgv) {
			t.Fatalf("argv = %q, want the exact fixed catalog argv %q", got, wantSchemaArgv)
		}
		if lookup != "" && strings.Contains(strings.Join(command.Args, "\x00"), lookup) {
			t.Fatalf("lookup name %q leaked into argv: %q", lookup, command.Args)
		}
	}

	// schema_list: ResolveArgs pins the prototype and Call with the exact
	// SchemaListArgs returns the CRLF-keyed catalog.
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(schemaCSV)})
	prototype, err := reg.ResolveArgs(rt, "postgres.schema_list")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prototype.(SchemaListArgs); !ok {
		t.Fatalf("schema_list prototype = %T, want SchemaListArgs", prototype)
	}
	value, err := reg.Call(context.Background(), rt, "postgres.schema_list", &SchemaListArgs{DBName: "testdb"})
	if err != nil {
		t.Fatal(err)
	}
	schemas, ok := value.(map[string]map[string]string)
	if !ok {
		t.Fatalf("schema_list type = %T", value)
	}
	if _, has := schemas["p\r\ng_toast"]; !has || schemas["p\r\ng_toast"]["owner"] != "postgres" {
		t.Fatalf("schema_list keys = %#v, want byte-exact embedded-CRLF key", schemas)
	}
	if len(schemas) != 2 {
		t.Fatalf("schema_list = %#v, want both pinned rows", schemas)
	}
	checkRunner(runner, "")

	// schema_get: the exact SchemaArgs carry the CRLF name, which stays
	// client-side — the row dictionary comes back and argv stays fixed.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(schemaCSV)})
	prototype, err = reg.ResolveArgs(rt, "postgres.schema_get")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prototype.(SchemaArgs); !ok {
		t.Fatalf("schema_get prototype = %T, want SchemaArgs", prototype)
	}
	value, err = reg.Call(context.Background(), rt, "postgres.schema_get", &SchemaArgs{DBName: "testdb", Name: "p\r\ng_toast"})
	if err != nil {
		t.Fatal(err)
	}
	row, ok := value.(map[string]string)
	if !ok || row["owner"] != "postgres" || row["acl"] != "" {
		t.Fatalf("schema_get(CRLF name) = %#v", value)
	}
	checkRunner(runner, "p\r\ng_toast")

	// schema_exists: bool(schema_get(...)) over the same exact SchemaArgs.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(schemaCSV)})
	prototype, err = reg.ResolveArgs(rt, "postgres.schema_exists")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prototype.(SchemaArgs); !ok {
		t.Fatalf("schema_exists prototype = %T, want SchemaArgs", prototype)
	}
	value, err = reg.Call(context.Background(), rt, "postgres.schema_exists", &SchemaArgs{DBName: "testdb", Name: "p\r\ng_toast"})
	if err != nil || value != true {
		t.Fatalf("schema_exists(CRLF name) = %#v err = %v, want true", value, err)
	}
	checkRunner(runner, "p\r\ng_toast")

	// Required arguments are rejected before any Runner exists: the exact
	// argument structs fail required validation with dbname or name unset.
	if err := config.ValidateRequired(&SchemaListArgs{}); err == nil {
		t.Fatal("schema_list must require dbname")
	}
	if err := config.ValidateRequired(&SchemaArgs{Name: "public"}); err == nil {
		t.Fatal("schema_get must require dbname")
	}
	if err := config.ValidateRequired(&SchemaArgs{DBName: "testdb"}); err == nil {
		t.Fatal("schema_exists must require name")
	}

	// Malformed arguments are rejected at the registry boundary with zero
	// Runner executions: a non-struct payload and the cross-family pointer.
	rt, runner = newPostgresRuntime()
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_get", "bogus"); err == nil {
		t.Fatal("schema_get must reject non-struct args")
	}
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_exists", &SchemaListArgs{DBName: "testdb"}); err == nil {
		t.Fatal("schema_exists must reject schema_list args")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("malformed runs executed %d commands", len(runner.calls))
	}

	// The pinned system-user argument stays a rejected runas, an oversized
	// dbname stays under the command-input ceiling, and a canceled context
	// aborts — all before any Runner invocation.
	rt, runner = newPostgresRuntime()
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_list",
		&SchemaListArgs{DBName: "testdb", User: postgresString("postgres")}); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user schema_list err = %v, want runas rejection", err)
	}
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_get",
		&SchemaArgs{DBName: "testdb", Name: "public", User: postgresString("postgres")}); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user schema_get err = %v, want runas rejection", err)
	}
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_exists",
		&SchemaArgs{DBName: "testdb", Name: "public", User: postgresString("postgres")}); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user schema_exists err = %v, want runas rejection", err)
	}
	oversize := strings.Repeat("d", runtime.MaxCommandInputBytes)
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_list",
		&SchemaListArgs{DBName: oversize}); !errors.Is(err, runtime.ErrCommandInputLimit) {
		t.Fatalf("oversize schema_list err = %v, want ErrCommandInputLimit", err)
	}
	if _, err := reg.Call(context.Background(), rt, "postgres.schema_get",
		&SchemaArgs{DBName: oversize, Name: "public"}); !errors.Is(err, runtime.ErrCommandInputLimit) {
		t.Fatalf("oversize schema_get err = %v, want ErrCommandInputLimit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reg.Call(ctx, rt, "postgres.schema_list", &SchemaListArgs{DBName: "testdb"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schema_list err = %v", err)
	}
	if _, err := reg.Call(ctx, rt, "postgres.schema_exists", &SchemaArgs{DBName: "testdb", Name: "public"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schema_exists err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("guarded runs executed %d commands", len(runner.calls))
	}
}

// ---------------------------------------------------------------------------
// R9.2f — role_get / user_exists / has_privileges
// (salt/modules/postgres.py:1104-1170, 2891-3123, 3184-3235, 3574-3711).

// roleUsersCSV renders a two-role pg_roles COPY CSV in the pinned
// test_user_list column shape (9.1 replication column included).
const roleUsersCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_user,t,t,t,t,t,t,,-1,,2017-08-16 08:57:46,
other_user,f,f,f,f,f,f,,10,,,
`

func fullRoleGetArgs(name string) *RoleGetArgs {
	return &RoleGetArgs{
		Name:          name,
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
	}
}

// TestPostgresRoleGet ports the pinned role_get shape: the shared user_list
// catalog runs first, the exact-case .get(name, None) returns the typed
// row or None, Salt's False catalog (unanswered version probe) maps to
// None through the pinned AttributeError branch, and return_password adds
// the password column and joins.
func TestPostgresRoleGet(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
	)
	value, err := (roleGetFunc{}).Execute(context.Background(), rt, fullRoleGetArgs("test_user"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedUserList) {
		t.Fatalf("role_get(test_user) = %#v, want the pinned user row %#v", value, wantPinnedUserList)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (version probe + role query)", len(runner.calls))
	}
	roleQuery := runner.calls[1].Args[len(runner.calls[1].Args)-1]
	if !strings.HasPrefix(roleQuery, "COPY (SELECT pg_roles.rolname") {
		t.Fatalf("role query = %q, want the fixed user_list COPY query", roleQuery)
	}
	// The lookup name never reaches SQL: with the connection user unset the
	// argv never contains the looked-up role.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
	)
	args := fullRoleGetArgs("other_user")
	args.User = nil
	if _, err := (roleGetFunc{}).Execute(context.Background(), rt, args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.calls[1].Args, "\x00"), "other_user") {
		t.Fatal("role_get leaked the lookup name into the role query")
	}

	// The pinned .get(name, None): a miss and a case mismatch are None.
	for _, name := range []string{"absent_user", "Test_User"} {
		rt, _ = newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
			process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
		)
		value, err = (roleGetFunc{}).Execute(context.Background(), rt, fullRoleGetArgs(name))
		if err != nil || value != nil {
			t.Fatalf("role_get(%q) = %#v err = %v, want nil, nil", name, value, err)
		}
	}

	// The pinned AttributeError branch: user_list's False catalog maps to
	// None after exactly one psql call.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("")})
	value, err = (roleGetFunc{}).Execute(context.Background(), rt, fullRoleGetArgs("test_user"))
	if err != nil || value != nil {
		t.Fatalf("role_get unanswered version = %#v err = %v, want nil, nil", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unanswered version executed %d commands, want 1", len(runner.calls))
	}

	// return_password passes through: the password column and joins appear.
	passwordCSV := `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables,password
test_user,f,t,t,t,f,t,,10,"{admins}",,,"md5abcdef"
`
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("15.7\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(passwordCSV)},
	)
	args = fullRoleGetArgs("test_user")
	args.ReturnPassword = true
	value, err = (roleGetFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := value.(map[string]any)
	if !ok || row["password"] != "md5abcdef" {
		t.Fatalf("role_get return_password = %#v, want the password column", value)
	}
	if joined := strings.Join(runner.calls[1].Args, "\x00"); !strings.Contains(joined, "pg_authid") || !strings.Contains(joined, "pg_shadow") {
		t.Fatalf("return_password query lacks the password joins: %q", joined)
	}
}

// TestPostgresUserExists ports the pinned user_exists: bool(role_get(...))
// with return_password pinned False — present roles are true, misses and
// the unanswered-version catalog are false, never errors.
func TestPostgresUserExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"test_user", true},
		{"other_user", true},
		{"absent_user", false},
		{"TEST_USER", false},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
			process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
		)
		value, err := (userExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: tc.name})
		if err != nil {
			t.Fatal(err)
		}
		if value != tc.want {
			t.Fatalf("user_exists(%q) = %#v, want %v", tc.name, value, tc.want)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("user_exists(%q) calls = %d, want 2", tc.name, len(runner.calls))
		}
	}

	// The False catalog is bool(None): false after one call.
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("")})
	value, err := (userExistsFunc{}).Execute(context.Background(), rt, &ExistsArgs{Name: "test_user"})
	if err != nil || value != false {
		t.Fatalf("user_exists unanswered = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unanswered user_exists executed %d commands", len(runner.calls))
	}
}

// ownerTableCSV renders the fixed owner catalog for tables: schemaname and
// tablename key columns plus the pinned tableowner AS name value. awl is
// owned by postgres so the table flows continue to the privilege query.
const ownerTableCSV = `schemaname,tablename,name
public,awl,postgres
public,other_table,postgres
`

// privTableCSV renders the fixed table privilege catalog with the pinned
// get_test_privileges_list_table_csv ACL string verbatim as the awl row.
const privTableCSV = `nspname,relname,relkind,name
public,other_table,r,
public,awl,r,"{baruwatest=arwdDxtm/baruwatest,bayestest=arwd/baruwatest,baruwa=a*r*w*d*D*x*t*m*/baruwatest}"
`

// privGroupCSV renders the fixed group membership catalog keyed by the
// group role's member_of column with the pinned admin_option values.
const privGroupCSV = `member_of,rolname,admin_option
admin,baruwa,f
admin,baruwatest2,t
admin,baruwatest,f
other_group,baruwa,t
`

func fullHasPrivilegesArgs(name, objectName, objectType, privileges string) *HasPrivilegesArgs {
	return &HasPrivilegesArgs{
		Name:          name,
		ObjectName:    objectName,
		ObjectType:    objectType,
		Privileges:    privileges,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

// TestPostgresHasPrivilegesTableArgv pins the exact two-call transport:
// the owner catalog query first, the privilege catalog query second, both
// fixed COPY-wrapped SQL with no caller string inside.
func TestPostgresHasPrivilegesTableArgv(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	args := fullHasPrivilegesArgs("bayestest", "awl", "table", "SELECT,INSERT")
	args.Prepend = postgresString("testschema")
	if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (owner + privileges)", len(runner.calls))
	}
	for i, want := range []string{
		`COPY (SELECT schemaname, tablename, tableowner AS name FROM pg_tables) TO STDOUT WITH CSV HEADER`,
		`COPY (SELECT nspname, relname, relkind, relacl AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE relkind in ('r', 'v') ORDER BY relname) TO STDOUT WITH CSV HEADER`,
	} {
		all := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if got := all[len(all)-1]; got != want {
			t.Fatalf("call %d SQL = %q, want %q", i, got, want)
		}
		if !strings.HasPrefix(all[0], "psql") || all[1] != "--no-align" {
			t.Fatalf("call %d argv head = %q", i, all)
		}
	}
	// Neither the role name, the object name, nor the schema prefix ever
	// reaches SQL.
	for i, call := range runner.calls {
		if joined := strings.Join(call.Args, "\x00"); strings.Contains(joined, "awl") ||
			strings.Contains(joined, "bayestest") || strings.Contains(joined, "testschema") {
			t.Fatalf("call %d leaked a lookup string into SQL: %q", i, joined)
		}
	}
	// The connection tuple is transported exactly like the pinned
	// psql_query call (runas rejected, password out of band).
	command := runner.calls[0]
	if command.Shell || len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=testpassword" {
		t.Fatalf("unsafe owner command: %#v", command)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
}

// TestPostgresHasPrivilegesTableSemantics ports the pinned
// test_has_privileges_on_table outcomes verbatim against the pinned ACL
// fixture, plus the owner shortcut and the absent-role false.
func TestPostgresHasPrivilegesTableSemantics(t *testing.T) {
	cases := []struct {
		label        string
		name         string
		privileges   string
		grantOption  bool
		ownerIsNamed bool
		want         any
	}{
		{"baruwa select insert grant", "baruwa", "SELECT,INSERT", true, false, true},
		{"baruwa all grant", "baruwa", "ALL", true, false, true},
		{"baruwa all no grant", "baruwa", "ALL", false, false, true},
		{"bayestest subset miss", "bayestest", "SELECT,INSERT,TRUNCATE", false, false, false},
		{"bayestest subset hit", "bayestest", "SELECT,INSERT", false, false, true},
		{"absent role", "tony", "SELECT", false, false, false},
		{"owner shortcut", "baruwa", "SELECT", false, true, true},
		{"lowercase privileges upper", "bayestest", "select,insert", false, false, true},
	}
	for _, tc := range cases {
		ownerCSV := ownerTableCSV
		if tc.ownerIsNamed {
			// awl owned by baruwa: the owner shortcut returns true after
			// the owner query alone.
			ownerCSV = "schemaname,tablename,name\npublic,awl,baruwa\n"
		}
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(ownerCSV)},
			{ExitCode: 0, Stdout: []byte(privTableCSV)},
		}
		rt, runner := newPostgresRuntime(results...)
		args := fullHasPrivilegesArgs(tc.name, "awl", "table", tc.privileges)
		args.GrantOption = tc.grantOption
		value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != tc.want {
			t.Fatalf("%s = %#v, want %#v", tc.label, value, tc.want)
		}
		wantCalls := 2
		if tc.ownerIsNamed {
			wantCalls = 1
		}
		if len(runner.calls) != wantCalls {
			t.Fatalf("%s calls = %d, want %d", tc.label, len(runner.calls), wantCalls)
		}
	}
}

// TestPostgresHasPrivilegesGroup ports the pinned test_has_privileges_on_group
// outcomes: membership is true, the grant-option check is the member's
// admin_option boolean, an absent role is false, and the group flow skips
// the owner query entirely (one call).
func TestPostgresHasPrivilegesGroup(t *testing.T) {
	for _, tc := range []struct {
		label       string
		name        string
		grantOption bool
		want        bool
	}{
		{"member", "baruwa", false, true},
		{"member admin check", "baruwa", true, false},
		{"member admin true", "baruwatest2", true, true},
		{"non member", "tony", false, false},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
		)
		args := fullHasPrivilegesArgs(tc.name, "admin", "group", "")
		args.GrantOption = tc.grantOption
		value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != tc.want {
			t.Fatalf("%s = %#v, want %v", tc.label, value, tc.want)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s calls = %d, want 1 (no owner query for groups)", tc.label, len(runner.calls))
		}
		got := runner.calls[0].Args[len(runner.calls[0].Args)-1]
		if !strings.HasPrefix(got, "COPY (SELECT (SELECT rolname FROM pg_catalog.pg_roles rr WHERE rr.oid = m.roleid) AS member_of, rolname, admin_option") {
			t.Fatalf("%s group SQL = %q", tc.label, got)
		}
	}

	// The group name never reaches SQL: a distinctive name (unlike the
	// pinned "admin", which the admin_option column name contains) is
	// matched client-side only.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasPrivilegesArgs("baruwa", "grp_leak_check", "group", ""))
	if err != nil || value != false {
		t.Fatalf("group leak check = %#v err = %v, want false", value, err)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "grp_leak_check") {
		t.Fatalf("group query leaked the group name into SQL: %q", joined)
	}
}

// TestPostgresHasPrivilegesFunction ports the pinned
// test_has_privileges_with_function outcome: baruwa's X* grant satisfies
// the EXECUTE grant-option check, and the owner query is the fixed
// function-owner catalog with the pinned ORDER BY proname, proargtypes.
func TestPostgresHasPrivilegesFunction(t *testing.T) {
	ownerCSV := `nspname,regprocedure,name
public,other,postgres
public,awl,postgres
`
	privCSV := `nspname,regprocedure,name
public,other,"{=X/postgres}"
public,awl,"{baruwatest=X/baruwatest,bayestest=r/baruwatest,baruwa=X*/baruwatest}"
`
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privCSV)},
	)
	args := fullHasPrivilegesArgs("baruwa", "awl", "function", "EXECUTE")
	args.GrantOption = true
	value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("has_privileges function = %#v, want true", value)
	}
	want := `COPY (SELECT nspname, p.oid::regprocedure::text AS regprocedure, rolname AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace JOIN pg_catalog.pg_roles r ON p.proowner = r.oid ORDER BY proname, proargtypes) TO STDOUT WITH CSV HEADER`
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != want {
		t.Fatalf("owner SQL = %q, want %q", got, want)
	}
	if strings.Contains(strings.Join(runner.calls[1].Args, "\x00"), "awl") {
		t.Fatal("function privileges query leaked the signature into SQL")
	}
}

// TestPostgresHasPrivilegesObjectTypes sweeps the remaining object types
// through their fixed owner and privilege catalogs: the client-side
// equality must select the pinned single row per catalog key.
func TestPostgresHasPrivilegesObjectTypes(t *testing.T) {
	cases := []struct {
		objectType string
		ownerCSV   string
		privCSV    string
		privileges string
		want       any
	}{
		{
			"sequence",
			"nspname,relname,name\npublic,awl_seq,postgres\n",
			`nspname,relname,relkind,name` + "\n" +
				`public,awl_seq,S,"{baruwa=rwU*/postgres}"` + "\n",
			"SELECT,UPDATE,USAGE",
			true,
		},
		{
			"schema",
			"nspname,name\npublic,postgres\n",
			`nspname,name` + "\n" +
				`public,"{postgres=UC/postgres,baruwa=U/postgres}"` + "\n",
			"USAGE",
			true,
		},
		{
			"tablespace",
			"spcname,name\npg_default,postgres\n",
			`spcname,name` + "\n" +
				`pg_default,"{postgres=C/postgres,baruwa=C/postgres}"` + "\n",
			"CREATE",
			true,
		},
		{
			"language",
			"lanname,name\nplpgsql,postgres\n",
			`lanname,name` + "\n" +
				`plpgsql,"{baruwa=U/postgres}"` + "\n",
			"USAGE",
			true,
		},
		{
			"database",
			"datname,name\ntest_db,postgres\n",
			`datname,name` + "\n" +
				`test_db,"{postgres=CTc/postgres,baruwa=c/postgres}"` + "\n",
			"CONNECT",
			true,
		},
	}
	for _, tc := range cases {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.privCSV)},
		)
		objectName := map[string]string{
			"sequence": "awl_seq", "schema": "public",
			"tablespace": "pg_default", "language": "plpgsql", "database": "test_db",
		}[tc.objectType]
		args := fullHasPrivilegesArgs("baruwa", objectName, tc.objectType, tc.privileges)
		value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.objectType, err)
		}
		if value != tc.want {
			t.Fatalf("%s = %#v, want %#v", tc.objectType, value, tc.want)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %d, want 2", tc.objectType, len(runner.calls))
		}
	}
}

// TestPostgresHasPrivilegesValidation pins the pinned validation head:
// every rejected input fails before any Runner invocation.
func TestPostgresHasPrivilegesValidation(t *testing.T) {
	cases := []struct {
		label      string
		objectType string
		privileges string
	}{
		{"unknown object type", "bogus", "SELECT"},
		{"empty object type", "", "SELECT"},
		{"invalid privilege", "table", "SELECT,BOGUS"},
		{"missing privileges", "table", ""},
		{"privileges for group", "group", "SELECT"},
	}
	for _, tc := range cases {
		rt, runner := newPostgresRuntime()
		args := fullHasPrivilegesArgs("baruwa", "awl", tc.objectType, tc.privileges)
		_, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want errPostgresInvalidArgument", tc.label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands before validation", tc.label, len(runner.calls))
		}
	}

	// The object type is lowercased exactly like the pinned _mod_priv_opts,
	// and the split tolerates single spaces around the comma.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	args := fullHasPrivilegesArgs("bayestest", "awl", "TABLE", "SELECT , INSERT")
	value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true {
		t.Fatalf("TABLE case/spaces = %#v err = %v, want true", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("TABLE case calls = %d, want 2", len(runner.calls))
	}
}

// TestPostgresHasPrivilegesCompatibilityData pins Salt's nonzero-exit
// shape: both catalog queries return the empty list, so the owner is None
// and every membership is false — data, not an error.
func TestPostgresHasPrivilegesCompatibilityData(t *testing.T) {
	failed := process.CommandResult{ExitCode: 2, Stderr: []byte("psql: error: connection refused")}
	rt, _ := newPostgresRuntime(failed)
	value, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT"))
	if err != nil || value != false {
		t.Fatalf("nonzero exit = %#v err = %v, want false, nil", value, err)
	}
	rt, _ = newPostgresRuntime(failed)
	value, err = (hasPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasPrivilegesArgs("baruwa", "admin", "group", ""))
	if err != nil || value != false {
		t.Fatalf("group nonzero exit = %#v err = %v, want false, nil", value, err)
	}
}

// TestPostgresHasPrivilegesGuards pins the shared failure modes: canceled
// context, runas rejection, redacted Runner errors, output limits,
// psql-unavailable fail-closed, and the argument guards, each with zero
// Runner executions where the guard precedes the call.
func TestPostgresHasPrivilegesGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (hasPrivilegesFunc{}).Execute(ctx, rt, fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	args := fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT")
	args.Runas = postgresString("postgres")
	if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v, want errPostgresRunas", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
	})
	_, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt, fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT"))
	if err == nil || strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("runner error = %v, want redacted", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt,
			fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql-unavailable err = %v, want errPostgresPsqlUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("has_privileges must reject non-struct args")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (hasPrivilegesFunc{}).Execute(context.Background(), rtEmpty,
		fullHasPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}

// wantPinnedTableACL is the pinned test_privileges_list_table expected
// dictionary: the exact privilege-to-grant-option maps per grantee.
var wantPinnedTableACL = map[string]map[string]bool{
	"bayestest": {
		"INSERT": false,
		"UPDATE": false,
		"SELECT": false,
		"DELETE": false,
	},
	"baruwa": {
		"INSERT":     true,
		"TRUNCATE":   true,
		"UPDATE":     true,
		"TRIGGER":    true,
		"REFERENCES": true,
		"SELECT":     true,
		"DELETE":     true,
		"MAINTAIN":   true,
	},
	"baruwatest": {
		"INSERT":     false,
		"TRUNCATE":   false,
		"UPDATE":     false,
		"TRIGGER":    false,
		"REFERENCES": false,
		"SELECT":     false,
		"DELETE":     false,
		"MAINTAIN":   false,
	},
}

// TestPostgresACLParseVectors pins the pinned ACL decode ladder with the
// pinned table ACL fixture, the public grantee, grant stars, the leading
// GRANT star, and the ValueError shapes.
func TestPostgresACLParseVectors(t *testing.T) {
	pinned := `{baruwatest=arwdDxtm/baruwatest,bayestest=arwd/baruwatest,baruwa=a*r*w*d*D*x*t*m*/baruwatest}`
	grants, err := parseACLGrants(pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grants, wantPinnedTableACL) {
		t.Fatalf("pinned table ACL = %#v, want %#v", grants, wantPinnedTableACL)
	}

	grants, err = parseACLGrants("{=c/postgres}")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grants, map[string]map[string]bool{"public": {"CONNECT": false}}) {
		t.Fatalf("public grantee = %#v", grants)
	}

	grants, err = parseACLGrants("{user=r*w/postgres}")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grants, map[string]map[string]bool{"user": {"SELECT": true, "UPDATE": false}}) {
		t.Fatalf("grant star = %#v", grants)
	}

	// A leading "*" stores the mapped GRANT name exactly like the pinned
	// first-branch lookup.
	grants, err = parseACLGrants("{user=*/postgres}")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grants, map[string]map[string]bool{"user": {"GRANT": false}}) {
		t.Fatalf("leading star = %#v", grants)
	}

	for _, acl := range []string{
		"",                 // NULL acl: strip yields "" whose only part lacks "/"
		"{a=b}",            // no grantor
		"{a=b/c/d}",        // two grantors
		"{ab/postgres}",    // no privilege separator
		"{a=b=c/postgres}", // two separators
		"{a=q/postgres}",   // unknown privilege character
	} {
		if _, err := parseACLGrants(acl); !errors.Is(err, errPostgresInvalidACL) {
			t.Fatalf("acl %q err = %v, want errPostgresInvalidACL", acl, err)
		}
	}
}

// TestPostgresRoleRegistryKeys drives the three R9.2f functions through
// the registry Call path, proving the canonical registrations resolve and
// execute with the shared transport.
func TestPostgresRoleRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, _ := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
	)
	value, err := reg.Call(context.Background(), rt, "postgres.role_get", &RoleGetArgs{Name: "test_user"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, wantPinnedUserList) {
		t.Fatalf("registry role_get = %#v", value)
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(roleUsersCSV)},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.user_exists", &ExistsArgs{Name: "test_user"})
	if err != nil || value != true {
		t.Fatalf("registry user_exists = %#v err = %v", value, err)
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.has_privileges",
		&HasPrivilegesArgs{Name: "baruwa", ObjectName: "awl", ObjectType: "table", Privileges: "ALL"})
	if err != nil || value != true {
		t.Fatalf("registry has_privileges = %#v err = %v", value, err)
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.privileges_list",
		&PrivilegesListArgs{Name: "awl", ObjectType: "table"})
	if err != nil {
		t.Fatal(err)
	}
	listed, ok := value.(map[string]any)
	if !ok || len(listed) != 3 {
		t.Fatalf("registry privileges_list = %#v, want the pinned three-role dictionary", value)
	}
	if !reflect.DeepEqual(listed["baruwa"], wantPinnedTableACL["baruwa"]) {
		t.Fatalf("registry privileges_list baruwa = %#v", listed["baruwa"])
	}

	// The slice additions are the only new surface: the generic query
	// transport and the write paths stay unregistered.
	if _, err := reg.Call(context.Background(), rt, "postgres.privileges_grant", &ExistsArgs{Name: "awl"}); err == nil {
		t.Fatal("postgres.privileges_grant must stay unregistered")
	}
}

// ---------------------------------------------------------------------------
// privileges_list — salt/modules/postgres.py:3335-3432 @ pinned revision.

func fullPrivilegesListArgs(name, objectType string) *PrivilegesListArgs {
	return &PrivilegesListArgs{
		Name:          name,
		ObjectType:    objectType,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

// TestPostgresPrivilegesListTableArgv pins the exact one-call transport of
// the public listing: the fixed COPY-wrapped table privilege catalog with
// the pinned relkind filter and ordering, the connection tuple transported
// exactly like the pinned psql_query call, and neither the object name nor
// the schema prefix ever reaching SQL.
func TestPostgresPrivilegesListTableArgv(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	args := fullPrivilegesListArgs("awl", "table")
	args.Prepend = postgresString("testschema")
	value, err := (privilegesListFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("privileges_list = %#v, want a dictionary", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	want := `COPY (SELECT nspname, relname, relkind, relacl AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE relkind in ('r', 'v') ORDER BY relname) TO STDOUT WITH CSV HEADER`
	all := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	if got := all[len(all)-1]; got != want {
		t.Fatalf("SQL = %q, want %q", got, want)
	}
	if !strings.HasPrefix(all[0], "psql") || all[1] != "--no-align" {
		t.Fatalf("argv head = %q", all)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "awl") ||
		strings.Contains(joined, "testschema") {
		t.Fatalf("query leaked a lookup string into SQL: %q", joined)
	}
	command := runner.calls[0]
	if command.Shell || len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
}

// TestPostgresPrivilegesListTable ports the pinned test_privileges_list_table
// outcome verbatim: the pinned table ACL fixture decodes to the pinned
// three-role grant-option dictionary, other rows (and the NULL-acl row) are
// filtered client-side, and the empty prepend default stays "public".
func TestPostgresPrivilegesListTable(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	value, err := (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("awl", "table"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{}
	for role, perms := range wantPinnedTableACL {
		want[role] = perms
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("privileges_list(table) = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
}

// TestPostgresPrivilegesListGroup ports the pinned test_privileges_list_group
// outcome verbatim: every member of the named group maps to its admin_option
// boolean, and members of other groups are filtered client-side.
func TestPostgresPrivilegesListGroup(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	value, err := (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("admin", "group"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"baruwa": false, "baruwatest": false, "baruwatest2": true}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("privileges_list(group) = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	wantSQL := `COPY (SELECT (SELECT rolname FROM pg_catalog.pg_roles rr WHERE rr.oid = m.roleid) AS member_of, rolname, admin_option FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON m.member=r.oid ORDER BY rolname) TO STDOUT WITH CSV HEADER`
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != wantSQL {
		t.Fatalf("group SQL = %q, want %q", got, wantSQL)
	}

	// The group name never reaches SQL: a distinctive name (unlike the
	// pinned "admin", which the admin_option column name contains) is
	// matched client-side only.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	value, err = (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("grp_leak_check", "group"))
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("group leak check = %#v err = %v, want {}", value, err)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "grp_leak_check") {
		t.Fatalf("group query leaked the group name into SQL: %q", joined)
	}
}

// TestPostgresPrivilegesListObjectTypes sweeps every remaining object type
// through its fixed privilege catalog, asserting the exact SQL, the
// client-side key match, and the grantee→privilege bool-map shape.
func TestPostgresPrivilegesListObjectTypes(t *testing.T) {
	cases := []struct {
		objectType string
		objectName string
		csv        string
		query      string
		want       map[string]any
	}{
		{
			"sequence", "awl_seq",
			"nspname,relname,relkind,name\n" +
				"public,awl_seq,S,\"{baruwa=rwU*/postgres}\"\n" +
				"public,other_seq,S,\"{other=r/postgres}\"\n",
			`SELECT nspname, relname, relkind, relacl AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE relkind = 'S' ORDER BY relname`,
			map[string]any{"baruwa": map[string]bool{"SELECT": false, "UPDATE": false, "USAGE": true}},
		},
		{
			"schema", "public",
			`nspname,name` + "\n" +
				`public,"{postgres=UC/postgres,=U/postgres}"` + "\n",
			`SELECT nspname, nspacl AS name FROM pg_catalog.pg_namespace ORDER BY nspname`,
			map[string]any{
				"postgres": map[string]bool{"USAGE": false, "CREATE": false},
				"public":   map[string]bool{"USAGE": false},
			},
		},
		{
			"tablespace", "pg_default",
			`spcname,name` + "\n" +
				`pg_default,"{postgres=C*/postgres,baruwa=C/postgres}"` + "\n",
			`SELECT spcname, spcacl AS name FROM pg_catalog.pg_tablespace ORDER BY spcname`,
			map[string]any{
				"postgres": map[string]bool{"CREATE": true},
				"baruwa":   map[string]bool{"CREATE": false},
			},
		},
		{
			"language", "plpgsql",
			`lanname,name` + "\n" +
				`plpgsql,"{=U/postgres,baruwa=U*/postgres}"` + "\n",
			`SELECT lanname, lanacl AS name FROM pg_catalog.pg_language ORDER BY lanname`,
			map[string]any{
				"public": map[string]bool{"USAGE": false},
				"baruwa": map[string]bool{"USAGE": true},
			},
		},
		{
			"database", "test_db",
			`datname,name` + "\n" +
				`test_db,"{=c/postgres,baruwa=C*T*c*/postgres}"` + "\n",
			`SELECT datname, datacl AS name FROM pg_catalog.pg_database ORDER BY datname`,
			map[string]any{
				"public": map[string]bool{"CONNECT": false},
				"baruwa": map[string]bool{"CREATE": true, "TEMPORARY": true, "CONNECT": true},
			},
		},
		{
			"function", "awl",
			`nspname,regprocedure,name` + "\n" +
				`public,other,"{=X/postgres}"` + "\n" +
				`public,awl,"{baruwatest=X/baruwatest,bayestest=r/baruwatest,baruwa=X*/baruwatest}"` + "\n",
			`SELECT nspname, p.oid::regprocedure::text AS regprocedure, proacl AS name FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace ORDER BY proname, proargtypes`,
			map[string]any{
				"baruwatest": map[string]bool{"EXECUTE": false},
				"bayestest":  map[string]bool{"SELECT": false},
				"baruwa":     map[string]bool{"EXECUTE": true},
			},
		},
	}
	for _, tc := range cases {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.csv)},
		)
		value, err := (privilegesListFunc{}).Execute(context.Background(), rt,
			fullPrivilegesListArgs(tc.objectName, tc.objectType))
		if err != nil {
			t.Fatalf("%s: %v", tc.objectType, err)
		}
		if !reflect.DeepEqual(value, tc.want) {
			t.Fatalf("%s = %#v, want %#v", tc.objectType, value, tc.want)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s calls = %d, want 1", tc.objectType, len(runner.calls))
		}
		wantSQL := "COPY (" + tc.query + ") TO STDOUT WITH CSV HEADER"
		if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != wantSQL {
			t.Fatalf("%s SQL = %q, want %q", tc.objectType, got, wantSQL)
		}
		if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, tc.objectName) {
			t.Fatalf("%s query leaked the object name into SQL: %q", tc.objectType, joined)
		}
	}
}

// TestPostgresPrivilegesListPrepend pins the prepend semantics: table,
// sequence, and function lookups are qualified by the schema prefix, so a
// different prepend selects a different row and the default is "public".
func TestPostgresPrivilegesListPrepend(t *testing.T) {
	csv := "nspname,relname,relkind,name\n" +
		"public,awl,r,\"{public_role=r/postgres}\"\n" +
		"private,awl,r,\"{private_role=r/postgres}\"\n"
	for _, tc := range []struct {
		prepend *string
		want    string
	}{
		{nil, "public_role"},
		{postgresString("private"), "private_role"},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(csv)},
		)
		args := fullPrivilegesListArgs("awl", "table")
		args.Prepend = tc.prepend
		value, err := (privilegesListFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("prepend %v: %v", tc.prepend, err)
		}
		listed := value.(map[string]any)
		if len(listed) != 1 {
			t.Fatalf("prepend %v = %#v, want one grantee", tc.prepend, listed)
		}
		if _, ok := listed[tc.want].(map[string]bool); !ok {
			t.Fatalf("prepend %v = %#v, want %q", tc.prepend, listed, tc.want)
		}
		if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "private") {
			t.Fatalf("prepend leaked into SQL: %q", joined)
		}
	}
}

// TestPostgresPrivilegesListValidation pins the pinned validation head:
// unknown object types are rejected before any Runner invocation, mixed
// case is lowercased exactly like the pinned object_type.lower(), and a
// missing object simply returns the empty dictionary (the pinned empty
// rows loop).
func TestPostgresPrivilegesListValidation(t *testing.T) {
	for _, objectType := range []string{"bogus", ""} {
		rt, runner := newPostgresRuntime()
		_, err := (privilegesListFunc{}).Execute(context.Background(), rt,
			fullPrivilegesListArgs("awl", objectType))
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("object_type %q err = %v, want errPostgresInvalidArgument", objectType, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("object_type %q executed %d commands before validation", objectType, len(runner.calls))
		}
	}

	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	value, err := (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("awl", "TABLE"))
	if err != nil {
		t.Fatal(err)
	}
	if listed := value.(map[string]any); len(listed) != 3 {
		t.Fatalf("TABLE lowercase = %#v, want the pinned dictionary", listed)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("TABLE calls = %d, want 1", len(runner.calls))
	}

	// A catalog row whose ACL is NULL (empty CSV field) is the pinned
	// ValueError from the unpack ladder, with the caller context of the
	// public function.
	nullACL := "nspname,relname,relkind,name\npublic,awl,r,\n"
	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(nullACL)},
	)
	_, err = (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("awl", "table"))
	if !errors.Is(err, errPostgresInvalidACL) {
		t.Fatalf("null acl err = %v, want errPostgresInvalidACL", err)
	}

	// Short rows carrying none of the pinned columns keep the pinned
	// row["name"]/row["rolname"]/row["admin_option"] KeyError as an
	// execution error naming the public function.
	for _, tc := range []struct {
		label      string
		objectType string
		objectName string
		csv        string
	}{
		{"table missing name column", "table", "awl", "nspname,relname,relkind\npublic,awl,r\n"},
		{"group missing columns", "group", "awl", "member_of\nawl\n"},
	} {
		rt, _ = newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.csv)},
		)
		_, err = (privilegesListFunc{}).Execute(context.Background(), rt,
			fullPrivilegesListArgs(tc.objectName, tc.objectType))
		if err == nil || !strings.Contains(err.Error(), "postgres.privileges_list") {
			t.Fatalf("%s err = %v, want a postgres.privileges_list row error", tc.label, err)
		}
	}
}

// TestPostgresPrivilegesListCompatibilityData pins Salt's nonzero-exit and
// missing-object shapes: both return the empty dictionary, data not an
// error.
func TestPostgresPrivilegesListCompatibilityData(t *testing.T) {
	failed := process.CommandResult{ExitCode: 2, Stderr: []byte("psql: error: connection refused")}
	rt, _ := newPostgresRuntime(failed)
	value, err := (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("awl", "table"))
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("nonzero exit = %#v err = %v, want {}, nil", value, err)
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	value, err = (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("absent_table", "table"))
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("absent object = %#v err = %v, want {}, nil", value, err)
	}
}

// TestPostgresPrivilegesListGuards pins the shared failure modes: canceled
// context, runas rejection, redacted Runner errors, output limits,
// psql-unavailable fail-closed, the argument guards, and the nil Runner —
// each with zero Runner executions where the guard precedes the call.
func TestPostgresPrivilegesListGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (privilegesListFunc{}).Execute(ctx, rt, fullPrivilegesListArgs("awl", "table")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	args := fullPrivilegesListArgs("awl", "table")
	args.Runas = postgresString("postgres")
	if _, err := (privilegesListFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v, want errPostgresRunas", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
	})
	_, err := (privilegesListFunc{}).Execute(context.Background(), rt, fullPrivilegesListArgs("awl", "table"))
	if err == nil || strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("runner error = %v, want redacted", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (privilegesListFunc{}).Execute(context.Background(), rt,
			fullPrivilegesListArgs("awl", "table")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (privilegesListFunc{}).Execute(context.Background(), rt,
		fullPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql-unavailable err = %v, want errPostgresPsqlUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	if _, err := (privilegesListFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("privileges_list must reject non-struct args")
	}
	if _, err := (privilegesListFunc{}).Execute(context.Background(), nil, &HasPrivilegesArgs{}); err == nil {
		t.Fatal("privileges_list must reject foreign argument structs")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (privilegesListFunc{}).Execute(context.Background(), rtEmpty,
		fullPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}
