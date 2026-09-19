package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
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

func postgresBool(value bool) *bool { return &value }

func postgresInt64(value int64) *int64 { return &value }

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

// TestPostgresRegistrySurface pins the forty-seven canonical
// registrations, their argument prototypes, and the absence of public
// psql_query, create_metadata, and _parsed_version entries.
func TestPostgresRegistrySurface(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"postgres.available_extensions",
		"postgres.create_extension",
		"postgres.db_alter",
		"postgres.datadir_exists",
		"postgres.datadir_init",
		"postgres.db_create",
		"postgres.db_exists",
		"postgres.db_list",
		"postgres.db_remove",
		"postgres.default_privileges_grant",
		"postgres.default_privileges_list",
		"postgres.default_privileges_revoke",
		"postgres.drop_extension",
		"postgres.get_available_extension",
		"postgres.get_installed_extension",
		"postgres.group_create",
		"postgres.group_remove",
		"postgres.group_update",
		"postgres.has_default_privileges",
		"postgres.has_privileges",
		"postgres.installed_extensions",
		"postgres.is_available_extension",
		"postgres.is_installed_extension",
		"postgres.language_create",
		"postgres.language_exists",
		"postgres.language_list",
		"postgres.language_remove",
		"postgres.privileges_grant",
		"postgres.privileges_list",
		"postgres.privileges_revoke",
		"postgres.role_get",
		"postgres.schema_create",
		"postgres.schema_exists",
		"postgres.schema_get",
		"postgres.schema_list",
		"postgres.schema_remove",
		"postgres.tablespace_alter",
		"postgres.tablespace_create",
		"postgres.tablespace_exists",
		"postgres.tablespace_list",
		"postgres.tablespace_remove",
		"postgres.user_create",
		"postgres.user_exists",
		"postgres.user_list",
		"postgres.user_remove",
		"postgres.user_update",
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
		case "postgres.db_create":
			want = DbCreateArgs{}
		case "postgres.db_remove":
			want = DbRemoveArgs{}
		case "postgres.db_alter":
			want = DbAlterArgs{}
		case "postgres.tablespace_create":
			want = TablespaceCreateArgs{}
		case "postgres.tablespace_alter":
			want = TablespaceAlterArgs{}
		case "postgres.tablespace_remove":
			want = TablespaceRemoveArgs{}
		case "postgres.user_create":
			want = UserCreateArgs{}
		case "postgres.user_update":
			want = UserUpdateArgs{}
		case "postgres.user_remove":
			want = UserRemoveArgs{}
		case "postgres.group_create":
			want = GroupCreateArgs{}
		case "postgres.group_update":
			want = GroupUpdateArgs{}
		case "postgres.group_remove":
			want = GroupRemoveArgs{}
		case "postgres.user_list":
			want = UserListArgs{}
		case "postgres.role_get":
			want = RoleGetArgs{}
		case "postgres.has_privileges":
			want = HasPrivilegesArgs{}
		case "postgres.has_default_privileges":
			want = HasDefaultPrivilegesArgs{}
		case "postgres.privileges_list":
			want = PrivilegesListArgs{}
		case "postgres.privileges_grant":
			want = PrivilegesGrantArgs{}
		case "postgres.privileges_revoke":
			want = PrivilegesRevokeArgs{}
		case "postgres.default_privileges_list":
			want = DefaultPrivilegesListArgs{}
		case "postgres.default_privileges_grant":
			want = DefaultPrivilegesGrantArgs{}
		case "postgres.default_privileges_revoke":
			want = DefaultPrivilegesRevokeArgs{}
		case "postgres.create_extension":
			want = CreateExtensionArgs{}
		case "postgres.drop_extension":
			want = DropExtensionArgs{}
		case "postgres.language_create", "postgres.language_remove":
			want = LanguageMutationArgs{}
		case "postgres.schema_create":
			want = SchemaCreateArgs{}
		case "postgres.schema_remove":
			want = SchemaRemoveArgs{}
		case "postgres.datadir_exists":
			want = DataDirExistsArgs{}
		case "postgres.datadir_init":
			want = DataDirInitArgs{}
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
		// DeepEqual, not ==: the R9.2i argument structs carry the pinned
		// union-typed any fields and the groups slice, which == cannot
		// compare; zero values still compare equal exactly.
		if !reflect.DeepEqual(fn.Args(), want) {
			t.Fatalf("%s prototype = %#v, want zero-value defaults %#v", name, fn.Args(), want)
		}
	}
	// The generic query surface and the private helpers stay unregistered;
	// create_metadata keeps its pending public name until a later round.
	for _, pending := range []string{
		"postgres.psql_query",
		"postgres._parsed_version",
		"postgres.create_metadata",
	} {
		if _, ok := reg.Get(pending); ok {
			t.Fatalf("%s must not be publicly registered", pending)
		}
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
		{dbCreateFunc{}, append([]string{
			"name", "tablespace", "encoding", "lc_collate", "lc_ctype", "owner", "template",
		}, connection...)},
		{dbRemoveFunc{}, append([]string{"name"}, connection...)},
		{dbAlterFunc{}, append([]string{"name", "tablespace", "owner", "owner_recurse"}, connection...)},
		{tablespaceListFunc{}, connection},
		{tablespaceExistsFunc{}, append([]string{"name"}, connection...)},
		{tablespaceCreateFunc{}, append([]string{"name", "location", "options", "owner"}, connection...)},
		{tablespaceAlterFunc{}, append([]string{
			"name", "new_name", "new_owner", "set_option", "reset_option",
		}, connection...)},
		{tablespaceRemoveFunc{}, append([]string{"name"}, connection...)},
		{datadirExistsFunc{}, []string{"name"}},
		{datadirInitFunc{}, []string{
			"name", "auth", "user", "password", "encoding", "locale",
			"waldir", "checksums", "runas",
		}},
		{userListFunc{}, append(connection, "return_password")},
		{availableExtensionsFunc{}, connection},
		{installedExtensionsFunc{}, connection},
		{getAvailableExtensionFunc{}, append([]string{"name"}, connection...)},
		{getInstalledExtensionFunc{}, append([]string{"name"}, connection...)},
		{isAvailableExtensionFunc{}, append([]string{"name"}, connection...)},
		{isInstalledExtensionFunc{}, append([]string{"name"}, connection...)},
		{createExtensionFunc{}, append([]string{
			"name", "if_not_exists", "schema", "ext_version", "from_version",
		}, connection...)},
		{dropExtensionFunc{}, append([]string{"name", "if_exists", "restrict", "cascade"}, connection...)},
		{languageListFunc{}, connection},
		{languageExistsFunc{}, append([]string{"name"}, connection...)},
		{languageCreateFunc{}, append([]string{"name"}, connection...)},
		{languageRemoveFunc{}, append([]string{"name"}, connection...)},
		{schemaListFunc{}, schemaConnection},
		{schemaGetFunc{}, append([]string{"name"}, schemaConnection...)},
		{schemaExistsFunc{}, append([]string{"name"}, schemaConnection...)},
		{schemaCreateFunc{}, append([]string{"name", "owner"}, schemaConnection...)},
		{schemaRemoveFunc{}, append([]string{"name"}, schemaConnection...)},
		{roleGetFunc{}, append(append([]string{"name"}, connection...), "return_password")},
		{userExistsFunc{}, append([]string{"name"}, connection...)},
		{userCreateFunc{}, append([]string{
			"username", "createdb", "createroles", "encrypted", "superuser",
			"login", "connlimit", "inherit", "replication", "rolepassword",
			"valid_until", "groups",
		}, connection...)},
		{userUpdateFunc{}, append([]string{
			"username", "createdb", "createroles", "encrypted", "superuser",
			"inherit", "login", "connlimit", "replication", "rolepassword",
			"valid_until", "groups",
		}, connection...)},
		{userRemoveFunc{}, append([]string{"username"}, connection...)},
		{groupCreateFunc{}, append([]string{
			"groupname", "createdb", "createroles", "encrypted", "login",
			"inherit", "superuser", "replication", "rolepassword", "groups",
		}, connection...)},
		{groupUpdateFunc{}, append([]string{
			"groupname", "createdb", "createroles", "encrypted", "inherit",
			"login", "superuser", "replication", "rolepassword", "groups",
		}, connection...)},
		{groupRemoveFunc{}, append([]string{"groupname"}, connection...)},
		{hasPrivilegesFunc{}, append([]string{
			"name", "object_name", "object_type", "privileges",
			"grant_option", "prepend",
		}, connection...)},
		{privilegesListFunc{}, append([]string{"name", "object_type", "prepend"}, connection...)},
		{privilegesGrantFunc{}, append([]string{
			"name", "object_name", "object_type", "privileges",
			"grant_option", "prepend",
		}, connection...)},
		{privilegesRevokeFunc{}, append([]string{
			"name", "object_name", "object_type", "privileges", "prepend",
		}, connection...)},
		{defaultPrivilegesListFunc{}, append([]string{"name", "object_type", "prepend"}, connection...)},
		{hasDefaultPrivilegesFunc{}, append([]string{
			"name", "object_name", "object_type", "defprivileges",
			"grant_option", "prepend",
		}, connection...)},
		{defaultPrivilegesGrantFunc{}, append([]string{
			"name", "object_name", "object_type", "defprivileges",
			"grant_option", "prepend",
		}, connection...)},
		{defaultPrivilegesRevokeFunc{}, append([]string{
			"name", "object_name", "object_type", "defprivileges", "prepend",
		}, connection...)},
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

// ---------------------------------------------------------------------------
// db_create / db_remove — pinned test_db_create, test_db_create_
// empty_string_param, test_db_create_with_trivial_sql_injection, and
// test_db_remove (tests/pytests/unit/modules/test_postgres.py:340-433,
// 502-592).

// TestPostgresDbCreateArgvAndResult ports the pinned test_db_create: the
// exact psql argv with the pinned statement at index 14, the clean PG
// environment, password redaction, and the retcode-boolean result. The
// pinned test's runas="foo" is covered by the runas rejection below
// because the single-user runtime rejects it before execution.
func TestPostgresDbCreateArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:          "dbname",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
		Tablespace:    postgresString("testspace"),
		Owner:         postgresString("otheruser"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_create = %#v, want true", value)
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
		"-c", `CREATE DATABASE "dbname" WITH TABLESPACE = "testspace" OWNER = "otheruser"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if all := append([]string{command.Name}, command.Args...); all[14] != want[14] {
		t.Fatalf("argv[14] = %q, want the pinned CREATE DATABASE statement", all[14])
	}
	wantEnv := []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestPostgresDbCreateEmptyStringParam ports the pinned
// test_db_create_empty_string_param: an explicit empty lc_collate stays
// the pinned quoted empty literal, the numeric port renders through the
// shared argv, and the statement keeps the pinned option order.
func TestPostgresDbCreateEmptyStringParam(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:          "dbname",
		LcCollate:     postgresString(""),
		Encoding:      postgresString("utf8"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("1234"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_create = %#v, want true", value)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "1234",
		"--dbname", "maint_db",
		"-c", `CREATE DATABASE "dbname" WITH ENCODING = 'utf8' LC_COLLATE = ''`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

// TestPostgresDbCreateAllOptions pins the full pinned OrderedDict option
// order — TABLESPACE, OWNER, TEMPLATE, ENCODING, LC_COLLATE, LC_CTYPE —
// including the pinned bare (unquoted) TEMPLATE identifier.
func TestPostgresDbCreateAllOptions(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:       "mydb",
		Tablespace: postgresString("ts"),
		Owner:      postgresString("own"),
		Template:   postgresString("template0"),
		Encoding:   postgresString("UTF8"),
		LcCollate:  postgresString("en_US.UTF-8"),
		LcCtype:    postgresString("en_US.UTF-8"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `CREATE DATABASE "mydb" WITH TABLESPACE = "ts" OWNER = "own" ` +
		`TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' ` +
		`LC_CTYPE = 'en_US.UTF-8'`
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != want {
		t.Fatalf("statement = %q, want %q", got, want)
	}
}

// TestPostgresDbCreateDefaults pins the no-option shape: exactly the
// pinned CREATE DATABASE head, the "postgres" maintenance fallback, a
// clean environment, and no redaction.
func TestPostgresDbCreateDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "dbname"})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_create = %#v, want true", value)
	}
	command := runner.calls[0]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-c", `CREATE DATABASE "dbname"`,
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

// TestPostgresDbCreateTrivialSQLInjection ports the pinned
// test_db_create_with_trivial_sql_injection: the pinned _quote_ddl_value
// SaltInvocationError for a quote character in a literal value, raised
// before any Runner invocation, as the value-free stable error naming the
// rejected argument key.
func TestPostgresDbCreateTrivialSQLInjection(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:      "dbname",
		LcCollate: postgresString("foo' ENCODING='utf8"),
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in lc_collate" {
		t.Fatalf("trivial sqli err = %v", err)
	}
	if !errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("trivial sqli err = %v, want invalid argument", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected value executed %d commands", len(runner.calls))
	}
	// The double-quoted identifier positions carry the same rejection.
	for _, tc := range []struct {
		name  string
		owner *string
	}{
		{"owner", postgresString(`oth"er`)},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
			Name:  "dbname",
			Owner: tc.owner,
		})
		if err == nil || err.Error() != `postgres: invalid argument: unsupported quote character in owner` {
			t.Fatalf("%s sqli err = %v", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s injected value executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresDbCreateInjectionIdentifiers pins the fail-closed boundary at
// the identifier positions the pinned source interpolates raw: the
// double-quoted database name and the unquoted TEMPLATE option, each with
// its exact value-free stable error.
func TestPostgresDbCreateInjectionIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dbname   string
		template *string
		want     string
	}{
		{`name quote`, `db" )`, nil, "postgres: invalid argument: unsupported quote character in name"},
		{"template quote", "db", postgresString(`tpl"; DROP DATABASE x; --`), "postgres: invalid argument: unsupported template identifier"},
		{"template literal", "db", postgresString(`tpl' `), "postgres: invalid argument: unsupported template identifier"},
		{"template statement", "db", postgresString(`tpl; DROP DATABASE x`), "postgres: invalid argument: unsupported template identifier"},
		{"template whitespace", "db", postgresString("tpl ENCODING='latin1'"), "postgres: invalid argument: unsupported template identifier"},
		{"template empty", "db", postgresString(""), "postgres: invalid argument: unsupported template identifier"},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
			Name:     tc.dbname,
			Template: tc.template,
		})
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresDbCreateNonzeroExitIsFalse pins the pinned tail
// ret["retcode"] == 0: a rejected CREATE is the boolean false, never an
// exception.
func TestPostgresDbCreateNonzeroExitIsFalse(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`psql: error: ERROR: database "dbname" already exists`),
	})
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "dbname"})
	if err != nil {
		t.Fatalf("nonzero exit must not error: %v", err)
	}
	if value != false {
		t.Fatalf("db_create = %#v, want false", value)
	}
}

// TestPostgresDbCreateGuards pins cancellation, runas rejection, psql
// unavailability, output limits, and redacted Runner errors.
func TestPostgresDbCreateGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (dbCreateFunc{}).Execute(ctx, rt, &DbCreateArgs{Name: "dbname"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:  "dbname",
		Runas: postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "dbname"}); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "dbname"}); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname postgres: secret foo rejected"),
	})
	_, err = (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{
		Name:     "dbname",
		Password: postgresString("foo"),
	})
	if err == nil || strings.Contains(err.Error(), "foo") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// wantDbRemoveStatements is the pinned three-statement sequence of
// test_db_remove, byte-for-byte.
var wantDbRemoveStatements = []string{
	`REVOKE CONNECT ON DATABASE "test_db" FROM public;`,
	"SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'test_db' AND pid <> pg_backend_pid();",
	`DROP DATABASE "test_db";`,
}

// TestPostgresDbRemoveArgvAndResult ports the pinned test_db_remove: the
// three fixed statements in the pinned order, each on the full pinned argv
// and clean environment, with the true result after the DROP.
func TestPostgresDbRemoveArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{
		Name:          "test_db",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_remove = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	for i, command := range runner.calls {
		want := []string{
			"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "maint_db",
			"-c", wantDbRemoveStatements[i],
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("call %d argv = %q, want %q", i, got, want)
		}
		wantEnv := []string{
			"PGPASSWORD=foo",
			"PGUSER=testuser",
			"PGHOST=testhost",
			"PGPORT=testport",
		}
		if !reflect.DeepEqual(command.Env, wantEnv) {
			t.Fatalf("call %d env = %q, want %q", i, command.Env, wantEnv)
		}
		if command.Shell {
			t.Fatalf("call %d must run without a shell", i)
		}
		if command.Timeout != commandTimeout ||
			command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("call %d unsafe command bounds: %#v", i, command)
		}
		if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
			t.Fatalf("call %d redact = %#v", i, command.Redact)
		}
	}
	// No statement runs after the DROP.
	if last := runner.calls[2].Args[len(runner.calls[2].Args)-1]; last != `DROP DATABASE "test_db";` {
		t.Fatalf("last statement = %q, want the DROP", last)
	}
}

// TestPostgresDbRemoveNonzeroAborts pins the pinned raise
// Exception(f"Failed: ret=...") semantics: the first nonzero retcode
// aborts the flow, so a missing database (the REVOKE fails) never reaches
// the backend termination or the DROP, and a failure on the termination or
// the DROP stops at exactly that statement.
func TestPostgresDbRemoveNonzeroAborts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fails  int // 1-based statement index that returns nonzero
		calls  int // runner calls before the abort
		retMsg string
	}{
		{"missing db fails revoke", 1, 1, "Failed: retcode=1"},
		{"termination fails", 2, 2, "Failed: retcode=2"},
		{"drop fails", 3, 3, "Failed: retcode=3"},
	} {
		results := []process.CommandResult{}
		for i := 1; i <= 3; i++ {
			exit := 0
			if i == tc.fails {
				exit = i
			}
			results = append(results, process.CommandResult{
				ExitCode: exit,
				Stderr:   []byte("psql: error: FATAL: database does not exist"),
			})
		}
		rt, runner := newPostgresRuntime(results...)
		value, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "test_db"})
		if err == nil || !strings.Contains(err.Error(), tc.retMsg) {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.retMsg)
		}
		if value != nil {
			t.Fatalf("%s value = %#v, want nil", tc.name, value)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s runner calls = %d, want %d", tc.name, len(runner.calls), tc.calls)
		}
		last := runner.calls[len(runner.calls)-1].Args[len(runner.calls[len(runner.calls)-1].Args)-1]
		if last != wantDbRemoveStatements[tc.calls-1] {
			t.Fatalf("%s last statement = %q, want %q", tc.name, last, wantDbRemoveStatements[tc.calls-1])
		}
		// The error must not carry captured server output.
		failing := results[tc.fails-1]
		if err != nil && strings.Contains(err.Error(), string(failing.Stderr)) {
			t.Fatalf("%s error embeds captured stderr: %v", tc.name, err)
		}
	}
}

// TestPostgresDbRemoveInjection pins the fail-closed name boundary: the
// pinned flow interpolates the name into both a double-quoted identifier
// and a single-quoted datname literal, so either quote character is
// rejected before any Runner invocation with the exact value-free stable
// error.
func TestPostgresDbRemoveInjection(t *testing.T) {
	for _, name := range []string{
		`x'; DROP DATABASE postgres; --`,
		`x" ; DROP DATABASE postgres; --`,
	} {
		rt, runner := newPostgresRuntime()
		_, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: name})
		if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in name" {
			t.Fatalf("injected name %q err = %v", name, err)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("injected name %q err = %v, want invalid argument", name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("injected name %q executed %d commands", name, len(runner.calls))
		}
	}
}

// postgresValidationMarker is the synthetic password marker for the
// validation-redaction tests: every rejected field value embeds it and the
// connection password is set to the same string, so any leak of a rejected
// value through a validation error is a password leak on the CLI exit
// path, where the error is raised before any Runner invocation and
// therefore before any Command.Redact or redactedError pass runs.
const postgresValidationMarker = "pgmark-7f3c-secret"

// dbCreateRejectedFields enumerates every db_create field the fixed
// statement construction rejects, with a rejected value embedding the
// marker, and the exact value-free stable error each rejection must
// return.
func dbCreateRejectedFields() []struct {
	field string
	args  *DbCreateArgs
	want  string
} {
	return []struct {
		field string
		args  *DbCreateArgs
		want  string
	}{
		{
			"name",
			&DbCreateArgs{Name: "db-" + postgresValidationMarker + `"`},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"tablespace",
			&DbCreateArgs{Name: "db", Tablespace: postgresString(`ts-` + postgresValidationMarker + `"`)},
			"postgres: invalid argument: unsupported quote character in tablespace",
		},
		{
			"owner",
			&DbCreateArgs{Name: "db", Owner: postgresString(`own-` + postgresValidationMarker + `"`)},
			"postgres: invalid argument: unsupported quote character in owner",
		},
		{
			"template",
			&DbCreateArgs{Name: "db", Template: postgresString(`tpl-` + postgresValidationMarker)},
			"postgres: invalid argument: unsupported template identifier",
		},
		{
			"encoding",
			&DbCreateArgs{Name: "db", Encoding: postgresString(`enc-` + postgresValidationMarker + `'`)},
			"postgres: invalid argument: unsupported quote character in encoding",
		},
		{
			"lc_collate",
			&DbCreateArgs{Name: "db", LcCollate: postgresString(`lcc-` + postgresValidationMarker + `'`)},
			"postgres: invalid argument: unsupported quote character in lc_collate",
		},
		{
			"lc_ctype",
			&DbCreateArgs{Name: "db", LcCtype: postgresString(`lct-` + postgresValidationMarker + `'`)},
			"postgres: invalid argument: unsupported quote character in lc_ctype",
		},
	}
}

// dbRemoveRejectedNames enumerates the db_remove name rejections — both
// quote characters of its double-quoted-identifier and single-quoted-
// literal contexts — with values embedding the marker.
func dbRemoveRejectedNames() []string {
	return []string{
		`x'-` + postgresValidationMarker,
		`x"-` + postgresValidationMarker,
		postgresValidationMarker + `'"`,
	}
}

// TestPostgresDbCreateValidationErrorRedaction loops every rejected
// db_create field with a value embedding the same synthetic marker as the
// connection password: the error must be exactly the stable argument-key
// message under the exact invalid-argument category — never the rejected
// value, so the marker cannot leak — and no Runner call may happen.
func TestPostgresDbCreateValidationErrorRedaction(t *testing.T) {
	for _, tc := range dbCreateRejectedFields() {
		tc.args.Password = postgresString(postgresValidationMarker)
		rt, runner := newPostgresRuntime()
		_, err := (dbCreateFunc{}).Execute(context.Background(), rt, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.field, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.field, err)
		}
		if strings.Contains(err.Error(), postgresValidationMarker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.field, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.field, len(runner.calls))
		}
	}
}

// TestPostgresDbRemoveValidationErrorRedaction loops the rejected
// db_remove names with values embedding the same synthetic marker as the
// connection password, asserting the same value-free stable error and zero
// Runner calls.
func TestPostgresDbRemoveValidationErrorRedaction(t *testing.T) {
	for _, name := range dbRemoveRejectedNames() {
		rt, runner := newPostgresRuntime()
		_, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{
			Name:     name,
			Password: postgresString(postgresValidationMarker),
		})
		if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in name" {
			t.Fatalf("name %q err = %v", name, err)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("name %q err = %v, want invalid argument", name, err)
		}
		if strings.Contains(err.Error(), postgresValidationMarker) {
			t.Fatalf("name %q error leaks the rejected value: %v", name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("name %q executed %d commands", name, len(runner.calls))
		}
	}
}

// TestPostgresDbValidationErrorsRedactedThroughRegistry repeats the loops
// through the ExecRegistry dispatch (the path the CLI drives): the same
// exact, marker-free stable errors and zero Runner calls, plus db_alter's
// owner_recurse UnsupportedError under the same marker overlap.
func TestPostgresDbValidationErrorsRedactedThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	type registryCall struct {
		fn   string
		args any
		want string
	}
	calls := []registryCall{}
	for _, tc := range dbCreateRejectedFields() {
		tc.args.Password = postgresString(postgresValidationMarker)
		calls = append(calls, registryCall{"postgres.db_create", tc.args, tc.want})
	}
	for _, name := range dbRemoveRejectedNames() {
		calls = append(calls, registryCall{"postgres.db_remove", &DbRemoveArgs{
			Name:     name,
			Password: postgresString(postgresValidationMarker),
		}, "postgres: invalid argument: unsupported quote character in name"})
	}
	for _, tc := range dbAlterRejectedFields() {
		tc.args.Password = postgresString(postgresValidationMarker)
		calls = append(calls, registryCall{"postgres.db_alter", tc.args, tc.want})
	}
	calls = append(calls, registryCall{"postgres.db_alter", &DbAlterArgs{
		Name:         "db-" + postgresValidationMarker,
		Owner:        postgresString(`own-` + postgresValidationMarker),
		OwnerRecurse: postgresBool(true),
		Password:     postgresString(postgresValidationMarker),
	}, `unsupported function "postgres.owner_to"`})
	for _, tc := range calls {
		rt, runner := newPostgresRuntime()
		_, err := reg.Call(context.Background(), rt, tc.fn, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), postgresValidationMarker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.fn, len(runner.calls))
		}
	}
}

// TestPostgresDbRemoveMaintenanceNotSpecialCased pins the pinned source's
// lack of a maintenance-database guard: the name equal to the maintenance
// database still gets exactly the three pinned statements, and PostgreSQL
// itself is the only rejection point.
func TestPostgresDbRemoveMaintenanceNotSpecialCased(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{
		Name:          "postgres",
		MaintenanceDB: postgresString("postgres"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_remove = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	if first := runner.calls[0].Args[len(runner.calls[0].Args)-1]; first != `REVOKE CONNECT ON DATABASE "postgres" FROM public;` {
		t.Fatalf("first statement = %q", first)
	}
}

// TestPostgresDbRemoveGuards pins cancellation, runas rejection, psql
// unavailability, output limits, and redacted Runner errors on the first
// statement of the flow.
func TestPostgresDbRemoveGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (dbRemoveFunc{}).Execute(ctx, rt, &DbRemoveArgs{Name: "test_db"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{
		Name:  "test_db",
		Runas: postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "test_db"}); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "test_db"}); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname postgres: secret foo rejected"),
	})
	_, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{
		Name:     "test_db",
		Password: postgresString("foo"),
	})
	if err == nil || strings.Contains(err.Error(), "foo") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// wantDbAlterStatements is the pinned two-statement sequence of
// test_db_alter, byte-for-byte: the OWNER change before the TABLESPACE
// change.
var wantDbAlterStatements = []string{
	`ALTER DATABASE "dbname" OWNER TO "otheruser"`,
	`ALTER DATABASE "dbname" SET TABLESPACE "testspace"`,
}

// TestPostgresDbAlterArgvAndResult ports the pinned test_db_alter: both
// statements in the pinned order, each on the full pinned argv with the
// clean PG environment and password redaction, and the true result after
// the TABLESPACE statement. The pinned test's runas="foo" is covered by
// the runas rejection below because the single-user runtime rejects it
// before execution.
func TestPostgresDbAlterArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:          "dbname",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
		Tablespace:    postgresString("testspace"),
		Owner:         postgresString("otheruser"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("db_alter = %#v, want true", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	for i, command := range runner.calls {
		want := []string{
			"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "maint_db",
			"-c", wantDbAlterStatements[i],
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("call %d argv = %q, want %q", i, got, want)
		}
		wantEnv := []string{
			"PGPASSWORD=foo",
			"PGUSER=testuser",
			"PGHOST=testhost",
			"PGPORT=testport",
		}
		if !reflect.DeepEqual(command.Env, wantEnv) {
			t.Fatalf("call %d env = %q, want %q", i, command.Env, wantEnv)
		}
		if command.Shell {
			t.Fatalf("call %d must run without a shell", i)
		}
		if command.Timeout != commandTimeout ||
			command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("call %d unsafe command bounds: %#v", i, command)
		}
		if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
			t.Fatalf("call %d unexpected command payload: %#v", i, command)
		}
		if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
			t.Fatalf("call %d redact = %#v", i, command.Redact)
		}
		if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
			t.Fatalf("call %d rendered command leaks password: %q", i, rendered)
		}
	}
}

// TestPostgresDbAlterSingleOption pins the one-statement shapes: owner
// alone runs only the pinned OWNER statement and tablespace alone only
// the pinned TABLESPACE statement, with the "postgres" maintenance
// fallback and a clean environment.
func TestPostgresDbAlterSingleOption(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner bool
		want  string
	}{
		{"owner only", true, wantDbAlterStatements[0]},
		{"tablespace only", false, wantDbAlterStatements[1]},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
		args := &DbAlterArgs{Name: "dbname"}
		if tc.owner {
			args.Owner = postgresString("otheruser")
		} else {
			args.Tablespace = postgresString("testspace")
		}
		value, err := (dbAlterFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatal(err)
		}
		if value != true {
			t.Fatalf("%s db_alter = %#v, want true", tc.name, value)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s runner calls = %d, want 1", tc.name, len(runner.calls))
		}
		command := runner.calls[0]
		want := []string{
			"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
			"--dbname", "postgres",
			"-c", tc.want,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.name, got, want)
		}
		if command.Env == nil || len(command.Env) != 0 {
			t.Fatalf("%s env = %q, want clean empty environment", tc.name, command.Env)
		}
		if command.Redact != nil {
			t.Fatalf("%s redact = %q, want none", tc.name, command.Redact)
		}
	}
}

// TestPostgresDbAlterNoop pins the pinned any((tablespace, owner)) head:
// nil arguments and Python-falsy explicit empty strings both answer the
// no-op True with no Runner invocation, whatever owner_recurse carries.
func TestPostgresDbAlterNoop(t *testing.T) {
	for _, tc := range []struct {
		name       string
		owner      *string
		tablespace *string
		recurse    *bool
	}{
		{"neither nil", nil, nil, nil},
		{"neither recurse", nil, nil, postgresBool(true)},
		{"owner empty", postgresString(""), nil, nil},
		{"tablespace empty", nil, postgresString(""), nil},
		{"both empty recurse", postgresString(""), postgresString(""), postgresBool(true)},
	} {
		rt, runner := newPostgresRuntime()
		value, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
			Name:         "dbname",
			Owner:        tc.owner,
			Tablespace:   tc.tablespace,
			OwnerRecurse: tc.recurse,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if value != true {
			t.Fatalf("%s db_alter = %#v, want true", tc.name, value)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands, want none", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresDbAlterOwnerRecurseUnsupported pins the owner+owner_recurse
// branch: owner_to stays pending, so the branch answers the deterministic
// value-free UnsupportedError before any Runner invocation instead of
// silently running the shallow ALTER OWNER — while owner_recurse without
// a truthy owner keeps the pinned else branch, and an explicit false
// owner_recurse runs the pinned shallow statements.
func TestPostgresDbAlterOwnerRecurseUnsupported(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:         "dbname",
		Owner:        postgresString("otheruser"),
		OwnerRecurse: postgresBool(true),
	})
	if err == nil || err.Error() != `unsupported function "postgres.owner_to"` {
		t.Fatalf("owner_recurse err = %v", err)
	}
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Name != "postgres.owner_to" {
		t.Fatalf("owner_recurse err = %v, want UnsupportedError for owner_to", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("owner_recurse executed %d commands", len(runner.calls))
	}

	// owner_recurse without an owner never selects the branch: the pinned
	// tablespace statement still runs (the pinned owner_to call passes no
	// maintenance_db either way; the pending name is not consulted).
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:         "dbname",
		Tablespace:   postgresString("testspace"),
		OwnerRecurse: postgresBool(true),
	})
	if err != nil {
		t.Fatalf("owner_recurse without owner: %v", err)
	}
	if value != true {
		t.Fatalf("owner_recurse without owner = %#v, want true", value)
	}
	if len(runner.calls) != 1 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != wantDbAlterStatements[1] {
		t.Fatalf("owner_recurse without owner calls = %d", len(runner.calls))
	}

	// An explicit false owner_recurse keeps the pinned shallow flow.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:         "dbname",
		Owner:        postgresString("otheruser"),
		Tablespace:   postgresString("testspace"),
		OwnerRecurse: postgresBool(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true || len(runner.calls) != 2 {
		t.Fatalf("explicit false recurse value=%#v calls=%d", value, len(runner.calls))
	}
	if first := runner.calls[0].Args[len(runner.calls[0].Args)-1]; first != wantDbAlterStatements[0] {
		t.Fatalf("explicit false recurse first statement = %q", first)
	}
}

// TestPostgresDbAlterNonzeroRetcodeStops pins the retcode boolean and the
// stop: the first nonzero retcode answers the pinned False and no later
// statement runs — the OWNER change never reaches the TABLESPACE change,
// and a failing TABLESPACE change alone still answers False after both
// statements were attempted.
func TestPostgresDbAlterNonzeroRetcodeStops(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fails   int // 1-based statement index that returns nonzero
		calls   int // runner calls before the stop
		owner   bool
		tablesp bool
	}{
		{"owner fails", 1, 1, true, true},
		{"tablespace fails after owner", 2, 2, true, true},
		{"tablespace fails alone", 1, 1, false, true},
		{"owner fails alone", 1, 1, true, false},
	} {
		results := []process.CommandResult{}
		for i := 1; i <= tc.calls; i++ {
			exit := 0
			if i == tc.fails {
				exit = 3
			}
			results = append(results, process.CommandResult{
				ExitCode: exit,
				Stderr:   []byte(`psql: error: ERROR: database "dbname" does not exist`),
			})
		}
		rt, runner := newPostgresRuntime(results...)
		args := &DbAlterArgs{Name: "dbname"}
		if tc.owner {
			args.Owner = postgresString("otheruser")
		}
		if tc.tablesp {
			args.Tablespace = postgresString("testspace")
		}
		value, err := (dbAlterFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s err = %v, want the retcode boolean only", tc.name, err)
		}
		if value != false {
			t.Fatalf("%s db_alter = %#v, want false", tc.name, value)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s runner calls = %d, want %d", tc.name, len(runner.calls), tc.calls)
		}
		last := runner.calls[len(runner.calls)-1].Args[len(runner.calls[len(runner.calls)-1].Args)-1]
		wantLast := wantDbAlterStatements[0]
		if !tc.owner {
			wantLast = wantDbAlterStatements[1]
		} else if tc.calls == 2 {
			wantLast = wantDbAlterStatements[1]
		}
		if last != wantLast {
			t.Fatalf("%s last statement = %q, want %q", tc.name, last, wantLast)
		}
	}
}

// TestPostgresDbAlterInjection pins the fail-closed identifier boundary:
// the pinned format strings interpolate the name, the owner, and the
// tablespace into double-quoted identifier positions without escaping, so
// the double quote is rejected before any Runner invocation with the
// exact value-free stable error naming the argument key.
func TestPostgresDbAlterInjection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dbname     string
		owner      *string
		tablespace *string
		want       string
	}{
		{`name quote`, `db" )`, postgresString("own"), nil, "postgres: invalid argument: unsupported quote character in name"},
		{"owner quote", "db", postgresString(`oth"; DROP DATABASE x; --`), nil, "postgres: invalid argument: unsupported quote character in owner"},
		{"tablespace quote", "db", nil, postgresString(`ts" ; DROP DATABASE x; --`), "postgres: invalid argument: unsupported quote character in tablespace"},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
			Name:       tc.dbname,
			Owner:      tc.owner,
			Tablespace: tc.tablespace,
		})
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// dbAlterRejectedFields enumerates every db_alter field the fail-closed
// identifier boundary rejects, with a rejected value embedding the marker
// and the exact value-free stable error each rejection must return.
func dbAlterRejectedFields() []struct {
	field string
	args  *DbAlterArgs
	want  string
} {
	return []struct {
		field string
		args  *DbAlterArgs
		want  string
	}{
		{
			"name",
			&DbAlterArgs{Name: "db-" + postgresValidationMarker + `"`, Owner: postgresString("own")},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"owner",
			&DbAlterArgs{Name: "db", Owner: postgresString(`own-` + postgresValidationMarker + `"`)},
			"postgres: invalid argument: unsupported quote character in owner",
		},
		{
			"tablespace",
			&DbAlterArgs{Name: "db", Tablespace: postgresString(`ts-` + postgresValidationMarker + `"`)},
			"postgres: invalid argument: unsupported quote character in tablespace",
		},
	}
}

// TestPostgresDbAlterValidationErrorRedaction loops every rejected
// db_alter field with a value embedding the same synthetic marker as the
// connection password: the error must be exactly the stable argument-key
// message — never the rejected value — and no Runner call may happen. The
// owner_recurse UnsupportedError is value-free by construction and is
// asserted the same way.
func TestPostgresDbAlterValidationErrorRedaction(t *testing.T) {
	for _, tc := range dbAlterRejectedFields() {
		tc.args.Password = postgresString(postgresValidationMarker)
		rt, runner := newPostgresRuntime()
		_, err := (dbAlterFunc{}).Execute(context.Background(), rt, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.field, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.field, err)
		}
		if strings.Contains(err.Error(), postgresValidationMarker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.field, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.field, len(runner.calls))
		}
	}

	// The owner_recurse branch must stay value-free under the same marker
	// overlap: neither the owner nor the password can reach the error.
	rt, runner := newPostgresRuntime()
	_, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:         "db-" + postgresValidationMarker,
		Owner:        postgresString(`own-` + postgresValidationMarker),
		OwnerRecurse: postgresBool(true),
		Password:     postgresString(postgresValidationMarker),
	})
	if err == nil || err.Error() != `unsupported function "postgres.owner_to"` {
		t.Fatalf("owner_recurse marker err = %v", err)
	}
	if strings.Contains(err.Error(), postgresValidationMarker) {
		t.Fatalf("owner_recurse error leaks a value: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("owner_recurse executed %d commands", len(runner.calls))
	}
}

// TestPostgresDbAlterGuards pins cancellation, runas rejection, psql
// unavailability, output limits, and redacted Runner errors on the first
// statement of the flow.
func TestPostgresDbAlterGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (dbAlterFunc{}).Execute(ctx, rt, &DbAlterArgs{Name: "dbname", Owner: postgresString("own")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:  "dbname",
		Owner: postgresString("own"),
		Runas: postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{Name: "dbname", Owner: postgresString("own")}); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{Name: "dbname", Owner: postgresString("own")}); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname postgres: secret foo rejected"),
	})
	_, err = (dbAlterFunc{}).Execute(context.Background(), rt, &DbAlterArgs{
		Name:     "dbname",
		Owner:    postgresString("own"),
		Password: postgresString("foo"),
	})
	if err == nil || strings.Contains(err.Error(), "foo") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// wantTablespaceCreateStatement is the exact statement of the pinned
// test_tablespace_create, byte-for-byte including the trailing space the
// pinned format string leaves for the empty options tail.
const wantTablespaceCreateStatement = `CREATE TABLESPACE "test_tablespace" OWNER "otheruser" LOCATION '/tmp/postgres_test_tablespace' `

// TestPostgresTablespaceCreateArgvAndResult ports the pinned
// test_tablespace_create: the exact CREATE TABLESPACE statement on the
// full pinned argv (SQL at index 14), the clean PG environment, password
// redaction, and the retcode boolean. The pinned test's runas="foo" is
// covered by the shared guards test because the single-user runtime
// rejects it before execution.
func TestPostgresTablespaceCreateArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
		Name:          "test_tablespace",
		Location:      "/tmp/postgres_test_tablespace",
		Owner:         postgresString("otheruser"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("tablespace_create = %#v, want true", value)
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
		"-c", wantTablespaceCreateStatement,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if all := append([]string{command.Name}, command.Args...); all[14] != wantTablespaceCreateStatement {
		t.Fatalf("argv[14] = %q, want the pinned CREATE TABLESPACE statement", all[14])
	}
	wantEnv := []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestPostgresTablespaceCreateShapes pins the remaining pinned statement
// shapes: the no-owner head keeps the pinned double space before
// LOCATION, the truthy options map renders the pinned WITH tail in the
// deterministic sorted-key order, an explicit empty owner string is the
// pinned falsy no-op, and the "postgres" maintenance fallback plus a
// clean environment apply like every connection default.
func TestPostgresTablespaceCreateShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner *string
		opts  map[string]string
		want  string
	}{
		{
			"no owner",
			nil,
			nil,
			`CREATE TABLESPACE "ts"  LOCATION '/srv/ts' `,
		},
		{
			"empty owner is falsy",
			postgresString(""),
			nil,
			`CREATE TABLESPACE "ts"  LOCATION '/srv/ts' `,
		},
		{
			"options only",
			nil,
			map[string]string{"opt2": "4.0", "opt1": "1.0"},
			`CREATE TABLESPACE "ts"  LOCATION '/srv/ts' WITH ( opt1 = 1.0, opt2 = 4.0 )`,
		},
		{
			"owner and options",
			postgresString("own"),
			map[string]string{"seq_page_cost": "1.1"},
			`CREATE TABLESPACE "ts" OWNER "own" LOCATION '/srv/ts' WITH ( seq_page_cost = 1.1 )`,
		},
		{
			"empty options map is falsy",
			nil,
			map[string]string{},
			`CREATE TABLESPACE "ts"  LOCATION '/srv/ts' `,
		},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
		value, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
			Name:     "ts",
			Location: "/srv/ts",
			Owner:    tc.owner,
			Options:  tc.opts,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if value != true {
			t.Fatalf("%s tablespace_create = %#v, want true", tc.name, value)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s runner calls = %d, want 1", tc.name, len(runner.calls))
		}
		command := runner.calls[0]
		want := []string{
			"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
			"--dbname", "postgres",
			"-c", tc.want,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.name, got, want)
		}
		if command.Env == nil || len(command.Env) != 0 {
			t.Fatalf("%s env = %q, want clean empty environment", tc.name, command.Env)
		}
		if command.Redact != nil {
			t.Fatalf("%s redact = %q, want none", tc.name, command.Redact)
		}
	}
}

// TestPostgresTablespaceCreateNonzeroExitIsFalse pins the pinned tail
// ret["retcode"] == 0: a rejected CREATE is the boolean false, never an
// exception — including the missing-directory and duplicate-tablespace
// server rejections.
func TestPostgresTablespaceCreateNonzeroExitIsFalse(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`psql: error: ERROR: directory "/srv/ts" does not exist`),
	})
	value, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
		Name:     "ts",
		Location: "/srv/ts",
	})
	if err != nil {
		t.Fatalf("nonzero exit must not error: %v", err)
	}
	if value != false {
		t.Fatalf("tablespace_create = %#v, want false", value)
	}
}

// TestPostgresTablespaceCreateLocationBoundary pins the StateKit LOCATION
// boundary: the pinned format string interpolates the location raw into a
// single-quoted literal, so anything but an absolute, clean,
// control-free, quote-free path is rejected value-free before any Runner
// invocation.
func TestPostgresTablespaceCreateLocationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		location string
		want     string
	}{
		{"relative", "srv/ts", "postgres: invalid argument: invalid tablespace location"},
		{"empty", "", "postgres: invalid argument: invalid tablespace location"},
		{"dot segment", "/srv/./ts", "postgres: invalid argument: invalid tablespace location"},
		{"parent traversal", "/srv/../ts", "postgres: invalid argument: invalid tablespace location"},
		{"trailing slash", "/srv/ts/", "postgres: invalid argument: invalid tablespace location"},
		{"double slash", "//srv/ts", "postgres: invalid argument: invalid tablespace location"},
		{"bare traversal", "..", "postgres: invalid argument: invalid tablespace location"},
		{"control newline", "/srv/t\ns", "postgres: invalid argument: invalid tablespace location"},
		{"control nul", "/srv/t\x00s", "postgres: invalid argument: invalid tablespace location"},
		{"control del", "/srv/t\x7fs", "postgres: invalid argument: invalid tablespace location"},
		{"quote escape", "/srv/ts'", "postgres: invalid argument: unsupported quote character in location"},
		{"quote injection", `/srv/ts' ; DROP TABLESPACE x; --`, "postgres: invalid argument: unsupported quote character in location"},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
			Name:     "ts",
			Location: tc.location,
		})
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}

	// A clean multi-segment absolute path with legal punctuation stays
	// inside the boundary; the server remains the semantic judge.
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
		Name:     "ts",
		Location: "/var/lib/postgresql/16/data-ts",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true || len(runner.calls) != 1 {
		t.Fatalf("clean location value=%#v calls=%d", value, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got !=
		`CREATE TABLESPACE "ts"  LOCATION '/var/lib/postgresql/16/data-ts' ` {
		t.Fatalf("clean location statement = %q", got)
	}
}

// TestPostgresTablespaceCreateOptionsBoundary pins the raw option-token
// boundary: the pinned source interpolates both the key and the value
// into the WITH clause with no quoting, so each must stay inside the
// bare token classes and every rejection is value-free.
func TestPostgresTablespaceCreateOptionsBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts map[string]string
		want string
	}{
		{
			"key injection",
			map[string]string{"seq_page_cost": "1.1", `x; DROP TABLESPACE y; --`: "1"},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"key quote",
			map[string]string{`x"`: "1"},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"key empty",
			map[string]string{"": "1"},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"value injection",
			map[string]string{"seq_page_cost": `1.1) ; DROP TABLESPACE x; --`},
			"postgres: invalid argument: unsupported tablespace option value",
		},
		{
			"value quote",
			map[string]string{"seq_page_cost": "'1.1'"},
			"postgres: invalid argument: unsupported tablespace option value",
		},
		{
			"value bare token class is accepted shape-wise",
			map[string]string{"max_stack_depth": "2MB"},
			"", // accepted: the server stays the semantic judge
		},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
			Name:     "ts",
			Location: "/srv/ts",
			Options:  tc.opts,
		})
		if tc.want == "" {
			// The bare token class accepted shape: exactly one statement
			// runs and no rejection exists.
			if err != nil {
				t.Fatalf("%s unexpected err = %v", tc.name, err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("%s executed %d commands, want 1", tc.name, len(runner.calls))
			}
			continue
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresTablespaceCreateInjection pins the fail-closed identifier
// boundary on the double-quoted positions: the name and the truthy owner
// may not carry the double quote, with the exact value-free stable error
// naming the argument key.
func TestPostgresTablespaceCreateInjection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ts    string
		owner *string
		want  string
	}{
		{`name quote`, `ts" )`, postgresString("own"), "postgres: invalid argument: unsupported quote character in name"},
		{"owner quote", "ts", postgresString(`own"; DROP TABLESPACE x; --`), "postgres: invalid argument: unsupported quote character in owner"},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
			Name:     tc.ts,
			Location: "/srv/ts",
			Owner:    tc.owner,
		})
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// wantTablespaceAlterStatements is the pinned four-statement sequence in
// the pinned clause order: RENAME TO, OWNER TO, SET, RESET.
var wantTablespaceAlterStatements = []string{
	`ALTER TABLESPACE "test_tablespace" RENAME TO "test_tablespace2"`,
	`ALTER TABLESPACE "test_tablespace" OWNER TO "testuser"`,
	`ALTER TABLESPACE "test_tablespace" SET (seq_page_cost = 1.1)`,
	`ALTER TABLESPACE "test_tablespace" RESET (seq_page_cost)`,
}

// TestPostgresTablespaceAlterArgvAndResult ports the pinned
// test_tablespace_alter_new_name and test_tablespace_alter_new_owner —
// each statement byte-for-byte on the full pinned argv (SQL at index 14)
// — and the SET/RESET statements of the pinned docstring examples on the
// same transport.
func TestPostgresTablespaceAlterArgvAndResult(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  *TablespaceAlterArgs
		calls int
		want  []string
	}{
		{
			"new owner (pinned)",
			&TablespaceAlterArgs{
				Name:          "test_tablespace",
				NewOwner:      postgresString("testuser"),
				User:          postgresString("testuser"),
				Host:          postgresString("testhost"),
				Port:          postgresString("testport"),
				MaintenanceDB: postgresString("maint_db"),
				Password:      postgresString("foo"),
			},
			1,
			[]string{wantTablespaceAlterStatements[1]},
		},
		{
			"new name (pinned)",
			&TablespaceAlterArgs{
				Name:          "test_tablespace",
				NewName:       postgresString("test_tablespace2"),
				User:          postgresString("testuser"),
				Host:          postgresString("testhost"),
				Port:          postgresString("testport"),
				MaintenanceDB: postgresString("maint_db"),
				Password:      postgresString("foo"),
			},
			1,
			[]string{wantTablespaceAlterStatements[0]},
		},
		{
			"set option",
			&TablespaceAlterArgs{
				Name:      "test_tablespace",
				SetOption: map[string]string{"seq_page_cost": "1.1"},
			},
			1,
			[]string{wantTablespaceAlterStatements[2]},
		},
		{
			"reset option",
			&TablespaceAlterArgs{
				Name:        "test_tablespace",
				ResetOption: postgresString("seq_page_cost"),
			},
			1,
			[]string{wantTablespaceAlterStatements[3]},
		},
		{
			"all four clauses in the pinned order",
			&TablespaceAlterArgs{
				Name:        "test_tablespace",
				NewName:     postgresString("test_tablespace2"),
				NewOwner:    postgresString("testuser"),
				SetOption:   map[string]string{"seq_page_cost": "1.1"},
				ResetOption: postgresString("seq_page_cost"),
			},
			4,
			wantTablespaceAlterStatements,
		},
	} {
		results := make([]process.CommandResult, tc.calls)
		for i := range results {
			results[i] = process.CommandResult{ExitCode: 0}
		}
		rt, runner := newPostgresRuntime(results...)
		value, err := (tablespaceAlterFunc{}).Execute(context.Background(), rt, tc.args)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if value != true {
			t.Fatalf("%s tablespace_alter = %#v, want true", tc.name, value)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s runner calls = %d, want %d", tc.name, len(runner.calls), tc.calls)
		}
		for i, command := range runner.calls {
			want := []string{
				"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
			}
			if tc.args.User != nil {
				want = append(want,
					"--username", "testuser",
					"--host", "testhost",
					"--port", "testport",
				)
			}
			if tc.args.MaintenanceDB != nil {
				want = append(want, "--dbname", "maint_db")
			} else {
				want = append(want, "--dbname", "postgres")
			}
			want = append(want, "-c", tc.want[i])
			if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s call %d argv = %q, want %q", tc.name, i, got, want)
			}
			if all := append([]string{command.Name}, command.Args...); all[len(all)-1] != tc.want[i] {
				t.Fatalf("%s call %d statement = %q, want %q", tc.name, i, all[len(all)-1], tc.want[i])
			}
			if tc.args.Password == nil {
				continue
			}
			if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
				t.Fatalf("%s call %d redact = %#v", tc.name, i, command.Redact)
			}
			if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
				t.Fatalf("%s call %d rendered command leaks password: %q", tc.name, i, rendered)
			}
		}
	}
}

// TestPostgresTablespaceAlterNoop pins the pinned any([new_name,
// new_owner, set_option, reset_option]) head: nil arguments, the
// Python-falsy explicit empty strings, and the empty map all answer the
// no-op True with no Runner invocation.
func TestPostgresTablespaceAlterNoop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		newName *string
		owner   *string
		setOpt  map[string]string
		reset   *string
	}{
		{"nothing set", nil, nil, nil, nil},
		{"new name empty", postgresString(""), nil, nil, nil},
		{"new owner empty", nil, postgresString(""), nil, nil},
		{"set option empty map", nil, nil, map[string]string{}, nil},
		{"reset option empty", nil, nil, nil, postgresString("")},
		{"all falsy", postgresString(""), postgresString(""), map[string]string{}, postgresString("")},
	} {
		rt, runner := newPostgresRuntime()
		value, err := (tablespaceAlterFunc{}).Execute(context.Background(), rt, &TablespaceAlterArgs{
			Name:        "test_tablespace",
			NewName:     tc.newName,
			NewOwner:    tc.owner,
			SetOption:   tc.setOpt,
			ResetOption: tc.reset,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if value != true {
			t.Fatalf("%s tablespace_alter = %#v, want true", tc.name, value)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands, want none", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresTablespaceAlterNonzeroRetcodeStops pins the pinned
// ret["retcode"] != 0 → False abort: the first nonzero retcode answers
// the boolean false and no later clause statement runs.
func TestPostgresTablespaceAlterNonzeroRetcodeStops(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fails int // 1-based statement index that returns nonzero
		calls int // runner calls before the stop
	}{
		{"first fails", 1, 1},
		{"second fails", 2, 2},
		{"third fails", 3, 3},
	} {
		results := make([]process.CommandResult, tc.calls)
		for i := range results {
			exit := 0
			if i+1 == tc.fails {
				exit = 3
			}
			results[i] = process.CommandResult{
				ExitCode: exit,
				Stderr:   []byte(`psql: error: ERROR: tablespace "test_tablespace" does not exist`),
			}
		}
		rt, runner := newPostgresRuntime(results...)
		value, err := (tablespaceAlterFunc{}).Execute(context.Background(), rt, &TablespaceAlterArgs{
			Name:        "test_tablespace",
			NewName:     postgresString("test_tablespace2"),
			NewOwner:    postgresString("testuser"),
			SetOption:   map[string]string{"seq_page_cost": "1.1"},
			ResetOption: postgresString("seq_page_cost"),
		})
		if err != nil {
			t.Fatalf("%s err = %v, want the retcode boolean only", tc.name, err)
		}
		if value != false {
			t.Fatalf("%s tablespace_alter = %#v, want false", tc.name, value)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s runner calls = %d, want %d", tc.name, len(runner.calls), tc.calls)
		}
		last := runner.calls[len(runner.calls)-1].Args[len(runner.calls[len(runner.calls)-1].Args)-1]
		if last != wantTablespaceAlterStatements[tc.calls-1] {
			t.Fatalf("%s last statement = %q, want %q", tc.name, last, wantTablespaceAlterStatements[tc.calls-1])
		}
	}
}

// TestPostgresTablespaceAlterInjection pins the fail-closed boundaries:
// the double-quoted identifier positions (name, new_name, new_owner),
// the raw reset_option token, the raw set_option key and value, and the
// multi-entry set_option ambiguity — every rejection value-free and
// before any Runner invocation.
func TestPostgresTablespaceAlterInjection(t *testing.T) {
	for _, tc := range []struct {
		name string
		args *TablespaceAlterArgs
		want string
	}{
		{
			"name quote",
			&TablespaceAlterArgs{Name: `ts" )`, NewOwner: postgresString("own")},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"new name quote",
			&TablespaceAlterArgs{Name: "ts", NewName: postgresString(`x"; DROP TABLESPACE y; --`)},
			"postgres: invalid argument: unsupported quote character in new_name",
		},
		{
			"new owner quote",
			&TablespaceAlterArgs{Name: "ts", NewOwner: postgresString(`own"; DROP TABLESPACE y; --`)},
			"postgres: invalid argument: unsupported quote character in new_owner",
		},
		{
			"reset option injection",
			&TablespaceAlterArgs{Name: "ts", ResetOption: postgresString(`x) ; DROP TABLESPACE y; --`)},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"set option key injection",
			&TablespaceAlterArgs{Name: "ts", SetOption: map[string]string{`x; DROP TABLESPACE y; --`: "1"}},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"set option value injection",
			&TablespaceAlterArgs{Name: "ts", SetOption: map[string]string{"seq_page_cost": `1.1) ; DROP TABLESPACE y; --`}},
			"postgres: invalid argument: unsupported tablespace option value",
		},
		{
			"set option multiple entries",
			&TablespaceAlterArgs{Name: "ts", SetOption: map[string]string{"seq_page_cost": "1.1", "random_page_cost": "4.0"}},
			"postgres: invalid argument: set_option must carry exactly one tablespace option",
		},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (tablespaceAlterFunc{}).Execute(context.Background(), rt, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresTablespaceRemoveArgvAndResult ports the pinned
// test_tablespace_remove: the exact DROP TABLESPACE statement (no
// trailing semicolon) on the full pinned argv (SQL at index 14), the
// clean PG environment, password redaction, and the retcode boolean —
// including the no-preflight missing-tablespace shape: exactly one call,
// the server rejection lands in the boolean false.
func TestPostgresTablespaceRemoveArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (tablespaceRemoveFunc{}).Execute(context.Background(), rt, &TablespaceRemoveArgs{
		Name:          "test_tablespace",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("tablespace_remove = %#v, want true", value)
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
		"-c", `DROP TABLESPACE "test_tablespace"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if all := append([]string{command.Name}, command.Args...); all[14] != `DROP TABLESPACE "test_tablespace"` {
		t.Fatalf("argv[14] = %q, want the pinned DROP TABLESPACE statement", all[14])
	}
	wantEnv := []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}

	// A missing tablespace keeps the pinned shape: no preflight call, one
	// statement, and the server rejection in the boolean false.
	rt, runner = newPostgresRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`psql: error: ERROR: tablespace "test_tablespace" does not exist`),
	})
	value, err = (tablespaceRemoveFunc{}).Execute(context.Background(), rt, &TablespaceRemoveArgs{
		Name: "test_tablespace",
	})
	if err != nil {
		t.Fatalf("missing tablespace must not error: %v", err)
	}
	if value != false {
		t.Fatalf("missing tablespace = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing tablespace calls = %d, want 1 (no preflight)", len(runner.calls))
	}
}

// TestPostgresTablespaceRemoveInjection pins the fail-closed identifier
// boundary: the name may not carry the double quote, value-free and
// before any Runner invocation.
func TestPostgresTablespaceRemoveInjection(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (tablespaceRemoveFunc{}).Execute(context.Background(), rt, &TablespaceRemoveArgs{
		Name: `ts"; DROP TABLESPACE x; --`,
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in name" {
		t.Fatalf("injected name err = %v", err)
	}
	if !errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("injected name err = %v, want invalid argument", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected name executed %d commands", len(runner.calls))
	}
}

// tablespaceRejectedCalls enumerates every tablespace mutation field the
// fail-closed boundaries reject, with a rejected value embedding the
// marker and the exact value-free stable error each rejection must
// return, keyed by the registered function name the registry dispatch
// must reproduce.
func tablespaceRejectedCalls() []struct {
	fn   string
	args any
	want string
} {
	marker := postgresValidationMarker
	return []struct {
		fn   string
		args any
		want string
	}{
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts-" + marker + `"`},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts", Location: "/srv/ts", Owner: postgresString(`own-` + marker + `"`)},
			"postgres: invalid argument: unsupported quote character in owner",
		},
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts", Location: "/srv/" + marker + "'"},
			"postgres: invalid argument: unsupported quote character in location",
		},
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts", Location: marker + "/ts"},
			"postgres: invalid argument: invalid tablespace location",
		},
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts", Location: "/srv/ts", Options: map[string]string{marker: "1"}},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"postgres.tablespace_create",
			&TablespaceCreateArgs{Name: "ts", Location: "/srv/ts", Options: map[string]string{"seq_page_cost": marker}},
			"postgres: invalid argument: unsupported tablespace option value",
		},
		{
			"postgres.tablespace_alter",
			&TablespaceAlterArgs{Name: "ts-" + marker + `"`, NewOwner: postgresString("own")},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"postgres.tablespace_alter",
			&TablespaceAlterArgs{Name: "ts", NewName: postgresString(`x-` + marker + `"`)},
			"postgres: invalid argument: unsupported quote character in new_name",
		},
		{
			"postgres.tablespace_alter",
			&TablespaceAlterArgs{Name: "ts", NewOwner: postgresString(`x-` + marker + `"`)},
			"postgres: invalid argument: unsupported quote character in new_owner",
		},
		{
			"postgres.tablespace_alter",
			&TablespaceAlterArgs{Name: "ts", ResetOption: postgresString(marker)},
			"postgres: invalid argument: unsupported tablespace option name",
		},
		{
			"postgres.tablespace_alter",
			&TablespaceAlterArgs{Name: "ts", SetOption: map[string]string{"seq_page_cost": "1.1", marker: "4.0"}},
			"postgres: invalid argument: set_option must carry exactly one tablespace option",
		},
		{
			"postgres.tablespace_remove",
			&TablespaceRemoveArgs{Name: `ts-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in name",
		},
	}
}

// TestPostgresTablespaceValidationErrorsRedacted repeats every rejected
// tablespace field with a value embedding the same synthetic marker as
// the connection password, both direct and through the ExecRegistry
// dispatch (the path the CLI drives): the error must be exactly the
// stable value-free message under the invalid-argument category — never
// the rejected value, so the marker cannot leak — and no Runner call may
// happen.
func TestPostgresTablespaceValidationErrorsRedacted(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range tablespaceRejectedCalls() {
		setPassword(tc.args, postgresString(postgresValidationMarker))
		rt, runner := newPostgresRuntime()
		var execErr error
		switch args := tc.args.(type) {
		case *TablespaceCreateArgs:
			_, execErr = (tablespaceCreateFunc{}).Execute(context.Background(), rt, args)
		case *TablespaceAlterArgs:
			_, execErr = (tablespaceAlterFunc{}).Execute(context.Background(), rt, args)
		case *TablespaceRemoveArgs:
			_, execErr = (tablespaceRemoveFunc{}).Execute(context.Background(), rt, args)
		}
		if execErr == nil || execErr.Error() != tc.want {
			t.Fatalf("%s direct err = %v, want %q", tc.fn, execErr, tc.want)
		}
		if !errors.Is(execErr, errPostgresInvalidArgument) {
			t.Fatalf("%s direct err = %v, want invalid argument", tc.fn, execErr)
		}
		if strings.Contains(execErr.Error(), postgresValidationMarker) {
			t.Fatalf("%s direct error leaks the rejected value: %v", tc.fn, execErr)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s direct executed %d commands", tc.fn, len(runner.calls))
		}

		rt, runner = newPostgresRuntime()
		_, registryErr := reg.Call(context.Background(), rt, tc.fn, tc.args)
		if registryErr == nil || registryErr.Error() != tc.want {
			t.Fatalf("%s registry err = %v, want %q", tc.fn, registryErr, tc.want)
		}
		if strings.Contains(registryErr.Error(), postgresValidationMarker) {
			t.Fatalf("%s registry error leaks the rejected value: %v", tc.fn, registryErr)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s registry executed %d commands", tc.fn, len(runner.calls))
		}
	}
}

// setPassword stamps the connection password on any tablespace args
// struct for the marker-overlap redaction tests.
func setPassword(args any, password *string) {
	switch a := args.(type) {
	case *TablespaceCreateArgs:
		a.Password = password
	case *TablespaceAlterArgs:
		a.Password = password
	case *TablespaceRemoveArgs:
		a.Password = password
	}
}

// TestPostgresTablespaceGuards pins cancellation, runas rejection, psql
// unavailability, output limits, and redacted Runner errors across the
// three tablespace mutations on their first statement.
func TestPostgresTablespaceGuards(t *testing.T) {
	type guardCase struct {
		name string
		run  func(rt *runtime.Runtime, ctx context.Context) (any, error)
	}
	cases := []guardCase{
		{"create", func(rt *runtime.Runtime, ctx context.Context) (any, error) {
			return (tablespaceCreateFunc{}).Execute(ctx, rt, &TablespaceCreateArgs{Name: "ts", Location: "/srv/ts"})
		}},
		{"alter", func(rt *runtime.Runtime, ctx context.Context) (any, error) {
			return (tablespaceAlterFunc{}).Execute(ctx, rt, &TablespaceAlterArgs{Name: "ts", NewOwner: postgresString("own")})
		}},
		{"remove", func(rt *runtime.Runtime, ctx context.Context) (any, error) {
			return (tablespaceRemoveFunc{}).Execute(ctx, rt, &TablespaceRemoveArgs{Name: "ts"})
		}},
	}
	for _, gc := range cases {
		rt, runner := newPostgresRuntime()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := gc.run(rt, ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s pre-canceled ctx err = %v", gc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s canceled run executed %d commands", gc.name, len(runner.calls))
		}

		rt, runner = newPostgresRuntime()
		var runasErr error
		switch gc.name {
		case "create":
			_, runasErr = (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
				Name: "ts", Location: "/srv/ts", Runas: postgresString("postgres"),
			})
		case "alter":
			_, runasErr = (tablespaceAlterFunc{}).Execute(context.Background(), rt, &TablespaceAlterArgs{
				Name: "ts", NewOwner: postgresString("own"), Runas: postgresString("postgres"),
			})
		case "remove":
			_, runasErr = (tablespaceRemoveFunc{}).Execute(context.Background(), rt, &TablespaceRemoveArgs{
				Name: "ts", Runas: postgresString("postgres"),
			})
		}
		if !errors.Is(runasErr, errPostgresRunas) {
			t.Fatalf("%s runas err = %v", gc.name, runasErr)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s runas run executed %d commands", gc.name, len(runner.calls))
		}

		rt, runner = newPostgresRuntime()
		runner.available = map[string]bool{"psql": false}
		if _, err := gc.run(rt, context.Background()); !errors.Is(err, errPostgresPsqlUnavailable) {
			t.Fatalf("%s psql unavailable err = %v", gc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s unavailable psql executed %d commands", gc.name, len(runner.calls))
		}

		for _, truncated := range []process.CommandResult{
			{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
			{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
		} {
			rt, _ := newPostgresRuntime(truncated)
			if _, err := gc.run(rt, context.Background()); !errors.Is(err, process.ErrOutputLimit) {
				t.Fatalf("%s output limit err = %v", gc.name, err)
			}
		}
	}

	// A raw Runner error carrying the password stays redacted on every
	// mutation's first statement.
	for _, tc := range []struct {
		name string
		run  func(rt *runtime.Runtime) (any, error)
	}{
		{
			"create",
			func(rt *runtime.Runtime) (any, error) {
				return (tablespaceCreateFunc{}).Execute(context.Background(), rt, &TablespaceCreateArgs{
					Name: "ts", Location: "/srv/ts", Password: postgresString("foo"),
				})
			},
		},
		{
			"alter",
			func(rt *runtime.Runtime) (any, error) {
				return (tablespaceAlterFunc{}).Execute(context.Background(), rt, &TablespaceAlterArgs{
					Name: "ts", NewOwner: postgresString("own"), Password: postgresString("foo"),
				})
			},
		},
		{
			"remove",
			func(rt *runtime.Runtime) (any, error) {
				return (tablespaceRemoveFunc{}).Execute(context.Background(), rt, &TablespaceRemoveArgs{
					Name: "ts", Password: postgresString("foo"),
				})
			},
		},
	} {
		rt, _ := newPostgresRuntime(process.CommandResult{
			ExitCode: -1,
			Err:      fmt.Errorf("exec psql --dbname postgres: secret foo rejected"),
		})
		_, err := tc.run(rt)
		if err == nil || strings.Contains(err.Error(), "foo") {
			t.Fatalf("%s runner error must be redacted: %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
			t.Fatalf("%s error lacks redaction placeholder: %v", tc.name, err)
		}
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

// postgresStubFS wraps a real FileSystem with selected failures so the
// datadir family's Runtime.FS boundaries stay testable hermetically: a
// denied Lstat (permission), a failing temp write, and a failing cleanup.
// failMkdirErr/failWriteErr override the default EACCES shapes so the
// raw filesystem errors can carry synthetic password, path, and stderr
// markers the surfaced datadir errors must not contain.
type postgresStubFS struct {
	runtime.FileSystem
	denyLstat    map[string]bool
	failMkdir    bool
	failWrite    bool
	failRemove   bool
	failMkdirErr error
	failWriteErr error
	writtenPath  string
}

func (f *postgresStubFS) Lstat(name string) (fs.FileInfo, error) {
	if f.denyLstat[name] {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: syscall.EACCES}
	}
	return f.FileSystem.Lstat(name)
}

func (f *postgresStubFS) MkdirTemp(dir, pattern string) (string, error) {
	if f.failMkdir {
		if f.failMkdirErr != nil {
			return "", f.failMkdirErr
		}
		return "", &fs.PathError{Op: "mkdirtemp", Path: dir, Err: syscall.EACCES}
	}
	return f.FileSystem.MkdirTemp(dir, pattern)
}

func (f *postgresStubFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if f.failWrite {
		if f.failWriteErr != nil {
			return f.failWriteErr
		}
		return &fs.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	f.writtenPath = name
	return f.FileSystem.WriteFile(name, data, perm)
}

func (f *postgresStubFS) RemoveAll(pathName string) error {
	if f.failRemove {
		return &fs.PathError{Op: "remove", Path: pathName, Err: syscall.EACCES}
	}
	return f.FileSystem.RemoveAll(pathName)
}

// seedDatadir writes the two pinned marker files into dir on fsys.
func seedDatadir(t *testing.T, fsys runtime.FileSystem, dir string) {
	t.Helper()
	if err := fsys.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"PG_VERSION", "postgresql.conf"} {
		if err := fsys.WriteFile(path.Join(dir, marker), []byte("9.6\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// tmpEntries returns the paths created under the MemoryFS temp root.
func tmpEntries(t *testing.T, fsys runtime.FileSystem) []string {
	t.Helper()
	memory, ok := fsys.(*runtime.MemoryFS)
	if !ok {
		return nil
	}
	entries, err := memory.Glob("/tmp/*")
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// TestPostgresDatadirExistsShapes pins the pinned marker-file probe
// (postgres.py:4390-4393) over the fake FS: both PG_VERSION and
// postgresql.conf must be regular files for True, and every miss — an
// absent marker, a marker that is a directory, a marker that is a symlink
// (the no-follow boundary: the pinned os.path.isfile would follow it), a
// name that is not a directory, and a permission error — answers the
// pinned boolean False exactly like os.path.isfile swallows OSError.
func TestPostgresDatadirExistsShapes(t *testing.T) {
	cases := []struct {
		name string
		seed func(t *testing.T, fsys runtime.FileSystem)
		want bool
	}{
		{"both markers", func(t *testing.T, fsys runtime.FileSystem) {
			seedDatadir(t, fsys, "/var/lib/pgsql/data")
		}, true},
		{"empty directory", func(t *testing.T, fsys runtime.FileSystem) {
			if err := fsys.MkdirAll("/var/lib/pgsql/data", 0o700); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"only PG_VERSION", func(t *testing.T, fsys runtime.FileSystem) {
			if err := fsys.MkdirAll("/var/lib/pgsql/data", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/lib/pgsql/data/PG_VERSION", []byte("9.6\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"only postgresql.conf", func(t *testing.T, fsys runtime.FileSystem) {
			if err := fsys.MkdirAll("/var/lib/pgsql/data", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/lib/pgsql/data/postgresql.conf", []byte(""), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"PG_VERSION is a directory", func(t *testing.T, fsys runtime.FileSystem) {
			if err := fsys.MkdirAll("/var/lib/pgsql/data/PG_VERSION", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/lib/pgsql/data/postgresql.conf", []byte(""), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"PG_VERSION is a symlink to a regular file", func(t *testing.T, fsys runtime.FileSystem) {
			seedDatadir(t, fsys, "/var/lib/pgsql/data")
			if err := fsys.WriteFile("/version.txt", []byte("9.6\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Remove("/var/lib/pgsql/data/PG_VERSION"); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Symlink("/version.txt", "/var/lib/pgsql/data/PG_VERSION"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"postgresql.conf is a symlink to a regular file", func(t *testing.T, fsys runtime.FileSystem) {
			seedDatadir(t, fsys, "/var/lib/pgsql/data")
			if err := fsys.WriteFile("/conf.txt", []byte(""), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Remove("/var/lib/pgsql/data/postgresql.conf"); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Symlink("/conf.txt", "/var/lib/pgsql/data/postgresql.conf"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"name is a regular file", func(t *testing.T, fsys runtime.FileSystem) {
			if err := fsys.MkdirAll("/var/lib", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/lib/pgsql", []byte("not a dir"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"absent name", func(t *testing.T, fsys runtime.FileSystem) {}, false},
	}
	for _, tc := range cases {
		rt, _ := newPostgresRuntime()
		tc.seed(t, rt.FS)
		value, err := (datadirExistsFunc{}).Execute(context.Background(), rt, &DataDirExistsArgs{Name: "/var/lib/pgsql/data"})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if value != tc.want {
			t.Fatalf("%s datadir_exists = %#v, want %v", tc.name, value, tc.want)
		}
	}

	// A denied Lstat is the pinned os.path.isfile False, never an error.
	rt, _ := newPostgresRuntime()
	seedDatadir(t, rt.FS, "/var/lib/pgsql/data")
	rt.FS = &postgresStubFS{FileSystem: rt.FS, denyLstat: map[string]bool{"/var/lib/pgsql/data/PG_VERSION": true}}
	value, err := (datadirExistsFunc{}).Execute(context.Background(), rt, &DataDirExistsArgs{Name: "/var/lib/pgsql/data"})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("denied lstat datadir_exists = %#v, want false", value)
	}

	// A runtime without an FS fails closed instead of panicking: the probe
	// answers False, the mutation answers the fixed unavailability error.
	rt, _ = newPostgresRuntime()
	rt.FS = nil
	if value, err := (datadirExistsFunc{}).Execute(context.Background(), rt, &DataDirExistsArgs{Name: "/var/lib/pgsql/data"}); err != nil || value != false {
		t.Fatalf("nil FS datadir_exists = (%#v, %v), want (false, nil)", value, err)
	}
	if _, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"}); !errors.Is(err, errPostgresFSUnavailable) {
		t.Fatalf("nil FS datadir_init err = %v", err)
	}
}

// TestPostgresDatadirExistsValidation pins the value-free datadir path
// boundary: empty, relative, unclean, and control-carrying names are
// rejected before any filesystem access, direct and through the registry
// dispatch the CLI drives, and the registered happy path answers over the
// seeded markers.
func TestPostgresDatadirExistsValidation(t *testing.T) {
	for _, name := range []string{
		"",
		"var/lib/pgsql/data",
		"/var/lib/pgsql/../pgsql/data",
		"/var/lib//pgsql/data",
		"/var/lib/pgsql/data/",
		"/var/lib/pgsql/da\x00ta",
		"/var/lib/pgsql/da\x1bta",
		"/var/lib/pgsql/da\nta",
	} {
		rt, _ := newPostgresRuntime()
		_, err := (datadirExistsFunc{}).Execute(context.Background(), rt, &DataDirExistsArgs{Name: name})
		if !errors.Is(err, errPostgresInvalidDataDirPath) {
			t.Fatalf("name %q err = %v, want the fixed data-directory rejection", name, err)
		}
		if name != "" && strings.Contains(err.Error(), name) {
			t.Fatalf("rejection leaks the rejected path: %v", err)
		}
		if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
			t.Fatalf("name %q touched the temp root: %q", name, entries)
		}
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newPostgresRuntime()
	seedDatadir(t, rt.FS, "/var/lib/pgsql/data")
	value, err := reg.Call(context.Background(), rt, "postgres.datadir_exists", &DataDirExistsArgs{Name: "/var/lib/pgsql/data"})
	if err != nil || value != true {
		t.Fatalf("registry datadir_exists = (%#v, %v), want (true, nil)", value, err)
	}
	_, err = reg.Call(context.Background(), rt, "postgres.datadir_exists", &DataDirExistsArgs{Name: "relative/path"})
	if !errors.Is(err, errPostgresInvalidDataDirPath) {
		t.Fatalf("registry validation err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("registry probe executed %d commands", len(runner.calls))
	}
}

// TestPostgresDatadirInitArgvAndResult drives the pinned
// test__run_initdb_with_timeout vector (the pinned runas argument is
// rejected by the single-user runtime, so the --username it would have
// contributed is supplied directly, and the pinned relative fakename
// name becomes the absolute /fakename the datadir path boundary
// requires — the only two adaptations; every argv byte between them is
// the pinned vector): the byte-exact pinned argv, the clean empty
// environment, no stdin, shell-free central Runner execution with the
// shared bounds, the retcode boolean, and the registry dispatch.
func TestPostgresDatadirInitArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name: "/fakename",
		User: postgresString("saltuser"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("datadir_init = %#v, want true", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := []string{
		"initdb",
		"--pgdata=/fakename",
		"--username=saltuser",
		"--auth=password",
		"--encoding=UTF8",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("env = %q, want clean empty non-nil environment", command.Env)
	}
	if command.Shell {
		t.Fatal("initdb must run without a shell")
	}
	if command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe command bounds: %#v", command)
	}
	if len(command.Stdin) != 0 || command.Dir != "" || command.WindowsCmdLine != "" {
		t.Fatalf("unexpected command payload: %#v", command)
	}
	if command.Redact != nil {
		t.Fatalf("no-password run carries redact secrets: %q", command.Redact)
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("no-password run left temp entries: %q", entries)
	}

	// The same dispatch through the registry the CLI drives.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err = reg.Call(context.Background(), rt, "postgres.datadir_init", &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	if err != nil || value != true {
		t.Fatalf("registry datadir_init = (%#v, %v), want (true, nil)", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("registry runner calls = %d, want 1", len(runner.calls))
	}
	if got := runner.calls[0].Args[0]; got != "--pgdata=/var/lib/pgsql/data" {
		t.Fatalf("registry argv[1] = %q", got)
	}
}

// TestPostgresDatadirInitDefaults pins the omitted-argument shape: the
// pinned user default (the effective postgres runas default the pinned
// helper resolves), the pinned auth and encoding literal defaults, and
// the omitted locale, -X waldir, checksums, and pwfile entries.
func TestPostgresDatadirInitDefaults(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("datadir_init = %#v, want true", value)
	}
	want := []string{
		"initdb",
		"--pgdata=/var/lib/pgsql/data",
		"--username=postgres",
		"--auth=password",
		"--encoding=UTF8",
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

// TestPostgresDatadirInitFullArgv pins the full pinned argv order with
// every optional entry present — --locale, the pinned short -X waldir
// pair before --data-checksums, and --pwfile last — plus the pwfile
// transport: the exact password bytes with no trailing newline at 0600
// inside a private temp directory, the password as the only Redact
// secret, and the removal of file and directory after initdb runs.
func TestPostgresDatadirInitFullArgv(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:      "/var/lib/pgsql/data",
		Auth:      postgresString("md5"),
		User:      postgresString("testuser"),
		Password:  postgresString("testpassword"),
		Encoding:  postgresString("LATIN1"),
		Locale:    postgresString("en_US.UTF-8"),
		WalDir:    postgresString("/var/lib/postgresql/wal"),
		Checksums: postgresBool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("datadir_init = %#v, want true", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 10 {
		t.Fatalf("argv = %q, want 10 entries", argv)
	}
	wantHead := []string{
		"initdb",
		"--pgdata=/var/lib/pgsql/data",
		"--username=testuser",
		"--auth=md5",
		"--encoding=LATIN1",
		"--locale=en_US.UTF-8",
		"-X", "/var/lib/postgresql/wal",
		"--data-checksums",
	}
	if !reflect.DeepEqual(argv[:9], wantHead) {
		t.Fatalf("argv head = %q, want %q", argv[:9], wantHead)
	}
	if !strings.HasPrefix(argv[9], "--pwfile=") {
		t.Fatalf("argv[9] = %q, want the --pwfile entry", argv[9])
	}
	pwPath := strings.TrimPrefix(argv[9], "--pwfile=")
	if path.Base(pwPath) != "pwfile" {
		t.Fatalf("pwfile base = %q", path.Base(pwPath))
	}
	if strings.Contains(argv[9], "testpassword") {
		t.Fatalf("pwfile argv leaks the password: %q", argv[9])
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q, want the password only", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "testpassword") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}

	// The pwfile held exactly the password bytes and both file and temp
	// directory are gone after the run.
	if data, err := rt.FS.ReadFile(pwPath); err == nil {
		t.Fatalf("pwfile survived the run: %q", data)
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("temp entries survived: %q", entries)
	}
}

// postgresPwfileCaptureFS records the pwfile write so the exact bytes and
// mode can be asserted before the cleanup removes them.
type postgresPwfileCaptureFS struct {
	runtime.FileSystem
	path string
	data []byte
	perm fs.FileMode
}

func (f *postgresPwfileCaptureFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if path.Base(name) == "pwfile" {
		f.path, f.perm = name, perm
		f.data = append([]byte(nil), data...)
	}
	return f.FileSystem.WriteFile(name, data, perm)
}

// TestPostgresDatadirInitPwfileBytes pins the pinned pwfile content: the
// exact password with no trailing newline (fp_.write(f"{password}")), the
// 0600 mode, and the password's absence from argv and the environment.
func TestPostgresDatadirInitPwfileBytes(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	capture := &postgresPwfileCaptureFS{FileSystem: rt.FS}
	rt.FS = capture
	if _, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("s3cr3t pass"),
	}); err != nil {
		t.Fatal(err)
	}
	if capture.path == "" || string(capture.data) != "s3cr3t pass" {
		t.Fatalf("pwfile = (%q, %q), want the exact password bytes", capture.path, capture.data)
	}
	if capture.perm != 0o600 {
		t.Fatalf("pwfile mode = %o, want 0600", capture.perm)
	}
}

// TestPostgresDatadirInitExistingNoop pins the pinned datadir_exists
// preflight head: an initialized directory answers the logged-and-False
// no-op with no initdb invocation and no pwfile write at all.
func TestPostgresDatadirInitExistingNoop(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	seedDatadir(t, rt.FS, "/var/lib/pgsql/data")
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("datadir_init existing = %#v, want false", value)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("existing datadir executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("existing datadir wrote temp entries: %q", entries)
	}
}

// TestPostgresDatadirInitNonzeroExitIsFalse pins the pinned tail
// ret["retcode"] == 0: a rejected initdb is the boolean false, never an
// error, and captured output carrying the password stays redacted.
func TestPostgresDatadirInitNonzeroExitIsFalse(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`initdb: error: directory "/var/lib/pgsql/data" exists but is not empty`),
	})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	if err != nil {
		t.Fatalf("nonzero exit must not error: %v", err)
	}
	if value != false {
		t.Fatalf("datadir_init = %#v, want false", value)
	}

	// A failing stderr that echoes the password stays redacted.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte("initdb: error: read pwfile: wrong password testpassword"),
	})
	value, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("password run datadir_init = %#v, want false", value)
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("failed run left temp entries: %q", entries)
	}
}

// TestPostgresDatadirInitEmptyWaldirShape pins the pinned waldir is not
// None gate: an explicit empty string still appends the -X pair with the
// empty element, exactly like the pinned source.
func TestPostgresDatadirInitEmptyWaldirShape(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 1})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:   "/var/lib/pgsql/data",
		WalDir: postgresString(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("datadir_init empty waldir = %#v, want the retcode false", value)
	}
	argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	want := []string{
		"initdb",
		"--pgdata=/var/lib/pgsql/data",
		"--username=postgres",
		"--auth=password",
		"--encoding=UTF8",
		"-X", "",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
}

// TestPostgresDatadirInitPathInjection pins the fail-closed value-free
// path boundary for both path arguments: relative, traversal, unclean,
// and control-carrying names and waldirs are rejected before any Runner
// invocation or pwfile write, and the errors name no rejected value.
func TestPostgresDatadirInitPathInjection(t *testing.T) {
	for _, tc := range []struct {
		label  string
		name   string
		waldir *string
	}{
		{"relative name", "var/lib/pgsql/data", nil},
		{"name traversal", "/var/lib/pgsql/../pgsql/data", nil},
		{"name double slash", "/var/lib//pgsql/data", nil},
		{"name trailing slash", "/var/lib/pgsql/data/", nil},
		{"name control byte", "/var/lib/pgsql/da\x1bta", nil},
		{"name newline", "/var/lib/pgsql/da\nta", nil},
		{"name empty", "", nil},
		{"relative waldir", "/var/lib/pgsql/data", postgresString("relwal")},
		{"waldir traversal", "/var/lib/pgsql/data", postgresString("/traverse/../x")},
		{"waldir control byte", "/var/lib/pgsql/data", postgresString("/wa\x1bl")},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
			Name:     tc.name,
			WalDir:   tc.waldir,
			Password: postgresString("pw-secret"),
		})
		wantErr := errPostgresInvalidDataDirPath
		if tc.waldir != nil {
			wantErr = errPostgresInvalidWalDirPath
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s err = %v", tc.label, err)
		}
		if tc.name != "" && strings.Contains(err.Error(), tc.name) {
			t.Fatalf("%s rejection leaks the rejected path: %v", tc.label, err)
		}
		if waldir := pointerString(tc.waldir); waldir != "" && strings.Contains(err.Error(), waldir) {
			t.Fatalf("%s rejection leaks the rejected waldir: %v", tc.label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.label, len(runner.calls))
		}
		if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
			t.Fatalf("%s wrote temp entries: %q", tc.label, entries)
		}
	}

	// The same rejections through the registry dispatch, with a synthetic
	// secret overlap in the password.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newPostgresRuntime()
	_, err := reg.Call(context.Background(), rt, "postgres.datadir_init", &DataDirInitArgs{
		Name:     "../escape",
		Password: postgresString("secretpw"),
	})
	if !errors.Is(err, errPostgresInvalidDataDirPath) {
		t.Fatalf("registry path err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("registry rejection executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("registry rejection wrote temp entries: %q", entries)
	}
}

// TestPostgresDatadirInitRunasRejected pins the runas boundary before any
// observable action: an explicit runas is rejected before the read-only
// preflight runs, and the pinned implicit default (nil) stays accepted.
func TestPostgresDatadirInitRunasRejected(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:  "/var/lib/pgsql/data",
		Runas: postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("runas run wrote temp entries: %q", entries)
	}
	// An explicit empty-string runas is the pinned falsy no-runas and
	// stays accepted exactly like nil.
	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0})
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:  "/var/lib/pgsql/data",
		Runas: postgresString(""),
	})
	if err != nil || value != true {
		t.Fatalf("empty runas datadir_init = (%#v, %v)", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("empty runas executed %d commands", len(runner.calls))
	}
}

// TestPostgresDatadirInitGuards pins cancellation, initdb
// unavailability, output limits, and the redacted Runner error on the
// mutation's single statement.
func TestPostgresDatadirInitGuards(t *testing.T) {
	run := func(rt *runtime.Runtime, ctx context.Context) (any, error) {
		return (datadirInitFunc{}).Execute(ctx, rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	}

	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := run(rt, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	rt.Runner = nil
	if _, err := run(rt, context.Background()); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v", err)
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"initdb": false}
	if _, err := run(rt, context.Background()); !errors.Is(err, errPostgresInitdbUnavailable) {
		t.Fatalf("initdb unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable initdb executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("unavailable initdb wrote temp entries: %q", entries)
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newPostgresRuntime(truncated)
		if _, err := run(rt, context.Background()); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	// A raw Runner error carrying the password stays redacted.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec initdb --pgdata=x: pwfile testpassword rejected"),
	})
	_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err == nil || strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
	// The cleanup ran despite the run error.
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("failed run left temp entries: %q", entries)
	}
}

// TestPostgresDatadirInitTestMode pins the process-wide test-mode
// no-mutation contract: with a missing datadir the answer is the nil
// would-change prediction with no pwfile write and no Runner invocation,
// and with an initialized datadir the pinned logged-and-False no-op still
// applies because the preflight is read-only.
func TestPostgresDatadirInitTestMode(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	rt.Options.Test = true
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("test-mode datadir_init = %#v, want nil", value)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("test-mode run executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("test-mode run wrote temp entries: %q", entries)
	}

	seedDatadir(t, rt.FS, "/var/lib/pgsql/data")
	value, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("test-mode existing datadir_init = %#v, want the pinned false", value)
	}
}

// TestPostgresDatadirInitPwfileFailures pins the pwfile transport's
// fail-closed boundaries: a failing temp write or MkdirTemp errors before
// any Runner invocation (and removes the temp directory), and a failing
// cleanup after a successful run is the fixed value-free
// errPostgresPwfileCleanup rather than a silent credential left on disk.
func TestPostgresDatadirInitPwfileFailures(t *testing.T) {
	rt, runner := newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: rt.FS, failMkdir: true}
	_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err == nil || strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("mkdirtemp failure must be a clean error: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("mkdirtemp failure executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: rt.FS, failWrite: true}
	_, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err == nil {
		t.Fatal("pwfile write failure must error")
	}
	if strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("write failure leaks the password: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("write failure executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, rt.FS); len(entries) != 0 {
		t.Fatalf("write failure left the temp directory: %q", entries)
	}

	rt, runner = newPostgresRuntime(process.CommandResult{ExitCode: 0})
	rt.FS = &postgresStubFS{FileSystem: rt.FS, failRemove: true}
	value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if !errors.Is(err, errPostgresPwfileCleanup) {
		t.Fatalf("cleanup failure err = %v, want the fixed cleanup error", err)
	}
	if strings.Contains(err.Error(), "testpassword") {
		t.Fatalf("cleanup failure leaks the password: %v", err)
	}
	if value != nil {
		t.Fatalf("cleanup failure value = %#v, want nil", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("cleanup-failure run executed %d commands", len(runner.calls))
	}

	// A primary Runner error keeps its sentinel semantics over the
	// cleanup failure.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec initdb: canceled"),
	})
	rt.FS = &postgresStubFS{FileSystem: rt.FS, failRemove: true}
	_, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString("testpassword"),
	})
	if err == nil || !strings.Contains(err.Error(), "exec initdb") {
		t.Fatalf("primary run error must win: %v", err)
	}
}

// TestPostgresDatadirInitPwfileErrorRedaction pins the value-free
// passthrough of the pwfile transport's preparation failures: a faulting
// filesystem whose MkdirTemp/WriteFile errors carry synthetic password,
// path, and stderr markers surfaces only the fixed sentinels — the raw
// filesystem rendering (an *fs.PathError names the credential-holding
// temp location) never travels — asserted direct and through the
// registry, with zero Runner invocations and no temp mutation.
func TestPostgresDatadirInitPwfileErrorRedaction(t *testing.T) {
	const (
		passwordMarker = "synthetic-pwfile-password"
		pathMarker     = "/synthetic/pwfile-path-marker"
		stderrMarker   = "synthetic pwfile stderr marker"
	)
	markers := []string{passwordMarker, pathMarker, stderrMarker}
	assertClean := func(label string, err error, want error, memory *runtime.MemoryFS, runner *postgresFakeRunner) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("%s err = %v, want %v", label, err, want)
		}
		if err.Error() != want.Error() {
			t.Fatalf("%s renders %q, want the exact sentinel %q", label, err, want)
		}
		for _, marker := range markers {
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("%s leaks the marker %q: %v", label, marker, err)
			}
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", label, len(runner.calls))
		}
		if entries := tmpEntries(t, memory); len(entries) != 0 {
			t.Fatalf("%s touched the temp root: %q", label, entries)
		}
	}

	// MkdirTemp failure: the fixed temp-dir category only.
	memory := runtime.NewMemoryFS()
	rt, runner := newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: memory, failMkdir: true, failMkdirErr: fmt.Errorf(
		"mkdir %s: %s: %s", pathMarker, passwordMarker, stderrMarker)}
	_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	assertClean("mkdirtemp failure", err, errPostgresPwfileTempDir, memory, runner)

	// WriteFile failure: the fixed write category only, and the temp
	// directory the failed write lived in is removed.
	memory = runtime.NewMemoryFS()
	rt, runner = newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: memory, failWrite: true, failWriteErr: fmt.Errorf(
		"open %s/pwfile: wrote %s: %s", pathMarker, passwordMarker, stderrMarker)}
	_, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	assertClean("write failure", err, errPostgresPwfileWrite, memory, runner)

	// The same two failures through the registry dispatch the CLI drives.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	memory = runtime.NewMemoryFS()
	rt, runner = newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: memory, failMkdir: true, failMkdirErr: fmt.Errorf(
		"mkdir %s: %s: %s", pathMarker, passwordMarker, stderrMarker)}
	_, err = reg.Call(context.Background(), rt, "postgres.datadir_init", &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	assertClean("registry mkdirtemp failure", err, errPostgresPwfileTempDir, memory, runner)

	memory = runtime.NewMemoryFS()
	rt, runner = newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: memory, failWrite: true, failWriteErr: fmt.Errorf(
		"open %s/pwfile: wrote %s: %s", pathMarker, passwordMarker, stderrMarker)}
	_, err = reg.Call(context.Background(), rt, "postgres.datadir_init", &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	assertClean("registry write failure", err, errPostgresPwfileWrite, memory, runner)
}

// TestPostgresDatadirInitPwfileDoubleFailure pins the partial-write
// cleanup precedence: a failed write whose RemoveAll cleanup succeeds is
// the write category with the temp directory removed, and a failed write
// whose cleanup also fails joins the write category with the fixed
// errPostgresPwfileCleanup so the stranded credential stays observable
// without hiding the primary category — value-free on both paths, with
// no Runner invocation.
func TestPostgresDatadirInitPwfileDoubleFailure(t *testing.T) {
	const passwordMarker = "synthetic-double-failure-pw"

	// Full partial-write: the write fails, the cleanup succeeds.
	memory := runtime.NewMemoryFS()
	rt, runner := newPostgresRuntime()
	rt.FS = &postgresStubFS{FileSystem: memory, failWrite: true, failWriteErr: fmt.Errorf(
		"open /synthetic/pwfile: partial write of %s", passwordMarker)}
	_, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	if !errors.Is(err, errPostgresPwfileWrite) {
		t.Fatalf("partial-write err = %v, want the write category", err)
	}
	if errors.Is(err, errPostgresPwfileCleanup) {
		t.Fatalf("successful cleanup must not raise the cleanup category: %v", err)
	}
	if err.Error() != errPostgresPwfileWrite.Error() {
		t.Fatalf("partial-write renders %q, want the exact sentinel", err)
	}
	if strings.Contains(err.Error(), passwordMarker) {
		t.Fatalf("partial-write leaks the password marker: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("partial-write executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, memory); len(entries) != 0 {
		t.Fatalf("successful cleanup left the temp directory: %q", entries)
	}

	// Double failure: the write and the cleanup both fail, so the joined
	// error exposes the cleanup failure while keeping the primary write
	// category, and the stranded directory stays observable.
	memory = runtime.NewMemoryFS()
	rt, runner = newPostgresRuntime()
	rt.FS = &postgresStubFS{
		FileSystem:   memory,
		failWrite:    true,
		failRemove:   true,
		failWriteErr: fmt.Errorf("open /synthetic/pwfile: partial write of %s", passwordMarker),
	}
	_, err = (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
		Name:     "/var/lib/pgsql/data",
		Password: postgresString(passwordMarker),
	})
	if !errors.Is(err, errPostgresPwfileWrite) {
		t.Fatalf("double failure hides the primary write category: %v", err)
	}
	if !errors.Is(err, errPostgresPwfileCleanup) {
		t.Fatalf("double failure hides the cleanup category: %v", err)
	}
	if want := errPostgresPwfileWrite.Error() + "\n" + errPostgresPwfileCleanup.Error(); err.Error() != want {
		t.Fatalf("double failure renders %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), passwordMarker) {
		t.Fatalf("double failure leaks the password marker: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("double failure executed %d commands", len(runner.calls))
	}
	if entries := tmpEntries(t, memory); len(entries) != 1 {
		t.Fatalf("double-failure temp entries = %q, want the single stranded directory", entries)
	}
}

// TestPostgresDatadirInitKernelDefaultUser pins the pinned runas default
// resolution of _run_initdb through the argv: OpenBSD resolves the
// _postgresql service account, FreeBSD and the Linux families keep
// postgres, a Facts-less runtime falls back to the compile-time GOOS,
// and an explicit user (including the pinned empty-string shape) always
// overrides. The mapping is argv-only; no native initdb execution on any
// kernel is claimed.
func TestPostgresDatadirInitKernelDefaultUser(t *testing.T) {
	for _, tc := range []struct {
		label  string
		family string
		want   string
	}{
		{"openbsd", facts.FamilyOpenBSD, "_postgresql"},
		{"freebsd", facts.FamilyFreeBSD, "postgres"},
		{"debian linux", facts.FamilyDebian, "postgres"},
		{"redhat linux", facts.FamilyRedHat, "postgres"},
		{"unknown family", "", "postgres"},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
		rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: tc.family}})
		value, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
		if err != nil || value != true {
			t.Fatalf("%s datadir_init = (%#v, %v)", tc.label, value, err)
		}
		if got := runner.calls[0].Args[1]; got != "--username="+tc.want {
			t.Fatalf("%s argv username = %q, want --username=%s", tc.label, got, tc.want)
		}
	}

	// A Facts-less runtime falls back to the compile-time GOOS: the same
	// openbsd answer a real OpenBSD host would resolve, postgres
	// elsewhere (the platform the hermetic suites run on).
	want := "postgres"
	if runtime.CurrentGOOS() == "openbsd" {
		want = "_postgresql"
	}
	if got := initdbDefaultUser(nil); got != want {
		t.Fatalf("nil-runtime default user = %q, want %q", got, want)
	}
	rt, _ := newPostgresRuntime()
	if got := initdbDefaultUser(rt); got != want {
		t.Fatalf("factsless default user = %q, want %q", got, want)
	}

	// The explicit user override wins on OpenBSD, including the pinned
	// explicit empty-string shape.
	for _, tc := range []struct {
		label string
		user  string
		want  string
	}{
		{"explicit user", "pgadmin", "--username=pgadmin"},
		{"explicit postgres", "postgres", "--username=postgres"},
		{"explicit empty", "", "--username="},
	} {
		rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
		rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyOpenBSD}})
		if _, err := (datadirInitFunc{}).Execute(context.Background(), rt, &DataDirInitArgs{
			Name: "/var/lib/pgsql/data",
			User: postgresString(tc.user),
		}); err != nil {
			t.Fatalf("%s err = %v", tc.label, err)
		}
		if got := runner.calls[0].Args[1]; got != tc.want {
			t.Fatalf("%s argv username = %q, want %q", tc.label, got, tc.want)
		}
	}

	// The same kernel mapping through the registry dispatch the CLI
	// drives.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0})
	rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyOpenBSD}})
	value, err := reg.Call(context.Background(), rt, "postgres.datadir_init", &DataDirInitArgs{Name: "/var/lib/pgsql/data"})
	if err != nil || value != true {
		t.Fatalf("registry openbsd datadir_init = (%#v, %v)", value, err)
	}
	if got := runner.calls[0].Args[1]; got != "--username=_postgresql" {
		t.Fatalf("registry openbsd argv username = %q, want --username=_postgresql", got)
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

// mutationUsersCSV is the user_list catalog for the R9.2i mutation flows:
// test_username is a non-superuser role, super_role a superuser, and the
// create-flow names are absent.
const mutationUsersCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_username,f,f,f,f,f,f,,-1,,,
super_role,t,t,f,f,f,t,,-1,,,
`

// newMutationRuntime seeds the version probe and role catalog answers the
// user_create/user_update/user_remove preflights and post-checks consume.
func newMutationRuntime(results ...process.CommandResult) (*runtime.Runtime, *postgresFakeRunner) {
	catalog := process.CommandResult{ExitCode: 0, Stdout: []byte(mutationUsersCSV)}
	seed := []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")}, // version probe
		catalog,                                // user_list catalog
	}
	return newPostgresRuntime(append(seed, results...)...)
}

// userCreateStatement returns the SQL argument of the CREATE call.
func userCreateStatement(runner *postgresFakeRunner) string {
	if len(runner.calls) == 0 {
		return ""
	}
	args := runner.calls[len(runner.calls)-1].Args
	return args[len(args)-1]
}

// TestPostgresUserCreateArgvAndResult ports the pinned test_user_create
// (postgres.py:695-736 of the pinned tests): the exact statement on the
// full pinned argv with the pinned double space after WITH, the preflight
// catalog calls before it, and the retcode boolean — with the rolepassword
// redacted out of the rendered command.
func TestPostgresUserCreateArgvAndResult(t *testing.T) {
	rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:      "testuser",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_test"),
		Password:      postgresString("test_pass"),
		Login:         postgresBool(true),
		Createdb:      postgresBool(false),
		Createroles:   postgresBool(false),
		Encrypted:     false,
		Superuser:     postgresBool(false),
		Replication:   postgresBool(false),
		Rolepassword:  "test_role_pass",
		ValidUntil:    postgresString("2042-07-01"),
		Groups:        []string{"test_groups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("user_create = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight pair plus CREATE)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_test",
		"-c", `CREATE ROLE "testuser" WITH  INHERIT NOCREATEDB NOCREATEROLE ` +
			`NOSUPERUSER NOREPLICATION LOGIN UNENCRYPTED PASSWORD ` +
			`'test_role_pass' VALID UNTIL '2042-07-01'; GRANT "test_groups" TO "testuser"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if got := append([]string{command.Name}, command.Args...); got[14] != want[14] {
		t.Fatalf("argv[14] = %q, want the pinned CREATE ROLE statement", got[14])
	}
	wantEnv := []string{
		"PGPASSWORD=test_pass",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	// The full statement-carried secret set: the quote-escaped plaintext
	// literal first, then the plaintext, then the connection password.
	if !reflect.DeepEqual(command.Redact, []string{"'test_role_pass'", "test_role_pass", "test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	rendered := command.RedactedString()
	if strings.Contains(rendered, "test_role_pass") || strings.Contains(rendered, "test_pass") ||
		strings.Contains(rendered, "'test_role_pass'") {
		t.Fatalf("rendered command leaks a password: %q", rendered)
	}
}

// TestPostgresUserCreateDefaults pins the no-argument shape: the pinned
// user-typed INHERIT and LOGIN defaults are the only clauses (the pinned
// double space after WITH kept), the maintenance fallback applies, the
// environment is clean, and nothing is redacted.
func TestPostgresUserCreateDefaults(t *testing.T) {
	rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username: "plainuser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("user_create = %#v, want true", value)
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-c", `CREATE ROLE "plainuser" WITH  INHERIT LOGIN`,
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

// TestPostgresUserCreateExistsIsFalse pins the pinned preflight no-op: an
// existing role is the logged-and-False answer after exactly the two
// catalog calls, with no CREATE statement issued.
func TestPostgresUserCreateExistsIsFalse(t *testing.T) {
	rt, runner := newMutationRuntime()
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "test_username",
		Rolepassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("user_create(existing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 preflight calls only", len(runner.calls))
	}
}

// absentRoleCSV is a catalog without test_username, so create flows for
// that name reach their statement while the md5 digest stays the pinned
// md5("foobar"+"test_username") vector.
const absentRoleCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
super_role,t,t,f,f,f,t,,-1,,,
`

// newAbsentRoleRuntime seeds the version probe and a catalog whose only
// role is super_role.
func newAbsentRoleRuntime(results ...process.CommandResult) (*runtime.Runtime, *postgresFakeRunner) {
	return newPostgresRuntime(append([]process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(absentRoleCSV)},
	}, results...)...)
}

// TestPostgresUserCreateEncryptedMD5 pins the default and explicit md5
// verifier paths: the derived digest is the pinned md5(password+role) of
// the quote-doubled password, rendered behind the ENCRYPTED clause.
func TestPostgresUserCreateEncryptedMD5(t *testing.T) {
	// The pinned test_user_update_encrypted_passwd digest: md5 of
	// "foobar" + "test_username".
	const wantDigest = "md531c27e68d3771c392b52102c01be1da1"
	if got := md5Password("test_username", "foobar"); got != wantDigest {
		t.Fatalf("md5 verifier = %s, want the pinned %s", got, wantDigest)
	}
	for _, tc := range []struct {
		name      string
		encrypted any
	}{
		{"default md5", nil},
		{"explicit md5", "md5"},
		{"true is md5", true},
	} {
		rt, runner := newAbsentRoleRuntime(process.CommandResult{ExitCode: 0})
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
			Username:     "test_username",
			Encrypted:    tc.encrypted,
			Rolepassword: "foobar",
		})
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		want := `CREATE ROLE "test_username" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '` +
			wantDigest + `'`
		if got := userCreateStatement(runner); got != want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, want)
		}
		// The generated verifier joins the Redact list in both its bare
		// and quote-escaped forms, so neither the rendered command nor a
		// redacted capture ever carries the digest.
		if !reflect.DeepEqual(runner.calls[2].Redact,
			[]string{"'" + wantDigest + "'", wantDigest, "foobar"}) {
			t.Fatalf("%s redact = %q", tc.name, runner.calls[2].Redact)
		}
		if rendered := runner.calls[2].RedactedString(); strings.Contains(rendered, "foobar") ||
			strings.Contains(rendered, wantDigest) {
			t.Fatalf("%s rendered command leaks a secret: %q", tc.name, rendered)
		}
	}

	// An already-md5 password passes through untouched: the full verifier
	// value readback is the whole statement.
	rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
	_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "newuser",
		Rolepassword: "md5deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD 'md5deadbeef'`
	if got := userCreateStatement(runner); got != want {
		t.Fatalf("md5 passthrough statement = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(runner.calls[2].Redact,
		[]string{"'md5deadbeef'", "md5deadbeef"}) {
		t.Fatalf("md5 passthrough redact = %q", runner.calls[2].Redact)
	}
}

// TestPostgresUserCreateScram pins the scram-sha-256 paths: an
// already-prefixed verifier passes through verbatim as the full statement
// value, a plaintext password becomes a verifier matching the exact pinned
// SCRAM-SHA-256$iterations:salt$stored:server rendering (the $ before the
// stored key) whose keys recompute exactly from the parsed salt, the
// generated verifier is a Redact secret in both forms, and a non-ASCII
// password fails closed at the saslprep bound with a value-free error.
func TestPostgresUserCreateScram(t *testing.T) {
	rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
	passthrough := "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"
	_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "newuser",
		Encrypted:    "scram-sha-256",
		Rolepassword: passthrough,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verifier readback on create: the full value, byte-for-byte.
	want := `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '` + passthrough + `'`
	if got := userCreateStatement(runner); got != want {
		t.Fatalf("scram passthrough statement = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(runner.calls[2].Redact,
		[]string{"'" + passthrough + "'", passthrough}) {
		t.Fatalf("scram passthrough redact = %q", runner.calls[2].Redact)
	}
	if rendered := runner.calls[2].RedactedString(); strings.Contains(rendered, passthrough) {
		t.Fatalf("scram passthrough rendered command leaks the verifier: %q", rendered)
	}

	rt, runner = newMutationRuntime(process.CommandResult{ExitCode: 0})
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "newuser",
		Encrypted:    "scram-sha-256",
		Rolepassword: "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	statement := userCreateStatement(runner)
	// The generated verifier occupies the whole literal and matches the
	// pinned full-value rendering: $iterations:salt$stored:server with
	// base64 shapes for a 16-byte salt and 32-byte keys.
	match := regexp.MustCompile(
		`^CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD ` +
			`'SCRAM-SHA-256\$(\d+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)'$`).
		FindStringSubmatch(statement)
	if match == nil {
		t.Fatalf("scram statement lacks a pinned-format verifier: %q", statement)
	}
	iterations, err := strconv.Atoi(match[1])
	if err != nil || iterations != scramIterations {
		t.Fatalf("scram iterations = %q, want %d", match[1], scramIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(match[2])
	if err != nil || len(salt) != scramSaltLen {
		t.Fatalf("scram salt = %q, want %d bytes", match[2], scramSaltLen)
	}
	salted, err := pbkdf2.Key(sha256.New, "hunter2", salt, iterations, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	clientHMAC := hmac.New(sha256.New, salted)
	clientHMAC.Write([]byte("Client Key"))
	storedKey := sha256.Sum256(clientHMAC.Sum(nil))
	if got := base64.StdEncoding.EncodeToString(storedKey[:]); got != match[3] {
		t.Fatalf("scram stored key mismatch: %s != %s", got, match[3])
	}
	serverHMAC := hmac.New(sha256.New, salted)
	serverHMAC.Write([]byte("Server Key"))
	if got := base64.StdEncoding.EncodeToString(serverHMAC.Sum(nil)); got != match[4] {
		t.Fatalf("scram server key mismatch: %s != %s", got, match[4])
	}
	// The whole generated verifier is a Redact secret in both its bare
	// and quote-escaped forms.
	verifier := fmt.Sprintf("SCRAM-SHA-256$%s:%s$%s:%s", match[1], match[2], match[3], match[4])
	if !reflect.DeepEqual(runner.calls[2].Redact,
		[]string{"'" + verifier + "'", verifier, "hunter2"}) {
		t.Fatalf("scram redact = %q", runner.calls[2].Redact)
	}
	if rendered := runner.calls[2].RedactedString(); strings.Contains(rendered, verifier) ||
		strings.Contains(rendered, "hunter2") {
		t.Fatalf("scram rendered command leaks a secret: %q", rendered)
	}
	// A second generation differs: the salt is random like the pinned one.
	first := statement
	rt, runner = newMutationRuntime(process.CommandResult{ExitCode: 0})
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "newuser",
		Encrypted:    "scram-sha-256",
		Rolepassword: "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second := userCreateStatement(runner); second == first {
		t.Fatal("two scram generations produced the same verifier")
	}

	// The saslprep bound: non-ASCII fails closed after the read-only
	// preflight with a value-free error and no CREATE.
	rt, runner = newMutationRuntime()
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "newuser",
		Encrypted:    "scram-sha-256",
		Rolepassword: "påsswörd",
	})
	if err == nil || !errors.Is(err, errPostgresSaslprep) {
		t.Fatalf("non-ascii err = %v, want the saslprep bound", err)
	}
	if strings.Contains(err.Error(), "påsswörd") {
		t.Fatalf("saslprep error embeds the password: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("saslprep-bound calls = %d, want the 2 preflight calls", len(runner.calls))
	}
}

// TestPostgresUserCreateUnknownAlgorithm pins the pinned
// _maybe_encrypt_password rejection: an algorithm outside
// False/"md5"/"scram-sha-256" fails after the read-only preflight with the
// fixed value-free unknown-algorithm error and no CREATE statement. The
// synthetic overlap vectors pass the rolepassword (and the connection
// password) as the algorithm so the error's value-freeness is asserted
// against real credential overlap, not just theory.
func TestPostgresUserCreateUnknownAlgorithm(t *testing.T) {
	const rolePW = "s3cret-role-pw"
	for _, tc := range []struct {
		name      string
		encrypted any
	}{
		{"unsupported algorithm", "bogus"},
		{"boolean spelling true", "true"},
		{"boolean spelling False", "False"},
		{"rolepassword overlap", rolePW},
		{"connection password overlap", "conn-pw"},
		{"nonzero number", 7},
		{"list value", []any{"x"}},
	} {
		rt, runner := newMutationRuntime()
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
			Username:     "newuser",
			Password:     postgresString("conn-pw"),
			Encrypted:    tc.encrypted,
			Rolepassword: rolePW,
			Groups:       "grp_a",
		})
		if err == nil || err.Error() != "postgres: invalid argument: unknown password algorithm" {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if !errors.Is(err, errPostgresUnknownPasswordAlgorithm) ||
			!errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want the fixed unknown-algorithm category", tc.name, err)
		}
		// Value-free: no algorithm string, rolepassword, or connection
		// password anywhere in the returned error.
		for _, marker := range []string{"bogus", "true", "False", rolePW, "conn-pw", "grp_a", "7"} {
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("%s error leaks %q: %v", tc.name, marker, err)
			}
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %d, want the 2 preflight calls", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresUserCreatePasswordShapes pins the remaining pinned
// _role_cmd_args password and limit shapes: the bool NOPASSWORD and bare
// PASSWORD clauses, the CONNECTION LIMIT zero and value renderings, the
// quote-doubled plaintext literal with both secrets redacted, and the
// falsy valid-until NOVALID UNTIL clause.
func TestPostgresUserCreatePasswordShapes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     UserCreateArgs
		want     string
		redact   []string
		wantFail bool
	}{
		{
			name: "bool false is NOPASSWORD",
			args: UserCreateArgs{Username: "u", Rolepassword: false, Inherit: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  NOINHERIT LOGIN NOPASSWORD`,
		},
		{
			name: "bool true is bare PASSWORD",
			args: UserCreateArgs{Username: "u", Rolepassword: true},
			want: `CREATE ROLE "u" WITH  INHERIT LOGIN PASSWORD`,
		},
		{
			name: "empty string password is skipped",
			args: UserCreateArgs{Username: "u", Rolepassword: "", Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN`,
		},
		{
			name: "connlimit zero",
			args: UserCreateArgs{Username: "u", Connlimit: postgresInt64(0), Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN NOCONNECTION LIMIT 0`,
		},
		{
			name: "connlimit value",
			args: UserCreateArgs{Username: "u", Connlimit: postgresInt64(10), Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN CONNECTION LIMIT 10`,
		},
		{
			name: "quote-doubled plaintext",
			args: UserCreateArgs{Username: "u", Encrypted: false, Rolepassword: "pa'ss", Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN UNENCRYPTED PASSWORD 'pa''ss'`,
			// The quote-escaped literal, the doubled plaintext, and the
			// plaintext itself.
			redact: []string{"'pa''ss'", "pa''ss", "pa'ss"},
		},
		{
			name: "falsy valid until",
			args: UserCreateArgs{Username: "u", ValidUntil: postgresString(""), Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN NOVALID UNTIL`,
		},
		{
			name: "quote-doubled valid until",
			args: UserCreateArgs{Username: "u", ValidUntil: postgresString("2042-01-01'; DROP ROLE x"), Login: postgresBool(false)},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN VALID UNTIL '2042-01-01''; DROP ROLE x'`,
		},
	} {
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &tc.args)
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
		command := runner.calls[2]
		if tc.redact != nil {
			if !reflect.DeepEqual(command.Redact, tc.redact) {
				t.Fatalf("%s redact = %q, want %q", tc.name, command.Redact, tc.redact)
			}
			for _, secret := range tc.redact {
				if strings.Contains(command.RedactedString(), secret) {
					t.Fatalf("%s rendered command leaks %q: %q", tc.name, secret,
						command.RedactedString())
				}
			}
		} else if command.Redact != nil {
			t.Fatalf("%s redact = %q, want none", tc.name, command.Redact)
		}
	}
}

// TestPostgresUserCreateGroupGrant pins the pinned type-preserving groups
// semantics: a string splits on the comma without trimming and without
// dropping empty elements (source exact), a []string keeps its exact
// elements and order through the join-then-split, the falsy shapes (empty
// string, empty list, absent) render nothing, and the caller's input is
// never mutated.
func TestPostgresUserCreateGroupGrant(t *testing.T) {
	listInput := []string{"group_a", "group_b"}
	for _, tc := range []struct {
		name   string
		groups any
		want   string
	}{
		{
			name:   "list keeps elements and order",
			groups: listInput,
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "group_a" TO "u"; GRANT "group_b" TO "u"`,
		},
		{
			name:   "string splits like the pinned source",
			groups: "group_a,group_b",
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "group_a" TO "u"; GRANT "group_b" TO "u"`,
		},
		{
			name:   "string trailing spaces survive",
			groups: "dev ,ops ",
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "dev " TO "u"; GRANT "ops " TO "u"`,
		},
		{
			name:   "string empty comma slots render their own empty GRANT",
			groups: "a,,b",
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "a" TO "u"; GRANT "" TO "u"; GRANT "b" TO "u"`,
		},
		{
			name:   "single-element list with spaces is exact",
			groups: []string{" spaced "},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT " spaced " TO "u"`,
		},
		{
			name:   "empty string is falsy",
			groups: "",
			want:   `CREATE ROLE "u" WITH  INHERIT NOLOGIN`,
		},
		{
			name:   "empty list is falsy",
			groups: []string{},
			want:   `CREATE ROLE "u" WITH  INHERIT NOLOGIN`,
		},
		{
			name:   "absent is falsy",
			groups: nil,
			want:   `CREATE ROLE "u" WITH  INHERIT NOLOGIN`,
		},
	} {
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
			Username: "u",
			Groups:   tc.groups,
			Login:    postgresBool(false),
		})
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}
	// The caller's slice is never mutated or aliased.
	if !reflect.DeepEqual(listInput, []string{"group_a", "group_b"}) {
		t.Fatalf("input groups mutated: %q", listInput)
	}

	// A malformed groups value fails closed before any Runner invocation
	// with the value-free invalid-argument error.
	for _, bad := range []any{map[string]any{"g": "x"}, true, 42, []any{"ok", 1}} {
		rt, runner := newPostgresRuntime()
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
			Username: "u",
			Groups:   bad,
		})
		if err == nil || !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("groups %#v err = %v, want invalid argument", bad, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("groups %#v executed %d commands", bad, len(runner.calls))
		}
	}
}

// TestPostgresUserCreateGroupsStructuredDecode pins the structured decode
// contract through config.Decode: a structured string stays the raw string
// (no list coercion, no trimming), a structured array keeps its exact
// elements, and the typed bool flags remain the only bool translation.
func TestPostgresUserCreateGroupsStructuredDecode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		structured map[string]any
		want       string
	}{
		{
			name:       "structured string is retained raw",
			structured: map[string]any{"groups": "x ,y,,z "},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "x " TO "u"; GRANT "y" TO "u"; GRANT "" TO "u"; GRANT "z " TO "u"`,
		},
		{
			name:       "structured array keeps exact elements",
			structured: map[string]any{"groups": []any{"g1", " g2 "}},
			want: `CREATE ROLE "u" WITH  INHERIT NOLOGIN` +
				`; GRANT "g1" TO "u"; GRANT " g2 " TO "u"`,
		},
	} {
		var args UserCreateArgs
		if err := config.Decode(&args, tc.structured, map[string]string{"username": "u", "login": "false"}); err != nil {
			t.Fatalf("%s decode err = %v", tc.name, err)
		}
		if args.Username != "u" || args.Login == nil || *args.Login {
			t.Fatalf("%s decoded scalars = %#v", tc.name, args)
		}
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		if _, err := (userCreateFunc{}).Execute(context.Background(), rt, &args); err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPostgresRolePasswordTypeSemantics pins the type-preserving union
// contract: bools stay bools and strings stay the exact strings, so the
// string "true" is a literal password (hashed like any plaintext) and the
// strings "true"/"False" as an algorithm are the value-free unknown-
// algorithm rejection — never a silently retyped boolean. Only the CLI
// decoder translates typed bool flags, which the structured-decode vectors
// exercise through config.Decode.
func TestPostgresRolePasswordTypeSemantics(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  saltScalar
	}{
		{nil, saltScalar{kind: saltNone}},
		{true, saltScalar{kind: saltBool, b: true}},
		{false, saltScalar{kind: saltBool, b: false}},
		{"true", saltScalar{kind: saltString, s: "true"}},
		{"False", saltScalar{kind: saltString, s: "False"}},
		{"md5", saltScalar{kind: saltString, s: "md5"}},
		{"", saltScalar{kind: saltString, s: ""}},
		{0, saltScalar{kind: saltOther, b: false, numZero: true}},
		{int64(0), saltScalar{kind: saltOther, b: false, numZero: true}},
		{float64(0), saltScalar{kind: saltOther, b: false, numZero: true}},
		{7, saltScalar{kind: saltOther, b: true}},
	} {
		if got := normalizeSaltScalar(tc.value); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("normalizeSaltScalar(%#v) = %#v, want %#v", tc.value, got, tc.want)
		}
	}

	// maybeEncryptPassword keeps the pinned source algorithm semantics:
	// only real bools (and Python's 0 == False numeric zeros) take the
	// bool branches; strings take the algorithm branches.
	digest := md5Password("u", "pw")
	for _, tc := range []struct {
		name      string
		encrypted saltScalar
		want      string
		wantErr   error
	}{
		{"bool false is plaintext", saltScalar{kind: saltBool}, "pw", nil},
		{"bool true is md5", saltScalar{kind: saltBool, b: true}, digest, nil},
		{"md5 string hashes", saltScalar{kind: saltString, s: "md5"}, digest, nil},
		{"numeric zero equals False", saltScalar{kind: saltOther, numZero: true}, "pw", nil},
		{"boolean spelling true is unknown", saltScalar{kind: saltString, s: "true"}, "",
			errPostgresUnknownPasswordAlgorithm},
		{"boolean spelling False is unknown", saltScalar{kind: saltString, s: "False"}, "",
			errPostgresUnknownPasswordAlgorithm},
		{"nonzero number is unknown", saltScalar{kind: saltOther, b: true}, "",
			errPostgresUnknownPasswordAlgorithm},
	} {
		got, err := maybeEncryptPassword("u", "pw", tc.encrypted)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s err = %v, want %v", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%s = %q err = %v, want %q", tc.name, got, err, tc.want)
		}
	}

	// Execute-level: the string "true" as rolepassword is a literal
	// password hashed by the default md5 algorithm, never the bare
	// PASSWORD the boolean true renders.
	for _, tc := range []struct {
		name         string
		rolepassword any
		want         string
	}{
		{"string true", "true", `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '` +
			md5Password("newuser", "true") + `'`},
		{"string False", "False", `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '` +
			md5Password("newuser", "False") + `'`},
		{"bool true stays the bare PASSWORD clause", true, `CREATE ROLE "newuser" WITH  INHERIT LOGIN PASSWORD`},
		{"bool false stays NOPASSWORD", false, `CREATE ROLE "newuser" WITH  INHERIT LOGIN NOPASSWORD`},
	} {
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
			Username:     "newuser",
			Rolepassword: tc.rolepassword,
		})
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Structured decode: real bools arrive as bools (the only translation
	// surface), strings keep their exact value.
	for _, tc := range []struct {
		name       string
		structured map[string]any
		want       string
	}{
		{
			name:       "structured bool false",
			structured: map[string]any{"encrypted": false, "rolepassword": "pw"},
			want:       `CREATE ROLE "newuser" WITH  INHERIT LOGIN UNENCRYPTED PASSWORD 'pw'`,
		},
		{
			name:       "structured bool true",
			structured: map[string]any{"encrypted": true, "rolepassword": "pw"},
			want: `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '` +
				md5Password("newuser", "pw") + `'`,
		},
		{
			name:       "structured string stays the exact string",
			structured: map[string]any{"encrypted": "scram-sha-256", "rolepassword": "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"},
			want: `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD ` +
				`'SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy'`,
		},
	} {
		var args UserCreateArgs
		if err := config.Decode(&args, tc.structured, map[string]string{"username": "newuser"}); err != nil {
			t.Fatalf("%s decode err = %v", tc.name, err)
		}
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		if _, err := (userCreateFunc{}).Execute(context.Background(), rt, &args); err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// statementLeakRunner replays the preset preflight results and then fails
// every later command with an error embedding the raw command line, the
// way a Runner that performs no redaction of its own would, so the
// module's error-redaction pass is exercised against the real secret
// forms carried in argv.
type statementLeakRunner struct {
	calls   []process.Command
	results []process.CommandResult
}

func (r *statementLeakRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) > 0 {
		result := r.results[0]
		r.results = r.results[1:]
		return result
	}
	raw := fmt.Sprintf("exec failed: %s %v %v", command.Name, command.Args, command.Env)
	return process.CommandResult{
		ExitCode: -1,
		Err:      errors.New(raw),
		Stdout:   []byte(raw),
		Stderr:   []byte(raw),
	}
}

// newLeakRuntime seeds the two preflight results over the given catalog
// CSV and hands the leak runner to the runtime.
func newLeakRuntime(catalog string) (*runtime.Runtime, *statementLeakRunner) {
	runner := &statementLeakRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(catalog)},
	}}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

// TestPostgresRoleVerifierRedaction asserts the full secret inventory of
// the statement transport for every password form: the rendered argv, the
// captured output redacted through the configured Redact list, and
// returned errors carry none of the plaintext, its escaped forms, or the
// generated md5/SCRAM verifier — direct, through the registry, and for
// both create and update statements.
func TestPostgresRoleVerifierRedaction(t *testing.T) {
	const md5Digest = "md531c27e68d3771c392b52102c01be1da1"
	scramVerifier := ""
	for _, tc := range []struct {
		name        string
		fn          string
		args        UserCreateArgs
		markersFrom func(command process.Command) []string
	}{
		{
			name: "md5 create",
			fn:   "postgres.user_create",
			args: UserCreateArgs{Username: "test_username", Password: postgresString("conn_pw"),
				Rolepassword: "foobar"},
		},
		{
			name: "scram create",
			fn:   "postgres.user_create",
			args: UserCreateArgs{Username: "test_username", Password: postgresString("conn_pw"),
				Encrypted: "scram-sha-256", Rolepassword: "hunter2"},
			markersFrom: func(command process.Command) []string {
				statement := command.Args[len(command.Args)-1]
				match := regexp.MustCompile(`SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+`).
					FindString(statement)
				if match == "" {
					t.Fatalf("scram statement lacks the verifier: %q", statement)
				}
				return []string{match}
			},
		},
	} {
		rt, runner := newLeakRuntime(absentRoleCSV)
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		rt.Exec = reg
		_, err := rt.Exec.Call(context.Background(), rt, tc.fn, &tc.args)
		if err == nil {
			t.Fatalf("%s expected the leak runner error", tc.name)
		}
		command := runner.calls[2]
		markers := []string{"foobar", "hunter2", "conn_pw", md5Digest, "'foobar'"}
		if tc.markersFrom != nil {
			markers = append(markers, tc.markersFrom(command)...)
		}
		// The escaped verifier literal and its bare form are Redact
		// entries (plaintext/doubled join for the unencrypted shapes).
		for _, marker := range markers {
			if marker == "" || !strings.Contains(command.Args[len(command.Args)-1], marker) {
				continue // markers absent from this statement form
			}
			if strings.Contains(command.RedactedString(), marker) {
				t.Fatalf("%s rendered argv leaks %q: %q", tc.name, marker, command.RedactedString())
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("%s returned error leaks %q: %v", tc.name, marker, err)
			}
			if got := string(process.RedactBytes(command.Redact, []byte("out "+marker))); strings.Contains(got, marker) {
				t.Fatalf("%s captured output redaction leaks %q: %q", tc.name, marker, got)
			}
		}
		if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
			t.Fatalf("%s error lacks the redaction placeholder: %v", tc.name, err)
		}
		if tc.markersFrom != nil {
			scramVerifier = tc.markersFrom(command)[0]
		}
	}
	if scramVerifier == "" {
		t.Fatal("scram verifier marker never collected")
	}

	// The update statement carries the same inventory: an ALTER ROLE with
	// the md5 verifier scrubs the digest and plaintext from a leak error.
	rt, runner := newLeakRuntime(mutationUsersCSV)
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt.Exec = reg
	_, err := rt.Exec.Call(context.Background(), rt, "postgres.user_update", &UserUpdateArgs{
		Username:     "test_username",
		Password:     postgresString("conn_pw"),
		Rolepassword: "foobar",
	})
	if err == nil {
		t.Fatal("expected the leak runner error")
	}
	for _, marker := range []string{"foobar", "'foobar'", md5Digest, "conn_pw"} {
		if strings.Contains(err.Error(), marker) || strings.Contains(runner.calls[2].RedactedString(), marker) {
			t.Fatalf("update leak of %q: %v", marker, err)
		}
	}

	// The group statements carry the same inventory: a group CREATE ROLE
	// and a group ALTER ROLE with the md5 verifier scrub the digest and
	// plaintext from a leak error through the registry path.
	for _, tc := range []struct {
		fn   string
		args any
	}{
		{"postgres.group_create", &GroupCreateArgs{Groupname: "newgroup",
			Password: postgresString("conn_pw"), Rolepassword: "foobar"}},
		{"postgres.group_update", &GroupUpdateArgs{Groupname: "testgroup",
			Password: postgresString("conn_pw"), Rolepassword: "foobar"}},
	} {
		rt, runner := newLeakRuntime(groupMutationsCSV)
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		rt.Exec = reg
		_, err := rt.Exec.Call(context.Background(), rt, tc.fn, tc.args)
		if err == nil {
			t.Fatal("expected the leak runner error")
		}
		for _, marker := range []string{"foobar", "'foobar'", md5Digest, "conn_pw"} {
			if strings.Contains(err.Error(), marker) || strings.Contains(runner.calls[2].RedactedString(), marker) {
				t.Fatalf("%s leak of %q: %v", tc.fn, marker, err)
			}
		}
	}

	// A plaintext UNENCRYPTED statement redacts the doubled form too.
	rt, runner = newLeakRuntime(absentRoleCSV)
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "test_username",
		Encrypted:    false,
		Rolepassword: "pa'ss",
	})
	if err == nil {
		t.Fatal("expected the leak runner error")
	}
	for _, marker := range []string{"pa'ss", "pa''ss", "'pa''ss'"} {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("unencrypted error leaks %q: %v", marker, err)
		}
	}
}

// TestPostgresUserUpdateVerifierReadback pins the verifier readback on
// update: md5- and SCRAM-prefixed rolepasswords pass through as the full
// literal value of the ALTER ROLE PASSWORD clause.
func TestPostgresUserUpdateVerifierReadback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted any
		password  string
	}{
		{"md5 readback", "md5", "md5deadbeef"},
		{"scram readback", "scram-sha-256", "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"},
	} {
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		_, err := (userUpdateFunc{}).Execute(context.Background(), rt, &UserUpdateArgs{
			Username:     "test_username",
			Encrypted:    tc.encrypted,
			Rolepassword: tc.password,
		})
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		want := `ALTER ROLE "test_username" WITH  ENCRYPTED PASSWORD '` + tc.password + `'`
		if got := userCreateStatement(runner); got != want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, want)
		}
		if !reflect.DeepEqual(runner.calls[2].Redact,
			[]string{"'" + tc.password + "'", tc.password}) {
			t.Fatalf("%s redact = %q", tc.name, runner.calls[2].Redact)
		}
		if strings.Contains(runner.calls[2].RedactedString(), tc.password) {
			t.Fatalf("%s rendered command leaks the verifier: %q", tc.name,
				runner.calls[2].RedactedString())
		}
	}
}

// TestPostgresUserCreateInjection pins the fail-closed identifier boundary
// at the role name and GRANT group positions the pinned source
// interpolates raw: the value-free stable errors fire before any Runner
// invocation.
func TestPostgresUserCreateInjection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  UserCreateArgs
		want  string
		calls int
	}{
		{
			name:  "username quote",
			args:  UserCreateArgs{Username: `u"; DROP ROLE postgres; --`},
			want:  "postgres: invalid argument: unsupported quote character in username",
			calls: 0,
		},
		{
			name:  "groups quote",
			args:  UserCreateArgs{Username: "u", Groups: []string{`g"; DROP ROLE x; --`}},
			want:  "postgres: invalid argument: unsupported quote character in groups",
			calls: 0,
		},
		{
			name:  "string groups quote after the exact split",
			args:  UserCreateArgs{Username: "u", Groups: `ok, g"; DROP ROLE x; --`},
			want:  "postgres: invalid argument: unsupported quote character in groups",
			calls: 0,
		},
	} {
		rt, runner := newPostgresRuntime()
		_, err := (userCreateFunc{}).Execute(context.Background(), rt, &tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.name, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.name, err)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s executed %d commands", tc.name, len(runner.calls))
		}
	}
}

// TestPostgresUserCreateGuards pins the shared transport guards for the
// create path: pre-cancellation, runas rejection, psql-unavailable
// fail-closed, output limits, and the redacted Runner error covering the
// rolepassword too.
func TestPostgresUserCreateGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (userCreateFunc{}).Execute(ctx, rt, &UserCreateArgs{Username: "u"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username: "u",
		Runas:    postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{Username: "u"}); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newMutationRuntime(truncated)
		if _, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{Username: "u"}); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	rt, _ = newMutationRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql -c: secret role_pw rejected"),
	})
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		Username:     "u",
		Password:     postgresString("conn_pw"),
		Rolepassword: "role_pw",
	})
	if err == nil || strings.Contains(err.Error(), "role_pw") || strings.Contains(err.Error(), "conn_pw") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// TestPostgresUserUpdateArgvAndResult ports the pinned test_user_update:
// the exact ALTER ROLE statement of the pinned regex byte-for-byte on the
// full argv after the two preflight calls.
func TestPostgresUserUpdateArgvAndResult(t *testing.T) {
	rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
	value, err := (userUpdateFunc{}).Execute(context.Background(), rt, &UserUpdateArgs{
		Username:      "test_username",
		User:          postgresString("test_user"),
		Host:          postgresString("test_host"),
		Port:          postgresString("test_port"),
		MaintenanceDB: postgresString("test_maint"),
		Password:      postgresString("test_pass"),
		Createdb:      postgresBool(false),
		Createroles:   postgresBool(false),
		Encrypted:     false,
		Inherit:       postgresBool(true),
		Login:         postgresBool(true),
		Replication:   postgresBool(false),
		Rolepassword:  "test_role_pass",
		ValidUntil:    postgresString("2017-07-01"),
		Groups:        []string{"test_groups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("user_update = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight pair plus ALTER)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "test_user",
		"--host", "test_host",
		"--port", "test_port",
		"--dbname", "test_maint",
		"-c", `ALTER ROLE "test_username" WITH  INHERIT NOCREATEDB NOCREATEROLE ` +
			`NOREPLICATION LOGIN UNENCRYPTED PASSWORD 'test_role_pass' ` +
			`VALID UNTIL '2017-07-01'; GRANT "test_groups" TO "test_username"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"'test_role_pass'", "test_role_pass", "test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "test_role_pass") ||
		strings.Contains(command.RedactedString(), "'test_role_pass'") {
		t.Fatalf("rendered command leaks the rolepassword: %q", command.RedactedString())
	}
}

// TestPostgresUserUpdatePinnedShapes ports the remaining pinned
// test_user_update vectors: the no-password shape (test_user_update2), the
// boolean NOPASSWORD shape (test_user_update3), and the md5 verifier shape
// of test_user_update_encrypted_passwd.
func TestPostgresUserUpdatePinnedShapes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     UserUpdateArgs
		want     string
		redacted bool
	}{
		{
			name: "pinned update2",
			args: UserUpdateArgs{
				Username:    "test_username",
				Createdb:    postgresBool(false),
				Createroles: postgresBool(true),
				Encrypted:   false,
				Inherit:     postgresBool(true),
				Login:       postgresBool(true),
				Replication: postgresBool(false),
				Groups:      []string{"test_groups"},
			},
			want: `ALTER ROLE "test_username" WITH  INHERIT NOCREATEDB CREATEROLE ` +
				`NOREPLICATION LOGIN; GRANT "test_groups" TO "test_username"`,
		},
		{
			name: "pinned update3",
			args: UserUpdateArgs{
				Username:     "test_username",
				Createdb:     postgresBool(false),
				Createroles:  postgresBool(true),
				Encrypted:    false,
				Inherit:      postgresBool(true),
				Login:        postgresBool(true),
				Rolepassword: false,
				Replication:  postgresBool(false),
				Groups:       []string{"test_groups"},
			},
			want: `ALTER ROLE "test_username" WITH  INHERIT NOCREATEDB CREATEROLE ` +
				`NOREPLICATION LOGIN NOPASSWORD; GRANT "test_groups" TO "test_username"`,
		},
		{
			name: "pinned encrypted md5",
			args: UserUpdateArgs{
				Username:     "test_username",
				Createdb:     postgresBool(false),
				Createroles:  postgresBool(true),
				Encrypted:    true,
				Inherit:      postgresBool(true),
				Login:        postgresBool(true),
				Rolepassword: "foobar",
				Replication:  postgresBool(false),
				Groups:       []string{"test_groups"},
			},
			want: `ALTER ROLE "test_username" WITH  INHERIT NOCREATEDB CREATEROLE ` +
				`NOREPLICATION LOGIN ENCRYPTED PASSWORD 'md531c27e68d3771c392b52102c01be1da1'` +
				`; GRANT "test_groups" TO "test_username"`,
			redacted: true,
		},
	} {
		rt, runner := newMutationRuntime(process.CommandResult{ExitCode: 0})
		value, err := (userUpdateFunc{}).Execute(context.Background(), rt, &tc.args)
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.name, value)
		}
		if got := userCreateStatement(runner); got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
		if tc.redacted && strings.Contains(runner.calls[2].RedactedString(), "foobar") {
			t.Fatalf("%s rendered command leaks the plaintext: %q", tc.name,
				runner.calls[2].RedactedString())
		}
	}
}

// TestPostgresUserUpdateSuperuserSkip pins the db_role-keyed superuser
// skip: the clause is skipped when the stored boolean equals the requested
// one, and the pinned None request never emits the clause.
func TestPostgresUserUpdateSuperuserSkip(t *testing.T) {
	superCSV := `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_username,f,f,f,f,f,f,,-1,,,
super_role,t,t,f,f,f,t,,-1,,,
`
	for _, tc := range []struct {
		name      string
		username  string
		superuser *bool
		want      string
	}{
		{"equal false skips", "test_username", postgresBool(false), ""},
		{"equal nil-false skips", "test_username", nil, ""},
		{"differs emits NOSUPERUSER", "super_role", postgresBool(false), " NOSUPERUSER"},
		{"differs emits SUPERUSER", "test_username", postgresBool(true), " SUPERUSER"},
		{"nil on superuser stays clauseless", "super_role", nil, ""},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
			process.CommandResult{ExitCode: 0, Stdout: []byte(superCSV)},
			process.CommandResult{ExitCode: 0},
		)
		_, err := (userUpdateFunc{}).Execute(context.Background(), rt, &UserUpdateArgs{
			Username:  tc.username,
			Superuser: tc.superuser,
		})
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		statement := userCreateStatement(runner)
		// The head joins one space plus the clause text, so a clause-less
		// statement keeps the pinned trailing space and any clause renders
		// the pinned double space after WITH.
		want := `ALTER ROLE "` + tc.username + `" WITH ` + tc.want
		if statement != want {
			t.Fatalf("%s statement = %q, want %q", tc.name, statement, want)
		}
	}
}

// TestPostgresUserUpdateMissingIsFalse pins the pinned role_get preflight
// no-op: a missing role is the logged-and-False answer after exactly the
// two catalog calls, with no ALTER issued — and a rejected ALTER keeps the
// retcode boolean.
func TestPostgresUserUpdateMissingIsFalse(t *testing.T) {
	rt, runner := newMutationRuntime()
	value, err := (userUpdateFunc{}).Execute(context.Background(), rt, &UserUpdateArgs{
		Username:     "absent_user",
		Rolepassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("user_update(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 preflight calls only", len(runner.calls))
	}

	rt, _ = newMutationRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`psql: error: ERROR: role "test_username" cannot be altered`),
	})
	value, err = (userUpdateFunc{}).Execute(context.Background(), rt, &UserUpdateArgs{
		Username: "test_username",
	})
	if err != nil || value != false {
		t.Fatalf("nonzero ALTER = %#v err = %v, want false", value, err)
	}
}

// TestPostgresUserRemoveArgvAndResult ports the pinned test_user_remove:
// the preflight pair, the exact DROP ROLE argv of the pinned assertion,
// and the post-check pair deciding true.
func TestPostgresUserRemoveArgvAndResult(t *testing.T) {
	rt, runner := newMutationRuntime(
		process.CommandResult{ExitCode: 0}, // DROP ROLE (retcode ignored)
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\nsuper_role,t,t,f,f,f,t,,-1,,,\n")},
	)
	value, err := (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{
		Username:      "test_username",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("user_remove = %#v, want true", value)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("runner calls = %d, want 5 (preflight, DROP, post-check)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `DROP ROLE "test_username"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}
	// No statement runs after the post-check pair.
	if last := runner.calls[4]; strings.HasPrefix(last.Args[len(last.Args)-1], "DROP") {
		t.Fatalf("unexpected second DROP: %q", last.Args)
	}
}

// TestPostgresUserRemoveShapes pins the remaining pinned flows: a missing
// role is the logged-and-False no-op with no DROP, and a failed DROP that
// leaves the role present is the logged-and-False answer after the full
// five-call flow.
func TestPostgresUserRemoveShapes(t *testing.T) {
	rt, runner := newMutationRuntime()
	value, err := (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{
		Username: "absent_user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("user_remove(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing-role calls = %d, want 2", len(runner.calls))
	}

	// The DROP retcode is ignored; the role still exists afterwards, so
	// the pinned answer is false after all five calls.
	rt, runner = newMutationRuntime(
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: role cannot be dropped")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(mutationUsersCSV)},
	)
	value, err = (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{
		Username: "test_username",
	})
	if err != nil || value != false {
		t.Fatalf("user_remove(failed drop) = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("failed-drop calls = %d, want 5", len(runner.calls))
	}
}

// TestPostgresUserRemoveGuards pins the fail-closed name boundary and the
// shared transport guards for the remove path: the value-free identifier
// rejection before any Runner invocation, runas rejection, and
// pre-cancellation.
func TestPostgresUserRemoveGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{
		Username: `x"; DROP ROLE postgres; --`,
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in username" {
		t.Fatalf("injected name err = %v", err)
	}
	if !errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("injected name err = %v, want invalid argument", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected name executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err = (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{
		Username: "u",
		Runas:    postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (userRemoveFunc{}).Execute(ctx, rt, &UserRemoveArgs{Username: "u"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// TestPostgresUserValidationErrorsRedactedThroughRegistry loops every
// rejected user_create/user_update/user_remove field through the registry
// Call path with the rejected value embedding a synthetic marker: the
// stable value-free error must carry no marker and no Runner call may
// happen beyond the read-only preflight pair the pinned flow runs first.
func TestPostgresUserValidationErrorsRedactedThroughRegistry(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn    string
		args  any
		want  string
		calls int
	}{
		{"postgres.user_create", &UserCreateArgs{Username: `u-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in username", 0},
		{"postgres.user_create", &UserCreateArgs{Username: "u", Groups: []string{`g-` + marker + `"`}},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.user_create", &UserCreateArgs{Username: "u", Groups: `ok,g-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.user_create", &UserCreateArgs{Username: "u", Groups: map[string]any{marker: "x"}},
			"postgres: invalid argument", 0},
		{"postgres.user_create", &UserCreateArgs{Username: "u", Encrypted: marker, Rolepassword: marker},
			"postgres: invalid argument: unknown password algorithm", 2},
		{"postgres.user_update", &UserUpdateArgs{Username: `u-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in username", 0},
		{"postgres.user_update", &UserUpdateArgs{Username: "u", Groups: []string{`g-` + marker + `"`}},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.user_update", &UserUpdateArgs{Username: "u", Groups: `g,` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.user_update", &UserUpdateArgs{Username: "test_username", Encrypted: marker, Rolepassword: marker},
			"postgres: invalid argument: unknown password algorithm", 2},
		{"postgres.user_remove", &UserRemoveArgs{Username: `u"-` + marker},
			"postgres: invalid argument: unsupported quote character in username", 0},
	} {
		rt, runner := newMutationRuntime()
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		_, err := rt.Exec.Call(context.Background(), rt, tc.fn, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s executed %d commands, want %d", tc.fn, len(runner.calls), tc.calls)
		}
	}
}

// groupMutationsCSV is the user_list catalog for the R9.2j group flows:
// testgroup exists as a non-superuser group role, super_role a superuser,
// and created names are absent.
const groupMutationsCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
testgroup,f,t,f,f,f,f,,-1,,,
super_role,t,t,f,f,f,t,,-1,,,
`

// groupAbsentCSV is a catalog whose only role is super_role, so create
// flows for testgroup reach their statement (the pinned test_group_create
// mocks user_exists False).
const groupAbsentCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
super_role,t,t,f,f,f,t,,-1,,,
`

// newGroupMutationRuntime seeds the version probe and role catalog answers
// the group_create/group_update/group_remove preflights and post-checks
// consume.
func newGroupMutationRuntime(results ...process.CommandResult) (*runtime.Runtime, *postgresFakeRunner) {
	return newPostgresRuntime(append([]process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},           // version probe
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)}, // role catalog
	}, results...)...)
}

// newGroupCreateRuntime seeds the version probe and a catalog without
// testgroup, so the pinned test_group_create vector reaches its statement.
func newGroupCreateRuntime(results ...process.CommandResult) (*runtime.Runtime, *postgresFakeRunner) {
	return newPostgresRuntime(append([]process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},        // version probe
		{ExitCode: 0, Stdout: []byte(groupAbsentCSV)}, // role catalog
	}, results...)...)
}

// TestPostgresGroupCreateArgvAndResult ports the pinned test_group_create
// (test_postgres.py:595-620): the exact group-typed statement on the full
// argv — the pinned INHERIT NOLOGIN defaults, the UNENCRYPTED PASSWORD
// literal, and the self-referential GRANT of groups="testgroup" — after
// the preflight catalog pair, with the rolepassword redacted out of the
// rendered command.
func TestPostgresGroupCreateArgvAndResult(t *testing.T) {
	rt, runner := newGroupCreateRuntime(process.CommandResult{ExitCode: 0})
	value, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{
		Groupname:     "testgroup",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
		Createdb:      postgresBool(false),
		Encrypted:     false,
		Superuser:     postgresBool(false),
		Replication:   postgresBool(false),
		Rolepassword:  "testrolepass",
		Groups:        "testgroup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("group_create = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight pair plus CREATE)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `CREATE ROLE "testgroup" WITH  INHERIT NOCREATEDB ` +
			`NOSUPERUSER NOREPLICATION NOLOGIN UNENCRYPTED PASSWORD ` +
			`'testrolepass'; GRANT "testgroup" TO "testgroup"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if got := append([]string{command.Name}, command.Args...); got[14] != want[14] {
		t.Fatalf("argv[14] = %q, want the pinned CREATE ROLE statement", got[14])
	}
	wantEnv := []string{
		"PGPASSWORD=foo",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	// The statement-carried secret set: the quote-escaped plaintext literal
	// first, then the plaintext, then the connection password.
	if !reflect.DeepEqual(command.Redact, []string{"'testrolepass'", "testrolepass", "foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "testrolepass") ||
		strings.Contains(rendered, "foo") || strings.Contains(rendered, "'testrolepass'") {
		t.Fatalf("rendered command leaks a password: %q", rendered)
	}
}

// TestPostgresGroupCreateDefaults pins the no-argument group shape: the
// pinned group-typed INHERIT NOLOGIN defaults are the only clauses (the
// pinned double space after WITH kept), the maintenance fallback applies,
// the environment is clean, and nothing is redacted. The pinned group
// signatures carry no connlimit or valid_until, so a groups-less call
// renders no other clause.
func TestPostgresGroupCreateDefaults(t *testing.T) {
	rt, runner := newGroupCreateRuntime(process.CommandResult{ExitCode: 0})
	value, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{
		Groupname: "plaingroup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("group_create = %#v, want true", value)
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--dbname", "postgres",
		"-c", `CREATE ROLE "plaingroup" WITH  INHERIT NOLOGIN`,
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

// TestPostgresGroupCreateExistsIsFalse pins the pinned preflight no-op: an
// existing role is the logged-and-False answer after exactly the two
// catalog calls, with no CREATE statement issued.
func TestPostgresGroupCreateExistsIsFalse(t *testing.T) {
	rt, runner := newGroupMutationRuntime()
	value, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{
		Groupname:    "testgroup",
		Rolepassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("group_create(existing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 preflight calls only", len(runner.calls))
	}
}

// TestPostgresGroupUpdateArgvAndResult ports the pinned test_group_update
// (test_postgres.py:664-692): the exact ALTER ROLE statement matching the
// pinned regex ('ALTER.* "testgroup" .* UNENCRYPTED PASSWORD') with the
// db_role-keyed superuser skip against the stored non-superuser row, no
// inherit/login defaults, and the pinned quoted connection user, after the
// two preflight calls.
func TestPostgresGroupUpdateArgvAndResult(t *testing.T) {
	rt, runner := newGroupMutationRuntime(process.CommandResult{ExitCode: 0})
	value, err := (groupUpdateFunc{}).Execute(context.Background(), rt, &GroupUpdateArgs{
		Groupname:     "testgroup",
		User:          postgresString(`"testuser"`),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
		Createdb:      postgresBool(false),
		Encrypted:     false,
		Replication:   postgresBool(false),
		Rolepassword:  "test_role_pass",
		Groups:        "testgroup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("group_update = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight pair plus ALTER)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", `"testuser"`,
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `ALTER ROLE "testgroup" WITH  NOCREATEDB NOREPLICATION ` +
			`UNENCRYPTED PASSWORD 'test_role_pass'; GRANT "testgroup" TO "testgroup"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if got := append([]string{command.Name}, command.Args...); !regexp.MustCompile(
		`ALTER.* "testgroup" .* UNENCRYPTED PASSWORD`).MatchString(got[14]) {
		t.Fatalf("argv[14] = %q, want the pinned ALTER ROLE shape", got[14])
	}
	if !reflect.DeepEqual(command.Redact, []string{"'test_role_pass'", "test_role_pass", "foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "test_role_pass") ||
		strings.Contains(command.RedactedString(), "'test_role_pass'") {
		t.Fatalf("rendered command leaks the rolepassword: %q", command.RedactedString())
	}
}

// TestPostgresGroupUpdateShapes pins the remaining group update contract:
// the md5 default verifier renders behind ENCRYPTED with the digest
// Redacted, the explicit inherit/login clauses render in the pinned order
// when requested, a missing role answers false after the preflight pair,
// and a rejected ALTER keeps the retcode boolean.
func TestPostgresGroupUpdateShapes(t *testing.T) {
	rt, runner := newGroupMutationRuntime(process.CommandResult{ExitCode: 0})
	_, err := (groupUpdateFunc{}).Execute(context.Background(), rt, &GroupUpdateArgs{
		Groupname:    "testgroup",
		Rolepassword: "foobar",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := md5Password("testgroup", "foobar")
	want := `ALTER ROLE "testgroup" WITH  ENCRYPTED PASSWORD '` + digest + `'`
	if got := userCreateStatement(runner); got != want {
		t.Fatalf("md5 statement = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(runner.calls[2].Redact,
		[]string{"'" + digest + "'", digest, "foobar"}) {
		t.Fatalf("md5 redact = %q", runner.calls[2].Redact)
	}

	rt, runner = newGroupMutationRuntime(process.CommandResult{ExitCode: 0})
	_, err = (groupUpdateFunc{}).Execute(context.Background(), rt, &GroupUpdateArgs{
		Groupname:   "testgroup",
		Inherit:     postgresBool(true),
		Login:       postgresBool(true),
		Createroles: postgresBool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	want = `ALTER ROLE "testgroup" WITH  INHERIT CREATEROLE LOGIN`
	if got := userCreateStatement(runner); got != want {
		t.Fatalf("flags statement = %q, want %q", got, want)
	}

	rt, runner = newGroupMutationRuntime()
	value, err := (groupUpdateFunc{}).Execute(context.Background(), rt, &GroupUpdateArgs{
		Groupname:    "absent_group",
		Rolepassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("group_update(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 preflight calls only", len(runner.calls))
	}

	rt, _ = newGroupMutationRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte(`psql: error: ERROR: role "testgroup" cannot be altered`),
	})
	value, err = (groupUpdateFunc{}).Execute(context.Background(), rt, &GroupUpdateArgs{
		Groupname: "testgroup",
	})
	if err != nil || value != false {
		t.Fatalf("nonzero ALTER = %#v err = %v, want false", value, err)
	}
}

// TestPostgresGroupRemoveArgvAndResult ports the pinned test_group_remove
// (test_postgres.py:623-661): the preflight pair, the exact 15-element
// DROP ROLE argv of the pinned assert_called_once_with, and the post-check
// pair deciding true.
func TestPostgresGroupRemoveArgvAndResult(t *testing.T) {
	rt, runner := newGroupMutationRuntime(
		process.CommandResult{ExitCode: 0}, // DROP ROLE (retcode ignored)
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\nsuper_role,t,t,f,f,f,t,,-1,,,\n")},
	)
	value, err := (groupRemoveFunc{}).Execute(context.Background(), rt, &GroupRemoveArgs{
		Groupname:     "testgroup",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("foo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("group_remove = %#v, want true", value)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("runner calls = %d, want 5 (preflight, DROP, post-check)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `DROP ROLE "testgroup"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"foo"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "foo") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}
	// No statement runs after the post-check pair.
	if last := runner.calls[4]; strings.HasPrefix(last.Args[len(last.Args)-1], "DROP") {
		t.Fatalf("unexpected second DROP: %q", last.Args)
	}
}

// TestPostgresGroupRemoveShapes pins the remaining pinned flows: a missing
// role is the logged-and-False no-op with no DROP, and a failed DROP that
// leaves the role present is the logged-and-False answer after the full
// five-call flow.
func TestPostgresGroupRemoveShapes(t *testing.T) {
	rt, runner := newGroupMutationRuntime()
	value, err := (groupRemoveFunc{}).Execute(context.Background(), rt, &GroupRemoveArgs{
		Groupname: "absent_group",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("group_remove(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing-role calls = %d, want 2", len(runner.calls))
	}

	// The DROP retcode is ignored; the role still exists afterwards, so
	// the pinned answer is false after all five calls.
	rt, runner = newGroupMutationRuntime(
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: role cannot be dropped")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("9.1\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
	)
	value, err = (groupRemoveFunc{}).Execute(context.Background(), rt, &GroupRemoveArgs{
		Groupname: "testgroup",
	})
	if err != nil || value != false {
		t.Fatalf("group_remove(failed drop) = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("failed-drop calls = %d, want 5", len(runner.calls))
	}
}

// TestPostgresGroupCreateGuards pins the shared transport guards for the
// group create path: pre-cancellation, runas rejection, psql-unavailable
// fail-closed, and the redacted Runner error covering the rolepassword
// too.
func TestPostgresGroupCreateGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (groupCreateFunc{}).Execute(ctx, rt, &GroupCreateArgs{Groupname: "g"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{
		Groupname: "g",
		Runas:     postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{Groupname: "g"}); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql unavailable err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	for _, truncated := range []process.CommandResult{
		{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
		{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
	} {
		rt, _ := newGroupMutationRuntime(truncated)
		if _, err := (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{Groupname: "g"}); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("output limit err = %v", err)
		}
	}

	rt, _ = newGroupMutationRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql -c: secret group_pw rejected"),
	})
	_, err = (groupCreateFunc{}).Execute(context.Background(), rt, &GroupCreateArgs{
		Groupname:    "g",
		Password:     postgresString("conn_pw"),
		Rolepassword: "group_pw",
	})
	if err == nil || strings.Contains(err.Error(), "group_pw") || strings.Contains(err.Error(), "conn_pw") {
		t.Fatalf("runner error must be redacted: %v", err)
	}
	if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
		t.Fatalf("error lacks redaction placeholder: %v", err)
	}
}

// TestPostgresGroupRemoveGuards pins the fail-closed name boundary and the
// shared transport guards for the group remove path: the value-free
// identifier rejection before any Runner invocation, runas rejection, and
// pre-cancellation.
func TestPostgresGroupRemoveGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (groupRemoveFunc{}).Execute(context.Background(), rt, &GroupRemoveArgs{
		Groupname: `x"; DROP ROLE postgres; --`,
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in groupname" {
		t.Fatalf("injected name err = %v", err)
	}
	if !errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("injected name err = %v, want invalid argument", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected name executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err = (groupRemoveFunc{}).Execute(context.Background(), rt, &GroupRemoveArgs{
		Groupname: "g",
		Runas:     postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (groupRemoveFunc{}).Execute(ctx, rt, &GroupRemoveArgs{Groupname: "g"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// TestPostgresGroupValidationErrorsRedactedThroughRegistry loops every
// rejected group_create/group_update/group_remove field through the
// registry Call path with the rejected value embedding a synthetic marker:
// the stable value-free error must carry no marker and no Runner call may
// happen beyond the read-only preflight pair the pinned flow runs first.
func TestPostgresGroupValidationErrorsRedactedThroughRegistry(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn    string
		args  any
		want  string
		calls int
	}{
		{"postgres.group_create", &GroupCreateArgs{Groupname: `g-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groupname", 0},
		{"postgres.group_create", &GroupCreateArgs{Groupname: "g", Groups: []string{`m-` + marker + `"`}},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.group_create", &GroupCreateArgs{Groupname: "g", Groups: `ok,m-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.group_create", &GroupCreateArgs{Groupname: "g", Groups: map[string]any{marker: "x"}},
			"postgres: invalid argument", 0},
		{"postgres.group_create", &GroupCreateArgs{Groupname: "g", Encrypted: marker, Rolepassword: marker},
			"postgres: invalid argument: unknown password algorithm", 2},
		{"postgres.group_update", &GroupUpdateArgs{Groupname: `g-` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groupname", 0},
		{"postgres.group_update", &GroupUpdateArgs{Groupname: "g", Groups: []string{`m-` + marker + `"`}},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.group_update", &GroupUpdateArgs{Groupname: "g", Groups: `m,` + marker + `"`},
			"postgres: invalid argument: unsupported quote character in groups", 0},
		{"postgres.group_update", &GroupUpdateArgs{Groupname: "testgroup", Encrypted: marker, Rolepassword: marker},
			"postgres: invalid argument: unknown password algorithm", 2},
		{"postgres.group_remove", &GroupRemoveArgs{Groupname: `g"-` + marker},
			"postgres: invalid argument: unsupported quote character in groupname", 0},
	} {
		rt, runner := newGroupMutationRuntime()
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		_, err := rt.Exec.Call(context.Background(), rt, tc.fn, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s executed %d commands, want %d", tc.fn, len(runner.calls), tc.calls)
		}
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
	// transport and the remaining write paths stay unregistered.
	for _, pending := range []string{
		"postgres.psql_query",
		"postgres.default_privileges_grant",
		"postgres.default_privileges_revoke",
	} {
		if _, err := reg.Call(context.Background(), rt, pending, &ExistsArgs{Name: "awl"}); err == nil {
			t.Fatalf("%s must stay unregistered", pending)
		}
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

// ---------------------------------------------------------------------------
// privileges_grant / privileges_revoke — salt/modules/postgres.py:4009-4297
// @ pinned revision.

// ownerFunctionCSV renders the fixed function owner catalog: fawl and
// f-awl are owned by postgres, so the preflight flows continue to the
// privilege query instead of taking the owner shortcut.
const ownerFunctionCSV = `nspname,regprocedure,name
public,fawl,postgres
public,f-awl,postgres
`

// privGrantTableCSV renders the table privilege catalog where baruwa
// holds nothing on awl (only bayestest does), so the grant preflight
// answers false and the mutation statement runs.
const privGrantTableCSV = `nspname,relname,relkind,name
public,awl,r,"{bayestest=arwd/baruwatest}"
`

// privGrantFunctionCSV renders the function privilege catalog where
// baruwa lacks EXECUTE on fawl and f-awl.
const privGrantFunctionCSV = `nspname,regprocedure,name
public,fawl,"{bayestest=X/baruwatest}"
public,f-awl,"{bayestest=X/baruwatest}"
`

// privGrantGroupCSV renders the group membership catalog where baruwa is
// not a member of admins, so the grant preflight answers false.
const privGrantGroupCSV = `member_of,rolname,admin_option
admins,baruwatest,f
other_group,baruwa,t
`

func fullPrivilegesGrantArgs(name, objectName, objectType, privileges string) *PrivilegesGrantArgs {
	return &PrivilegesGrantArgs{
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

func fullPrivilegesRevokeArgs(name, objectName, objectType, privileges string) *PrivilegesRevokeArgs {
	return &PrivilegesRevokeArgs{
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

// TestPostgresPrivilegesGrantArgv ports the pinned
// test_privileges_grant_table, test_privileges_grant_function, and
// test_privileges_grant_group statements byte-for-byte: the preflight
// owner and privilege queries answer "not granted", then exactly one
// mutation call carries the pinned GRANT statement on the full pinned
// argv (SQL at index 14) with the pinned clean environment and the
// password as the only Redact secret. The pinned tests mock
// has_privileges to False and pass runas="user"; StateKit reaches the
// same preflight answer through the fixed catalogs and rejects runas
// before execution, so the vectors here drop runas.
func TestPostgresPrivilegesGrantArgv(t *testing.T) {
	cases := []struct {
		label       string
		name        string
		objectName  string
		objectType  string
		privileges  string
		grantOption bool
		ownerCSV    string
		privCSV     string
		query       string
	}{
		{
			"table all with grant option", "baruwa", "awl", "table", "ALL", true,
			ownerTableCSV, privGrantTableCSV,
			`GRANT ALL ON TABLE public."awl" TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"table all", "baruwa", "awl", "table", "ALL", false,
			ownerTableCSV, privGrantTableCSV,
			`GRANT ALL ON TABLE public."awl" TO "baruwa"`,
		},
		{
			"all tables in schema", "baruwa", "ALL", "table", "SELECT", false,
			ownerTableCSV, privGrantTableCSV,
			`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "baruwa"`,
		},
		{
			"function all with grant option", "baruwa", "fawl", "function", "ALL", true,
			ownerFunctionCSV, privGrantFunctionCSV,
			`GRANT ALL ON FUNCTION public."fawl" TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"function all", "baruwa", "fawl", "function", "ALL", false,
			ownerFunctionCSV, privGrantFunctionCSV,
			`GRANT ALL ON FUNCTION public."fawl" TO "baruwa"`,
		},
		{
			"all functions in schema", "baruwa", "ALL", "function", "EXECUTE", false,
			ownerFunctionCSV, privGrantFunctionCSV,
			`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO "baruwa"`,
		},
	}
	for _, tc := range cases {
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			{ExitCode: 0, Stdout: []byte(tc.privCSV)},
			{ExitCode: 0},
		}
		rt, runner := newPostgresRuntime(results...)
		args := fullPrivilegesGrantArgs(tc.name, tc.objectName, tc.objectType, tc.privileges)
		args.GrantOption = tc.grantOption
		value, err := (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.label, value)
		}
		if len(runner.calls) != 3 {
			t.Fatalf("%s calls = %d, want 3 (owner + privileges + grant)", tc.label, len(runner.calls))
		}
		command := runner.calls[2]
		want := []string{
			"psql",
			"--no-align",
			"--no-readline",
			"--no-psqlrc",
			"--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "db_name",
			"-c", tc.query,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.label, got, want)
		}
		wantEnv := []string{
			"PGPASSWORD=testpassword",
			"PGUSER=testuser",
			"PGHOST=testhost",
			"PGPORT=testport",
		}
		if !reflect.DeepEqual(command.Env, wantEnv) {
			t.Fatalf("%s env = %q, want %q", tc.label, command.Env, wantEnv)
		}
		if command.Shell {
			t.Fatalf("%s psql must run without a shell", tc.label)
		}
		if command.Timeout != commandTimeout ||
			command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("%s unsafe command bounds: %#v", tc.label, command)
		}
		if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
			t.Fatalf("%s redact = %q", tc.label, command.Redact)
		}
		if rendered := command.RedactedString(); strings.Contains(rendered, "testpassword") {
			t.Fatalf("%s rendered command leaks password: %q", tc.label, rendered)
		}
	}

	// The pinned group statements: one preflight membership query, then
	// the raw group membership GRANT with and without ADMIN OPTION.
	for _, tc := range []struct {
		label       string
		grantOption bool
		query       string
	}{
		{"group admin option", true, `GRANT admins TO "baruwa" WITH ADMIN OPTION`},
		{"group membership", false, `GRANT admins TO "baruwa"`},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantGroupCSV)},
			process.CommandResult{ExitCode: 0},
		)
		args := fullPrivilegesGrantArgs("baruwa", "admins", "group", "")
		args.GrantOption = tc.grantOption
		value, err := (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
		if err != nil || value != true {
			t.Fatalf("%s = %#v err = %v, want true", tc.label, value, err)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %d, want 2 (membership + grant)", tc.label, len(runner.calls))
		}
		if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != tc.query {
			t.Fatalf("%s statement = %q, want %q", tc.label, got, tc.query)
		}
	}
}

// TestPostgresPrivilegesRevokeArgv ports the pinned
// test_privileges_revoke_table, test_privileges_revoke_function, and
// test_privileges_revoke_group statements byte-for-byte: the preflight
// answers "held" through the fixed catalogs, then exactly one mutation
// call carries the pinned REVOKE statement — including the pinned raw
// (unquoted) role name of the REVOKE tail. The pinned tests mock
// has_privileges to True; the fixtures here answer true through the real
// preflight.
func TestPostgresPrivilegesRevokeArgv(t *testing.T) {
	cases := []struct {
		label      string
		name       string
		objectName string
		objectType string
		privileges string
		ownerCSV   string
		privCSV    string
		query      string
	}{
		{
			"table all", "baruwa", "awl", "table", "ALL",
			ownerTableCSV, privTableCSV,
			`REVOKE ALL ON TABLE public."awl" FROM baruwa`,
		},
		{
			"function execute", "baruwa", "f-awl", "function", "EXECUTE",
			ownerFunctionCSV, `nspname,regprocedure,name` + "\n" +
				`public,f-awl,"{baruwa=X*/baruwatest}"` + "\n",
			`REVOKE EXECUTE ON FUNCTION public."f-awl" FROM baruwa`,
		},
	}
	for _, tc := range cases {
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			{ExitCode: 0, Stdout: []byte(tc.privCSV)},
			{ExitCode: 0},
		}
		rt, runner := newPostgresRuntime(results...)
		value, err := (privilegesRevokeFunc{}).Execute(context.Background(), rt,
			fullPrivilegesRevokeArgs(tc.name, tc.objectName, tc.objectType, tc.privileges))
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.label, value)
		}
		if len(runner.calls) != 3 {
			t.Fatalf("%s calls = %d, want 3 (owner + privileges + revoke)", tc.label, len(runner.calls))
		}
		command := runner.calls[2]
		want := []string{
			"psql",
			"--no-align",
			"--no-readline",
			"--no-psqlrc",
			"--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "db_name",
			"-c", tc.query,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.label, got, want)
		}
		if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
			t.Fatalf("%s redact = %q", tc.label, command.Redact)
		}
	}

	// The pinned group statement with both names raw: one membership
	// preflight where baruwa is a member, then the REVOKE.
	privHeldGroupCSV := `member_of,rolname,admin_option
admins,baruwa,f
`
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privHeldGroupCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (privilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullPrivilegesRevokeArgs("baruwa", "admins", "group", ""))
	if err != nil || value != true {
		t.Fatalf("group revoke = %#v err = %v, want true", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("group revoke calls = %d, want 2", len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "REVOKE admins FROM baruwa" {
		t.Fatalf("group revoke statement = %q", got)
	}
}

// TestPostgresPrivilegesMutationNoop pins the pinned preflight short
// circuits: an already-granted grant and a not-yet-held revoke return
// False with no mutation statement — exactly the pinned calls the two
// runner results cover and no third call — including the owner shortcut
// that satisfies the preflight after the owner query alone and the
// grant-option-independent preflight the pinned source issues.
func TestPostgresPrivilegesMutationNoop(t *testing.T) {
	// Grant to the role that already holds every table privilege (the
	// pinned privTableCSV baruwa row), with grant_option set: the pinned
	// preflight never receives grant_option, so the membership/ALL check
	// alone answers true and no GRANT runs.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
	)
	args := fullPrivilegesGrantArgs("baruwa", "awl", "table", "ALL")
	args.GrantOption = true
	value, err := (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != false {
		t.Fatalf("already-granted = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("already-granted calls = %d, want 2", len(runner.calls))
	}

	// The owner shortcut: postgres owns awl, so the preflight answers
	// true after the owner query alone.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
	)
	value, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
		fullPrivilegesGrantArgs("postgres", "awl", "table", "SELECT"))
	if err != nil || value != false {
		t.Fatalf("owner grant = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("owner grant calls = %d, want 1", len(runner.calls))
	}

	// Grant to a group member: membership alone satisfies the preflight
	// even though the admin_option is false.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	args = fullPrivilegesGrantArgs("baruwa", "admin", "group", "")
	args.GrantOption = true
	value, err = (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != false {
		t.Fatalf("member grant = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("member grant calls = %d, want 1", len(runner.calls))
	}

	// Revoke from a role that holds nothing: false after the two
	// preflight queries, no REVOKE.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantTableCSV)},
	)
	value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullPrivilegesRevokeArgs("baruwa", "awl", "table", "ALL"))
	if err != nil || value != false {
		t.Fatalf("nothing-held revoke = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("nothing-held revoke calls = %d, want 2", len(runner.calls))
	}

	// Revoke from a non-member: false after the one membership query.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantGroupCSV)},
	)
	value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullPrivilegesRevokeArgs("baruwa", "admins", "group", ""))
	if err != nil || value != false {
		t.Fatalf("non-member revoke = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("non-member revoke calls = %d, want 1", len(runner.calls))
	}

	// Every short-circuit path keeps its executed commands free of any
	// mutation verb: only fixed COPY catalogs ran.
	for i, call := range runner.calls {
		joined := strings.Join(call.Args, " ")
		for _, verb := range []string{"GRANT ", "REVOKE "} {
			if strings.Contains(joined, verb) {
				t.Fatalf("no-op path executed a mutation: call %d = %q", i, joined)
			}
		}
	}
}

// TestPostgresPrivilegesMutationShapes pins the remaining statement
// surface: the multi-privilege comma join with the pinned split
// semantics, the quoted on-part of the schema/tablespace/language/
// database types, the lowercase "all" object name selecting the
// ALL-variant, the pinned prepend default, and the retcode-false
// compatibility shape of both mutations.
func TestPostgresPrivilegesMutationShapes(t *testing.T) {
	cases := []struct {
		label      string
		revoke     bool
		name       string
		objectName string
		objectType string
		privileges string
		prepend    *string
		ownerCSV   string
		privCSV    string
		query      string
	}{
		{
			"multi privileges split", false, "baruwa", "awl", "table", "SELECT , UPDATE", nil,
			ownerTableCSV, privGrantTableCSV,
			`GRANT SELECT,UPDATE ON TABLE public."awl" TO "baruwa"`,
		},
		{
			"schema quoted", false, "baruwa", "myschema", "schema", "USAGE,CREATE", nil,
			"nspname,name\npublic,postgres\n", "nspname,name\npublic,\"{postgres=UC/postgres}\"\n",
			`GRANT USAGE,CREATE ON SCHEMA "myschema" TO "baruwa"`,
		},
		{
			"tablespace quoted", false, "baruwa", "pg_default", "tablespace", "CREATE", nil,
			"spcname,name\npg_default,postgres\n", "spcname,name\npg_default,\"{postgres=C/postgres}\"\n",
			`GRANT CREATE ON TABLESPACE "pg_default" TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"database quoted", true, "baruwa", "test_db", "database", "CONNECT,TEMPORARY", nil,
			"datname,name\ntest_db,postgres\n",
			"datname,name\ntest_db,\"{postgres=CTc/postgres,baruwa=cT*/postgres}\"\n",
			`REVOKE CONNECT,TEMPORARY ON DATABASE "test_db" FROM baruwa`,
		},
		{
			"language quoted", true, "baruwa", "plpgsql", "language", "USAGE", nil,
			"lanname,name\nplpgsql,postgres\n", "lanname,name\nplpgsql,\"{baruwa=U*/postgres}\"\n",
			`REVOKE USAGE ON LANGUAGE "plpgsql" FROM baruwa`,
		},
		{
			"sequence prepend", false, "baruwa", "awl_seq", "sequence", "SELECT", postgresString("private"),
			"nspname,relname,name\nprivate,awl_seq,postgres\n",
			"nspname,relname,relkind,name\nprivate,awl_seq,S,\"{other=r/postgres}\"\n",
			`GRANT SELECT ON SEQUENCE private."awl_seq" TO "baruwa"`,
		},
	}
	for _, tc := range cases {
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			{ExitCode: 0, Stdout: []byte(tc.privCSV)},
			{ExitCode: 0},
		}
		rt, runner := newPostgresRuntime(results...)
		var value any
		var err error
		if tc.revoke {
			args := fullPrivilegesRevokeArgs(tc.name, tc.objectName, tc.objectType, tc.privileges)
			args.Prepend = tc.prepend
			value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt, args)
		} else {
			args := fullPrivilegesGrantArgs(tc.name, tc.objectName, tc.objectType, tc.privileges)
			args.GrantOption = strings.Contains(tc.query, "WITH GRANT OPTION")
			args.Prepend = tc.prepend
			value, err = (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.label, value)
		}
		if got := runner.calls[len(runner.calls)-1].Args[len(runner.calls[len(runner.calls)-1].Args)-1]; got != tc.query {
			t.Fatalf("%s statement = %q, want %q", tc.label, got, tc.query)
		}
	}

	// A lowercase "all" object name selects the ALL-variant exactly like
	// the pinned object_name.upper() == "ALL" comparison.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (privilegesGrantFunc{}).Execute(context.Background(), rt,
		fullPrivilegesGrantArgs("baruwa", "all", "table", "SELECT"))
	if err != nil || value != true {
		t.Fatalf("lowercase all = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `GRANT SELECT ON ALL TABLES IN SCHEMA public TO "baruwa"` {
		t.Fatalf("lowercase all statement = %q", got)
	}

	// The preflight queries embed no caller string; only the mutation
	// statement does, in its validated identifier positions.
	for i, call := range runner.calls[:2] {
		joined := strings.Join(call.Args, "\x00")
		if strings.Contains(joined, "baruwa") || strings.Contains(joined, "public") {
			t.Fatalf("preflight call %d leaked a lookup string: %q", i, joined)
		}
	}

	// A rejected statement keeps the pinned retcode boolean: false,
	// never an error.
	for _, revoke := range []bool{false, true} {
		rt, _ := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantTableCSV)},
			process.CommandResult{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: relation "awl" does not exist`)},
		)
		var value any
		var err error
		if revoke {
			value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
				fullPrivilegesRevokeArgs("bayestest", "awl", "table", "SELECT,INSERT"))
		} else {
			value, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
				fullPrivilegesGrantArgs("baruwa", "awl", "table", "ALL"))
		}
		if err != nil || value != false {
			t.Fatalf("nonzero exit revoke=%v = %#v err = %v, want false", revoke, value, err)
		}
	}
}

// TestPostgresPrivilegesMutationValidation pins the pinned validation
// head for both mutations: every rejected input fails before any Runner
// invocation, the object type is lowercased, and the split tolerates the
// pinned single spaces.
func TestPostgresPrivilegesValidationRedaction(t *testing.T) {
	const marker = "synthetic_privilege_marker"
	for _, entry := range []string{"direct", "registry"} {
		for _, function := range []string{"postgres.privileges_grant", "postgres.privileges_revoke", "postgres.has_privileges"} {
			for _, field := range []string{"privileges", "object_type"} {
				t.Run(entry+"/"+function+"/"+field, func(t *testing.T) {
					objectType, privileges := "table", "SELECT,"+marker
					if field == "object_type" {
						objectType, privileges = marker, "SELECT"
					}
					rt, runner := newPostgresRuntime()
					var fn runtime.ExecFunction
					var args any
					switch function {
					case "postgres.privileges_grant":
						a := fullPrivilegesGrantArgs("baruwa", "awl", objectType, privileges)
						a.Password = postgresString(marker)
						fn, args = privilegesGrantFunc{}, a
					case "postgres.privileges_revoke":
						a := fullPrivilegesRevokeArgs("baruwa", "awl", objectType, privileges)
						a.Password = postgresString(marker)
						fn, args = privilegesRevokeFunc{}, a
					default:
						fn, args = hasPrivilegesFunc{}, &HasPrivilegesArgs{Name: "baruwa", ObjectName: "awl", ObjectType: objectType, Privileges: privileges, Password: postgresString(marker)}
					}
					var value any
					var err error
					if entry == "registry" {
						rt.Exec = runtime.NewExecRegistry()
						if err := Register(rt.Exec); err != nil {
							t.Fatal(err)
						}
						value, err = rt.Exec.Call(context.Background(), rt, function, args)
					} else {
						value, err = fn.Execute(context.Background(), rt, args)
					}
					if !errors.Is(err, errPostgresInvalidArgument) || err.Error() != "postgres: invalid argument: invalid "+field {
						t.Fatal("expected stable invalid-argument error with fixed key only")
					}
					if value != nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
						t.Fatal("validation leaked input or invoked Runner")
					}
				})
			}
		}
	}
}

func TestPostgresPrivilegesMutationValidation(t *testing.T) {
	for _, tc := range []struct {
		label      string
		objectType string
		privileges string
	}{
		{"unknown object type", "bogus", "SELECT"},
		{"empty object type", "", "SELECT"},
		{"invalid privilege", "table", "SELECT,BOGUS"},
		{"missing privileges", "table", ""},
		{"privileges for group", "group", "SELECT"},
	} {
		for _, revoke := range []bool{false, true} {
			rt, runner := newPostgresRuntime()
			var err error
			if revoke {
				_, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
					fullPrivilegesRevokeArgs("baruwa", "awl", tc.objectType, tc.privileges))
			} else {
				_, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
					fullPrivilegesGrantArgs("baruwa", "awl", tc.objectType, tc.privileges))
			}
			if !errors.Is(err, errPostgresInvalidArgument) {
				t.Fatalf("%s revoke=%v err = %v, want errPostgresInvalidArgument", tc.label, revoke, err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("%s revoke=%v executed %d commands before validation", tc.label, revoke, len(runner.calls))
			}
		}
	}

	// Mixed-case object types and spaced privilege lists behave exactly
	// like the pinned _mod_priv_opts for both functions.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (privilegesGrantFunc{}).Execute(context.Background(), rt,
		fullPrivilegesGrantArgs("baruwa", "awl", "TABLE", "select , insert"))
	if err != nil || value != true {
		t.Fatalf("TABLE case/spaces = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `GRANT SELECT,INSERT ON TABLE public."awl" TO "baruwa"` {
		t.Fatalf("TABLE case/spaces statement = %q", got)
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("nspname,name\npublic,postgres\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("nspname,name\npublic,\"{postgres=UC/postgres,baruwa=UC/postgres}\"\n")},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullPrivilegesRevokeArgs("baruwa", "public", "SCHEMA", "usage , create"))
	if err != nil || value != true {
		t.Fatalf("SCHEMA case/spaces = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `REVOKE USAGE,CREATE ON SCHEMA "public" FROM baruwa` {
		t.Fatalf("SCHEMA case/spaces statement = %q", got)
	}
}

// TestPostgresPrivilegesMutationInjection pins the fail-closed boundary
// at every identifier position the pinned format strings interpolate raw
// or quote without escaping, each with its exact value-free stable error
// and zero Runner executions, including the synthetic marker overlap that
// proves a rejected value cannot leak through the error.
func TestPostgresPrivilegesMutationInjection(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn     string
		revoke bool
		args   func(marker string) any
		want   string
	}{
		{
			"postgres.privileges_grant", false,
			func(marker string) any {
				return fullPrivilegesGrantArgs(`baruwa-`+marker+`"`, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"postgres.privileges_grant", false,
			func(marker string) any {
				return fullPrivilegesGrantArgs("baruwa", `aw`+marker+`"`, "table", "SELECT")
			},
			"postgres: invalid argument: unsupported quote character in object_name",
		},
		{
			"postgres.privileges_grant", false,
			func(marker string) any {
				return fullPrivilegesGrantArgs("baruwa", `admins; DROP ROLE x; --`+marker, "group", "")
			},
			"postgres: invalid argument: unsupported identifier in object_name",
		},
		{
			"postgres.privileges_grant", false,
			func(marker string) any {
				args := fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
				args.Prepend = postgresString(`public; DROP SCHEMA x; --` + marker)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
		{
			"postgres.privileges_grant", false,
			func(marker string) any {
				args := fullPrivilegesGrantArgs("baruwa", "ALL", "table", "SELECT")
				args.Prepend = postgresString("public '" + marker)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
		{
			"postgres.privileges_revoke", true,
			func(marker string) any {
				return fullPrivilegesRevokeArgs(`baruwa; DROP ROLE x; --`+marker, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported identifier in name",
		},
		{
			"postgres.privileges_revoke", true,
			func(marker string) any {
				return fullPrivilegesRevokeArgs(`bar uwa`+marker, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported identifier in name",
		},
		{
			"postgres.privileges_revoke", true,
			func(marker string) any {
				return fullPrivilegesRevokeArgs("baruwa", `admi`+marker+`"`, "group", "")
			},
			"postgres: invalid argument: unsupported identifier in object_name",
		},
		{
			"postgres.privileges_revoke", true,
			func(marker string) any {
				args := fullPrivilegesRevokeArgs("baruwa", "awl", "function", "EXECUTE")
				args.Prepend = postgresString(`pub` + marker + `"lic`)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
	} {
		rt, runner := newPostgresRuntime()
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		var err error
		if tc.revoke {
			args := tc.args(marker).(*PrivilegesRevokeArgs)
			args.Password = postgresString(marker)
			_, err = rt.Exec.Call(context.Background(), rt, tc.fn, args)
		} else {
			args := tc.args(marker).(*PrivilegesGrantArgs)
			args.Password = postgresString(marker)
			_, err = rt.Exec.Call(context.Background(), rt, tc.fn, args)
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands, want 0", tc.fn, len(runner.calls))
		}
	}
}

// TestPostgresPrivilegesMutationRedaction drives both mutations with a
// synthetic marker secret — always the connection password, additionally
// overlapping one other connection argument per case, exactly like the
// role-family battery: a preflight failure at either catalog query and a
// mutation-time Runner failure (the leak Runner's raw command-line error
// embedding argv and environment) all surface redacted errors, every
// executed command keeps the exact marker secret inventory, no mutation
// runs after a failed preflight, and the rendered command never carries
// the marker.
func TestPostgresPrivilegesMutationRedaction(t *testing.T) {
	const marker = "synthetic'preflight"
	for _, fn := range []string{"postgres.privileges_grant", "postgres.privileges_revoke"} {
		// The grant preflight must answer false (baruwa holds nothing)
		// and the revoke preflight true (baruwa holds everything), so
		// both functions reach their mutation at call 3.
		privCSV := privGrantTableCSV
		if fn == "postgres.privileges_revoke" {
			privCSV = privTableCSV
		}
		for _, overlap := range []string{"password", "host", "user", "maintenance_db"} {
			for _, failAt := range []int{1, 2, 3} {
				t.Run(fn+"/"+overlap+"/"+strconv.Itoa(failAt), func(t *testing.T) {
					grantArgs := fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
					revokeArgs := fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")
					grantArgs.Password = postgresString(marker)
					revokeArgs.Password = postgresString(marker)
					switch overlap {
					case "host":
						grantArgs.Host = postgresString(marker)
						revokeArgs.Host = postgresString(marker)
					case "user":
						grantArgs.User = postgresString(marker)
						revokeArgs.User = postgresString(marker)
					case "maintenance_db":
						grantArgs.MaintenanceDB = postgresString(marker)
						revokeArgs.MaintenanceDB = postgresString(marker)
					}
					runner := &statementLeakRunner{}
					runner.results = []process.CommandResult{
						{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
						{ExitCode: 0, Stdout: []byte(privCSV)},
					}
					runner.results = runner.results[:failAt-1]
					rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
					var value any
					var err error
					if fn == "postgres.privileges_grant" {
						value, err = (privilegesGrantFunc{}).Execute(context.Background(), rt, grantArgs)
					} else {
						value, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt, revokeArgs)
					}
					if err == nil || value != nil {
						t.Fatal("run did not stop at injected error")
					}
					if strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), process.RedactedPlaceholder) {
						t.Fatalf("error was not redacted: %v", err)
					}
					if len(runner.calls) != failAt {
						t.Fatalf("calls = %d, want %d", len(runner.calls), failAt)
					}
					for _, command := range runner.calls {
						if strings.Contains(command.RedactedString(), marker) {
							t.Fatal("rendered command leaks marker")
						}
						if !reflect.DeepEqual(command.Redact, []string{marker}) {
							t.Fatalf("secret inventory changed: %q", command.Redact)
						}
					}
					if failAt < 3 {
						for _, command := range runner.calls {
							joined := strings.Join(command.Args, " ")
							for _, verb := range []string{"GRANT ", "REVOKE "} {
								if strings.Contains(joined, verb) {
									t.Fatalf("mutation after failed preflight: %q", joined)
								}
							}
						}
					}
				})
			}
		}
	}
}

// TestPostgresPrivilegesMutationRegistryKeys drives both mutations
// through the registry Call path and proves the mutation statement is
// reachable end to end with the shared transport after the preflight.
func TestPostgresPrivilegesMutationRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := reg.Call(context.Background(), rt, "postgres.privileges_grant",
		&PrivilegesGrantArgs{Name: "baruwa", ObjectName: "awl", ObjectType: "table", Privileges: "ALL"})
	if err != nil || value != true {
		t.Fatalf("registry grant = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `GRANT ALL ON TABLE public."awl" TO "baruwa"` {
		t.Fatalf("registry grant statement = %q", got)
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(privTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.privileges_revoke",
		&PrivilegesRevokeArgs{Name: "baruwa", ObjectName: "awl", ObjectType: "table", Privileges: "ALL"})
	if err != nil || value != true {
		t.Fatalf("registry revoke = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `REVOKE ALL ON TABLE public."awl" FROM baruwa` {
		t.Fatalf("registry revoke statement = %q", got)
	}
}

// TestPostgresPrivilegesMutationGuards pins the shared failure modes for
// both mutations: canceled context, runas rejection, redacted Runner
// errors, output limits, psql-unavailable fail-closed, the argument
// guards, and the nil Runner — each with zero Runner executions where the
// guard precedes the call.
func TestPostgresPrivilegesMutationGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (privilegesGrantFunc{}).Execute(ctx, rt, fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled grant err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled grant executed %d commands", len(runner.calls))
	}
	rt, runner = newPostgresRuntime()
	if _, err := (privilegesRevokeFunc{}).Execute(ctx, rt, fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled revoke err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled revoke executed %d commands", len(runner.calls))
	}

	for _, revoke := range []bool{false, true} {
		label := "grant"
		if revoke {
			label = "revoke"
		}
		rt, runner = newPostgresRuntime()
		var err error
		if revoke {
			args := fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")
			args.Runas = postgresString("postgres")
			_, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt, args)
		} else {
			args := fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
			args.Runas = postgresString("postgres")
			_, err = (privilegesGrantFunc{}).Execute(context.Background(), rt, args)
		}
		if !errors.Is(err, errPostgresRunas) {
			t.Fatalf("%s runas err = %v, want errPostgresRunas", label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s runas run executed %d commands", label, len(runner.calls))
		}

		rt, _ = newPostgresRuntime(process.CommandResult{
			ExitCode: -1,
			Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
		})
		if revoke {
			_, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
				fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
		} else {
			_, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
				fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
		}
		if err == nil || strings.Contains(err.Error(), "testpassword") {
			t.Fatalf("%s runner error = %v, want redacted", label, err)
		}
		if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
			t.Fatalf("%s error lacks redaction placeholder: %v", label, err)
		}

		for _, truncated := range []process.CommandResult{
			{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
			{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
		} {
			rt, _ = newPostgresRuntime(truncated)
			if revoke {
				_, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
					fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
			} else {
				_, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
					fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
			}
			if !errors.Is(err, process.ErrOutputLimit) {
				t.Fatalf("%s truncated err = %v, want ErrOutputLimit", label, err)
			}
		}

		rt, runner = newPostgresRuntime()
		runner.available = map[string]bool{"psql": false}
		if revoke {
			_, err = (privilegesRevokeFunc{}).Execute(context.Background(), rt,
				fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
		} else {
			_, err = (privilegesGrantFunc{}).Execute(context.Background(), rt,
				fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
		}
		if !errors.Is(err, errPostgresPsqlUnavailable) {
			t.Fatalf("%s psql-unavailable err = %v, want errPostgresPsqlUnavailable", label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s unavailable psql executed %d commands", label, len(runner.calls))
		}
	}

	if _, err := (privilegesGrantFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("privileges_grant must reject non-struct args")
	}
	if _, err := (privilegesGrantFunc{}).Execute(context.Background(), nil, &HasPrivilegesArgs{}); err == nil {
		t.Fatal("privileges_grant must reject foreign argument structs")
	}
	if _, err := (privilegesRevokeFunc{}).Execute(context.Background(), nil, &PrivilegesGrantArgs{}); err == nil {
		t.Fatal("privileges_revoke must reject foreign argument structs")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (privilegesGrantFunc{}).Execute(context.Background(), rtEmpty,
		fullPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
	if _, err := (privilegesRevokeFunc{}).Execute(context.Background(), rtEmpty,
		fullPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// default_privileges — salt/modules/postgres.py:3238-3332, 3435-3571,
// 3714-3877, 3880-4006 @ pinned revision. The pinned pytests do not cover
// the default-privilege family (only the postgres_default_privileges state
// maps it), so every vector here is derived from the pinned source.

// defPrivTableCSV renders the fixed pg_default_acl table catalog: the
// public schema carries a default ACL where baruwa holds every table
// privilege with the grant option and baruwatest holds the plain subset,
// while the private schema carries only a bayestest entry.
const defPrivTableCSV = `nspname,name
public,"{baruwatest=arwd/baruwatest,baruwa=a*r*w*d*D*x*t*/public}"
private,"{bayestest=arw/public}"
`

// defPrivGrantTableCSV renders the catalog where baruwa holds nothing in
// the public schema, so the grant preflight answers false.
const defPrivGrantTableCSV = `nspname,name
public,"{bayestest=arw/baruwatest}"
`

// defPrivHeldTableCSV renders the catalog where baruwa holds the plain
// SELECT,INSERT subset without grant options, so the revoke preflight
// answers true for that subset.
const defPrivHeldTableCSV = `nspname,name
public,"{baruwa=ar/public}"
`

// defPrivFunctionCSV renders the fixed pg_default_acl function catalog
// where baruwa holds plain EXECUTE in public.
const defPrivFunctionCSV = `nspname,name
public,"{baruwa=X/public}"
`

// defPrivGrantFunctionCSV renders the function catalog where baruwa
// holds nothing.
const defPrivGrantFunctionCSV = `nspname,name
public,"{bayestest=X/baruwatest}"
`

func fullDefaultPrivilegesListArgs(name, objectType string) *DefaultPrivilegesListArgs {
	return &DefaultPrivilegesListArgs{
		Name:          name,
		ObjectType:    objectType,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

func fullDefaultPrivilegesGrantArgs(name, objectName, objectType, defprivileges string) *DefaultPrivilegesGrantArgs {
	return &DefaultPrivilegesGrantArgs{
		Name:          name,
		ObjectName:    objectName,
		ObjectType:    objectType,
		DefPrivileges: defprivileges,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

func fullDefaultPrivilegesRevokeArgs(name, objectName, objectType, defprivileges string) *DefaultPrivilegesRevokeArgs {
	return &DefaultPrivilegesRevokeArgs{
		Name:          name,
		ObjectName:    objectName,
		ObjectType:    objectType,
		DefPrivileges: defprivileges,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

func fullHasDefaultPrivilegesArgs(name, objectName, objectType, defprivileges string) *HasDefaultPrivilegesArgs {
	return &HasDefaultPrivilegesArgs{
		Name:          name,
		ObjectName:    objectName,
		ObjectType:    objectType,
		DefPrivileges: defprivileges,
		MaintenanceDB: postgresString("db_name"),
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	}
}

// TestPostgresDefaultPrivilegesListArgv pins the fixed COPY-wrapped
// pg_default_acl catalog query on the full pinned argv with the pinned
// clean environment, the password as the only Redact secret, the shared
// command bounds, and the pinned prepend default matching client-side.
func TestPostgresDefaultPrivilegesListArgv(t *testing.T) {
	rt, runner := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(defPrivTableCSV),
	})
	value, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	want := []string{
		"psql",
		"--no-align",
		"--no-readline",
		"--no-psqlrc",
		"--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "db_name",
		"-v", "datestyle=ISO,MDY",
		"-c", "COPY (SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='r' ORDER BY nspname) TO STDOUT WITH CSV HEADER",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	wantEnv := []string{
		"PGPASSWORD=testpassword",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "testpassword") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
	// The pinned object name and schema prefix never reach SQL: only the
	// fixed catalog does, and the caller's lookup strings appear nowhere.
	if joined := strings.Join(command.Args, "\x00"); strings.Contains(joined, "awl") || strings.Contains(joined, "public") {
		t.Fatalf("query leaked a lookup string: %q", joined)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("value = %#v, want map", value)
	}
}

// TestPostgresDefaultPrivilegesListDecode pins the pinned default-ACL
// decode ladder: the grantee bool-maps with the grant-star flip, the
// public grantee, the leading-star GRANT key, the group admin_option
// booleans, the NULL/malformed-ACL ValueError shape, and the schema-type
// row whose key is the object name.
func TestPostgresDefaultPrivilegesListDecode(t *testing.T) {
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte(`nspname,name
public,"{=ar/public,baruwa=a*r*w*d*D*x*t*/public,postgres=*t/public}"
`),
	})
	value, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"public": map[string]bool{"INSERT": false, "SELECT": false},
		"baruwa": map[string]bool{
			"INSERT": true, "SELECT": true, "UPDATE": true, "DELETE": true,
			"TRUNCATE": true, "REFERENCES": true, "TRIGGER": true,
		},
		"postgres": map[string]bool{"GRANT": false, "TRIGGER": false},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("table decode = %#v, want %#v", value, want)
	}

	// The CONNECT/TEMPORARY/MAINTAIN characters the pinned
	// _DEFAULT_PRIVILEGES_MAP lacks are the pinned KeyError.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte(`nspname,name
public,"{baruwa=c/public}"
`),
	})
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresInvalidACL) {
		t.Fatalf("CONNECT err = %v, want errPostgresInvalidACL", err)
	}

	// A NULL default ACL (empty CSV field) and a malformed entry are the
	// pinned ValueError.
	for _, acl := range []string{`public,`, `public,"{baruwa/public}"`, `public,"{baruwa=a/public/extra}"`} {
		rt, _ := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("nspname,name\n" + acl + "\n"),
		})
		if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
			fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresInvalidACL) {
			t.Fatalf("acl %q err = %v, want errPostgresInvalidACL", acl, err)
		}
	}

	// The schema type keys the pinned nspname equality on the object name
	// and decodes the namespace ACL with the default map.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte(`nspname,name
public,"{baruwa=UC/postgres}"
`),
	})
	value, err = (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("public", "schema"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string]any{
		"baruwa": map[string]bool{"USAGE": false, "CREATE": false},
	}) {
		t.Fatalf("schema decode = %#v", value)
	}

	// The group type maps every member rolname to its admin_option.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(privGroupCSV),
	})
	value, err = (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("admin", "group"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string]any{
		"baruwa": false, "baruwatest2": true, "baruwatest": false,
	}) {
		t.Fatalf("group decode = %#v", value)
	}

	// A missing object answers the empty dictionary: the fake Runner
	// answers whatever CSV it holds regardless of the SQL, so the
	// client-side nspname match against the pinned public default must
	// miss a private-only catalog. A failed psql connection keeps
	// Salt's empty-catalog compatibility shape.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("nspname,name\nprivate,\"{bayestest=arw/public}\"\n"),
	})
	value, err = (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table"))
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("missing object = %#v err = %v, want {}, nil", value, err)
	}
	rt, _ = newPostgresRuntime(process.CommandResult{ExitCode: 2, Stderr: []byte("psql: error: connection refused")})
	value, err = (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table"))
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("nonzero exit = %#v err = %v, want {}, nil", value, err)
	}
}

// TestPostgresDefaultPrivilegesListObjectTypes pins the per-object-type
// fixed SQL — the pinned defaclobjtype constants and orderings, the reused
// schema and group catalogs — and the client-side prepend and object-name
// filters.
func TestPostgresDefaultPrivilegesListObjectTypes(t *testing.T) {
	cases := []struct {
		label      string
		name       string
		objectType string
		prepend    *string
		query      string
	}{
		{
			"table", "awl", "table", nil,
			"SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='r' ORDER BY nspname",
		},
		{
			"sequence", "awl_seq", "sequence", postgresString("private"),
			"SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='S' ORDER BY nspname",
		},
		{
			"schema", "public", "schema", nil,
			"SELECT nspname, nspacl AS name FROM pg_catalog.pg_namespace ORDER BY nspname",
		},
		{
			"function", "fawl", "function", nil,
			"SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='f' ORDER BY nspname",
		},
		{
			"group", "admins", "group", nil,
			"SELECT (SELECT rolname FROM pg_catalog.pg_roles rr WHERE rr.oid = m.roleid) AS member_of, rolname, admin_option FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON m.member=r.oid ORDER BY rolname",
		},
	}
	for _, tc := range cases {
		rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("name\n\n")})
		args := fullDefaultPrivilegesListArgs(tc.name, tc.objectType)
		args.Prepend = tc.prepend
		if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args); err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s calls = %d, want 1", tc.label, len(runner.calls))
		}
		got := runner.calls[0].Args[len(runner.calls[0].Args)-1]
		if want := "COPY (" + tc.query + ") TO STDOUT WITH CSV HEADER"; got != want {
			t.Fatalf("%s query = %q, want %q", tc.label, got, want)
		}
	}

	// The prepend filter is client-side and exact: the pinned "public"
	// default answers the public row and prepend=private answers the
	// private row, while an explicit empty prepend matches nothing
	// (Salt's empty-schema handling).
	for _, tc := range []struct {
		prepend *string
		keys    []string
	}{
		{nil, []string{"baruwatest", "baruwa"}},
		{postgresString("private"), []string{"bayestest"}},
	} {
		rt, _ := newPostgresRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte(defPrivTableCSV),
		})
		args := fullDefaultPrivilegesListArgs("awl", "table")
		args.Prepend = tc.prepend
		value, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatal(err)
		}
		listed, ok := value.(map[string]any)
		if !ok || len(listed) != len(tc.keys) {
			t.Fatalf("prepend %+v decode = %#v, want keys %q", tc.prepend, value, tc.keys)
		}
		for _, key := range tc.keys {
			if _, ok := listed[key]; !ok {
				t.Fatalf("prepend %+v decode = %#v, missing %s", tc.prepend, value, key)
			}
		}
	}
	rt, _ := newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(defPrivTableCSV),
	})
	args := fullDefaultPrivilegesListArgs("awl", "table")
	args.Prepend = postgresString("")
	if value, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args); err != nil ||
		!reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("empty prepend = %#v err = %v, want {}", value, err)
	}

	// The schema filter keys the object name, not the prepend.
	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("nspname,name\npublic,\"{baruwa=UC/postgres}\"\n"),
	})
	args = fullDefaultPrivilegesListArgs("other", "schema")
	args.Prepend = postgresString("public")
	if value, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args); err != nil ||
		!reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("schema name filter = %#v err = %v, want {}", value, err)
	}
}

// TestPostgresDefaultPrivilegesListValidation pins the pinned head: the
// object type is lowercased and unknown types are rejected before any
// Runner invocation, covering the pinned dead SaltInvocationError after
// the unbound-local query builder.
func TestPostgresDefaultPrivilegesListValidation(t *testing.T) {
	for _, objectType := range []string{"bogus", "", "database", "tablespace", "language"} {
		rt, runner := newPostgresRuntime()
		_, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
			fullDefaultPrivilegesListArgs("awl", objectType))
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("object_type %q err = %v, want errPostgresInvalidArgument", objectType, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("object_type %q executed %d commands before validation", objectType, len(runner.calls))
		}
	}

	// Mixed case lowercases onto the pinned catalog.
	rt, runner := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)})
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "TaBLe")); err != nil {
		t.Fatalf("TaBLe err = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("TaBLe calls = %d, want 1", len(runner.calls))
	}
}

// TestPostgresDefaultPrivilegesListGuards pins the shared failure modes:
// canceled context, runas rejection, redacted Runner errors, output
// limits, psql-unavailable fail-closed, the argument guards, and the nil
// Runner — each with zero Runner executions where the guard precedes the
// call.
func TestPostgresDefaultPrivilegesListGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (defaultPrivilegesListFunc{}).Execute(ctx, rt, fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	args := fullDefaultPrivilegesListArgs("awl", "table")
	args.Runas = postgresString("postgres")
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v, want errPostgresRunas", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
	})
	_, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, fullDefaultPrivilegesListArgs("awl", "table"))
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
		if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
			fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql-unavailable err = %v, want errPostgresPsqlUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("default_privileges_list must reject non-struct args")
	}
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), nil, &HasPrivilegesArgs{}); err == nil {
		t.Fatal("default_privileges_list must reject foreign argument structs")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (defaultPrivilegesListFunc{}).Execute(context.Background(), rtEmpty,
		fullDefaultPrivilegesListArgs("awl", "table")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}

// TestPostgresDefaultPrivilegesGrantArgv pins the pinned ALTER DEFAULT
// PRIVILEGES statements for every branch: the group membership forms with
// and without ADMIN OPTION, the ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA
// variants, and the plain forms — including the pinned asymmetry where
// the grant_option non-ALL branch interpolates the on-part into IN SCHEMA
// (schema-qualified double-quoted for table/sequence, the bare function
// name for function, the plain quoted name for schema) while every other
// branch interpolates the bare schema prefix. Statements ride the full
// pinned argv (SQL at index 14) after the owner-plus-catalog preflight
// pair, with the pinned clean environment and the password as the only
// Redact secret.
func TestPostgresDefaultPrivilegesGrantArgv(t *testing.T) {
	cases := []struct {
		label       string
		name        string
		objectName  string
		objectType  string
		defprivs    string
		grantOption bool
		prepend     *string
		ownerCSV    string
		defCSV      string
		query       string
	}{
		{
			"table with option carries the on-part", "baruwa", "awl", "table", "ALL", true,
			nil, ownerTableCSV, defPrivGrantTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public."awl" GRANT ALL ON TABLES TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"table plain uses the schema prefix", "baruwa", "awl", "table", "ALL", false,
			nil, ownerTableCSV, defPrivGrantTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "baruwa"`,
		},
		{
			"all tables in schema", "baruwa", "ALL", "table", "SELECT", false,
			nil, ownerTableCSV, defPrivGrantTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "baruwa"`,
		},
		{
			"all tables in schema with option", "baruwa", "all", "table", "SELECT", true,
			nil, ownerTableCSV, defPrivGrantTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"sequence prepend and split", "baruwa", "awl_seq", "sequence", "SELECT , USAGE", false,
			postgresString("private"), "nspname,relname,name\nprivate,awl_seq,postgres\n", defPrivGrantTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA private GRANT SELECT,USAGE ON SEQUENCES TO "baruwa"`,
		},
		{
			"function with option carries the bare name", "baruwa", "fawl", "function", "EXECUTE", true,
			nil, ownerFunctionCSV, defPrivGrantFunctionCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA fawl GRANT EXECUTE ON FUNCTIONS TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"function plain uses the schema prefix", "baruwa", "fawl", "function", "EXECUTE", false,
			nil, ownerFunctionCSV, defPrivGrantFunctionCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO "baruwa"`,
		},
		{
			"schema with option carries the quoted name", "baruwa", "myschema", "schema", "USAGE,CREATE", true,
			nil, "nspname,name\npublic,postgres\n", "nspname,name\npublic,\"{bayestest=UC/postgres}\"\n",
			`ALTER DEFAULT PRIVILEGES IN SCHEMA "myschema" GRANT USAGE,CREATE ON SCHEMAS TO "baruwa" WITH GRANT OPTION`,
		},
		{
			"schema plain uses the schema prefix", "baruwa", "myschema", "schema", "USAGE", false,
			nil, "nspname,name\npublic,postgres\n", "nspname,name\npublic,\"{bayestest=UC/postgres}\"\n",
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SCHEMAS TO "baruwa"`,
		},
	}
	for _, tc := range cases {
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			{ExitCode: 0, Stdout: []byte(tc.defCSV)},
			{ExitCode: 0},
		}
		rt, runner := newPostgresRuntime(results...)
		args := fullDefaultPrivilegesGrantArgs(tc.name, tc.objectName, tc.objectType, tc.defprivs)
		args.GrantOption = tc.grantOption
		args.Prepend = tc.prepend
		value, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.label, value)
		}
		if len(runner.calls) != 3 {
			t.Fatalf("%s calls = %d, want 3 (owner + catalog + grant)", tc.label, len(runner.calls))
		}
		command := runner.calls[2]
		want := []string{
			"psql",
			"--no-align",
			"--no-readline",
			"--no-psqlrc",
			"--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "db_name",
			"-c", tc.query,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.label, got, want)
		}
		wantEnv := []string{
			"PGPASSWORD=testpassword",
			"PGUSER=testuser",
			"PGHOST=testhost",
			"PGPORT=testport",
		}
		if !reflect.DeepEqual(command.Env, wantEnv) {
			t.Fatalf("%s env = %q, want %q", tc.label, command.Env, wantEnv)
		}
		if command.Shell {
			t.Fatalf("%s psql must run without a shell", tc.label)
		}
		if command.Timeout != commandTimeout ||
			command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("%s unsafe command bounds: %#v", tc.label, command)
		}
		if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
			t.Fatalf("%s redact = %q", tc.label, command.Redact)
		}
		if rendered := command.RedactedString(); strings.Contains(rendered, "testpassword") {
			t.Fatalf("%s rendered command leaks password: %q", tc.label, rendered)
		}
		// The preflight queries embed no caller string; only the mutation
		// statement does, in its validated identifier positions.
		for i, call := range runner.calls[:2] {
			joined := strings.Join(call.Args, "\x00")
			if strings.Contains(joined, "baruwa") || strings.Contains(joined, "awl") {
				t.Fatalf("%s preflight call %d leaked a lookup string: %q", tc.label, i, joined)
			}
		}
	}

	// The pinned group statements: one membership preflight, then the raw
	// membership GRANT with and without ADMIN OPTION.
	for _, tc := range []struct {
		label       string
		grantOption bool
		query       string
	}{
		{"group admin option", true, `ALTER DEFAULT PRIVILEGES GRANT admins TO "baruwa" WITH ADMIN OPTION`},
		{"group membership", false, `ALTER DEFAULT PRIVILEGES GRANT admins TO "baruwa"`},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantGroupCSV)},
			process.CommandResult{ExitCode: 0},
		)
		args := fullDefaultPrivilegesGrantArgs("baruwa", "admins", "group", "")
		args.GrantOption = tc.grantOption
		value, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, args)
		if err != nil || value != true {
			t.Fatalf("%s = %#v err = %v, want true", tc.label, value, err)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %d, want 2 (membership + grant)", tc.label, len(runner.calls))
		}
		if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != tc.query {
			t.Fatalf("%s statement = %q, want %q", tc.label, got, tc.query)
		}
	}
}

// TestPostgresDefaultPrivilegesRevokeArgv pins the pinned ALTER DEFAULT
// PRIVILEGES REVOKE statements: the object form with the bare schema
// prefix in IN SCHEMA and the raw (unquoted) role name of the REVOKE
// tail, and the group membership form with both names raw. The ALL
// privilege list never reaches a statement in the pinned flow (its
// preflight branch is the deterministic dict_keys failure), so the
// working vectors use plain privilege lists the preflight answers held.
func TestPostgresDefaultPrivilegesRevokeArgv(t *testing.T) {
	cases := []struct {
		label      string
		name       string
		objectName string
		objectType string
		defprivs   string
		prepend    *string
		ownerCSV   string
		defCSV     string
		query      string
	}{
		{
			"table subset", "baruwa", "awl", "table", "SELECT,INSERT", nil,
			ownerTableCSV, defPrivHeldTableCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT,INSERT ON TABLES FROM baruwa`,
		},
		{
			"sequence prepend", "baruwa", "awl_seq", "sequence", "SELECT", postgresString("private"),
			"nspname,relname,name\nprivate,awl_seq,postgres\n",
			"nspname,name\nprivate,\"{baruwa=ar/public}\"\n",
			`ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE SELECT ON SEQUENCES FROM baruwa`,
		},
		{
			"function execute", "baruwa", "fawl", "function", "EXECUTE", nil,
			ownerFunctionCSV, defPrivFunctionCSV,
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM baruwa`,
		},
		{
			"schema usage", "baruwa", "public", "schema", "USAGE", nil,
			"nspname,name\npublic,postgres\n", "nspname,name\npublic,\"{baruwa=UC/postgres}\"\n",
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON SCHEMAS FROM baruwa`,
		},
	}
	for _, tc := range cases {
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			{ExitCode: 0, Stdout: []byte(tc.defCSV)},
			{ExitCode: 0},
		}
		rt, runner := newPostgresRuntime(results...)
		args := fullDefaultPrivilegesRevokeArgs(tc.name, tc.objectName, tc.objectType, tc.defprivs)
		args.Prepend = tc.prepend
		value, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != true {
			t.Fatalf("%s = %#v, want true", tc.label, value)
		}
		if len(runner.calls) != 3 {
			t.Fatalf("%s calls = %d, want 3 (owner + catalog + revoke)", tc.label, len(runner.calls))
		}
		command := runner.calls[2]
		want := []string{
			"psql",
			"--no-align",
			"--no-readline",
			"--no-psqlrc",
			"--no-password",
			"--username", "testuser",
			"--host", "testhost",
			"--port", "testport",
			"--dbname", "db_name",
			"-c", tc.query,
		}
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv = %q, want %q", tc.label, got, want)
		}
		if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
			t.Fatalf("%s redact = %q", tc.label, command.Redact)
		}
	}

	// The pinned group statement with both names raw: one membership
	// preflight where baruwa is a member, then the REVOKE.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesRevokeArgs("baruwa", "admin", "group", ""))
	if err != nil || value != true {
		t.Fatalf("group revoke = %#v err = %v, want true", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("group revoke calls = %d, want 2", len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "ALTER DEFAULT PRIVILEGES REVOKE admin FROM baruwa" {
		t.Fatalf("group revoke statement = %q", got)
	}
}

// TestPostgresDefaultPrivilegesMutationNoop pins the pinned preflight
// short circuits: an already-granted grant and a not-yet-held revoke
// return False with no mutation statement — exactly the pinned calls the
// runner results cover and no extra one — including the owner shortcut
// that satisfies the preflight after the owner query alone, the member
// no-op, and the group admin_option shape.
func TestPostgresDefaultPrivilegesMutationNoop(t *testing.T) {
	// Grant to the role that already holds the plain subset (the
	// defPrivHeldTableCSV baruwa row), with grant_option set: the pinned
	// preflight never receives grant_option, so the subset check alone
	// answers true and no GRANT runs.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivHeldTableCSV)},
	)
	args := fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
	args.GrantOption = true
	value, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != false {
		t.Fatalf("already-granted = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("already-granted calls = %d, want 2", len(runner.calls))
	}

	// The owner shortcut: postgres owns awl, so the preflight answers
	// true after the owner query alone.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
	)
	value, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesGrantArgs("postgres", "awl", "table", "SELECT"))
	if err != nil || value != false {
		t.Fatalf("owner grant = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("owner grant calls = %d, want 1", len(runner.calls))
	}

	// Grant to a group member: membership alone satisfies the preflight
	// even though the admin_option is false.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	args = fullDefaultPrivilegesGrantArgs("baruwa", "admin", "group", "")
	args.GrantOption = true
	value, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != false {
		t.Fatalf("member grant = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("member grant calls = %d, want 1", len(runner.calls))
	}

	// Revoke from a role that holds nothing: false after the two
	// preflight queries, no REVOKE.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
	)
	value, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT,INSERT"))
	if err != nil || value != false {
		t.Fatalf("nothing-held revoke = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("nothing-held revoke calls = %d, want 2", len(runner.calls))
	}

	// Revoke from a non-member: false after the one membership query.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGrantGroupCSV)},
	)
	value, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesRevokeArgs("baruwa", "admins", "group", ""))
	if err != nil || value != false {
		t.Fatalf("non-member revoke = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("non-member revoke calls = %d, want 1", len(runner.calls))
	}

	// Every short-circuit path keeps its executed commands free of any
	// mutation verb: only fixed COPY catalogs ran.
	for i, call := range runner.calls {
		joined := strings.Join(call.Args, " ")
		for _, verb := range []string{"GRANT ", "REVOKE ", "ALTER DEFAULT PRIVILEGES"} {
			if strings.Contains(joined, verb) {
				t.Fatalf("no-op path executed a mutation: call %d = %q", i, joined)
			}
		}
	}

	// A rejected statement keeps the pinned retcode boolean: false,
	// never an error.
	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: schema "public" does not exist`)},
	)
	value, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
	if err != nil || value != false {
		t.Fatalf("nonzero exit grant = %#v err = %v, want false", value, err)
	}
}

// TestPostgresDefaultPrivilegesHasSemantics pins the internal
// has_default_privileges decision core directly (the shared core the
// R9.2q public registration and the pinned mutations both run): the
// grant-option dict equality, the pinned
// ALL comparison whose dict_keys.sort() shape is a deterministic
// AttributeError mapped to a fixed value-free error, the strict-subset
// miss, and the group admin_option boolean under grant_option.
func TestPostgresDefaultPrivilegesHasSemantics(t *testing.T) {
	conn := &pgConnection{}
	ctx := context.Background()

	// The grant-option equality: baruwa's starred row carries every table
	// privilege with the option, baruwatest's plain row does not.
	for _, tc := range []struct {
		name string
		want bool
	}{{"baruwa", true}, {"baruwatest", false}} {
		rt, _ := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
		)
		got, err := hasDefaultPrivileges(ctx, rt, conn, "test", tc.name, "awl", "table",
			[]string{"SELECT"}, true, "public")
		if err != nil || got != tc.want {
			t.Fatalf("grant-option %s = %v err = %v, want %v", tc.name, got, err, tc.want)
		}
	}

	// The pinned ALL branch: defperms.sort() == dict_keys.sort() raises
	// AttributeError before any boolean, both directly and through the
	// public mutation preflights.
	rt, _ := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	if _, err := hasDefaultPrivileges(ctx, rt, conn, "test", "baruwa", "awl", "table",
		[]string{"ALL"}, false, "public"); !errors.Is(err, errPostgresDefprivilegesAllCompare) {
		t.Fatalf("ALL err = %v, want errPostgresDefprivilegesAllCompare", err)
	}
	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	if _, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "ALL")); !errors.Is(err, errPostgresDefprivilegesAllCompare) {
		t.Fatalf("grant ALL err = %v, want errPostgresDefprivilegesAllCompare", err)
	}
	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	if _, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "ALL")); !errors.Is(err, errPostgresDefprivilegesAllCompare) {
		t.Fatalf("revoke ALL err = %v, want errPostgresDefprivilegesAllCompare", err)
	}
	// ALL against an absent grantee never reaches the branch: the miss is
	// the logged-and-False revoke no-op.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
	)
	value, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "ALL"))
	if err != nil || value != false {
		t.Fatalf("absent ALL revoke = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("absent ALL revoke calls = %d, want 2", len(runner.calls))
	}
	// The same false preflight is not a grant no-op: mutation runs and
	// its retcode determines the result.
	for _, exitCode := range []int{0, 1} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
			process.CommandResult{ExitCode: exitCode},
		)
		value, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
			fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "ALL"))
		if err != nil || value != (exitCode == 0) || len(runner.calls) != 3 {
			t.Fatalf("absent ALL grant retcode=%d value=%v err=%v calls=%d", exitCode, value, err, len(runner.calls))
		}
		if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "baruwa"` {
			t.Fatalf("absent ALL grant statement = %q", got)
		}
	}

	// The strict-subset miss: SELECT,UPDATE against a plain ar row.
	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivHeldTableCSV)},
	)
	got, err := hasDefaultPrivileges(ctx, rt, conn, "test", "baruwa", "awl", "table",
		[]string{"SELECT", "UPDATE"}, false, "public")
	if err != nil || got != false {
		t.Fatalf("subset miss = %v err = %v, want false", got, err)
	}

	// The group admin_option boolean under grant_option; the runner is
	// rebuilt per case because the fake serves one queued result.
	for _, tc := range []struct {
		name string
		want bool
	}{{"baruwa", false}, {"baruwatest2", true}} {
		rt, _ := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
		)
		got, err := hasDefaultPrivileges(ctx, rt, conn, "test", tc.name, "admin", "group",
			nil, true, "public")
		if err != nil || got != tc.want {
			t.Fatalf("group grant-option %s = %v err = %v, want %v", tc.name, got, err, tc.want)
		}
	}
}

// TestPostgresHasDefaultPrivilegesArgv pins the exact two-call transport
// of the public R9.2q registration: the fixed owner catalog query first,
// the fixed pg_default_acl default-privilege catalog second, both
// COPY-wrapped SQL with no caller string inside, and the connection tuple
// transported exactly like the pinned psql_query call.
func TestPostgresHasDefaultPrivilegesArgv(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	args := fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT,INSERT")
	args.Prepend = postgresString("testschema")
	if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (owner + default privileges)", len(runner.calls))
	}
	for i, want := range []string{
		`COPY (SELECT schemaname, tablename, tableowner AS name FROM pg_tables) TO STDOUT WITH CSV HEADER`,
		`COPY (SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='r' ORDER BY nspname) TO STDOUT WITH CSV HEADER`,
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
			strings.Contains(joined, "baruwa") || strings.Contains(joined, "testschema") {
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

// TestPostgresHasDefaultPrivilegesSemantics pins the public
// postgres.has_default_privileges outcomes on the R9.2l fixtures: the
// owner shortcut after the owner query alone, the strict-subset hit and
// miss, the schema-prefix client-side match, the grant-option dict
// equality under the caller's own grant_option, the absent-grantee false,
// and the pinned ALL comparison error against a grantee holding an entry.
func TestPostgresHasDefaultPrivilegesSemantics(t *testing.T) {
	cases := []struct {
		label         string
		name          string
		defprivileges string
		grantOption   bool
		prepend       string
		shortcut      bool
		want          bool
	}{
		{"baruwa subset hit", "baruwa", "SELECT,INSERT", false, "public", false, true},
		{"baruwatest subset miss", "baruwatest", "SELECT,INSERT,TRUNCATE", false, "public", false, false},
		{"baruwa grant option", "baruwa", "SELECT", true, "public", false, true},
		{"baruwatest grant option", "baruwatest", "SELECT", true, "public", false, false},
		{"private schema subset", "bayestest", "SELECT,INSERT,UPDATE", false, "private", false, true},
		{"public schema miss", "bayestest", "SELECT", false, "public", false, false},
		{"absent role", "tony", "SELECT", false, "public", false, false},
		{"owner shortcut", "postgres", "SELECT", false, "public", true, true},
		{"owner shortcut named", "baruwa", "SELECT", false, "public", true, true},
	}
	for _, tc := range cases {
		ownerCSV := ownerTableCSV
		if tc.shortcut && tc.name == "baruwa" {
			// awl owned by baruwa: the owner shortcut returns true after
			// the owner query alone.
			ownerCSV = "schemaname,tablename,name\npublic,awl,baruwa\n"
		}
		results := []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(ownerCSV)},
			{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
		}
		rt, runner := newPostgresRuntime(results...)
		args := fullHasDefaultPrivilegesArgs(tc.name, "awl", "table", tc.defprivileges)
		args.GrantOption = tc.grantOption
		args.Prepend = postgresString(tc.prepend)
		value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != tc.want {
			t.Fatalf("%s = %#v, want %#v", tc.label, value, tc.want)
		}
		wantCalls := 2
		if tc.shortcut {
			wantCalls = 1
		}
		if len(runner.calls) != wantCalls {
			t.Fatalf("%s calls = %d, want %d", tc.label, len(runner.calls), wantCalls)
		}
	}

	// The pinned ALL branch: against a grantee holding a default ACL
	// entry the dict_keys.sort() comparison is the fixed value-free
	// error; against an absent grantee the miss answers false without
	// reaching the branch.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	_, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "ALL"))
	if !errors.Is(err, errPostgresDefprivilegesAllCompare) {
		t.Fatalf("held ALL err = %v, want errPostgresDefprivilegesAllCompare", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("held ALL calls = %d, want 2", len(runner.calls))
	}
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
	)
	value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "ALL"))
	if err != nil || value != false {
		t.Fatalf("absent ALL = %#v err = %v, want false, nil", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("absent ALL calls = %d, want 2", len(runner.calls))
	}
	// The error is value-free: a caller secret overlapping the connection
	// cannot travel through it.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	marker := "synthetic_hasdefpriv_all_marker"
	args := fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "ALL")
	args.Password = postgresString(marker)
	_, err = (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args)
	if !errors.Is(err, errPostgresDefprivilegesAllCompare) || strings.Contains(err.Error(), marker) {
		t.Fatalf("ALL overlap err = %v", err)
	}
}

// TestPostgresHasDefaultPrivilegesGroup pins the public group flow: no
// owner query at all, membership true, the grant-option check answering
// the member's admin_option boolean, an absent role false, and the group
// name matched client-side only.
func TestPostgresHasDefaultPrivilegesGroup(t *testing.T) {
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
		args := fullHasDefaultPrivilegesArgs(tc.name, "admin", "group", "")
		args.GrantOption = tc.grantOption
		value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args)
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

	// The group name never reaches SQL.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(privGroupCSV)},
	)
	value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "grp_leak_check", "group", ""))
	if err != nil || value != false {
		t.Fatalf("group leak check = %#v err = %v, want false", value, err)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "grp_leak_check") {
		t.Fatalf("group query leaked the group name into SQL: %q", joined)
	}
}

// TestPostgresHasDefaultPrivilegesObjectTypes sweeps the remaining
// default-privilege object types through their fixed owner and
// pg_default_acl catalogs, including the schema branch that keys the
// object name (not the prepend prefix) on nspname.
func TestPostgresHasDefaultPrivilegesObjectTypes(t *testing.T) {
	defPrivSequenceCSV := `nspname,name
public,"{baruwa=rwU/public}"
`
	ownerSchemaCSV := `nspname,name
public,postgres
private,postgres
`
	defPrivSchemaCSV := `nspname,name
public,"{postgres=UC/postgres,baruwa=U/public}"
private,"{bayestest=U/public}"
`
	ownerFunctionFixtureCSV := `nspname,regprocedure,name
public,awl,postgres
`
	sequenceSQL := `COPY (SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='S' ORDER BY nspname) TO STDOUT WITH CSV HEADER`
	schemaSQL := `COPY (SELECT nspname, nspacl AS name FROM pg_catalog.pg_namespace ORDER BY nspname) TO STDOUT WITH CSV HEADER`
	functionSQL := `COPY (SELECT nspname, defacl.defaclacl AS name FROM pg_default_acl defacl JOIN pg_authid aid ON defacl.defaclrole = aid.oid  JOIN pg_namespace nsp  ON nsp.oid = defacl.defaclnamespace WHERE defaclobjtype ='f' ORDER BY nspname) TO STDOUT WITH CSV HEADER`
	for _, tc := range []struct {
		label         string
		name          string
		objectType    string
		objectName    string
		defprivileges string
		ownerCSV      string
		privCSV       string
		want          bool
		wantObjectSQL string
	}{
		{
			"sequence", "baruwa", "sequence", "awl_seq", "SELECT,UPDATE,USAGE",
			"nspname,relname,name\npublic,awl_seq,postgres\n",
			defPrivSequenceCSV, true, sequenceSQL,
		},
		{
			"schema public row", "baruwa", "schema", "public", "USAGE",
			ownerSchemaCSV, defPrivSchemaCSV, true, schemaSQL,
		},
		{
			"schema subset miss", "baruwa", "schema", "public", "USAGE,CREATE",
			ownerSchemaCSV, defPrivSchemaCSV, false, "",
		},
		{
			"schema other row", "bayestest", "schema", "private", "USAGE",
			ownerSchemaCSV, defPrivSchemaCSV, true, "",
		},
		{
			"schema wrong row for role", "baruwa", "schema", "private", "USAGE",
			ownerSchemaCSV, defPrivSchemaCSV, false, "",
		},
		{
			"function", "baruwa", "function", "awl", "EXECUTE",
			ownerFunctionFixtureCSV, defPrivFunctionCSV, true, functionSQL,
		},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.ownerCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.privCSV)},
		)
		value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
			fullHasDefaultPrivilegesArgs(tc.name, tc.objectName, tc.objectType, tc.defprivileges))
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if value != tc.want {
			t.Fatalf("%s = %#v, want %#v", tc.label, value, tc.want)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %d, want 2", tc.label, len(runner.calls))
		}
		if tc.wantObjectSQL != "" {
			if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != tc.wantObjectSQL {
				t.Fatalf("%s default-privilege SQL = %q, want %q", tc.label, got, tc.wantObjectSQL)
			}
		}
	}
}

// TestPostgresHasDefaultPrivilegesValidation pins the pinned validation
// head for the public check: every rejected input fails value-free before
// any Runner invocation, direct and through the registry, and the
// default-privilege allowlist refuses the characters the pinned
// _PRIVILEGES map carries but the pinned _DEFAULT_PRIVILEGES map does
// not.
func TestPostgresHasDefaultPrivilegesValidation(t *testing.T) {
	const marker = "synthetic_hasdefpriv_marker"
	for _, tc := range []struct {
		label      string
		objectType string
		defprivs   string
	}{
		{"unknown object type", "bogus", "SELECT"},
		{"empty object type", "", "SELECT"},
		{"non-default object type", "tablespace", "CREATE"},
		{"non-default object type language", "language", "USAGE"},
		{"non-default object type database", "database", "CONNECT"},
		{"invalid privilege", "table", "SELECT,BOGUS"},
		{"missing privileges", "table", ""},
		{"connect not a default privilege", "table", "CONNECT"},
		{"temporary not a default privilege", "schema", "TEMPORARY"},
		{"maintain not a default privilege", "table", "MAINTAIN"},
		{"privileges for group", "group", "SELECT"},
	} {
		for _, entry := range []string{"direct", "registry"} {
			t.Run(tc.label+"/"+entry, func(t *testing.T) {
				rt, runner := newPostgresRuntime()
				args := fullHasDefaultPrivilegesArgs("baruwa", "awl", tc.objectType, tc.defprivs)
				args.Password = postgresString(marker)
				var err error
				if entry == "registry" {
					rt.Exec = runtime.NewExecRegistry()
					if err := Register(rt.Exec); err != nil {
						t.Fatal(err)
					}
					_, err = rt.Exec.Call(context.Background(), rt, "postgres.has_default_privileges", args)
				} else {
					_, err = (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args)
				}
				if !errors.Is(err, errPostgresInvalidArgument) {
					t.Fatalf("%s %s err = %v, want errPostgresInvalidArgument", tc.label, entry, err)
				}
				if strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
					t.Fatalf("%s %s leaked input or invoked Runner", tc.label, entry)
				}
			})
		}
	}

	// Mixed-case object types and spaced privilege lists behave exactly
	// like the pinned _mod_defpriv_opts.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "TABLE", "select , insert"))
	if err != nil || value != true {
		t.Fatalf("TABLE case/spaces = %#v err = %v, want true", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("TABLE case calls = %d, want 2", len(runner.calls))
	}
}

// TestPostgresHasDefaultPrivilegesCompatibilityData pins Salt's
// nonzero-exit shape on the public check: both catalog queries return the
// empty list, so the owner is None and every membership is false — data,
// not an error.
func TestPostgresHasDefaultPrivilegesCompatibilityData(t *testing.T) {
	failed := process.CommandResult{ExitCode: 2, Stderr: []byte("psql: error: connection refused")}
	rt, _ := newPostgresRuntime(failed)
	value, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT"))
	if err != nil || value != false {
		t.Fatalf("nonzero exit = %#v err = %v, want false, nil", value, err)
	}
	rt, _ = newPostgresRuntime(failed)
	value, err = (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "admin", "group", ""))
	if err != nil || value != false {
		t.Fatalf("group nonzero exit = %#v err = %v, want false, nil", value, err)
	}
}

// TestPostgresHasDefaultPrivilegesGuards pins the shared failure modes on
// the public check: canceled context, runas rejection, redacted Runner
// errors, output limits, psql-unavailable fail-closed, and the argument
// guards, each with zero Runner executions where the guard precedes the
// call.
func TestPostgresHasDefaultPrivilegesGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (hasDefaultPrivilegesFunc{}).Execute(ctx, rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	args := fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT")
	args.Runas = postgresString("postgres")
	if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt, args); !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v, want errPostgresRunas", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
	})
	_, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT"))
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
		rt, _ = newPostgresRuntime(truncated)
		if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
			fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("truncated err = %v, want ErrOutputLimit", err)
		}
	}

	rt, runner = newPostgresRuntime()
	runner.available = map[string]bool{"psql": false}
	if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rt,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresPsqlUnavailable) {
		t.Fatalf("psql-unavailable err = %v, want errPostgresPsqlUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable psql executed %d commands", len(runner.calls))
	}

	if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("has_default_privileges must reject non-struct args")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (hasDefaultPrivilegesFunc{}).Execute(context.Background(), rtEmpty,
		fullHasDefaultPrivilegesArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}

// TestPostgresDefaultPrivilegesMutationValidation pins the pinned
// validation head for both mutations: every rejected input fails before
// any Runner invocation, the object type is lowercased, the split
// tolerates the pinned single spaces, and the default-privilege
// allowlist refuses the characters the pinned _PRIVILEGES map carries
// but the pinned _DEFAULT_PRIVILEGES map does not.
func TestPostgresDefaultPrivilegesMutationValidation(t *testing.T) {
	for _, tc := range []struct {
		label      string
		objectType string
		defprivs   string
	}{
		{"unknown object type", "bogus", "SELECT"},
		{"empty object type", "", "SELECT"},
		{"non-default object type", "tablespace", "CREATE"},
		{"invalid privilege", "table", "SELECT,BOGUS"},
		{"missing privileges", "table", ""},
		{"connect not a default privilege", "table", "CONNECT"},
		{"temporary not a default privilege", "database", "TEMPORARY"},
		{"maintain not a default privilege", "table", "MAINTAIN"},
		{"privileges for group", "group", "SELECT"},
	} {
		for _, revoke := range []bool{false, true} {
			rt, runner := newPostgresRuntime()
			var err error
			if revoke {
				_, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
					fullDefaultPrivilegesRevokeArgs("baruwa", "awl", tc.objectType, tc.defprivs))
			} else {
				_, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
					fullDefaultPrivilegesGrantArgs("baruwa", "awl", tc.objectType, tc.defprivs))
			}
			if !errors.Is(err, errPostgresInvalidArgument) {
				t.Fatalf("%s revoke=%v err = %v, want errPostgresInvalidArgument", tc.label, revoke, err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("%s revoke=%v executed %d commands before validation", tc.label, revoke, len(runner.calls))
			}
		}
	}

	// Mixed-case object types and spaced privilege lists behave exactly
	// like the pinned _mod_defpriv_opts for both functions.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
		fullDefaultPrivilegesGrantArgs("baruwa", "awl", "TABLE", "select , insert"))
	if err != nil || value != true {
		t.Fatalf("TABLE case/spaces = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT ON TABLES TO "baruwa"` {
		t.Fatalf("TABLE case/spaces statement = %q", got)
	}
}

// TestPostgresDefaultPrivilegesListValidationRedaction pins value-free
// object_type errors before Runner execution, including password overlap.
func TestPostgresDefaultPrivilegesListValidationRedaction(t *testing.T) {
	const marker = "synthetic_defpriv_list_marker"
	for _, entry := range []string{"direct", "registry"} {
		for _, objectType := range []string{marker, "invalid_" + marker + "_type"} {
			t.Run(entry+"/"+objectType, func(t *testing.T) {
				rt, runner := newPostgresRuntime()
				args := fullDefaultPrivilegesListArgs("awl", objectType)
				args.Password = postgresString(marker)
				var value any
				var err error
				if entry == "registry" {
					rt.Exec = runtime.NewExecRegistry()
					if err := Register(rt.Exec); err != nil {
						t.Fatal(err)
					}
					value, err = rt.Exec.Call(context.Background(), rt, "postgres.default_privileges_list", args)
				} else {
					value, err = (defaultPrivilegesListFunc{}).Execute(context.Background(), rt, args)
				}
				if !errors.Is(err, errPostgresInvalidArgument) || err.Error() != "postgres: invalid argument: invalid object_type" {
					t.Fatal("expected stable value-free invalid object_type error")
				}
				if value != nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
					t.Fatal("validation leaked input or invoked Runner")
				}
			})
		}
	}
}

func TestPostgresDefaultPrivilegesValidationRedaction(t *testing.T) {
	const marker = "synthetic_defpriv_marker"
	for _, entry := range []string{"direct", "registry"} {
		for _, function := range []string{"postgres.default_privileges_grant", "postgres.default_privileges_revoke"} {
			for _, field := range []string{"defprivileges", "object_type"} {
				t.Run(entry+"/"+function+"/"+field, func(t *testing.T) {
					objectType, defprivileges := "table", "SELECT,"+marker
					if field == "object_type" {
						objectType, defprivileges = marker, "SELECT"
					}
					rt, runner := newPostgresRuntime()
					var fn runtime.ExecFunction
					var args any
					if function == "postgres.default_privileges_grant" {
						fn, args = defaultPrivilegesGrantFunc{},
							fullDefaultPrivilegesGrantArgs("baruwa", "awl", objectType, defprivileges)
					} else {
						fn, args = defaultPrivilegesRevokeFunc{},
							fullDefaultPrivilegesRevokeArgs("baruwa", "awl", objectType, defprivileges)
					}
					if a, ok := args.(*DefaultPrivilegesGrantArgs); ok {
						a.Password = postgresString(marker)
					}
					if a, ok := args.(*DefaultPrivilegesRevokeArgs); ok {
						a.Password = postgresString(marker)
					}
					var value any
					var err error
					if entry == "registry" {
						rt.Exec = runtime.NewExecRegistry()
						if err := Register(rt.Exec); err != nil {
							t.Fatal(err)
						}
						value, err = rt.Exec.Call(context.Background(), rt, function, args)
					} else {
						value, err = fn.Execute(context.Background(), rt, args)
					}
					want := "postgres: invalid argument: invalid object_type"
					if field == "defprivileges" {
						want = "postgres: invalid argument: invalid default privileges"
					}
					if !errors.Is(err, errPostgresInvalidArgument) || err.Error() != want {
						t.Fatalf("err = %v, want %q", err, want)
					}
					if value != nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
						t.Fatal("validation leaked input or invoked Runner")
					}
				})
			}
		}
	}
}

// TestPostgresDefaultPrivilegesMutationInjection pins the fail-closed
// boundary at every identifier position the pinned format strings
// interpolate raw or quote without escaping, each with its exact
// value-free stable error and zero Runner executions, including the
// synthetic marker overlap that proves a rejected value cannot leak
// through the error.
func TestPostgresDefaultPrivilegesMutationInjection(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn     string
		revoke bool
		args   func(marker string) any
		want   string
	}{
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				return fullDefaultPrivilegesGrantArgs(`baruwa-`+marker+`"`, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported quote character in name",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				return fullDefaultPrivilegesGrantArgs("baruwa", `admins; DROP ROLE x; --`+marker, "group", "")
			},
			"postgres: invalid argument: unsupported identifier in object_name",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
				args.Prepend = postgresString(`public; DROP SCHEMA x; --` + marker)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", "ALL", "table", "SELECT")
				args.Prepend = postgresString("public '" + marker)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
				args.GrantOption = true
				args.Prepend = postgresString(`pub` + marker + `"lic`)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", `aw`+marker+`"`, "table", "SELECT")
				args.GrantOption = true
				return args
			},
			"postgres: invalid argument: unsupported quote character in object_name",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", `fawl; `+marker, "function", "EXECUTE")
				args.GrantOption = true
				return args
			},
			"postgres: invalid argument: unsupported identifier in object_name",
		},
		{
			"postgres.default_privileges_grant", false,
			func(marker string) any {
				args := fullDefaultPrivilegesGrantArgs("baruwa", `my`+marker+`"`, "schema", "USAGE")
				args.GrantOption = true
				return args
			},
			"postgres: invalid argument: unsupported quote character in object_name",
		},
		{
			"postgres.default_privileges_revoke", true,
			func(marker string) any {
				return fullDefaultPrivilegesRevokeArgs(`baruwa; DROP ROLE x; --`+marker, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported identifier in name",
		},
		{
			"postgres.default_privileges_revoke", true,
			func(marker string) any {
				return fullDefaultPrivilegesRevokeArgs(`bar uwa`+marker, "awl", "table", "SELECT")
			},
			"postgres: invalid argument: unsupported identifier in name",
		},
		{
			"postgres.default_privileges_revoke", true,
			func(marker string) any {
				return fullDefaultPrivilegesRevokeArgs("baruwa", `admi`+marker+`"`, "group", "")
			},
			"postgres: invalid argument: unsupported identifier in object_name",
		},
		{
			"postgres.default_privileges_revoke", true,
			func(marker string) any {
				args := fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")
				args.Prepend = postgresString(`public; ` + marker)
				return args
			},
			"postgres: invalid argument: unsupported identifier in prepend",
		},
	} {
		rt, runner := newPostgresRuntime()
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		var err error
		if tc.revoke {
			args := tc.args(marker).(*DefaultPrivilegesRevokeArgs)
			args.Password = postgresString(marker)
			_, err = rt.Exec.Call(context.Background(), rt, tc.fn, args)
		} else {
			args := tc.args(marker).(*DefaultPrivilegesGrantArgs)
			args.Password = postgresString(marker)
			_, err = rt.Exec.Call(context.Background(), rt, tc.fn, args)
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands, want 0", tc.fn, len(runner.calls))
		}
	}
}

// TestPostgresDefaultPrivilegesMutationRedaction drives both mutations
// with a synthetic marker secret — always the connection password,
// additionally overlapping one other connection argument per case —
// against the leak Runner's raw command-line errors embedding argv and
// environment: a preflight failure at either catalog query and a
// mutation-time failure all surface redacted errors, every executed
// command keeps the exact marker secret inventory, and no mutation runs
// after a failed preflight.
func TestPostgresDefaultPrivilegesMutationRedaction(t *testing.T) {
	const marker = "synthetic'preflight"
	for _, fn := range []string{"postgres.default_privileges_grant", "postgres.default_privileges_revoke"} {
		// The grant preflight must answer false (baruwa holds nothing)
		// and the revoke preflight true (baruwa holds the subset), so
		// both functions reach their mutation at call 3.
		defCSV := defPrivGrantTableCSV
		if fn == "postgres.default_privileges_revoke" {
			defCSV = defPrivHeldTableCSV
		}
		for _, overlap := range []string{"password", "host", "user", "maintenance_db"} {
			for _, failAt := range []int{1, 2, 3} {
				t.Run(fn+"/"+overlap+"/"+strconv.Itoa(failAt), func(t *testing.T) {
					grantArgs := fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT,INSERT")
					revokeArgs := fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT,INSERT")
					grantArgs.Password = postgresString(marker)
					revokeArgs.Password = postgresString(marker)
					switch overlap {
					case "host":
						grantArgs.Host = postgresString(marker)
						revokeArgs.Host = postgresString(marker)
					case "user":
						grantArgs.User = postgresString(marker)
						revokeArgs.User = postgresString(marker)
					case "maintenance_db":
						grantArgs.MaintenanceDB = postgresString(marker)
						revokeArgs.MaintenanceDB = postgresString(marker)
					}
					runner := &statementLeakRunner{}
					runner.results = []process.CommandResult{
						{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
						{ExitCode: 0, Stdout: []byte(defCSV)},
					}
					runner.results = runner.results[:failAt-1]
					rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
					var value any
					var err error
					if fn == "postgres.default_privileges_grant" {
						value, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, grantArgs)
					} else {
						value, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt, revokeArgs)
					}
					if err == nil || value != nil {
						t.Fatal("run did not stop at injected error")
					}
					if strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), process.RedactedPlaceholder) {
						t.Fatalf("error was not redacted: %v", err)
					}
					if len(runner.calls) != failAt {
						t.Fatalf("calls = %d, want %d", len(runner.calls), failAt)
					}
					for _, command := range runner.calls {
						if strings.Contains(command.RedactedString(), marker) {
							t.Fatal("rendered command leaks marker")
						}
						if !reflect.DeepEqual(command.Redact, []string{marker}) {
							t.Fatalf("secret inventory changed: %q", command.Redact)
						}
					}
					if failAt < 3 {
						for _, command := range runner.calls {
							joined := strings.Join(command.Args, " ")
							if strings.Contains(joined, "ALTER DEFAULT PRIVILEGES") {
								t.Fatalf("mutation after failed preflight: %q", joined)
							}
						}
					}
				})
			}
		}
	}
}

// TestPostgresDefaultPrivilegesMutationRegistryKeys drives all three
// functions through the registry Call path: the list answers the decoded
// catalog and both mutations reach their statements end to end over the
// shared transport after the preflight.
func TestPostgresDefaultPrivilegesMutationRegistryKeys(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivTableCSV)},
	)
	value, err := reg.Call(context.Background(), rt, "postgres.default_privileges_list",
		&DefaultPrivilegesListArgs{Name: "awl", ObjectType: "table"})
	if err != nil {
		t.Fatal(err)
	}
	listed, ok := value.(map[string]any)
	if !ok || len(listed) != 2 {
		t.Fatalf("registry list = %#v, want the two-role map", value)
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivGrantTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.default_privileges_grant",
		&DefaultPrivilegesGrantArgs{Name: "baruwa", ObjectName: "awl", ObjectType: "table", DefPrivileges: "SELECT"})
	if err != nil || value != true {
		t.Fatalf("registry grant = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "baruwa"` {
		t.Fatalf("registry grant statement = %q", got)
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ownerTableCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(defPrivHeldTableCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err = reg.Call(context.Background(), rt, "postgres.default_privileges_revoke",
		&DefaultPrivilegesRevokeArgs{Name: "baruwa", ObjectName: "awl", ObjectType: "table", DefPrivileges: "SELECT"})
	if err != nil || value != true {
		t.Fatalf("registry revoke = %#v err = %v, want true", value, err)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM baruwa` {
		t.Fatalf("registry revoke statement = %q", got)
	}
}

// TestPostgresDefaultPrivilegesMutationGuards pins the shared failure
// modes for both mutations: canceled context, runas rejection, redacted
// Runner errors, output limits, psql-unavailable fail-closed, the
// argument guards, and the nil Runner — each with zero Runner executions
// where the guard precedes the call.
func TestPostgresDefaultPrivilegesMutationGuards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := newPostgresRuntime()
	if _, err := (defaultPrivilegesGrantFunc{}).Execute(ctx, rt, fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled grant err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled grant executed %d commands", len(runner.calls))
	}
	rt, runner = newPostgresRuntime()
	if _, err := (defaultPrivilegesRevokeFunc{}).Execute(ctx, rt, fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled revoke err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled revoke executed %d commands", len(runner.calls))
	}

	for _, revoke := range []bool{false, true} {
		label := "grant"
		if revoke {
			label = "revoke"
		}
		rt, runner = newPostgresRuntime()
		var err error
		if revoke {
			args := fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")
			args.Runas = postgresString("postgres")
			_, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt, args)
		} else {
			args := fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")
			args.Runas = postgresString("postgres")
			_, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt, args)
		}
		if !errors.Is(err, errPostgresRunas) {
			t.Fatalf("%s runas err = %v, want errPostgresRunas", label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s runas run executed %d commands", label, len(runner.calls))
		}

		rt, _ = newPostgresRuntime(process.CommandResult{
			ExitCode: -1,
			Err:      fmt.Errorf("exec psql --dbname db_name: secret testpassword rejected"),
		})
		if revoke {
			_, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
				fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
		} else {
			_, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
				fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
		}
		if err == nil || strings.Contains(err.Error(), "testpassword") {
			t.Fatalf("%s runner error = %v, want redacted", label, err)
		}
		if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
			t.Fatalf("%s error lacks redaction placeholder: %v", label, err)
		}

		for _, truncated := range []process.CommandResult{
			{ExitCode: 0, StdoutTruncated: true, Stdout: []byte(strings.Repeat("9", outputLimit+1))},
			{ExitCode: 0, StderrTruncated: true, Stderr: []byte(strings.Repeat("e", outputLimit+1))},
		} {
			rt, _ := newPostgresRuntime(truncated)
			if revoke {
				_, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
					fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
			} else {
				_, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
					fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
			}
			if !errors.Is(err, process.ErrOutputLimit) {
				t.Fatalf("%s truncated err = %v, want ErrOutputLimit", label, err)
			}
		}

		rt, runner = newPostgresRuntime()
		runner.available = map[string]bool{"psql": false}
		if revoke {
			_, err = (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rt,
				fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT"))
		} else {
			_, err = (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rt,
				fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT"))
		}
		if !errors.Is(err, errPostgresPsqlUnavailable) {
			t.Fatalf("%s psql-unavailable err = %v, want errPostgresPsqlUnavailable", label, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s unavailable psql executed %d commands", label, len(runner.calls))
		}
	}

	if _, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("default_privileges_grant must reject non-struct args")
	}
	if _, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), nil, &DefaultPrivilegesRevokeArgs{}); err == nil {
		t.Fatal("default_privileges_grant must reject foreign argument structs")
	}
	if _, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), nil, &DefaultPrivilegesGrantArgs{}); err == nil {
		t.Fatal("default_privileges_revoke must reject foreign argument structs")
	}
	rtEmpty := &runtime.Runtime{Runner: nil, FS: runtime.NewMemoryFS()}
	if _, err := (defaultPrivilegesGrantFunc{}).Execute(context.Background(), rtEmpty,
		fullDefaultPrivilegesGrantArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
	if _, err := (defaultPrivilegesRevokeFunc{}).Execute(context.Background(), rtEmpty,
		fullDefaultPrivilegesRevokeArgs("baruwa", "awl", "table", "SELECT")); !errors.Is(err, errPostgresRunnerUnavailable) {
		t.Fatalf("nil runner err = %v, want errPostgresRunnerUnavailable", err)
	}
}

// The error originates at either preflight command, before any verifier
// generation or mutation. Every marker is synthetic test data.
func TestPostgresRolePreflightRedaction(t *testing.T) {
	for _, entry := range []string{"direct", "registry"} {
		for _, function := range []string{"postgres.user_create", "postgres.user_update",
			"postgres.group_create", "postgres.group_update"} {
			for _, overlap := range []string{"password", "host", "user", "maintenance_db", "sql", "md5", "scram", "apostrophe"} {
				for _, failAt := range []int{1, 2} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", entry, function, overlap, failAt), func(t *testing.T) {
						marker := "synthetic_preflight_marker"
						switch overlap {
						case "sql":
							marker = "pg_catalog"
						case "md5":
							marker = "md5deadbeef"
						case "scram":
							marker = "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"
						case "apostrophe":
							marker = "pre'flight"
						}
						a := UserCreateArgs{Username: "test_username", Rolepassword: marker, Encrypted: "scram-sha-256"}
						switch overlap {
						case "host":
							a.Host = &marker
						case "user":
							a.User = &marker
						case "maintenance_db":
							a.MaintenanceDB = &marker
						case "sql": // Both fixed preflight queries contain this marker.
						default:
							a.Password = &marker
						}
						runner := &statementLeakRunner{}
						if failAt == 2 {
							runner.results = []process.CommandResult{{ExitCode: 0, Stdout: []byte("9.1\n")}}
						}
						rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
						var fn runtime.ExecFunction = userCreateFunc{}
						var args any = &a
						if function == "postgres.user_update" {
							fn = userUpdateFunc{}
							args = &UserUpdateArgs{Username: a.Username, Rolepassword: a.Rolepassword, Encrypted: a.Encrypted,
								Host: a.Host, User: a.User, MaintenanceDB: a.MaintenanceDB, Password: a.Password}
						}
						if function == "postgres.group_create" {
							fn = groupCreateFunc{}
							args = &GroupCreateArgs{Groupname: "testgroup", Rolepassword: a.Rolepassword, Encrypted: a.Encrypted,
								Host: a.Host, User: a.User, MaintenanceDB: a.MaintenanceDB, Password: a.Password}
						}
						if function == "postgres.group_update" {
							fn = groupUpdateFunc{}
							args = &GroupUpdateArgs{Groupname: "testgroup", Rolepassword: a.Rolepassword, Encrypted: a.Encrypted,
								Host: a.Host, User: a.User, MaintenanceDB: a.MaintenanceDB, Password: a.Password}
						}
						var value any
						var err error
						if entry == "registry" {
							rt.Exec = runtime.NewExecRegistry()
							if err := Register(rt.Exec); err != nil {
								t.Fatal(err)
							}
							value, err = rt.Exec.Call(context.Background(), rt, function, args)
						} else {
							value, err = fn.Execute(context.Background(), rt, args)
						}
						if err == nil || value != nil || len(runner.calls) != failAt {
							t.Fatal("preflight did not stop at injected error")
						}
						if strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), process.RedactedPlaceholder) {
							t.Fatal("preflight error was not redacted")
						}
						for _, command := range runner.calls {
							if strings.Contains(command.RedactedString(), marker) {
								t.Fatal("rendered preflight leaks marker")
							}
							if !reflect.DeepEqual(command.Redact, []string{marker}) {
								t.Fatal("preflight secret inventory changed or verifier generated early")
							}
							for _, verb := range []string{"CREATE ROLE", "ALTER ROLE", "GRANT "} {
								if strings.Contains(strings.Join(command.Args, " "), verb) {
									t.Fatal("mutation after failed preflight")
								}
							}
							for _, stream := range []string{"stdout ", "stderr "} {
								if strings.Contains(string(process.RedactBytes(command.Redact, []byte(stream+marker))), marker) {
									t.Fatal("preflight output redaction leaks marker")
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestPostgresTransportSecretNormalization(t *testing.T) {
	const marker = "synthetic'overlap"
	const doubled = "synthetic''overlap"
	const literal = "'synthetic''overlap'"
	want := []string{literal, doubled, marker, "thetic"}
	if got := secretList("thetic", marker, literal, "", doubled, marker); !reflect.DeepEqual(got, want) {
		t.Fatal("secrets must be unique and longest-first")
	}
	runner := &statementLeakRunner{}
	rt := &runtime.Runtime{Runner: runner}
	conn := &pgConnection{Password: postgresString(marker), Secrets: []string{marker, "thetic"}}
	result, err := runPsqlSecrets(context.Background(), rt, psqlArgv("", "", "", "", "-c", "SELECT "+literal), conn, nil)
	if err == nil || !reflect.DeepEqual(runner.calls[0].Redact, want) {
		t.Fatal("SQL secret forms not normalized")
	}
	for _, secret := range want {
		for _, output := range []string{err.Error(), result.Err.Error(), string(result.Stdout), string(result.Stderr), runner.calls[0].RedactedString()} {
			if strings.Contains(output, secret) {
				t.Fatal("transport leaked a secret form")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// R9.2m schema_create / schema_remove — pinned
// salt/modules/postgres.py:2316-2366, 2369-2441.

// schemaMutationCSV is the schema catalog with testschema present: the
// schema_create preflight hit and both schema_remove checks' hit answer.
const schemaMutationCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n" +
	"testschema,postgres,\"\"\n"

// schemaAbsentCSV is the same catalog without testschema: the create
// preflight miss and the remove post-check miss.
const schemaAbsentCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n"

// TestPostgresSchemaCreateArgvAndResult ports the pinned test_schema_create
// (test_postgres.py:1320-1357): the exact pinned argv — every connection
// flag, the maintenance database, and the CREATE SCHEMA statement — after
// the one catalog preflight call, with the db_password redacted. The
// pinned runas="user" argument is rejected before execution by the
// single-user runtime, so it is absent here.
func TestPostgresSchemaCreateArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName:     "maint_db",
		Name:       "testschema",
		DBUser:     postgresString("testuser"),
		DBHost:     postgresString("testhost"),
		DBPort:     postgresString("testport"),
		DBPassword: postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("schema_create = %#v, want true", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (preflight plus CREATE)", len(runner.calls))
	}
	command := runner.calls[1]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `CREATE SCHEMA "testschema"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	wantEnv := []string{
		"PGPASSWORD=testpassword",
		"PGUSER=testuser",
		"PGHOST=testhost",
		"PGPORT=testport",
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
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}
}

// TestPostgresSchemaCreateShapes pins the remaining pinned create flows: an
// existing schema is the logged-and-False no-op after one catalog call, the
// AUTHORIZATION owner clause renders exactly, and a rejected CREATE answers
// the pinned retcode boolean false, never an error.
func TestPostgresSchemaCreateShapes(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaMutationCSV)},
	)
	value, err := (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "test_db",
		Name:   "testschema",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("schema_create(existing) = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("existing calls = %d, want 1", len(runner.calls))
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   "testschema",
		Owner:  postgresString("owner_role"),
	})
	if err != nil || value != true {
		t.Fatalf("owner clause = %#v err = %v, want true", value, err)
	}
	statement := runner.calls[1].Args
	if got := statement[len(statement)-1]; got != `CREATE SCHEMA "testschema" AUTHORIZATION "owner_role"` {
		t.Fatalf("owner statement = %q", got)
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: permission denied for database`)},
	)
	value, err = (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   "testschema",
	})
	if err != nil || value != false {
		t.Fatalf("rejected CREATE = %#v err = %v, want false", value, err)
	}

	// An empty-string owner keeps the pinned quoted empty identifier.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
		process.CommandResult{ExitCode: 0},
	)
	if _, err := (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   "testschema",
		Owner:  postgresString(""),
	}); err != nil {
		t.Fatal(err)
	}
	statement = runner.calls[1].Args
	if got := statement[len(statement)-1]; got != `CREATE SCHEMA "testschema" AUTHORIZATION ""` {
		t.Fatalf("empty owner statement = %q", got)
	}
}

// TestPostgresSchemaRemoveArgvAndResult ports the pinned test_schema_remove
// (test_postgres.py:1374-1411): the preflight catalog hit, the exact pinned
// DROP SCHEMA argv, and the post-check miss deciding true — three calls,
// with the DROP retcode never consulted.
func TestPostgresSchemaRemoveArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaMutationCSV)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
	)
	value, err := (schemaRemoveFunc{}).Execute(context.Background(), rt, &SchemaRemoveArgs{
		DBName:     "maint_db",
		Name:       "testschema",
		DBUser:     postgresString("testuser"),
		DBHost:     postgresString("testhost"),
		DBPort:     postgresString("testport"),
		DBPassword: postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("schema_remove = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight, DROP, post-check)", len(runner.calls))
	}
	command := runner.calls[1]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `DROP SCHEMA "testschema"`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}
	// The post-check is the catalog query, never a second DROP.
	if last := runner.calls[2]; strings.HasPrefix(last.Args[len(last.Args)-1], "DROP") {
		t.Fatalf("unexpected second DROP: %q", last.Args)
	}
}

// TestPostgresSchemaRemoveShapes pins the remaining pinned remove flows: a
// missing schema is the logged-and-False no-op after one catalog call (the
// pinned user=None preflight keeps the db_* tuple), a failed DROP that
// leaves the schema present is the logged-and-False answer after all three
// calls, and the pinned flow's user argument reaches the DROP — rejected
// by the single-user runtime after the connection-less preflight.
func TestPostgresSchemaRemoveShapes(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaAbsentCSV)},
	)
	value, err := (schemaRemoveFunc{}).Execute(context.Background(), rt, &SchemaRemoveArgs{
		DBName: "test_db",
		Name:   "testschema",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("schema_remove(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing calls = %d, want 1", len(runner.calls))
	}

	// The DROP retcode is ignored; the schema still exists afterwards, so
	// the pinned answer is false after all three calls.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaMutationCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: dependent objects exist")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaMutationCSV)},
	)
	value, err = (schemaRemoveFunc{}).Execute(context.Background(), rt, &SchemaRemoveArgs{
		DBName: "maint_db",
		Name:   "testschema",
	})
	if err != nil || value != false {
		t.Fatalf("schema_remove(failed drop) = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("failed-drop calls = %d, want 3", len(runner.calls))
	}

	// The pinned user argument is the psql runas of the DROP and the
	// post-check, but the pinned preflight drops it explicitly: the
	// catalog call runs first and the runas rejection fires at the DROP.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(schemaMutationCSV)},
	)
	_, err = (schemaRemoveFunc{}).Execute(context.Background(), rt, &SchemaRemoveArgs{
		DBName: "maint_db",
		Name:   "testschema",
		User:   postgresString("user"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("user runas err = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runas flow calls = %d, want 1 (connection-less preflight only)", len(runner.calls))
	}
}

// TestPostgresSchemaMutationGuards pins the fail-closed identifier boundary
// and the shared transport guards for the schema family: the value-free
// quote rejections before any Runner invocation, the create preflight's
// runas rejection through the pinned user argument, and pre-cancellation.
func TestPostgresSchemaMutationGuards(t *testing.T) {
	rt, runner := newPostgresRuntime()
	_, err := (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   `x"; DROP SCHEMA public; --`,
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in name" {
		t.Fatalf("injected name err = %v", err)
	}
	if !errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("injected name err = %v, want invalid argument", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected name executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err = (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   "testschema",
		Owner:  postgresString(`o"; DROP ROLE postgres; --`),
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in owner" {
		t.Fatalf("injected owner err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("injected owner executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err = (schemaRemoveFunc{}).Execute(context.Background(), rt, &SchemaRemoveArgs{
		DBName: "maint_db",
		Name:   `x"; DROP SCHEMA public; --`,
	})
	if err == nil || err.Error() != "postgres: invalid argument: unsupported quote character in name" {
		t.Fatalf("remove injected name err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("remove injected name executed %d commands", len(runner.calls))
	}

	// The create preflight passes the pinned user argument as the runas,
	// so it rejects before any Runner invocation.
	rt, runner = newPostgresRuntime()
	_, err = (schemaCreateFunc{}).Execute(context.Background(), rt, &SchemaCreateArgs{
		DBName: "maint_db",
		Name:   "testschema",
		User:   postgresString("user"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("create runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("create runas executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (schemaCreateFunc{}).Execute(ctx, rt, &SchemaCreateArgs{DBName: "d", Name: "s"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// ---------------------------------------------------------------------------
// R9.2m create_extension / drop_extension / create_metadata — pinned
// salt/modules/postgres.py:1895-1962, 1965-2063, 1849-1892.

// extMutAvailableCSV is the pg_available_extensions catalog naming foo.
const extMutAvailableCSV = "name,default_version,comment\nfoo,1.4,foo extension\n"

// extMutHeaderCSV is an empty installed-extensions catalog (header only).
const extMutHeaderCSV = "extname,extversion,extrelocatable,schema_name\n"

// extMutInstalledCSV is an installed catalog whose foo row is relocatable,
// parked in public, and older than 1.4: the TO_MOVE and TO_UPGRADE source.
const extMutInstalledCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,0.8,t,foo\n"

// extMutCurrentCSV is an installed catalog whose foo row is up to date and
// already parked in the target schema: plain INSTALLED metadata.
const extMutCurrentCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,1.4,t,b\n"

// extMutSettledABCSV is the settled catalog for the full-options CREATE
// vector: the requested schema "a" and version "b" leave plain INSTALLED.
const extMutSettledABCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,b,t,a\n"

// extMutSettledCSV is the settled catalog for the ALTER vectors: the
// pinned ext_version "a" and target schema "b" leave plain INSTALLED.
const extMutSettledCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,a,t,b\n"

// TestPostgresCreateExtensionArgvAndResult ports the create half of the
// pinned test_create_extension_newerthan sequence: the fresh CREATE (with
// and without the full WITH clause set) on the full pinned argv with the
// pinned space before the semicolon, and the failed CREATE answering
// False through the recomputed metadata.
func TestPostgresCreateExtensionArgvAndResult(t *testing.T) {
	// create succeeded: NOT_INSTALLED → INSTALLED.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)}, // metadata
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutAvailableCSV)},
		process.CommandResult{ExitCode: 0}, // CREATE EXTENSION
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
	)
	value, err := (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{
		Name:          "foo",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("create_extension = %#v, want true", value)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("runner calls = %d, want 4 (metadata, available, CREATE, metadata)", len(runner.calls))
	}
	command := runner.calls[2]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `CREATE EXTENSION IF NOT EXISTS "foo" ;`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}

	// The full WITH clause set renders the pinned order and spacing.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutAvailableCSV)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutSettledABCSV)},
	)
	value, err = (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{
		Name:        "foo",
		Schema:      postgresString("a"),
		ExtVersion:  postgresString("b"),
		FromVersion: postgresString("c"),
	})
	if err != nil || value != true {
		t.Fatalf("full options = %#v err = %v, want true", value, err)
	}
	statement := runner.calls[2].Args
	if got := statement[len(statement)-1]; got != `CREATE EXTENSION IF NOT EXISTS "foo" WITH SCHEMA "a" VERSION b FROM c ;` {
		t.Fatalf("full options statement = %q", got)
	}

	// create failed: the recomputed metadata still says NOT_INSTALLED.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutAvailableCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: extension not available")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
	)
	value, err = (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{Name: "foo"})
	if err != nil || value != false {
		t.Fatalf("failed create = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("failed create calls = %d, want 4", len(runner.calls))
	}
}

// TestPostgresCreateExtensionAlterFlows ports the ALTER half of the pinned
// test_create_extension_newerthan sequence: move+upgrade, move only,
// upgrade only, and the failed move and upgrade tails — each statement
// byte-for-byte on the full argv with the per-clause semicolons.
func TestPostgresCreateExtensionAlterFlows(t *testing.T) {
	for _, tc := range []struct {
		name       string
		schema     string
		extVersion string
		firstCSV   string
		lastCSV    string
		want       string
		value      bool
	}{
		{
			name:       "move and upgrade",
			schema:     "b",
			extVersion: "a",
			firstCSV:   extMutInstalledCSV,
			lastCSV:    extMutSettledCSV,
			want:       `ALTER EXTENSION "foo" SET SCHEMA "b"; ALTER EXTENSION "foo" UPDATE TO a;`,
			value:      true,
		},
		{
			name:     "move only",
			schema:   "b",
			firstCSV: extMutInstalledCSV,
			lastCSV:  extMutCurrentCSV,
			want:     `ALTER EXTENSION "foo" SET SCHEMA "b";`,
			value:    true,
		},
		{
			name:       "upgrade only",
			extVersion: "a",
			firstCSV:   extMutInstalledCSV,
			lastCSV:    extMutSettledCSV,
			want:       `ALTER EXTENSION "foo" UPDATE TO a;`,
			value:      true,
		},
		{
			name:       "upgrade failed",
			schema:     "b",
			extVersion: "a",
			firstCSV:   extMutInstalledCSV,
			lastCSV:    extMutInstalledCSV,
			want:       `ALTER EXTENSION "foo" SET SCHEMA "b"; ALTER EXTENSION "foo" UPDATE TO a;`,
			value:      false,
		},
		{
			name:     "move failed",
			schema:   "b",
			firstCSV: extMutInstalledCSV,
			lastCSV:  extMutInstalledCSV,
			want:     `ALTER EXTENSION "foo" SET SCHEMA "b";`,
			value:    false,
		},
	} {
		rt, runner := newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.firstCSV)},
			process.CommandResult{ExitCode: 0, Stdout: []byte(extMutAvailableCSV)},
			process.CommandResult{ExitCode: 0},
			process.CommandResult{ExitCode: 0, Stdout: []byte(tc.lastCSV)},
		)
		args := &CreateExtensionArgs{Name: "foo"}
		if tc.schema != "" {
			args.Schema = postgresString(tc.schema)
		}
		if tc.extVersion != "" {
			args.ExtVersion = postgresString(tc.extVersion)
		}
		value, err := (createExtensionFunc{}).Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if value != tc.value {
			t.Fatalf("%s = %#v, want %v", tc.name, value, tc.value)
		}
		if len(runner.calls) != 4 {
			t.Fatalf("%s calls = %d, want 4", tc.name, len(runner.calls))
		}
		statement := runner.calls[2].Args
		if got := statement[len(statement)-1]; got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPostgresCreateExtensionUnavailable pins the is_available_extension
// gate: an unavailable extension issues no statement at all, and the
// boolean is decided purely by the recomputed metadata — an installed but
// unavailable extension is True, a missing one False.
func TestPostgresCreateExtensionUnavailable(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,default_version\nbar,1.0\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
	)
	value, err := (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{Name: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("unavailable create = %#v, want false", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("unavailable calls = %d, want 3 (no statement)", len(runner.calls))
	}

	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,default_version\nbar,1.0\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
	)
	value, err = (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{Name: "foo"})
	if err != nil || value != true {
		t.Fatalf("installed unavailable = %#v err = %v, want true", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("installed unavailable calls = %d, want 3", len(runner.calls))
	}

	// The availability match is case-insensitive like the pinned
	// is_available_extension, while the installed lookup stays exact-case.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte("name,default_version\nFOO,1.4\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
	)
	value, err = (createExtensionFunc{}).Execute(context.Background(), rt, &CreateExtensionArgs{Name: "foo"})
	if err != nil || value != true {
		t.Fatalf("case-insensitive availability = %#v err = %v, want true", value, err)
	}
}

// TestPostgresCreateMetadataVectors pins the internal create_metadata
// ladder directly: the exact-case miss, the LooseVersion TO_UPGRADE
// comparisons (including the pinned .get fallbacks), the relocatable
// TO_MOVE conditions, and the is-not-None versus truthiness distinction
// between the metadata checks and the clause guards.
func TestPostgresCreateMetadataVectors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		csv        string
		extVersion *string
		schema     *string
		want       []string
	}{{
		name: "miss is not installed",
		csv:  extMutHeaderCSV,
		want: []string{extFlagNotInstalled},
	},
		{
			name: "plain hit is installed",
			csv:  extMutCurrentCSV,
			want: []string{extFlagInstalled},
		},
		{
			name:       "older extversion to upgrade",
			csv:        extMutInstalledCSV,
			extVersion: postgresString("1.4"),
			want:       []string{extFlagInstalled, extFlagToUpgrade},
		},
		{
			name:       "equal extversion stays installed",
			csv:        extMutCurrentCSV,
			extVersion: postgresString("1.4"),
			want:       []string{extFlagInstalled},
		},
		{
			name:       "newer requested extversion no flag",
			csv:        extMutCurrentCSV,
			extVersion: postgresString("1.0"),
			want:       []string{extFlagInstalled},
		},
		{
			name:       "numeric looser ordering 0.10 after 0.8",
			csv:        "extname,extversion,extrelocatable,schema_name\nfoo,0.8,t,foo\n",
			extVersion: postgresString("0.10"),
			want:       []string{extFlagInstalled, extFlagToUpgrade},
		},
		{
			name:   "relocatable different schema to move",
			csv:    extMutInstalledCSV,
			schema: postgresString("b"),
			want:   []string{extFlagInstalled, extFlagToMove},
		},
		{
			name:   "same schema stays installed",
			csv:    extMutInstalledCSV,
			schema: postgresString("foo"),
			want:   []string{extFlagInstalled},
		},
		{
			name:   "non-relocatable never moves",
			csv:    "extname,extversion,extrelocatable,schema_name\nfoo,0.8,f,foo\n",
			schema: postgresString("b"),
			want:   []string{extFlagInstalled},
		},
		{
			name: "missing columns fall back to the caller values",
			csv:  "extname,extversion,extrelocatable\nfoo,,t\n",
			// extversion present but empty and schema_name absent: the
			// pinned .get fallbacks make the version compare
			// LooseVersion("") < LooseVersion("1.4") while the missing
			// schema_name defaults to the caller's schema, which never
			// differs — so TO_MOVE cannot fire without the column.
			extVersion: postgresString("1.4"),
			schema:     postgresString("b"),
			want:       []string{extFlagInstalled, extFlagToUpgrade},
		},
		{
			name: "nil arguments never trigger a flag",
			csv:  extMutInstalledCSV,
			want: []string{extFlagInstalled},
		},
		{
			name:       "empty-string extversion is not none",
			csv:        extMutInstalledCSV,
			extVersion: postgresString(""),
			want:       []string{extFlagInstalled},
		},
		{
			name:   "empty-string schema is not none",
			csv:    extMutInstalledCSV,
			schema: postgresString(""),
			want:   []string{extFlagInstalled, extFlagToMove},
		},
	} {
		rt, _ := newPostgresRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.csv)})
		got, err := createMetadata(context.Background(), rt, &pgConnection{}, "foo", tc.extVersion, tc.schema)
		if err != nil {
			t.Fatalf("%s err = %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s metadata = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPostgresDropExtensionArgvAndResult ports the pinned
// test_drop_extension2/3/1 trio plus the clause variants: the never
// installed no-DROP True, the installed-then-gone DROP on the exact
// pinned argv (default CASCADE and the pinned space before the
// semicolon), and the still-installed False.
func TestPostgresDropExtensionArgvAndResult(t *testing.T) {
	// test_drop_extension2: never installed, still absent — True with no
	// DROP statement.
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
	)
	value, err := (dropExtensionFunc{}).Execute(context.Background(), rt, &DropExtensionArgs{Name: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("drop_extension(absent) = %#v, want true", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("absent calls = %d, want 2 (no DROP)", len(runner.calls))
	}

	// test_drop_extension3: installed, then gone — the exact pinned argv.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
	)
	value, err = (dropExtensionFunc{}).Execute(context.Background(), rt, &DropExtensionArgs{
		Name:          "foo",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		MaintenanceDB: postgresString("maint_db"),
		Password:      postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("drop_extension = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (preflight, DROP, post-check)", len(runner.calls))
	}
	command := runner.calls[1]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "maint_db",
		"-c", `DROP EXTENSION foo CASCADE ;`,
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}

	// test_drop_extension1: installed, still installed — False after the
	// full three-call flow.
	rt, runner = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: dependent objects")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
	)
	value, err = (dropExtensionFunc{}).Execute(context.Background(), rt, &DropExtensionArgs{Name: "foo"})
	if err != nil || value != false {
		t.Fatalf("failed drop = %#v err = %v, want false", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("failed drop calls = %d, want 3", len(runner.calls))
	}

	// Clause variants keep the pinned join: IF EXISTS, RESTRICT, and the
	// clause-less shape when both cascade and restrict are false.
	for _, tc := range []struct {
		name                        string
		ifExists, cascade, restrict *bool
		want                        string
	}{
		{"if exists", postgresBool(true), nil, nil, `DROP EXTENSION IF EXISTS foo CASCADE ;`},
		{"restrict", nil, postgresBool(false), postgresBool(true), `DROP EXTENSION foo RESTRICT ;`},
		{"no clauses", nil, postgresBool(false), postgresBool(false), `DROP EXTENSION foo ;`},
		{"explicit cascade", nil, postgresBool(true), nil, `DROP EXTENSION foo CASCADE ;`},
	} {
		rt, runner = newPostgresRuntime(
			process.CommandResult{ExitCode: 0, Stdout: []byte(extMutCurrentCSV)},
			process.CommandResult{ExitCode: 0},
			process.CommandResult{ExitCode: 0, Stdout: []byte(extMutHeaderCSV)},
		)
		value, err := (dropExtensionFunc{}).Execute(context.Background(), rt, &DropExtensionArgs{
			Name:     "foo",
			IfExists: tc.ifExists,
			Cascade:  tc.cascade,
			Restrict: tc.restrict,
		})
		if err != nil || value != true {
			t.Fatalf("%s = %#v err = %v, want true", tc.name, value, err)
		}
		statement := runner.calls[1].Args
		if got := statement[len(statement)-1]; got != tc.want {
			t.Fatalf("%s statement = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPostgresExtensionMutationGuards pins the fail-closed identifier
// boundaries of the extension family: the raw DROP name must be a bare
// identifier, the quoted create positions may not carry the double quote,
// the raw version tokens may not carry anything outside the version class,
// runas rejects before any Runner invocation, and pre-cancellation holds.
func TestPostgresExtensionMutationGuards(t *testing.T) {
	for _, tc := range []struct {
		fn   string
		args any
		want string
	}{
		{
			fn:   "postgres.drop_extension",
			args: &DropExtensionArgs{Name: `foo; DROP SCHEMA public`},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
		{
			fn:   "postgres.drop_extension",
			args: &DropExtensionArgs{Name: `f"oo`},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
		{
			fn:   "postgres.drop_extension",
			args: &DropExtensionArgs{Name: ""},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: `fo"o`},
			want: "postgres: invalid argument: unsupported quote character in name",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", Schema: postgresString(`a"; DROP SCHEMA public; --`)},
			want: "postgres: invalid argument: unsupported quote character in schema",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", ExtVersion: postgresString("1.0; DROP SCHEMA public")},
			want: "postgres: invalid argument: unsupported identifier in ext_version",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", FromVersion: postgresString("1.0--x")},
			want: "postgres: invalid argument: unsupported identifier in from_version",
		},
	} {
		rt, runner := newPostgresRuntime()
		var err error
		switch tc.fn {
		case "postgres.drop_extension":
			_, err = (dropExtensionFunc{}).Execute(context.Background(), rt, tc.args.(*DropExtensionArgs))
		case "postgres.create_extension":
			_, err = (createExtensionFunc{}).Execute(context.Background(), rt, tc.args.(*CreateExtensionArgs))
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", tc.fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.fn, len(runner.calls))
		}
	}

	// A dot is a legal version token: the dotted version passes
	// validation (only the canceled context stops the flow, proving no
	// invalid-argument rejection fired).
	rt, runner := newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (createExtensionFunc{}).Execute(ctx, rt, &CreateExtensionArgs{
		Name:       "foo",
		ExtVersion: postgresString("1.4.0"),
	}); !errors.Is(err, context.Canceled) || errors.Is(err, errPostgresInvalidArgument) {
		t.Fatalf("dotted version err = %v, want cancellation (not a rejection)", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled dotted-version run executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	_, err := (dropExtensionFunc{}).Execute(context.Background(), rt, &DropExtensionArgs{
		Name:  "foo",
		Runas: postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas executed %d commands", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := (createExtensionFunc{}).Execute(ctx2, rt, &CreateExtensionArgs{Name: "foo"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// ---------------------------------------------------------------------------
// R9.2m language_create / language_remove — pinned
// salt/modules/postgres.py:2698-2750, 2753-2805.

// languageMutationCSV is the pinned get_test_list_language_csv fixture.
const languageMutationCSV = "Name\ninternal\nc\nsql\nplpgsql\n"

// TestPostgresLanguageCreateArgvAndResult ports the pinned
// test_language_create (test_postgres.py:1474-1514): the exact pinned argv
// after the connection-less preflight, the pinned quirk that the preflight
// catalog call carries none of the connection arguments, and the retcode
// boolean. The pinned runas="user" argument is rejected before execution
// by the single-user runtime, so it is absent here.
func TestPostgresLanguageCreateArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (languageCreateFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpythonu",
		MaintenanceDB: "testdb",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("language_create = %#v, want true", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (preflight plus CREATE)", len(runner.calls))
	}
	// The pinned preflight passes only (name, maintenance_db): the
	// catalog call carries no connection flags at all.
	preflight := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	joined := strings.Join(preflight, "\x00")
	for _, flag := range []string{"--username", "--host", "--port"} {
		if strings.Contains(joined, flag) {
			t.Fatalf("preflight argv carries %s: %q", flag, preflight)
		}
	}
	if !strings.Contains(joined, "\x00--dbname\x00testdb\x00") {
		t.Fatalf("preflight argv = %q, want the maintenance database", preflight)
	}
	command := runner.calls[1]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "testdb",
		"-c", "CREATE LANGUAGE plpythonu",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"testpassword"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks the password: %q", command.RedactedString())
	}
}

// TestPostgresLanguageCreateShapes pins the pinned existing-language no-op
// and the rejected-CREATE retcode boolean.
func TestPostgresLanguageCreateShapes(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
	)
	value, err := (languageCreateFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpgsql",
		MaintenanceDB: "testdb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("language_create(existing) = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("existing calls = %d, want 1", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: language already exists")},
	)
	value, err = (languageCreateFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpythonu",
		MaintenanceDB: "testdb",
	})
	if err != nil || value != false {
		t.Fatalf("rejected CREATE = %#v err = %v, want false", value, err)
	}
}

// TestPostgresLanguageRemoveArgvAndResult ports the pinned
// test_language_remove (test_postgres.py:1534-1574): the exact pinned
// argv, the connection-less preflight quirk, and the retcode boolean with
// no post-check in the pinned flow.
func TestPostgresLanguageRemoveArgvAndResult(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (languageRemoveFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpgsql",
		MaintenanceDB: "testdb",
		User:          postgresString("testuser"),
		Host:          postgresString("testhost"),
		Port:          postgresString("testport"),
		Password:      postgresString("testpassword"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("language_remove = %#v, want true", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (preflight plus DROP)", len(runner.calls))
	}
	preflight := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	joinedPreflight := strings.Join(preflight, "\x00")
	for _, flag := range []string{"--username", "--host", "--port"} {
		if strings.Contains(joinedPreflight, flag) {
			t.Fatalf("preflight argv carries %s: %q", flag, preflight)
		}
	}
	command := runner.calls[1]
	want := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser",
		"--host", "testhost",
		"--port", "testport",
		"--dbname", "testdb",
		"-c", "DROP LANGUAGE plpgsql",
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

// TestPostgresLanguageRemoveShapes pins the pinned missing-language no-op
// (test_language_remove_non_exist) and the rejected-DROP retcode boolean.
func TestPostgresLanguageRemoveShapes(t *testing.T) {
	rt, runner := newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
	)
	value, err := (languageRemoveFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpythonu",
		MaintenanceDB: "testdb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != false {
		t.Fatalf("language_remove(missing) = %#v, want false", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing calls = %d, want 1", len(runner.calls))
	}

	rt, _ = newPostgresRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(languageMutationCSV)},
		process.CommandResult{ExitCode: 1, Stderr: []byte("psql: error: ERROR: language is required")},
	)
	value, err = (languageRemoveFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpgsql",
		MaintenanceDB: "testdb",
	})
	if err != nil || value != false {
		t.Fatalf("rejected DROP = %#v err = %v, want false", value, err)
	}
}

// The catalog preflight must redact without using the caller's authentication.
func TestPostgresLanguagePreflightRedaction(t *testing.T) {
	const marker = "synthetic-language-preflight-marker"
	for _, name := range []string{"postgres.language_create", "postgres.language_remove"} {
		for _, registry := range []bool{false, true} {
			for _, db := range []string{"maintenance", "db_" + marker + "_overlap"} {
				t.Run(fmt.Sprintf("%s/registry=%t/overlap=%t", name, registry, strings.Contains(db, marker)), func(t *testing.T) {
					rt, runner := newPostgresRuntime(process.CommandResult{
						Err:    errors.New("first catalog failure: " + marker + " " + db),
						Stdout: []byte(marker), Stderr: []byte(marker),
					})
					a := &LanguageMutationArgs{Name: "plpgsql", MaintenanceDB: db,
						User: postgresString("ignored-user"), Host: postgresString("ignored-host"),
						Port: postgresString("1234"), Password: postgresString(marker), Runas: postgresString("ignored-runas")}
					var value any
					var err error
					if registry {
						rt.Exec = runtime.NewExecRegistry()
						if err := Register(rt.Exec); err != nil {
							t.Fatal(err)
						}
						value, err = rt.Exec.Call(context.Background(), rt, name, a)
					} else if name == "postgres.language_create" {
						value, err = (languageCreateFunc{}).Execute(context.Background(), rt, a)
					} else {
						value, err = (languageRemoveFunc{}).Execute(context.Background(), rt, a)
					}
					if value != nil || err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "first catalog failure") {
						t.Fatal("first catalog error must survive without the synthetic marker")
					}
					if len(runner.calls) != 1 {
						t.Fatalf("calls = %d, want one catalog and zero mutations", len(runner.calls))
					}
					cmd := runner.calls[0]
					want := []string{"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password", "--dbname", db,
						"-v", "datestyle=ISO,MDY", "-c", `COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER`}
					if !reflect.DeepEqual(append([]string{cmd.Name}, cmd.Args...), want) || cmd.Shell {
						t.Fatal("pinned catalog argv changed")
					}
					if cmd.Env == nil || len(cmd.Env) != 0 {
						t.Fatal("preflight must have a clean environment without authentication")
					}
					if !reflect.DeepEqual(cmd.Redact, []string{marker}) || strings.Contains(cmd.RedactedString(), marker) {
						t.Fatal("preflight redaction missing")
					}
				})
			}
		}
	}
}

func TestPostgresCreateExtensionEmptyVersions(t *testing.T) {
	for _, registry := range []bool{false, true} {
		for _, field := range []string{"omitted", "ext_version", "from_version", "both"} {
			for _, installed := range []bool{false, true} {
				t.Run(fmt.Sprintf("registry=%t/%s/installed=%t", registry, field, installed), func(t *testing.T) {
					a := &CreateExtensionArgs{Name: "foo", User: postgresString("u"), Host: postgresString("h"), Port: postgresString("5432"), MaintenanceDB: postgresString("d")}
					if field == "ext_version" || field == "both" {
						a.ExtVersion = postgresString("")
					}
					if field == "from_version" || field == "both" {
						a.FromVersion = postgresString("")
					}
					first := extMutHeaderCSV
					if installed {
						first = extMutCurrentCSV
					}
					results := []process.CommandResult{{Stdout: []byte(first)}, {Stdout: []byte(extMutAvailableCSV)}}
					queries := []string{
						"COPY (select a.*, b.nspname as schema_name from pg_extension a,  pg_namespace b where a.extnamespace = b.oid) TO STDOUT WITH CSV HEADER",
						"COPY (select * from pg_available_extensions()) TO STDOUT WITH CSV HEADER",
					}
					if !installed {
						results = append(results, process.CommandResult{})
						queries = append(queries, `CREATE EXTENSION IF NOT EXISTS "foo" ;`)
					}
					results = append(results, process.CommandResult{Stdout: []byte(extMutCurrentCSV)})
					queries = append(queries, queries[0])
					rt, runner := newPostgresRuntime(results...)
					var value any
					var err error
					if registry {
						rt.Exec = runtime.NewExecRegistry()
						if err := Register(rt.Exec); err != nil {
							t.Fatal(err)
						}
						value, err = rt.Exec.Call(context.Background(), rt, "postgres.create_extension", a)
					} else {
						value, err = (createExtensionFunc{}).Execute(context.Background(), rt, a)
					}
					if err != nil || value != true {
						t.Fatalf("result = %v, err = %v", value, err)
					}
					if len(runner.calls) != len(queries) {
						t.Fatalf("calls = %d, want %d", len(runner.calls), len(queries))
					}
					for i, query := range queries {
						want := []string{"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password", "--username", "u", "--host", "h", "--port", "5432", "--dbname", "d"}
						if strings.HasPrefix(query, "COPY") {
							want = append(want, "-v", "datestyle=ISO,MDY")
						}
						want = append(want, "-c", query)
						cmd := runner.calls[i]
						if !reflect.DeepEqual(append([]string{cmd.Name}, cmd.Args...), want) || cmd.Shell {
							t.Fatalf("call %d = %q, want %q", i, cmd.Args, want)
						}
					}
					// Empty pointers remain present; omission stays nil. In particular,
					// createMetadata receives ExtVersion unchanged, not a truthiness default.
					if (a.ExtVersion != nil) != (field == "ext_version" || field == "both") || (a.FromVersion != nil) != (field == "from_version" || field == "both") {
						t.Fatal("version presence changed")
					}
				})
			}
		}
	}
}

// TestPostgresLanguageMutationGuards pins the raw-language-name boundary
// and the shared transport guards for the language family.
func TestPostgresLanguageMutationGuards(t *testing.T) {
	for _, fn := range []string{"postgres.language_create", "postgres.language_remove"} {
		rt, runner := newPostgresRuntime()
		var err error
		if fn == "postgres.language_create" {
			_, err = (languageCreateFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
				Name:          "plpythonu; DROP SCHEMA public",
				MaintenanceDB: "testdb",
			})
		} else {
			_, err = (languageRemoveFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
				Name:          `pl"x`,
				MaintenanceDB: "testdb",
			})
		}
		if err == nil || err.Error() != "postgres: invalid argument: unsupported identifier in name" {
			t.Fatalf("%s err = %v, want the value-free identifier rejection", fn, err)
		}
		if !errors.Is(err, errPostgresInvalidArgument) {
			t.Fatalf("%s err = %v, want invalid argument", fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", fn, len(runner.calls))
		}
	}

	rt, runner := newPostgresRuntime()
	_, err := (languageCreateFunc{}).Execute(context.Background(), rt, &LanguageMutationArgs{
		Name:          "plpythonu",
		MaintenanceDB: "testdb",
		Runas:         postgresString("postgres"),
	})
	if !errors.Is(err, errPostgresRunas) {
		t.Fatalf("runas err = %v", err)
	}
	// The pinned connection-less preflight carries no runas, so exactly
	// the catalog call runs before the rejection fires at the CREATE.
	if len(runner.calls) != 1 {
		t.Fatalf("runas executed %d commands, want 1 (connection-less preflight)", len(runner.calls))
	}

	rt, runner = newPostgresRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (languageRemoveFunc{}).Execute(ctx, rt, &LanguageMutationArgs{
		Name:          "plpgsql",
		MaintenanceDB: "testdb",
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled run executed %d commands", len(runner.calls))
	}
}

// TestPostgresMutationValidationErrorsRedactedThroughRegistry loops every
// rejected R9.2m field through the registry Call path with the rejected
// value embedding a synthetic marker: the stable value-free error must
// carry no marker and no Runner call may happen at all, because every
// R9.2m validation precedes the first preflight.
func TestPostgresMutationValidationErrorsRedactedThroughRegistry(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn   string
		args any
		want string
	}{
		{
			fn:   "postgres.schema_create",
			args: &SchemaCreateArgs{DBName: "d", Name: `x"` + marker},
			want: "postgres: invalid argument: unsupported quote character in name",
		},
		{
			fn:   "postgres.schema_create",
			args: &SchemaCreateArgs{DBName: "d", Name: "s", Owner: postgresString(`o"` + marker)},
			want: "postgres: invalid argument: unsupported quote character in owner",
		},
		{
			fn:   "postgres.schema_remove",
			args: &SchemaRemoveArgs{DBName: "d", Name: `x"` + marker},
			want: "postgres: invalid argument: unsupported quote character in name",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: `x"` + marker},
			want: "postgres: invalid argument: unsupported quote character in name",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", Schema: postgresString(`a"` + marker)},
			want: "postgres: invalid argument: unsupported quote character in schema",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", ExtVersion: postgresString("1.0 " + marker)},
			want: "postgres: invalid argument: unsupported identifier in ext_version",
		},
		{
			fn:   "postgres.create_extension",
			args: &CreateExtensionArgs{Name: "foo", FromVersion: postgresString(marker + ";")},
			want: "postgres: invalid argument: unsupported identifier in from_version",
		},
		{
			fn:   "postgres.drop_extension",
			args: &DropExtensionArgs{Name: marker + ";"},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
		{
			fn:   "postgres.language_create",
			args: &LanguageMutationArgs{Name: marker + ";", MaintenanceDB: "d"},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
		{
			fn:   "postgres.language_remove",
			args: &LanguageMutationArgs{Name: marker, MaintenanceDB: "d"},
			want: "postgres: invalid argument: unsupported identifier in name",
		},
	} {
		rt, runner := newPostgresRuntime()
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		_, err := rt.Exec.Call(context.Background(), rt, tc.fn, tc.args)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s err = %v, want %q", tc.fn, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("%s error leaks the rejected value: %v", tc.fn, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands, want 0", tc.fn, len(runner.calls))
		}
	}
}
