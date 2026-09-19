package cli

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execmysql "github.com/friz-zy/statekit/modules/exec/mysql"
)

// mysqlCLIApp builds a CLI app whose runtime has NO Runner attached: the
// R9.2a mysql slice is pure and must run end to end without one.
func mysqlCLIApp(t *testing.T) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
	}
	if err := execmysql.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestMySQLCLIQuoteIdentifier drives mysql.quote_identifier through the CLI
// with the source docstring vector plus the for_grants flag spelling.
func TestMySQLCLIQuoteIdentifier(t *testing.T) {
	app := mysqlCLIApp(t)

	code, out, errS := captureCode(t, app, "exec", "mysql.quote_identifier", "--identifier", "foo`bar", "-o", "json")
	var quoted string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quoted) != nil || quoted != "`foo``bar`" {
		t.Fatalf("quote_identifier code=%d out=%q err=%q", code, out, errS)
	}

	code, out, errS = captureCode(t, app, "exec", "mysql.quote_identifier", "--identifier", "my_%db", "--for-grants", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quoted) != nil || quoted != "`my\\_%%db`" {
		t.Fatalf("quote_identifier for_grants code=%d out=%q err=%q", code, out, errS)
	}

	// The underscore flag spelling must also be accepted verbatim.
	code, out, errS = captureCode(t, app, "exec", "mysql.quote_identifier", "--identifier", "a_b", "--for_grants", "-o", "json")
	if code != ExitOK || json.Unmarshal([]byte(out), &quoted) != nil || quoted != "`a\\_b`" {
		t.Fatalf("quote_identifier underscore flag code=%d out=%q err=%q", code, out, errS)
	}

	// Missing required identifier is invalid input, not a runner failure.
	code, _, errS = captureCode(t, app, "exec", "mysql.quote_identifier", "-o", "json")
	if code != ExitInvalidInput {
		t.Fatalf("missing identifier code=%d err=%q, want ExitInvalidInput", code, errS)
	}
}

// TestMySQLCLITokenizeGrant drives mysql.tokenize_grant through the CLI
// with the docstring example and asserts the exact user/host/grant/database
// JSON shape, including the [] rendering of an empty grant list.
func TestMySQLCLITokenizeGrant(t *testing.T) {
	app := mysqlCLIApp(t)

	code, out, errS := captureCode(t, app, "exec", "mysql.tokenize_grant",
		"--grant", "GRANT SELECT, INSERT ON testdb.* TO 'testuser'@'localhost'", "-o", "json")
	var tokens map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tokens) != nil {
		t.Fatalf("tokenize_grant code=%d out=%q err=%q", code, out, errS)
	}
	if tokens["user"] != "testuser" || tokens["host"] != "localhost" || tokens["database"] != "testdb.*" {
		t.Fatalf("tokenize_grant scalars = %#v", tokens)
	}
	if !reflect.DeepEqual(tokens["grant"], []any{"SELECT", "INSERT"}) {
		t.Fatalf("tokenize_grant grant list = %#v", tokens["grant"])
	}

	code, out, errS = captureCode(t, app, "exec", "mysql.tokenize_grant", "--grant", "GRANT", "-o", "json")
	var empty map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &empty) != nil {
		t.Fatalf("empty grant code=%d out=%q err=%q", code, out, errS)
	}
	if list, ok := empty["grant"].([]any); !ok || len(list) != 0 {
		t.Fatalf("empty grant list = %#v", empty["grant"])
	}

	// Malformed grants keep the pinned error classes: unterminated quotes
	// and read-ahead truncation surface as execution failures.
	for _, malformed := range []string{
		"GRANT SELECT ON `db.* TO 'u'@'h'",
		"GRANT SELECT",
	} {
		code, _, errS = captureCode(t, app, "exec", "mysql.tokenize_grant", "--grant", malformed, "-o", "json")
		if code != ExitFailed {
			t.Fatalf("malformed grant %q code=%d err=%q, want ExitFailed", malformed, code, errS)
		}
	}
	if code, _, errS = captureCode(t, app, "exec", "mysql.tokenize_grant", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("missing grant code=%d err=%q, want ExitInvalidInput", code, errS)
	}
}

// mysqlCLIRunnerApp builds a CLI app whose runtime carries the mysql
// module and a recording fake Runner: the R9.3a read-only family is
// mock-only and must never reach a real mysql client or server.
func mysqlCLIRunnerApp(t *testing.T, runner *cliRecordingRunner) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := execmysql.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestMySQLCLIDBList drives mysql.db_list end to end with the full
// connection surface: exact argv and the MYSQL_PWD-only environment
// through the fake Runner, the JSON array rendering, and no password
// anywhere in the rendered command or CLI output.
func TestMySQLCLIDBList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\ninformation_schema\nmysql\nsalt\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_list",
		"--connection-user", "test_user", "--connection-host", "test_host",
		"--connection-port", "test_port", "--connection-db", "test_maint",
		"--connection-pass", "test_pass", "-o", "json")
	var databases []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil ||
		!reflect.DeepEqual(databases, []string{"information_schema", "mysql", "salt"}) {
		t.Fatalf("db_list code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch",
		"--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA",
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 1 || command.Env[0] != "MYSQL_PWD=test_pass" {
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

	// The underscore flag spelling must also be accepted verbatim.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\nmysql\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_list",
		"--connection_user", "test_user", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil ||
		!reflect.DeepEqual(databases, []string{"mysql"}) {
		t.Fatalf("underscore flag db_list code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIDBListShapes pins the bare default call and the pinned
// nonzero-exit compatibility data: an unreachable or denying server
// answers the empty list with a zero CLI exit, never an error.
func TestMySQLCLIDBListShapes(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("ERROR 1045 (28000): Access denied\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_list", "-o", "json")
	var databases []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil || len(databases) != 0 {
		t.Fatalf("nonzero-exit db_list code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA"}) {
		t.Fatalf("bare argv = %q", argv)
	}
	if runner.calls[0].Env == nil || len(runner.calls[0].Env) != 0 {
		t.Fatalf("bare env = %#v, want the clean empty environment", runner.calls[0].Env)
	}
}

// TestMySQLCLIDBExists drives db_exists through the CLI: the exact bool
// rendering for hits, misses, and the nonzero-exit compatibility false.
func TestMySQLCLIDBExists(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\ninformation_schema\nmysql\nsalt\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_exists", "--name", "mysql", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("db_exists hit code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\ninformation_schema\nmysql\nsalt\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_exists", "--name", "missing", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("db_exists miss code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("ERROR 2002: Can't connect\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_exists", "--name", "mysql", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("nonzero-exit db_exists code=%d out=%q err=%q", code, out, errS)
	}

	// Missing required name is invalid input.
	app = mysqlCLIRunnerApp(t, &cliRecordingRunner{})
	if code, _, errS = captureCode(t, app, "exec", "mysql.db_exists", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("missing name code=%d err=%q, want ExitInvalidInput", code, errS)
	}
}

// TestMySQLCLIUserList drives user_list through the CLI: the JSON array
// of the pinned DictRow objects.
func TestMySQLCLIUserList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\nsalt\t%\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.user_list", "-o", "json")
	var users []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &users) != nil ||
		!reflect.DeepEqual(users, []map[string]any{
			{"User": "root", "Host": "localhost"},
			{"User": "salt", "Host": "%"},
		}) {
		t.Fatalf("user_list code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=SELECT COALESCE(User, UNHEX('00')) AS User, COALESCE(Host, UNHEX('00')) AS Host FROM mysql.user"}) {
		t.Fatalf("argv = %q", argv)
	}
}

// TestMySQLCLIUserExists drives user_exists through the CLI: the exact
// bool for the pinned localhost default and an explicit host, and the
// password-verification boundary as exit 3 with zero Runner calls and no
// credential in the output.
func TestMySQLCLIUserExists(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\nroot\t%\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.user_exists", "--user", "root", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("user_exists hit code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\nroot\t%\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_exists", "--user", "root", "--host", "%", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("user_exists explicit host code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_exists", "--user", "ghost", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("user_exists miss code=%d out=%q err=%q", code, out, errS)
	}

	// The password-verification boundary answers the unsupported exit 3
	// before any Runner invocation, with no credential in the output.
	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "mysql.user_exists",
		"--user", "root", "--password", "BLUECOW", "-o", "json")
	if code != ExitUnsupported {
		t.Fatalf("password boundary code=%d err=%q, want ExitUnsupported", code, errS)
	}
	if strings.Contains(errS, "BLUECOW") {
		t.Fatalf("boundary stderr leaks password: %q", errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("password boundary made %d calls, want 0", len(runner.calls))
	}

	// The pinned falsy empty password stays on the bare path.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_exists",
		"--user", "root", "--password", "", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("empty password code=%d out=%q err=%q", code, out, errS)
	}

	// Missing required user is invalid input.
	app = mysqlCLIRunnerApp(t, &cliRecordingRunner{})
	if code, _, errS = captureCode(t, app, "exec", "mysql.user_exists", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("missing user code=%d err=%q, want ExitInvalidInput", code, errS)
	}
}

// TestMySQLCLIUserListBatchDecoding drives user_list through the CLI on
// batch output carrying the mysql client's field escaping: the JSON is
// the exact decoded shape — doubled backslashes collapse to the account's
// single backslash, the NULL sentinel renders as null, the literal string
// NULL stays the ordinary string, and CRLF framing leaves no delimiter CR
// in any field — with no password anywhere in the output.
func TestMySQLCLIUserListBatchDecoding(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\r\nwin\\\\admin\tlocalhost\r\n\\0\t%\r\nNULL\tlocalhost\r\nplain\t\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.user_list", "-o", "json")
	var users []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &users) != nil ||
		!reflect.DeepEqual(users, []map[string]any{
			{"User": `win\admin`, "Host": "localhost"},
			{"User": nil, "Host": "%"},
			{"User": "NULL", "Host": "localhost"},
			{"User": "plain", "Host": ""},
		}) {
		t.Fatalf("decoded user_list code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}
}

// TestMySQLCLIUserExistsBatchDecoding drives the blocking R9.3a
// regressions through the CLI: the single-backslash account name matches
// after batch decoding, the still-encoded spelling stays a miss, the NULL
// sentinel never matches while a user or host literally spelled NULL
// matches exactly, and CRLF framing never breaks the exact match.
func TestMySQLCLIUserExistsBatchDecoding(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nwin\\\\admin\tlocalhost\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.user_exists",
		"--user", `win\admin`, "--host", "localhost", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
		t.Fatalf("decoded user_exists hit code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nwin\\\\admin\tlocalhost\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_exists",
		"--user", `win\\admin`, "--host", "localhost", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("encoded-spelling user_exists miss code=%d out=%q err=%q", code, out, errS)
	}

	for _, tc := range []struct {
		name string
		out  string
		user string
		host string
		want string
	}{
		{"sentinel-host-miss", "User\tHost\nroot\t\\0\n", "root", "NULL", "false"},
		{"literal-null-host-hit", "User\tHost\nroot\tNULL\n", "root", "NULL", "true"},
		{"sentinel-user-miss", "User\tHost\n\\0\tlocalhost\n", "NULL", "localhost", "false"},
		{"literal-null-user-hit", "User\tHost\nNULL\tlocalhost\n", "NULL", "localhost", "true"},
		{"crlf-framing-hit", "User\tHost\r\nroot\tlocalhost\r\n", "root", "localhost", "true"},
		{"crlf-framing-miss", "User\tHost\r\nroot\tlocalhost\r\n", "root", "localhost\r", "false"},
	} {
		runner = &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.out)},
		}}
		app = mysqlCLIRunnerApp(t, runner)
		code, out, errS = captureCode(t, app, "exec", "mysql.user_exists",
			"--user", tc.user, "--host", tc.host, "-o", "json")
		if code != ExitOK || errS != "" || strings.TrimSpace(out) != tc.want {
			t.Fatalf("%s: user_exists code=%d out=%q err=%q, want %s", tc.name, code, out, errS, tc.want)
		}
	}
}

// TestMySQLCLIDBCatalogDecoding drives the NULL sentinel and CRLF framing
// through the CLI db catalog: the sentinel row is skipped while a database
// literally named NULL is listed and matched, and CRLF framing changes
// neither the listing nor the exact match.
func TestMySQLCLIDBCatalogDecoding(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\r\n\\0\r\nNULL\r\nmysql\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_list", "-o", "json")
	var databases []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil ||
		!reflect.DeepEqual(databases, []string{"NULL", "mysql"}) {
		t.Fatalf("decoded db_list code=%d out=%q err=%q", code, out, errS)
	}

	for _, tc := range []struct {
		name string
		db   string
		want string
	}{
		{"literal-null-name-hit", "NULL", "true"},
		{"mysql-hit", "mysql", "true"},
		{"sentinel-name-miss", "\x00", "false"},
	} {
		runner = &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("Database\r\n\\0\r\nNULL\r\nmysql\r\n")},
		}}
		app = mysqlCLIRunnerApp(t, runner)
		code, out, errS = captureCode(t, app, "exec", "mysql.db_exists", "--name", tc.db, "-o", "json")
		if code != ExitOK || errS != "" || strings.TrimSpace(out) != tc.want {
			t.Fatalf("%s: db_exists(%q) code=%d out=%q err=%q", tc.name, tc.db, code, out, errS)
		}
	}
}

// TestMySQLCLIVersion drives mysql.version end to end through the CLI:
// the exact pinned SELECT VERSION() argv with the full connection surface,
// the JSON string answer, the pinned "" compatibility data on a nonzero
// exit, and no password anywhere.
func TestMySQLCLIVersion(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.36\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.version",
		"--connection-user", "test_user", "--connection-host", "test_host",
		"--connection-port", "test_port", "--connection-db", "test_maint",
		"--connection-pass", "test_pass", "-o", "json")
	var version string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &version) != nil || version != "8.0.36" {
		t.Fatalf("version code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch",
		"--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=SELECT VERSION()",
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 1 || command.Env[0] != "MYSQL_PWD=test_pass" {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "test_pass" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// The pinned empty-string compatibility data on a nonzero exit.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("ERROR 1045 (28000): Access denied\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.version", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &version) != nil || version != "" {
		t.Fatalf("nonzero-exit version code=%d out=%q err=%q", code, out, errS)
	}

	// A header-only success is the pinned fetchone IndexError shape.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("VERSION()\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.version", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &version) != nil || version != "" {
		t.Fatalf("header-only version code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIStatus drives mysql.status through the CLI: the exact pinned
// SHOW STATUS argv, the JSON object with batch-decoded values on CRLF
// framing, and the pinned {} compatibility data on a nonzero exit.
func TestMySQLCLIStatus(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\r\nUptime\t347\r\nSsl_cipher\t\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.status", "-o", "json")
	var status map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &status) != nil ||
		!reflect.DeepEqual(status, map[string]string{"Uptime": "347", "Ssl_cipher": ""}) {
		t.Fatalf("status code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=SHOW STATUS"}) {
		t.Fatalf("argv = %q", argv)
	}

	// Batch-escaped and raw-CR values decode through the CLI.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\nwin\\\\path\tC:\\\\data\ncarriage\tva\rl\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.status", "-o", "json")
	var decodedStatus map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &decodedStatus) != nil ||
		!reflect.DeepEqual(decodedStatus, map[string]string{`win\path`: `C:\data`, "carriage": "va\rl"}) {
		t.Fatalf("decoded status code=%d out=%q err=%q", code, out, errS)
	}

	// The pinned {} compatibility data on a nonzero exit.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("ERROR 2002 (HY000): Can't connect\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.status", "-o", "json")
	var emptyStatus map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &emptyStatus) != nil || len(emptyStatus) != 0 {
		t.Fatalf("nonzero-exit status code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIShowVariables drives mysql.showvariables through the CLI:
// the exact pinned SHOW VARIABLES argv, the JSON array of row dicts with
// decoded values, the pinned [[ ]] empty-result quirk, and the bare []
// _connect-failure shape on a nonzero exit.
func TestMySQLCLIShowVariables(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\nmax_connections\t151\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.showvariables", "-o", "json")
	var variables []map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &variables) != nil ||
		!reflect.DeepEqual(variables, []map[string]string{
			{"Variable_name": "max_connections", "Value": "151"},
		}) {
		t.Fatalf("showvariables code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=SHOW VARIABLES"}) {
		t.Fatalf("argv = %q", argv)
	}

	// The pinned empty-result quirk renders [[ ]] exactly like Salt's —
	// the CLI JSON is pretty-printed, so the shape is asserted parsed.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.showvariables", "-o", "json")
	var quirk []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quirk) != nil || len(quirk) != 1 || len(quirk[0].([]any)) != 0 {
		t.Fatalf("empty showvariables code=%d out=%q err=%q, want [[]]", code, out, errS)
	}

	// The pinned _connect-failure shape renders the bare [].
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("ERROR 1045 (28000): Access denied\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.showvariables", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quirk) != nil || len(quirk) != 0 {
		t.Fatalf("nonzero-exit showvariables code=%d out=%q err=%q, want []", code, out, errS)
	}
}

// TestMySQLCLIRunnerErrorRedaction exercises actual secret-bearing Runner
// errors, rather than inferring error redaction from successful calls.
func TestMySQLCLIRunnerErrorRedaction(t *testing.T) {
	marker := "synthetic-cli-runner-password"
	for _, name := range []string{"mysql.version", "mysql.status", "mysql.showvariables", "mysql.showglobal", "mysql.user_list", "mysql.db_list"} {
		t.Run(name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("runner failed: " + marker)}}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", name, "--connection-pass", marker, "-o", "json")
			if code != ExitFailed || strings.Contains(out+errS, marker) || !strings.Contains(errS, "runner failed:") || len(runner.calls) != 1 {
				t.Fatal("CLI must expose a redacted Runner failure after one call")
			}
			if !reflect.DeepEqual(runner.calls[0].Redact, []string{marker}) || strings.Contains(runner.calls[0].RedactedString(), marker) {
				t.Fatal("CLI command failed synthetic secret guard")
			}
		})
	}
}

// TestMySQLCLIShowGlobal asserts the query and ordinary/empty/failure shapes.
func TestMySQLCLIShowGlobal(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\r\ndatadir\t/var/lib/mysql/\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.showglobal", "-o", "json")
	var variables []map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &variables) != nil ||
		!reflect.DeepEqual(variables, []map[string]string{
			{"Variable_name": "datadir", "Value": "/var/lib/mysql/"},
		}) {
		t.Fatalf("showglobal code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=SHOW GLOBAL VARIABLES"}) {
		t.Fatalf("argv = %q", argv)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.showglobal", "-o", "json")
	var quirk []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quirk) != nil || len(quirk) != 1 || len(quirk[0].([]any)) != 0 {
		t.Fatalf("empty showglobal code=%d out=%q err=%q, want [[]]", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.showglobal", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &quirk) != nil || len(quirk) != 0 {
		t.Fatalf("nonzero-exit showglobal code=%d out=%q err=%q, want []", code, out, errS)
	}
}

// TestMySQLCLIDBCheck drives mysql.db_check end to end over the whole
// table=None flow: the two fixed catalog queries with the client-side
// database match, then one CHECK TABLE statement per table in source
// order (the catalog's result order — deliberately unsorted here), with
// the pinned list-of-lists JSON shape and no password anywhere in the
// rendered command or CLI output.
func TestMySQLCLIDBCheck(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ninformation_schema\ntest_db\n")},
		{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\nother_db\tforeign\ntest_db\tbeta\ntest_db\talpha\n")},
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`beta`\tcheck\tstatus\tOK\n")},
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`alpha`\tcheck\twarning\tTable is marked as crashed\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_check", "--name", "test_db",
		"--connection-user", "test_user", "--connection-pass", "test_pass", "-o", "json")
	var results []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &results) != nil || len(results) != 2 {
		t.Fatalf("db_check code=%d out=%q err=%q", code, out, errS)
	}
	first, ok := results[0].([]any)
	if !ok || len(first) != 1 {
		t.Fatalf("db_check first table result = %#v", results[0])
	}
	firstRow, ok := first[0].(map[string]any)
	if !ok || firstRow["Msg_text"] != "OK" || firstRow["Table"] != "`test_db`.`beta`" {
		t.Fatalf("db_check first row = %#v", firstRow)
	}
	second, ok := results[1].([]any)
	if !ok || len(second) != 1 {
		t.Fatalf("db_check second table result = %#v", results[1])
	}
	secondRow, ok := second[0].(map[string]any)
	if !ok || secondRow["Msg_type"] != "warning" || secondRow["Table"] != "`test_db`.`alpha`" {
		t.Fatalf("db_check second row = %#v", secondRow)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("runner calls = %d, want 4", len(runner.calls))
	}
	wantArgv := [][]string{
		{"mysql", "--batch", "--user=test_user", "--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA"},
		{"mysql", "--batch", "--user=test_user", "--execute=SELECT COALESCE(TABLE_SCHEMA, UNHEX('00')) AS TABLE_SCHEMA, COALESCE(TABLE_NAME, UNHEX('00')) AS TABLE_NAME FROM information_schema.TABLES ORDER BY information_schema.TABLES.TABLE_NAME"},
		{"mysql", "--batch", "--user=test_user", "--execute=CHECK TABLE `test_db`.`beta`"},
		{"mysql", "--batch", "--user=test_user", "--execute=CHECK TABLE `test_db`.`alpha`"},
	}
	for i, want := range wantArgv {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if !reflect.DeepEqual(argv, want) {
			t.Fatalf("call %d argv = %q, want %q", i, argv, want)
		}
	}
	for i, command := range runner.calls {
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=test_pass"}) {
			t.Fatalf("env = %q", command.Env)
		}
		var wantRedact []string
		if i >= 2 {
			wantRedact = []string{"test_pass"}
		}
		if !reflect.DeepEqual(command.Redact, wantRedact) || command.Shell {
			t.Fatalf("unsafe command: %#v", command)
		}
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// The database exists but carries no tables: the pinned empty list.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ntest_db\n")},
		{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\nother_db\tforeign\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_check", "--name", "test_db", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty db_check code=%d out=%q err=%q, want []", code, out, errS)
	}
}

// TestMySQLCLIDBRepairOptimize drives the single-table REPAIR and
// OPTIMIZE statements through the CLI, including the underscore flag
// spelling: one statement, the pinned unwrapped row-list shape.
func TestMySQLCLIDBRepairOptimize(t *testing.T) {
	for _, tc := range []struct {
		name      string
		statement string
		op        string
	}{
		{"mysql.db_repair", "REPAIR TABLE `test_db`.`test_tbl`", "repair"},
		{"mysql.db_optimize", "OPTIMIZE TABLE `test_db`.`test_tbl`", "optimize"},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`test_tbl`\t" + tc.op + "\tstatus\tOK\n")},
		}}
		app := mysqlCLIRunnerApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", tc.name, "--name", "test_db", "--table", "test_tbl", "-o", "json")
		var rows []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &rows) != nil ||
			len(rows) != 1 || rows[0]["Op"] != tc.op || rows[0]["Msg_text"] != "OK" {
			t.Fatalf("%s code=%d out=%q err=%q", tc.name, code, out, errS)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s runner calls = %d, want 1", tc.name, len(runner.calls))
		}
		if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
			[]string{"mysql", "--batch", "--execute=" + tc.statement}) {
			t.Fatalf("%s argv = %q", tc.name, argv)
		}
	}

	// The underscore flag spelling must also be accepted verbatim.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`test_tbl`\trepair\tstatus\tOK\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.db_repair", "--name", "test_db", "--table", "test_tbl", "-o", "json")
	var rows []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 {
		t.Fatalf("underscore db_repair code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIDBCheckErrors pins the CLI failure surfaces: the strict
// maintenance errors exit failed with the fixed value-free messages, a
// missing required name is invalid input, and a rejected identifier
// never reaches the Runner.
func TestMySQLCLIDBCheckErrors(t *testing.T) {
	// Missing required name is invalid input, not a runner failure.
	app := mysqlCLIRunnerApp(t, &cliRecordingRunner{})
	if code, _, errS := captureCode(t, app, "exec", "mysql.db_check", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("missing name code=%d err=%q, want ExitInvalidInput", code, errS)
	}

	// The missing database answers the pinned module-error surface.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ninformation_schema\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.db_check", "--name", "ghost", "-o", "json")
	if code != ExitFailed || errS == "" || !strings.Contains(errS, "mysql: database does not exist") ||
		strings.Contains(errS, "ghost") || out != "" || len(runner.calls) != 1 {
		t.Fatalf("missing database code=%d out=%q err=%q", code, out, errS)
	}

	// A nonzero mysql exit anywhere in the flow is the strict abort.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ntest_db\n")},
		{ExitCode: 1, Stderr: []byte("ERROR 2002 (HY000): Can't connect\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_optimize", "--name", "test_db", "-o", "json")
	if code != ExitFailed || errS == "" || !strings.Contains(errS, "maintenance run completed nonzero") || out != "" {
		t.Fatalf("nonzero db_optimize code=%d out=%q err=%q", code, out, errS)
	}

	// A control-carrying identifier is rejected before any Runner call.
	empty := &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, empty)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_repair", "--name", "test_db", "--table", "bad\ntable", "-o", "json")
	if code != ExitFailed || errS == "" || !strings.Contains(errS, "unsupported identifier in table") ||
		strings.Contains(errS, "bad") || out != "" || len(empty.calls) != 0 {
		t.Fatalf("identifier rejection code=%d out=%q err=%q calls=%d", code, out, errS, len(empty.calls))
	}

	// A secret-bearing Runner error is redacted on the maintenance path:
	// fixed catalog reads defer redaction to the transport, never CLI output.
	marker := "synthetic-cli-maintenance-password"
	leaking := &cliRecordingRunner{results: []process.CommandResult{
		{Err: errors.New("runner failed: " + marker)},
	}}
	app = mysqlCLIRunnerApp(t, leaking)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_check", "--name", "test_db",
		"--connection-pass", marker, "-o", "json")
	if code != ExitFailed || strings.Contains(out+errS, marker) || !strings.Contains(errS, "runner failed:") || len(leaking.calls) != 1 {
		t.Fatalf("runner error redaction code=%d out=%q err=%q calls=%d", code, out, errS, len(leaking.calls))
	}
	if len(leaking.calls[0].Redact) != 0 ||
		strings.Contains(leaking.calls[0].RedactedString(), marker) ||
		!reflect.DeepEqual(leaking.calls[0].Env, []string{"MYSQL_PWD=" + marker}) {
		t.Fatalf("maintenance redaction command = %#v", leaking.calls[0])
	}
}
