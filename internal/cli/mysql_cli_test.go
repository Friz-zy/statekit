package cli

import (
	"encoding/json"
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
