package cli

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execmysql "github.com/friz-zy/statekit/modules/exec/mysql"
	"gopkg.in/yaml.v3"
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

func TestMySQLCLIQueryUsesStdinAndPreservesShapes(t *testing.T) {
	query := "/* cli comment */\nSELECT 1 AS id, 'quoted; value' AS note, NULL AS missing\n"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("id\tnote\tmissing\n1\tquoted; value\tNULL\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.query",
		"--database", "query_db", "--query", query,
		"--connection-user", "query_user", "--connection-pass", "query-pass", "-o", "json")
	var value map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil {
		t.Fatalf("query code=%d out=%q err=%q", code, out, errS)
	}
	if !reflect.DeepEqual(value["columns"], []any{"id", "note", "missing"}) ||
		!reflect.DeepEqual(value["results"], []any{[]any{"1", "quoted; value", nil}}) ||
		value["rows returned"] != float64(1) {
		t.Fatalf("query shape = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("query calls = %d", len(runner.calls))
	}
	call := runner.calls[0]
	argv := append([]string{call.Name}, call.Args...)
	if strings.Contains(strings.Join(argv, "\x00"), query) || strings.Contains(strings.Join(argv, "\x00"), "quoted; value") {
		t.Fatalf("query leaked into argv: %#v", argv)
	}
	if string(call.Stdin) != query || !containsCLISecret(call.Redact, query) || !containsCLISecret(call.Redact, "query-pass") {
		t.Fatalf("query stdin/redaction = stdin %q redact %#v", call.Stdin, call.Redact)
	}
	if call.Shell || call.Timeout <= 0 || call.MaxStdoutBytes <= 0 || call.MaxStderrBytes <= 0 {
		t.Fatalf("unsafe query command = %#v", call)
	}

	writeQuery := "UPDATE t SET note = 'x' WHERE id = 1"
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("__statekit_rows_affected__\n1\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.query", "--database", "query_db", "--query", writeQuery, "-o", "json")
	var affected map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &affected) != nil || affected["rows affected"] != float64(1) {
		t.Fatalf("query write code=%d out=%q err=%q value=%#v", code, out, errS, affected)
	}
	if len(runner.calls) != 1 || !strings.HasSuffix(string(runner.calls[0].Stdin), "SELECT ROW_COUNT() AS __statekit_rows_affected__;\n") {
		t.Fatalf("query write stdin=%q", runner.calls[0].Stdin)
	}
}

func mysqlCLIFileRunnerApp(t *testing.T, runner *cliRecordingRunner, path, contents string) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := rt.FS.(*runtime.MemoryFS).WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execmysql.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

func TestMySQLCLIFileQueryUsesBoundedStdinAndPreservesAggregateShape(t *testing.T) {
	path := "/tmp/cli-file-query.sql"
	contents := "SELECT 1 AS id, 'quoted; value' AS note"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("id\tnote\n1\tquoted; value\n")},
	}}
	code, out, errS := captureCode(t, mysqlCLIFileRunnerApp(t, runner, path, contents),
		"exec", "mysql.file_query", "--database", "query_db", "--file-name", path,
		"--connection-pass", "file-query-pass", "-o", "json")
	var value map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil {
		t.Fatalf("file_query code=%d out=%q err=%q", code, out, errS)
	}
	if !reflect.DeepEqual(value["columns"], []any{[]any{"id", "note"}}) ||
		!reflect.DeepEqual(value["results"], []any{[]any{[]any{"1", "quoted; value"}}}) ||
		value["rows returned"] != float64(1) {
		t.Fatalf("file_query shape = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("file_query calls = %d", len(runner.calls))
	}
	call := runner.calls[0]
	argv := append([]string{call.Name}, call.Args...)
	if strings.Contains(strings.Join(argv, "\x00"), path) || strings.Contains(strings.Join(argv, "\x00"), contents) ||
		strings.Contains(strings.Join(argv, "\x00"), "quoted; value") {
		t.Fatalf("file/query value escaped argv: %#v", argv)
	}
	if string(call.Stdin) != contents || !containsCLISecret(call.Redact, contents) ||
		!containsCLISecret(call.Redact, "file-query-pass") || call.Shell ||
		call.Timeout <= 0 || call.MaxStdoutBytes <= 0 || call.MaxStderrBytes <= 0 {
		t.Fatalf("file_query transport = %#v", call)
	}

	runner = &cliRecordingRunner{}
	invalidPath := "/tmp/file-query-\n-invalid.sql"
	code, out, errS = captureCode(t, mysqlCLIFileRunnerApp(t, runner, path, contents),
		"exec", "mysql.file_query", "--database", "query_db", "--file-name", invalidPath, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(errS, invalidPath) || len(runner.calls) != 0 {
		t.Fatalf("file_query invalid path code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}

func TestMySQLCLIQueryAndFileQueryNormalizePercentExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		statement string
		stdout    string
		wantStdin string
	}{
		{
			name:      "select",
			statement: "SELECT '%%%%' AS percent",
			stdout:    "percent\n%%\n",
			wantStdin: "SELECT '%%' AS percent",
		},
		{
			name:      "mutation",
			statement: "UPDATE t SET note = '%%%%' WHERE id = 1",
			stdout:    "__statekit_rows_affected__\n3\n",
			wantStdin: "UPDATE t SET note = '%%' WHERE id = 1;\nSELECT ROW_COUNT() AS __statekit_rows_affected__;\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directRunner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(tc.stdout)}}}
			code, _, errS := captureCode(t, mysqlCLIRunnerApp(t, directRunner),
				"exec", "mysql.query", "--database", "query_db", "--query", tc.statement, "-o", "json")
			if code != ExitOK || errS != "" || len(directRunner.calls) != 1 {
				t.Fatalf("direct code=%d err=%q calls=%d", code, errS, len(directRunner.calls))
			}

			fileRunner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(tc.stdout)}}}
			path := "/tmp/cli-percent-" + tc.name + ".sql"
			code, _, errS = captureCode(t, mysqlCLIFileRunnerApp(t, fileRunner, path, tc.statement),
				"exec", "mysql.file_query", "--database", "query_db", "--file-name", path, "-o", "json")
			if code != ExitOK || errS != "" || len(fileRunner.calls) != 1 {
				t.Fatalf("file code=%d err=%q calls=%d", code, errS, len(fileRunner.calls))
			}
			if got := string(directRunner.calls[0].Stdin); got != tc.wantStdin {
				t.Fatalf("direct stdin=%q want=%q", got, tc.wantStdin)
			}
			if got := string(fileRunner.calls[0].Stdin); got != tc.wantStdin {
				t.Fatalf("file stdin=%q want=%q", got, tc.wantStdin)
			}
		})
	}
}

func TestMySQLCLIQueryPreservesPositionalColumnsAndEmptyHeaders(t *testing.T) {
	marker := "mysql-cli-query-column-secret"
	backslashPassword := `mysql-cli-query-column-secret\backslash`
	tabPassword := "mysql-cli-query-column-secret\\slash	internal-tab"
	backslashWire := mysqlCLIBatchEscape(backslashPassword)
	tabWire := mysqlCLIBatchEscape(tabPassword)
	for _, tc := range []struct {
		name        string
		query       string
		stdout      string
		password    string
		wantColumns []any
		wantResults []any
	}{
		{
			name:        "empty-alias-with-populated-row",
			query:       "SELECT 1 AS ''",
			stdout:      "\npopulated\n",
			wantColumns: []any{""},
			wantResults: []any{[]any{"populated"}},
		},
		{
			name:        "empty-string-row",
			query:       "SELECT '' AS value",
			stdout:      "value\n\n",
			wantColumns: []any{"value"},
			wantResults: []any{[]any{""}},
		},
		{
			name:        "no-rows",
			query:       "SELECT 1 AS value WHERE 1 = 0",
			stdout:      "value\n",
			wantColumns: []any{"value"},
			wantResults: []any{},
		},
		{
			name:        "duplicate-aliases",
			query:       "SELECT 1 AS alias, 2 AS alias",
			stdout:      "alias\talias\nfirst\tsecond\n",
			wantColumns: []any{"alias", "alias"},
			wantResults: []any{[]any{"first", "second"}},
		},
		{
			name:        "redaction-collision",
			query:       "SELECT 1 AS first, 2 AS second",
			stdout:      marker + "\t" + process.RedactedPlaceholder + "\nfirst\tsecond\n",
			password:    marker,
			wantColumns: []any{process.RedactedPlaceholder, process.RedactedPlaceholder},
			wantResults: []any{[]any{"first", "second"}},
		},
		{
			name:        "raw-and-batch-escaped-password-with-backslash",
			query:       "SELECT 1 AS first, 2 AS second, 3 AS third",
			stdout:      backslashPassword + "\t" + backslashWire + "\t" + process.RedactedPlaceholder + "\nfirst\tsecond\tthird\n",
			password:    backslashPassword,
			wantColumns: []any{process.RedactedPlaceholder, process.RedactedPlaceholder, process.RedactedPlaceholder},
			wantResults: []any{[]any{"first", "second", "third"}},
		},
		{
			name:        "duplicate-batch-escaped-password-with-tab",
			query:       "SELECT 1 AS first, 2 AS second, 3 AS third",
			stdout:      tabWire + "\t" + tabWire + "\t" + process.RedactedPlaceholder + "\nfirst\tsecond\tthird\n",
			password:    tabPassword,
			wantColumns: []any{process.RedactedPlaceholder, process.RedactedPlaceholder, process.RedactedPlaceholder},
			wantResults: []any{[]any{"first", "second", "third"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{{
				ExitCode: 0,
				Stdout:   []byte(tc.stdout),
			}}}
			argv := []string{"exec", "mysql.query", "--database", "db", "--query", tc.query}
			if tc.password != "" {
				argv = append(argv, "--connection-pass", tc.password)
			}
			argv = append(argv, "-o", "json")
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), argv...)
			var value map[string]any
			if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || len(runner.calls) != 1 {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
			if !reflect.DeepEqual(value["columns"], tc.wantColumns) ||
				!reflect.DeepEqual(value["results"], tc.wantResults) ||
				value["rows returned"] != float64(len(tc.wantResults)) || strings.Contains(out+errS, marker) {
				t.Fatalf("query shape=%#v out=%q", value, out)
			}
			if tc.password != "" {
				wire := mysqlCLIBatchEscape(tc.password)
				if strings.Contains(out+errS, tc.password) || strings.Contains(out+errS, wire) {
					t.Fatalf("CLI output leaks a connection secret form: out=%q err=%q", out, errS)
				}
				if !containsCLISecret(runner.calls[0].Redact, tc.password) || !containsCLISecret(runner.calls[0].Redact, wire) {
					t.Fatalf("connection secret inventory = %#v", runner.calls[0].Redact)
				}
				decodeMySQLCLIValueWithSecrets(t, "json", out, tc.password, wire)
			}
		})
	}
}

func TestMySQLCLIQueryNegativeInputAndErrorAreValueFree(t *testing.T) {
	query := "SELECT 'cli-query-secret'"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("runner failed: " + query)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
		"--database", "query_db", "--query", query, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(errS, "cli-query-secret") || len(runner.calls) != 1 {
		t.Fatalf("query error code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
		"--database", "bad\ndb", "--query", "SELECT 1", "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(errS, "bad\ndb") || len(runner.calls) != 0 {
		t.Fatalf("query invalid database code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}

func TestMySQLCLIQueryRejectsSecondStatementAndExecutableComments(t *testing.T) {
	for _, query := range []string{
		"SELECT 1;\n--\nSELECT 2",
		"SELECT 1 /*!40101 UNION SELECT 2 */",
		"UPDATE t SET x = 1 /*! WHERE id = 1 */",
		"SELECT 1 /*+ MAX_EXECUTION_TIME(1) */",
	} {
		t.Run(query, func(t *testing.T) {
			runner := &cliRecordingRunner{}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
				"--database", "query_db", "--query", query, "-o", "json")
			if code != ExitFailed || out != "" || errS != "statekit: mysql: invalid query\n" || len(runner.calls) != 0 {
				t.Fatalf("query=%q code=%d out=%q err=%q calls=%d", query, code, out, errS, len(runner.calls))
			}
		})
	}
}

func TestMySQLCLIQueryRejectsSQLModeDependentBackslashQuotesBeforeRunner(t *testing.T) {
	for _, query := range []string{
		`SELECT 'a\\'; SELECT 2; -- '`,
		`SELECT 'a\'; SELECT 2; -- '`,
		`SELECT "a\"; SELECT 2; -- "`,
		"SELECT `a\\`; SELECT 2; -- `",
	} {
		t.Run(query, func(t *testing.T) {
			runner := &cliRecordingRunner{}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
				"--database", "query_db", "--query", query, "-o", "json")
			if code != ExitFailed || out != "" || errS != "statekit: mysql: invalid query\n" || len(runner.calls) != 0 {
				t.Fatalf("query=%q code=%d out=%q err=%q calls=%d", query, code, out, errS, len(runner.calls))
			}
		})
	}
}

func TestMySQLCLIQueryFramesEmptyLineCommentExact(t *testing.T) {
	query := "UPDATE t SET note = 'x'\n--\n"
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("__statekit_rows_affected__\n2\n"),
	}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
		"--database", "query_db", "--query", query, "-o", "json")
	if code != ExitOK || out == "" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	want := "UPDATE t SET note = 'x';\n--\nSELECT ROW_COUNT() AS __statekit_rows_affected__;\n"
	if got := string(runner.calls[0].Stdin); got != want {
		t.Fatalf("stdin=%q, want %q", got, want)
	}
}

func TestMySQLCLIQueryWithWriteCTEUsesAffectedProbe(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("__statekit_rows_affected__\n1\n"),
	}}}
	query := "WITH cte AS (SELECT 1) UPDATE t SET id = 2"
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
		"--database", "query_db", "--query", query, "-o", "json")
	var result map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &result) != nil || result["rows affected"] != float64(1) || len(runner.calls) != 1 {
		t.Fatalf("code=%d out=%q err=%q calls=%d result=%#v", code, out, errS, len(runner.calls), result)
	}
	want := query + ";\nSELECT ROW_COUNT() AS __statekit_rows_affected__;\n"
	if got := string(runner.calls[0].Stdin); got != want {
		t.Fatalf("CTE stdin=%q, want %q", got, want)
	}
}

func TestMySQLCLIQueryCanonicalTransportErrors(t *testing.T) {
	marker := "cli-partial-sql-credential-fragment"
	cases := []struct {
		name      string
		result    process.CommandResult
		wantError string
	}{
		{name: "cancel", result: process.CommandResult{Err: fmt.Errorf("runner %s: %w", marker, context.Canceled)}, wantError: "context canceled"},
		{name: "deadline", result: process.CommandResult{Err: fmt.Errorf("runner %s: %w", marker, context.DeadlineExceeded)}, wantError: "context deadline exceeded"},
		{name: "output", result: process.CommandResult{Err: fmt.Errorf("runner %s: %w", marker, process.ErrOutputLimit)}, wantError: "process: output limit exceeded"},
		{name: "arbitrary", result: process.CommandResult{Err: fmt.Errorf("runner %s: %w", marker, errors.New("private transport detail"))}, wantError: "mysql: query execution failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{tc.result}}
			query := "SELECT '" + marker + "'"
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.query",
				"--database", "query_db", "--query", query, "--connection-pass", marker, "-o", "json")
			if code != ExitFailed || out != "" || !strings.Contains(errS, tc.wantError) || strings.Contains(out+errS, marker) || len(runner.calls) != 1 {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
		})
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

	// The pinned SHOW DATABASES LIKE query would treat these as wildcard
	// patterns. The fixed catalog deliberately matches them literally, so a
	// different database never produces a false positive.
	for _, name := range []string{"my%", "mysq_"} {
		runner = &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("Database\nmysql\n")},
		}}
		app = mysqlCLIRunnerApp(t, runner)
		code, out, errS = captureCode(t, app, "exec", "mysql.db_exists", "--name", name, "-o", "json")
		if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" || len(runner.calls) != 1 {
			t.Fatalf("literal wildcard db_exists(%q) code=%d out=%q err=%q calls=%d", name, code, out, errS, len(runner.calls))
		}
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

// TestMySQLCLIDBGet drives mysql.db_get through the actual CLI with the
// fixed SCHEMATA query, the source dict shape, SQL NULL sentinel mapping,
// client-side name matching, and the complete connection/redaction surface.
func TestMySQLCLIDBGet(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\r\n" +
			"other\tlatin1\tlatin1_swedish_ci\r\n" +
			"test_db\tutf8mb4\tutf8mb4_0900_ai_ci\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "mysql.db_get", "--name", "test_db",
		"--connection-user", "test_user", "--connection-host", "test_host",
		"--connection-port", "test_port", "--connection-db", "test_maint",
		"--connection-pass", "test_pass", "-o", "json")
	var got map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil ||
		!reflect.DeepEqual(got, map[string]any{"character_set": "utf8mb4", "collate": "utf8mb4_0900_ai_ci"}) {
		t.Fatalf("db_get code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) AS SCHEMA_NAME, COALESCE(DEFAULT_CHARACTER_SET_NAME, UNHEX('00')) AS DEFAULT_CHARACTER_SET_NAME, COALESCE(DEFAULT_COLLATION_NAME, UNHEX('00')) AS DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA",
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=test_pass"}) || !reflect.DeepEqual(command.Redact, []string{"test_pass"}) || command.Shell {
		t.Fatalf("unsafe db_get command = %#v", command)
	}
	if strings.Contains(command.RedactedString()+out+errS, "test_pass") {
		t.Fatalf("db_get output leaks password: command=%q out=%q err=%q", command.RedactedString(), out, errS)
	}

	// SQL NULL becomes JSON null; a literal NULL remains a string.
	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\n" +
			"test_db\t\\0\tNULL\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_get", "--name", "test_db", "-o", "json")
	got = nil
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil ||
		!reflect.DeepEqual(got, map[string]any{"character_set": nil, "collate": "NULL"}) {
		t.Fatalf("db_get NULL code=%d out=%q err=%q", code, out, errS)
	}

	// Successful absence is {}, while a nonzero mysql exit is [].
	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\nother\tutf8\tutf8_general_ci\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_get", "--name", "missing", "-o", "json")
	var empty map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &empty) != nil || len(empty) != 0 {
		t.Fatalf("db_get missing code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("ERROR 1045: denied\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_get", "--name", "missing", "-o", "json")
	var emptyList []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &emptyList) != nil || len(emptyList) != 0 {
		t.Fatalf("db_get nonzero code=%d out=%q err=%q", code, out, errS)
	}

	if code, _, errS = captureCode(t, mysqlCLIRunnerApp(t, &cliRecordingRunner{}), "exec", "mysql.db_get", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("db_get missing name code=%d err=%q", code, errS)
	}
}

// TestMySQLCLIDBTables drives mysql.db_tables with both the source default and
// the optional exact client-side table filter; no caller name reaches SQL and
// result order is the fixed catalog's order.
func TestMySQLCLIDBTables(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("Database\r\ntest_db\r\nother\r\n")},
		{Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\r\ntest_db\tzeta\r\ntest_db\twanted\r\nother\tignored\r\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.db_tables", "--name", "test_db", "--table", "wanted",
		"--connection-user", "test_user", "--connection-host", "test_host", "--connection-port", "test_port",
		"--connection-db", "test_maint", "--connection-pass", "test_pass", "-o", "json")
	var tables []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tables) != nil || !reflect.DeepEqual(tables, []string{"wanted"}) {
		t.Fatalf("db_tables filtered code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	for i, query := range []string{
		"SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA",
		"SELECT COALESCE(TABLE_SCHEMA, UNHEX('00')) AS TABLE_SCHEMA, COALESCE(TABLE_NAME, UNHEX('00')) AS TABLE_NAME FROM information_schema.TABLES ORDER BY information_schema.TABLES.TABLE_NAME",
	} {
		command := runner.calls[i]
		if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
			"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint", "--execute=" + query,
		}) {
			t.Fatalf("call %d argv=%q", i, argv)
		}
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=test_pass"}) || !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
			t.Fatalf("call %d env/redact=%#v", i, command)
		}
		if strings.Contains(strings.Join(command.Args, "\x00"), "test_db") || strings.Contains(command.RedactedString()+out+errS, "test_pass") {
			t.Fatalf("call %d leaked input: command=%q out=%q err=%q", i, command.RedactedString(), out, errS)
		}
	}

	// Default table=None returns all matching tables in catalog order.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("Database\ntest_db\n")},
		{Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\ntest_db\tzeta\ntest_db\twanted\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_tables", "--name", "test_db", "-o", "json")
	tables = nil
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tables) != nil || !reflect.DeepEqual(tables, []string{"zeta", "wanted"}) {
		t.Fatalf("db_tables all code=%d out=%q err=%q", code, out, errS)
	}

	// Missing database is false after one preflight; a failed table catalog is
	// the source-compatible empty list after a successful preflight.
	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte("Database\nother\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_tables", "--name", "missing", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" || len(runner.calls) != 1 {
		t.Fatalf("db_tables missing code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("Database\ntest_db\n")},
		{ExitCode: 1, Stderr: []byte("ERROR 1045: denied\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_tables", "--name", "test_db", "-o", "json")
	tables = nil
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tables) != nil || len(tables) != 0 {
		t.Fatalf("db_tables failed table catalog code=%d out=%q err=%q", code, out, errS)
	}

	if code, _, errS = captureCode(t, mysqlCLIRunnerApp(t, &cliRecordingRunner{}), "exec", "mysql.db_tables", "-o", "json"); code != ExitInvalidInput {
		t.Fatalf("db_tables missing name code=%d err=%q", code, errS)
	}
}

// TestMySQLCLIDBGetTablesRunnerErrorRedaction keeps synthetic Runner errors
// value-free on both R9.3d registry paths.
func TestMySQLCLIDBGetTablesRunnerErrorRedaction(t *testing.T) {
	marker := "S3CRET-r93d-cli"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("mysql failed with " + marker)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_get", "--name", "db", "--connection-pass", marker, "-o", "json")
	if code != ExitFailed || strings.Contains(out+errS, marker) || len(runner.calls) != 1 {
		t.Fatalf("db_get redaction code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("mysql failed with " + marker)}}}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_tables", "--name", "db", "--connection-pass", marker, "-o", "json")
	if code != ExitFailed || strings.Contains(out+errS, marker) || len(runner.calls) != 1 {
		t.Fatalf("db_tables redaction code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
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
	for _, name := range []string{"mysql.version", "mysql.status", "mysql.showvariables", "mysql.showglobal", "mysql.user_list", "mysql.db_list", "mysql.plugin_status", "mysql.plugins_list"} {
		t.Run(name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("runner failed: " + marker)}}}
			args := []string{"exec", name}
			if name == "mysql.plugin_status" {
				args = append(args, "--name", "synthetic-plugin")
			}
			args = append(args, "--connection-pass", marker, "-o", "json")
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), args...)
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

func mysqlCLIUserInfoStdout(user, host string) []byte {
	fields := strings.Split("User\tHost\tSelect_priv\tInsert_priv\tUpdate_priv\tDelete_priv\tCreate_priv\tDrop_priv\tReload_priv\tShutdown_priv\tProcess_priv\tFile_priv\tGrant_priv\tReferences_priv\tIndex_priv\tAlter_priv\tShow_db_priv\tSuper_priv\tCreate_tmp_table_priv\tLock_tables_priv\tExecute_priv\tRepl_slave_priv\tRepl_client_priv\tCreate_view_priv\tShow_view_priv\tCreate_routine_priv\tAlter_routine_priv\tCreate_user_priv\tEvent_priv\tTrigger_priv\tCreate_tablespace_priv", "\t")
	values := make([]string, len(fields))
	values[0], values[1] = user, host
	for i := 2; i < len(values); i++ {
		values[i] = "Y"
	}
	return []byte(strings.Join(fields, "\t") + "\n" + strings.Join(values, "\t") + "\n")
}

// TestMySQLCLIUserInfo drives the fixed non-secret projection through the
// actual CLI parser and Runner, including the source null/false shapes and
// password redaction.
func TestMySQLCLIUserInfo(t *testing.T) {
	connPass := "cli_info_conn_pass"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: mysqlCLIUserInfoStdout("cli_user", "localhost")}}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.user_info",
		"--user", "cli_user", "--host", "localhost",
		"--connection-user", "admin", "--connection-host", "mysql-host",
		"--connection-port", "3307", "--connection-db", "mysql", "--connection-pass", connPass,
		"-o", "json")
	var result map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &result) != nil || result["User"] != "cli_user" || result["Host"] != "localhost" {
		t.Fatalf("user_info code=%d out=%q err=%q", code, out, errS)
	}
	if _, ok := result["Password"]; ok || strings.Contains(out+errS, connPass) {
		t.Fatalf("user_info leaked secret: out=%q err=%q", out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("user_info calls=%d", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 7 || argv[1] != "--batch" || argv[2] != "--user=admin" || argv[3] != "--host=mysql-host" || argv[4] != "--port=3307" || argv[5] != "--database=mysql" || !strings.HasPrefix(argv[6], "--execute=SELECT COALESCE(User, UNHEX('00')) AS User") {
		t.Fatalf("user_info argv=%q", argv)
	}
	if strings.Contains(strings.ToLower(argv[6]), "password") || strings.Contains(argv[6], "SELECT *") {
		t.Fatalf("user_info SQL is not fixed/non-secret: %q", argv[6])
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || !reflect.DeepEqual(command.Redact, []string{connPass}) || command.Shell || command.Timeout <= 0 || command.MaxStdoutBytes <= 0 || command.MaxStderrBytes <= 0 {
		t.Fatalf("user_info transport=%#v", command)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: mysqlCLIUserInfoStdout("other", "localhost")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_info", "--user", "missing", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "null" || errS != "" {
		t.Fatalf("missing user_info code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_info", "--user", "missing", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" {
		t.Fatalf("failed user_info code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIUserCreateRemove pins actual CLI argument decoding, SQL argv,
// MYSQL_PWD connection transport, bool result rendering, and secret-bearing
// Runner/error redaction for both account mutations.
func TestMySQLCLIUserCreateRemove(t *testing.T) {
	createPass := "cli_create_pass"
	connPass := "cli_conn_pass"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: []byte("User\tHost\nother\tlocalhost\n")},
		{Stdout: []byte("HasPassword\n")},
		{ExitCode: 0, Stderr: []byte("created cli_create_pass\n")},
		{Stdout: []byte("User\tHost\tplugin\ncli_user\tlocalhost\tmysql_native_password\n")},
		{Stdout: []byte("Verified\n1\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.user_create",
		"--user", "cli_user", "--password", createPass, "--auth-plugin", "mysql_native_password",
		"--connection-user", "admin", "--connection-host", "mysql-host", "--connection-port", "3307",
		"--connection-db", "mysql", "--connection-pass", connPass, "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" {
		t.Fatalf("user_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("user_create calls=%d", len(runner.calls))
	}
	createCommand := runner.calls[3]
	createArgv := append([]string{createCommand.Name}, createCommand.Args...)
	if createArgv[len(createArgv)-1] != "--execute=CREATE USER 'cli_user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'cli_create_pass'" {
		t.Fatalf("create SQL=%q", createArgv[len(createArgv)-1])
	}
	if !reflect.DeepEqual(createCommand.Env, []string{"MYSQL_PWD=" + connPass}) || createCommand.Shell || len(createCommand.Redact) < 3 || strings.Contains(createCommand.RedactedString(), createPass) || strings.Contains(createCommand.RedactedString(), connPass) {
		t.Fatalf("create redaction/transport=%#v", createCommand)
	}
	if strings.Contains(out+errS, createPass) || strings.Contains(out+errS, connPass) {
		t.Fatalf("create output leaked secret: out=%q err=%q", out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("User\tHost\ncli_user\tlocalhost\n")},
		{ExitCode: 0},
		{Stdout: []byte("User\tHost\nother\tlocalhost\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_remove", "--user", "cli_user", "--connection-pass", connPass, "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 3 {
		t.Fatalf("user_remove code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	removeArgv := append([]string{runner.calls[1].Name}, runner.calls[1].Args...)
	if removeArgv[len(removeArgv)-1] != "--execute=DROP USER IF EXISTS 'cli_user'@'localhost'" {
		t.Fatalf("remove SQL=%q", removeArgv[len(removeArgv)-1])
	}
	for i, command := range runner.calls {
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || command.Shell || command.Timeout <= 0 || command.MaxStdoutBytes <= 0 || command.MaxStderrBytes <= 0 {
			t.Fatalf("remove call %d transport=%#v", i, command)
		}
		for _, secret := range []string{connPass, "cli_user", "localhost", "'cli_user'@'localhost'"} {
			found := false
			for _, configured := range command.Redact {
				if configured == secret {
					found = true
					break
				}
			}
			if !found || strings.Contains(command.RedactedString(), secret) {
				t.Fatalf("remove call %d redaction missing/leaking %q: %#v", i, secret, command)
			}
		}
	}

	// A hostile account is quoted as a literal and cannot add a second SQL
	// statement; the value is never copied into an error on invalid input.
	hostile := "u' OR '1'='1"
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("User\tHost\n" + hostile + "\tlocalhost\n")},
		{ExitCode: 0},
		{Stdout: []byte("User\tHost\nother\tlocalhost\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_remove", "--user", hostile, "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || !strings.Contains(runner.calls[1].Args[len(runner.calls[1].Args)-1], "DROP USER IF EXISTS 'u'' OR ''1''=''1'@'localhost'") {
		t.Fatalf("hostile remove code=%d out=%q err=%q argv=%q", code, out, errS, runner.calls[1].Args)
	}
}

func TestMySQLCLIUserRemoveCompleteRedactionInventory(t *testing.T) {
	marker := "cli'remove"
	doubled := strings.ReplaceAll(marker, "'", "''")
	literal := "'" + doubled + "'"
	forms := []string{literal + "@" + literal, literal, doubled, marker}
	leak := "runner failure " + strings.Join(forms, " ") + " DROP USER IF EXISTS " + forms[0]

	for failAt := 0; failAt < 3; failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		for call := 0; call < failAt; call++ {
			if call == 1 {
				results = append(results, process.CommandResult{ExitCode: 0})
				continue
			}
			results = append(results, process.CommandResult{Stdout: []byte("User\tHost\n" + marker + "\t" + marker + "\n")})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak),
			Stderr: []byte("stderr " + leak),
		})
		runner := &cliRecordingRunner{results: results}
		app := mysqlCLIRunnerApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "mysql.user_remove",
			"--user", marker, "--host", marker, "--connection-pass", marker, "-o", "json")
		if code != ExitFailed || len(runner.calls) != failAt+1 || !strings.Contains(errS, process.RedactedPlaceholder) {
			t.Fatalf("failAt=%d code=%d out=%q err=%q calls=%d", failAt, code, out, errS, len(runner.calls))
		}
		for _, form := range forms {
			if strings.Contains(out+errS, form) {
				t.Fatalf("failAt=%d CLI output leaked %q: out=%q err=%q", failAt, form, out, errS)
			}
		}
		for index, command := range runner.calls {
			if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) {
				t.Fatalf("failAt=%d call=%d transport=%#v", failAt, index, command)
			}
			for _, form := range forms {
				if strings.Contains(command.RedactedString(), form) {
					t.Fatalf("failAt=%d call=%d rendered command leaked %q: %q", failAt, index, form, command.RedactedString())
				}
				found := false
				for _, secret := range command.Redact {
					if secret == form {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("failAt=%d call=%d inventory missing %q: %#v", failAt, index, form, command.Redact)
				}
			}
			for secretIndex := 1; secretIndex < len(command.Redact); secretIndex++ {
				if len(command.Redact[secretIndex-1]) < len(command.Redact[secretIndex]) {
					t.Fatalf("failAt=%d call=%d inventory is not longest-first: %#v", failAt, index, command.Redact)
				}
			}
			if failAt == 0 && strings.Contains(strings.Join(command.Args, " "), "DROP USER") {
				t.Fatalf("failAt=%d reached DROP before the failing preflight", failAt)
			}
		}
	}
}

// TestMySQLCLIUserMutationErrors pins value-free validation, cancellation at
// the transport boundary, nonzero bool results, and redacted Runner errors.
func TestMySQLCLIUserMutationErrors(t *testing.T) {
	runner := &cliRecordingRunner{}
	app := mysqlCLIRunnerApp(t, runner)
	marker := "synthetic-cli-mysql-account-secret"
	code, out, errS := captureCode(t, app, "exec", "mysql.user_remove", "--user", "bad\n"+marker, "-o", "json")
	if code != ExitFailed || out != "" || !strings.Contains(errS, "mysql: invalid account argument") || strings.Contains(errS, marker) || len(runner.calls) != 0 {
		t.Fatalf("invalid account code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte("VERSION()\n8.0.34\n")}, {Stdout: []byte("User\tHost\nother\tlocalhost\n")}, {Err: errors.New("runner leaked synthetic-cli-mysql-pass")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_create", "--user", "u", "--password", "synthetic-cli-mysql-pass", "--connection-pass", "conn-pass", "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(out+errS, "synthetic-cli-mysql-pass") || !strings.Contains(errS, "runner leaked") || len(runner.calls) != 3 {
		t.Fatalf("create Runner error code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if strings.Contains(runner.calls[2].RedactedString(), "synthetic-cli-mysql-pass") || len(runner.calls[2].Redact) < 3 {
		t.Fatalf("create Runner command leaked secret: %#v", runner.calls[2])
	}

	connectionMarker := "R9_CLI_CONN_FIRST_PREFLIGHT"
	passwordMarker := "R9_CLI_PASSWORD_FIRST_PREFLIGHT"
	hashMarker := "*R9_CLI_HASH_FIRST_PREFLIGHT"
	runner = &cliRecordingRunner{results: []process.CommandResult{{
		Err:    errors.New("first preflight " + connectionMarker + " " + passwordMarker + " " + hashMarker),
		Stdout: []byte("stdout " + connectionMarker + " " + passwordMarker + " " + hashMarker),
		Stderr: []byte("stderr " + connectionMarker + " " + passwordMarker + " " + hashMarker),
	}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_create",
		"--user", "u", "--password", passwordMarker, "--password-hash", hashMarker,
		"--connection-pass", connectionMarker, "-o", "json")
	if code != ExitFailed || len(runner.calls) != 1 {
		t.Fatalf("first preflight CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	for _, marker := range []string{connectionMarker, passwordMarker, hashMarker} {
		if strings.Contains(out+errS, marker) || strings.Contains(runner.calls[0].RedactedString(), marker) {
			t.Fatalf("first preflight CLI leaked %q: out=%q err=%q command=%q", marker, out, errS, runner.calls[0].RedactedString())
		}
		found := false
		for _, secret := range runner.calls[0].Redact {
			if secret == marker {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("first preflight CLI inventory missing %q: %#v", marker, runner.calls[0].Redact)
		}
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte("User\tHost\nu\tlocalhost\n")}, {ExitCode: 1}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_remove", "--user", "u", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" {
		t.Fatalf("nonzero remove code=%d out=%q err=%q", code, out, errS)
	}
}

func TestMySQLCLIUserGrants(t *testing.T) {
	connectionPassword := "cli-user-grants-pass"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\ncli_user\tcli_host\n")},
		{ExitCode: 0, Stdout: []byte("Grants for cli_user@cli_host\n" +
			"GRANT ALL PRIVILEGES ON *.* TO 'cli_user'@'cli_host' IDENTIFIED BY 'ignored' WITH GRANT OPTION\n" +
			"GRANT SELECT ON `cli_db`.* TO 'cli_user'@'cli_host'\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.user_grants",
		"--user", "cli_user", "--host", "cli_host",
		"--connection-user", "conn_user", "--connection-host", "conn_host",
		"--connection-port", "3308", "--connection-db", "maintenance",
		"--connection-pass", connectionPassword, "-o", "json")
	var grants []string
	want := []string{
		"GRANT ALL PRIVILEGES ON *.* TO 'cli_user'@'cli_host' WITH GRANT OPTION",
		"GRANT SELECT ON `cli_db`.* TO 'cli_user'@'cli_host'",
	}
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &grants) != nil || !reflect.DeepEqual(grants, want) {
		t.Fatalf("user_grants code=%d out=%q err=%q grants=%#v", code, out, errS, grants)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("user_grants calls=%d, want 2", len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute="+"SELECT COALESCE(User, UNHEX('00')) AS User, COALESCE(Host, UNHEX('00')) AS Host FROM mysql.user" {
		t.Fatalf("user_grants preflight query=%q", got)
	}
	command := runner.calls[1]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3308", "--database=maintenance",
		"--execute=SHOW GRANTS FOR 'cli_user'@'cli_host'",
	}) {
		t.Fatalf("user_grants argv=%q", got)
	}
	for index, call := range runner.calls {
		if call.Shell || !reflect.DeepEqual(call.Env, []string{"MYSQL_PWD=" + connectionPassword}) ||
			call.Timeout <= 0 || call.MaxStdoutBytes <= 0 || call.MaxStderrBytes <= 0 {
			t.Fatalf("user_grants call %d transport=%#v", index, call)
		}
		for _, secret := range []string{"cli_user", "cli_host", "'cli_user'@'cli_host'", connectionPassword} {
			if !containsCLISecret(call.Redact, secret) {
				t.Fatalf("user_grants call %d Redact missing %q: %#v", index, secret, call.Redact)
			}
		}
		if strings.Contains(call.RedactedString(), connectionPassword) {
			t.Fatalf("user_grants call %d leaked connection password: %q", index, call.RedactedString())
		}
	}
	if strings.Contains(out+errS, connectionPassword) {
		t.Fatalf("user_grants leaked connection password: out=%q err=%q", out, errS)
	}

	// A missing account returns false from the preflight without issuing SHOW
	// GRANTS, matching the pinned user_grants flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("User\tHost\nother\tlocalhost\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_grants", "--user", "missing", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("user_grants missing preflight code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	// runas is rejected before the fixed user_exists preflight.
	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.user_grants", "--user", "u", "--runas", "other", "-o", "json")
	if code != ExitFailed || out != "" || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("user_grants runas code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}

func containsCLISecret(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestMySQLCLIGrantFamily(t *testing.T) {
	connPass := "cli-grant-connection-pass"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{ExitCode: 0, Stdout: []byte("Grants for cli_user@cli_host\nGRANT SELECT ON `cli_db`.`cli_table` TO 'cli_user'@'cli_host' WITH GRANT OPTION\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.grant_add",
		"--user", "cli_user", "--host", "cli_host", "--grant", "SELECT",
		"--database", "cli_db.cli_table", "--grant-option=true", "--escape=false",
		"--connection-user", "conn_user", "--connection-host", "conn_host",
		"--connection-port", "3308", "--connection-db", "maintenance",
		"--connection-pass", connPass, "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 3 {
		t.Fatalf("grant_add code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3308", "--database=maintenance",
		"--execute=GRANT SELECT ON cli_db.cli_table TO 'cli_user'@'cli_host' WITH GRANT OPTION",
	}) {
		t.Fatalf("grant_add SQL = %q", got)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != "--execute=SHOW GRANTS FOR 'cli_user'@'cli_host'" {
		t.Fatalf("grant_exists SQL = %q", got)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SELECT VERSION()" {
		t.Fatalf("grant_exists version SQL = %q", got)
	}
	if got := append([]string{runner.calls[2].Name}, runner.calls[2].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3308", "--database=maintenance",
		"--execute=SHOW GRANTS FOR 'cli_user'@'cli_host'",
	}) {
		t.Fatalf("grant_exists SQL = %q", got)
	}
	for i, command := range runner.calls {
		if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || command.Timeout <= 0 || command.MaxStdoutBytes <= 0 || command.MaxStderrBytes <= 0 {
			t.Fatalf("grant call %d transport=%#v", i, command)
		}
		if strings.Contains(command.RedactedString(), connPass) || strings.Contains(out+errS, connPass) {
			t.Fatalf("grant password leaked at call %d: command=%q out=%q err=%q", i, command.RedactedString(), out, errS)
		}
		for _, secret := range []string{"cli_user", "cli_host", "'cli_user'@'cli_host'", connPass} {
			found := false
			for _, configured := range command.Redact {
				if configured == secret {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("grant call %d redaction inventory missing %q: %#v", i, secret, command.Redact)
			}
		}
	}

	// grant_exists requires the option when requested; the same SHOW GRANTS
	// row without it is a successful false result rather than an error.
	runner = &cliRecordingRunner{results: []process.CommandResult{{
		Stdout: []byte("VERSION()\n8.0.34\n"),
	}, {
		ExitCode: 0,
		Stdout:   []byte("Grants for cli_user@cli_host\nGRANT SELECT ON `cli_db`.`cli_table` TO 'cli_user'@'cli_host'\n"),
	}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.grant_exists",
		"--user", "cli_user", "--host", "cli_host", "--grant", "SELECT",
		"--database", "cli_db.cli_table", "--grant-option=true", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 2 {
		t.Fatalf("grant_exists option miss code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{ExitCode: 0, Stdout: []byte("Grants for cli_user@cli_host\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.grant_revoke",
		"--user", "cli_user", "--host", "cli_host", "--grant", "SELECT",
		"--database", "cli_db.cli_table", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 3 {
		t.Fatalf("grant_revoke code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); got[len(got)-1] != "--execute=REVOKE SELECT ON `cli_db`.`cli_table` FROM 'cli_user'@'cli_host';" {
		t.Fatalf("grant_revoke SQL=%q", got)
	}

	// Unknown grants and incomplete required fields fail before Runner use and
	// the fixed error carries no caller value.
	marker := "unknown-grant-secret"
	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.grant_exists",
		"--user", "u", "--grant", marker, "--database", "db.tbl", "-o", "json")
	if code != ExitFailed || out != "" || !strings.Contains(errS, "mysql: invalid grant") || strings.Contains(errS, marker) || len(runner.calls) != 0 {
		t.Fatalf("unknown grant code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "mysql.grant_add", "--user", "u", "--grant", "SELECT", "--database", "db.tbl", "--table", "legacy", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "table") || len(runner.calls) != 0 {
		t.Fatalf("legacy table code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// A synthetic Runner failure is value-redacted and remains shell-free.
	runner = &cliRecordingRunner{results: []process.CommandResult{{Err: errors.New("runner leaked " + marker)}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.grant_add",
		"--user", marker, "--grant", "SELECT", "--database", "db.tbl",
		"--connection-pass", marker, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(out+errS, marker) || len(runner.calls) != 1 || runner.calls[0].Shell || strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("grant Runner redaction code=%d out=%q err=%q calls=%d command=%q", code, out, errS, len(runner.calls), runner.calls[0].RedactedString())
	}

	// runas is rejected before the central Runner, so no live command can be
	// reached through the CLI.
	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "mysql.grant_exists",
		"--user", "u", "--grant", "SELECT", "--database", "db.tbl", "--runas", "other", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("grant runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

func TestMySQLCLIGrantCompleteRedactionInventory(t *testing.T) {
	marker := "grant'overlap"
	doubled := strings.ReplaceAll(marker, "'", "''")
	quoted := "'" + doubled + "'"
	account := quoted + "@" + quoted
	object := "`" + marker + "`.`" + marker + "`"
	forms := []string{marker, doubled, quoted, account, object}
	leak := "runner grant overlap " + strings.Join(forms, " ")
	config := `{"user":"grant'overlap@grant'overlap","database":"grant'overlap.grant'overlap","grant":"SELECT","ssl_option":[{"CIPHER":"grant'overlap"}],"connection_pass":"grant'overlap"}`

	for failAt := 0; failAt < 3; failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		if failAt > 0 {
			results = append(results, process.CommandResult{ExitCode: 0})
		}
		if failAt > 1 {
			results = append(results, process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak),
			Stderr: []byte("stderr " + leak),
		})
		runner := &cliRecordingRunner{results: results}
		app := mysqlCLIRunnerApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "mysql.grant_add", "--config", config, "-o", "json")
		if code != ExitFailed || out != "" || len(runner.calls) != failAt+1 || !strings.Contains(errS, process.RedactedPlaceholder) {
			t.Fatalf("failAt=%d code=%d out=%q err=%q calls=%d", failAt, code, out, errS, len(runner.calls))
		}
		for callIndex, command := range runner.calls {
			if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) {
				t.Fatalf("failAt=%d call=%d transport=%#v", failAt, callIndex, command)
			}
			for _, form := range forms {
				if strings.Contains(out+errS, form) || strings.Contains(command.RedactedString(), form) {
					t.Fatalf("failAt=%d call=%d leaked %q: out=%q err=%q command=%q", failAt, callIndex, form, out, errS, command.RedactedString())
				}
				found := false
				for _, configured := range command.Redact {
					if configured == form {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("failAt=%d call=%d inventory missing %q: %#v", failAt, callIndex, form, command.Redact)
				}
			}
			for i := 1; i < len(command.Redact); i++ {
				if len(command.Redact[i-1]) < len(command.Redact[i]) {
					t.Fatalf("failAt=%d call=%d inventory not longest-first: %#v", failAt, callIndex, command.Redact)
				}
			}
		}
	}
}

func TestMySQLCLIGrantRevokeRedactionInventory(t *testing.T) {
	marker := "grant'overlap"
	host := "host'overlap"
	doubled := strings.ReplaceAll(marker, "'", "''")
	hostDoubled := strings.ReplaceAll(host, "'", "''")
	quoted := "'" + doubled + "'"
	hostQuoted := "'" + hostDoubled + "'"
	forms := []string{
		marker,
		doubled,
		quoted,
		host,
		hostDoubled,
		hostQuoted,
		marker + "@" + host,
		quoted + "@" + hostQuoted,
		"`" + marker + "`.`" + marker + "`",
		marker + "." + marker,
	}
	leak := "runner grant revoke overlap " + strings.Join(forms, " ")
	args := []string{
		"exec", "mysql.grant_revoke",
		"--user", marker, "--host", host, "--grant", "SELECT",
		"--database", marker + "." + marker, "--grant-option=true", "--escape=true",
		"--connection-user", "conn_user", "--connection-host", "conn_host",
		"--connection-port", "3308", "--connection-db", "maintenance",
		"--connection-pass", marker, "-o", "json",
	}
	wantQueries := []string{
		"--execute=REVOKE SELECT, GRANT OPTION ON `" + marker + "`.`" + marker + "` FROM '" + doubled + "'@'" + hostDoubled + "';",
		"--execute=SELECT VERSION()",
		"--execute=SHOW GRANTS FOR '" + doubled + "'@'" + hostDoubled + "'",
	}
	wantPrefix := []string{"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3308", "--database=maintenance"}
	argsBefore := append([]string(nil), args...)

	for failAt := 0; failAt < len(wantQueries); failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		if failAt > 0 {
			results = append(results, process.CommandResult{ExitCode: 0})
		}
		if failAt > 1 {
			results = append(results, process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak + "\n"),
			Stderr: []byte("stderr " + leak + "\n"),
		})
		runner := &cliRecordingRunner{results: results}
		code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), args...)
		if code != ExitFailed || out != "" || len(runner.calls) != failAt+1 || !strings.Contains(errS, process.RedactedPlaceholder) {
			t.Fatalf("failAt=%d code=%d out=%q err=%q calls=%d", failAt, code, out, errS, len(runner.calls))
		}
		for index, command := range runner.calls {
			wantArgv := append(append([]string(nil), wantPrefix...), wantQueries[index])
			if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, wantArgv) {
				t.Fatalf("failAt=%d call %d argv=%q, want %q", failAt, index, got, wantArgv)
			}
			if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) {
				t.Fatalf("failAt=%d call %d transport=%#v", failAt, index, command)
			}
			for _, form := range forms {
				if strings.Contains(out+errS, form) || strings.Contains(command.RedactedString(), form) {
					t.Fatalf("failAt=%d call %d leaked %q: out=%q err=%q command=%q", failAt, index, form, out, errS, command.RedactedString())
				}
				found := false
				for _, configured := range command.Redact {
					if configured == form {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("failAt=%d call %d inventory missing %q: %#v", failAt, index, form, command.Redact)
				}
			}
			for i := 1; i < len(command.Redact); i++ {
				if len(command.Redact[i-1]) < len(command.Redact[i]) {
					t.Fatalf("failAt=%d call %d inventory not longest-first: %#v", failAt, index, command.Redact)
				}
			}
			if index > 0 && (strings.Contains(wantQueries[index], "GRANT ") || strings.Contains(wantQueries[index], "REVOKE ")) {
				t.Fatalf("failAt=%d issued a mutation after the failing read", failAt)
			}
		}
		if !reflect.DeepEqual(args, argsBefore) {
			t.Fatalf("failAt=%d mutated CLI argument vector: before=%#v after=%#v", failAt, argsBefore, args)
		}
	}
}

func TestMySQLCLIGrantShowPrivilegesRedactionInventory(t *testing.T) {
	marker := "global'overlap"
	doubled := strings.ReplaceAll(marker, "'", "''")
	quoted := "'" + doubled + "'"
	account := quoted + "@" + quoted
	verifier := mysqlCLITestNativePasswordVerifier(marker)
	forms := []string{
		marker,
		doubled,
		quoted,
		account,
		"*.*",
		"`*`.`*`",
		verifier,
		"'" + verifier + "'",
	}
	leak := "global grant overlap " + strings.Join(forms, " ")
	config := `{"user":"global'overlap@global'overlap","database":"*.*","grant":"ALL","connection_pass":"global'overlap"}`

	for failAt := 0; failAt < 3; failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		if failAt > 0 {
			results = append(results, process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")})
		}
		if failAt > 1 {
			results = append(results, process.CommandResult{Stdout: []byte("Privilege\tContext\tComment\nSELECT\tGlobal\t\n")})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak),
			Stderr: []byte("stderr " + leak),
		})
		runner := &cliRecordingRunner{results: results}
		app := mysqlCLIRunnerApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "mysql.grant_exists", "--config", config, "-o", "json")
		if code != ExitFailed || out != "" || len(runner.calls) != failAt+1 {
			t.Fatalf("failAt=%d code=%d out=%q err=%q calls=%d", failAt, code, out, errS, len(runner.calls))
		}
		for callIndex, command := range runner.calls {
			if !strings.Contains(errS, process.RedactedPlaceholder) {
				t.Fatalf("failAt=%d call=%d redaction output=%q command=%q", failAt, callIndex, errS, command.RedactedString())
			}
			for _, form := range forms {
				if strings.Contains(out, form) || strings.Contains(errS, form) || strings.Contains(command.RedactedString(), form) {
					t.Fatalf("failAt=%d call=%d leaked %q: out=%q err=%q command=%q", failAt, callIndex, form, out, errS, command.RedactedString())
				}
				found := false
				for _, configured := range command.Redact {
					if configured == form {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("failAt=%d call=%d inventory missing %q: %#v", failAt, callIndex, form, command.Redact)
				}
			}
		}
	}
}

func mysqlCLITestNativePasswordVerifier(password string) string {
	first := sha1.Sum([]byte(password))
	second := sha1.Sum(first[:])
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

func mysqlCLIUserChpassRedactionForms(marker string) []string {
	doubled := strings.ReplaceAll(marker, "'", "''")
	quoted := "'" + doubled + "'"
	hash := "*" + marker
	hashDoubled := "*" + doubled
	hashQuoted := "'" + hashDoubled + "'"
	verifier := mysqlCLITestNativePasswordVerifier(marker)
	return []string{
		marker, doubled, quoted,
		hash, hashDoubled, hashQuoted,
		quoted + "@" + quoted,
		verifier, "'" + verifier + "'",
	}
}

func mysqlCLIUserChpassRedactionResults(failAt int, marker string) []process.CommandResult {
	successes := []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: []byte("User\tHost\n" + marker + "\t" + marker + "\n")},
		{Stdout: []byte("HasPassword\n")},
		{Stdout: []byte("User\tHost\tplugin\n" + marker + "\t" + marker + "\ted25519\n")},
		{ExitCode: 0},
		{ExitCode: 0},
	}
	forms := mysqlCLIUserChpassRedactionForms(marker)
	leak := strings.Join(forms, " ")
	results := append([]process.CommandResult(nil), successes[:failAt]...)
	return append(results, process.CommandResult{
		Err:    errors.New("phase failure " + leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	})
}

// TestMySQLCLIUserChpassRedactionPhaseMatrix covers the actual CLI decoder
// and registry at every version/account/schema/plugin preflight, mutation, and
// separate FLUSH phase. The child output streams are injected at each phase;
// the CLI-visible error and output plus every rendered command stay redacted.
func TestMySQLCLIUserChpassRedactionPhaseMatrix(t *testing.T) {
	marker := "cli'matrix"
	hash := "*" + marker
	forms := mysqlCLIUserChpassRedactionForms(marker)
	for failAt := 0; failAt < 6; failAt++ {
		t.Run(fmt.Sprintf("phase-%d", failAt), func(t *testing.T) {
			runner := &cliRecordingRunner{results: mysqlCLIUserChpassRedactionResults(failAt, marker)}
			app := mysqlCLIRunnerApp(t, runner)
			code, out, errS := captureCode(t, app, "exec", "mysql.user_chpass",
				"--user", marker, "--host", marker, "--password", marker,
				"--password-hash", hash, "--connection-user", "admin",
				"--connection-pass", marker, "-o", "json")
			if code != ExitFailed || out != "" || len(runner.calls) != failAt+1 {
				t.Fatalf("phase=%d code=%d out=%q calls=%d", failAt, code, out, len(runner.calls))
			}
			for callIndex, command := range runner.calls {
				if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) || command.Timeout <= 0 || command.MaxStdoutBytes <= 0 || command.MaxStderrBytes <= 0 {
					t.Fatalf("phase=%d call=%d unsafe transport", failAt, callIndex)
				}
				for _, form := range forms {
					if strings.Contains(strings.Join(command.Args, " "), form) {
						t.Fatal("user_chpass argv contains a credential form")
					}
					if strings.Contains(out+errS, form) || strings.Contains(command.RedactedString(), form) {
						t.Fatalf("phase=%d call=%d leaked redaction form", failAt, callIndex)
					}
					found := false
					for _, configured := range command.Redact {
						if configured == form {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("phase=%d call=%d omitted redaction form", failAt, callIndex)
					}
				}
				for index := 1; index < len(command.Redact); index++ {
					if len(command.Redact[index-1]) < len(command.Redact[index]) {
						t.Fatalf("phase=%d call=%d redaction inventory is not longest-first", failAt, callIndex)
					}
				}
			}
		})
	}
}

// TestMySQLCLIUserChpassAndVerifyLogin drives the R9.3g mutation/login names
// through the real CLI argument decoder and registry. The fake Runner is the
// only execution provider; no mysql client or database is contacted.
func TestMySQLCLIUserChpassAndVerifyLogin(t *testing.T) {
	connectionPassword := "cli-connection-pass"
	password := "cli'p%ass"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: []byte("User\tHost\ncli-user\tremote\n")},
		{Stdout: []byte("HasPassword\n")},
		{Stdout: []byte("User\tHost\tplugin\ncli-user\tremote\tcaching_sha2_password\n")},
		{ExitCode: 0},
		{ExitCode: 0},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.user_chpass",
		"--user", "cli-user", "--host", "remote", "--password", password,
		"--connection-user", "admin", "--connection-host", "db-host",
		"--connection-port", "3308", "--connection-db", "mysql",
		"--connection-pass", connectionPassword, "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 6 {
		t.Fatalf("user_chpass CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	mutation := runner.calls[4]
	if got := append([]string{mutation.Name}, mutation.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=admin", "--host=db-host", "--port=3308", "--database=mysql",
	}) {
		t.Fatalf("user_chpass CLI mutation argv=%q", got)
	}
	if string(mutation.Stdin) != "ALTER USER 'cli-user'@'remote' IDENTIFIED WITH caching_sha2_password BY 'cli''p%ass';" {
		t.Fatal("user_chpass CLI mutation stdin mismatch")
	}
	if mutation.Shell || !reflect.DeepEqual(mutation.Env, []string{"MYSQL_PWD=" + connectionPassword}) || strings.Contains(mutation.RedactedString(), password) || strings.Contains(mutation.RedactedString(), connectionPassword) {
		t.Fatalf("user_chpass CLI transport=%#v", mutation)
	}
	if strings.Contains(out+errS, password) || strings.Contains(out+errS, connectionPassword) {
		t.Fatalf("user_chpass CLI leaked credential: out=%q err=%q", out, errS)
	}

	loginPassword := "login'p%ass"
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("1\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.verify_login",
		"--user", "login-user", "--password", loginPassword,
		"--connection-user", "ignored", "--connection-host", "db-host",
		"--connection-port", "3307", "--connection-db", "maintenance", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 1 {
		t.Fatalf("verify_login CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	command := runner.calls[0]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=login-user", "--host=db-host", "--port=3307", "--database=maintenance", "--execute=SELECT 1",
	}) {
		t.Fatalf("verify_login CLI argv=%q", got)
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + loginPassword}) || command.Shell || strings.Contains(command.RedactedString(), loginPassword) {
		t.Fatalf("verify_login CLI transport=%#v", command)
	}
	if strings.Contains(out+errS, loginPassword) {
		t.Fatalf("verify_login CLI leaked password: out=%q err=%q", out, errS)
	}
}

// TestMySQLCLIUserChpassSelfPasswordSingleCommand verifies the self-password
// branch through the real argument decoder: ALTER USER and FLUSH PRIVILEGES
// share bounded stdin and one MYSQL_PWD-bearing Runner call.
func TestMySQLCLIUserChpassSelfPasswordSingleCommand(t *testing.T) {
	oldPassword := "cli-old'secret"
	newPassword := "cli-new'secret"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: []byte("User\tHost\nself-user\tlocalhost\n")},
		{Stdout: []byte("HasPassword\n")},
		{Stdout: []byte("User\tHost\tplugin\nself-user\tlocalhost\tcaching_sha2_password\n")},
		{ExitCode: 0},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.user_chpass",
		"--user", "self-user", "--password", newPassword,
		"--connection-user", "self-user", "--connection-pass", oldPassword, "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 5 {
		t.Fatalf("self user_chpass CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	command := runner.calls[4]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=self-user",
	}) {
		t.Fatalf("self user_chpass CLI argv=%q", got)
	}
	if string(command.Stdin) != "ALTER USER 'self-user'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'cli-new''secret'; FLUSH PRIVILEGES;" {
		t.Fatal("self user_chpass CLI ordered stdin mismatch")
	}
	if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + oldPassword}) || strings.Contains(command.RedactedString(), oldPassword) || strings.Contains(command.RedactedString(), newPassword) {
		t.Fatalf("self user_chpass CLI transport=%#v", command)
	}
	for _, secret := range []string{oldPassword, strings.ReplaceAll(oldPassword, "'", "''"), "'" + strings.ReplaceAll(oldPassword, "'", "''") + "'", newPassword, strings.ReplaceAll(newPassword, "'", "''"), "'" + strings.ReplaceAll(newPassword, "'", "''") + "'"} {
		found := false
		for _, configured := range command.Redact {
			if configured == secret {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("self user_chpass CLI omitted a credential redaction form")
		}
	}
	if strings.Count(string(command.Stdin), "ALTER USER") != 1 || strings.Count(string(command.Stdin), "FLUSH PRIVILEGES;") != 1 {
		t.Fatalf("self user_chpass CLI repeated a statement")
	}
}

// Applicability follows the verify_login connection-only path; account SQL,
// password_hash and native verifiers are not generated or compared here.
func TestMySQLCLIVerifyLoginRedactionMatrix(t *testing.T) {
	marker := "verify'cli-matrix"
	doubled := "verify''cli-matrix"
	first := sha1.Sum([]byte(marker))
	second := sha1.Sum(first[:])
	verifier := "*" + strings.ToUpper(hex.EncodeToString(second[:]))
	for _, tc := range []struct {
		name, form string
		applicable bool
	}{
		{"raw", marker, true}, {"doubled", doubled, true}, {"quoted", "'" + doubled + "'", true},
		{"connection", "MYSQL_PWD=" + marker, true},
		{"account-SQL-not-generated", "'login-user'@'db-host'", false},
		{"hash-not-accepted", "*unused-hash", false},
		{"native-verifier-not-derived", verifier, false},
		{"overridden-connection-password", "unused-connection-password", false},
	} {
		t.Run(fmt.Sprintf("%s/applicable=%t", tc.name, tc.applicable), func(t *testing.T) {
			result := process.CommandResult{Stdout: []byte("1\n")}
			if tc.applicable {
				result = process.CommandResult{Err: errors.New("failure " + tc.form), Stdout: []byte(tc.form), Stderr: []byte(tc.form)}
			}
			runner := &cliRecordingRunner{results: []process.CommandResult{result}}
			app := mysqlCLIRunnerApp(t, runner)
			code, out, errS := captureCode(t, app, "exec", "mysql.verify_login", "--user", "login-user", "--password", marker, "--connection-host", "db-host", "--connection-pass", "unused-connection-password", "-o", "json")
			if len(runner.calls) != 1 {
				t.Fatal("verify_login repeated connection")
			}
			command := runner.calls[0]
			if !reflect.DeepEqual(command.Args, []string{"--batch", "--user=login-user", "--host=db-host", "--execute=SELECT 1"}) || len(command.Stdin) != 0 || command.Shell {
				t.Fatal("verify_login generated non-constant SQL")
			}
			if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) {
				t.Fatal("effective credential override lost")
			}
			if !tc.applicable {
				if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || strings.Contains(strings.Join(command.Redact, " ")+strings.Join(command.Args, " ")+strings.Join(command.Env, " "), tc.form) {
					t.Fatal("inapplicable form unexpectedly generated")
				}
				return
			}
			if code != ExitFailed || out != "" {
				t.Fatal("verify_login error contract changed")
			}
			for _, surface := range []string{out, errS, command.RedactedString(), strings.Join(command.Args, " ")} {
				if strings.Contains(surface, tc.form) || strings.Contains(surface, marker) || strings.Contains(surface, doubled) {
					t.Fatal("verify_login leaked applicable credential form")
				}
			}
		})
	}
}

func TestMySQLCLIUserChpassAndVerifyLoginErrors(t *testing.T) {
	marker := "cli-error'secret"
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		Err:    errors.New("mysql failed " + marker),
		Stdout: []byte("stdout " + marker),
		Stderr: []byte("stderr " + marker),
	}}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.verify_login", "--user", "u", "--password", marker, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(errS, marker) || len(runner.calls) != 1 {
		t.Fatalf("verify_login CLI error code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{}
	app = mysqlCLIRunnerApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "mysql.user_chpass", "--user", "u", "--password", `bad\\password`, "-o", "json")
	if code != ExitFailed || strings.Contains(errS, "bad") || len(runner.calls) != 0 {
		t.Fatalf("unsafe chpass CLI code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

func TestMySQLCLIPluginStatusAndPluginsList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout: []byte("Name\tStatus\tType\tLibrary\tLicense\tLoad_option\r\n" +
			"auth_socket\tACTIVE\tAUTHENTICATION\tauth.so\tGPL\tON\r\n" +
			"daemon_example\tDISABLED\tDAEMON\tdaemon.so\tGPL\tON\r\n"),
	}}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.plugins_list",
		"--connection-user", "cli-user", "--connection-host", "cli-host",
		"--connection-port", "3307", "--connection-pass", "cli-pass",
		"--connection-db", "maintenance", "-o", "json")
	var plugins []map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &plugins) != nil || !reflect.DeepEqual(plugins, []map[string]string{
		{"name": "auth_socket", "status": "ACTIVE"},
		{"name": "daemon_example", "status": "DISABLED"},
	}) {
		t.Fatalf("plugins_list code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=cli-user", "--host=cli-host", "--port=3307",
		"--database=maintenance", "--execute=SHOW PLUGINS",
	}) || runner.calls[0].Shell || !reflect.DeepEqual(runner.calls[0].Env, []string{"MYSQL_PWD=cli-pass"}) {
		t.Fatalf("plugins_list transport=%#v argv=%q", runner.calls[0], argv)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\nauth_socket\tACTIVE\ndaemon_example\tDISABLED\n"),
	}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_status", "--name", "daemon_example",
		"--connection-pass", "cli-pass", "-o", "json")
	var status string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &status) != nil || status != "DISABLED" {
		t.Fatalf("plugin_status code=%d out=%q err=%q", code, out, errS)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--execute=" + "SELECT COALESCE(PLUGIN_NAME, UNHEX('00')) AS PLUGIN_NAME, COALESCE(PLUGIN_STATUS, UNHEX('00')) AS PLUGIN_STATUS FROM information_schema.PLUGINS",
	}) || runner.calls[0].Shell {
		t.Fatalf("plugin_status transport=%#v argv=%q", runner.calls[0], argv)
	}

	// The source compatibility shapes remain [] and "" after a nonzero
	// mysql exit; the CLI itself still exits successfully.
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("access denied")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugins_list", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "[]" {
		t.Fatalf("plugins_list nonzero code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("access denied")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_status", "--name", "missing", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != `""` {
		t.Fatalf("plugin_status nonzero code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLIPluginRowsRedactAfterDecode covers both R9.3i regressions at
// the public CLI boundary: a backslash-escaped plugin name is redacted only
// after batch decoding, and a name equal to the connection password still
// matches plugin_status. The marker is synthetic test data, never a real
// credential.
func TestMySQLCLIPluginRowsRedactAfterDecode(t *testing.T) {
	escapedSecret := "r93i\\cli-plugin"
	wireName := strings.ReplaceAll(escapedSecret, `\`, `\\`)
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout: []byte("Name\tStatus\tType\tLibrary\tLicense\tLoad_option\n" +
			wireName + "\tACTIVE\tDAEMON\tplugin.so\tGPL\tON\n"),
	}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.plugins_list",
		"--connection-pass", escapedSecret, "-o", "json")
	decodedPlugins := decodeMySQLCLIValue(t, "json", out, escapedSecret)
	if code != ExitOK || errS != "" ||
		!reflect.DeepEqual(decodedPlugins, []any{map[string]any{"name": process.RedactedPlaceholder, "status": "ACTIVE"}}) ||
		len(runner.calls) != 1 {
		t.Error("CLI plugins_list did not safely redact the decoded name")
	}
	command := runner.calls[0]
	if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + escapedSecret}) ||
		!reflect.DeepEqual(command.Redact, []string{escapedSecret}) || strings.Contains(command.RedactedString(), escapedSecret) ||
		command.Timeout != 30*time.Second || command.MaxStdoutBytes != 4<<20 || command.MaxStderrBytes != 4<<20 {
		t.Fatal("CLI plugins_list transport changed its redaction or bounds")
	}

	overlap := "r93i-cli-overlap"
	runner = &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\n" + overlap + "\tACTIVE\n"),
	}}}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.plugin_status",
		"--name", overlap, "--connection-pass", overlap, "-o", "json")
	decodedStatus := decodeMySQLCLIValue(t, "json", out, overlap)
	if code != ExitOK || errS != "" || decodedStatus != "ACTIVE" ||
		len(runner.calls) != 1 || strings.Contains(runner.calls[0].RedactedString(), overlap) {
		t.Fatal("CLI plugin_status lost a raw name match or leaked the marker")
	}
}

func TestMySQLCLIPluginMutations(t *testing.T) {
	// Absent custom plugin: the CLI exposes the source true result and the
	// exact fixed INSTALL statement without a shell or SQL interpolation path.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("PLUGIN_NAME\tPLUGIN_STATUS\n")},
		{ExitCode: 0},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.plugin_add", "--name", "cli_plugin", "--soname", "custom/cli_plugin.so",
		"--connection-user", "cli-user", "--connection-host", "cli-host", "--connection-port", "3307", "--connection-pass", "cli-pass", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 2 {
		t.Fatalf("plugin_add CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if argv := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=cli-user", "--host=cli-host", "--port=3307",
		"--execute=INSTALL PLUGIN cli_plugin SONAME \"custom/cli_plugin.so\"",
	}) || runner.calls[1].Shell || !reflect.DeepEqual(runner.calls[1].Env, []string{"MYSQL_PWD=cli-pass"}) {
		t.Fatalf("plugin_add CLI transport=%#v argv=%q", runner.calls[1], argv)
	}

	// Installed add and absent remove are idempotent and do not issue a
	// mutation command after plugin_status.
	runner = &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\ncli_plugin\tACTIVE\n"),
	}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_add", "--name", "cli_plugin", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("installed plugin_add CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\n"),
	}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_remove", "--name", "cli_plugin", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("absent plugin_remove CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	// A connection/query failure is false and never falls through to INSTALL.
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("catalog unavailable")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_add", "--name", "cli_plugin", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("query-failed plugin_add CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	for _, tc := range []struct {
		name, value string
		args        []string
	}{
		{name: "invalid name", value: "bad;DROP", args: []string{"--name", "bad;DROP"}},
		{name: "invalid soname", value: `bad"plugin.so`, args: []string{"--name", "cli_plugin", "--soname", `bad"plugin.so`}},
	} {
		runner = &cliRecordingRunner{}
		app = mysqlCLIRunnerApp(t, runner)
		cliArgs := append([]string{"exec", "mysql.plugin_add"}, tc.args...)
		cliArgs = append(cliArgs, "-o", "json")
		code, out, errS = captureCode(t, app, cliArgs...)
		if code != ExitFailed || out != "" || !strings.Contains(errS, "mysql: invalid argument") || strings.Contains(errS, tc.value) || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d out=%q err=%q calls=%d", tc.name, code, out, errS, len(runner.calls))
		}
	}

	// Runner failures from the mutation are value-free at the public CLI
	// boundary, including plugin and connection-password overlaps.
	marker := "cli_plugin_redaction"
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("PLUGIN_NAME\tPLUGIN_STATUS\n")},
		{Err: errors.New("mysql mutation failed " + marker), Stdout: []byte(marker), Stderr: []byte(marker)},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.plugin_add", "--name", marker, "--soname", marker+".so", "--connection-pass", marker, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(errS, marker) || len(runner.calls) != 2 {
		t.Fatalf("redacted plugin_add CLI code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	command := runner.calls[1]
	hasPluginSecret := false
	hasSonameSecret := false
	for _, secret := range command.Redact {
		hasPluginSecret = hasPluginSecret || secret == marker
		hasSonameSecret = hasSonameSecret || secret == marker+".so"
	}
	if command.Shell || command.Timeout != 30*time.Second || command.MaxStdoutBytes != 4<<20 || command.MaxStderrBytes != 4<<20 ||
		strings.Contains(command.RedactedString(), marker) || !hasPluginSecret || !hasSonameSecret {
		t.Fatalf("redacted plugin_add CLI transport=%#v", command)
	}
}

func mysqlCLIBatchEscape(value string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		"\x00", `\0`,
		"\t", `\t`,
		"\n", `\n`,
		"\r", `\r`,
		"\b", `\b`,
		"\x1a", `\Z`,
	).Replace(value)
}

func assertMySQLCLIValueHasNoMarker(t *testing.T, value any, marker string) {
	assertMySQLCLIValueHasNoSecrets(t, value, marker)
}

func assertMySQLCLIValueHasNoSecrets(t *testing.T, value any, markers ...string) {
	t.Helper()
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		if !v.IsValid() {
			return
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.String:
			for _, marker := range markers {
				if strings.Contains(v.String(), marker) {
					t.Fatal("serialized CLI value contains an unredacted secret form")
				}
			}
		case reflect.Map:
			if v.IsNil() {
				return
			}
			iter := v.MapRange()
			for iter.Next() {
				walk(iter.Key())
				walk(iter.Value())
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		}
	}
	walk(reflect.ValueOf(value))
}

func decodeMySQLCLIValue(t *testing.T, format, serialized, marker string) any {
	return decodeMySQLCLIValueWithSecrets(t, format, serialized, marker)
}

func decodeMySQLCLIValueWithSecrets(t *testing.T, format, serialized string, markers ...string) any {
	t.Helper()
	var value any
	var err error
	if format == "json" {
		err = json.Unmarshal([]byte(serialized), &value)
	} else {
		err = yaml.Unmarshal([]byte(serialized), &value)
	}
	if err != nil {
		t.Fatalf("CLI %s output could not be decoded", format)
	}
	assertMySQLCLIValueHasNoSecrets(t, value, markers...)
	return value
}

func assertMySQLCLIExplicitNull(t *testing.T, value any, key string) {
	t.Helper()
	rows, ok := value.([]any)
	if !ok || len(rows) != 1 {
		t.Fatal("serialized null result has an unexpected row shape")
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatal("serialized null result is not a map")
	}
	nullValue, present := row[key]
	if !present || nullValue != nil {
		t.Fatal("serialized redacted null key is absent or non-null")
	}
}

// TestMySQLCLIHeaderRedactionSerialization covers raw and batch-escaped
// headers, decoded secret values, explicit nulls, short rows, and exact
// JSON/YAML/text result shapes at every affected CLI boundary.
func TestMySQLCLIHeaderRedactionSerialization(t *testing.T) {
	marker := `fixture-marker-r93i\cli-header`
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	header := strings.Join([]string{marker, "wire-" + wireMarker, "stable-column"}, "\t")
	redacted := process.RedactedPlaceholder
	cases := []struct {
		name   string
		extra  []string
		stdout string
		want   any
		null   bool
	}{
		{
			name:   "mysql.user_list",
			stdout: header + "\n\\0\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}},
			null:   true,
		},
		{
			name:   "mysql.showvariables",
			stdout: header + "\n" + wireMarker + "\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: redacted, "wire-" + redacted: redacted}},
		},
		{
			name:   "mysql.showglobal",
			stdout: header + "\n" + wireMarker + "\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: redacted, "wire-" + redacted: redacted}},
		},
		{
			name:   "mysql.db_check",
			extra:  []string{"--name", "db", "--table", "table"},
			stdout: header + "\n\\0\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}},
			null:   true,
		},
		{
			name:   "mysql.db_repair",
			extra:  []string{"--name", "db", "--table", "table"},
			stdout: header + "\n\\0\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}},
			null:   true,
		},
		{
			name:   "mysql.db_optimize",
			extra:  []string{"--name", "db", "--table", "table"},
			stdout: header + "\n\\0\t" + wireMarker + "\n",
			want:   []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}},
			null:   true,
		},
	}
	for _, tc := range cases {
		for _, format := range []string{"json", "yaml", "text"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				runner := &cliRecordingRunner{results: []process.CommandResult{{
					ExitCode: 0,
					Stdout:   []byte(tc.stdout),
				}}}
				argv := []string{"exec", tc.name}
				argv = append(argv, tc.extra...)
				argv = append(argv, "--connection-pass", marker, "-o", format)
				code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), argv...)
				if code != ExitOK || errS != "" || len(runner.calls) != 1 {
					t.Fatal("CLI serialization call failed")
				}
				decoded := decodeMySQLCLIValue(t, format, out, marker)
				if !reflect.DeepEqual(decoded, tc.want) {
					t.Fatal("CLI serialization shape differs from the expected shape")
				}
				if tc.null {
					assertMySQLCLIExplicitNull(t, decoded, redacted)
				}
				if !reflect.DeepEqual(runner.calls[0].Redact, []string{marker}) ||
					strings.Contains(runner.calls[0].RedactedString(), marker) {
					t.Fatal("CLI serialization transport contains an unredacted marker")
				}
			})
		}
	}
}

func TestMySQLCLIHeaderCollisionIsSafe(t *testing.T) {
	marker := `fixture-marker-r93i\cli-collision`
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	for _, header := range []string{marker + "\t" + wireMarker, marker + "\t" + process.RedactedPlaceholder} {
		for _, tc := range []struct {
			name  string
			extra []string
		}{
			{"mysql.user_list", nil},
			{"mysql.showvariables", nil},
			{"mysql.showglobal", nil},
			{"mysql.db_check", []string{"--name", "db", "--table", "table"}},
			{"mysql.db_repair", []string{"--name", "db", "--table", "table"}},
			{"mysql.db_optimize", []string{"--name", "db", "--table", "table"}},
		} {
			for _, format := range []string{"json", "yaml", "text"} {
				t.Run(tc.name+"/"+format, func(t *testing.T) {
					runner := &cliRecordingRunner{results: []process.CommandResult{{
						Stdout: []byte(header + "\nfirst\tsecond\n"),
					}}}
					argv := []string{"exec", tc.name}
					argv = append(argv, tc.extra...)
					argv = append(argv, "--connection-pass", marker, "-o", format)
					code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), argv...)
					if code != ExitFailed || out != "" || strings.TrimSpace(errS) != "statekit: mysql: redacted result header collision" || len(runner.calls) != 1 {
						t.Fatal("CLI header collision did not fail with the stable value-free error")
					}
				})
			}
		}
	}
}

// TestMySQLCLIDatabaseMutations drives mysql.db_create and mysql.db_remove
// through argument decoding, registry dispatch, and the value-free output
// boundary using only a fake Runner.
func TestMySQLCLIDatabaseMutations(t *testing.T) {
	connectionPassword := "cli-db-connection-pass"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
		{ExitCode: 0},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "mysql.db_create",
		"--name", "cli_db", "--character-set", "utf8mb4", "--collate", "utf8mb4_0900_ai_ci",
		"--connection-user", "admin", "--connection-host", "mysql-host", "--connection-port", "3307",
		"--connection-db", "mysql", "--connection-pass", connectionPassword, "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 2 {
		t.Fatalf("db_create code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=admin", "--host=mysql-host", "--port=3307", "--database=mysql",
		"--execute=CREATE DATABASE IF NOT EXISTS `cli_db` CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_0900_ai_ci';",
	}) {
		t.Fatalf("db_create argv=%q", got)
	}
	if !reflect.DeepEqual(runner.calls[1].Env, []string{"MYSQL_PWD=" + connectionPassword}) ||
		runner.calls[1].Shell || strings.Contains(runner.calls[1].RedactedString(), connectionPassword) {
		t.Fatalf("db_create unsafe transport=%#v", runner.calls[1])
	}

	// Identifier wildcard bytes stay literal and optional values use the same
	// SQL-literal escaping as the pinned MySQLdb parameter path.
	characterSet := "utf'\\%"
	collate := "ci'\\_"
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nother\n")},
		{ExitCode: 0},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_create",
		"--name", "db`%_", "--character-set", characterSet, "--collate", collate, "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 2 {
		t.Fatalf("quoted db_create code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=CREATE DATABASE IF NOT EXISTS `db``%_` CHARACTER SET 'utf''\\\\%' COLLATE 'ci''\\\\_';" {
		t.Fatalf("quoted db_create SQL=%q", got)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ncli_db\n")},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_remove", "--name", "cli_db",
		"--connection-user", "admin", "--connection-host", "mysql-host", "--connection-port", "3307",
		"--connection-db", "mysql", "--connection-pass", connectionPassword, "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 3 {
		t.Fatalf("db_remove code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=admin", "--host=mysql-host", "--port=3307", "--database=mysql",
		"--execute=DROP DATABASE `cli_db`;",
	}) {
		t.Fatalf("db_remove argv=%q", got)
	}

	// A successful DROP followed by a nonzero compatibility post-check is the
	// source public true result: db_exists is false, but db_remove has already
	// completed the mutation and returns not db_exists.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ncli_db\n")},
		{ExitCode: 0},
		{ExitCode: 1, Stderr: []byte("post-check unavailable")},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_remove", "--name", "cli_db", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" || len(runner.calls) != 3 {
		t.Fatalf("post-check failure db_remove code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	// Existing create and missing remove are source false/no-op results, not
	// errors, and never issue the mutation statement.
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ncli_db\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_create", "--name", "cli_db", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("existing db_create code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")}}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_remove", "--name", "cli_db", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("missing db_remove code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	// A failed existence preflight is an unknown absence and must not fall
	// through to CREATE, even when a queued second result would succeed.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("catalog unavailable")},
		{ExitCode: 0},
	}}
	app = mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.db_create", "--name", "uncertain_db", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 1 {
		t.Fatalf("failed preflight db_create code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}

func TestMySQLCLIDatabaseMutationValidation(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", "bad\nname", "bad\x01name", "bad\x7fname"} {
		runner := &cliRecordingRunner{}
		code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_create",
			"--name", name, "-o", "json")
		if (code != ExitFailed && code != ExitInvalidInput) || out != "" || len(runner.calls) != 0 {
			t.Fatalf("invalid create name %q code=%d out=%q err=%q calls=%d", name, code, out, errS, len(runner.calls))
		}
		if name != "" && !strings.Contains(errS, "mysql: invalid argument") {
			t.Fatalf("invalid create name %q error=%q", name, errS)
		}
	}
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_remove",
		"--name", "db", "--runas", "other", "-o", "json")
	if code != ExitFailed || out != "" || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas db_remove code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, &cliRecordingRunner{}), "exec", "mysql.db_create", "-o", "json")
	if code != ExitInvalidInput || out != "" || !strings.Contains(errS, "missing required argument") {
		t.Fatalf("missing db_create name code=%d out=%q err=%q", code, out, errS)
	}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, &cliRecordingRunner{}), "exec", "mysql.db_remove", "-o", "json")
	if code != ExitInvalidInput || out != "" || !strings.Contains(errS, "missing required argument") {
		t.Fatalf("missing db_remove name code=%d out=%q err=%q", code, out, errS)
	}

	for _, flag := range []string{"--character-set", "--collate"} {
		runner = &cliRecordingRunner{}
		code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_create",
			"--name", "db", flag, "bad\noption", "-o", "json")
		if code != ExitFailed || out != "" || !strings.Contains(errS, "mysql: invalid argument") || strings.Contains(errS, "bad") || len(runner.calls) != 0 {
			t.Fatalf("invalid %s code=%d out=%q err=%q calls=%d", flag, code, out, errS, len(runner.calls))
		}
	}
}

// TestMySQLCLIDatabaseMutationPhaseFailures covers lifecycle timeout and
// output-limit failures at the mutation/post-check boundaries and checks the
// shared finite timeout/output transport on every attempted command.
func TestMySQLCLIDatabaseMutationPhaseFailures(t *testing.T) {
	cases := []struct {
		name    string
		command string
		results []process.CommandResult
		calls   int
	}{
		{
			name:    "create-mutation-timeout",
			command: "mysql.db_create",
			results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")}, {Err: context.DeadlineExceeded}},
			calls:   2,
		},
		{
			name:    "remove-mutation-output",
			command: "mysql.db_remove",
			results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {StdoutTruncated: true}},
			calls:   2,
		},
		{
			name:    "remove-postcheck-timeout",
			command: "mysql.db_remove",
			results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {ExitCode: 0}, {Err: context.DeadlineExceeded}},
			calls:   3,
		},
		{
			name:    "remove-postcheck-output",
			command: "mysql.db_remove",
			results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {ExitCode: 0}, {StderrTruncated: true}},
			calls:   3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			args := []string{"exec", tc.command, "--name", "db", "-o", "json"}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), args...)
			if code != ExitFailed || out != "" || errS == "" || len(runner.calls) != tc.calls {
				t.Fatalf("code=%d out=%q err=%q calls=%d; want failure and %d calls", code, out, errS, len(runner.calls), tc.calls)
			}
			for i, command := range runner.calls {
				if command.Shell || command.Timeout != 30*time.Second || command.MaxStdoutBytes != 4<<20 || command.MaxStderrBytes != 4<<20 {
					t.Fatalf("call %d transport=%#v", i, command)
				}
			}
		})
	}

	marker := "cli-db-phase-secret"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")},
		{ExitCode: 0},
		{Err: errors.New("post-check failed with " + marker), Stdout: []byte(marker), Stderr: []byte(marker)},
	}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.db_remove", "--name", "db", "--connection-pass", marker, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(out+errS, marker) || len(runner.calls) != 3 {
		t.Fatalf("post-check redaction code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	redacted := false
	for _, secret := range runner.calls[2].Redact {
		if secret == marker {
			redacted = true
			break
		}
	}
	if !redacted || strings.Contains(runner.calls[2].RedactedString(), marker) {
		t.Fatalf("post-check redaction transport=%#v", runner.calls[2])
	}
}

// TestMySQLCLIAlterDatabase drives mysql.alter_db through flag decoding and
// registry dispatch. The first fake call is the db_get default read and the
// second is the fixed ALTER DATABASE mutation; no real client is used.
func TestMySQLCLIAlterDatabase(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ncli_alter\tlatin1\tlatin1_swedish_ci\n")},
		{ExitCode: 0},
	}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db",
		"--name", "cli_alter", "--character-set", "utf8mb4", "--collate", "utf8mb4_0900_ai_ci",
		"--connection-user", "admin", "--connection-host", "mysql-host", "--connection-port", "3307",
		"--connection-db", "mysql", "--connection-pass", "cli-alter-pass", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 2 {
		t.Fatalf("alter_db code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=admin", "--host=mysql-host", "--port=3307", "--database=mysql",
		"--execute=ALTER DATABASE `cli_alter` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;",
	}) {
		t.Fatalf("alter_db argv=%q", got)
	}
	for _, command := range runner.calls {
		if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=cli-alter-pass"}) ||
			strings.Contains(command.RedactedString(), "cli-alter-pass") {
			t.Fatalf("alter_db unsafe transport=%#v", command)
		}
	}

	// A single explicit option keeps the other catalog default, matching the
	// source's truthy `or existing.get(...)` expressions.
	for _, tc := range []struct {
		name      string
		option    string
		value     string
		statement string
	}{
		{name: "explicit charset", option: "--character-set", value: "utf8mb4", statement: "ALTER DATABASE `cli_alter` CHARACTER SET utf8mb4 COLLATE latin1_swedish_ci;"},
		{name: "explicit collate", option: "--collate", value: "utf8mb4_0900_ai_ci", statement: "ALTER DATABASE `cli_alter` CHARACTER SET latin1 COLLATE utf8mb4_0900_ai_ci;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ncli_alter\tlatin1\tlatin1_swedish_ci\n")},
				{ExitCode: 0},
			}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db",
				"--name", "cli_alter", tc.option, tc.value, "-o", "json")
			if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" || len(runner.calls) != 2 ||
				runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute="+tc.statement {
				t.Fatalf("partial %s code=%d out=%q err=%q calls=%d argv=%#v", tc.name, code, out, errS, len(runner.calls), runner.calls)
			}
		})
	}

	// Omitted options use db_get defaults, and an ALTER rejection remains the
	// pinned false compatibility result.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ncli_alter\tutf8\tutf8_general_ci\n")},
		{ExitCode: 1, Stderr: []byte("rejected")},
	}}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db", "--name", "cli_alter", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "false" || errS != "" || len(runner.calls) != 2 {
		t.Fatalf("default-preserving alter_db code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=ALTER DATABASE `cli_alter` CHARACTER SET utf8 COLLATE utf8_general_ci;" {
		t.Fatalf("default-preserving SQL=%q", got)
	}

	for _, option := range []string{"--character-set", "--collate"} {
		runner = &cliRecordingRunner{}
		code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db",
			"--name", "cli_alter", option, "utf8;DROP", "-o", "json")
		if code != ExitFailed || out != "" || !strings.Contains(errS, "mysql: invalid argument") ||
			strings.Contains(errS, "utf8;DROP") || len(runner.calls) != 0 {
			t.Fatalf("invalid %s code=%d out=%q err=%q calls=%d", option, code, out, errS, len(runner.calls))
		}
	}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, &cliRecordingRunner{}), "exec", "mysql.alter_db", "-o", "json")
	if code != ExitInvalidInput || out != "" || !strings.Contains(errS, "missing required argument") {
		t.Fatalf("missing alter_db name code=%d out=%q err=%q", code, out, errS)
	}
}

func TestMySQLCLIAlterDatabaseRedaction(t *testing.T) {
	marker := "cli_alter_secret"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")},
		{Err: errors.New("alter failed " + marker), Stdout: []byte(marker), Stderr: []byte(marker)},
	}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db",
		"--name", "db", "--character-set", marker, "-o", "json")
	if code != ExitFailed || out != "" || strings.Contains(out+errS, marker) || len(runner.calls) != 2 {
		t.Fatalf("alter_db redaction code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
	if strings.Contains(runner.calls[1].RedactedString(), marker) {
		t.Fatalf("alter_db command leaks marker: %q", runner.calls[1].RedactedString())
	}
}

// TestMySQLCLIAlterDatabaseSourceShapes documents the distinction between a
// successful rowless db_get ({}), which can still support two explicit source
// values, and a failed db_get ([]), which is returned without mutation.
func TestMySQLCLIAlterDatabaseSourceShapes(t *testing.T) {
	missingCatalog := "SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\nother\tutf8\tutf8_general_ci\n"
	for _, tc := range []struct {
		name    string
		args    []string
		results []process.CommandResult
		code    int
		output  string
		calls   int
		wantSQL string
		caller  string
	}{
		{
			name:    "missing catalog no options fails before alter",
			args:    []string{"--name", "missing", "-o", "json"},
			results: []process.CommandResult{{Stdout: []byte(missingCatalog)}},
			code:    ExitFailed,
			calls:   1,
			caller:  "missing",
		},
		{
			name:    "missing catalog partial option fails before alter",
			args:    []string{"--name", "missing", "--character-set", "utf8mb4", "-o", "json"},
			results: []process.CommandResult{{Stdout: []byte(missingCatalog)}},
			code:    ExitFailed,
			calls:   1,
			caller:  "missing",
		},
		{
			name:    "missing catalog explicit pair follows source bypass",
			args:    []string{"--name", "missing", "--character-set", "utf8mb4", "--collate", "utf8mb4_0900_ai_ci", "-o", "json"},
			results: []process.CommandResult{{Stdout: []byte(missingCatalog)}, {ExitCode: 0}},
			code:    ExitOK,
			output:  "true",
			calls:   2,
			wantSQL: "--execute=ALTER DATABASE `missing` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;",
		},
		{
			name:    "failed catalog explicit pair is returned without alter",
			args:    []string{"--name", "db", "--character-set", "utf8mb4", "--collate", "utf8mb4_0900_ai_ci", "-o", "json"},
			results: []process.CommandResult{{ExitCode: 1, Stderr: []byte("catalog denied")}, {ExitCode: 0}},
			code:    ExitOK,
			output:  "[]",
			calls:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), append([]string{"exec", "mysql.alter_db"}, tc.args...)...)
			if code != tc.code || strings.TrimSpace(out) != tc.output || len(runner.calls) != tc.calls {
				t.Fatalf("code=%d out=%q err=%q calls=%d; want code=%d out=%q calls=%d", code, out, errS, len(runner.calls), tc.code, tc.output, tc.calls)
			}
			if tc.caller != "" && strings.Contains(errS, tc.caller) {
				// The stable error names the fixed argument key, not the caller's
				// database value.
				t.Fatalf("source shape error contains caller value: %q", errS)
			}
			if tc.wantSQL != "" && runner.calls[1].Args[len(runner.calls[1].Args)-1] != tc.wantSQL {
				t.Fatalf("statement=%q, want %q", runner.calls[1].Args[len(runner.calls[1].Args)-1], tc.wantSQL)
			}
		})
	}
}

// TestMySQLCLIAlterDatabaseNativeResultVectors pins the CLI-visible truthy
// and falsy process results separately from the unobservable DB-API
// cursor.execute return value in the pinned Salt implementation.
func TestMySQLCLIAlterDatabaseNativeResultVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   string
	}{
		{name: "process success", result: process.CommandResult{ExitCode: 0}, want: "true"},
		{name: "process rejection", result: process.CommandResult{ExitCode: 1}, want: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")},
				tc.result,
			}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db", "--name", "db", "-o", "json")
			if code != ExitOK || strings.TrimSpace(out) != tc.want || errS != "" || len(runner.calls) != 2 {
				t.Fatalf("native result code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
		})
	}
}

// TestMySQLCLIAlterDatabasePhaseFailures keeps timeout/output errors fail
// closed at both the db_get preflight and ALTER phases, and checks the
// connection credential redaction on a failed preflight.
func TestMySQLCLIAlterDatabasePhaseFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []process.CommandResult
		calls   int
	}{
		{name: "preflight-timeout", results: []process.CommandResult{{Err: context.DeadlineExceeded}}, calls: 1},
		{name: "preflight-output", results: []process.CommandResult{{StdoutTruncated: true}}, calls: 1},
		{name: "mutation-timeout", results: []process.CommandResult{{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")}, {Err: context.DeadlineExceeded}}, calls: 2},
		{name: "mutation-output", results: []process.CommandResult{{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")}, {StdoutTruncated: true}}, calls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db", "--name", "db", "-o", "json")
			if code != ExitFailed || out != "" || errS == "" || len(runner.calls) != tc.calls {
				t.Fatalf("phase code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
			for i, command := range runner.calls {
				if command.Shell || command.Timeout != 30*time.Second || command.MaxStdoutBytes != 4<<20 || command.MaxStderrBytes != 4<<20 {
					t.Fatalf("phase %s call %d transport=%#v", tc.name, i, command)
				}
			}
		})
	}

	marker := "cli-alter-preflight-secret"
	runner := &cliRecordingRunner{results: []process.CommandResult{{
		Err:    errors.New("db_get failed " + marker),
		Stdout: []byte(marker),
		Stderr: []byte(marker),
	}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.alter_db", "--name", "db", "--connection-pass", marker, "-o", "json")
	found := false
	if len(runner.calls) == 1 {
		for _, secret := range runner.calls[0].Redact {
			if secret == marker {
				found = true
				break
			}
		}
	}
	if code != ExitFailed || out != "" || strings.Contains(out+errS, marker) || len(runner.calls) != 1 ||
		strings.Contains(runner.calls[0].RedactedString(), marker) || !found {
		t.Fatalf("preflight redaction code=%d out=%q err=%q calls=%d command=%q redact=%q", code, out, errS, len(runner.calls), runner.calls[0].RedactedString(), runner.calls[0].Redact)
	}
}

// TestMySQLCLIProcessAndReplicationStatus drives the newly registered SHOW
// readers through the production CLI decoder with a fake Runner only. It pins
// the fixed SQL, JSON shapes, native numeric conversion, and value-free
// connection transport.
func TestMySQLCLIProcessAndReplicationStatus(t *testing.T) {
	marker := "cli-status-secret"
	processOutput := "Id\tUser\tHost\tCommand\tTime\tState\tInfo\n" +
		"7\troot\tlocalhost\tQuery\t0\tNULL\t" + marker + "\n"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(processOutput)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.processlist",
		"--connection-user", "test_user", "--connection-host", "test_host",
		"--connection-port", "3306", "--connection-pass", marker, "-o", "json")
	var processes []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &processes) != nil ||
		!reflect.DeepEqual(processes, []map[string]any{{
			"Id": float64(7), "User": "root", "Host": "localhost", "Command": "Query",
			"Time": float64(0), "State": nil, "Info": "***REDACTED***",
		}}) || strings.Contains(out+errS, marker) {
		t.Fatalf("processlist code=%d out=%q err=%q value=%#v", code, out, errS, processes)
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=3306",
		"--execute=SHOW FULL PROCESSLIST",
	}) {
		t.Fatalf("processlist argv=%#v", got)
	}
	if runner.calls[0].Shell || runner.calls[0].Timeout != 30*time.Second ||
		runner.calls[0].MaxStdoutBytes != 4<<20 || runner.calls[0].MaxStderrBytes != 4<<20 ||
		!reflect.DeepEqual(runner.calls[0].Env, []string{"MYSQL_PWD=" + marker}) ||
		!reflect.DeepEqual(runner.calls[0].Redact, []string{marker}) ||
		strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("processlist transport=%#v", runner.calls[0])
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("File\tPosition\nmysql-bin.000001\t42\n")},
		{Stdout: []byte("Master_Port\tSeconds_Behind_Master\n")},
	}}
	app := mysqlCLIRunnerApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "mysql.get_master_status", "-o", "json")
	var master map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &master) != nil ||
		!reflect.DeepEqual(master, map[string]any{"File": "mysql-bin.000001", "Position": float64(42)}) {
		t.Fatalf("master status code=%d out=%q err=%q value=%#v", code, out, errS, master)
	}
	code, out, errS = captureCode(t, app, "exec", "mysql.get_slave_status", "-o", "json")
	var slave []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &slave) != nil || len(slave) != 0 {
		t.Fatalf("slave status empty code=%d out=%q err=%q value=%#v", code, out, errS, slave)
	}
	if len(runner.calls) != 2 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SHOW MASTER STATUS" ||
		runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute=SHOW SLAVE STATUS" {
		t.Fatalf("status argv=%#v", runner.calls)
	}
}

// TestMySQLCLIProcessAndReplicationStatusNullRedactionOverlap verifies the
// public CLI boundary: native SHOW NULL is classified before a password equal
// to the client's NULL marker is redacted, while an ordinary overlapping value
// is still redacted.
func TestMySQLCLIProcessAndReplicationStatusNullRedactionOverlap(t *testing.T) {
	marker := "NULL"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"Id\tState\tInfo\n1\tNULL\tquery-NULL-tail\n",
	)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.processlist",
		"--connection-pass", marker, "-o", "json")
	var processes []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &processes) != nil ||
		!reflect.DeepEqual(processes, []map[string]any{{
			"Id": float64(1), "State": nil, "Info": "query-***REDACTED***-tail",
		}}) || strings.Contains(out+errS, marker) {
		t.Fatalf("NULL-overlap processlist code=%d out=%q err=%q value=%#v", code, out, errS, processes)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].Redact, []string{marker}) ||
		strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("NULL-overlap transport=%#v", runner.calls)
	}
}

// TestMySQLCLIProcessAndReplicationStatusShortRow documents the intentional
// defensive divergence from Salt's IndexError on malformed short SHOW rows.
func TestMySQLCLIProcessAndReplicationStatusShortRow(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"Id\tInfo\n39\n",
	)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.processlist", "-o", "json")
	var processes []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &processes) != nil ||
		!reflect.DeepEqual(processes, []map[string]any{{"Id": float64(39)}}) {
		t.Fatalf("short-row processlist code=%d out=%q err=%q value=%#v", code, out, errS, processes)
	}
}

// TestMySQLCLIProcessAndReplicationStatusFailures pins the CLI transport's
// empty shape for every nonzero exit and the shared bounded failures. A native
// mysql exit cannot identify whether the source failed at connection or query
// time; for processlist, mapping both to [] is an intentional defensive
// divergence from the connected query-error exception branch.
func TestMySQLCLIProcessAndReplicationStatusFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		function string
		result   process.CommandResult
		want     string
	}{
		{name: "process-nonzero-transport", function: "mysql.processlist", result: process.CommandResult{ExitCode: 1}, want: "[]"},
		{name: "master-nonzero-transport", function: "mysql.get_master_status", result: process.CommandResult{ExitCode: 1}, want: "[]"},
		{name: "slave-nonzero-transport", function: "mysql.get_slave_status", result: process.CommandResult{ExitCode: 1}, want: "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{tc.result}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", tc.function, "-o", "json")
			if code != ExitOK || errS != "" || strings.TrimSpace(out) != tc.want || len(runner.calls) != 1 {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
		})
	}

	for _, tc := range []struct {
		name     string
		function string
	}{
		{name: "process-limit", function: "mysql.processlist"},
		{name: "master-limit", function: "mysql.get_master_status"},
		{name: "slave-timeout", function: "mysql.get_slave_status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := process.CommandResult{}
			if strings.Contains(tc.name, "limit") {
				result.StdoutTruncated = true
			} else {
				result.Err = context.DeadlineExceeded
			}
			runner := &cliRecordingRunner{results: []process.CommandResult{result}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", tc.function, "-o", "json")
			if code != ExitFailed || out != "" || errS == "" || len(runner.calls) != 1 {
				t.Fatalf("bounded code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
			if runner.calls[0].Timeout != 30*time.Second || runner.calls[0].MaxStdoutBytes != 4<<20 || runner.calls[0].MaxStderrBytes != 4<<20 {
				t.Fatalf("bounded transport=%#v", runner.calls[0])
			}
		})
	}
}

// TestMySQLCLISlaveLagSourceVectors drives the newly registered scalar through
// the production argument decoder and JSON renderer. It pins the exact native
// SHOW statement, the -1/-2/-3 Salt-compatible values, NULL, malformed-row
// failure, and the numeric JSON shape without a live database.
func TestMySQLCLISlaveLagSourceVectors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		result     process.CommandResult
		wantCode   int
		wantOutput string
		password   string
	}{
		{name: "numeric", result: process.CommandResult{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\nYes\t37\n")}, wantCode: ExitOK, wantOutput: "37"},
		{name: "null", result: process.CommandResult{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\nYes\tNULL\n")}, wantCode: ExitOK, wantOutput: "null", password: "NULL"},
		{name: "no-row", result: process.CommandResult{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\n")}, wantCode: ExitOK, wantOutput: "-1"},
		{name: "broken-io", result: process.CommandResult{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\nNo\t37\n")}, wantCode: ExitOK, wantOutput: "-2"},
		{name: "unsupported-query", result: process.CommandResult{ExitCode: 1, Stderr: []byte("ERROR 1064 (42000): SHOW SLAVE STATUS is unsupported\n")}, wantCode: ExitOK, wantOutput: "-3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{tc.result}}
			args := []string{"exec", "mysql.slave_lag"}
			if tc.password != "" {
				args = append(args, "--connection-pass", tc.password)
			}
			args = append(args, "-o", "json")
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), args...)
			if code != tc.wantCode || strings.TrimSpace(out) != tc.wantOutput || errS != "" || len(runner.calls) != 1 {
				t.Fatalf("slave_lag %s code=%d out=%q err=%q calls=%d", tc.name, code, out, errS, len(runner.calls))
			}
			if runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SHOW SLAVE STATUS" || runner.calls[0].Shell || runner.calls[0].Timeout != 30*time.Second || runner.calls[0].MaxStdoutBytes != 4<<20 || runner.calls[0].MaxStderrBytes != 4<<20 {
				t.Fatalf("slave_lag %s transport=%#v", tc.name, runner.calls[0])
			}
		})
	}

	marker := "42"
	runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"Slave_IO_Running\tSeconds_Behind_Master\nYes\t" + marker + "\n",
	)}}}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.slave_lag", "--connection-pass", marker, "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != `"***REDACTED***"` || errS != "" || strings.Contains(out+errS, marker) || strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("slave_lag numeric redaction code=%d out=%q err=%q calls=%#v", code, out, errS, runner.calls)
	}

	for _, tc := range []struct {
		name string
		lag  string
	}{
		{name: "malformed-secret-overlap", lag: "not-a-number"},
		{name: "overflow-secret-overlap", lag: "9223372036854775808"},
		{name: "underflow-secret-overlap", lag: "-9223372036854775809"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
				"Slave_IO_Running\tSeconds_Behind_Master\nYes\t" + tc.lag + "\n",
			)}}}
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.slave_lag", "--connection-pass", tc.lag, "-o", "json")
			if code != ExitFailed || out != "" || errS == "" || strings.Contains(out+errS, tc.lag) || len(runner.calls) != 1 {
				t.Fatalf("secret-overlap slave_lag %s code=%d out=%q err=%q calls=%d", tc.name, code, out, errS, len(runner.calls))
			}
			if strings.Contains(runner.calls[0].RedactedString(), tc.lag) || !reflect.DeepEqual(runner.calls[0].Redact, []string{tc.lag}) {
				t.Fatalf("secret-overlap transport %s = %#v", tc.name, runner.calls[0])
			}
		})
	}

	// Required columns and the numeric field are value-free execution errors,
	// never a fabricated lag or a panic through the CLI renderer.
	runner = &cliRecordingRunner{results: []process.CommandResult{{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\nYes\n")}}}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.slave_lag", "-o", "json")
	if code != ExitFailed || out != "" || errS == "" || strings.Contains(errS, "Yes") {
		t.Fatalf("slave_lag short row code=%d out=%q err=%q", code, out, errS)
	}
}

// TestMySQLCLISlaveLagBoundedFailures pins timeout/output-limit behavior on
// the direct CLI surface and keeps the return stream value-free.
func TestMySQLCLISlaveLagBoundedFailures(t *testing.T) {
	for _, result := range []process.CommandResult{
		{Err: context.DeadlineExceeded},
		{StdoutTruncated: true},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{result}}
		code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), "exec", "mysql.slave_lag", "-o", "json")
		if code != ExitFailed || out != "" || errS == "" || len(runner.calls) != 1 {
			t.Fatalf("slave_lag bounded code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
		}
		if runner.calls[0].Timeout != 30*time.Second || runner.calls[0].MaxStdoutBytes != 4<<20 || runner.calls[0].MaxStderrBytes != 4<<20 || runner.calls[0].Shell {
			t.Fatalf("slave_lag bounded transport=%#v", runner.calls[0])
		}
	}
}

// TestMySQLCLIFreeSlaveR93R02NoRunner drives the guarded compatibility surface
// through argument decoding and JSON rendering. Unsupported and status-shaped
// native outputs are deliberately queued but must not be consumed.
func TestMySQLCLIFreeSlaveR93R02NoRunner(t *testing.T) {
	secret := "free-slave-cli-secret"
	cases := []struct {
		name    string
		args    []string
		results []process.CommandResult
	}{
		{
			name: "unsupported-status",
			results: []process.CommandResult{{
				ExitCode: 1,
				Stderr:   []byte("ERROR 1064 (42000): SHOW SLAVE STATUS"),
			}},
		},
		{
			name: "malformed-status",
			results: []process.CommandResult{{
				Stdout: []byte("Master_Host\n" + secret + "\n"),
			}},
		},
		{
			name: "partial-topology",
			args: []string{
				"--connection-host", "replica.example",
				"--connection-pass", secret,
			},
			results: []process.CommandResult{{Stdout: []byte("Master_Host\nmaster.example\n")}},
		},
		{
			name: "no-topology",
			args: []string{"--connection-pass", secret},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			argv := append([]string{"exec", "mysql.free_slave"}, tc.args...)
			argv = append(argv, "-o", "json")
			code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner), argv...)
			if code != ExitOK || strings.TrimSpace(out) != `""` || errS != "" || len(runner.calls) != 0 {
				t.Fatalf("free_slave %s code=%d out=%q err=%q calls=%d", tc.name, code, out, errS, len(runner.calls))
			}
			if strings.Contains(out+errS, secret) {
				t.Fatalf("free_slave %s leaked secret: out=%q err=%q", tc.name, out, errS)
			}
		})
	}
}

func TestMySQLCLIFreeSlaveR93R03MalformedDiagnostic(t *testing.T) {
	secret := "free-slave-cli-invalid-secret"
	runner := &cliRecordingRunner{}
	code, out, errS := captureCode(t, mysqlCLIRunnerApp(t, runner),
		"exec", "mysql.free_slave", "--connection-host", secret+"\n",
		"--connection-pass", secret, "-o", "json")
	if code != ExitFailed || out != "" || len(runner.calls) != 0 || strings.Contains(errS, secret) ||
		!strings.Contains(errS, "mysql: invalid argument") {
		t.Fatalf("free_slave malformed code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}

	runner = &cliRecordingRunner{}
	code, out, errS = captureCode(t, mysqlCLIRunnerApp(t, runner),
		"exec", "mysql.free_slave", "--runas", secret, "-o", "json")
	if code != ExitFailed || out != "" || len(runner.calls) != 0 || strings.Contains(errS, secret) ||
		!strings.Contains(errS, "runas") {
		t.Fatalf("free_slave runas code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
	}
}
