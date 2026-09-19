package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// pureRT is deliberately nil: the R9.2a mysql slice must not touch the
// runtime, its Runner, or its filesystem.
func callQuote(t *testing.T, identifier string, forGrants bool) (string, error) {
	t.Helper()
	value, err := (quoteIdentifierFunc{}).Execute(context.Background(), nil,
		&QuoteIdentifierArgs{Identifier: identifier, ForGrants: forGrants})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

// TestQuoteIdentifierVectors pins salt/modules/mysql.py:692-721 replacement
// order (backtick doubling, then _ for grants, then % doubling) with
// source-derived expected strings.
func TestQuoteIdentifierVectors(t *testing.T) {
	cases := []struct {
		identifier string
		forGrants  bool
		want       string
	}{
		{"foo`bar", false, "`foo``bar`"},
		{"foo`bar", true, "`foo``bar`"},
		{"my_%db`x", false, "`my_%%db``x`"},
		{"my_%db`x", true, "`my\\_%%db``x`"},
		{"", false, "``"},
		{"", true, "``"},
		{"plain", false, "`plain`"},
		{"a_b%c`d`e", true, "`a\\_b%%c``d``e`"},
		{"ALL", false, "`ALL`"},
		{"ün_ï`", true, "`ün\\_ï```"},
	}
	for _, tc := range cases {
		got, err := callQuote(t, tc.identifier, tc.forGrants)
		if err != nil {
			t.Fatalf("quote_identifier(%q, %v): %v", tc.identifier, tc.forGrants, err)
		}
		if got != tc.want {
			t.Errorf("quote_identifier(%q, %v) = %q, want %q", tc.identifier, tc.forGrants, got, tc.want)
		}
	}
}

// TestQuoteIdentifierCLIExample is the docstring CLI vector
// salt '*' mysql.quote_identifier 'foo`bar'.
func TestQuoteIdentifierCLIExample(t *testing.T) {
	got, err := callQuote(t, "foo`bar", false)
	if err != nil || got != "`foo``bar`" {
		t.Fatalf("docstring vector = %q, %v", got, err)
	}
}

func callTokenize(t *testing.T, grant string) (map[string]any, error) {
	t.Helper()
	value, err := (tokenizeGrantFunc{}).Execute(context.Background(), nil, &TokenizeGrantArgs{Grant: grant})
	if err != nil {
		return nil, err
	}
	mapped, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("tokenize_grant returned %T", value)
	}
	return mapped, nil
}

func tokens(user, host string, grant []string, database string) map[string]any {
	if grant == nil {
		grant = []string{}
	}
	return map[string]any{"user": user, "host": host, "grant": grant, "database": database}
}

// TestTokenizeGrantVectors pins the exact pinned-source output shapes,
// including the docstring examples, ALL/GRANT OPTION forms, column lists,
// quoted user-host forms, backtick doubling, and the degenerate shapes.
func TestTokenizeGrantVectors(t *testing.T) {
	cases := []struct {
		name  string
		grant string
		want  map[string]any
	}{
		{"cli-docstring",
			"GRANT SELECT, INSERT ON testdb.* TO 'testuser'@'localhost'",
			tokens("testuser", "localhost", []string{"SELECT", "INSERT"}, "testdb.*")},
		{"docstring-backtick-doubling",
			"GRANT SELECT, LOCK TABLES, UPDATE, CREATE ON `test ``(:=saltdb)`.* TO 'foo'@'localhost' WITH GRANT OPTION",
			tokens("foo", "localhost", []string{"SELECT", "LOCK TABLES", "UPDATE", "CREATE"}, "`test ``(:=saltdb)`.*")},
		{"docstring-spaces-and-quotes",
			"GRANT SELECT, INSERT, UPDATE, CREATE ON `te s.t'\"sa;ltdb`.`tbl ``'\"xx` TO 'foo ' bar'@'localhost'",
			tokens("foo 'bar", "localhost", []string{"SELECT", "INSERT", "UPDATE", "CREATE"}, "`te s.t'\"sa;ltdb`.`tbl ``'\"xx`")},
		{"docstring-shell-hostile-user",
			"GRANT USAGE ON *.* TO 'user \";--,?:&/\\'@'localhost'",
			tokens(`user ";--,?:&/\`, "localhost", []string{"USAGE"}, "*.*")},
		{"all-privileges-with-grant-option",
			"GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION",
			tokens("root", "localhost", []string{"ALL PRIVILEGES"}, "*.*")},
		{"all-on-database",
			"GRANT ALL ON `mydb`.* TO 'u'@'h'",
			tokens("u", "h", []string{"ALL"}, "`mydb`.*")},
		{"proxy-concatenates-everything-after-on",
			"GRANT PROXY ON 'user'@'%' TO 'relay'@'%' WITH GRANT OPTION",
			tokens("", "", []string{"PROXY"}, "'user'@'%'TO'relay'@'%'WITHGRANTOPTION")},
		{"columns-no-space",
			"GRANT SELECT(col1), INSERT(col2, col3) ON `mydb`.`mytable` TO 'u'@'localhost'",
			tokens("u", "localhost", []string{"SELECT", "SELECT.col1", "INSERT", "INSERT.col2", "INSERT.col3"}, "`mydb`.`mytable`")},
		{"columns-with-space",
			"GRANT SELECT (col1, col2) ON mydb.mytable TO 'u'@'localhost'",
			tokens("u", "localhost", []string{"SELECT", "SELECT.col1", "SELECT.col2"}, "mydb.mytable")},
		{"single-column",
			"GRANT UPDATE (a) ON d.t TO 'x'@'y'",
			tokens("x", "y", []string{"UPDATE", "UPDATE.a"}, "d.t")},
		{"multiword-column-keeps-empty-prefix",
			// Upstream quirk: a column after a multi-word privilege is
			// prefixed with the still-empty current_grant.
			"GRANT LOCK TABLES(c1) ON d.t TO 'x'@'y'",
			tokens("x", "y", []string{"LOCK TABLES", ".c1"}, "d.t")},
		{"quoted-user-host-with-spaces",
			"GRANT SELECT ON `d b`.`t t` TO 'us er '@'ho st'",
			tokens("us er ", "ho st", []string{"SELECT"}, "`d b`.`t t`")},
		{"backtick-quoted-user-host",
			"GRANT SELECT ON d.* TO `u s`@`h st`",
			tokens("`u s`", "`h st`", []string{"SELECT"}, "d.*")},
		{"wildcard-host-and-db",
			"GRANT SELECT ON my_db.% TO 'u'@'%'",
			tokens("u", "%", []string{"SELECT"}, "my_db.%")},
		{"missing-host-after-at",
			"GRANT SELECT ON *.* TO 'u'@",
			tokens("u", "", []string{"SELECT"}, "*.*")},
		{"db-only-no-to",
			"GRANT SELECT ON `justdb`",
			tokens("", "", []string{"SELECT"}, "`justdb`")},
		{"db-and-tables-no-to",
			"GRANT SELECT ON *.*",
			tokens("", "", []string{"SELECT"}, "*.*")},
		{"empty-grant", "", tokens("", "", nil, "")},
		{"grant-only", "GRANT", tokens("", "", nil, "")},
		{"empty-user",
			"GRANT USAGE ON *.* TO ''@'localhost'",
			tokens("", "localhost", []string{"USAGE"}, "*.*")},
		{"percent-percent-untouched-in-string-mode",
			"GRANT SELECT ON `db%%x`.* TO 'u'@'h'",
			tokens("u", "h", []string{"SELECT"}, "`db%%x`.*")},
		{"backslash-is-punctuation-not-escape",
			"GRANT SELECT ON `a\\b`.* TO 'u\\s'@'h'",
			tokens(`u\s`, "h", []string{"SELECT"}, "`a\\b`.*")},
		{"non-ascii-codepoints",
			"GRANT SELECT ON `débàr`.* TO 'ù'@'hö'",
			tokens("ù", "hö", []string{"SELECT"}, "`débàr`.*")},
		{"double-quote-wordchars",
			"GRANT SELECT ON \"we\"ird.* TO 'u'@'h'",
			tokens("u", "h", []string{"SELECT"}, "\"we\"ird.*")},
		{"trailing-clause-ignored-after-host",
			"GRANT SELECT ON d.* TO 'u'@'h' IDENTIFIED BY 'pw'",
			tokens("u", "h", []string{"SELECT"}, "d.*")},
		{"grant-option-privilege",
			"GRANT GRANT OPTION ON *.* TO 'u'@'h'",
			tokens("u", "h", []string{"GRANT OPTION"}, "*.*")},
		{"multiple-multiword",
			"GRANT LOCK TABLES, SHOW VIEW, CREATE TEMPORARY TABLES ON d.* TO 'u'@'h'",
			tokens("u", "h", []string{"LOCK TABLES", "SHOW VIEW", "CREATE TEMPORARY TABLES"}, "d.*")},
	}
	for _, tc := range cases {
		got, err := callTokenize(t, tc.grant)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %#v\nwant %#v", tc.name, got, tc.want)
		}
	}
}

// TestTokenizeGrantErrorShapes pins the exact pinned failure classes: the
// shlex ValueError for an unterminated quote and the read-ahead IndexError
// shapes. Messages keep the verbatim Python fragments.
func TestTokenizeGrantErrorShapes(t *testing.T) {
	cases := []struct {
		grant string
		err   error
	}{
		{"GRANT SELECT", errGrantIndexOutOfRange},
		{"GRANT SELECT ON *.* TO 'u'", errGrantIndexOutOfRange},
		{"GRANT SELECT ON `db.* TO 'u'@'h'", errGrantNoClosingQuotation},
		{"GRANT SELECT ON *.* TO 'u@'h'", errGrantIndexOutOfRange},
	}
	for _, tc := range cases {
		_, err := callTokenize(t, tc.grant)
		if !errors.Is(err, tc.err) {
			t.Errorf("tokenize_grant(%q) error = %v, want %v", tc.grant, err, tc.err)
			continue
		}
		switch tc.err {
		case errGrantNoClosingQuotation:
			if err.Error() != "mysql: No closing quotation" {
				t.Errorf("quotation error text = %q", err.Error())
			}
		case errGrantIndexOutOfRange:
			if err.Error() != "mysql: list index out of range" {
				t.Errorf("index error text = %q", err.Error())
			}
		}
	}
}

// TestGrantToTokensDictMode pins the dict-mode contract used by Salt's
// internal callers: MySQLdb '%%' unescaping, arg-supplied user/host without
// quote stripping, the "undefined" defaults, and the user-phrase break.
func TestGrantToTokensDictMode(t *testing.T) {
	quoted := "'testuser'"
	got, err := grantToTokens(grantDict{
		Qry:  "GRANT SELECT, INSERT ON `test%%db`.* TO %s@%s",
		Args: grantDictArgs{User: &quoted, Host: &quoted},
	})
	if err != nil {
		t.Fatalf("dict mode: %v", err)
	}
	want := grantTokens{User: "'testuser'", Host: "'testuser'", Grant: []string{"SELECT", "INSERT"}, Database: "`test%db`.*"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dict mode = %#v, want %#v", got, want)
	}

	got, err = grantToTokens(grantDict{Qry: "GRANT ALL PRIVILEGES ON *.* TO %s@%s", Args: grantDictArgs{}})
	if err != nil {
		t.Fatalf("dict defaults: %v", err)
	}
	want = grantTokens{User: "undefined", Host: "undefined", Grant: []string{"ALL PRIVILEGES"}, Database: "*.*"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dict defaults = %#v, want %#v", got, want)
	}

	got, err = grantToTokens(grantDict{Qry: "GRANT SELECT(col1) ON d.t TO %s@%s", Args: grantDictArgs{}})
	if err != nil {
		t.Fatalf("dict columns: %v", err)
	}
	want = grantTokens{User: "undefined", Host: "undefined", Grant: []string{"SELECT", "SELECT.col1"}, Database: "d.t"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dict columns = %#v, want %#v", got, want)
	}

	if _, err := grantToTokens(grantDict{Qry: "undefined-ish"}); !errors.Is(err, errGrantIndexOutOfRange) {
		t.Fatalf("dict malformed error = %v", err)
	}
	if _, err := grantToTokens(42); !errors.Is(err, errGrantKind) {
		t.Fatalf("unsupported grant kind error = %v", err)
	}
}

// TestGrantListRendersEmptyJSONArray guards the Python [] (not null)
// rendering of an empty grant list.
func TestGrantListRendersEmptyJSONArray(t *testing.T) {
	encoded, err := json.Marshal(tokens("", "", nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"grant":[]`) {
		t.Fatalf("empty grant list must render as []: %s", encoded)
	}
}

// TestMysqlRegistryNames pins the canonical registered names: exactly one
// registration per function, nothing more.
func TestMysqlRegistryNames(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"mysql.db_check",
		"mysql.db_exists",
		"mysql.db_get",
		"mysql.db_list",
		"mysql.db_optimize",
		"mysql.db_repair",
		"mysql.db_tables",
		"mysql.quote_identifier",
		"mysql.showglobal",
		"mysql.showvariables",
		"mysql.status",
		"mysql.tokenize_grant",
		"mysql.user_exists",
		"mysql.user_list",
		"mysql.version",
	}
	if reg.Len() != len(wantNames) {
		t.Fatalf("registry length = %d, want %d", reg.Len(), len(wantNames))
	}
	for _, name := range wantNames {
		if _, ok := reg.Get(name); !ok {
			t.Fatalf("%s not registered", name)
		}
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration must fail")
	}
}

// TestMysqlPureFunctionsIgnoreRuntime proves the R9.2a slice requires no
// Runner, filesystem, or facts: a zero runtime executes both functions.
func TestMysqlPureFunctionsIgnoreRuntime(t *testing.T) {
	rt := &runtime.Runtime{}
	if _, err := (quoteIdentifierFunc{}).Execute(context.Background(), rt, &QuoteIdentifierArgs{Identifier: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (tokenizeGrantFunc{}).Execute(context.Background(), rt, &TokenizeGrantArgs{Grant: "GRANT SELECT ON d.* TO 'u'@'h'"}); err != nil {
		t.Fatal(err)
	}
}

// TestMysqlArgsRejectWrongTypes pins the typed-args guard.
func TestMysqlArgsRejectWrongTypes(t *testing.T) {
	if _, err := (quoteIdentifierFunc{}).Execute(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("quote_identifier must reject non-struct args")
	}
	if _, err := (tokenizeGrantFunc{}).Execute(context.Background(), nil, 7); err == nil {
		t.Fatal("tokenize_grant must reject non-struct args")
	}
}

// ---------------------------------------------------------------------------
// R9.3a read-only catalog family (db_list, db_exists, user_list,
// user_exists) over the central mysql CLI transport. Every test runs on a
// fake Runner: no mysql binary is executed and no server is contacted.

// mysqlFakeRunner records every command and answers queued results.
type mysqlFakeRunner struct {
	results   []process.CommandResult
	calls     []process.Command
	available map[string]bool
}

func (r *mysqlFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Redact = append([]string(nil), command.Redact...)
	if command.Env != nil {
		copied := make([]string, len(command.Env))
		copy(copied, command.Env)
		command.Env = copied
	}
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func (r *mysqlFakeRunner) CommandAvailable(name string) bool {
	if r.available == nil {
		return true
	}
	return r.available[name]
}

func newMysqlRuntime(results ...process.CommandResult) (*runtime.Runtime, *mysqlFakeRunner) {
	runner := &mysqlFakeRunner{results: results}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func mysqlString(value string) *string { return &value }

func mysqlBool(value bool) *bool { return &value }

// fullDbListArgs carries every connection argument at once.
func fullDbListArgs() *DbListArgs {
	return &DbListArgs{
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// wantFullArgv is the exact mysql client argv with every connection
// argument supplied: the fixed query rides the final --execute at argv
// index 6.
var wantFullArgv = []string{
	"mysql",
	"--batch",
	"--user=test_user",
	"--host=test_host",
	"--port=test_port",
	"--database=test_maint",
	"--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA",
}

// wantBareArgv is the argv with no connection argument at all.
var wantBareArgv = []string{
	"mysql", "--batch",
	"--execute=SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) FROM information_schema.SCHEMATA",
}

// TestMysqlDBListArgvEnvAndResult pins the transport contract: exact
// batch-mode argv with the joined connection flags, the MYSQL_PWD-only
// clean environment, the password as the single Redact secret, the 30s
// timeout and 4 MiB output caps, and the pinned first-column list shape.
func TestMysqlDBListArgvEnvAndResult(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Database\ninformation_schema\nmysql\nsalt\n"),
	})
	value, err := (dbListFunc{}).Execute(context.Background(), rt, fullDbListArgs())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.([]string)
	if !ok || !reflect.DeepEqual(got, []string{"information_schema", "mysql", "salt"}) {
		t.Fatalf("db_list = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, wantFullArgv) {
		t.Fatalf("argv = %q", argv)
	}
	// The index-6 query assertion, checked directly.
	if argv := append([]string{command.Name}, command.Args...); argv[6] != "--execute="+showDatabasesQuery {
		t.Fatalf("argv[6] = %q, want the database catalog query", argv[6])
	}
	if want := []string{"MYSQL_PWD=test_pass"}; !reflect.DeepEqual(command.Env, want) {
		t.Fatalf("env = %q, want %q", command.Env, want)
	}
	if command.Shell {
		t.Fatal("db_list must never run through a shell")
	}
	if !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("bounds: timeout=%v stdout=%d stderr=%d", command.Timeout, command.MaxStdoutBytes, command.MaxStderrBytes)
	}
	if command.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v, want the 30s ceiling", command.Timeout)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestMysqlDBListShapes pins the bare argv and clean environment without
// connection arguments, the header-only empty list, and the pinned
// nonzero-exit compatibility data (the _connect failure and
// OperationalError paths answer the empty list, never an error).
func TestMysqlDBListShapes(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Database\n"),
	})
	value, err := (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]string); !ok || len(got) != 0 {
		t.Fatalf("header-only db_list = %#v", value)
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, wantBareArgv) {
		t.Fatalf("bare argv = %q", argv)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("bare env = %#v, want the clean empty environment", command.Env)
	}
	if command.Redact != nil {
		t.Fatalf("bare redact = %q, want none", command.Redact)
	}

	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte("ERROR 1045 (28000): Access denied\n"),
	})
	value, err = (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{})
	if err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok := value.([]string); !ok || len(got) != 0 {
		t.Fatalf("nonzero-exit db_list = %#v", value)
	}
}

// TestMysqlDBListFailClosed pins the error boundaries: no Runner at all,
// an unavailable mysql client, an explicit runas, and a cancelled context
// all fail before any Runner invocation; Runner failures and
// output-limit violations are errors; a Runner error carrying the
// connection password is returned redacted.
func TestMysqlDBListFailClosed(t *testing.T) {
	_, err := (dbListFunc{}).Execute(context.Background(), &runtime.Runtime{}, &DbListArgs{})
	if !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}

	runner := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	rt := &runtime.Runtime{Runner: runner}
	if _, err = (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{}); !errors.Is(err, errMysqlClientUnavailable) {
		t.Fatalf("unavailable client error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable client made %d calls", len(runner.calls))
	}

	for _, tc := range []struct {
		name string
		args *DbListArgs
		want error
	}{
		{"runas", &DbListArgs{Runas: mysqlString("mysql")}, errMysqlRunas},
		{"runas-invalid", &DbListArgs{Runas: mysqlString("root\n")}, errMysqlInvalidArgument},
	} {
		runner := &mysqlFakeRunner{}
		rt := &runtime.Runtime{Runner: runner}
		_, err := (dbListFunc{}).Execute(context.Background(), rt, tc.args)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s error = %v, want %v", tc.name, err, tc.want)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s made %d calls, want 0", tc.name, len(runner.calls))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	rt = &runtime.Runtime{Runner: runner}
	if _, err = (dbListFunc{}).Execute(ctx, rt, &DbListArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("cancelled call made %d calls", len(runner.calls))
	}

	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
	if _, err = (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{}); err == nil || err.Error() != "boom" {
		t.Fatalf("runner error = %v", err)
	}

	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StdoutTruncated: true})
	if _, err = (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error = %v", err)
	}

	marker := "S3CRET-mysql-pass"
	rt, _ = newMysqlRuntime(process.CommandResult{
		Err: errors.New("mysql failed with " + marker),
	})
	_, err = (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// TestMysqlDBExists pins the exact boolean, the client-side name match,
// and that the caller's name never reaches the argv: a hostile name runs
// the identical catalog argv of db_list.
func TestMysqlDBExists(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Database\ninformation_schema\nmysql\nsalt\n"),
	})
	value, err := (dbExistsFunc{}).Execute(context.Background(), rt, &DbExistsArgs{Name: "mysql"})
	if err != nil || value != true {
		t.Fatalf("db_exists(mysql) = %v, %v", value, err)
	}
	if argv := append([]string{command0Name(runner)}, runner.calls[0].Args...); !reflect.DeepEqual(argv, wantBareArgv) {
		t.Fatalf("argv = %q", argv)
	}

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"missing", false},
		// LIKE wildcards stay literal under the client-side exact match.
		{"my%", false},
		{"mysql_", false},
		{"information_schema", true},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("Database\ninformation_schema\nmysql\nsalt\n"),
		})
		value, err := (dbExistsFunc{}).Execute(context.Background(), rt, &DbExistsArgs{Name: tc.name})
		if err != nil || value != tc.want {
			t.Fatalf("db_exists(%q) = %v, %v; want %v", tc.name, value, err, tc.want)
		}
	}

	// A hostile name runs byte-identical argv: nothing is interpolated.
	hostile := "x' OR '1'='1' --; DROP TABLE user"
	plainRunner := &mysqlFakeRunner{}
	hostileRunner := &mysqlFakeRunner{}
	_, err = (dbExistsFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: plainRunner}, &DbExistsArgs{Name: "mysql"})
	_, err = (dbExistsFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: hostileRunner}, &DbExistsArgs{Name: hostile})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainRunner.calls[0].Args, hostileRunner.calls[0].Args) {
		t.Fatalf("hostile name changed argv: %q vs %q", hostileRunner.calls[0].Args, plainRunner.calls[0].Args)
	}

	// The pinned error paths answer False, never an error.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	if value, err = (dbExistsFunc{}).Execute(context.Background(), rt, &DbExistsArgs{Name: "mysql"}); err != nil || value != false {
		t.Fatalf("nonzero-exit db_exists = %v, %v", value, err)
	}
}

func command0Name(runner *mysqlFakeRunner) string { return runner.calls[0].Name }

// fullDbGetArgs carries every connection argument at once.
func fullDbGetArgs(name string) *DbGetArgs {
	return &DbGetArgs{
		Name:     name,
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// fullDbTablesArgs carries every connection argument at once.
func fullDbTablesArgs(name string) *DbTablesArgs {
	return &DbTablesArgs{
		Name:     name,
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

const dbGetQueryForTest = "SELECT COALESCE(SCHEMA_NAME, UNHEX('00')) AS SCHEMA_NAME, COALESCE(DEFAULT_CHARACTER_SET_NAME, UNHEX('00')) AS DEFAULT_CHARACTER_SET_NAME, COALESCE(DEFAULT_COLLATION_NAME, UNHEX('00')) AS DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA"

// TestMysqlDBGet pins db_get's fixed SCHEMATA catalog, the source dict keys,
// client-side matching, and the full connection/redaction/bounds contract.
func TestMysqlDBGet(t *testing.T) {
	if dbGetQuery != dbGetQueryForTest {
		t.Fatalf("db_get query = %q, want %q", dbGetQuery, dbGetQueryForTest)
	}
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\r\n" +
			"other\tlatin1\tlatin1_swedish_ci\r\n" +
			"test_db\tutf8mb4\tutf8mb4_0900_ai_ci\r\n"),
	})
	value, err := (dbGetFunc{}).Execute(context.Background(), rt, fullDbGetArgs("test_db"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"character_set": "utf8mb4", "collate": "utf8mb4_0900_ai_ci"}
	if got, ok := value.(map[string]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("db_get = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=" + dbGetQuery,
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if want := []string{"MYSQL_PWD=test_pass"}; !reflect.DeepEqual(command.Env, want) {
		t.Fatalf("env = %q, want %q", command.Env, want)
	}
	if !reflect.DeepEqual(command.Redact, []string{"test_pass"}) || strings.Contains(command.RedactedString(), "test_pass") {
		t.Fatalf("password redaction failed: %#v", command)
	}
	if command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("transport bounds/shell = %#v", command)
	}

	// The sentinel maps SQL NULL to nil, while literal NULL stays a value;
	// CRLF framing is removed before either comparison.
	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte(
		"SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\r\n" +
			"test_db\t\\0\tNULL\r\n")})
	value, err = (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "test_db"})
	if err != nil || !reflect.DeepEqual(value, map[string]any{"character_set": nil, "collate": "NULL"}) {
		t.Fatalf("db_get NULL shape = %#v, %v", value, err)
	}

	// A missing database is the successful empty dict, not false or an error.
	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte(
		"SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\n" +
			"other\tutf8\tutf8_general_ci\n")})
	value, err = (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "missing"})
	if err != nil || !reflect.DeepEqual(value, map[string]any{}) {
		t.Fatalf("db_get missing = %#v, %v", value, err)
	}

	// A nonzero mysql exit is the pinned [] compatibility shape, distinct
	// from a successful rowless query's {}.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	value, err = (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "test_db"})
	if err != nil || !reflect.DeepEqual(value, []any{}) {
		t.Fatalf("db_get nonzero = %#v, %v", value, err)
	}
}

// TestMysqlDBGetFailClosed pins the shared preflight and failure boundaries
// on the new catalog surface without contacting a database.
func TestMysqlDBGetFailClosed(t *testing.T) {
	if _, err := (dbGetFunc{}).Execute(context.Background(), &runtime.Runtime{}, &DbGetArgs{Name: "db"}); !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}
	unavailable := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	if _, err := (dbGetFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: unavailable}, &DbGetArgs{Name: "db"}); !errors.Is(err, errMysqlClientUnavailable) || len(unavailable.calls) != 0 {
		t.Fatalf("unavailable client error=%v calls=%d", err, len(unavailable.calls))
	}
	for _, tc := range []struct {
		name string
		args *DbGetArgs
		want error
	}{
		{"runas", &DbGetArgs{Name: "db", Runas: mysqlString("mysql")}, errMysqlRunas},
		{"runas-invalid", &DbGetArgs{Name: "db", Runas: mysqlString("root\n")}, errMysqlInvalidArgument},
	} {
		runner := &mysqlFakeRunner{}
		_, err := (dbGetFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, tc.args)
		if !errors.Is(err, tc.want) || len(runner.calls) != 0 {
			t.Fatalf("%s error=%v calls=%d", tc.name, err, len(runner.calls))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &mysqlFakeRunner{}
	if _, err := (dbGetFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &DbGetArgs{Name: "db"}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled error=%v calls=%d", err, len(runner.calls))
	}
	rt, _ := newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
	if _, err := (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "db"}); err == nil || err.Error() != "boom" {
		t.Fatalf("runner error = %v", err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{StdoutTruncated: true})
	if _, err := (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "db"}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error = %v", err)
	}
	marker := "S3CRET-db-get-pass"
	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("mysql failed with " + marker)})
	_, err := (dbGetFunc{}).Execute(context.Background(), rt, &DbGetArgs{Name: "db", Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// TestMysqlDBTables pins the db_exists preflight, fixed TABLES catalog, source
// order, literal/sentinel NULL distinction, and optional client-side filter.
func TestMysqlDBTables(t *testing.T) {
	catalog := []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\r\nother\r\ntest_db\r\n")},
		{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\r\n" +
			"other\tignored\r\n" +
			"test_db\tzeta\r\n" +
			"test_db\t\\0\r\n" +
			"test_db\tNULL\r\n" +
			"test_db\talpha\r\n" +
			"\\0\tghost\r\n")},
	}
	rt, runner := newMysqlRuntime(catalog...)
	value, err := (dbTablesFunc{}).Execute(context.Background(), rt, fullDbTablesArgs("test_db"))
	if err != nil || !reflect.DeepEqual(value, []string{"zeta", "NULL", "alpha"}) {
		t.Fatalf("db_tables = %#v, %v", value, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	for i, query := range []string{showDatabasesQuery, tableCatalogQuery} {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		want := []string{"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint", "--execute=" + query}
		if !reflect.DeepEqual(argv, want) {
			t.Fatalf("call %d argv=%q want=%q", i, argv, want)
		}
		if !reflect.DeepEqual(runner.calls[i].Env, []string{"MYSQL_PWD=test_pass"}) || !reflect.DeepEqual(runner.calls[i].Redact, []string{"test_pass"}) {
			t.Fatalf("call %d password transport = %#v", i, runner.calls[i])
		}
	}
	if strings.Contains(strings.Join(runner.calls[1].Args, "\x00"), "test_db") {
		t.Fatal("db_tables interpolated the database name into SQL")
	}

	filtered := "alpha"
	rt, runner = newMysqlRuntime(catalog...)
	value, err = (dbTablesFunc{}).Execute(context.Background(), rt, &DbTablesArgs{Name: "test_db", Table: &filtered})
	if err != nil || !reflect.DeepEqual(value, []string{"alpha"}) || len(runner.calls) != 2 {
		t.Fatalf("filtered db_tables = %#v, %v calls=%d", value, err, len(runner.calls))
	}

	// A missing database is False after only the db_exists catalog call.
	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: []byte("Database\nother\n")})
	value, err = (dbTablesFunc{}).Execute(context.Background(), rt, &DbTablesArgs{Name: "missing"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("missing db_tables = %#v, %v calls=%d", value, err, len(runner.calls))
	}

	// The second catalog's nonzero compatibility result is an empty list.
	rt, _ = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("Database\ntest_db\n")},
		process.CommandResult{ExitCode: 1},
	)
	value, err = (dbTablesFunc{}).Execute(context.Background(), rt, &DbTablesArgs{Name: "test_db"})
	if err != nil || !reflect.DeepEqual(value, []string{}) {
		t.Fatalf("failed table catalog = %#v, %v", value, err)
	}
}

// TestMysqlDBTablesFailClosed pins the shared transport guards on both fixed
// catalog calls and keeps all caller filters out of argv.
func TestMysqlDBTablesFailClosed(t *testing.T) {
	if _, err := (dbTablesFunc{}).Execute(context.Background(), &runtime.Runtime{}, &DbTablesArgs{Name: "db"}); !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}
	unavailable := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	if _, err := (dbTablesFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: unavailable}, &DbTablesArgs{Name: "db"}); !errors.Is(err, errMysqlClientUnavailable) || len(unavailable.calls) != 0 {
		t.Fatalf("unavailable client error=%v calls=%d", err, len(unavailable.calls))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &mysqlFakeRunner{}
	if _, err := (dbTablesFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &DbTablesArgs{Name: "db"}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled error=%v calls=%d", err, len(runner.calls))
	}
	marker := "S3CRET-db-tables-pass"
	rt, _ := newMysqlRuntime(process.CommandResult{Err: errors.New("mysql failed with " + marker)})
	_, err := (dbTablesFunc{}).Execute(context.Background(), rt, &DbTablesArgs{Name: "db", Password: mysqlString(marker), Table: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// TestMysqlDBCatalogThroughRegistry drives the R9.3d names through the actual
// exec registry, including their mixed list/dict/false compatibility shapes.
func TestMysqlDBCatalogThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	runner.results = []process.CommandResult{{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")}}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.db_get", &DbGetArgs{Name: "db"})
	if err != nil || !reflect.DeepEqual(value, map[string]any{"character_set": "utf8", "collate": "utf8_general_ci"}) {
		t.Fatalf("registry db_get = %#v, %v", value, err)
	}

	runner.results = []process.CommandResult{
		{Stdout: []byte("Database\ndb\n")},
		{Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\ndb\ntable\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_tables", &DbTablesArgs{Name: "db"})
	if err != nil || !reflect.DeepEqual(value, []string{}) {
		t.Fatalf("registry db_tables short row = %#v, %v", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("registry R9.3d calls = %d, want 3", len(runner.calls))
	}
}

// TestMysqlUserList pins the exact query, the DictRow map shape keyed by
// the batch header, the prefix-zip of a short row, and that no password
// column ever enters the query or the result.
func TestMysqlUserList(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("User\tHost\nroot\tlocalhost\nsalt\t%\n"),
	})
	value, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.([]map[string]any)
	if !ok || !reflect.DeepEqual(got, []map[string]any{
		{"User": "root", "Host": "localhost"},
		{"User": "salt", "Host": "%"},
	}) {
		t.Fatalf("user_list = %#v", value)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--execute=" + userListQuery,
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(userListQuery, "assword") {
		t.Fatalf("user_list query selects a password column: %q", userListQuery)
	}
	for _, row := range got {
		for column := range row {
			if strings.Contains(strings.ToLower(column), "password") {
				t.Fatalf("user_list row carries password column %q", column)
			}
		}
	}

	// StateKit defensively retains only the available prefix of a short row.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("User\tHost\nonlyuser\n"),
	})
	value, err = (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok = value.([]map[string]any); !ok || !reflect.DeepEqual(got, []map[string]any{{"User": "onlyuser"}}) {
		t.Fatalf("short row user_list = %#v", value)
	}

	// The pinned failure paths answer the empty list.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	if value, err = (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{}); err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok = value.([]map[string]any); !ok || len(got) != 0 {
		t.Fatalf("nonzero-exit user_list = %#v", value)
	}
}

// fullUserExistsArgs carries the full argument surface at once.
func fullUserExistsArgs() *UserExistsArgs {
	return &UserExistsArgs{
		User:     "root",
		Host:     mysqlString("%"),
		ConnUser: mysqlString("test_user"),
		ConnHost: mysqlString("test_host"),
		ConnPort: mysqlString("test_port"),
		ConnPass: mysqlString("test_pass"),
		ConnDB:   mysqlString("test_maint"),
	}
}

// TestMysqlUserExists pins the exact boolean: the (user, host) pair is
// matched client-side against the fixed catalog with the pinned
// localhost default, and the full connection surface lands on the exact
// catalog argv.
func TestMysqlUserExists(t *testing.T) {
	stdout := []byte("User\tHost\nroot\tlocalhost\nroot\t%\nsalt\tlocalhost\n")
	rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: stdout})
	value, err := (userExistsFunc{}).Execute(context.Background(), rt, fullUserExistsArgs())
	if err != nil || value != true {
		t.Fatalf("user_exists(root, %%) = %v, %v", value, err)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint", "--execute=" + userListQuery}) {
		t.Fatalf("argv = %q", argv)
	}

	for _, tc := range []struct {
		user string
		host *string
		want bool
	}{
		{"root", nil, true}, // the pinned localhost default
		{"root", mysqlString("localhost"), true},
		{"root", mysqlString("%"), true},
		{"ghost", nil, false},
		{"salt", mysqlString("%"), false},
		{"", nil, false},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: stdout})
		value, err := (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: tc.user, Host: tc.host})
		if err != nil || value != tc.want {
			t.Fatalf("user_exists(%q, %v) = %v, %v; want %v", tc.user, tc.host, value, err, tc.want)
		}
	}

	// The pinned error paths answer False, never an error.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	if value, err = (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: "root"}); err != nil || value != false {
		t.Fatalf("nonzero-exit user_exists = %v, %v", value, err)
	}
}

// TestMysqlUserExistsPasswordBoundary pins the unsupported
// password-verification variants — refused value-free before any Runner
// invocation — and the pinned truthiness that keeps None and the empty
// string on the supported bare path, with password_column inert.
func TestMysqlUserExistsPasswordBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		args *UserExistsArgs
	}{
		{"password", &UserExistsArgs{User: "root", Password: mysqlString("BLUECOW")}},
		{"password-hash", &UserExistsArgs{User: "root", PasswordHash: mysqlString("*1A01CF8FBE6425398935FB90359AD8B817399102")}},
		{"passwordless", &UserExistsArgs{User: "root", Passwordless: mysqlBool(true)}},
		{"unix-socket", &UserExistsArgs{User: "root", Passwordless: mysqlBool(true), UnixSocket: mysqlBool(true)}},
	} {
		runner := &mysqlFakeRunner{}
		rt := &runtime.Runtime{Runner: runner}
		_, err := (userExistsFunc{}).Execute(context.Background(), rt, tc.args)
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("%s error = %v, want the unsupported boundary", tc.name, err)
		}
		if strings.Contains(err.Error(), "BLUECOW") || strings.Contains(err.Error(), "1A01CF") {
			t.Fatalf("%s error leaks the credential: %v", tc.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s made %d calls, want 0", tc.name, len(runner.calls))
		}
	}

	// The pinned falsy shapes stay on the bare existence path.
	for _, tc := range []struct {
		name string
		args *UserExistsArgs
		want bool
	}{
		{"empty-password", &UserExistsArgs{User: "root", Password: mysqlString("")}, true},
		{"empty-password-hash", &UserExistsArgs{User: "root", PasswordHash: mysqlString("")}, true},
		{"explicit-false-passwordless", &UserExistsArgs{User: "root", Passwordless: mysqlBool(false)}, true},
		{"inert-password-column", &UserExistsArgs{User: "root", PasswordColumn: mysqlString("authentication_string")}, true},
		{"inert-password-column-miss", &UserExistsArgs{User: "ghost", PasswordColumn: mysqlString("Password")}, false},
	} {
		rt, runner := newMysqlRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("User\tHost\nroot\tlocalhost\n"),
		})
		value, err := (userExistsFunc{}).Execute(context.Background(), rt, tc.args)
		if err != nil || value != tc.want {
			t.Fatalf("%s = %v, %v; want %v", tc.name, value, err, tc.want)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s made %d calls, want 1", tc.name, len(runner.calls))
		}
	}
}

// TestMysqlUserExistsMissingColumn pins the value-free missing-column
// error a malformed catalog row answers.
func TestMysqlUserExistsMissingColumn(t *testing.T) {
	rt, _ := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("user\thost\nroot\tlocalhost\n"),
	})
	_, err := (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: "root"})
	if err == nil || !strings.Contains(err.Error(), "missing column") {
		t.Fatalf("missing column error = %v", err)
	}
}

// TestMysqlCatalogThroughRegistry drives the four read-only functions
// through the execution registry on the same fake Runner: the registry
// path answers the same results with the same single call each.
func TestMysqlCatalogThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	value, err := rt.Exec.Call(context.Background(), rt, "mysql.db_list", &DbListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]string); !ok || len(got) != 0 {
		t.Fatalf("registry db_list = %#v", value)
	}

	runner.results = []process.CommandResult{{ExitCode: 0, Stdout: []byte("Database\nmysql\n")}}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_exists", &DbExistsArgs{Name: "mysql"})
	if err != nil || value != true {
		t.Fatalf("registry db_exists = %v, %v", value, err)
	}

	runner.results = []process.CommandResult{{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\n")}}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_list", &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]map[string]any); !ok || len(got) != 1 {
		t.Fatalf("registry user_list = %#v", value)
	}

	runner.results = []process.CommandResult{{ExitCode: 0, Stdout: []byte("User\tHost\nroot\tlocalhost\n")}}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_exists", &UserExistsArgs{User: "root"})
	if err != nil || value != true {
		t.Fatalf("registry user_exists = %v, %v", value, err)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("registry path made %d calls, want 4", len(runner.calls))
	}
}

// ---------------------------------------------------------------------------
// R9.3a batch row framing and field decoder. The mysql client's --batch
// escaper (safe_put_field over tee_write in client/mysql.cc of MySQL
// 5.7/8.0 and MariaDB) escapes exactly NUL, tab, newline, and backslash
// (\0 \t \n \\) and writes every other byte raw, including carriage
// returns; the fixed catalog queries substitute the COALESCE(UNHEX('00'))
// sentinel for SQL NULL so a bare NULL on the wire is always the literal
// string. These vectors pin the bounded row splitter and decoder on that
// encoding: both framing delimiters, the documented escape family, the
// escaped-literal-backslash distinction, the sentinel mapping, and the
// malformed shapes.

// TestMysqlBatchRowSplitter pins splitBatchRows: "\n" and "\r\n" end a
// row with the delimiter CR removed, a CR that is not the delimiter half
// stays a raw field byte (a lone trailing CR included), and empty input
// answers no rows.
func TestMysqlBatchRowSplitter(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   []string
	}{
		{"empty", "", []string{}},
		{"lf-only", "a\nb\n", []string{"a", "b"}},
		{"crlf-only", "a\r\nb\r\n", []string{"a", "b"}},
		{"no-trailing-newline", "a\nb", []string{"a", "b"}},
		{"crlf-no-trailing", "a\r\nb", []string{"a", "b"}},
		{"lf-inside-crlf-stream", "a\r\nb\nc\r\n", []string{"a", "b", "c"}},
		{"raw-cr-inside-field", "a\rb\nc\n", []string{"a\rb", "c"}},
		{"cr-before-tab", "a\r\tb\nc\n", []string{"a\r\tb", "c"}},
		{"lone-trailing-cr", "a\nb\r", []string{"a", "b\r"}},
		{"bare-cr-stream", "a\rb\rc", []string{"a\rb\rc"}},
		{"double-cr-inside-field", "a\r\nb\r\rc\r\n", []string{"a", "b\r\rc"}},
		{"empty-lf-rows", "a\n\nb\n", []string{"a", "", "b"}},
		{"empty-crlf-rows", "a\r\n\r\nb\r\n", []string{"a", "", "b"}},
		{"empty-input-newline-only", "\n", []string{""}},
	}
	for _, tc := range cases {
		got := splitBatchRows(tc.stdout)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: splitBatchRows(%q) = %q, want %q", tc.name, tc.stdout, got, tc.want)
		}
	}
}

// TestMysqlBatchFieldDecoder pins decodeBatchField, the sentinel mapping
// of decodeCatalogField, and the raw-header contract of parseBatchRows:
// one bounded left-to-right pass where an encoded \\n keeps the literal
// backslash before n, unknown escapes and a trailing lone backslash are
// preserved verbatim, the literal string NULL stays a value, and header
// cells stay byte-raw exactly like the client prints them.
func TestMysqlBatchFieldDecoder(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  batchField
	}{
		{"plain", "root", batchField{value: "root"}},
		{"empty", "", batchField{value: ""}},
		{"literal-null-string", "NULL", batchField{value: "NULL"}},
		{"escaped-tab", `a\tb`, batchField{value: "a\tb"}},
		{"escaped-newline", `a\nb`, batchField{value: "a\nb"}},
		{"escaped-carriage", `a\rb`, batchField{value: "a\rb"}},
		{"raw-carriage", "a\rb", batchField{value: "a\rb"}},
		{"escaped-nul", `a\0b`, batchField{value: "a\x00b"}},
		{"escaped-backspace", `a\bb`, batchField{value: "a\x08b"}},
		{"escaped-ctrl-z", `a\Zb`, batchField{value: "a\x1ab"}},
		{"escaped-backslash", `a\\b`, batchField{value: `a\b`}},
		{"single-backslash-account", `win\\admin`, batchField{value: `win\admin`}},
		{"literal-backslash-n", `\\n`, batchField{value: `\n`}},
		{"literal-backslash-then-escape", `x\\n\ty`, batchField{value: "x\\n\ty"}},
		{"only-two-backslashes", `\\`, batchField{value: `\`}},
		{"unknown-escape-preserved", `q\xq`, batchField{value: `q\xq`}},
		{"dump-null-spelling-not-a-sentinel", `\N`, batchField{value: `\N`}},
		{"trailing-lone-backslash", `abc\`, batchField{value: `abc\`}},
	}
	for _, tc := range cases {
		if got := decodeBatchField(tc.field); got != tc.want {
			t.Errorf("%s: decodeBatchField(%q) = %+v, want %+v", tc.name, tc.field, got, tc.want)
		}
	}

	// The sentinel mapping is catalog-level: only the decoded one-NUL
	// field maps to null, through the escape the client prints for it
	// and through a raw NUL byte alike, while the literal string NULL
	// and the mysqldump \N spelling stay values.
	for _, tc := range []struct {
		name  string
		field string
		want  batchField
	}{
		{"sentinel-escaped", `\0`, batchField{null: true}},
		{"sentinel-raw", "\x00", batchField{null: true}},
		{"literal-null-value", "NULL", batchField{value: "NULL"}},
		{"dump-null-spelling", `\N`, batchField{value: `\N`}},
		{"nul-plus-more-is-a-value", `a\0b`, batchField{value: "a\x00b"}},
		{"escaped-nul-literal", `\\0`, batchField{value: `\0`}},
	} {
		if got := decodeCatalogField(tc.field); got != tc.want {
			t.Errorf("%s: decodeCatalogField(%q) = %+v, want %+v", tc.name, tc.field, got, tc.want)
		}
	}

	// The header is printed raw by the client (tee_fputs, no escaper), so
	// a backslash-carrying column name stays byte-raw after the split.
	header, rows := parseBatchRows("Na\\me\tHost\nv\th\n")
	if !reflect.DeepEqual(header, []string{`Na\me`, "Host"}) {
		t.Fatalf("raw header = %q", header)
	}
	if len(rows) != 1 || rows[0][0] != (batchField{value: "v"}) || rows[0][1] != (batchField{value: "h"}) {
		t.Fatalf("decoded rows = %#v", rows)
	}
}

// TestMysqlUserListDecodesBatchFields drives the decoder through user_list
// on batch output carrying every encoded shape: the single-backslash
// account, escaped control bytes, the NULL sentinel, the literal string
// NULL, an empty field, and a long row bounded by the prefix zip.
func TestMysqlUserListDecodesBatchFields(t *testing.T) {
	rt, _ := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("User\tHost\n" +
			"win\\\\admin\tlocalhost\n" +
			"a\\tb\tc\\nd\n" +
			"\\0\t%\n" +
			"NULL\tlocalhost\n" +
			"plain\t\n" +
			"x\\\\ny\tlocalhost\textra\n"),
	})
	value, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"User": `win\admin`, "Host": "localhost"},
		{"User": "a\tb", "Host": "c\nd"},
		{"User": nil, "Host": "%"},
		{"User": "NULL", "Host": "localhost"},
		{"User": "plain", "Host": ""},
		// The long row keeps its zipped prefix; the third field is dropped.
		{"User": `x\ny`, "Host": "localhost"},
	}
	if got, ok := value.([]map[string]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded user_list = %#v, want %#v", value, want)
	}
}

// TestMysqlDBCatalogDecodesBatchFields drives the decoder through db_list
// and db_exists: an escaped database name matches client-side after
// decoding, the NULL sentinel row is skipped — it has no []string shape
// and never matches a caller name — and a database literally named NULL
// stays the ordinary string NULL, listed and matched like any other name.
func TestMysqlDBCatalogDecodesBatchFields(t *testing.T) {
	stdout := []byte("Database\nwe\\tird\n\\0\nNULL\nplain\n")
	rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: stdout})
	value, err := (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]string); !ok || !reflect.DeepEqual(got, []string{"we\tird", "NULL", "plain"}) {
		t.Fatalf("decoded db_list = %#v", value)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"we\tird", true},
		{"plain", true},
		{"NULL", true},
		{"weird", false},
		{"\x00", false},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: stdout})
		value, err := (dbExistsFunc{}).Execute(context.Background(), rt, &DbExistsArgs{Name: tc.name})
		if err != nil || value != tc.want {
			t.Fatalf("db_exists(%q) = %v, %v; want %v", tc.name, value, err, tc.want)
		}
	}
}

// TestMysqlUserExistsDecodesBatchAccount pins the blocking R9.3a
// regression: an account name carrying a single backslash is batch-encoded
// with the backslash doubled and must match client-side after decoding —
// while the still-encoded spelling, the collapsed spelling, and the
// sentinel spellings of SQL NULL all stay misses, and a user or host
// literally spelled NULL matches exactly.
func TestMysqlUserExistsDecodesBatchAccount(t *testing.T) {
	stdout := []byte("User\tHost\nwin\\\\admin\tlocalhost\nx\\\\ny\t%\n")
	for _, tc := range []struct {
		user string
		host string
		want bool
	}{
		{`win\admin`, "localhost", true},
		{`x\ny`, "%", true},
		{`win\\admin`, "localhost", false},
		{"winadmin", "localhost", false},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: stdout})
		value, err := (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: tc.user, Host: mysqlString(tc.host)})
		if err != nil || value != tc.want {
			t.Fatalf("user_exists(%q, %q) = %v, %v; want %v", tc.user, tc.host, value, err, tc.want)
		}
	}

	// A sentinel host — the wire form of SQL NULL — decodes to nil,
	// MySQLdb's None, and never matches any caller string, while a host
	// literally spelled NULL is the ordinary string and matches exactly:
	// no false negatives on either side of the ambiguity the bare marker
	// cannot resolve.
	for _, tc := range []struct {
		name   string
		stdout string
		user   string
		host   string
		want   bool
	}{
		{"sentinel-host", "User\tHost\nroot\t\\0\n", "root", "NULL", false},
		{"literal-null-host", "User\tHost\nroot\tNULL\n", "root", "NULL", true},
		{"sentinel-user", "User\tHost\n\\0\tlocalhost\n", "NULL", "localhost", false},
		{"literal-null-user", "User\tHost\nNULL\tlocalhost\n", "NULL", "localhost", true},
		{"sentinel-host-never-matches-sentinel-name", "User\tHost\nroot\t\\0\n", "root", "\x00", false},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: tc.user, Host: mysqlString(tc.host)})
		if err != nil || value != tc.want {
			t.Fatalf("%s: user_exists(%q, %q) = %v, %v; want %v", tc.name, tc.user, tc.host, value, err, tc.want)
		}
	}
}

// TestMysqlBatchDecodeThroughRegistry drives the decoded catalogs through
// the execution registry: the registry path answers the same decoded
// shapes and the same decoded user_exists hit on one Runner call each.
func TestMysqlBatchDecodeThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nwin\\\\admin\tlocalhost\n")},
	}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.user_exists", &UserExistsArgs{User: `win\admin`, Host: mysqlString("localhost")})
	if err != nil || value != true {
		t.Fatalf("registry decoded user_exists = %v, %v", value, err)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("User\tHost\nwin\\\\admin\tlocalhost\nNULL\t%\n\\0\tlocalhost\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_list", &UserListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]map[string]any); !ok || !reflect.DeepEqual(got, []map[string]any{
		{"User": `win\admin`, "Host": "localhost"},
		{"User": "NULL", "Host": "%"},
		{"User": nil, "Host": "localhost"},
	}) {
		t.Fatalf("registry decoded user_list = %#v", value)
	}

	// The registry path keeps the sentinel skip and the literal NULL
	// listing of the db catalog.
	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\n\\0\nNULL\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_list", &DbListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]string); !ok || !reflect.DeepEqual(got, []string{"NULL"}) {
		t.Fatalf("registry decoded db_list = %#v", value)
	}
	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\n\\0\nNULL\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_exists", &DbExistsArgs{Name: "NULL"})
	if err != nil || value != true {
		t.Fatalf("registry decoded db_exists(NULL) = %v, %v", value, err)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Database\nwe\\tird\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_exists", &DbExistsArgs{Name: "we\tird"})
	if err != nil || value != true {
		t.Fatalf("registry decoded db_exists = %v, %v", value, err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("registry decode path made %d calls, want 5", len(runner.calls))
	}
}

// TestMysqlCatalogRowFraming pins the blocking R9.3a CRLF framing fix end
// to end through both catalogs and the exact user_exists match: CRLF-framed
// rows — header included — carry no delimiter CR into their fields, mixed
// CRLF/LF framing decodes identically, a missing trailing newline and
// empty rows change nothing, and a raw CR that is not a delimiter half
// stays inside its field.
func TestMysqlCatalogRowFraming(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stdout   string
		want     []map[string]any
		wantUser string
		wantHost string
		wantHit  bool
	}{
		{
			name:     "crlf",
			stdout:   "User\tHost\r\nroot\tlocalhost\r\nsalt\t%\r\n",
			want:     []map[string]any{{"User": "root", "Host": "localhost"}, {"User": "salt", "Host": "%"}},
			wantUser: "root", wantHost: "localhost", wantHit: true,
		},
		{
			name:     "lf",
			stdout:   "User\tHost\nroot\tlocalhost\nsalt\t%\n",
			want:     []map[string]any{{"User": "root", "Host": "localhost"}, {"User": "salt", "Host": "%"}},
			wantUser: "salt", wantHost: "%", wantHit: true,
		},
		{
			name:     "mixed-crlf-lf",
			stdout:   "User\tHost\r\nroot\tlocalhost\nsalt\t%\r\n",
			want:     []map[string]any{{"User": "root", "Host": "localhost"}, {"User": "salt", "Host": "%"}},
			wantUser: "root", wantHost: "localhost", wantHit: true,
		},
		{
			name:     "crlf-no-trailing-newline",
			stdout:   "User\tHost\r\nroot\tlocalhost\r\nsalt\t%",
			want:     []map[string]any{{"User": "root", "Host": "localhost"}, {"User": "salt", "Host": "%"}},
			wantUser: "salt", wantHost: "%", wantHit: true,
		},
		{
			name:     "empty-rows-between-rows",
			stdout:   "User\tHost\r\n\r\nroot\tlocalhost\r\n\r\n\r\nsalt\t%\r\n",
			want:     []map[string]any{{"User": "root", "Host": "localhost"}, {"User": "salt", "Host": "%"}},
			wantUser: "salt", wantHost: "%", wantHit: true,
		},
		{
			name:   "raw-cr-inside-field-kept",
			stdout: "User\tHost\nro\rot\tlocalhost\n",
			// The CR before 'o' is not a delimiter half (no LF follows),
			// so it survives inside the user name.
			want:     []map[string]any{{"User": "ro\rot", "Host": "localhost"}},
			wantUser: "ro\rot", wantHost: "localhost", wantHit: true,
		},
		{
			name:     "raw-cr-miss",
			stdout:   "User\tHost\nro\rot\tlocalhost\n",
			want:     []map[string]any{{"User": "ro\rot", "Host": "localhost"}},
			wantUser: "root", wantHost: "localhost", wantHit: false,
		},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := (userListFunc{}).Execute(context.Background(), rt, &UserListArgs{})
		if err != nil {
			t.Fatalf("%s: user_list: %v", tc.name, err)
		}
		if got, ok := value.([]map[string]any); !ok || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: user_list = %#v, want %#v", tc.name, value, tc.want)
		}
		rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err = (userExistsFunc{}).Execute(context.Background(), rt, &UserExistsArgs{User: tc.wantUser, Host: mysqlString(tc.wantHost)})
		if err != nil || value != tc.wantHit {
			t.Fatalf("%s: user_exists(%q, %q) = %v, %v; want %v", tc.name, tc.wantUser, tc.wantHost, value, err, tc.wantHit)
		}
	}

	// The db catalog decodes CRLF framing identically, header included.
	for _, tc := range []struct {
		name   string
		stdout string
		want   []string
		hit    string
		wantOK bool
	}{
		{"crlf", "Database\r\nmysql\r\nsalt\r\n", []string{"mysql", "salt"}, "salt", true},
		{"mixed", "Database\r\nmysql\nsalt\r\n", []string{"mysql", "salt"}, "mysql", true},
		{"crlf-no-trailing", "Database\r\nmysql\r\nsalt", []string{"mysql", "salt"}, "mysql", true},
		{"empty-rows", "Database\r\n\r\nmysql\r\n\r\nsalt\r\n", []string{"mysql", "salt"}, "salt", true},
		{"crlf-miss", "Database\r\nmysql\r\nsalt\r\n", []string{"mysql", "salt"}, "mysql\r", false},
	} {
		rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := (dbListFunc{}).Execute(context.Background(), rt, &DbListArgs{})
		if err != nil {
			t.Fatalf("%s: db_list: %v", tc.name, err)
		}
		if got, ok := value.([]string); !ok || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: db_list = %#v, want %#v", tc.name, value, tc.want)
		}
		rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err = (dbExistsFunc{}).Execute(context.Background(), rt, &DbExistsArgs{Name: tc.hit})
		if err != nil || value != tc.wantOK {
			t.Fatalf("%s: db_exists(%q) = %v, %v; want %v", tc.name, tc.hit, value, err, tc.wantOK)
		}
	}

	// A header framed with CRLF keys the DictRow exactly like an
	// LF-framed one: no delimiter CR glues onto the Host column name.
	header, rows := parseBatchRows("User\tHost\r\nroot\tlocalhost\r\n")
	if !reflect.DeepEqual(header, []string{"User", "Host"}) {
		t.Fatalf("CRLF-framed header = %q", header)
	}
	if len(rows) != 1 || rows[0][0] != (batchField{value: "root"}) || rows[0][1] != (batchField{value: "localhost"}) {
		t.Fatalf("CRLF-framed rows = %#v", rows)
	}
}

// ---------------------------------------------------------------------------
// R9.3b read-only server facts family (version, status, showvariables,
// showglobal) over the same central mysql CLI transport. Every test runs
// on a fake Runner: no mysql binary is executed and no server is
// contacted, exactly like the R9.3a family.

// fullVersionArgs carries every connection argument at once.
func fullVersionArgs() *VersionArgs {
	return &VersionArgs{
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// wantVersionFullArgv is the exact version argv with every connection
// argument supplied: the fixed query rides the final --execute at argv
// index 6.
var wantVersionFullArgv = []string{
	"mysql",
	"--batch",
	"--user=test_user",
	"--host=test_host",
	"--port=test_port",
	"--database=test_maint",
	"--execute=SELECT VERSION()",
}

// TestMysqlVersionArgvEnvAndResult pins the version transport contract:
// the exact pinned qry SELECT VERSION() as the fixed --execute payload
// (the pinned module reads the server version; it has no `mysql
// --version` client-binary path), the MYSQL_PWD-only clean environment,
// the password as the single Redact secret, the shared bounds, and the
// decoded first-field string answer.
func TestMysqlVersionArgvEnvAndResult(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("VERSION()\n8.0.36\n"),
	})
	value, err := (versionFunc{}).Execute(context.Background(), rt, fullVersionArgs())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(string); !ok || got != "8.0.36" {
		t.Fatalf("version = %#v", value)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, wantVersionFullArgv) {
		t.Fatalf("argv = %q", argv)
	}
	if argv := append([]string{command.Name}, command.Args...); argv[6] != "--execute="+selectVersionQuery {
		t.Fatalf("argv[6] = %q, want the pinned version query", argv[6])
	}
	if want := []string{"MYSQL_PWD=test_pass"}; !reflect.DeepEqual(command.Env, want) {
		t.Fatalf("env = %q, want %q", command.Env, want)
	}
	if command.Shell {
		t.Fatal("version must never run through a shell")
	}
	if !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if command.Timeout != 30*time.Second || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("bounds: timeout=%v stdout=%d stderr=%d", command.Timeout, command.MaxStdoutBytes, command.MaxStderrBytes)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
}

// TestMysqlVersionShapes pins the bare argv, the MariaDB answer, the
// batch-decoded and CRLF-framed answers, and the pinned empty-string
// compatibility data: the _connect-None path, the OperationalError path,
// and the fetchone IndexError all answer "" with a zero error.
func TestMysqlVersionShapes(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("VERSION()\n10.11.6-MariaDB\n"),
	})
	value, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(string); !ok || got != "10.11.6-MariaDB" {
		t.Fatalf("bare version = %#v", value)
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=" + selectVersionQuery}) {
		t.Fatalf("bare argv = %q", argv)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("bare env = %#v, want the clean empty environment", command.Env)
	}
	if command.Redact != nil {
		t.Fatalf("bare redact = %q, want none", command.Redact)
	}

	// CRLF framing decodes identically, header included.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("VERSION()\r\n8.0.36\r\n"),
	})
	if value, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(string); !ok || got != "8.0.36" {
		t.Fatalf("CRLF version = %#v", value)
	}

	// A batch-escaped answer decodes: the doubled backslash collapses.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("VERSION()\n8.0.36-0ubuntu0.22.04.1\\\\log\n"),
	})
	if value, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(string); !ok || got != `8.0.36-0ubuntu0.22.04.1\log` {
		t.Fatalf("escaped version = %#v", value)
	}

	for _, tc := range []struct {
		name   string
		stdout string
	}{
		{"empty-stdout", ""},
		{"header-only", "VERSION()\n"},
		{"empty-crlf", "VERSION()\r\n"},
	} {
		rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got, ok := value.(string); !ok || got != "" {
			t.Fatalf("%s version = %#v, want the pinned empty string", tc.name, value)
		}
	}

	// The pinned _connect-None and OperationalError paths answer "".
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte("ERROR 1045 (28000): Access denied\n"),
	})
	if value, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok := value.(string); !ok || got != "" {
		t.Fatalf("nonzero-exit version = %#v", value)
	}
}

// TestMysqlVersionFailClosed pins the shared error boundaries on the
// version probe: no Runner, an unavailable mysql client, an explicit
// runas, and a cancelled context all fail before any Runner invocation,
// Runner failures and output-limit violations are errors, and a Runner
// error carrying the connection password is returned redacted.
func TestMysqlVersionFailClosed(t *testing.T) {
	_, err := (versionFunc{}).Execute(context.Background(), &runtime.Runtime{}, &VersionArgs{})
	if !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}

	runner := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	rt := &runtime.Runtime{Runner: runner}
	if _, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); !errors.Is(err, errMysqlClientUnavailable) {
		t.Fatalf("unavailable client error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable client made %d calls", len(runner.calls))
	}

	for _, tc := range []struct {
		name string
		args *VersionArgs
		want error
	}{
		{"runas", &VersionArgs{Runas: mysqlString("mysql")}, errMysqlRunas},
		{"runas-invalid", &VersionArgs{Runas: mysqlString("root\n")}, errMysqlInvalidArgument},
	} {
		runner := &mysqlFakeRunner{}
		rt := &runtime.Runtime{Runner: runner}
		_, err := (versionFunc{}).Execute(context.Background(), rt, tc.args)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s error = %v, want %v", tc.name, err, tc.want)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s made %d calls, want 0", tc.name, len(runner.calls))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	rt = &runtime.Runtime{Runner: runner}
	if _, err = (versionFunc{}).Execute(ctx, rt, &VersionArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("cancelled call made %d calls", len(runner.calls))
	}

	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
	if _, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); err == nil || err.Error() != "boom" {
		t.Fatalf("runner error = %v", err)
	}

	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StdoutTruncated: true})
	if _, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error = %v", err)
	}

	marker := "S3CRET-mysql-pass"
	rt, _ = newMysqlRuntime(process.CommandResult{
		Err: errors.New("mysql failed with " + marker),
	})
	_, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// TestMysqlStatus pins the status contract: the exact pinned qry
// SHOW STATUS, the name→value dict shape with the pinned
// later-row-overwrites loop, batch-escaped and CRLF-framed values, the
// literal NULL string staying a value, and the pinned {} compatibility
// data on every empty or failing shape.
func TestMysqlStatus(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Variable_name\tValue\n" +
			"Uptime\t347\n" +
			"Threads_connected\t1\n" +
			"Ssl_cipher\t\n"),
	})
	value, err := (statusFunc{}).Execute(context.Background(), rt, fullStatusArgs())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Uptime": "347", "Threads_connected": "1", "Ssl_cipher": ""}
	if got, ok := value.(map[string]string); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %#v, want %#v", value, want)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch",
		"--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=" + showStatusQuery,
	}) {
		t.Fatalf("argv = %q", argv)
	}

	// A later duplicate row overwrites the earlier value exactly like the
	// pinned ret[row[0]] = row[1] loop.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Variable_name\tValue\nUptime\t347\nUptime\t999\n"),
	})
	value, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(map[string]string); !ok || got["Uptime"] != "999" || len(got) != 1 {
		t.Fatalf("duplicate status = %#v", value)
	}

	// Batch escaping, both framings, a raw non-delimiter CR, the literal
	// string NULL, and a one-field row (impossible from the real client)
	// staying skipped.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Variable_name\tValue\r\n" +
			"win\\\\path\tC:\\\\data\r\n" +
			"we\\tird\tval\\nue\r\n" +
			"carriage\tva\rl\r\n" +
			"NULL\tNULL\r\n" +
			"onlyname\r\n"),
	})
	value, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]string{
		`win\path`: `C:\data`,
		"we\tird":  "val\nue",
		"carriage": "va\rl",
		"NULL":     "NULL",
	}
	if got, ok := value.(map[string]string); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded status = %#v, want %#v", value, want)
	}

	for _, tc := range []struct {
		name   string
		stdout string
	}{
		{"empty-stdout", ""},
		{"header-only", "Variable_name\tValue\n"},
	} {
		rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got, ok := value.(map[string]string); !ok || len(got) != 0 {
			t.Fatalf("%s status = %#v, want the pinned empty dict", tc.name, value)
		}
	}

	// The pinned _connect-None and OperationalError paths answer {}.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte("ERROR 2002 (HY000): Can't connect\n"),
	})
	if value, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{}); err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok := value.(map[string]string); !ok || len(got) != 0 {
		t.Fatalf("nonzero-exit status = %#v", value)
	}

	// The shared fail-closed boundaries.
	_, err = (statusFunc{}).Execute(context.Background(), &runtime.Runtime{}, &StatusArgs{})
	if !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}
	unavailable := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	if _, err = (statusFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: unavailable}, &StatusArgs{}); !errors.Is(err, errMysqlClientUnavailable) {
		t.Fatalf("unavailable client error = %v", err)
	}
	preflight := &mysqlFakeRunner{}
	if _, err = (statusFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: preflight}, &StatusArgs{Runas: mysqlString("mysql")}); !errors.Is(err, errMysqlRunas) {
		t.Fatalf("runas error = %v", err)
	}
	if len(preflight.calls) != 0 {
		t.Fatalf("runas made %d calls, want 0", len(preflight.calls))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := &mysqlFakeRunner{}
	if _, err = (statusFunc{}).Execute(ctx, &runtime.Runtime{Runner: cancelled}, &StatusArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
	if _, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{}); err == nil || err.Error() != "boom" {
		t.Fatalf("runner error = %v", err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StdoutTruncated: true})
	if _, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error = %v", err)
	}
	marker := "S3CRET-mysql-pass"
	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("mysql failed with " + marker)})
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// fullStatusArgs carries every connection argument at once.
func fullStatusArgs() *StatusArgs {
	return &StatusArgs{
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// TestMysqlShowVariables pins the showvariables contract: the exact pinned
// qry SHOW VARIABLES, the row-dict list keyed by the batch header, the
// pinned [[ ]] empty-result quirk, the bare [] _connect-failure shape on
// a nonzero exit, and the prefix-zip of short rows.
func TestMysqlShowVariables(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Variable_name\tValue\n" +
			"max_connections\t151\n" +
			"sql_mode\tNO_ENGINE_SUBSTITUTION\n"),
	})
	value, err := (showVariablesFunc{}).Execute(context.Background(), rt, fullShowVariablesArgs())
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]string{"Variable_name": "max_connections", "Value": "151"},
		map[string]string{"Variable_name": "sql_mode", "Value": "NO_ENGINE_SUBSTITUTION"},
	}
	if got, ok := value.([]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("showvariables = %#v, want %#v", value, want)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch",
		"--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=" + showVariablesQuery,
	}) {
		t.Fatalf("argv = %q", argv)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); argv[6] != "--execute="+showVariablesQuery {
		t.Fatalf("argv[6] = %q, want the pinned variables query", argv[6])
	}

	// Intentional divergence from the pinned helper's Python IndexError:
	// malformed short rows retain their available prefix without a panic.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Variable_name\tValue\nonlyname\n"),
	})
	value, err = (showVariablesFunc{}).Execute(context.Background(), rt, &ShowVariablesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || !reflect.DeepEqual(got, []any{
		map[string]string{"Variable_name": "onlyname"},
	}) {
		t.Fatalf("short-row showvariables = %#v", value)
	}

	// A successful query answering no rows hits the pinned
	// `if not rtnv: rtnv.append([])` quirk: [[ ]] renders with the empty
	// inner list.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Variable_name\tValue\n"),
	})
	value, err = (showVariablesFunc{}).Execute(context.Background(), rt, &ShowVariablesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || len(got) != 1 {
		t.Fatalf("empty showvariables = %#v, want the pinned one-element quirk", value)
	} else if encoded, marshalErr := json.Marshal(got); marshalErr != nil || string(encoded) != "[[]]" {
		t.Fatalf("empty showvariables renders %s (%v), want [[]]", encoded, marshalErr)
	}

	// The pinned _connect-None path answers the bare empty list; the
	// renderings of [] and [[]] differ exactly like Salt's.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 1,
		Stderr:   []byte("ERROR 1045 (28000): Access denied\n"),
	})
	value, err = (showVariablesFunc{}).Execute(context.Background(), rt, &ShowVariablesArgs{})
	if err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok := value.([]any); !ok || len(got) != 0 {
		t.Fatalf("nonzero-exit showvariables = %#v, want the bare empty list", value)
	} else if encoded, marshalErr := json.Marshal(got); marshalErr != nil || string(encoded) != "[]" {
		t.Fatalf("nonzero-exit showvariables renders %s, want []", encoded)
	}
}

// fullShowVariablesArgs carries every connection argument at once.
func fullShowVariablesArgs() *ShowVariablesArgs {
	return &ShowVariablesArgs{
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// TestMysqlShowGlobal pins the showglobal contract: the exact pinned qry
// SHOW GLOBAL VARIABLES — variables, not status — with the same shapes,
// decoding, and quirks as showvariables.
func TestMysqlShowGlobal(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Variable_name\tValue\r\n" +
			"max_connections\t151\r\n" +
			"datadir\tC:\\\\ProgramData\\\\MySQL\\\\\r\n" +
			"we\\\\ird\t\\\\n\r\n"),
	})
	value, err := (showGlobalFunc{}).Execute(context.Background(), rt, &ShowGlobalArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]string{"Variable_name": "max_connections", "Value": "151"},
		map[string]string{"Variable_name": "datadir", "Value": `C:\ProgramData\MySQL\`},
		map[string]string{"Variable_name": `we\ird`, "Value": `\n`},
	}
	if got, ok := value.([]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("showglobal = %#v, want %#v", value, want)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv,
		[]string{"mysql", "--batch", "--execute=" + showGlobalVariablesQuery}) {
		t.Fatalf("argv = %q", argv)
	}

	// The pinned empty shapes: [[]] on a rowless success, [] on a
	// nonzero exit.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Variable_name\tValue\n")})
	value, err = (showGlobalFunc{}).Execute(context.Background(), rt, &ShowGlobalArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || len(got) != 1 {
		t.Fatalf("empty showglobal = %#v, want the pinned one-element quirk", value)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	if value, err = (showGlobalFunc{}).Execute(context.Background(), rt, &ShowGlobalArgs{}); err != nil {
		t.Fatalf("nonzero exit must be compatibility data: %v", err)
	}
	if got, ok := value.([]any); !ok || len(got) != 0 {
		t.Fatalf("nonzero-exit showglobal = %#v", value)
	}
}

// TestMysqlServerFactsFailClosed pins the remaining shared boundaries of
// the show pair: no Runner, unavailable client, cancellation, Runner
// failures, and output limits.
func TestMysqlServerFactsFailClosed(t *testing.T) {
	for _, call := range []struct {
		name string
		run  func(ctx context.Context, rt *runtime.Runtime) (any, error)
	}{
		{"showvariables", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (showVariablesFunc{}).Execute(ctx, rt, &ShowVariablesArgs{})
		}},
		{"showglobal", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (showGlobalFunc{}).Execute(ctx, rt, &ShowGlobalArgs{})
		}},
	} {
		if _, err := call.run(context.Background(), &runtime.Runtime{}); !errors.Is(err, errMysqlRunnerUnavailable) {
			t.Fatalf("%s nil runner error = %v", call.name, err)
		}
		unavailable := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
		if _, err := call.run(context.Background(), &runtime.Runtime{Runner: unavailable}); !errors.Is(err, errMysqlClientUnavailable) {
			t.Fatalf("%s unavailable client error = %v", call.name, err)
		}
		if len(unavailable.calls) != 0 {
			t.Fatalf("%s unavailable client made %d calls", call.name, len(unavailable.calls))
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cancelled := &mysqlFakeRunner{}
		if _, err := call.run(ctx, &runtime.Runtime{Runner: cancelled}); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s cancelled error = %v", call.name, err)
		}
		if len(cancelled.calls) != 0 {
			t.Fatalf("%s cancelled made %d calls, want 0", call.name, len(cancelled.calls))
		}
		rt, _ := newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
		if _, err := call.run(context.Background(), rt); err == nil || err.Error() != "boom" {
			t.Fatalf("%s runner error = %v", call.name, err)
		}
		rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StderrTruncated: true})
		if _, err := call.run(context.Background(), rt); !errors.Is(err, process.ErrOutputLimit) {
			t.Fatalf("%s output limit error = %v", call.name, err)
		}
	}
}

// TestMysqlServerFactsRunasRejected pins the runas rejection before any
// Runner invocation for the whole R9.3b family.
func TestMysqlServerFactsRunasRejected(t *testing.T) {
	calls := []struct {
		name string
		run  func(rt *runtime.Runtime) (any, error)
	}{
		{"version", func(rt *runtime.Runtime) (any, error) {
			return (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Runas: mysqlString("mysql")})
		}},
		{"status", func(rt *runtime.Runtime) (any, error) {
			return (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{Runas: mysqlString("mysql")})
		}},
		{"showvariables", func(rt *runtime.Runtime) (any, error) {
			return (showVariablesFunc{}).Execute(context.Background(), rt, &ShowVariablesArgs{Runas: mysqlString("mysql")})
		}},
		{"showglobal", func(rt *runtime.Runtime) (any, error) {
			return (showGlobalFunc{}).Execute(context.Background(), rt, &ShowGlobalArgs{Runas: mysqlString("mysql")})
		}},
	}
	for _, call := range calls {
		runner := &mysqlFakeRunner{}
		if _, err := call.run(&runtime.Runtime{Runner: runner}); !errors.Is(err, errMysqlRunas) {
			t.Fatalf("%s runas error = %v", call.name, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s runas made %d calls, want 0", call.name, len(runner.calls))
		}
	}
}

// TestMysqlServerFactsThroughRegistry drives the four functions through
// the execution registry on the same fake Runner: the registry path
// answers the same results with the same single call each.
func TestMysqlServerFactsThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.36\n")},
	}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.version", &VersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(string); !ok || got != "8.0.36" {
		t.Fatalf("registry version = %#v", value)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\nUptime\t347\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.status", &StatusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(map[string]string); !ok || !reflect.DeepEqual(got, map[string]string{"Uptime": "347"}) {
		t.Fatalf("registry status = %#v", value)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\nmax_connections\t151\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.showvariables", &ShowVariablesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || !reflect.DeepEqual(got, []any{
		map[string]string{"Variable_name": "max_connections", "Value": "151"},
	}) {
		t.Fatalf("registry showvariables = %#v", value)
	}

	// This vector checks the rowless showglobal result; exact JSON and
	// nonzero-exit shapes are covered by TestMysqlRegistryEmptyShapes.
	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.showglobal", &ShowGlobalArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || len(got) != 1 {
		t.Fatalf("registry empty showglobal = %#v, want the pinned quirk", value)
	}
	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Variable_name\tValue\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.showvariables", &ShowVariablesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.([]any); !ok {
		t.Fatalf("registry showvariables = %#v", value)
	}

	if len(runner.calls) != 5 {
		t.Fatalf("registry path made %d calls, want 5", len(runner.calls))
	}
}

func TestMysqlRegistryEmptyShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    any
		header  string
		rowless string
	}{
		{"mysql.showvariables", &ShowVariablesArgs{}, "Variable_name\tValue\n", "[[]]"},
		{"mysql.showglobal", &ShowGlobalArgs{}, "Variable_name\tValue\n", "[[]]"},
		{"mysql.user_list", &UserListArgs{}, "User\tHost\n", "[]"},
		{"mysql.db_list", &DbListArgs{}, "Database\n", "[]"},
	} {
		for _, shape := range []struct {
			name   string
			result process.CommandResult
			want   string
		}{
			{"nonzero", process.CommandResult{ExitCode: 1, Stdout: []byte(tc.header + "ignored\tvalue\n")}, "[]"},
			{"header-only", process.CommandResult{Stdout: []byte(tc.header)}, tc.rowless},
			{"empty-stdout", process.CommandResult{}, tc.rowless},
		} {
			t.Run(tc.name+"/"+shape.name, func(t *testing.T) {
				rt, runner := newMysqlRuntime(shape.result)
				rt.Exec = runtime.NewExecRegistry()
				if err := Register(rt.Exec); err != nil {
					t.Fatal(err)
				}
				value, err := rt.Exec.Call(context.Background(), rt, tc.name, tc.args)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(value)
				if err != nil || string(encoded) != shape.want || len(runner.calls) != 1 {
					t.Fatalf("shape=%s error=%v calls=%d; want %s and one call", encoded, err, len(runner.calls), shape.want)
				}
			})
		}
	}
}

// The pinned __do_query_into_hash indexes row[i] for each described column:
// a one-field row under a two-column description raises Python IndexError.
// These source-derived vectors deliberately assert a different Go outcome,
// not Python execution or pinned malformed-row parity.
func TestMysqlShowShortRowDefensiveDivergence(t *testing.T) {
	marker := "synthetic-short-row-password"
	for _, query := range []string{showVariablesQuery, showGlobalVariablesQuery} {
		t.Run(query, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte("Variable_name\tValue\nonlyname\n")})
			got, err := showCatalog(context.Background(), rt, (&ShowVariablesArgs{Password: &marker}).connection(), query)
			if err != nil || !reflect.DeepEqual(got, []any{map[string]string{"Variable_name": "onlyname"}}) {
				t.Fatal("short row must return only its prefix, not IndexError or a fabricated Value")
			}
			encoded, err := json.Marshal(got)
			if err != nil || strings.Contains(string(encoded), marker) || len(runner.calls) != 1 || strings.Contains(runner.calls[0].RedactedString(), marker) {
				t.Fatal("short-row result or rendered command failed synthetic secret guard")
			}
		})
	}
}

func TestMysqlRegistryRunnerErrorRedaction(t *testing.T) {
	marker := "synthetic-registry-runner-password"
	for _, tc := range []struct {
		name string
		args any
	}{
		{"mysql.version", &VersionArgs{Password: &marker}},
		{"mysql.status", &StatusArgs{Password: &marker}},
		{"mysql.showvariables", &ShowVariablesArgs{Password: &marker}},
		{"mysql.showglobal", &ShowGlobalArgs{Password: &marker}},
		{"mysql.user_list", &UserListArgs{Password: &marker}},
		{"mysql.db_list", &DbListArgs{Password: &marker}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{Err: errors.New("runner failed: " + marker)})
			rt.Exec = runtime.NewExecRegistry()
			if err := Register(rt.Exec); err != nil {
				t.Fatal(err)
			}
			_, err := rt.Exec.Call(context.Background(), rt, tc.name, tc.args)
			if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "runner failed:") || len(runner.calls) != 1 {
				t.Fatal("registry must return a redacted Runner error after one call")
			}
			if !reflect.DeepEqual(runner.calls[0].Redact, []string{marker}) || strings.Contains(runner.calls[0].RedactedString(), marker) {
				t.Fatal("registry command failed synthetic secret guard")
			}
		})
	}
}

// TestMysqlProviderRunnerErrorRedaction closes the direct-coverage gap the
// registry-level TestMysqlRegistryRunnerErrorRedaction leaves for the
// three functions whose direct tests carried no marker-bearing synthetic
// Runner error: user_list, showvariables, and showglobal (db_list,
// status, and version pin theirs inside their fail-closed tests). The
// synthetic Runner result carries the same connection password marker in
// the error, stdout, and stderr at once. The provider surface is asserted
// first: a value-free redacted error that keeps the synthetic error's
// non-secret class, exactly one Runner call over the fixed query-only
// argv, the marker as the single Redact secret with a marker-free
// rendered command, the password riding only the out-of-band MYSQL_PWD
// environment, and the caller's args left unmutated. The providers
// discard the sanitized CommandResult on the error path, so the captured
// stdout/stderr redaction of the same synthetic vector is pinned through
// the shared transport on each function's exact argv. The rowless and
// nonzero-exit compatibility shapes stay pinned by the dedicated shape
// tests and are deliberately not re-asserted here.
func TestMysqlProviderRunnerErrorRedaction(t *testing.T) {
	marker := "S3CRET-mysql-pass"
	userList := &UserListArgs{Password: mysqlString(marker)}
	showVariables := &ShowVariablesArgs{Password: mysqlString(marker)}
	showGlobal := &ShowGlobalArgs{Password: mysqlString(marker)}
	for _, tc := range []struct {
		name       string
		query      string
		args       any
		connection func() *myConnection
		run        func(rt *runtime.Runtime) (any, error)
	}{
		{"user_list", userListQuery, userList, userList.connection, func(rt *runtime.Runtime) (any, error) {
			return (userListFunc{}).Execute(context.Background(), rt, userList)
		}},
		{"showvariables", showVariablesQuery, showVariables, showVariables.connection, func(rt *runtime.Runtime) (any, error) {
			return (showVariablesFunc{}).Execute(context.Background(), rt, showVariables)
		}},
		{"showglobal", showGlobalVariablesQuery, showGlobal, showGlobal.connection, func(rt *runtime.Runtime) (any, error) {
			return (showGlobalFunc{}).Execute(context.Background(), rt, showGlobal)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := process.CommandResult{
				Err:    errors.New("mysql failed with " + marker),
				Stdout: []byte("stdout leak " + marker + "\n"),
				Stderr: []byte("stderr leak " + marker + "\n"),
			}
			before := reflect.ValueOf(tc.args).Elem().Interface()
			rt, runner := newMysqlRuntime(result)
			value, err := tc.run(rt)
			if err == nil {
				t.Fatalf("%s = (%#v, nil), want the Runner error", tc.name, value)
			}
			// The providers answer the typed nil of their pinned result
			// shape alongside the error; any non-nil data would be a leak.
			if value != nil && !reflect.ValueOf(value).IsNil() {
				t.Fatalf("%s returned data alongside the error: %#v", tc.name, value)
			}
			if strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "mysql failed with") {
				t.Fatalf("%s error = %v, want the redacted class-preserving Runner error", tc.name, err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("%s made %d Runner calls, want exactly 1", tc.name, len(runner.calls))
			}
			command := runner.calls[0]
			if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv,
				[]string{"mysql", "--batch", "--execute=" + tc.query}) {
				t.Fatalf("%s argv = %q, want the fixed query-only argv", tc.name, argv)
			}
			if !reflect.DeepEqual(command.Redact, []string{marker}) {
				t.Fatalf("%s redact inventory = %q, want exactly the marker", tc.name, command.Redact)
			}
			if rendered := command.RedactedString(); strings.Contains(rendered, marker) {
				t.Fatalf("%s rendered command leaks the marker: %q", tc.name, rendered)
			}
			if want := []string{"MYSQL_PWD=" + marker}; !reflect.DeepEqual(command.Env, want) {
				t.Fatalf("%s env = %q, want the out-of-band password channel %q", tc.name, command.Env, want)
			}
			if after := reflect.ValueOf(tc.args).Elem().Interface(); !reflect.DeepEqual(after, before) {
				t.Fatalf("%s mutated caller args: before=%#v after=%#v", tc.name, before, after)
			}

			// The captured stdout/stderr the transport sanitizes on the
			// Runner-error path — and would hand to any non-error
			// consumer — pinned through runMysql on this function's
			// exact argv and connection.
			conn := tc.connection()
			rt, runner = newMysqlRuntime(result)
			transportResult, transportErr := runMysql(context.Background(), rt, mysqlQueryArgv(conn, tc.query), conn)
			if transportErr == nil || strings.Contains(transportErr.Error(), marker) {
				t.Fatalf("%s transport error = %v, want the redacted Runner error", tc.name, transportErr)
			}
			if strings.Contains(string(transportResult.Stdout), marker) || strings.Contains(string(transportResult.Stderr), marker) {
				t.Fatalf("%s captured output leaks the marker: stdout=%q stderr=%q",
					tc.name, transportResult.Stdout, transportResult.Stderr)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("%s transport made %d Runner calls, want exactly 1", tc.name, len(runner.calls))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R9.3c maintenance family (db_check, db_repair, db_optimize) over the
// central mysql CLI transport. Every test runs on a fake Runner: no mysql
// binary is executed and no server is contacted — REPAIR and OPTIMIZE are
// mutations, so no partial fake success may ever be answered.

// maintenanceCheckStdout is the canonical CHECK TABLE batch output: the
// four result columns (Table, Op, Msg_type, Msg_text) the pinned
// DictCursor would return as one dict row.
const maintenanceCheckStdout = "Table\tOp\tMsg_type\tMsg_text\n" +
	"`test_db`.`test_tbl`\tcheck\tstatus\tOK\n"

// fullMaintenanceArgs carries every connection argument at once.
func fullMaintenanceArgs() *DbMaintenanceArgs {
	return &DbMaintenanceArgs{
		Name:     "test_db",
		Table:    mysqlString("test_tbl"),
		User:     mysqlString("test_user"),
		Host:     mysqlString("test_host"),
		Port:     mysqlString("test_port"),
		Password: mysqlString("test_pass"),
		DB:       mysqlString("test_maint"),
	}
}

// TestMysqlMaintenanceSingleTable pins the transport contract of the
// whole family through db_check: exact batch-mode argv with the joined
// connection flags and the quoted statement at argv index 6, the
// MYSQL_PWD-only clean environment, the password as the single Redact
// secret, the 30s timeout and 4 MiB output caps, and the pinned
// DictCursor fetchall shape — one map per row keyed by the result column
// names. The REPAIR and OPTIMIZE verbs ride the identical shape.
func TestMysqlMaintenanceSingleTable(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(maintenanceCheckStdout),
	})
	value, err := (dbCheckFunc{}).Execute(context.Background(), rt, fullMaintenanceArgs())
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{{
		"Table":    "`test_db`.`test_tbl`",
		"Op":       "check",
		"Msg_type": "status",
		"Msg_text": "OK",
	}}
	if got, ok := value.([]map[string]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("db_check = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch",
		"--user=test_user", "--host=test_host", "--port=test_port", "--database=test_maint",
		"--execute=CHECK TABLE `test_db`.`test_tbl`",
	}) {
		t.Fatalf("argv = %q", argv)
	}
	// The index-6 statement assertion, checked directly.
	if argv := append([]string{command.Name}, command.Args...); argv[6] != "--execute=CHECK TABLE `test_db`.`test_tbl`" {
		t.Fatalf("argv[6] = %q, want the maintenance statement", argv[6])
	}
	if want := []string{"MYSQL_PWD=test_pass"}; !reflect.DeepEqual(command.Env, want) {
		t.Fatalf("env = %q, want %q", command.Env, want)
	}
	if command.Shell {
		t.Fatal("db_check must never run through a shell")
	}
	if !reflect.DeepEqual(command.Redact, []string{"test_pass"}) {
		t.Fatalf("redact = %q", command.Redact)
	}
	if command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("bounds: timeout=%v stdout=%d stderr=%d", command.Timeout, command.MaxStdoutBytes, command.MaxStderrBytes)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}

	// The bare argv without connection arguments.
	rt, runner = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(maintenanceCheckStdout),
	})
	if _, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "test_db", Table: mysqlString("test_tbl")}); err != nil {
		t.Fatal(err)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--execute=CHECK TABLE `test_db`.`test_tbl`",
	}) {
		t.Fatalf("bare argv = %q", argv)
	}

	// The REPAIR and OPTIMIZE verbs ride the identical contract.
	for _, tc := range []struct {
		verb string
		op   string
	}{
		{"REPAIR", "repair"},
		{"OPTIMIZE", "optimize"},
	} {
		rt, runner := newMysqlRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`test_tbl`\t" +
				tc.op + "\tstatus\tOK\n"),
		})
		var value any
		var err error
		switch tc.verb {
		case "REPAIR":
			value, err = (dbRepairFunc{}).Execute(context.Background(), rt, fullMaintenanceArgs())
		default:
			value, err = (dbOptimizeFunc{}).Execute(context.Background(), rt, fullMaintenanceArgs())
		}
		if err != nil {
			t.Fatal(err)
		}
		got, ok := value.([]map[string]any)
		if !ok || len(got) != 1 || got[0]["Op"] != tc.op {
			t.Fatalf("%s = %#v", tc.verb, value)
		}
		if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); argv[6] != "--execute="+tc.verb+" TABLE `test_db`.`test_tbl`" {
			t.Fatalf("%s argv[6] = %q", tc.verb, argv[6])
		}
	}
}

// TestMysqlMaintenanceQuoting pins the statement construction: the
// committed quoteIdentifier's backtick doubling and MySQLdb's doubled
// percent, with the pinned _execute no-args unescape restoring single
// percent signs, so the --execute string is byte-identical to the SQL
// the pinned module sends through MySQLdb. The underscore stays raw
// (for_grants is false — these are not grant positions).
func TestMysqlMaintenanceQuoting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		table     string
		statement string
	}{
		{"my_%db", "t1", "CHECK TABLE `my_%db`.`t1`"},
		{"foo`bar", "ba`z", "CHECK TABLE `foo``bar`.`ba``z`"},
		{"a_b", "c_d", "CHECK TABLE `a_b`.`c_d`"},
		{"p_%`q", "x`_y%", "CHECK TABLE `p_%``q`.`x``_y%`"},
	} {
		rt, runner := newMysqlRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("Table\tOp\tMsg_type\tMsg_text\nx\tcheck\tstatus\tOK\n"),
		})
		_, err := (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: tc.name, Table: mysqlString(tc.table)})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); argv[len(argv)-1] != "--execute="+tc.statement {
			t.Fatalf("%s statement = %q, want %q", tc.name, argv[len(argv)-1], "--execute="+tc.statement)
		}
	}
}

// TestMysqlMaintenanceAllTables pins the table=None flow: the fixed
// SCHEMATA catalog with the client-side database match, the fixed
// information_schema.TABLES catalog filtered to the schema in result
// order (the order the pinned SHOW TABLES returns — deliberately not
// sorted here to prove order preservation), and then one CHECK TABLE
// statement per table in that order, with the pinned
// ret.append(fetchall) list-of-lists shape.
func TestMysqlMaintenanceAllTables(t *testing.T) {
	const orderedQuery = "SELECT COALESCE(TABLE_SCHEMA, UNHEX('00')) AS TABLE_SCHEMA, COALESCE(TABLE_NAME, UNHEX('00')) AS TABLE_NAME FROM information_schema.TABLES ORDER BY information_schema.TABLES.TABLE_NAME"
	if tableCatalogQuery != orderedQuery {
		t.Fatal("table catalog must order the original server column, not its binary COALESCE alias")
	}
	rt, runner := newMysqlRuntime(
		process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("SCHEMA_NAME\ninformation_schema\nmysql\ntest_db\n"),
		},
		process.CommandResult{
			ExitCode: 0,
			Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\n" +
				"mysql\tglobal_priv\n" +
				"test_db\tsecond\n" +
				"other_db\tforeign\n" +
				"test_db\tfirst\n"),
		},
		process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`second`\tcheck\tstatus\tOK\n"),
		},
		process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("Table\tOp\tMsg_type\tMsg_text\n`test_db`.`first`\tcheck\terror\tCorrupt\n"),
		},
	)
	value, err := (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "test_db"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("db_check all-tables = %#v, want two per-table results", value)
	}
	first, ok := got[0].([]map[string]any)
	if !ok || !reflect.DeepEqual(first, []map[string]any{{
		"Table": "`test_db`.`second`", "Op": "check", "Msg_type": "status", "Msg_text": "OK",
	}}) {
		t.Fatalf("first table result = %#v", got[0])
	}
	second, ok := got[1].([]map[string]any)
	if !ok || !reflect.DeepEqual(second, []map[string]any{{
		"Table": "`test_db`.`first`", "Op": "check", "Msg_type": "error", "Msg_text": "Corrupt",
	}}) {
		t.Fatalf("second table result = %#v", got[1])
	}
	if len(runner.calls) != 4 {
		t.Fatalf("runner calls = %d, want 4", len(runner.calls))
	}
	wantArgv := [][]string{
		{"mysql", "--batch", "--execute=" + showDatabasesQuery},
		{"mysql", "--batch", "--execute=" + tableCatalogQuery},
		{"mysql", "--batch", "--execute=CHECK TABLE `test_db`.`second`"},
		{"mysql", "--batch", "--execute=CHECK TABLE `test_db`.`first`"},
	}
	for i, want := range wantArgv {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if !reflect.DeepEqual(argv, want) {
			t.Fatalf("call %d argv = %q, want %q", i, argv, want)
		}
	}
}

// Synthetic markers below are test data, not credentials. Both raw schema
// matching and raw table quoting must survive a substring redaction collision.
func TestMysqlMaintenanceRawCatalog(t *testing.T) {
	marker := "catalog-marker"
	name := "db_" + marker
	table := "t_" + marker + "`%\\tail"
	wireTable := strings.ReplaceAll(table, "\\", "\\\\")
	for _, verb := range []string{"CHECK", "REPAIR", "OPTIMIZE"} {
		t.Run(verb, func(t *testing.T) {
			for _, failAt := range []int{-1, 0, 1, 2} {
				results := []process.CommandResult{
					{Stdout: []byte("SCHEMA_NAME\n" + name + "\n")},
					{Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\nother\tignored\n" + name + "\t" + wireTable + "\n")},
					{Stdout: []byte("Table\tMsg_text\n" + name + "." + wireTable + "\t" + marker + "\n")},
				}
				if failAt >= 0 {
					results[failAt].Err = errors.New("runner: " + marker)
				}
				rt, runner := newMysqlRuntime(results...)
				value, err := dbMaintenance(context.Background(), rt, &myConnection{Password: &marker}, verb, name, nil)
				if failAt >= 0 {
					if err == nil || err.Error() != "runner: "+process.RedactedPlaceholder || value != nil || len(runner.calls) != failAt+1 {
						t.Fatalf("phase %d did not fail safely", failAt)
					}
				} else if err != nil || strings.Contains(fmt.Sprint(value), marker) || len(runner.calls) != 3 {
					t.Fatal("raw catalog did not produce safe maintenance output")
				}
				for i, command := range runner.calls {
					if i < 2 {
						if len(command.Redact) != 0 || strings.Contains(command.Args[len(command.Args)-1], marker) {
							t.Fatal("fixed catalogs must defer output redaction and contain no caller value")
						}
					} else {
						want := "--execute=" + verb + " TABLE `" + name + "`.`t_" + marker + "``%\\tail`"
						if command.Args[len(command.Args)-1] != want || strings.Contains(command.RedactedString(), marker) {
							t.Fatal("maintenance must execute the original identifier but render a safe command")
						}
					}
				}
			}
		})
	}
}

func TestMysqlMaintenanceCatalogSourceOrder(t *testing.T) {
	// Deliberately not Go-sorted: the fake result is authoritative, just as
	// ORDER BY on the server's column collation is authoritative in production.
	for _, verb := range []string{"CHECK", "REPAIR", "OPTIMIZE"} {
		rt, runner := newMysqlRuntime(
			process.CommandResult{Stdout: []byte("SCHEMA_NAME\ndb\n")},
			process.CommandResult{Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\ndb\tzeta\nother\tignored\ndb\tAlpha\ndb\talpha\n")},
			process.CommandResult{}, process.CommandResult{}, process.CommandResult{},
		)
		if _, err := dbMaintenance(context.Background(), rt, &myConnection{}, verb, "db", nil); err != nil {
			t.Fatal(err)
		}
		if len(runner.calls) != 5 {
			t.Fatalf("%s: expected two catalogs and three statements", verb)
		}
		for i, table := range []string{"zeta", "Alpha", "alpha"} {
			args := runner.calls[i+2].Args
			if args[len(args)-1] != "--execute="+verb+" TABLE `db`.`"+table+"`" {
				t.Fatalf("%s: catalog source order changed at %d", verb, i)
			}
		}
	}
}

func TestMysqlRawCatalogSafeResult(t *testing.T) {
	marker := "catalog-marker"
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   error
	}{
		{"success", process.CommandResult{Stdout: []byte(marker), Stderr: []byte(marker)}, nil},
		{"runner", process.CommandResult{Stdout: []byte(marker), Err: errors.New(marker)}, errors.New(process.RedactedPlaceholder)},
		{"truncated", process.CommandResult{Stdout: []byte(marker), StdoutTruncated: true}, process.ErrOutputLimit},
		{"oversized", process.CommandResult{Stdout: []byte(strings.Repeat("x", outputLimit+1))}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := newMysqlRuntime(tc.result)
			conn := &myConnection{Password: &marker}
			var raw []byte
			safe, err := runMysqlResult(context.Background(), rt, mysqlQueryArgv(conn, tableCatalogQuery), conn, &raw)
			if strings.Contains(string(safe.Stdout)+string(safe.Stderr), marker) {
				t.Fatal("safe result contains raw marker")
			}
			if tc.want == nil {
				if err != nil || string(raw) != marker {
					t.Fatal("raw identifier unavailable after success")
				}
			} else if err == nil || err.Error() != tc.want.Error() || raw != nil {
				t.Fatal("failed catalog exposed raw data or wrong error")
			}
		})
	}
	rt, runner := newMysqlRuntime()
	var raw []byte
	if _, err := runMysqlResult(context.Background(), rt, []string{"mysql", "--execute=SHOW STATUS"}, nil, &raw); !errors.Is(err, errMysqlInvalidArgument) || len(runner.calls) != 0 {
		t.Fatal("raw path accepted a non-catalog query")
	}
}

// TestMysqlMaintenanceShapes pins the remaining result shapes: the empty
// table list (the pinned [] over zero tables), the rowless statement
// success, batch decoding of the result fields with both framings, the
// literal NULL string staying a value, the sentinel mapping to nil, and
// the defensive short-row prefix-zip divergence.
func TestMysqlMaintenanceShapes(t *testing.T) {
	// The database exists but carries no tables: exactly the two catalog
	// calls, zero statements, and the pinned empty list.
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ntest_db\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\nother_db\tx\n")},
	)
	value, err := (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "test_db"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]any); !ok || len(got) != 0 {
		t.Fatalf("empty table list = %#v, want the pinned []", value)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("empty table list made %d calls, want 2", len(runner.calls))
	}

	// A rowless statement success answers the pinned fetchall [] shape.
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n")})
	value, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]map[string]any); !ok || len(got) != 0 {
		t.Fatalf("rowless statement = %#v, want []", value)
	}

	// Batch escaping, CRLF framing, a literal NULL value, a sentinel
	// field rendering nil, and a short row keeping its prefix.
	rt, _ = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\r\n" +
			"db.t\tcheck\tstatus\tOK\r\n" +
			"db.u\tcheck\tnote\tTable\\\\does\\\\not\\\\support\\\\quick\\\\check\r\n" +
			"db.v\tcheck\tNULL\t\\0\r\n" +
			"db.w\tcheck\tstatus\r\n"),
	})
	value, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.([]map[string]any)
	if !ok || len(got) != 4 {
		t.Fatalf("decoded maintenance rows = %#v", value)
	}
	if got[1]["Msg_text"] != `Table\does\not\support\quick\check` {
		t.Fatalf("escaped Msg_text = %#v", got[1]["Msg_text"])
	}
	if got[2]["Msg_type"] != "NULL" || got[2]["Msg_text"] != nil {
		t.Fatalf("literal NULL / sentinel row = %#v", got[2])
	}
	if _, present := got[3]["Msg_text"]; present {
		t.Fatalf("short row fabricated a field: %#v", got[3])
	}
	if got[3]["Msg_type"] != "status" {
		t.Fatalf("short row prefix = %#v", got[3])
	}
}

// TestMysqlMaintenanceMissingDatabase pins the pinned db_tables miss:
// the pinned db_check/db_repair/db_optimize fail on `for table in
// False:` with a TypeError Salt surfaces as a module error; the port
// answers the same failed call with the value-free missing-database
// error after exactly one catalog call and no statement.
func TestMysqlMaintenanceMissingDatabase(t *testing.T) {
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("SCHEMA_NAME\ninformation_schema\nmysql\n"),
	})
	_, err := (dbRepairFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "ghost"})
	if !errors.Is(err, errMysqlDatabaseMissing) {
		t.Fatalf("missing database error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing database made %d calls, want 1", len(runner.calls))
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); argv[len(argv)-1] != "--execute="+showDatabasesQuery {
		t.Fatalf("missing database argv = %q", argv)
	}
	if err.Error() != "mysql: database does not exist" || strings.Contains(err.Error(), "ghost") {
		t.Fatalf("missing database error leaks or misnames: %v", err)
	}
}

// TestMysqlMaintenanceNonzeroExit pins the strict nonzero-aborts policy
// at every phase of both flows: the read-side compatibility mapping of
// the read-only families is refused — a failed catalog or statement is
// an error with no partial success value, exactly the divergence the
// mutation surface requires (the pinned module either raises the
// OperationalError or returns {} on a connect failure the CLI transport
// cannot distinguish).
func TestMysqlMaintenanceNonzeroExit(t *testing.T) {
	nonzero := process.CommandResult{ExitCode: 1, Stderr: []byte("ERROR 2002 (HY000): Can't connect\n")}
	for _, tc := range []struct {
		name    string
		args    *DbMaintenanceArgs
		results []process.CommandResult
		calls   int
	}{
		{"schema-catalog", &DbMaintenanceArgs{Name: "db"}, []process.CommandResult{nonzero}, 1},
		{"table-catalog", &DbMaintenanceArgs{Name: "db"}, []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, nonzero,
		}, 2},
		{"single-statement", &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")}, []process.CommandResult{nonzero}, 1},
		{"second-statement", &DbMaintenanceArgs{Name: "db"}, []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")},
			{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\ndb\tone\ndb\ttwo\n")},
			{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\ndb.one\tcheck\tstatus\tOK\n")},
			nonzero,
		}, 4},
	} {
		rt, runner := newMysqlRuntime(tc.results...)
		value, err := (dbCheckFunc{}).Execute(context.Background(), rt, tc.args)
		if !errors.Is(err, errMysqlMaintenanceExit) {
			t.Fatalf("%s error = %v, want the strict nonzero abort", tc.name, err)
		}
		// The typed nil of the pinned result shape may ride alongside the
		// error; any non-nil data would be a partial success leak.
		if value != nil && !reflect.ValueOf(value).IsNil() {
			t.Fatalf("%s returned data alongside the error: %#v", tc.name, value)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("%s made %d calls, want %d", tc.name, len(runner.calls), tc.calls)
		}
	}
	if err := errMysqlMaintenanceExit.Error(); err != "mysql: maintenance run completed nonzero" {
		t.Fatalf("nonzero error text = %q", err)
	}
}

// TestMysqlMaintenanceFailClosed pins the shared fail-closed boundaries
// of the family: nil Runner, unavailable mysql client, runas rejection,
// cancellation, Runner errors, and output-limit violations — the last
// four with zero or exactly one Runner invocation.
func TestMysqlMaintenanceFailClosed(t *testing.T) {
	_, err := (dbCheckFunc{}).Execute(context.Background(), &runtime.Runtime{}, &DbMaintenanceArgs{Name: "db"})
	if !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil runner error = %v", err)
	}

	runner := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	rt := &runtime.Runtime{Runner: runner}
	if _, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db"}); !errors.Is(err, errMysqlClientUnavailable) {
		t.Fatalf("unavailable client error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unavailable client made %d calls", len(runner.calls))
	}

	for _, tc := range []struct {
		name string
		args *DbMaintenanceArgs
		want error
	}{
		{"runas", &DbMaintenanceArgs{Name: "db", Runas: mysqlString("mysql")}, errMysqlRunas},
		{"runas-invalid", &DbMaintenanceArgs{Name: "db", Runas: mysqlString("root\n")}, errMysqlInvalidArgument},
	} {
		runner := &mysqlFakeRunner{}
		rt := &runtime.Runtime{Runner: runner}
		_, err := (dbOptimizeFunc{}).Execute(context.Background(), rt, tc.args)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s error = %v, want %v", tc.name, err, tc.want)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s made %d calls, want 0", tc.name, len(runner.calls))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	rt = &runtime.Runtime{Runner: runner}
	if _, err = (dbRepairFunc{}).Execute(ctx, rt, &DbMaintenanceArgs{Name: "db"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("cancelled call made %d calls", len(runner.calls))
	}

	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("boom")})
	if _, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")}); err == nil || err.Error() != "boom" {
		t.Fatalf("runner error = %v", err)
	}

	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StdoutTruncated: true})
	if _, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error = %v", err)
	}

	marker := "S3CRET-mysql-pass"
	rt, _ = newMysqlRuntime(process.CommandResult{Err: errors.New("mysql failed with " + marker)})
	_, err = (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString("t"), Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("runner error leaks password: %v", err)
	}
}

// TestMysqlMaintenanceIdentifierBoundary pins the value-free identifier
// rejection: empty, NUL, CR, LF, other C0 controls, and DEL in either
// position are refused before any Runner invocation with the fixed
// invalid-argument error naming only the argument key — a rejected value
// carrying a synthetic secret cannot leak through the error.
func TestMysqlMaintenanceIdentifierBoundary(t *testing.T) {
	invalid := []string{"", "\x00", "a\nb", "a\rb", "a\x01b", "a\x1fb", "a\x7fb", "S3CRET-x\n"}
	for _, key := range []string{"name", "table"} {
		for _, value := range invalid {
			args := &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")}
			if key == "name" {
				args.Name = value
			} else {
				args.Table = mysqlString(value)
			}
			runner := &mysqlFakeRunner{}
			rt := &runtime.Runtime{Runner: runner}
			_, err := (dbCheckFunc{}).Execute(context.Background(), rt, args)
			if !errors.Is(err, errMysqlInvalidArgument) {
				t.Fatalf("%s %q error = %v, want the invalid-argument rejection", key, value, err)
			}
			if err.Error() != "mysql: invalid argument: unsupported identifier in "+key {
				t.Fatalf("%s error text = %q", key, err.Error())
			}
			if strings.Contains(err.Error(), "S3CRET") {
				t.Fatalf("%s error leaks the rejected value: %v", key, err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("%s %q made %d calls, want 0", key, value, len(runner.calls))
			}
		}
	}

	// The accepted class: backticks, percent, underscore, and non-ASCII
	// stay inside the doubled backticks and never reject.
	for _, value := range []string{"foo`bar", "my_%db", "a_b", "täble", "表"} {
		rt, runner := newMysqlRuntime(process.CommandResult{
			ExitCode: 0,
			Stdout:   []byte("Table\tOp\tMsg_type\tMsg_text\nx\tcheck\tstatus\tOK\n"),
		})
		if _, err := (dbCheckFunc{}).Execute(context.Background(), rt, &DbMaintenanceArgs{Name: "db", Table: mysqlString(value)}); err != nil {
			t.Fatalf("accepted identifier %q rejected: %v", value, err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("accepted identifier %q made %d calls", value, len(runner.calls))
		}
	}
}

// TestMysqlMaintenanceThroughRegistry drives all three functions through
// the exec registry: the registry path runs the same statements and
// renders the same JSON shapes as the direct path.
func TestMysqlMaintenanceThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`db`.`t`\trepair\tstatus\tOK\n")},
	}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.db_repair", &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != `[{"Msg_text":"OK","Msg_type":"status","Op":"repair","Table":"`+"`db`.`t`"+`"}]` {
		t.Fatalf("registry db_repair JSON = %s (%v)", encoded, err)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")},
		{ExitCode: 0, Stdout: []byte("TABLE_SCHEMA\tTABLE_NAME\ndb\tt\n")},
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`db`.`t`\toptimize\tstatus\tOK\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_optimize", &DbMaintenanceArgs{Name: "db"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(value)
	if err != nil || string(encoded) != `[[{"Msg_text":"OK","Msg_type":"status","Op":"optimize","Table":"`+"`db`.`t`"+`"}]]` {
		t.Fatalf("registry db_optimize JSON = %s (%v)", encoded, err)
	}

	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Table\tOp\tMsg_type\tMsg_text\n`db`.`t`\tcheck\tstatus\tOK\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.db_check", &DbMaintenanceArgs{Name: "db", Table: mysqlString("t")})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]map[string]any); !ok || got[0]["Op"] != "check" {
		t.Fatalf("registry db_check = %#v", value)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("registry path made %d calls, want 5", len(runner.calls))
	}
}
