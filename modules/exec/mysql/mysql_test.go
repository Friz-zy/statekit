package mysql

import (
	"context"
	"encoding/json"
	"errors"
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
		"mysql.db_exists",
		"mysql.db_list",
		"mysql.quote_identifier",
		"mysql.tokenize_grant",
		"mysql.user_exists",
		"mysql.user_list",
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

	// A short row keeps its zipped prefix exactly like dict(zip(...)).
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
