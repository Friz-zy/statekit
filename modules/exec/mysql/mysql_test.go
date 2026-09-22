package mysql

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
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
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	grants, ok := decoded["grant"].([]any)
	if !ok || len(grants) != 0 {
		t.Fatal("empty grant list did not decode as an empty array")
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
		"mysql.alter_db",
		"mysql.db_check",
		"mysql.db_create",
		"mysql.db_exists",
		"mysql.db_get",
		"mysql.db_list",
		"mysql.db_optimize",
		"mysql.db_repair",
		"mysql.db_remove",
		"mysql.db_tables",
		"mysql.get_master_status",
		"mysql.get_slave_status",
		"mysql.grant_add",
		"mysql.grant_exists",
		"mysql.grant_revoke",
		"mysql.plugin_status",
		"mysql.plugins_list",
		"mysql.processlist",
		"mysql.quote_identifier",
		"mysql.showglobal",
		"mysql.showvariables",
		"mysql.slave_lag",
		"mysql.status",
		"mysql.tokenize_grant",
		"mysql.user_create",
		"mysql.user_chpass",
		"mysql.user_exists",
		"mysql.user_grants",
		"mysql.user_info",
		"mysql.user_list",
		"mysql.user_remove",
		"mysql.verify_login",
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

func TestMysqlUserGrantsExactShapeAndTransport(t *testing.T) {
	user := "grant'user"
	host := "host,`name'\\suffix"
	connectionPassword := "connection-pass"
	stdout := "Grants for account\n" +
		"GRANT ALL PRIVILEGES ON *.* TO 'result'@'quoted' IDENTIFIED BY 'ignored' WITH GRANT OPTION\n" +
		"GRANT SELECT ON `db`.* TO 'result'@'quoted' WITH GRANT OPTION IDENTIFIED BY 'ignored'\n" +
		"GRANT USAGE ON *.* TO 'result'@'quoted'\n"
	preflight := "User\tHost\n" + strings.ReplaceAll(user, `\`, `\\`) + "\t" + strings.ReplaceAll(host, `\`, `\\`) + "\n"
	args := &UserGrantsArgs{
		User:     user,
		Host:     mysqlString(host),
		ConnUser: mysqlString("connection-user"),
		ConnHost: mysqlString("connection-host"),
		ConnPort: mysqlString("3307"),
		ConnPass: mysqlString(connectionPassword),
		ConnDB:   mysqlString("maintenance"),
	}
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(preflight)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)},
	)
	value, err := (userGrantsFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GRANT ALL PRIVILEGES ON *.* TO 'result'@'quoted' WITH GRANT OPTION",
		"GRANT SELECT ON `db`.* TO 'result'@'quoted' WITH GRANT OPTION",
		"GRANT USAGE ON *.* TO 'result'@'quoted'",
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("user_grants value = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("user_grants calls = %d, want 2", len(runner.calls))
	}
	preflightCommand := runner.calls[0]
	wantPreflightArgv := []string{
		"mysql", "--batch", "--user=connection-user", "--host=connection-host",
		"--port=3307", "--database=maintenance", "--execute=" + userListQuery,
	}
	if got := append([]string{preflightCommand.Name}, preflightCommand.Args...); !reflect.DeepEqual(got, wantPreflightArgv) {
		t.Fatalf("user_grants preflight argv = %q, want %q", got, wantPreflightArgv)
	}
	command := runner.calls[1]
	wantArgv := []string{
		"mysql", "--batch", "--user=connection-user", "--host=connection-host",
		"--port=3307", "--database=maintenance", "--execute=" + grantQuery(user, host),
	}
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("user_grants argv = %q, want %q", got, wantArgv)
	}
	for index, call := range runner.calls {
		if call.Shell || !reflect.DeepEqual(call.Env, []string{"MYSQL_PWD=" + connectionPassword}) ||
			call.Timeout != commandTimeout || call.MaxStdoutBytes != outputLimit || call.MaxStderrBytes != outputLimit {
			t.Fatalf("user_grants call %d transport = %#v", index, call)
		}
		for _, secret := range []string{
			connectionPassword, user, strings.ReplaceAll(user, "'", "''"), "'" + strings.ReplaceAll(user, "'", "''") + "'",
			host, strings.ReplaceAll(host, "'", "''"), "'" + strings.ReplaceAll(host, "'", "''") + "'",
			user + "@" + host, mysqlAccount(user, host),
		} {
			if !containsAll(call.Redact, []string{secret}) {
				t.Fatalf("user_grants call %d Redact missing %q: %#v", index, secret, call.Redact)
			}
		}
		if strings.Contains(call.RedactedString(), connectionPassword) || strings.Contains(call.RedactedString(), user) || strings.Contains(call.RedactedString(), host) {
			t.Fatalf("user_grants call %d rendered command leaked caller data: %q", index, call.RedactedString())
		}
	}

	// The registered path uses the same preflight plus SHOW GRANTS contract and
	// exact JSON value.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(preflight)},
		process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)},
	)
	rt.Exec = runtime.NewExecRegistry()
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_grants", args)
	if err != nil || !reflect.DeepEqual(value, want) || len(runner.calls) != 2 {
		t.Fatalf("registered user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

func TestMysqlUserGrantsShapesAndFailClosed(t *testing.T) {
	preflight := process.CommandResult{ExitCode: 0, Stdout: []byte("User\tHost\nu\tlocalhost\n")}
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   any
	}{
		{name: "empty", result: process.CommandResult{ExitCode: 0}, want: []string{}},
		{name: "header-only", result: process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for account\n")}, want: []string{}},
		{name: "nonzero", result: process.CommandResult{ExitCode: 1, Stderr: []byte("missing account")}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(preflight, tc.result)
			value, err := (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u"})
			if err != nil || !reflect.DeepEqual(value, tc.want) || len(runner.calls) != 2 {
				t.Fatalf("shape = %#v, %v, calls=%d, want %#v", value, err, len(runner.calls), tc.want)
			}
		})
	}

	rt, runner := newMysqlRuntime(preflight, process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for account\n\\0\n")})
	value, err := (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u"})
	if !errors.Is(err, errMysqlGrant) || value != nil || len(runner.calls) != 2 {
		t.Fatalf("malformed grant = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newMysqlRuntime()
	value, err = (userGrantsFunc{}).Execute(ctx, rt, &UserGrantsArgs{User: "u"})
	if !errors.Is(err, context.Canceled) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("cancelled user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime()
	runas := "other"
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u", Runas: &runas})
	if !errors.Is(err, errMysqlRunas) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("runas user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime()
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u\nsecret"})
	if !errors.Is(err, errMysqlAccountArgument) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("unsafe account user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime()
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: strings.Repeat("x", runtime.MaxCommandInputBytes)})
	if !errors.Is(err, runtime.ErrCommandInputLimit) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("oversized account user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// An unavailable mysql client is a pre-Runner failure, not a false query.
	rt, runner = newMysqlRuntime()
	runner.available = map[string]bool{mysqlCommand: false}
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u"})
	if !errors.Is(err, errMysqlClientUnavailable) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("unavailable client user_grants = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

func TestMysqlUserGrantsRunnerErrorRedaction(t *testing.T) {
	marker := "grant'overlap\\suffix"
	host := "host'overlap\\suffix"
	formsFor := func(value string) []string {
		doubled := strings.ReplaceAll(value, "'", "''")
		quoted := "'" + doubled + "'"
		literal := mysqlStringLiteral(value)
		return []string{value, doubled, quoted, literal[1 : len(literal)-1], literal}
	}
	forms := append(formsFor(marker), formsFor(host)...)
	forms = append(forms, marker+"@"+host, mysqlAccount(marker, host))
	leak := "runner user grants failure " + strings.Join(forms, " ")
	rt, runner := newMysqlRuntime(process.CommandResult{
		Err:    errors.New(leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	})
	args := &UserGrantsArgs{User: marker, Host: mysqlString(host), ConnPass: mysqlString(marker)}
	value, err := (userGrantsFunc{}).Execute(context.Background(), rt, args)
	if err == nil || value != nil || len(runner.calls) != 1 {
		t.Fatalf("user_grants Runner error = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	for _, form := range forms {
		if strings.Contains(err.Error(), form) || strings.Contains(string(runner.calls[0].RedactedString()), form) {
			t.Fatalf("user_grants redaction leaked %q: err=%q command=%q", form, err, runner.calls[0].RedactedString())
		}
		if !containsAll(runner.calls[0].Redact, []string{form}) {
			t.Fatalf("user_grants Redact missing %q: %#v", form, runner.calls[0].Redact)
		}
	}

	// A credential overlapping the returned account is redacted after parsing,
	// while the source cleanup and list order remain otherwise unchanged.
	preflight := []byte("User\tHost\n" + strings.ReplaceAll(marker, `\`, `\\`) + "\tlocalhost\n")
	stdout := []byte("Grants for account\nGRANT USAGE ON *.* TO '" + strings.ReplaceAll(marker, "'", "''") + "'@'host'\n")
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: preflight},
		process.CommandResult{ExitCode: 0, Stdout: stdout},
	)
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: marker, ConnPass: mysqlString(marker)})
	got, ok := value.([]string)
	if err != nil || !ok || len(got) != 1 || strings.Contains(got[0], marker) || len(runner.calls) != 2 {
		t.Fatalf("user_grants successful redaction = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// A malformed or unusual server row can contain the credential as raw text
	// rather than as a quoted SQL literal; the returned grant remains redacted.
	preflight = []byte("User\tHost\nu\tlocalhost\n")
	row := "GRANT " + mysqlStringLiteral(marker)[1:len(mysqlStringLiteral(marker))-1] + " ON *.* TO 'u'@'host'"
	batchRow := strings.ReplaceAll(row, `\`, `\\`)
	stdout = []byte("Grants for account\n" + batchRow + "\n")
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: preflight},
		process.CommandResult{ExitCode: 0, Stdout: stdout},
	)
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &UserGrantsArgs{User: "u", ConnPass: mysqlString(marker)})
	got, ok = value.([]string)
	if err != nil || !ok || len(got) != 1 || strings.Contains(got[0], marker) || len(runner.calls) != 2 {
		t.Fatalf("user_grants escaped successful redaction = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	for _, form := range formsFor(marker) {
		if strings.Contains(got[0], form) {
			t.Fatalf("user_grants escaped output leaked %q: %q", form, got[0])
		}
	}
}

func TestMysqlUserGrantsUserExistsPreflight(t *testing.T) {
	connection := &UserGrantsArgs{
		User:     "missing",
		Host:     mysqlString("remote"),
		ConnUser: mysqlString("conn_user"),
		ConnHost: mysqlString("conn_host"),
		ConnPort: mysqlString("3307"),
		ConnPass: mysqlString("conn_pass"),
		ConnDB:   mysqlString("maintenance"),
	}

	rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("User\tHost\nother\tremote\n")})
	value, err := (userGrantsFunc{}).Execute(context.Background(), rt, connection)
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("missing user preflight = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute="+userListQuery {
		t.Fatalf("missing user preflight query = %q", got)
	}

	existing := *connection
	existing.User = "existing"
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("User\tHost\nexisting\tremote\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Grants\nGRANT USAGE ON *.* TO 'existing'@'remote'\n")},
	)
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, &existing)
	if err != nil || !reflect.DeepEqual(value, []string{"GRANT USAGE ON *.* TO 'existing'@'remote'"}) || len(runner.calls) != 2 {
		t.Fatalf("existing user preflight = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute="+userListQuery {
		t.Fatalf("existing preflight query = %q", got)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SHOW GRANTS FOR 'existing'@'remote'" {
		t.Fatalf("existing SHOW GRANTS query = %q", got)
	}
	for _, call := range runner.calls {
		if !reflect.DeepEqual(call.Env, []string{"MYSQL_PWD=conn_pass"}) || !containsAll(call.Redact, []string{"conn_pass", "existing", "remote", "'existing'@'remote'"}) {
			t.Fatalf("preflight transport = %#v", call)
		}
	}

	rt, runner = newMysqlRuntime(process.CommandResult{Err: errors.New("preflight error")})
	value, err = (userGrantsFunc{}).Execute(context.Background(), rt, connection)
	if err == nil || value != nil || len(runner.calls) != 1 {
		t.Fatalf("preflight error = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newMysqlRuntime()
	value, err = (userGrantsFunc{}).Execute(ctx, rt, connection)
	if !errors.Is(err, context.Canceled) || value != nil || len(runner.calls) != 0 {
		t.Fatalf("preflight cancellation = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

func TestMysqlUnsupportedProviderNotRegistered(t *testing.T) {
	rt, runner := newMysqlRuntime()
	rt.Exec = runtime.NewExecRegistry()
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.Exec.Get("mysql.query"); ok {
		t.Fatal("unsupported mysql.query must remain unregistered")
	}
	if _, err := rt.Exec.Call(context.Background(), rt, "mysql.query", nil); err == nil || len(runner.calls) != 0 {
		t.Fatalf("unsupported mysql.query call = %v, calls=%d", err, len(runner.calls))
	}
}

func grantTestShowGrants(statement string) []byte {
	return []byte("Grants for account\n" + statement + "\n")
}

func TestMysqlGrantAddExactSQLAndPostCheck(t *testing.T) {
	connPass := "grant-connection-pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT(COL1, COL2) ON `db_%``x`.`tbl``_x` TO 'u''ser'@'h%ost'")},
	)
	args := &GrantAddArgs{
		User:     "u'ser@h%ost",
		Grant:    "select(col1, col2)",
		Database: "db_%`x.tbl`_x",
		ConnUser: mysqlString("conn_user"),
		ConnHost: mysqlString("conn_host"),
		ConnPort: mysqlString("3307"),
		ConnPass: mysqlString(connPass),
		ConnDB:   mysqlString("maintenance"),
	}
	value, err := (grantAddFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	if ok, isBool := value.(bool); !isBool || !ok {
		t.Fatalf("grant_add result = %#v, want true", value)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("grant_add calls = %d, want mutation, version, SHOW GRANTS", len(runner.calls))
	}
	mutation := runner.calls[0]
	if argv := append([]string{mutation.Name}, mutation.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3307", "--database=maintenance",
		"--execute=GRANT SELECT(COL1, COL2) ON `db_%``x`.`tbl``_x` TO 'u''ser'@'h%ost'",
	}) {
		t.Fatalf("grant_add argv = %q", argv)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SELECT VERSION()" {
		t.Fatalf("grant_exists version query = %q", got)
	}
	check := runner.calls[2]
	if argv := append([]string{check.Name}, check.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=conn_user", "--host=conn_host", "--port=3307", "--database=maintenance",
		"--execute=SHOW GRANTS FOR 'u''ser'@'h%ost'",
	}) {
		t.Fatalf("grant_exists argv = %q", argv)
	}
	for i, command := range runner.calls {
		if command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("call %d transport = %#v", i, command)
		}
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || !containsAll(command.Redact,
			[]string{connPass, "u'ser", "u''ser", "'u''ser'", "'u''ser'@'h%ost'", "db_%`x", "tbl`_x"}) {
			t.Fatalf("call %d redaction = %#v", i, command)
		}
		if strings.Contains(command.RedactedString(), connPass) {
			t.Fatalf("call %d rendered password", i)
		}
	}
}

func TestMysqlGrantHostEscapeDefaultsAndSourceMapping(t *testing.T) {
	// Omitted host and escape retain the pinned localhost/True defaults, while
	// explicit host maps the source's separate user/host parameters and an
	// explicit false escape keeps the raw database.table spelling.
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON db.tbl TO 'u'@'remote'")},
	)
	host := "remote"
	escape := false
	value, err := (grantAddFunc{}).Execute(context.Background(), rt, &GrantAddArgs{
		User: "u", Database: "db.tbl", Grant: "SELECT", Host: &host, Escape: &escape,
	})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("explicit host/escape = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute=GRANT SELECT ON db.tbl TO 'u'@'remote'" {
		t.Fatalf("raw grant SQL = %q", got)
	}
	if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != "--execute=SHOW GRANTS FOR 'u'@'remote'" {
		t.Fatalf("explicit host post-check SQL = %q", got)
	}

	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost'")},
	)
	value, err = (grantAddFunc{}).Execute(context.Background(), rt, &GrantAddArgs{
		User: "u", Database: "db.tbl", Grant: "SELECT",
	})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("default host/escape = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute=GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost'" {
		t.Fatalf("default grant SQL = %q", got)
	}
}

func TestMysqlGrantAddSSLOption(t *testing.T) {
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost'")},
	)
	value, err := (grantAddFunc{}).Execute(context.Background(), rt, &GrantAddArgs{
		User:     "u",
		Database: "db.tbl",
		Grant:    "SELECT",
		SSLOption: []any{
			map[string]any{"SSL": true},
			map[string]any{"CIPHER": "AES256"},
		},
	})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("ssl grant_add = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	got := runner.calls[0].Args[len(runner.calls[0].Args)-1]
	want := "--execute=GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost' REQUIRE SSL AND CIPHER 'AES256'"
	if got != want {
		t.Fatalf("ssl grant SQL = %q, want %q", got, want)
	}
}

func containsAll(values []string, wanted []string) bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	for _, value := range wanted {
		if !set[value] {
			return false
		}
	}
	return true
}

func mysqlGrantRedactionForms(marker, host, database, table string) []string {
	doubled := strings.ReplaceAll(marker, "'", "''")
	hostDoubled := strings.ReplaceAll(host, "'", "''")
	quoted := "'" + doubled + "'"
	hostQuoted := "'" + hostDoubled + "'"
	databaseQuoted := "`" + strings.ReplaceAll(database, "`", "``") + "`"
	tableQuoted := "`" + strings.ReplaceAll(table, "`", "``") + "`"
	forms := []string{
		marker,
		doubled,
		quoted,
		host,
		hostDoubled,
		hostQuoted,
		marker + "@" + host,
		quoted + "@" + hostQuoted,
		mysqlNativePasswordHash(marker),
	}
	if database != "" {
		forms = append(forms,
			database,
			strings.ReplaceAll(database, "'", "''"),
			"'"+strings.ReplaceAll(database, "'", "''")+"'",
			databaseQuoted,
		)
	}
	if table != "" {
		forms = append(forms,
			table,
			strings.ReplaceAll(table, "'", "''"),
			"'"+strings.ReplaceAll(table, "'", "''")+"'",
			tableQuoted,
		)
	}
	if database != "" && table != "" {
		forms = append(forms,
			database+"."+table,
			databaseQuoted+"."+tableQuoted,
		)
	}
	return forms
}

func mysqlGrantGlobalAllRedactionForms(marker, host string) []string {
	forms := mysqlGrantRedactionForms(marker, host, "*", "*")
	filtered := make([]string, 0, len(forms))
	for _, form := range forms {
		switch form {
		case "*", "'*'", "`*`":
			// A one-character wildcard is present in the command redaction
			// inventory, but it is also part of the redaction placeholder.
			// Keep the object-level forms below, which are unambiguous checks.
			continue
		default:
			filtered = append(filtered, form)
		}
	}
	return filtered
}

func mysqlGrantFailureResult(forms []string) process.CommandResult {
	leak := "runner grant failure " + strings.Join(forms, " ")
	return process.CommandResult{
		Err:    errors.New(leak),
		Stdout: []byte("stdout " + leak + "\n"),
		Stderr: []byte("stderr " + leak + "\n"),
	}
}

func mysqlGrantQuery(command process.Command) string {
	if len(command.Args) == 0 {
		return ""
	}
	return command.Args[len(command.Args)-1]
}

func assertMysqlGrantRedactedTransport(t *testing.T, result process.CommandResult, argv []string, conn *myConnection, secrets, forms []string, preserve bool) {
	t.Helper()
	rt, runner := newMysqlRuntime(result)
	var (
		safe process.CommandResult
		err  error
	)
	if preserve {
		safe, err = runMysqlPreserveSecrets(context.Background(), rt, argv, conn, secrets...)
	} else {
		safe, err = runMysqlSecrets(context.Background(), rt, argv, conn, secrets...)
	}
	if err == nil || safe.Err == nil {
		t.Fatal("redacting transport must return the Runner error")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("redacting transport made %d Runner calls, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	outputs := []string{err.Error(), safe.Err.Error(), string(safe.Stdout), string(safe.Stderr), command.RedactedString()}
	for outputIndex, output := range outputs {
		for formIndex, form := range forms {
			if strings.Contains(output, form) {
				t.Fatalf("redacting transport leaked marker form index %d in output %d", formIndex, outputIndex)
			}
		}
	}
	if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + *conn.Password}) {
		t.Fatal("redacting transport changed the shell-free password transport")
	}
	if !containsAll(command.Redact, forms) {
		t.Fatal("redacting transport omitted a marker form from Redact")
	}
}

func TestMysqlGrantProviderRunnerErrorRedaction(t *testing.T) {
	marker := "grant'overlap"
	host := "host'overlap"
	database, table := marker, marker
	forms := mysqlGrantRedactionForms(marker, host, database, table)
	sslOption := []any{map[string]any{"CIPHER": marker}}

	for _, tc := range []struct {
		name          string
		mutationQuery string
		makeArgs      func() any
		run           func(*runtime.Runtime, any) (any, error)
		connection    func(any) *myConnection
		secrets       func(*myConnection) []string
	}{
		{
			name:          "grant_add",
			mutationQuery: "--execute=GRANT SELECT ON `" + marker + "`.`" + marker + "` TO '" + strings.ReplaceAll(marker, "'", "''") + "'@'" + strings.ReplaceAll(host, "'", "''") + "' REQUIRE CIPHER '" + strings.ReplaceAll(marker, "'", "''") + "' WITH GRANT OPTION",
			makeArgs: func() any {
				grantOption := true
				return &GrantAddArgs{
					User:        marker,
					Host:        mysqlString(host),
					Grant:       "SELECT",
					Database:    database + "." + table,
					GrantOption: &grantOption,
					SSLOption:   sslOption,
					ConnPass:    mysqlString(marker),
				}
			},
			run: func(rt *runtime.Runtime, args any) (any, error) {
				return (grantAddFunc{}).Execute(context.Background(), rt, args)
			},
			connection: func(args any) *myConnection { return args.(*GrantAddArgs).connection() },
			secrets: func(conn *myConnection) []string {
				return grantSecretInventory(conn, marker, host, "SELECT", database, table, sslOption)
			},
		},
		{
			name:          "grant_revoke",
			mutationQuery: "--execute=REVOKE SELECT, GRANT OPTION ON `" + marker + "`.`" + marker + "` FROM '" + strings.ReplaceAll(marker, "'", "''") + "'@'" + strings.ReplaceAll(host, "'", "''") + "';",
			makeArgs: func() any {
				grantOption := true
				return &GrantRevokeArgs{
					User:        marker,
					Host:        mysqlString(host),
					Grant:       "SELECT",
					Database:    database + "." + table,
					GrantOption: &grantOption,
					ConnPass:    mysqlString(marker),
				}
			},
			run: func(rt *runtime.Runtime, args any) (any, error) {
				return (grantRevokeFunc{}).Execute(context.Background(), rt, args)
			},
			connection: func(args any) *myConnection { return args.(*GrantRevokeArgs).connection() },
			secrets: func(conn *myConnection) []string {
				return grantSecretInventory(conn, marker, host, "SELECT", database, table)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for failAt := 0; failAt < 3; failAt++ {
				results := make([]process.CommandResult, 0, failAt+1)
				if failAt > 0 {
					results = append(results, process.CommandResult{ExitCode: 0})
				}
				if failAt > 1 {
					results = append(results, process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")})
				}
				results = append(results, mysqlGrantFailureResult(forms))
				rt, runner := newMysqlRuntime(results...)
				args := tc.makeArgs()
				before := reflect.ValueOf(args).Elem().Interface()
				value, err := tc.run(rt, args)
				if err == nil || value != false || len(runner.calls) != failAt+1 {
					t.Fatalf("failAt=%d returned %#v, %v after %d calls", failAt, value, err, len(runner.calls))
				}
				if !reflect.DeepEqual(reflect.ValueOf(args).Elem().Interface(), before) {
					t.Fatalf("failAt=%d mutated provider arguments", failAt)
				}
				for _, form := range forms {
					if strings.Contains(err.Error(), form) {
						t.Fatalf("failAt=%d returned an unredacted Runner error", failAt)
					}
				}

				for index, command := range runner.calls {
					query := mysqlGrantQuery(command)
					switch index {
					case 0:
						if query != tc.mutationQuery {
							t.Fatalf("failAt=%d changed mutation call order", failAt)
						}
					case 1:
						if query != "--execute=SELECT VERSION()" {
							t.Fatalf("failAt=%d changed version call order", failAt)
						}
					case 2:
						if query != "--execute=SHOW GRANTS FOR '"+strings.ReplaceAll(marker, "'", "''")+"'@'"+strings.ReplaceAll(host, "'", "''")+"'" {
							t.Fatalf("failAt=%d changed SHOW GRANTS call order", failAt)
						}
					}
					if index > 0 && (strings.Contains(query, "GRANT ") || strings.Contains(query, "REVOKE ")) {
						t.Fatalf("failAt=%d issued an extra mutation after the failing read", failAt)
					}
				}

				conn := tc.connection(args)
				secrets := tc.secrets(conn)
				failing := runner.calls[len(runner.calls)-1]
				assertMysqlGrantRedactedTransport(t, mysqlGrantFailureResult(forms),
					append([]string{failing.Name}, failing.Args...), conn, secrets, forms, failAt != 0)
			}
		})
	}
}

func TestMysqlRegistryGrantRevokeRunnerErrorRedaction(t *testing.T) {
	marker := "grant'overlap"
	host := "host'overlap"
	database, table := marker, marker
	forms := mysqlGrantRedactionForms(marker, host, database, table)
	doubled := strings.ReplaceAll(marker, "'", "''")
	hostDoubled := strings.ReplaceAll(host, "'", "''")
	wantQueries := []string{
		"--execute=REVOKE SELECT, GRANT OPTION ON `" + marker + "`.`" + marker + "` FROM '" + doubled + "'@'" + hostDoubled + "';",
		"--execute=SELECT VERSION()",
		"--execute=SHOW GRANTS FOR '" + doubled + "'@'" + hostDoubled + "'",
	}

	for failAt := 0; failAt < len(wantQueries); failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		if failAt > 0 {
			results = append(results, process.CommandResult{ExitCode: 0})
		}
		if failAt > 1 {
			results = append(results, process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")})
		}
		results = append(results, mysqlGrantFailureResult(forms))

		rt, runner := newMysqlRuntime(results...)
		rt.Exec = runtime.NewExecRegistry()
		if err := Register(rt.Exec); err != nil {
			t.Fatal(err)
		}
		args := &GrantRevokeArgs{
			User:        marker,
			Host:        mysqlString(host),
			Grant:       "SELECT",
			Database:    database + "." + table,
			GrantOption: mysqlBool(true),
			Escape:      mysqlBool(true),
			ConnPass:    mysqlString(marker),
		}
		before := reflect.ValueOf(args).Elem().Interface()
		value, err := rt.Exec.Call(context.Background(), rt, "mysql.grant_revoke", args)
		if err == nil || value != false || len(runner.calls) != failAt+1 {
			t.Fatalf("failAt=%d returned %#v, %v after %d calls", failAt, value, err, len(runner.calls))
		}
		if after := reflect.ValueOf(args).Elem().Interface(); !reflect.DeepEqual(after, before) {
			t.Fatalf("failAt=%d mutated grant_revoke arguments: before=%#v after=%#v", failAt, before, after)
		}
		for _, form := range forms {
			if strings.Contains(err.Error(), form) {
				t.Fatalf("failAt=%d registry error leaked marker form %q: %v", failAt, form, err)
			}
		}

		for index, command := range runner.calls {
			if got := mysqlGrantQuery(command); got != wantQueries[index] {
				t.Fatalf("failAt=%d call %d query=%q, want %q", failAt, index, got, wantQueries[index])
			}
			if command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
				t.Fatalf("failAt=%d call %d transport=%#v", failAt, index, command)
			}
			if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) || !containsAll(command.Redact, forms) {
				t.Fatalf("failAt=%d call %d redaction transport=%#v", failAt, index, command)
			}
			if rendered := command.RedactedString(); func() bool {
				for _, form := range forms {
					if strings.Contains(rendered, form) {
						return true
					}
				}
				return false
			}() {
				t.Fatalf("failAt=%d call %d rendered command leaked a marker: %q", failAt, index, rendered)
			}
			if index > 0 && (strings.Contains(wantQueries[index], "GRANT ") || strings.Contains(wantQueries[index], "REVOKE ")) {
				t.Fatalf("failAt=%d issued a mutation after the failing read", failAt)
			}
		}

		// The registry returns only the safe error. Re-run the exact failing
		// transport to pin the same synthetic error's stdout/stderr sanitization.
		failing := runner.calls[len(runner.calls)-1]
		conn := args.connection()
		assertMysqlGrantRedactedTransport(t, mysqlGrantFailureResult(forms),
			append([]string{failing.Name}, failing.Args...), conn,
			grantSecretInventory(conn, marker, host, "SELECT", database, table), forms, failAt > 0)
	}
}

func TestMysqlGrantExistsProviderRunnerErrorRedaction(t *testing.T) {
	marker := "grant'overlap"
	host := "host'overlap"
	forms := mysqlGrantRedactionForms(marker, host, "", "")
	args := &GrantExistsArgs{
		User:     marker,
		Host:     mysqlString(host),
		Grant:    "ALL",
		Database: "*.*",
		ConnPass: mysqlString(marker),
	}

	for failAt := 0; failAt < 3; failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		if failAt > 0 {
			results = append(results, process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")})
		}
		if failAt > 1 {
			results = append(results, process.CommandResult{ExitCode: 0, Stdout: []byte("Privilege\tContext\tComment\nSELECT\tGlobal\t\n")})
		}
		results = append(results, mysqlGrantFailureResult(forms))
		rt, runner := newMysqlRuntime(results...)
		before := *args
		value, err := (grantExistsFunc{}).Execute(context.Background(), rt, args)
		if err == nil || value != false || len(runner.calls) != failAt+1 {
			t.Fatalf("failAt=%d returned %#v, %v after %d calls", failAt, value, err, len(runner.calls))
		}
		if !reflect.DeepEqual(*args, before) {
			t.Fatalf("failAt=%d mutated provider arguments", failAt)
		}
		for _, form := range forms {
			if strings.Contains(err.Error(), form) {
				t.Fatalf("failAt=%d returned an unredacted Runner error", failAt)
			}
		}

		wantQueries := []string{
			"--execute=SELECT VERSION()",
			"--execute=SHOW PRIVILEGES",
			"--execute=SHOW GRANTS FOR '" + strings.ReplaceAll(marker, "'", "''") + "'@'" + strings.ReplaceAll(host, "'", "''") + "'",
		}
		for index, command := range runner.calls {
			if mysqlGrantQuery(command) != wantQueries[index] {
				t.Fatalf("failAt=%d changed query order", failAt)
			}
			if strings.Contains(mysqlGrantQuery(command), "GRANT ") || strings.Contains(mysqlGrantQuery(command), "REVOKE ") {
				t.Fatalf("failAt=%d issued a mutation query", failAt)
			}
			if !containsAll(command.Redact, forms) {
				t.Fatalf("failAt=%d omitted a marker form from Redact", failAt)
			}
			if strings.Contains(command.RedactedString(), marker) || strings.Contains(command.RedactedString(), host) {
				t.Fatalf("failAt=%d rendered command leaked a marker", failAt)
			}
		}

		conn := args.connection()
		secrets := grantSecretInventory(conn, marker, host, "ALL", "*", "*")
		failing := runner.calls[len(runner.calls)-1]
		assertMysqlGrantRedactedTransport(t, mysqlGrantFailureResult(forms),
			append([]string{failing.Name}, failing.Args...), conn, secrets, forms, true)
	}
}

// TestMysqlGrantMutationGlobalAllPostCheckErrorAfterOneMutation pins the
// source order: a successful GRANT/REVOKE is followed by the VERSION and SHOW
// PRIVILEGES post-checks. A post-check failure cannot undo that first
// mutation, but it must not cause a repeat mutation; only the final error,
// redaction, and input-preservation guarantees remain under test.
func TestMysqlGrantMutationGlobalAllPostCheckErrorAfterOneMutation(t *testing.T) {
	marker := "global'grant"
	host := "host'grant"
	database, table := "*", "*"
	doubled := strings.ReplaceAll(marker, "'", "''")
	hostDoubled := strings.ReplaceAll(host, "'", "''")
	mutationQueries := map[string]string{
		"grant_add":    "--execute=GRANT ALL PRIVILEGES ON *.* TO '" + doubled + "'@'" + hostDoubled + "'",
		"grant_revoke": "--execute=REVOKE ALL PRIVILEGES ON *.* FROM '" + doubled + "'@'" + hostDoubled + "';",
	}

	testCases := []struct {
		name         string
		registryName string
		makeArgs     func() any
		direct       func(*runtime.Runtime, any) (any, error)
		connection   func(any) *myConnection
		secretArgs   func(*myConnection) []string
	}{
		{
			name:         "grant_add",
			registryName: "mysql.grant_add",
			makeArgs: func() any {
				return &GrantAddArgs{
					User:     marker,
					Host:     mysqlString(host),
					Grant:    "ALL",
					Database: database + "." + table,
					ConnPass: mysqlString(marker),
				}
			},
			direct: func(rt *runtime.Runtime, args any) (any, error) {
				return (grantAddFunc{}).Execute(context.Background(), rt, args)
			},
			connection: func(args any) *myConnection { return args.(*GrantAddArgs).connection() },
			secretArgs: func(conn *myConnection) []string {
				return grantSecretInventory(conn, marker, host, "ALL", database, table)
			},
		},
		{
			name:         "grant_revoke",
			registryName: "mysql.grant_revoke",
			makeArgs: func() any {
				return &GrantRevokeArgs{
					User:     marker,
					Host:     mysqlString(host),
					Grant:    "ALL",
					Database: database + "." + table,
					ConnPass: mysqlString(marker),
				}
			},
			direct: func(rt *runtime.Runtime, args any) (any, error) {
				return (grantRevokeFunc{}).Execute(context.Background(), rt, args)
			},
			connection: func(args any) *myConnection { return args.(*GrantRevokeArgs).connection() },
			secretArgs: func(conn *myConnection) []string {
				return grantSecretInventory(conn, marker, host, "ALL", database, table)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"/direct", func(t *testing.T) {
			runMysqlGrantMutationGlobalAllPostCheckErrorAfterOneMutation(t, tc.makeArgs(), tc.direct, tc.connection, tc.secretArgs, "direct", mutationQueries[tc.name])
		})
		t.Run(tc.name+"/registry", func(t *testing.T) {
			args := tc.makeArgs()
			run := func(rt *runtime.Runtime, value any) (any, error) {
				if rt.Exec == nil {
					rt.Exec = runtime.NewExecRegistry()
					if err := Register(rt.Exec); err != nil {
						t.Fatal(err)
					}
				}
				return rt.Exec.Call(context.Background(), rt, tc.registryName, value)
			}
			runMysqlGrantMutationGlobalAllPostCheckErrorAfterOneMutation(t, args, run, tc.connection, tc.secretArgs, "registry", mutationQueries[tc.name])
		})
	}
}

func runMysqlGrantMutationGlobalAllPostCheckErrorAfterOneMutation(
	t *testing.T,
	args any,
	call func(*runtime.Runtime, any) (any, error),
	connection func(any) *myConnection,
	secretArgs func(*myConnection) []string,
	surface, mutationQuery string,
) {
	t.Helper()
	marker := "global'grant"
	host := "host'grant"
	forms := mysqlGrantGlobalAllRedactionForms(marker, host)
	showPrivilegesFailure := mysqlGrantFailureResult(forms)
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		showPrivilegesFailure,
	)
	before := reflect.ValueOf(args).Elem().Interface()
	value, err := call(rt, args)
	if err == nil || value != false || len(runner.calls) != 3 {
		t.Fatalf("%s returned %#v, %v after %d calls", surface, value, err, len(runner.calls))
	}
	if after := reflect.ValueOf(args).Elem().Interface(); !reflect.DeepEqual(after, before) {
		t.Fatalf("%s mutated input: before=%#v after=%#v", surface, before, after)
	}
	for _, form := range forms {
		if strings.Contains(err.Error(), form) {
			t.Fatalf("%s error leaked marker form %q: %v", surface, form, err)
		}
	}

	// The first call is the already-successful mutation. The remaining calls
	// are the post-check; neither may issue a second GRANT/REVOKE.
	wantQueries := []string{mutationQuery, "--execute=SELECT VERSION()", "--execute=SHOW PRIVILEGES"}
	mutationCalls := 0
	for index, command := range runner.calls {
		if got := mysqlGrantQuery(command); got != wantQueries[index] {
			t.Fatalf("%s call %d query=%q, want %q", surface, index, got, wantQueries[index])
		}
		if strings.Contains(mysqlGrantQuery(command), "GRANT ") || strings.Contains(mysqlGrantQuery(command), "REVOKE ") {
			mutationCalls++
			if index != 0 {
				t.Fatalf("%s issued a repeat mutation after the initial operation: %q", surface, mysqlGrantQuery(command))
			}
		}
		if command.Shell {
			t.Fatalf("%s call %d unexpectedly used a shell", surface, index)
		}
		for _, form := range forms {
			if strings.Contains(command.RedactedString(), form) {
				t.Fatalf("%s call %d rendered command leaked marker form %q: %q", surface, index, form, command.RedactedString())
			}
		}
	}
	if mutationCalls != 1 {
		t.Fatalf("%s issued %d mutations, want exactly one initial mutation", surface, mutationCalls)
	}

	failing := runner.calls[2]
	conn := connection(args)
	assertMysqlGrantRedactedTransport(t, showPrivilegesFailure,
		append([]string{failing.Name}, failing.Args...), conn, secretArgs(conn), forms, true)
}

func TestMysqlGrantExistsAllOptionAndShapes(t *testing.T) {
	withOption := "GRANT SELECT ON `db`.* TO 'bob'@'localhost' WITH GRANT OPTION\n"
	withoutOption := "GRANT INSERT ON `db`.* TO 'bob'@'localhost'\n"
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for bob@localhost\n" + withOption + withoutOption)},
	)
	grantOption := true
	value, err := (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "bob", Grant: "SELECT, INSERT", Database: "db.*", GrantOption: &grantOption,
	})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("grant_exists combined option = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SELECT VERSION()" || runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute=SHOW GRANTS FOR 'bob'@'localhost'" {
		t.Fatalf("grant_exists query order = %#v", runner.calls)
	}

	// Global ALL on MySQL 8 uses SHOW PRIVILEGES before SHOW GRANTS.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Privilege\tContext\tComment\nALTER\tGlobal\t\nSELECT\tGlobal\t\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for bob@localhost\nGRANT ALTER, SELECT ON *.* TO 'bob'@'localhost'\n")},
	)
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "bob", Grant: "ALL PRIVILEGES", Database: "*.*",
	})
	if err != nil || value != true || len(runner.calls) != 3 || !strings.HasSuffix(runner.calls[1].Args[len(runner.calls[1].Args)-1], "SHOW PRIVILEGES") {
		t.Fatalf("grant_exists ALL = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// MariaDB has a separate path: no SHOW PRIVILEGES expansion and aliases are
	// resolved only at the pinned version thresholds.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n10.5.1-MariaDB\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT REPLICATION SLAVE ON `db`.* TO 'bob'@'localhost'")},
	)
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: "bob", Grant: "REPLICATION REPLICA", Database: "db.*"})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("MariaDB alias = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// A literal ALL row is not a universal grant for an ordinary object.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT ALL PRIVILEGES ON `db`.* TO 'bob'@'localhost'")},
	)
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "bob", Grant: "SELECT", Database: "db.*",
	})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("literal ALL ordinary grant = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// A missing version is a false answer and stops before SHOW GRANTS.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "bob", Grant: "SELECT", Database: "db.*", GrantOption: &grantOption,
	})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("missing version = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime()
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "bob", Grant: "UNKNOWN_PRIVILEGE", Database: "db.*",
	})
	if !errors.Is(err, errMysqlGrant) || value != false || len(runner.calls) != 0 {
		t.Fatalf("unknown grant = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

}

func TestMysqlGrantExistsVersionThresholdsAndAliases(t *testing.T) {
	showPrivileges := []byte("Privilege\tContext\tComment\nSELECT\tGlobal\t\n")
	for _, version := range []string{"8.0.0", "8.0.1", "8.0.11"} {
		t.Run("mysql-"+version, func(t *testing.T) {
			rt, runner := newMysqlRuntime(
				process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n" + version + "\n")},
				process.CommandResult{ExitCode: 0, Stdout: showPrivileges},
				process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON *.* TO 'u'@'localhost'")},
			)
			value, err := (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
				User: "u", Database: "*.*", Grant: "ALL",
			})
			if err != nil || value != true || len(runner.calls) != 3 {
				t.Fatalf("version=%s result=%#v err=%v calls=%d", version, value, err, len(runner.calls))
			}
			queries := []string{
				runner.calls[0].Args[len(runner.calls[0].Args)-1],
				runner.calls[1].Args[len(runner.calls[1].Args)-1],
				runner.calls[2].Args[len(runner.calls[2].Args)-1],
			}
			want := []string{"--execute=SELECT VERSION()", "--execute=SHOW PRIVILEGES", "--execute=SHOW GRANTS FOR 'u'@'localhost'"}
			if !reflect.DeepEqual(queries, want) {
				t.Fatalf("version=%s query order=%q want=%q", version, queries, want)
			}
		})
	}
	// A failed SHOW PRIVILEGES result falls back to the pinned static MySQL
	// privilege list, but the query remains part of the exact call sequence.
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.11\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("SHOW PRIVILEGES unavailable\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT " + strings.Join(mysqlAllPrivileges, ", ") + " ON *.* TO 'u'@'localhost'")},
	)
	value, err := (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: "u", Database: "*.*", Grant: "ALL"})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("SHOW PRIVILEGES fallback result=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SHOW PRIVILEGES" {
		t.Fatalf("SHOW PRIVILEGES fallback query=%q", got)
	}

	// MySQL before 8.0 keeps the source's concrete ALL PRIVILEGES comparison
	// and never probes SHOW PRIVILEGES.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n5.7.44\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT ALL PRIVILEGES ON *.* TO 'u'@'localhost'")},
	)
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: "u", Database: "*.*", Grant: "ALL PRIVILEGES"})
	if err != nil || value != true || len(runner.calls) != 2 || strings.Contains(runner.calls[1].Args[len(runner.calls[1].Args)-1], "PRIVILEGES") {
		t.Fatalf("old MySQL result=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// A concrete global token is not the source's global ALL branch.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.11\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON *.* TO 'u'@'localhost'")},
	)
	value, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: "u", Database: "*.*", Grant: "SELECT"})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("concrete global result=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SHOW GRANTS FOR 'u'@'localhost'" {
		t.Fatalf("concrete global query=%q", got)
	}

	aliasCases := []struct {
		name      string
		version   string
		requested string
		observed  string
		want      bool
	}{
		{"replication-replica-at-10.5.1", "10.5.1-MariaDB", "REPLICATION REPLICA", "REPLICATION SLAVE", true},
		{"replication-replica-before", "10.5.0-MariaDB", "REPLICATION REPLICA", "REPLICATION SLAVE", false},
		{"binlog-monitor-at-10.5.2", "10.5.2-MariaDB", "REPLICATION CLIENT", "BINLOG MONITOR", true},
		{"binlog-monitor-before", "10.5.1-MariaDB", "REPLICATION CLIENT", "BINLOG MONITOR", false},
		{"slave-monitor-at-10.5.9", "10.5.9-MariaDB", "REPLICA MONITOR", "SLAVE MONITOR", true},
		{"slave-monitor-before", "10.5.8-MariaDB", "REPLICA MONITOR", "SLAVE MONITOR", false},
	}
	for _, tc := range aliasCases {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(
				process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n" + tc.version + "\n")},
				process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT " + tc.observed + " ON `db`.* TO 'u'@'localhost'")},
			)
			value, err := (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: "u", Database: "db.*", Grant: tc.requested})
			if err != nil || value != tc.want || len(runner.calls) != 2 {
				t.Fatalf("version=%s result=%#v err=%v calls=%d want=%v", tc.version, value, err, len(runner.calls), tc.want)
			}
		})
	}
}

func TestMysqlGrantRevokeExactSQLAndFailures(t *testing.T) {
	grantOption := true
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for u@h\n")},
	)
	value, err := (grantRevokeFunc{}).Execute(context.Background(), rt, &GrantRevokeArgs{
		User: "u@h", Grant: "SELECT", Database: "db.tbl",
		GrantOption: &grantOption, ConnPass: mysqlString("revoke-pass"),
	})
	if err != nil || value != true {
		t.Fatalf("grant_revoke result = %#v, %v", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("grant_revoke calls = %d, want 3", len(runner.calls))
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--execute=REVOKE SELECT, GRANT OPTION ON `db`.`tbl` FROM 'u'@'h';",
	}) {
		t.Fatalf("grant_revoke argv = %q", got)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=SELECT VERSION()" {
		t.Fatalf("grant_revoke version query = %q", got)
	}
	if got := append([]string{runner.calls[2].Name}, runner.calls[2].Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--execute=SHOW GRANTS FOR 'u'@'h'",
	}) {
		t.Fatalf("grant_revoke post-check argv = %q", got)
	}

	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("permission denied")})
	value, err = (grantRevokeFunc{}).Execute(context.Background(), rt, &GrantRevokeArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("grant_revoke nonzero = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newMysqlRuntime()
	_, err = (grantAddFunc{}).Execute(ctx, rt, &GrantAddArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("grant cancellation = %v, calls=%d", err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: bytes.Repeat([]byte{'x'}, outputLimit+1)})
	_, err = (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("grant output bound = %v, calls=%d", err, len(runner.calls))
	}

	longDatabase := strings.Repeat("d", runtime.MaxCommandInputBytes)
	rt, runner = newMysqlRuntime()
	_, err = (grantAddFunc{}).Execute(context.Background(), rt, &GrantAddArgs{
		User: "u", Grant: "SELECT", Database: longDatabase + ".tbl",
	})
	if !errors.Is(err, runtime.ErrCommandInputLimit) || len(runner.calls) != 0 {
		t.Fatalf("grant argv bound = %v, calls=%d", err, len(runner.calls))
	}
}

func TestMysqlGrantNoRunnerAndRegistry(t *testing.T) {
	_, err := (grantExistsFunc{}).Execute(context.Background(), &runtime.Runtime{}, &GrantExistsArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("nil Runner error = %v", err)
	}

	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost'")},
	)
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	value, err := reg.Call(context.Background(), rt, "mysql.grant_exists", &GrantExistsArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("registry grant_exists = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	addRuntime, addRunner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON `db`.`tbl` TO 'u'@'localhost'")},
	)
	value, err = reg.Call(context.Background(), addRuntime, "mysql.grant_add", &GrantAddArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if err != nil || value != true || len(addRunner.calls) != 3 {
		t.Fatalf("registry grant_add = %#v, %v, calls=%d", value, err, len(addRunner.calls))
	}

	revokeRuntime, revokeRunner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: grantTestShowGrants("GRANT SELECT ON `other`.`tbl` TO 'u'@'localhost'")},
	)
	value, err = reg.Call(context.Background(), revokeRuntime, "mysql.grant_revoke", &GrantRevokeArgs{
		User: "u", Grant: "SELECT", Database: "db.tbl",
	})
	if err != nil || value != true || len(revokeRunner.calls) != 3 {
		t.Fatalf("registry grant_revoke = %#v, %v, calls=%d", value, err, len(revokeRunner.calls))
	}
}

func TestMysqlGrantArgumentContract(t *testing.T) {
	wantAdd := []string{"connection_db", "connection_host", "connection_pass", "connection_port", "connection_user", "database", "escape", "grant", "grant_option", "host", "runas", "ssl_option", "user"}
	wantCommon := []string{"connection_db", "connection_host", "connection_pass", "connection_port", "connection_user", "database", "escape", "grant", "grant_option", "host", "runas", "user"}
	for name, template := range map[string]struct {
		template any
		want     []string
	}{
		"add":    {GrantAddArgs{}, wantAdd},
		"exists": {GrantExistsArgs{}, wantCommon},
		"revoke": {GrantRevokeArgs{}, wantCommon},
	} {
		got, err := config.ArgumentNames(template.template)
		if err != nil || !reflect.DeepEqual(got, template.want) {
			t.Fatalf("%s argument names = %#v, %v; want %#v", name, got, err, template.want)
		}
	}
}

func TestMysqlGrantQuotedAccountRoundTrip(t *testing.T) {
	account := "'u'@'h''ost,`tick'"
	show := grantTestShowGrants("GRANT SELECT ON `db`.`tbl` TO " + account)
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: show},
	)
	value, err := (grantExistsFunc{}).Execute(context.Background(), rt, &GrantExistsArgs{User: account, Database: "db.tbl", Grant: "SELECT"})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("quoted account grant_exists = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if !strings.Contains(runner.calls[1].Args[len(runner.calls[1].Args)-1], "h''ost,`tick") {
		t.Fatalf("quoted account was truncated: %#v", runner.calls[1].Args)
	}

	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("Grants for account\n")},
	)
	value, err = (grantRevokeFunc{}).Execute(context.Background(), rt, &GrantRevokeArgs{User: account, Database: "db.tbl", Grant: "SELECT"})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("quoted account grant_revoke = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if !strings.Contains(runner.calls[0].Args[len(runner.calls[0].Args)-1], "FROM 'u'@'h''ost,`tick';") {
		t.Fatalf("quoted account revoke was truncated: %#v", runner.calls[0].Args)
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
// the identical catalog argv of db_list. The wildcard cases are an explicit
// compatibility ceiling: Salt's unescaped SHOW DATABASES LIKE would match
// these patterns, while the fixed catalog deliberately treats them literally.
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
		// LIKE wildcards stay literal under the client-side exact match;
		// both patterns would match "mysql" in the pinned source.
		{"my%", false},
		{"mysq_", false},
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

func TestMysqlPluginStatusAndPluginsList(t *testing.T) {
	password := "plugin-connection-pass"
	listStdout := "Name\tStatus\tType\tLibrary\tLicense\tLoad_option\r\n" +
		"first\\\\plugin\tACTIVE\tAUTHENTICATION\tfirst.so\tGPL\tON\r\n" +
		"target\tDISABLED\tSTORAGE ENGINE\tsecond.so\tGPL\tON\r\n" +
		"target\tACTIVE\tSTORAGE ENGINE\tthird.so\tGPL\tON\r\n"
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(listStdout),
	})
	listArgs := &PluginsListArgs{
		User: mysqlString("plugin-user"), Host: mysqlString("plugin-host"),
		Port: mysqlString("3307"), Password: mysqlString(password),
		DB: mysqlString("maintenance"),
	}
	value, err := (pluginsListFunc{}).Execute(context.Background(), rt, listArgs)
	if err != nil {
		t.Fatal(err)
	}
	wantList := []map[string]string{
		{"name": `first\plugin`, "status": "ACTIVE"},
		{"name": "target", "status": "DISABLED"},
		{"name": "target", "status": "ACTIVE"},
	}
	if got, ok := value.([]map[string]string); !ok || !reflect.DeepEqual(got, wantList) {
		t.Fatalf("plugins_list = %#v, want %#v", value, wantList)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=plugin-user", "--host=plugin-host", "--port=3307",
		"--database=maintenance", "--execute=" + showPluginsQuery,
	}) {
		t.Fatalf("plugins_list argv = %q", argv)
	}
	if runner.calls[0].Shell || !reflect.DeepEqual(runner.calls[0].Env, []string{"MYSQL_PWD=" + password}) ||
		!reflect.DeepEqual(runner.calls[0].Redact, []string{password}) || strings.Contains(runner.calls[0].RedactedString(), password) {
		t.Fatalf("plugins_list transport = %#v", runner.calls[0])
	}

	statusStdout := "PLUGIN_NAME\tPLUGIN_STATUS\n" +
		"other\tACTIVE\n" +
		"target\tDISABLED\n" +
		"target\tACTIVE\n"
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(statusStdout)})
	statusArgs := &PluginStatusArgs{
		Name: "target", User: mysqlString("plugin-user"), Host: mysqlString("plugin-host"),
		Port: mysqlString("3307"), Password: mysqlString(password), DB: mysqlString("maintenance"),
	}
	value, err = (pluginStatusFunc{}).Execute(context.Background(), rt, statusArgs)
	if err != nil || value != "DISABLED" {
		t.Fatalf("plugin_status = %#v, err=%v", value, err)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=plugin-user", "--host=plugin-host", "--port=3307",
		"--database=maintenance", "--execute=" + pluginStatusQuery,
	}) {
		t.Fatalf("plugin_status argv = %q", argv)
	}

	// Filtering is exact and client-side; a SQL-looking name remains a miss
	// and cannot alter the fixed query.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(statusStdout)})
	value, err = (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{Name: "target' OR 1=1 --"})
	if err != nil || value != "" || len(runner.calls) != 1 || strings.Contains(runner.calls[0].Args[len(runner.calls[0].Args)-1], "target") {
		t.Fatalf("plugin_status filtering = %#v, err=%v, calls=%#v", value, err, runner.calls)
	}
}

// TestMysqlPluginRowsRedactAfterDecode keeps the parser's matching view raw
// while redacting values only after mysql --batch escaping has been decoded.
// The synthetic password contains a backslash so its wire spelling cannot be
// redacted before decoding; a plain name overlap also must not turn
// plugin_status into a false empty result.
func TestMysqlPluginRowsRedactAfterDecode(t *testing.T) {
	escapedSecret := "r93i\\escaped-plugin"
	wireName := strings.ReplaceAll(escapedSecret, `\`, `\\`)
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout: []byte("Name\tStatus\tType\tLibrary\tLicense\tLoad_option\n" +
			wireName + "\tACTIVE\tDAEMON\tplugin.so\tGPL\tON\n"),
	})
	value, err := (pluginsListFunc{}).Execute(context.Background(), rt, &PluginsListArgs{Password: mysqlString(escapedSecret)})
	if err != nil {
		t.Fatal("plugins_list returned an error")
	}
	plugins, ok := value.([]map[string]string)
	if !ok || !reflect.DeepEqual(plugins, []map[string]string{{
		"name": process.RedactedPlaceholder, "status": "ACTIVE",
	}}) {
		t.Error("plugins_list did not redact the decoded name")
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].Redact, []string{escapedSecret}) ||
		!runner.calls[0].PreserveStdout || runner.calls[0].MaxStdoutBytes != outputLimit || runner.calls[0].MaxStderrBytes != outputLimit {
		t.Fatal("plugins_list transport changed its redaction or bounds")
	}

	overlap := "r93i-plugin-overlap"
	rt, runner = newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\n" + overlap + "\tACTIVE\n"),
	})
	value, err = (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{
		Name: overlap, Password: mysqlString(overlap),
	})
	if err != nil || value != "ACTIVE" || len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].Redact, []string{overlap}) {
		t.Fatal("plugin_status lost a raw name match after redaction")
	}
}

// TestMysqlPluginRowsRedactAfterDecodeThroughRegistry keeps the same
// decoded-secret and password/name-overlap regressions on the registered
// execution path.
func TestMysqlPluginRowsRedactAfterDecodeThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	escapedSecret := "r93i\\registry-plugin"
	wireName := strings.ReplaceAll(escapedSecret, `\`, `\\`)
	runner := &mysqlFakeRunner{results: []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("Name\tStatus\tType\tLibrary\tLicense\tLoad_option\n" + wireName + "\tACTIVE\tDAEMON\tplugin.so\tGPL\tON\n"),
	}}}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	value, err := reg.Call(context.Background(), rt, "mysql.plugins_list", &PluginsListArgs{Password: mysqlString(escapedSecret)})
	if err != nil {
		t.Fatal("registry plugins_list returned an error")
	}
	plugins, ok := value.([]map[string]string)
	if !ok || !reflect.DeepEqual(plugins, []map[string]string{{
		"name": process.RedactedPlaceholder, "status": "ACTIVE",
	}}) {
		t.Error("registry plugins_list did not redact the decoded name")
	}

	overlap := "r93i-registry-overlap"
	runner.results = []process.CommandResult{{
		ExitCode: 0,
		Stdout:   []byte("PLUGIN_NAME\tPLUGIN_STATUS\n" + overlap + "\tACTIVE\n"),
	}}
	value, err = reg.Call(context.Background(), rt, "mysql.plugin_status", &PluginStatusArgs{
		Name: overlap, Password: mysqlString(overlap),
	})
	if err != nil || value != "ACTIVE" || len(runner.calls) != 2 {
		t.Fatal("registry plugin_status lost a raw name match")
	}
}

func TestMysqlPluginCompatibilityAndBoundaries(t *testing.T) {
	// Empty name returns the pinned False before connection, while an empty
	// successful catalog returns the pinned empty string/list shapes.
	rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Name\tStatus\n")})
	value, err := (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{})
	if err != nil || value != false || len(runner.calls) != 0 {
		t.Fatalf("empty plugin name = %#v, err=%v, calls=%d", value, err, len(runner.calls))
	}
	value, err = (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{Name: "missing"})
	if err != nil || value != "" {
		t.Fatalf("missing plugin status = %#v, err=%v", value, err)
	}
	value, err = (pluginsListFunc{}).Execute(context.Background(), rt, &PluginsListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.([]map[string]string); !ok || got == nil || len(got) != 0 {
		t.Fatalf("empty plugins_list = %#v, want non-nil empty list", value)
	}

	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want any
	}{
		{"status-nonzero", process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")}, ""},
		{"list-nonzero", process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")}, []map[string]string{}},
	} {
		rt, _ = newMysqlRuntime(tc.res)
		if tc.name == "status-nonzero" {
			value, err = (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{Name: "x"})
		} else {
			value, err = (pluginsListFunc{}).Execute(context.Background(), rt, &PluginsListArgs{})
		}
		if err != nil || !reflect.DeepEqual(value, tc.want) {
			t.Fatalf("%s = %#v, err=%v, want %#v", tc.name, value, err, tc.want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newMysqlRuntime(process.CommandResult{})
	if _, err = (pluginsListFunc{}).Execute(ctx, rt, &PluginsListArgs{}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled plugins_list err=%v calls=%d", err, len(runner.calls))
	}
	rt, runner = newMysqlRuntime(process.CommandResult{})
	if _, err = (pluginsListFunc{}).Execute(context.Background(), rt, &PluginsListArgs{Runas: mysqlString("other")}); !errors.Is(err, errMysqlRunas) || len(runner.calls) != 0 {
		t.Fatalf("runas plugins_list err=%v calls=%d", err, len(runner.calls))
	}
	unavailable := &mysqlFakeRunner{available: map[string]bool{"mysql": false}}
	if _, err = (pluginsListFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: unavailable}, &PluginsListArgs{}); !errors.Is(err, errMysqlClientUnavailable) {
		t.Fatalf("unavailable plugins_list err=%v", err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 0, StdoutTruncated: true})
	if _, err = (pluginStatusFunc{}).Execute(context.Background(), rt, &PluginStatusArgs{Name: "x"}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("plugin_status output limit err=%v", err)
	}

	marker := "S3CRET-plugin-pass"
	rt, runner = newMysqlRuntime(process.CommandResult{
		Err:    errors.New("mysql failed with " + marker),
		Stdout: []byte("stdout " + marker),
		Stderr: []byte("stderr " + marker),
	})
	_, err = (pluginsListFunc{}).Execute(context.Background(), rt, &PluginsListArgs{Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 || strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("plugins_list password redaction err=%v calls=%#v", err, runner.calls)
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
	marker := "fixture-marker-r93i-short-row"
	for _, query := range []string{showVariablesQuery, showGlobalVariablesQuery} {
		t.Run(query, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte("Variable_name\tValue\nonlyname\n")})
			got, err := showCatalog(context.Background(), rt, (&ShowVariablesArgs{Password: &marker}).connection(), query)
			if err != nil || !reflect.DeepEqual(got, []any{map[string]string{"Variable_name": "onlyname"}}) {
				t.Fatal("short row must return only its prefix, not IndexError or a fabricated Value")
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal("short-row result could not be serialized")
			}
			_ = decodeMysqlJSONValue(t, encoded, marker)
			if len(runner.calls) != 1 || strings.Contains(runner.calls[0].RedactedString(), marker) {
				t.Fatal("short-row result or rendered command failed marker guard")
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

// mysqlUserInfoStdout builds a complete fixed-column batch response. The
// helper is intentionally local to the fake Runner tests: no mysql client or
// database is contacted.
func mysqlUserInfoStdout(user, host string) []byte {
	values := make([]string, len(userInfoColumns))
	values[0] = user
	values[1] = host
	for i := 2; i < len(values); i++ {
		values[i] = "Y"
	}
	return []byte(strings.Join(userInfoColumns, "\t") + "\n" + strings.Join(values, "\t") + "\n")
}

func mysqlUserListStdout(rows ...string) []byte {
	return []byte("User\tHost\n" + strings.Join(rows, "\n") + "\n")
}

func mysqlRemoveRedactionForms(marker string) []string {
	doubled := strings.ReplaceAll(marker, "'", "''")
	literal := "'" + doubled + "'"
	return []string{literal + "@" + literal, literal, doubled, marker}
}

func mysqlRemoveLeakPayload(forms []string) string {
	return "runner failure " + strings.Join(forms, " ") + " DROP USER IF EXISTS " + forms[0]
}

// TestMysqlUserInfo pins the fixed non-secret projection, the exact map
// shape, client-side User/Host matching, connection argv/env/redaction/bounds,
// and the source None/False distinction for a miss versus a failed mysql run.
func TestMysqlUserInfo(t *testing.T) {
	connPass := "info_conn_pass"
	rt, runner := newMysqlRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("User\tHost\nother\tlocalhost\n"),
	})
	// Replace the first result with a complete fixed projection and include a
	// non-matching row before the target to pin client-side filtering.
	runner.results[0] = process.CommandResult{ExitCode: 0, Stdout: append(
		mysqlUserInfoStdout("other", "localhost"),
		mysqlUserInfoStdout("target", "remote")...)}
	args := &UserInfoArgs{
		User:     "target",
		Host:     mysqlString("remote"),
		ConnUser: mysqlString("info_user"),
		ConnHost: mysqlString("info_host"),
		ConnPort: mysqlString("3307"),
		ConnPass: mysqlString(connPass),
		ConnDB:   mysqlString("info_db"),
	}
	before := *args
	value, err := (userInfoFunc{}).Execute(context.Background(), rt, args)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := value.(map[string]any)
	if !ok || len(got) != len(userInfoColumns) || got["User"] != "target" || got["Host"] != "remote" || got["Select_priv"] != "Y" {
		t.Fatalf("user_info = %#v", value)
	}
	for _, field := range []string{"Password", "password", "authentication_string", "Password_hash"} {
		if _, exists := got[field]; exists {
			t.Fatalf("user_info returned secret field %q: %#v", field, got)
		}
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatalf("user_info mutated input: before=%#v after=%#v", before, *args)
	}
	if strings.Contains(strings.ToLower(userInfoQuery), "password") || strings.Contains(userInfoQuery, "SELECT *") {
		t.Fatalf("user_info query is not a fixed non-secret projection: %q", userInfoQuery)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("user_info calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, []string{
		"mysql", "--batch", "--user=info_user", "--host=info_host", "--port=3307", "--database=info_db",
		"--execute=" + userInfoQuery,
	}) {
		t.Fatalf("user_info argv = %q", argv)
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || !reflect.DeepEqual(command.Redact, []string{connPass}) || command.Shell {
		t.Fatalf("user_info transport = %#v", command)
	}
	if command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("user_info bounds = %#v", command)
	}
	if strings.Contains(command.RedactedString(), connPass) {
		t.Fatalf("user_info command leaks connection password: %q", command.RedactedString())
	}

	// User/Host are never interpolated: an injection-shaped lookup uses the
	// byte-identical fixed query and simply produces the source None shape.
	plainRT, plainRunner := newMysqlRuntime(process.CommandResult{Stdout: mysqlUserInfoStdout("safe", "localhost")})
	hostileRT, hostileRunner := newMysqlRuntime(process.CommandResult{Stdout: mysqlUserInfoStdout("safe", "localhost")})
	_, err = (userInfoFunc{}).Execute(context.Background(), plainRT, &UserInfoArgs{User: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (userInfoFunc{}).Execute(context.Background(), hostileRT, &UserInfoArgs{User: "safe' OR '1'='1"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainRunner.calls[0].Args, hostileRunner.calls[0].Args) {
		t.Fatalf("hostile user changed fixed query argv: %q vs %q", hostileRunner.calls[0].Args, plainRunner.calls[0].Args)
	}

	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: mysqlUserInfoStdout("other", "localhost")})
	value, err = (userInfoFunc{}).Execute(context.Background(), rt, &UserInfoArgs{User: "missing"})
	if err != nil || value != nil {
		t.Fatalf("missing user_info = %#v, %v; want nil", value, err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	value, err = (userInfoFunc{}).Execute(context.Background(), rt, &UserInfoArgs{User: "target"})
	if err != nil || value != false {
		t.Fatalf("failed user_info = %#v, %v; want false", value, err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte("User\tHost\nmissing\n")})
	if _, err = (userInfoFunc{}).Execute(context.Background(), rt, &UserInfoArgs{User: "missing"}); !errors.Is(err, errMysqlUserInfoColumn) {
		t.Fatalf("short user_info error = %v", err)
	}
}

// TestMysqlUserInfoFailClosed pins cancellation, missing fixed columns,
// output bounds, Runner failures, and connection-password redaction without a
// live database.
func TestMysqlUserInfoFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &mysqlFakeRunner{}
	if _, err := (userInfoFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &UserInfoArgs{User: "u"}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled user_info error=%v calls=%d", err, len(runner.calls))
	}
	rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte("User\tHost\nu\tlocalhost\n"), StdoutTruncated: true})
	if _, err := (userInfoFunc{}).Execute(context.Background(), rt, &UserInfoArgs{User: "u"}); !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("bounded user_info error=%v calls=%d", err, len(runner.calls))
	}
	marker := "S3CRET-user-info-pass"
	rt, runner = newMysqlRuntime(process.CommandResult{Err: errors.New("mysql failed with " + marker)})
	_, err := (userInfoFunc{}).Execute(context.Background(), rt, &UserInfoArgs{User: "u", ConnPass: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 {
		t.Fatalf("user_info Runner error leaks secret: %v calls=%d", err, len(runner.calls))
	}
}

// TestMysqlCreateStatementVectors pins the source version ladder and all
// fixed CREATE USER clause forms. No vector invokes a Runner or database.
func TestMysqlCreateStatementVectors(t *testing.T) {
	pass := mysqlString("p'ass%✓")
	hash := mysqlString("*hash")
	cases := []struct {
		name     string
		version  string
		password *string
		hash     *string
		allow    bool
		socket   bool
		host     string
		want     string
		wantOK   bool
	}{
		{"modern-password", "8.0.34", pass, nil, false, false, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password BY 'p''ass%✓'", true},
		{"allow-passwordless-wins", "8.0.34", pass, nil, true, false, "localhost", "CREATE USER 'u'@'localhost'", true},
		{"old-password", "8.0.10", pass, nil, false, false, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED BY 'p''ass%✓'", true},
		{"modern-hash", "8.0.34", nil, hash, false, false, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password AS '*hash'", true},
		{"mariadb-hash", "10.5.0-MariaDB", nil, hash, false, false, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED BY PASSWORD '*hash'", true},
		{"passwordless", "8.0.34", nil, nil, true, false, "localhost", "CREATE USER 'u'@'localhost'", true},
		{"mysql-socket", "8.0.34", nil, nil, false, true, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED WITH auth_socket", true},
		{"mariadb-socket", "10.5.0-MariaDB", nil, nil, false, true, "localhost", "CREATE USER 'u'@'localhost' IDENTIFIED VIA unix_socket", true},
		{"socket-nonlocal", "8.0.34", nil, nil, false, true, "%", "", false},
		{"missing-password", "8.0.34", nil, nil, false, false, "localhost", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok := mysqlCreateStatement("u", tc.host, tc.version, tc.password, tc.hash, tc.allow, tc.socket, "mysql_native_password")
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("statement=%q ok=%v, want %q/%v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
	if got := mysqlAccount("u' OR 1=1 --", "h"); got != "'u'' OR 1=1 --'@'h'" {
		t.Fatalf("account quoting = %q", got)
	}
	if _, err := mysqlAuthPlugin(mysqlString("plugin;DROP")); !errors.Is(err, errMysqlAuthPlugin) {
		t.Fatalf("unsafe auth plugin error = %v", err)
	}
}

func TestMysqlPasswordColumnAndVerification(t *testing.T) {
	legacyRT, legacyRunner := newMysqlRuntime(process.CommandResult{Stdout: []byte("HasPassword\n1\n")})
	column, err := mysqlResolvePasswordColumn(context.Background(), legacyRT, &myConnection{}, nil, "Password")
	if err != nil || column != "Password" || len(legacyRunner.calls) != 1 || legacyRunner.calls[0].Args[len(legacyRunner.calls[0].Args)-1] != "--execute="+passwordColumnQuery {
		t.Fatalf("legacy column=%q err=%v calls=%d", column, err, len(legacyRunner.calls))
	}
	modernRT, modernRunner := newMysqlRuntime(process.CommandResult{Stdout: []byte("HasPassword\n")})
	column, err = mysqlResolvePasswordColumn(context.Background(), modernRT, &myConnection{}, nil)
	if err != nil || column != "authentication_string" || len(modernRunner.calls) != 1 {
		t.Fatalf("modern column=%q err=%v calls=%d", column, err, len(modernRunner.calls))
	}
	fallbackRT, fallbackRunner := newMysqlRuntime(process.CommandResult{ExitCode: 1})
	column, err = mysqlResolvePasswordColumn(context.Background(), fallbackRT, &myConnection{}, nil)
	if err != nil || column != "Password" || len(fallbackRunner.calls) != 1 {
		t.Fatalf("fallback column=%q err=%v calls=%d", column, err, len(fallbackRunner.calls))
	}
	explicitRunner := &mysqlFakeRunner{}
	column, err = mysqlResolvePasswordColumn(context.Background(), &runtime.Runtime{Runner: explicitRunner}, &myConnection{}, mysqlString("Password"))
	if err != nil || column != "Password" || len(explicitRunner.calls) != 0 {
		t.Fatalf("explicit column=%q err=%v calls=%d", column, err, len(explicitRunner.calls))
	}

	// The verification result is a constant, so an account/password overlap
	// cannot be destroyed by transport redaction before parsing.
	overlap := "same"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\nsame\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{Stdout: []byte("Verified\n1\n")},
	)
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: overlap, Password: mysqlString(overlap), ConnPass: mysqlString("8.0.34")})
	if err != nil || value != true || len(runner.calls) != 6 {
		t.Fatalf("overlap user_create=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	post := runner.calls[5]
	if strings.Contains(post.RedactedString(), overlap) || !strings.Contains(post.Args[len(post.Args)-1], "SELECT 1 AS Verified") {
		t.Fatalf("overlap post command=%#v", post)
	}
}

// TestMysqlUserCreate pins the source version/preflight/create/post-check
// flow, exact argv and connection flags, idempotent existing-user result,
// password redaction, and statement nonzero compatibility false.
func TestMysqlUserCreate(t *testing.T) {
	connPass := "conn_create_pass"
	createPass := "create_pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("created\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\nnewuser\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{Stdout: []byte("Verified\n1\n")},
	)
	args := &UserCreateArgs{
		User:     "newuser",
		Password: mysqlString(createPass),
		ConnUser: mysqlString("admin"),
		ConnHost: mysqlString("db-host"),
		ConnPort: mysqlString("3308"),
		ConnPass: mysqlString(connPass),
		ConnDB:   mysqlString("mysql"),
	}
	before := *args
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true {
		t.Fatalf("user_create = %#v, %v; want true", value, err)
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatalf("user_create mutated input: before=%#v after=%#v", before, *args)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("user_create calls = %d, want 6", len(runner.calls))
	}
	wantStatements := []string{
		"--execute=" + selectVersionQuery,
		"--execute=" + userListQuery,
		"--execute=" + passwordColumnQuery,
		"--execute=CREATE USER 'newuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'create_pass'",
		"--execute=" + userPluginQuery,
		"--execute=SELECT 1 AS Verified FROM mysql.user WHERE User = 'newuser' AND Host = 'localhost' AND authentication_string = '" + mysqlNativePasswordHash(createPass) + "'",
	}
	for i, want := range wantStatements {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if argv[len(argv)-1] != want {
			t.Fatalf("call %d argv=%q, want final %q", i, argv, want)
		}
		if len(runner.calls[i].Env) != 1 || runner.calls[i].Env[0] != "MYSQL_PWD="+connPass || runner.calls[i].Shell {
			t.Fatalf("call %d connection transport=%#v", i, runner.calls[i])
		}
	}
	statementCommand := runner.calls[3]
	if len(statementCommand.Redact) < 3 || strings.Contains(statementCommand.RedactedString(), createPass) || strings.Contains(statementCommand.RedactedString(), connPass) {
		t.Fatalf("statement redaction=%#v rendered=%q", statementCommand.Redact, statementCommand.RedactedString())
	}
	if statementCommand.Timeout != commandTimeout || statementCommand.MaxStdoutBytes != outputLimit || statementCommand.MaxStderrBytes != outputLimit {
		t.Fatalf("statement bounds=%#v", statementCommand)
	}

	// Existing accounts are an idempotent source no-op: version and fixed
	// User/Host preflight only, never CREATE USER.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("newuser\tlocalhost")},
	)
	value, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: "newuser", Password: mysqlString(createPass)})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("existing user_create=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// A nonzero CREATE result is the source boolean False, with no post-check.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("denied create_pass\n")},
	)
	value, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: "newuser", Password: mysqlString(createPass)})
	if err != nil || value != false || len(runner.calls) != 4 {
		t.Fatalf("failed user_create=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// unix_socket is source-preflighted through the fixed plugin catalog, and
	// its plugin clause wins over the supplied password. The post-check reads
	// the actual plugin and therefore does not fake a native password check.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("PLUGIN_NAME\tPLUGIN_STATUS\nauth_socket\tACTIVE\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\nsocket_user\tlocalhost\tauth_socket\n")},
	)
	value, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: "socket_user", Password: mysqlString("ignored"), AllowPasswordless: mysqlBool(true), UnixSocket: mysqlBool(true)})
	if err != nil || value != true || len(runner.calls) != 6 {
		t.Fatalf("socket user_create=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[3].Args[len(runner.calls[3].Args)-1]; got != "--execute="+pluginStatusQuery {
		t.Fatalf("plugin preflight SQL=%q", got)
	}
	if got := runner.calls[4].Args[len(runner.calls[4].Args)-1]; got != "--execute=CREATE USER 'socket_user'@'localhost' IDENTIFIED WITH auth_socket" {
		t.Fatalf("socket CREATE SQL=%q", got)
	}
	if got := runner.calls[5].Args[len(runner.calls[5].Args)-1]; got != "--execute="+userPluginQuery {
		t.Fatalf("socket post-check SQL=%q", got)
	}
}

func TestMysqlUserCreatePluginAwareVerification(t *testing.T) {
	tests := []struct {
		name            string
		args            *UserCreateArgs
		actualPlugin    string
		verification    string
		want            bool
		wantCalls       int
		wantVerifyQuery string
	}{
		{
			name:            "native-password-success",
			args:            &UserCreateArgs{User: "native", Password: mysqlString("native-pass")},
			actualPlugin:    "mysql_native_password",
			verification:    "1",
			want:            true,
			wantCalls:       6,
			wantVerifyQuery: "SELECT 1 AS Verified FROM mysql.user WHERE User = 'native' AND Host = 'localhost' AND authentication_string = '" + mysqlNativePasswordHash("native-pass") + "'",
		},
		{
			name:            "native-password-mismatch",
			args:            &UserCreateArgs{User: "native-mismatch", Password: mysqlString("native-pass")},
			actualPlugin:    "mysql_native_password",
			verification:    "0",
			want:            false,
			wantCalls:       6,
			wantVerifyQuery: "SELECT 1 AS Verified FROM mysql.user WHERE User = 'native-mismatch' AND Host = 'localhost' AND authentication_string = '" + mysqlNativePasswordHash("native-pass") + "'",
		},
		{
			name:            "native-password-hash",
			args:            &UserCreateArgs{User: "native-hash", PasswordHash: mysqlString("*HASH")},
			actualPlugin:    "mysql_native_password",
			verification:    "1",
			want:            true,
			wantCalls:       6,
			wantVerifyQuery: "SELECT 1 AS Verified FROM mysql.user WHERE User = 'native-hash' AND Host = 'localhost' AND authentication_string = '*HASH'",
		},
		{
			name:         "non-native-password",
			args:         &UserCreateArgs{User: "caching", Password: mysqlString("native-pass"), AuthPlugin: mysqlString("caching_sha2_password")},
			actualPlugin: "caching_sha2_password",
			want:         true,
			wantCalls:    5,
		},
		{
			name:         "default-plugin",
			args:         &UserCreateArgs{User: "default-plugin", Password: mysqlString("native-pass")},
			actualPlugin: "",
			want:         true,
			wantCalls:    5,
		},
		{
			name:         "socket-password",
			args:         &UserCreateArgs{User: "socket", Password: mysqlString("ignored"), UnixSocket: mysqlBool(true)},
			actualPlugin: "auth_socket",
			want:         true,
			wantCalls:    6,
		},
		{
			name:         "passwordless-native",
			args:         &UserCreateArgs{User: "passwordless", Password: mysqlString("ignored"), AllowPasswordless: mysqlBool(true)},
			actualPlugin: "mysql_native_password",
			want:         true,
			wantCalls:    5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := []process.CommandResult{
				{Stdout: []byte("VERSION()\n8.0.34\n")},
				{Stdout: mysqlUserListStdout("other\tlocalhost")},
				{Stdout: []byte("HasPassword\n")},
			}
			if pointerBool(tc.args.UnixSocket) {
				results = append(results, process.CommandResult{Stdout: []byte("PLUGIN_NAME\tPLUGIN_STATUS\nauth_socket\tACTIVE\n")})
			}
			results = append(results,
				process.CommandResult{ExitCode: 0},
				process.CommandResult{Stdout: []byte("User\tHost\tplugin\n" + tc.args.User + "\tlocalhost\t" + tc.actualPlugin + "\n")},
			)
			if tc.verification != "" {
				results = append(results, process.CommandResult{Stdout: []byte("Verified\n" + tc.verification + "\n")})
			}
			rt, runner := newMysqlRuntime(results...)
			value, err := (userCreateFunc{}).Execute(context.Background(), rt, tc.args)
			if err != nil || value != tc.want || len(runner.calls) != tc.wantCalls {
				t.Fatalf("value=%#v err=%v calls=%d", value, err, len(runner.calls))
			}
			pluginIndex := tc.wantCalls - 1
			if tc.verification != "" {
				pluginIndex--
			}
			pluginCall := runner.calls[pluginIndex]
			if got := pluginCall.Args[len(pluginCall.Args)-1]; got != "--execute="+userPluginQuery {
				t.Fatalf("plugin query=%q", got)
			}
			if tc.wantVerifyQuery != "" {
				verifyCall := runner.calls[tc.wantCalls-1]
				if got := verifyCall.Args[len(verifyCall.Args)-1]; got != "--execute="+tc.wantVerifyQuery {
					t.Fatalf("verify query=%q", got)
				}
			} else {
				for _, call := range runner.calls {
					if strings.Contains(call.Args[len(call.Args)-1], "Verified") {
						t.Fatal("unsupported/passwordless plugin path performed native verification")
					}
				}
			}
		})
	}
}

func TestMysqlUserCreateValidLiteralBoundary(t *testing.T) {
	user, host, password := "u'✓%", "h'✓%", "p'✓%"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\n" + user + "\t" + host + "\tcaching_sha2_password\n")},
	)
	value, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		User:       user,
		Host:       mysqlString(host),
		Password:   mysqlString(password),
		AuthPlugin: mysqlString("caching_sha2_password"),
	})
	if err != nil || value != true || len(runner.calls) != 5 {
		t.Fatalf("valid literal create=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	want := "--execute=CREATE USER 'u''✓%'@'h''✓%' IDENTIFIED WITH caching_sha2_password BY 'p''✓%'"
	if got := runner.calls[3].Args[len(runner.calls[3].Args)-1]; got != want {
		t.Fatalf("valid literal SQL=%q want=%q", got, want)
	}
}

// TestMysqlUserCreateFailClosed pins invalid account/plugin/input boundaries,
// cancellation, output limits, and Runner-error redaction before any real DB.
func TestMysqlUserCreateFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		args *UserCreateArgs
		want error
	}{
		{"account-newline", &UserCreateArgs{User: "bad\nuser", Password: mysqlString("secret")}, errMysqlAccountArgument},
		{"account-backslash", &UserCreateArgs{User: `bad\\user`, Password: mysqlString("secret")}, errMysqlAccountArgument},
		{"account-control", &UserCreateArgs{User: "bad\x7fuser", Password: mysqlString("secret")}, errMysqlAccountArgument},
		{"host-backslash", &UserCreateArgs{User: "u", Host: mysqlString(`bad\\host`), Password: mysqlString("secret")}, errMysqlAccountArgument},
		{"password-backslash", &UserCreateArgs{User: "u", Password: mysqlString(`bad\\password`)}, errMysqlAccountArgument},
		{"password-control", &UserCreateArgs{User: "u", Password: mysqlString("bad\x01password")}, errMysqlAccountArgument},
		{"password-hash-backslash", &UserCreateArgs{User: "u", PasswordHash: mysqlString(`*bad\\hash`)}, errMysqlAccountArgument},
		{"password-hash-control", &UserCreateArgs{User: "u", PasswordHash: mysqlString("*bad\x1fhash")}, errMysqlAccountArgument},
		{"plugin", &UserCreateArgs{User: "u", Password: mysqlString("secret"), AuthPlugin: mysqlString("bad;plugin")}, errMysqlAuthPlugin},
		{"runas", &UserCreateArgs{User: "u", Password: mysqlString("secret"), Runas: mysqlString("root")}, errMysqlRunas},
	} {
		runner := &mysqlFakeRunner{}
		_, err := (userCreateFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, tc.args)
		if !errors.Is(err, tc.want) || len(runner.calls) != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s err=%v calls=%d", tc.name, err, len(runner.calls))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &mysqlFakeRunner{}
	if _, err := (userCreateFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &UserCreateArgs{User: "u", Password: mysqlString("secret")}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled create err=%v calls=%d", err, len(runner.calls))
	}

	marker := "S3CRET-create-pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Err: errors.New("create failed " + marker + " conn")},
	)
	_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: "u", Password: mysqlString(marker), ConnPass: mysqlString("conn")})
	if err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 4 {
		t.Fatalf("redacted create error=%v calls=%d", err, len(runner.calls))
	}

	longPassword := strings.Repeat("x", runtime.MaxCommandInputBytes)
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
	)
	_, err = (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{User: "u", Password: mysqlString(longPassword)})
	if !errors.Is(err, runtime.ErrCommandInputLimit) || len(runner.calls) != 3 {
		t.Fatalf("bounded create err=%v calls=%d", err, len(runner.calls))
	}
}

func TestMysqlUserCreateFirstPreflightRedaction(t *testing.T) {
	connectionPassword := "R9_CONN_FIRST_PREFLIGHT"
	password := "R9_PASSWORD_FIRST_PREFLIGHT"
	passwordHash := "*R9_HASH_FIRST_PREFLIGHT"
	markers := []string{connectionPassword, password, passwordHash}
	resultWithMarkers := process.CommandResult{
		Err:    errors.New("runner error " + connectionPassword + " " + password + " " + passwordHash),
		Stdout: []byte("stdout " + connectionPassword + " " + password + " " + passwordHash),
		Stderr: []byte("stderr " + connectionPassword + " " + password + " " + passwordHash),
	}
	rt, runner := newMysqlRuntime(resultWithMarkers)
	_, err := (userCreateFunc{}).Execute(context.Background(), rt, &UserCreateArgs{
		User:         "u",
		Password:     mysqlString(password),
		PasswordHash: mysqlString(passwordHash),
		ConnPass:     mysqlString(connectionPassword),
	})
	if err == nil || len(runner.calls) != 1 {
		t.Fatalf("first preflight err=%v calls=%d", err, len(runner.calls))
	}
	for _, marker := range markers {
		if strings.Contains(err.Error(), marker) || strings.Contains(runner.calls[0].RedactedString(), marker) {
			t.Fatalf("first preflight leaked %q: err=%v command=%q", marker, err, runner.calls[0].RedactedString())
		}
		found := false
		for _, secret := range runner.calls[0].Redact {
			if secret == marker {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("first preflight inventory missing %q: %#v", marker, runner.calls[0].Redact)
		}
	}
	if runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute="+selectVersionQuery {
		t.Fatalf("first preflight executed mutation: %q", runner.calls[0].Args[len(runner.calls[0].Args)-1])
	}

	// PreserveStdout is parser-only. Even a direct transport caller receives
	// redacted stdout/stderr when the first preflight fails.
	transportRT, _ := newMysqlRuntime(resultWithMarkers)
	inventory := mysqlMutationSecretInventory(&myConnection{Password: mysqlString(connectionPassword)}, mysqlString(password), mysqlString(passwordHash))
	transportResult, transportErr := runMysqlPreserve(context.Background(), transportRT, mysqlQueryArgv(&myConnection{}, selectVersionQuery), &myConnection{Password: mysqlString(connectionPassword)}, inventory...)
	if transportErr == nil {
		t.Fatal("direct preflight transport unexpectedly succeeded")
	}
	for _, value := range []string{string(transportResult.Stdout), string(transportResult.Stderr), transportErr.Error()} {
		for _, marker := range markers {
			if strings.Contains(value, marker) {
				t.Fatalf("direct transport leaked %q in %q", marker, value)
			}
		}
	}

	// The connection-password retry carries the same inventory even though
	// MYSQL_PWD switches to the requested account password on the second run.
	retryRT, retryRunner := newMysqlRuntime(process.CommandResult{ExitCode: 1}, resultWithMarkers)
	_, retryErr := (userCreateFunc{}).Execute(context.Background(), retryRT, &UserCreateArgs{
		User:         "u",
		Password:     mysqlString(password),
		PasswordHash: mysqlString(passwordHash),
		ConnPass:     mysqlString(connectionPassword),
	})
	if retryErr == nil || len(retryRunner.calls) != 2 {
		t.Fatalf("retry first preflight err=%v calls=%d", retryErr, len(retryRunner.calls))
	}
	for index, command := range retryRunner.calls {
		for _, marker := range markers {
			if strings.Contains(command.RedactedString(), marker) {
				t.Fatalf("retry %d leaked %q in rendered command %q", index, marker, command.RedactedString())
			}
		}
		if strings.Contains(command.Args[len(command.Args)-1], "CREATE USER") {
			t.Fatalf("retry %d reached mutation", index)
		}
	}
}

// TestMysqlUserRemove pins the source preflight/no-op/post-check flow and the
// required DROP USER IF EXISTS statement with safe account-literal quoting.
func TestMysqlUserRemove(t *testing.T) {
	connPass := "remove_conn_pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: mysqlUserListStdout("gone\tlocalhost")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
	)
	args := &UserRemoveArgs{User: "gone", ConnUser: mysqlString("admin"), ConnHost: mysqlString("db"), ConnPort: mysqlString("3306"), ConnPass: mysqlString(connPass), ConnDB: mysqlString("mysql")}
	before := *args
	value, err := (userRemoveFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("user_remove=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatalf("user_remove mutated input: before=%#v after=%#v", before, *args)
	}
	wantRedact := mysqlUserRemoveSecretInventory(&myConnection{Password: mysqlString(connPass)}, "gone", "localhost")
	if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); got[len(got)-1] != "--execute=DROP USER IF EXISTS 'gone'@'localhost'" {
		t.Fatalf("drop argv=%q", got)
	}
	for i, command := range runner.calls {
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) || !reflect.DeepEqual(command.Redact, wantRedact) || command.Shell {
			t.Fatalf("call %d transport=%#v", i, command)
		}
		if command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("call %d bounds=%#v", i, command)
		}
	}

	// A missing account is a source False no-op and never sends DROP USER.
	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")})
	value, err = (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{User: "gone"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("missing user_remove=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// An unsuccessful DROP remains the source False result and skips the
	// post-check.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: mysqlUserListStdout("gone\tlocalhost")},
		process.CommandResult{ExitCode: 1},
	)
	value, err = (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{User: "gone"})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("failed user_remove=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// Account strings are SQL literals, never executable query fragments.
	hostile := "u' OR '1'='1"
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: mysqlUserListStdout(hostile + "\tlocalhost")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
	)
	value, err = (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{User: hostile})
	if err != nil || value != true || !strings.Contains(runner.calls[1].Args[len(runner.calls[1].Args)-1], "DROP USER IF EXISTS 'u'' OR ''1''=''1'@'localhost'") {
		t.Fatalf("hostile user_remove=%#v err=%v argv=%q", value, err, runner.calls[1].Args)
	}
}

// TestMysqlUserRemoveCompleteRedactionInventory covers every user_remove
// transport phase when the connection password is the apostrophe-bearing User
// and Host. The fixed catalog must still parse the raw account on successful
// preflights, while synthetic raw/doubled/quoted/account SQL is absent from
// errors, captured streams, and rendered commands.
func TestMysqlUserRemoveCompleteRedactionInventory(t *testing.T) {
	marker := "remove'account"
	user, host := marker, marker
	forms := mysqlRemoveRedactionForms(marker)
	leak := mysqlRemoveLeakPayload(forms)

	for failAt := 0; failAt < 3; failAt++ {
		results := make([]process.CommandResult, 0, failAt+1)
		for call := 0; call < failAt; call++ {
			if call == 1 {
				results = append(results, process.CommandResult{ExitCode: 0})
				continue
			}
			results = append(results, process.CommandResult{Stdout: mysqlUserListStdout(user + "\t" + host)})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak),
			Stderr: []byte("stderr " + leak),
		})
		rt, runner := newMysqlRuntime(results...)
		args := &UserRemoveArgs{
			User:     user,
			Host:     mysqlString(host),
			ConnUser: mysqlString("admin"),
			ConnHost: mysqlString("db-host"),
			ConnPort: mysqlString("3306"),
			ConnPass: mysqlString(marker),
			ConnDB:   mysqlString("mysql"),
		}
		before := *args
		_, err := (userRemoveFunc{}).Execute(context.Background(), rt, args)
		if err == nil || len(runner.calls) != failAt+1 {
			t.Fatalf("failAt=%d err=%v calls=%d, want one failing call at each phase", failAt, err, len(runner.calls))
		}
		if !strings.Contains(err.Error(), process.RedactedPlaceholder) {
			t.Fatalf("failAt=%d error lacks redaction placeholder: %v", failAt, err)
		}
		for _, form := range forms {
			if strings.Contains(err.Error(), form) {
				t.Fatalf("failAt=%d error leaked %q: %v", failAt, form, err)
			}
		}
		if !reflect.DeepEqual(*args, before) {
			t.Fatalf("failAt=%d mutated input: before=%#v after=%#v", failAt, before, *args)
		}
		for index, command := range runner.calls {
			if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) || command.Shell {
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

	conn := &myConnection{Password: mysqlString(marker)}
	inventory := mysqlUserRemoveSecretInventory(conn, user, host)
	rt, runner := newMysqlRuntime(process.CommandResult{
		Err:    errors.New(leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	})
	result, err := runMysqlPreserve(context.Background(), rt, mysqlQueryArgv(conn, userListQuery), conn, inventory...)
	if err == nil || result.Err == nil || len(runner.calls) != 1 {
		t.Fatalf("direct preserved transport err=%v result=%v calls=%d", err, result.Err, len(runner.calls))
	}
	for _, output := range []string{err.Error(), result.Err.Error(), string(result.Stdout), string(result.Stderr), runner.calls[0].RedactedString()} {
		for _, form := range forms {
			if strings.Contains(output, form) {
				t.Fatalf("direct transport leaked %q in %q", form, output)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	args := &UserRemoveArgs{User: user, Host: mysqlString(host), ConnPass: mysqlString(marker)}
	before := *args
	runner = &mysqlFakeRunner{}
	_, err = (userRemoveFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, args)
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 || !reflect.DeepEqual(*args, before) {
		t.Fatalf("cancelled remove err=%v calls=%d before=%#v after=%#v", err, len(runner.calls), before, *args)
	}
}

// TestMysqlUserMutationsFailClosed covers shared cancellation, malformed
// account values, and mutation Runner error redaction on the remove path.
func TestMysqlUserMutationsFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &mysqlFakeRunner{}
	if _, err := (userRemoveFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &UserRemoveArgs{User: "u"}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled remove err=%v calls=%d", err, len(runner.calls))
	}
	runner = &mysqlFakeRunner{}
	if _, err := (userRemoveFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, &UserRemoveArgs{User: "bad\x00user"}); !errors.Is(err, errMysqlAccountArgument) || len(runner.calls) != 0 {
		t.Fatalf("invalid remove err=%v calls=%d", err, len(runner.calls))
	}
	marker := "S3CRET-remove-pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: mysqlUserListStdout("u\tlocalhost")},
		process.CommandResult{Err: errors.New("drop failed " + marker)},
	)
	_, err := (userRemoveFunc{}).Execute(context.Background(), rt, &UserRemoveArgs{User: "u", ConnPass: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 2 {
		t.Fatalf("redacted remove error=%v calls=%d", err, len(runner.calls))
	}
}

// TestMysqlUserMutationRegistry drives all three R9.3e names through the
// actual runtime registry and asserts the bool/null map result contracts.
func TestMysqlUserMutationRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}

	runner.results = []process.CommandResult{{Stdout: mysqlUserInfoStdout("u", "localhost")}}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.user_info", &UserInfoArgs{User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := value.(map[string]any); !ok || got["User"] != "u" {
		t.Fatalf("registry user_info=%#v", value)
	}

	runner.results = []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: mysqlUserListStdout("other\tlocalhost")},
		{Stdout: []byte("HasPassword\n")},
		{ExitCode: 0},
		{Stdout: []byte("User\tHost\tplugin\nu\tlocalhost\tmysql_native_password\n")},
		{Stdout: []byte("Verified\n1\n")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_create", &UserCreateArgs{User: "u", Password: mysqlString("p")})
	if err != nil || value != true {
		t.Fatalf("registry user_create=%#v err=%v", value, err)
	}

	runner.results = []process.CommandResult{
		{Stdout: mysqlUserListStdout("u\tlocalhost")},
		{ExitCode: 0},
		{Stdout: mysqlUserListStdout("other\tlocalhost")},
	}
	value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_remove", &UserRemoveArgs{User: "u"})
	if err != nil || value != true || len(runner.calls) != 10 {
		t.Fatalf("registry user_remove=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
}

func TestMysqlUserMutationRegistryFirstPreflightRedaction(t *testing.T) {
	connectionPassword := "R9_REGISTRY_CONN_PREFLIGHT"
	password := "R9_REGISTRY_PASSWORD_PREFLIGHT"
	passwordHash := "*R9_REGISTRY_HASH_PREFLIGHT"
	runner := &mysqlFakeRunner{results: []process.CommandResult{{
		Err:    errors.New("registry " + connectionPassword + " " + password + " " + passwordHash),
		Stdout: []byte("registry stdout " + connectionPassword + " " + password + " " + passwordHash),
		Stderr: []byte("registry stderr " + connectionPassword + " " + password + " " + passwordHash),
	}}}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	_, err := rt.Exec.Call(context.Background(), rt, "mysql.user_create", &UserCreateArgs{
		User:         "u",
		Password:     mysqlString(password),
		PasswordHash: mysqlString(passwordHash),
		ConnPass:     mysqlString(connectionPassword),
	})
	if err == nil || len(runner.calls) != 1 {
		t.Fatalf("registry first preflight err=%v calls=%d", err, len(runner.calls))
	}
	for _, marker := range []string{connectionPassword, password, passwordHash} {
		if strings.Contains(err.Error(), marker) || strings.Contains(runner.calls[0].RedactedString(), marker) {
			t.Fatalf("registry first preflight leaked %q: err=%v command=%q", marker, err, runner.calls[0].RedactedString())
		}
		found := false
		for _, secret := range runner.calls[0].Redact {
			if secret == marker {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("registry first preflight inventory missing %q: %#v", marker, runner.calls[0].Redact)
		}
	}
}

func TestMysqlUserRemoveRegistryRedactionInventory(t *testing.T) {
	marker := "registry'remove"
	forms := mysqlRemoveRedactionForms(marker)
	leak := mysqlRemoveLeakPayload(forms)
	for failAt := 0; failAt < 3; failAt++ {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		results := make([]process.CommandResult, 0, failAt+1)
		for call := 0; call < failAt; call++ {
			if call == 1 {
				results = append(results, process.CommandResult{ExitCode: 0})
				continue
			}
			results = append(results, process.CommandResult{Stdout: mysqlUserListStdout(marker + "\t" + marker)})
		}
		results = append(results, process.CommandResult{
			Err:    errors.New(leak),
			Stdout: []byte("stdout " + leak),
			Stderr: []byte("stderr " + leak),
		})
		runner := &mysqlFakeRunner{results: results}
		rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
		args := &UserRemoveArgs{User: marker, Host: mysqlString(marker), ConnPass: mysqlString(marker)}
		before := *args
		value, err := rt.Exec.Call(context.Background(), rt, "mysql.user_remove", args)
		if err == nil || value != nil || len(runner.calls) != failAt+1 {
			t.Fatalf("failAt=%d value=%#v err=%v calls=%d", failAt, value, err, len(runner.calls))
		}
		for _, form := range forms {
			if strings.Contains(err.Error(), form) {
				t.Fatalf("failAt=%d registry error leaked %q: %v", failAt, form, err)
			}
		}
		if !reflect.DeepEqual(*args, before) {
			t.Fatalf("failAt=%d registry mutated input: before=%#v after=%#v", failAt, before, *args)
		}
		for index, command := range runner.calls {
			for _, form := range forms {
				if strings.Contains(command.RedactedString(), form) {
					t.Fatalf("failAt=%d call=%d registry command leaked %q: %q", failAt, index, form, command.RedactedString())
				}
			}
			if failAt == 0 && strings.Contains(strings.Join(command.Args, " "), "DROP USER") {
				t.Fatalf("failAt=%d registry reached DROP before the failing preflight", failAt)
			}
		}
	}
}

// TestMysqlUserChpassStatementVectors pins the source MySQL/MariaDB version
// ladder, password-over-hash precedence, empty-password handling, plugin
// clauses, passwordless/socket branches, and the value-free unsafe boundary.
// These are pure builders: no mysql client or database is contacted.
func TestMysqlUserChpassStatementVectors(t *testing.T) {
	pass := mysqlString("p'ass%✓")
	hash := mysqlString("*HASH")
	empty := mysqlString("")
	cases := []struct {
		name    string
		version string
		pass    *string
		hash    *string
		allow   bool
		socket  bool
		host    string
		plugin  string
		want    string
		ok      bool
	}{
		{"mysql-modern-password", "8.0.34", pass, hash, false, false, "localhost", "caching_sha2_password", "ALTER USER 'u'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'p''ass%✓';", true},
		{"mysql-modern-hash", "8.0.34", nil, hash, false, false, "localhost", "mysql_native_password", "ALTER USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password AS '*HASH';", true},
		{"mysql-old-password", "8.0.10", pass, nil, false, false, "localhost", "mysql_native_password", "UPDATE mysql.user SET Password=PASSWORD('p''ass%✓') WHERE User='u' AND Host = 'localhost';", true},
		{"mariadb-modern-password", "10.5.0-MariaDB", pass, nil, false, false, "localhost", "ed25519", "ALTER USER 'u'@'localhost' IDENTIFIED VIA ed25519 USING PASSWORD('p''ass%✓')", true},
		{"mariadb-old-hash", "10.3.9-MariaDB", nil, hash, false, false, "localhost", "mysql_native_password", "UPDATE mysql.user SET Password='*HASH' WHERE User='u' AND Host = 'localhost';", true},
		{"mysql-empty-wins", "8.0.34", empty, hash, false, false, "localhost", "mysql_native_password", "ALTER USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password BY '';", true},
		{"mysql-passwordless", "8.0.34", nil, nil, true, false, "localhost", "mysql_native_password", "ALTER USER 'u'@'localhost' IDENTIFIED WITH mysql_native_password ", true},
		{"mysql-socket-modern", "8.0.34", pass, nil, true, true, "localhost", "mysql_native_password", "ALTER USER 'u'@'localhost' IDENTIFIED WITH auth_socket AS 'u';", true},
		{"mariadb-socket-old", "10.3.9-MariaDB", pass, nil, true, true, "localhost", "mysql_native_password", "UPDATE mysql.user SET Password=PASSWORD('p''ass%✓'), plugin='unix_socket' WHERE User='u' AND Host = 'localhost';", true},
		{"socket-nonlocal", "8.0.34", nil, nil, true, true, "%", "mysql_native_password", "", false},
		{"missing-credential", "8.0.34", nil, nil, false, false, "localhost", "mysql_native_password", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok := mysqlChangePasswordStatement("u", tc.host, tc.version, tc.pass, tc.hash, tc.allow, tc.socket, "Password", tc.plugin)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("statement=%q ok=%v, want %q/%v", got, ok, tc.want, tc.ok)
			}
		})
	}
	if _, _, ok := mysqlChangePasswordStatement("u", "localhost", "8.0.34", pass, nil, false, false, "Password", "bad-plugin"); ok {
		t.Fatal("unsafe plugin was accepted")
	}
	if _, err := mysqlPasswordColumn(mysqlString("password")); !errors.Is(err, errMysqlPasswordColumn) {
		t.Fatalf("unsafe password column error=%v", err)
	}
}

// TestMysqlUserChpass pins the fixed preflight/schema/plugin/mutation/flush
// sequence, exact connection flags, hash-independent plugin handling, and
// the complete redaction/bounds contract on a fake Runner.
func TestMysqlUserChpass(t *testing.T) {
	connPass := "chpass_conn_pass"
	newPass := "new'p%ass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tremote")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tremote\tcaching_sha2_password\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	args := &UserChpassArgs{
		User:         "target",
		Host:         mysqlString("remote"),
		Password:     mysqlString(newPass),
		PasswordHash: mysqlString("*ignored-hash"),
		ConnUser:     mysqlString("admin"),
		ConnHost:     mysqlString("db-host"),
		ConnPort:     mysqlString("3308"),
		ConnPass:     mysqlString(connPass),
		ConnDB:       mysqlString("mysql"),
	}
	before := *args
	value, err := (userChpassFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true {
		t.Fatalf("user_chpass=%#v err=%v, want true", value, err)
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatalf("user_chpass mutated input: before=%#v after=%#v", before, *args)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("user_chpass calls=%d, want 6", len(runner.calls))
	}
	want := []string{
		"--execute=" + selectVersionQuery,
		"--execute=" + userListQuery,
		"--execute=" + passwordColumnQuery,
		"--execute=" + userPluginQuery,
		"ALTER USER 'target'@'remote' IDENTIFIED WITH caching_sha2_password BY 'new''p%ass';",
		"--execute=FLUSH PRIVILEGES;",
	}
	for i, command := range runner.calls {
		got := command.Args[len(command.Args)-1]
		if i == 4 {
			got = string(command.Stdin)
			if !reflect.DeepEqual(command.Args, []string{"--batch", "--user=admin", "--host=db-host", "--port=3308", "--database=mysql"}) {
				t.Fatal("mutation argv is not fixed connection-only argv")
			}
		}
		if got != want[i] {
			t.Fatalf("call %d SQL=%q want=%q", i, got, want[i])
		}
		if command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("call %d unsafe transport=%#v", i, command)
		}
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connPass}) {
			t.Fatalf("call %d environment=%#v", i, command.Env)
		}
	}
	statement := runner.calls[4]
	if strings.Contains(statement.RedactedString(), newPass) || strings.Contains(statement.RedactedString(), connPass) {
		t.Fatalf("statement command leaked password: %q", statement.RedactedString())
	}
	for _, secret := range mysqlUserChpassSecretInventory(&myConnection{Password: mysqlString(connPass)}, "target", "remote", mysqlString(newPass), mysqlString("*ignored-hash")) {
		found := false
		for _, redacted := range statement.Redact {
			if redacted == secret {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mutation redaction missing %q: %#v", secret, statement.Redact)
		}
	}
}

// TestMysqlUserChpassSelfPasswordUsesOneSession guards the connection
// boundary that a CLI transport cannot otherwise preserve: changing the
// password of the account used for the connection must execute the fixed
// mutation and FLUSH in one mysql process, with no second login using the old
// MYSQL_PWD and no repeated mutation.
func TestMysqlUserChpassSelfPasswordUsesOneSession(t *testing.T) {
	connectionPassword := "old-self-pass"
	newPassword := "new'self%pass"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("self-user\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\nself-user\tlocalhost\tcaching_sha2_password\n")},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{
		User:     "self-user",
		Password: mysqlString(newPassword),
		ConnUser: mysqlString("self-user"),
		ConnPass: mysqlString(connectionPassword),
	})
	if err != nil || value != true {
		t.Fatalf("self user_chpass=%#v err=%v, want true", value, err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("self user_chpass calls=%d, want four preflights plus one same-session command", len(runner.calls))
	}
	command := runner.calls[4]
	query := string(command.Stdin)
	wantQuery := "ALTER USER 'self-user'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'new''self%pass'; FLUSH PRIVILEGES;"
	if !reflect.DeepEqual(command.Args, []string{"--batch", "--user=self-user"}) {
		t.Fatal("self mutation argv is not connection-only")
	}
	if query != wantQuery || strings.Count(query, "ALTER USER") != 1 || strings.Count(query, "FLUSH PRIVILEGES;") != 1 {
		t.Fatalf("self same-session query=%q, want ordered mutation and flush", query)
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connectionPassword}) || command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("self same-session transport=%#v", command)
	}
	secrets := mysqlUserChpassSecretInventory(&myConnection{User: mysqlString("self-user"), Password: mysqlString(connectionPassword)}, "self-user", "localhost", mysqlString(newPassword), nil)
	if !containsAll(command.Redact, secrets) || strings.Contains(command.RedactedString(), connectionPassword) || strings.Contains(command.RedactedString(), newPassword) {
		t.Fatalf("self same-session redaction=%#v rendered=%q", command.Redact, command.RedactedString())
	}
	if strings.Count(query, "ALTER USER") != 1 {
		t.Fatalf("self mutation repeated in query=%q", query)
	}
}

// TestMysqlUserChpassSelfPasswordRetryUsesNewCredential verifies the source
// recovery path after a preceding state changed the connection account: the
// version retry uses the new password, then the self mutation and FLUSH still
// share one command and no mutation is repeated.
func TestMysqlUserChpassSelfPasswordRetryUsesNewCredential(t *testing.T) {
	oldPassword := "old-retry-pass"
	newPassword := "new-retry'secret"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n")},
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("retry-user\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\nretry-user\tlocalhost\tcaching_sha2_password\n")},
		process.CommandResult{ExitCode: 0},
	)
	args := &UserChpassArgs{
		User:     "retry-user",
		Password: mysqlString(newPassword),
		ConnUser: mysqlString("retry-user"),
		ConnPass: mysqlString(oldPassword),
	}
	before := *args
	value, err := (userChpassFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true || len(runner.calls) != 6 {
		t.Fatalf("retry self user_chpass=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if !reflect.DeepEqual(*args, before) {
		t.Fatal("retry self user_chpass mutated its input")
	}
	if !reflect.DeepEqual(runner.calls[0].Env, []string{"MYSQL_PWD=" + oldPassword}) {
		t.Fatal("initial retry preflight did not use the original connection password")
	}
	for _, command := range runner.calls[1:] {
		if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + newPassword}) {
			t.Fatal("retry flow did not switch to the new connection password")
		}
	}
	query := string(runner.calls[5].Stdin)
	if query != "ALTER USER 'retry-user'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'new-retry''secret'; FLUSH PRIVILEGES;" || strings.Count(query, "ALTER USER") != 1 {
		t.Fatal("retry self flow did not issue one ordered same-session command")
	}
}

func mysqlUserChpassRedactionMatrixResults(failAt int) []process.CommandResult {
	successes := []process.CommandResult{
		{Stdout: []byte("VERSION()\n8.0.34\n")},
		{Stdout: []byte("User\tHost\nmatrix'user\tmatrix'host\n")},
		{Stdout: []byte("HasPassword\n")},
		{Stdout: []byte("User\tHost\tplugin\nmatrix'user\tmatrix'host\ted25519\n")},
		{ExitCode: 0},
		{ExitCode: 0},
	}
	results := append([]process.CommandResult(nil), successes[:failAt]...)
	marker := "matrix'redaction"
	hash := "*" + marker
	forms := mysqlUserChpassSecretInventory(
		&myConnection{Password: mysqlString(marker)},
		"matrix'user", "matrix'host", mysqlString(marker), mysqlString(hash),
	)
	leak := strings.Join(forms, " ")
	results = append(results, process.CommandResult{
		Err:    errors.New("phase failure " + leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	})
	return results
}

func mysqlUserChpassRedactionMatrixArgs() *UserChpassArgs {
	marker := "matrix'redaction"
	return &UserChpassArgs{
		User:         "matrix'user",
		Host:         mysqlString("matrix'host"),
		Password:     mysqlString(marker),
		PasswordHash: mysqlString("*" + marker),
		ConnUser:     mysqlString("matrix-connection"),
		ConnPass:     mysqlString(marker),
	}
}

func assertMysqlUserChpassRedaction(t *testing.T, command process.Command, err error, forms []string) {
	t.Helper()
	if err == nil {
		t.Fatal("user_chpass phase unexpectedly succeeded")
	}
	for _, form := range forms {
		if strings.Contains(strings.Join(command.Args, " "), form) {
			t.Fatal("user_chpass argv contains a credential or SQL account form")
		}
		if strings.Contains(err.Error(), form) || strings.Contains(command.RedactedString(), form) {
			t.Fatal("user_chpass phase leaked a redaction form")
		}
		if !containsAll(command.Redact, []string{form}) {
			t.Fatal("user_chpass phase omitted a redaction form")
		}
	}
	if command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatal("user_chpass phase used an unsafe transport")
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=matrix'redaction"}) {
		t.Fatal("user_chpass phase did not keep the connection password out of argv")
	}
}

// TestMysqlUserChpassDirectRedactionPhaseMatrix injects the same complete
// credential/account inventory at each direct user_chpass phase. The replayed
// transport assertion also checks sanitized stdout and stderr, which the
// public bool/error result does not expose.
func TestMysqlUserChpassDirectRedactionPhaseMatrix(t *testing.T) {
	marker := "matrix'redaction"
	hash := "*" + marker
	forms := mysqlUserChpassSecretInventory(
		&myConnection{Password: mysqlString(marker)},
		"matrix'user", "matrix'host", mysqlString(marker), mysqlString(hash),
	)
	for failAt := 0; failAt < 6; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			rt, runner := newMysqlRuntime(mysqlUserChpassRedactionMatrixResults(failAt)...)
			value, err := (userChpassFunc{}).Execute(context.Background(), rt, mysqlUserChpassRedactionMatrixArgs())
			if err == nil || value != nil || len(runner.calls) != failAt+1 {
				t.Fatalf("phase=%d value=%#v calls=%d", failAt, value, len(runner.calls))
			}
			failedCommand := runner.calls[len(runner.calls)-1]
			assertMysqlUserChpassRedaction(t, failedCommand, err, forms)

			transportRunner := &mysqlFakeRunner{results: []process.CommandResult{{
				Err:    errors.New("transport phase failure " + strings.Join(forms, " ")),
				Stdout: []byte("transport stdout " + strings.Join(forms, " ")),
				Stderr: []byte("transport stderr " + strings.Join(forms, " ")),
			}}}
			transportRuntime := &runtime.Runtime{Runner: transportRunner}
			argv := append([]string{failedCommand.Name}, failedCommand.Args...)
			safeResult, transportErr := runMysqlInputResultSecrets(
				context.Background(), transportRuntime, argv, string(failedCommand.Stdin),
				&myConnection{User: mysqlString("matrix-connection"), Password: mysqlString(marker)}, nil, failedCommand.PreserveStdout, forms...,
			)
			if transportErr == nil || safeResult.Err == nil {
				t.Fatal("direct transport did not return the injected phase failure")
			}
			for _, surface := range []string{transportErr.Error(), safeResult.Err.Error(), string(safeResult.Stdout), string(safeResult.Stderr), failedCommand.RedactedString()} {
				for _, form := range forms {
					if strings.Contains(surface, form) {
						t.Fatal("direct phase transport leaked a redaction form")
					}
				}
			}
		})
	}
}

// TestMysqlUserChpassRegistryRedactionPhaseMatrix drives every preflight,
// mutation, and separate flush failure through the registered public name.
func TestMysqlUserChpassRegistryRedactionPhaseMatrix(t *testing.T) {
	marker := "matrix'redaction"
	forms := mysqlUserChpassSecretInventory(
		&myConnection{Password: mysqlString(marker)},
		"matrix'user", "matrix'host", mysqlString(marker), mysqlString("*"+marker),
	)
	for failAt := 0; failAt < 6; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			rt := &runtime.Runtime{Runner: &mysqlFakeRunner{results: mysqlUserChpassRedactionMatrixResults(failAt)}, Exec: reg, FS: runtime.NewMemoryFS()}
			value, err := rt.Exec.Call(context.Background(), rt, "mysql.user_chpass", mysqlUserChpassRedactionMatrixArgs())
			runner := rt.Runner.(*mysqlFakeRunner)
			if err == nil || value != nil || len(runner.calls) != failAt+1 {
				t.Fatalf("phase=%d value=%#v calls=%d", failAt, value, len(runner.calls))
			}
			assertMysqlUserChpassRedaction(t, runner.calls[len(runner.calls)-1], err, forms)
		})
	}
}

func TestMysqlUserChpassShapesAndFailClosed(t *testing.T) {
	// An existing-account miss is a source false/no-op and never mutates.
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("other\tlocalhost")},
	)
	value, err := (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{User: "target", Password: mysqlString("secret")})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("missing account=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// Empty password is explicit and wins over password_hash.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{User: "target", Password: mysqlString(""), PasswordHash: mysqlString("*HASH")})
	if err != nil || value != true || !strings.Contains(string(runner.calls[4].Stdin), " BY '';") || strings.Contains(string(runner.calls[4].Stdin), "*HASH") {
		t.Fatal("empty password precedence lost")
	}

	// A nonzero mutation is a source false and stops before FLUSH.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("denied secret")},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{User: "target", Password: mysqlString("secret")})
	if err != nil || value != false || len(runner.calls) != 5 {
		t.Fatalf("mutation nonzero=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// A failed flush is an execution error after exactly one mutation.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 1, Stderr: []byte("flush secret")},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{User: "target", Password: mysqlString("secret")})
	if !errors.Is(err, errMysqlPasswordChangeExit) || value != nil || len(runner.calls) != 6 {
		t.Fatalf("flush error=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// Unknown but syntactically safe plugins are preserved in the fixed clause;
	// unsafe plugin bytes from a server row fail closed before mutation.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\ted25519\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{User: "target", Password: mysqlString("secret")})
	if err != nil || value != true || !strings.Contains(string(runner.calls[4].Stdin), "WITH ed25519") {
		t.Fatalf("unknown plugin=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// Passwordless socket mode performs its fixed plugin-status preflight and
	// keeps the source mutation/flush calls separate even when the connection
	// user is the target account.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{Stdout: []byte("PLUGIN_NAME\tPLUGIN_STATUS\nauth_socket\tACTIVE\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{
		User:              "target",
		Password:          mysqlString("ignored-by-socket"),
		AllowPasswordless: mysqlBool(true),
		UnixSocket:        mysqlBool(true),
		ConnUser:          mysqlString("target"),
	})
	if err != nil || value != true || len(runner.calls) != 7 {
		t.Fatalf("socket path=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if got := string(runner.calls[5].Stdin); got != "ALTER USER 'target'@'localhost' IDENTIFIED WITH auth_socket AS 'target';" {
		t.Fatalf("socket mutation=%q", got)
	}
	if got := runner.calls[6].Args[len(runner.calls[6].Args)-1]; got != "--execute=FLUSH PRIVILEGES;" {
		t.Fatalf("socket flush=%q", got)
	}

	// Bare passwordless mode also retains the source's distinct mutation and
	// flush commands instead of taking the self-password same-session branch.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("VERSION()\n8.0.34\n")},
		process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
		process.CommandResult{Stdout: []byte("HasPassword\n")},
		process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\tmysql_native_password\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0},
	)
	value, err = (userChpassFunc{}).Execute(context.Background(), rt, &UserChpassArgs{
		User:              "target",
		AllowPasswordless: mysqlBool(true),
		ConnUser:          mysqlString("target"),
	})
	if err != nil || value != true || len(runner.calls) != 6 {
		t.Fatalf("passwordless path=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	mutationSQL := string(runner.calls[4].Stdin)
	if !strings.HasSuffix(mutationSQL, "IDENTIFIED WITH mysql_native_password ") || strings.Contains(mutationSQL, "FLUSH PRIVILEGES") {
		t.Fatalf("passwordless mutation=%q", mutationSQL)
	}
	if got := runner.calls[5].Args[len(runner.calls[5].Args)-1]; got != "--execute=FLUSH PRIVILEGES;" {
		t.Fatalf("passwordless flush=%q", got)
	}

	// The fixed transport fails closed without a database/Runner, and the
	// caller's unsafe backslash never reaches a Runner.
	if _, err = (userChpassFunc{}).Execute(context.Background(), &runtime.Runtime{}, &UserChpassArgs{User: "u", Password: mysqlString("secret")}); !errors.Is(err, errMysqlRunnerUnavailable) {
		t.Fatalf("no Runner error=%v", err)
	}
	invalidRunner := &mysqlFakeRunner{}
	if _, err = (userChpassFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: invalidRunner}, &UserChpassArgs{User: "u", Password: mysqlString(`bad\\password`)}); !errors.Is(err, errMysqlAccountArgument) || len(invalidRunner.calls) != 0 {
		t.Fatalf("unsafe password err=%v calls=%d", err, len(invalidRunner.calls))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelRunner := &mysqlFakeRunner{}
	if _, err = (userChpassFunc{}).Execute(ctx, &runtime.Runtime{Runner: cancelRunner}, &UserChpassArgs{User: "u", Password: mysqlString("secret")}); !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 0 {
		t.Fatalf("cancelled chpass err=%v calls=%d", err, len(cancelRunner.calls))
	}
}

func TestMysqlUserChpassRedactionAndRegistry(t *testing.T) {
	marker := "same'overlap"
	hash := "*" + marker
	forms := append(mysqlLiteralSecretForms(marker), mysqlLiteralSecretForms(hash)...)
	forms = append(forms, mysqlLiteralSecretForms(marker)...)
	forms = append(forms, mysqlAccount(marker, marker))
	leak := strings.Join(forms, " ")
	runner := &mysqlFakeRunner{results: []process.CommandResult{{
		Err:    errors.New("preflight " + leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	}}}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	args := &UserChpassArgs{User: marker, Host: mysqlString(marker), Password: mysqlString(marker), PasswordHash: mysqlString(hash), ConnPass: mysqlString(marker)}
	value, err := rt.Exec.Call(context.Background(), rt, "mysql.user_chpass", args)
	if err == nil || value != nil || len(runner.calls) != 1 {
		t.Fatalf("registry redaction value=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	for _, output := range []string{err.Error(), runner.calls[0].RedactedString()} {
		for _, form := range forms {
			if strings.Contains(output, form) {
				t.Fatalf("redaction leaked %q in %q", form, output)
			}
		}
	}
	if runner.calls[0].Shell || runner.calls[0].Timeout != commandTimeout || runner.calls[0].MaxStdoutBytes != outputLimit || runner.calls[0].MaxStderrBytes != outputLimit {
		t.Fatalf("unsafe redaction transport=%#v", runner.calls[0])
	}
}

// TestMysqlVerifyLogin pins source connection override semantics: the login
// user/password replace connection_user/connection_pass, host/port/database
// survive, the SQL is fixed, and the password remains only MYSQL_PWD.
func TestMysqlVerifyLogin(t *testing.T) {
	password := "verify'p%ass"
	rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("1\n")})
	args := &VerifyLoginArgs{
		User:     "login_user",
		Password: mysqlString(password),
		ConnUser: mysqlString("ignored_user"),
		ConnHost: mysqlString("db-host"),
		ConnPort: mysqlString("3307"),
		ConnPass: mysqlString("ignored_pass"),
		ConnDB:   mysqlString("maintenance"),
	}
	value, err := (verifyLoginFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true || len(runner.calls) != 1 {
		t.Fatalf("verify_login=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	command := runner.calls[0]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=login_user", "--host=db-host", "--port=3307", "--database=maintenance", "--execute=" + verifyLoginQuery,
	}) {
		t.Fatalf("verify_login argv=%q", got)
	}
	if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + password}) || command.Shell || command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
		t.Fatalf("verify_login transport=%#v", command)
	}
	if strings.Contains(command.RedactedString(), password) || !containsAll(command.Redact, mysqlLiteralSecretForms(password)) {
		t.Fatalf("verify_login redaction=%#v rendered=%q", command.Redact, command.RedactedString())
	}

	// Login failure is the source false result, with no plugin/hash query.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")})
	value, err = (verifyLoginFunc{}).Execute(context.Background(), rt, &VerifyLoginArgs{User: "login_user", Password: mysqlString(password)})
	if err != nil || value != false || len(runner.calls) != 1 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute="+verifyLoginQuery {
		t.Fatalf("verify_login failure=%#v err=%v calls=%d", value, err, len(runner.calls))
	}

	// Empty password stays an explicit out-of-band value; nil has no env entry.
	for _, tc := range []struct {
		name string
		pass *string
		env  []string
	}{
		{"empty", mysqlString(""), []string{"MYSQL_PWD="}},
		{"nil", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 0})
			value, err := (verifyLoginFunc{}).Execute(context.Background(), rt, &VerifyLoginArgs{User: "u", Password: tc.pass})
			if err != nil || value != true || !reflect.DeepEqual(runner.calls[0].Env, tc.env) {
				t.Fatalf("value=%#v err=%v env=%#v", value, err, runner.calls[0].Env)
			}
		})
	}
}

// Both entry points exercise the actual mutation transport, including legacy
// UPDATE and hash-only paths, not just the statement constructor.
func TestMysqlUserChpassStdinDirectAndRegistry(t *testing.T) {
	for _, registered := range []bool{false, true} {
		for _, tc := range []struct {
			name, version, plugin, sql string
			hashOnly                   bool
		}{
			{"modern-password", "8.0.34", "caching_sha2_password", "ALTER USER 'target'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'stdin''password'; FLUSH PRIVILEGES;", false},
			{"modern-hash", "8.0.34", "mysql_native_password", "ALTER USER 'target'@'localhost' IDENTIFIED WITH mysql_native_password AS '*stdin''hash'; FLUSH PRIVILEGES;", true},
			{"legacy-password", "5.6.51", "mysql_native_password", "UPDATE mysql.user SET Password=PASSWORD('stdin''password') WHERE User='target' AND Host = 'localhost'; FLUSH PRIVILEGES;", false},
		} {
			for _, failed := range []bool{false, true} {
				t.Run(fmt.Sprintf("registry=%t/%s/failure=%t", registered, tc.name, failed), func(t *testing.T) {
					password, hash, connection := "stdin'password", "*stdin'hash", "stdin'connection"
					args := &UserChpassArgs{User: "target", ConnUser: mysqlString("target"), ConnPass: &connection, PasswordColumn: mysqlString("Password"), Password: &password, PasswordHash: &hash}
					if tc.hashOnly {
						args.Password = nil
					}
					forms := mysqlUserChpassSecretInventory(args.connection(), args.User, "localhost", args.Password, args.PasswordHash)
					last := process.CommandResult{}
					if failed {
						last = process.CommandResult{Err: errors.New(strings.Join(forms, " ")), Stdout: []byte(strings.Join(forms, " ")), Stderr: []byte(strings.Join(forms, " "))}
					}
					rt, runner := newMysqlRuntime(
						process.CommandResult{Stdout: []byte("VERSION()\n" + tc.version + "\n")},
						process.CommandResult{Stdout: mysqlUserListStdout("target\tlocalhost")},
						process.CommandResult{Stdout: []byte("User\tHost\tplugin\ntarget\tlocalhost\t" + tc.plugin + "\n")}, last,
					)
					var value any
					var err error
					if registered {
						rt.Exec = runtime.NewExecRegistry()
						if err := Register(rt.Exec); err != nil {
							t.Fatal(err)
						}
						value, err = rt.Exec.Call(context.Background(), rt, "mysql.user_chpass", args)
					} else {
						value, err = (userChpassFunc{}).Execute(context.Background(), rt, args)
					}
					if len(runner.calls) != 4 || (failed && (err == nil || value != nil)) || (!failed && (err != nil || value != true)) {
						t.Fatal("unexpected mutation result or repeated process")
					}
					command := runner.calls[3]
					if string(command.Stdin) != tc.sql {
						t.Fatalf("ordered stdin mismatch for %s", tc.name)
					}
					if !reflect.DeepEqual(command.Args, []string{"--batch", "--user=target"}) || command.Shell || len(command.Stdin) > runtime.MaxCommandInputBytes {
						t.Fatal("unsafe stdin transport")
					}
					for _, c := range runner.calls {
						for _, form := range mysqlMutationSecretInventory(args.connection(), args.Password, args.PasswordHash) {
							if strings.Contains(strings.Join(c.Args, " "), form) {
								t.Fatal("credential present in argv")
							}
						}
						for _, form := range forms {
							if strings.Contains(c.RedactedString(), form) || (err != nil && strings.Contains(err.Error(), form)) {
								t.Fatal("credential leaked")
							}
						}
					}
				})
			}
		}
	}
}

func TestMysqlUserChpassStdinBounds(t *testing.T) {
	rt, runner := newMysqlRuntime()
	_, err := runMysqlStatement(context.Background(), rt, nil, strings.Repeat("x", runtime.MaxCommandInputBytes+1))
	if !errors.Is(err, runtime.ErrCommandInputLimit) || len(runner.calls) != 0 {
		t.Fatal("oversized stdin reached Runner")
	}
	for _, result := range []process.CommandResult{{StdoutTruncated: true}, {StderrTruncated: true}, {Stdout: make([]byte, outputLimit+1)}, {Stderr: make([]byte, outputLimit+1)}} {
		rt, runner := newMysqlRuntime(result)
		_, err := runMysqlStatement(context.Background(), rt, nil, "FLUSH PRIVILEGES;")
		if !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
			t.Fatal("stdin transport lost output bounds")
		}
	}
}

// SQL account, password_hash, and native-verifier derivations are inapplicable:
// verify_login only connects with the supplied password and runs SELECT 1.
// Connection forms here mean the effective MYSQL_PWD, not ignored ConnPass.
func TestMysqlVerifyLoginRedactionDirectAndRegistryMatrix(t *testing.T) {
	marker := "verify'matrix"
	doubled := "verify''matrix"
	for _, registered := range []bool{false, true} {
		for _, tc := range []struct {
			name, form string
			applicable bool
		}{
			{"raw", marker, true}, {"doubled", doubled, true}, {"quoted", "'" + doubled + "'", true},
			{"connection", "MYSQL_PWD=" + marker, true},
			{"account-SQL-not-generated", "'login-user'@'db-host'", false},
			{"hash-not-accepted", "*unused-hash", false},
			{"native-verifier-not-derived", mysqlNativePasswordHash(marker), false},
			{"overridden-connection-password", "unused-connection-password", false},
		} {
			t.Run(fmt.Sprintf("registry=%t/%s/applicable=%t", registered, tc.name, tc.applicable), func(t *testing.T) {
				result := process.CommandResult{Stdout: []byte("1\n")}
				if tc.applicable {
					result = process.CommandResult{Err: errors.New("failure " + tc.form), Stdout: []byte(tc.form), Stderr: []byte(tc.form)}
				}
				rt, runner := newMysqlRuntime(result)
				args := &VerifyLoginArgs{User: "login-user", Password: &marker, ConnHost: mysqlString("db-host"), ConnPass: mysqlString("unused-connection-password")}
				var value any
				var err error
				if registered {
					rt.Exec = runtime.NewExecRegistry()
					if err := Register(rt.Exec); err != nil {
						t.Fatal(err)
					}
					value, err = rt.Exec.Call(context.Background(), rt, "mysql.verify_login", args)
				} else {
					value, err = (verifyLoginFunc{}).Execute(context.Background(), rt, args)
				}
				if len(runner.calls) != 1 {
					t.Fatal("verify_login must use one process")
				}
				command := runner.calls[0]
				if !reflect.DeepEqual(command.Args, []string{"--batch", "--user=login-user", "--host=db-host", "--execute=SELECT 1"}) || len(command.Stdin) != 0 || command.Shell {
					t.Fatal("verify_login generated non-constant SQL")
				}
				if !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + marker}) {
					t.Fatal("effective credential override lost")
				}
				if !tc.applicable {
					if err != nil || value != true || strings.Contains(strings.Join(command.Redact, " ")+string(command.Stdin)+strings.Join(command.Args, " ")+strings.Join(command.Env, " "), tc.form) {
						t.Fatal("inapplicable form unexpectedly generated")
					}
					return
				}
				if err == nil || value != nil {
					t.Fatal("injected failure missing")
				}
				// Replay the same transport to inspect streams hidden by the bool API.
				rt, _ = newMysqlRuntime(result)
				login := &myConnection{User: &args.User, Host: args.ConnHost, Password: &marker}
				safe, replayErr := runMysqlSecrets(context.Background(), rt, mysqlQueryArgv(login, verifyLoginQuery), login, mysqlLiteralSecretForms(marker)...)
				if replayErr == nil || safe.Err == nil {
					t.Fatal("transport failure missing")
				}
				for _, surface := range []string{err.Error(), replayErr.Error(), safe.Err.Error(), string(safe.Stdout), string(safe.Stderr), command.RedactedString(), strings.Join(command.Args, " ")} {
					if strings.Contains(surface, tc.form) || strings.Contains(surface, marker) || strings.Contains(surface, doubled) {
						t.Fatal("verify_login leaked applicable credential form")
					}
				}
			})
		}
	}
}

func TestMysqlVerifyLoginFailClosed(t *testing.T) {
	marker := "verify'secret"
	result := process.CommandResult{
		Err:    errors.New("verify failed " + marker),
		Stdout: []byte("stdout " + marker),
		Stderr: []byte("stderr " + marker),
	}
	rt, runner := newMysqlRuntime(result)
	value, err := (verifyLoginFunc{}).Execute(context.Background(), rt, &VerifyLoginArgs{User: "u", Password: mysqlString(marker)})
	if err == nil || value != nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 {
		t.Fatalf("verify error value=%#v err=%v calls=%d", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("verify transport leaked marker: %#v", runner.calls[0])
	}
	for _, tc := range []struct {
		name string
		args *VerifyLoginArgs
		want error
	}{
		{"runas", &VerifyLoginArgs{User: "u", Password: mysqlString(marker), Runas: mysqlString("root")}, errMysqlRunas},
		{"nul-password", &VerifyLoginArgs{User: "u", Password: mysqlString("bad\x00pass")}, errMysqlInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &mysqlFakeRunner{}
			_, err := (verifyLoginFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, tc.args)
			if !errors.Is(err, tc.want) || len(runner.calls) != 0 {
				t.Fatalf("err=%v calls=%d", err, len(runner.calls))
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	if _, err := (verifyLoginFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &VerifyLoginArgs{User: "u", Password: mysqlString(marker)}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled verify err=%v calls=%d", err, len(runner.calls))
	}
}

func assertMysqlValueHasNoMarker(t *testing.T, value any, marker string) {
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
			if strings.Contains(v.String(), marker) {
				t.Fatal("serialized value contains an unredacted marker")
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

func decodeMysqlJSONValue(t *testing.T, encoded []byte, marker string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("serialized JSON could not be decoded")
	}
	assertMysqlValueHasNoMarker(t, value, marker)
	return value
}

func assertMysqlExactValue(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("serialized value shape differs from the expected shape")
	}
}

func mysqlValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// TestMysqlPublicHeaderRedaction covers raw and batch-escaped headers,
// decoded secret values, explicit null presence, and prefix-zipped short rows
// at every public direct renderer.
func TestMysqlPublicHeaderRedaction(t *testing.T) {
	marker := `fixture-marker-r93i\header`
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	header := strings.Join([]string{marker, "wire-" + wireMarker, "stable-column"}, "\t")
	redacted := process.RedactedPlaceholder
	userWant := []map[string]any{{
		redacted:           nil,
		"wire-" + redacted: redacted,
	}}
	maintenanceWant := []map[string]any{{
		redacted:           nil,
		"wire-" + redacted: redacted,
	}}
	showWant := []any{map[string]string{
		redacted:           redacted,
		"wire-" + redacted: redacted,
	}}
	conn := &myConnection{Password: mysqlString(marker)}

	rt, _ := newMysqlRuntime(process.CommandResult{Stdout: []byte(header + "\n\\0\t" + wireMarker + "\n")})
	value, err := userCatalog(context.Background(), rt, conn)
	if err != nil {
		t.Fatal("user_list returned an unexpected error")
	}
	assertMysqlExactValue(t, value, userWant)
	assertMysqlValueHasNoMarker(t, value, marker)
	if row := value[0]; len(row) != 2 {
		t.Fatalf("user_list short-row key count = %d", len(row))
	}
	if nullValue, present := value[0][redacted]; !present || nullValue != nil {
		t.Fatal("user_list redacted null key is absent or non-null")
	}

	for _, query := range []string{showVariablesQuery, showGlobalVariablesQuery} {
		rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte(header + "\n" + wireMarker + "\t" + wireMarker + "\n")})
		value, err := showCatalog(context.Background(), rt, conn, query)
		if err != nil {
			t.Fatal("SHOW renderer returned an unexpected error")
		}
		assertMysqlExactValue(t, value, showWant)
		assertMysqlValueHasNoMarker(t, value, marker)
		if row := value[0].(map[string]string); len(row) != 2 {
			t.Fatalf("SHOW short-row key count = %d", len(row))
		}
	}

	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte(header + "\n\\0\t" + wireMarker + "\n")})
	value, err = maintenanceOne(context.Background(), rt, conn, "CHECK", "db", "table")
	if err != nil {
		t.Fatal("maintenance renderer returned an unexpected error")
	}
	assertMysqlExactValue(t, value, maintenanceWant)
	assertMysqlValueHasNoMarker(t, value, marker)
	if row := value[0]; len(row) != 2 {
		t.Fatalf("maintenance short-row key count = %d", len(row))
	}
	if nullValue, present := value[0][redacted]; !present || nullValue != nil {
		t.Fatal("maintenance redacted null key is absent or non-null")
	}
}

// TestMysqlPublicHeaderCollisionIsSafe ensures both a batch-escaped header
// and an existing redaction-placeholder header fail closed without a map
// overwrite.
func TestMysqlPublicHeaderCollisionIsSafe(t *testing.T) {
	marker := `fixture-marker-r93i\header-collision`
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	conn := &myConnection{Password: mysqlString(marker)}
	for _, collisionHeader := range []struct {
		name   string
		header string
	}{
		{"batch-escaped-header", marker + "\t" + wireMarker},
		{"existing-redaction-placeholder", marker + "\t" + process.RedactedPlaceholder},
	} {
		for _, surface := range []struct {
			name string
			run  func(*runtime.Runtime) (any, error)
		}{
			{"user_list", func(rt *runtime.Runtime) (any, error) {
				return userCatalog(context.Background(), rt, conn)
			}},
			{"showvariables", func(rt *runtime.Runtime) (any, error) {
				return showCatalog(context.Background(), rt, conn, showVariablesQuery)
			}},
			{"showglobal", func(rt *runtime.Runtime) (any, error) {
				return showCatalog(context.Background(), rt, conn, showGlobalVariablesQuery)
			}},
			{"maintenance", func(rt *runtime.Runtime) (any, error) {
				return maintenanceOne(context.Background(), rt, conn, "CHECK", "db", "table")
			}},
		} {
			t.Run(collisionHeader.name+"/"+surface.name, func(t *testing.T) {
				rt, runner := newMysqlRuntime(process.CommandResult{
					Stdout: []byte(collisionHeader.header + "\nfirst\tsecond\n"),
				})
				value, err := surface.run(rt)
				if !mysqlValueIsNil(value) || err == nil || err.Error() != errMysqlHeaderCollision.Error() || len(runner.calls) != 1 {
					t.Fatal("header collision did not fail with the stable value-free error")
				}
				if strings.Contains(err.Error(), marker) {
					t.Fatal("header collision error contains a synthetic marker")
				}
			})
		}
	}
}

// TestMysqlPublicHeaderRedactionThroughRegistry pins exact decoded JSON
// shapes after the execution registry crosses each affected renderer.
func TestMysqlPublicHeaderRedactionThroughRegistry(t *testing.T) {
	marker := `fixture-marker-r93i\registry-header`
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	header := strings.Join([]string{marker, "wire-" + wireMarker, "stable-column"}, "\t")
	redacted := process.RedactedPlaceholder
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	cases := []struct {
		name   string
		args   any
		stdout string
		want   any
		null   bool
	}{
		{"mysql.user_list", &UserListArgs{Password: mysqlString(marker)}, header + "\n\\0\t" + wireMarker + "\n", []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}}, true},
		{"mysql.showvariables", &ShowVariablesArgs{Password: mysqlString(marker)}, header + "\n" + wireMarker + "\t" + wireMarker + "\n", []any{map[string]any{redacted: redacted, "wire-" + redacted: redacted}}, false},
		{"mysql.showglobal", &ShowGlobalArgs{Password: mysqlString(marker)}, header + "\n" + wireMarker + "\t" + wireMarker + "\n", []any{map[string]any{redacted: redacted, "wire-" + redacted: redacted}}, false},
		{"mysql.db_check", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: mysqlString(marker)}, header + "\n\\0\t" + wireMarker + "\n", []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}}, true},
		{"mysql.db_repair", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: mysqlString(marker)}, header + "\n\\0\t" + wireMarker + "\n", []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}}, true},
		{"mysql.db_optimize", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: mysqlString(marker)}, header + "\n\\0\t" + wireMarker + "\n", []any{map[string]any{redacted: nil, "wire-" + redacted: redacted}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner.calls = nil
			runner.results = []process.CommandResult{{Stdout: []byte(tc.stdout)}}
			value, err := reg.Call(context.Background(), rt, tc.name, tc.args)
			if err != nil {
				t.Fatal("registry renderer returned an unexpected error")
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal("registry renderer result could not be serialized")
			}
			got := decodeMysqlJSONValue(t, encoded, marker)
			assertMysqlExactValue(t, got, tc.want)
			if tc.null {
				rows, ok := got.([]any)
				if !ok || len(rows) != 1 {
					t.Fatal("registry null result has an unexpected row shape")
				}
				row, ok := rows[0].(map[string]any)
				if !ok {
					t.Fatal("registry null result is not a map")
				}
				if nullValue, present := row[redacted]; !present || nullValue != nil {
					t.Fatal("registry redacted null key is absent or non-null")
				}
			}
		})
	}
}

func TestMysqlPublicHeaderCollisionThroughRegistry(t *testing.T) {
	marker := `fixture-marker-r93i\registry-collision`
	connArgs := mysqlString(marker)
	wireMarker := strings.ReplaceAll(marker, `\`, `\\`)
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	for _, header := range []string{marker + "\t" + wireMarker, marker + "\t" + process.RedactedPlaceholder} {
		for _, tc := range []struct {
			name string
			args any
		}{
			{"mysql.user_list", &UserListArgs{Password: connArgs}},
			{"mysql.showvariables", &ShowVariablesArgs{Password: connArgs}},
			{"mysql.showglobal", &ShowGlobalArgs{Password: connArgs}},
			{"mysql.db_check", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: connArgs}},
			{"mysql.db_repair", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: connArgs}},
			{"mysql.db_optimize", &DbMaintenanceArgs{Name: "db", Table: mysqlString("table"), Password: connArgs}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				runner.calls = nil
				runner.results = []process.CommandResult{{Stdout: []byte(header + "\nfirst\tsecond\n")}}
				value, err := reg.Call(context.Background(), rt, tc.name, tc.args)
				if !mysqlValueIsNil(value) || err == nil || err.Error() != errMysqlHeaderCollision.Error() || len(runner.calls) != 1 {
					t.Fatal("registry header collision did not fail safely")
				}
				if strings.Contains(err.Error(), marker) {
					t.Fatal("registry header collision error contains a synthetic marker")
				}
			})
		}
	}
}

// TestMysqlDatabaseMutations pins the source db_create/db_remove lifecycle:
// database existence is checked through the fixed catalog, CREATE returns
// the source boolean on the mutation exit status, and DROP performs the
// source post-check before returning its boolean.  All calls use the central
// shell-free mysql transport and carry the password only in MYSQL_PWD.
func TestMysqlDatabaseMutations(t *testing.T) {
	connectionPassword := "db-mutation-connection-pass"
	createArgs := &DbCreateArgs{
		Name:         "new`db%",
		CharacterSet: mysqlString("utf8mb4"),
		Collate:      mysqlString("utf8mb4_0900_ai_ci"),
		User:         mysqlString("admin"),
		Host:         mysqlString("mysql-host"),
		Port:         mysqlString("3307"),
		Password:     mysqlString(connectionPassword),
		DB:           mysqlString("mysql"),
	}
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nother\n")},
		process.CommandResult{ExitCode: 0},
	)
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, createArgs)
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("db_create = %#v, %v, calls=%d; want true and two calls", value, err, len(runner.calls))
	}
	wantCreate := "CREATE DATABASE IF NOT EXISTS `new``db%` CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_0900_ai_ci';"
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute="+wantCreate {
		t.Fatalf("db_create statement = %q, want %q", got, "--execute="+wantCreate)
	}
	for i, command := range runner.calls {
		if command.Shell || !reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + connectionPassword}) ||
			command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
			t.Fatalf("db_create call %d transport = %#v", i, command)
		}
		if strings.Contains(command.RedactedString(), connectionPassword) {
			t.Fatalf("db_create call %d leaks the connection password: %q", i, command.RedactedString())
		}
	}

	// Existing databases are not idempotent success: the pinned preflight
	// returns False without issuing CREATE DATABASE.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nnew`db%\n")})
	value, err = (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "new`db%"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("existing db_create = %#v, %v, calls=%d; want false and one call", value, err, len(runner.calls))
	}

	// A rejected CREATE is the source's false compatibility shape and does not
	// trigger a post-check or a retry.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")},
	)
	value, err = (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "newdb"})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("failed db_create = %#v, %v, calls=%d; want false and two calls", value, err, len(runner.calls))
	}

	// DROP follows the source's exists -> protected-name -> mutation ->
	// exists flow.  A successful post-check miss is true.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nremove_db\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
	)
	value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "remove_db", Password: mysqlString(connectionPassword)})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("db_remove = %#v, %v, calls=%d; want true and three calls", value, err, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=DROP DATABASE `remove_db`;" {
		t.Fatalf("db_remove statement = %q", got)
	}
	if !reflect.DeepEqual(runner.calls[1].Env, []string{"MYSQL_PWD=" + connectionPassword}) || runner.calls[1].Shell {
		t.Fatalf("db_remove transport = %#v", runner.calls[1])
	}

	// Missing and protected names preserve the source false/no-op shape.  The
	// protected check follows the existence preflight, as in mysql.py.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")})
	value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "remove_db"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("missing db_remove = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nmysql\n")})
	value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "mysql"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("protected db_remove = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	// A failed DROP is false without a post-check; a failed post-check is the
	// pinned db_exists false result, so the source returns true after a
	// successful mutation even though the follow-up connection failed.
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")},
		process.CommandResult{ExitCode: 1},
	)
	value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "db"})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("failed db_remove = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	rt, runner = newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 1},
	)
	value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "db"})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("post-check failure db_remove = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

// TestMysqlDatabaseCreateFailsClosedAfterExistenceQueryFailure pins the
// deliberate F2 compatibility ceiling. Salt treats db_exists' False result as
// permission to reconnect and attempt CREATE; StateKit treats a nonzero
// existence query as unknown and never mutates on that path.
func TestMysqlDatabaseCreateFailsClosedAfterExistenceQueryFailure(t *testing.T) {
	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 1, Stderr: []byte("catalog query failed")},
		process.CommandResult{ExitCode: 0}, // must remain unused
	)
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "newdb"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("failed existence preflight = %#v, %v, calls=%d; want false, nil, one call", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[0].Args[len(runner.calls[0].Args)-1], "CREATE DATABASE") {
		t.Fatal("db_create issued CREATE on an uncertain existence result")
	}
}

// TestMysqlDatabaseWildcardPreflightUsesLiteralMatch pins the deliberate F3
// exact-match ceiling. The pinned SHOW DATABASES LIKE query would treat % and
// _ as wildcards; the fixed catalog must not let either pattern match another
// database, while a literal database carrying the wildcard remains a hit.
func TestMysqlDatabaseWildcardPreflightUsesLiteralMatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		other string
	}{
		{name: "my%", other: "my_database"},
		{name: "mysq_", other: "mysql"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(
				process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n" + tc.other + "\n")},
				process.CommandResult{ExitCode: 0},
			)
			value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: tc.name})
			if err != nil || value != true || len(runner.calls) != 2 {
				t.Fatalf("literal wildcard create = %#v, %v, calls=%d; want true and mutation", value, err, len(runner.calls))
			}
			if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; !strings.Contains(got, "CREATE DATABASE IF NOT EXISTS `"+tc.name+"`") {
				t.Fatalf("wildcard name was not carried as a quoted literal: %q", got)
			}

			rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n" + tc.other + "\n")})
			value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: tc.name})
			if err != nil || value != false || len(runner.calls) != 1 {
				t.Fatalf("literal wildcard remove = %#v, %v, calls=%d; want false and no mutation", value, err, len(runner.calls))
			}
		})
	}

	rt, runner := newMysqlRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nmy%\n")},
	)
	value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "my%"})
	if err != nil || value != false || len(runner.calls) != 1 {
		t.Fatalf("literal wildcard existing create = %#v, %v, calls=%d; want false and no mutation", value, err, len(runner.calls))
	}
}

// TestMysqlDatabaseCreateOptionsAndQuoting pins the native-CLI rendering of
// source parameter values: identifier backticks are doubled, % is restored to
// one identifier byte, quote/backslash option data is SQL-literal escaped, and
// explicit empty options are not confused with omitted options.
func TestMysqlDatabaseCreateOptionsAndQuoting(t *testing.T) {
	characterSet := "utf'\\%"
	collate := "ci'\\_"
	statement, err := mysqlDatabaseCreateStatement("db`%_", &characterSet, &collate)
	if err != nil {
		t.Fatal(err)
	}
	want := "CREATE DATABASE IF NOT EXISTS `db``%_` CHARACTER SET 'utf''\\\\%' COLLATE 'ci''\\\\_';"
	if statement != want {
		t.Fatalf("quoted create statement = %q, want %q", statement, want)
	}

	empty := ""
	statement, err = mysqlDatabaseCreateStatement("db", &empty, &empty)
	if err != nil || statement != "CREATE DATABASE IF NOT EXISTS `db` CHARACTER SET '' COLLATE '';" {
		t.Fatalf("explicit empty options = %q, %v", statement, err)
	}

	for _, tc := range []struct {
		key string
		set func(*DbCreateArgs, *string)
	}{
		{key: "character_set", set: func(args *DbCreateArgs, value *string) { args.CharacterSet = value }},
		{key: "collate", set: func(args *DbCreateArgs, value *string) { args.Collate = value }},
	} {
		marker := "option-secret\nmarker"
		args := &DbCreateArgs{Name: "db"}
		tc.set(args, &marker)
		runner := &mysqlFakeRunner{}
		_, err := (dbCreateFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, args)
		if !errors.Is(err, errMysqlInvalidArgument) || strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
			t.Fatalf("invalid %s = %v, calls=%d", tc.key, err, len(runner.calls))
		}
	}
}

type mysqlCancelAfterRunner struct {
	base   *mysqlFakeRunner
	cancel context.CancelFunc
	after  int
}

func (r *mysqlCancelAfterRunner) Run(ctx context.Context, command process.Command) process.CommandResult {
	result := r.base.Run(ctx, command)
	if len(r.base.calls) == r.after {
		r.cancel()
	}
	return result
}

func (r *mysqlCancelAfterRunner) CommandAvailable(name string) bool {
	return r.base.CommandAvailable(name)
}

func mysqlFailureWithSecret(forms []string) process.CommandResult {
	leak := "lifecycle phase failure " + strings.Join(forms, " ")
	return process.CommandResult{
		Err:    errors.New(leak),
		Stdout: []byte("stdout " + leak),
		Stderr: []byte("stderr " + leak),
	}
}

// TestMysqlDatabaseMutationPhaseFailures covers the smallest lifecycle phase
// matrix needed by F4: timeout/output-limit failures at preflight, mutation,
// and post-check; cancellation after a successful preflight; and redaction at
// both mutation and post-check without changing the shared transport.
func TestMysqlDatabaseMutationPhaseFailures(t *testing.T) {
	type phaseCase struct {
		name       string
		results    []process.CommandResult
		wantCalls  int
		wantErr    error
		wantResult any
	}

	createCases := []phaseCase{
		{name: "preflight-timeout", results: []process.CommandResult{{Err: context.DeadlineExceeded}}, wantCalls: 1, wantErr: context.DeadlineExceeded},
		{name: "mutation-timeout", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")}, {Err: context.DeadlineExceeded}}, wantCalls: 2, wantErr: context.DeadlineExceeded},
		{name: "preflight-output", results: []process.CommandResult{{StdoutTruncated: true}}, wantCalls: 1, wantErr: process.ErrOutputLimit},
		{name: "mutation-output", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")}, {StdoutTruncated: true}}, wantCalls: 2, wantErr: process.ErrOutputLimit},
	}
	for _, tc := range createCases {
		t.Run("create/"+tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(tc.results...)
			value, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "db"})
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if value != tc.wantResult || len(runner.calls) != tc.wantCalls {
				t.Fatalf("result = %#v, %v, calls=%d; want %#v, %v, %d", value, err, len(runner.calls), tc.wantResult, tc.wantErr, tc.wantCalls)
			}
		})
	}

	removeCases := []phaseCase{
		{name: "mutation-timeout", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {Err: context.DeadlineExceeded}}, wantCalls: 2, wantErr: context.DeadlineExceeded},
		{name: "postcheck-timeout", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {ExitCode: 0}, {Err: context.DeadlineExceeded}}, wantCalls: 3, wantErr: context.DeadlineExceeded},
		{name: "postcheck-output", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {ExitCode: 0}, {StdoutTruncated: true}}, wantCalls: 3, wantErr: process.ErrOutputLimit},
	}
	for _, tc := range removeCases {
		t.Run("remove/"+tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(tc.results...)
			value, err := (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "db"})
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if value != tc.wantResult || len(runner.calls) != tc.wantCalls {
				t.Fatalf("result = %#v, %v, calls=%d; want %#v, %v, %d", value, err, len(runner.calls), tc.wantResult, tc.wantErr, tc.wantCalls)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	base := &mysqlFakeRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
		{ExitCode: 0},
	}}
	runner := &mysqlCancelAfterRunner{base: base, cancel: cancel, after: 1}
	value, err := (dbCreateFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &DbCreateArgs{Name: "db"})
	if !errors.Is(err, context.Canceled) || value != nil || len(base.calls) != 1 {
		t.Fatalf("cancelled after create preflight = %#v, %v, calls=%d", value, err, len(base.calls))
	}

	marker := "phase-secret'\\suffix"
	forms := mysqlLiteralSecretForms(marker)
	for _, tc := range []struct {
		name    string
		remove  bool
		results []process.CommandResult
		want    int
	}{
		{name: "create-mutation-redaction", results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")}, mysqlFailureWithSecret(forms)}, want: 2},
		{name: "remove-postcheck-redaction", remove: true, results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\ndb\n")}, {ExitCode: 0}, mysqlFailureWithSecret(forms)}, want: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(tc.results...)
			var value any
			var err error
			if tc.remove {
				value, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: "db", Password: mysqlString(marker)})
			} else {
				value, err = (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "db", Password: mysqlString(marker)})
			}
			if err == nil || value != nil || len(runner.calls) != tc.want {
				t.Fatalf("redaction phase = %#v, %v, calls=%d", value, err, len(runner.calls))
			}
			if strings.Contains(err.Error(), marker) || !containsAll(runner.calls[len(runner.calls)-1].Redact, forms) || strings.Contains(runner.calls[len(runner.calls)-1].RedactedString(), marker) {
				t.Fatalf("redaction leaked at %s: err=%q command=%q redact=%#v", tc.name, err, runner.calls[len(runner.calls)-1].RedactedString(), runner.calls[len(runner.calls)-1].Redact)
			}
		})
	}
}

// TestMysqlDatabaseMutationBoundaries pins the shared fail-closed behavior:
// invalid identifiers and runas never reach the Runner, cancellation is
// observed before the preflight, and Runner errors redact connection data.
func TestMysqlDatabaseMutationBoundaries(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", "bad\nname", "bad\x01name", "bad\x7fname"} {
		runner := &mysqlFakeRunner{}
		rt := &runtime.Runtime{Runner: runner}
		_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: name})
		if !errors.Is(err, errMysqlInvalidArgument) || len(runner.calls) != 0 {
			t.Fatalf("invalid db_create name %q: err=%v calls=%d", name, err, len(runner.calls))
		}
		runner = &mysqlFakeRunner{}
		rt = &runtime.Runtime{Runner: runner}
		_, err = (dbRemoveFunc{}).Execute(context.Background(), rt, &DbRemoveArgs{Name: name})
		if !errors.Is(err, errMysqlInvalidArgument) || len(runner.calls) != 0 {
			t.Fatalf("invalid db_remove name %q: err=%v calls=%d", name, err, len(runner.calls))
		}
	}

	runner := &mysqlFakeRunner{}
	rt := &runtime.Runtime{Runner: runner}
	_, err := (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "db", Runas: mysqlString("other")})
	if !errors.Is(err, errMysqlRunas) || len(runner.calls) != 0 {
		t.Fatalf("runas db_create: err=%v calls=%d", err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	rt = &runtime.Runtime{Runner: runner}
	_, err = (dbRemoveFunc{}).Execute(ctx, rt, &DbRemoveArgs{Name: "db"})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled db_remove: err=%v calls=%d", err, len(runner.calls))
	}

	marker := "db-mutation-secret"
	rt, runner = newMysqlRuntime(process.CommandResult{Err: errors.New("runner failed with " + marker)})
	_, err = (dbCreateFunc{}).Execute(context.Background(), rt, &DbCreateArgs{Name: "db", Password: mysqlString(marker)})
	if err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 {
		t.Fatalf("db_create Runner error leaks marker: err=%v calls=%d", err, len(runner.calls))
	}

	for _, fn := range []struct {
		name string
		call func(context.Context, *runtime.Runtime) (any, error)
	}{
		{name: "create", call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (dbCreateFunc{}).Execute(ctx, rt, &DbCreateArgs{Name: "db"})
		}},
		{name: "remove", call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (dbRemoveFunc{}).Execute(ctx, rt, &DbRemoveArgs{Name: "db"})
		}},
	} {
		rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("connection refused")})
		value, err := fn.call(context.Background(), rt)
		if err != nil || value != false || len(runner.calls) != 1 {
			t.Fatalf("preflight %s failure = %#v, %v, calls=%d", fn.name, value, err, len(runner.calls))
		}
	}
}

// TestMysqlDatabaseMutationsThroughRegistry drives both canonical names
// through the same registry used by the CLI and differential inventory.
func TestMysqlDatabaseMutationsThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
		{ExitCode: 0},
	}}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	value, err := reg.Call(context.Background(), rt, "mysql.db_create", &DbCreateArgs{Name: "registry_db"})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("registry db_create = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	runner.calls = nil
	runner.results = []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\nregistry_db\n")},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte("SCHEMA_NAME\n")},
	}
	value, err = reg.Call(context.Background(), rt, "mysql.db_remove", &DbRemoveArgs{Name: "registry_db"})
	if err != nil || value != true || len(runner.calls) != 3 {
		t.Fatalf("registry db_remove existing = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

// TestMysqlAlterDatabaseSourceVectors pins the alter_db source flow: db_get
// supplies falsy-option defaults, then exactly one ALTER DATABASE statement is
// sent with the source's backtick identifier and bare charset/collation tokens.
func TestMysqlAlterDatabaseSourceVectors(t *testing.T) {
	name := "alter`db%"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\n" + name + "\tlatin1\tlatin1_swedish_ci\n")},
		process.CommandResult{ExitCode: 0},
	)
	empty := ""
	args := &AlterDbArgs{
		Name:         name,
		CharacterSet: &empty,
		Collate:      &empty,
		User:         mysqlString("alter-user"),
		Host:         mysqlString("alter-host"),
		Port:         mysqlString("3307"),
		Password:     mysqlString("alter-pass"),
		DB:           mysqlString("maintenance"),
	}
	value, err := (alterDbFunc{}).Execute(context.Background(), rt, args)
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("alter_db defaults = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got != "--execute="+dbGetQuery {
		t.Fatalf("alter_db preflight = %q", got)
	}
	want := "ALTER DATABASE `alter``db%` CHARACTER SET latin1 COLLATE latin1_swedish_ci;"
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute="+want {
		t.Fatalf("alter_db statement = %q, want %q", got, "--execute="+want)
	}
	for i, command := range runner.calls {
		if command.Shell || command.Timeout != commandTimeout ||
			command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit ||
			!reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=alter-pass"}) {
			t.Fatalf("alter_db transport %d = %#v", i, command)
		}
		if strings.Contains(command.RedactedString(), "alter-pass") {
			t.Fatalf("alter_db transport %d leaks password", i)
		}
	}

	// Explicit non-empty options keep their source spelling and do not use the
	// catalog values.
	rt, runner = newMysqlRuntime(
		process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tlatin1\tlatin1_swedish_ci\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("rejected")},
	)
	value, err = (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{
		Name:         "db",
		CharacterSet: mysqlString("utf8mb4"),
		Collate:      mysqlString("utf8mb4_0900_ai_ci"),
	})
	if err != nil || value != false || len(runner.calls) != 2 {
		t.Fatalf("alter_db rejected mutation = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=ALTER DATABASE `db` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;" {
		t.Fatalf("alter_db explicit statement = %q", got)
	}

	// A failed db_get retains its [] compatibility result and prevents ALTER.
	rt, runner = newMysqlRuntime(process.CommandResult{ExitCode: 1})
	value, err = (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db"})
	if err != nil || !reflect.DeepEqual(value, []any{}) || len(runner.calls) != 1 {
		t.Fatalf("alter_db failed db_get = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

// TestMysqlAlterDatabaseSourceExecuteResultVectors keeps the source predicate
// visible even though the native CLI cannot return cursor.execute's value.
// The pinned _execute wrapper returns that DB-API result directly, so the
// representative truthy/falsy integer vectors are 1 and 0.
func TestMysqlAlterDatabaseSourceExecuteResultVectors(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cursorExecute int
		want          bool
	}{
		{name: "truthy execute result", cursorExecute: 1, want: true},
		{name: "falsy execute result", cursorExecute: 0, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cursorExecute != 0; got != tc.want {
				t.Fatalf("source cursor.execute(%d) truthiness = %v, want %v", tc.cursorExecute, got, tc.want)
			}
		})
	}
}

// TestMysqlAlterDatabaseNativeExitResultVectors pins the only result predicate
// observable through the shell-free mysql transport: process success is true
// and process rejection is false. It deliberately does not claim that either
// process result exposes MySQLdb cursor.execute's affected-row value.
func TestMysqlAlterDatabaseNativeExitResultVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   bool
	}{
		{name: "native truthy process result", result: process.CommandResult{ExitCode: 0}, want: true},
		{name: "native falsy process result", result: process.CommandResult{ExitCode: 1}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(
				process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")},
				tc.result,
			)
			value, err := (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db"})
			if err != nil || value != tc.want || len(runner.calls) != 2 {
				t.Fatalf("native result = %#v, %v, calls=%d; want %v", value, err, len(runner.calls), tc.want)
			}
			if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "--execute=ALTER DATABASE `db` CHARACTER SET utf8 COLLATE utf8_general_ci;" {
				t.Fatalf("native exit vector statement=%q", got)
			}
		})
	}
}

// TestMysqlAlterDatabasePreflightShapes documents the source/transport
// boundary around db_get. A successful rowless catalog is {}, whereas a
// failed catalog is []; only the latter is an uncertain preflight and it must
// never be followed by ALTER, even when both options are explicit.
func TestMysqlAlterDatabasePreflightShapes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      *AlterDbArgs
		statement string
	}{
		{
			name:      "explicit character set with catalog collate",
			args:      &AlterDbArgs{Name: "db", CharacterSet: mysqlString("utf8mb4")},
			statement: "ALTER DATABASE `db` CHARACTER SET utf8mb4 COLLATE latin1_swedish_ci;",
		},
		{
			name:      "catalog character set with explicit collate",
			args:      &AlterDbArgs{Name: "db", Collate: mysqlString("utf8mb4_0900_ai_ci")},
			statement: "ALTER DATABASE `db` CHARACTER SET latin1 COLLATE utf8mb4_0900_ai_ci;",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(
				process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tlatin1\tlatin1_swedish_ci\n")},
				process.CommandResult{ExitCode: 0},
			)
			value, err := (alterDbFunc{}).Execute(context.Background(), rt, tc.args)
			if err != nil || value != true || len(runner.calls) != 2 || runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute="+tc.statement {
				t.Fatalf("partial options = %#v, %v, calls=%d argv=%#v", value, err, len(runner.calls), runner.calls)
			}
		})
	}

	missingCatalog := process.CommandResult{Stdout: []byte(
		"SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\nother\tutf8\tutf8_general_ci\n")}
	for _, tc := range []struct {
		name      string
		args      *AlterDbArgs
		wantCalls int
		wantError bool
		statement string
	}{
		{name: "missing catalog and no options", args: &AlterDbArgs{Name: "missing"}, wantCalls: 1, wantError: true},
		{name: "missing catalog and partial options", args: &AlterDbArgs{Name: "missing", CharacterSet: mysqlString("utf8mb4")}, wantCalls: 1, wantError: true},
		{
			name:      "missing catalog and both explicit options",
			args:      &AlterDbArgs{Name: "missing", CharacterSet: mysqlString("utf8mb4"), Collate: mysqlString("utf8mb4_0900_ai_ci")},
			wantCalls: 2,
			statement: "ALTER DATABASE `missing` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(missingCatalog, process.CommandResult{ExitCode: 0})
			value, err := (alterDbFunc{}).Execute(context.Background(), rt, tc.args)
			if tc.wantError {
				if !errors.Is(err, errMysqlInvalidArgument) || value != nil {
					t.Fatalf("missing catalog = %#v, %v; want value-free invalid-argument error", value, err)
				}
			} else if err != nil || value != true {
				t.Fatalf("explicit missing catalog = %#v, %v; want true", value, err)
			}
			if len(runner.calls) != tc.wantCalls {
				t.Fatalf("missing catalog calls=%d, want %d", len(runner.calls), tc.wantCalls)
			}
			if tc.statement != "" && runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute="+tc.statement {
				t.Fatalf("missing catalog statement=%q, want %q", runner.calls[1].Args[len(runner.calls[1].Args)-1], "--execute="+tc.statement)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args *AlterDbArgs
	}{
		{name: "catalog failure without options", args: &AlterDbArgs{Name: "db"}},
		{name: "catalog failure with partial options", args: &AlterDbArgs{Name: "db", CharacterSet: mysqlString("utf8mb4")}},
		{name: "catalog failure with both explicit options", args: &AlterDbArgs{Name: "db", CharacterSet: mysqlString("utf8mb4"), Collate: mysqlString("utf8mb4_0900_ai_ci")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("catalog denied")}, process.CommandResult{ExitCode: 0})
			value, err := (alterDbFunc{}).Execute(context.Background(), rt, tc.args)
			if err != nil || !reflect.DeepEqual(value, []any{}) || len(runner.calls) != 1 {
				t.Fatalf("failed catalog = %#v, %v, calls=%d; want [] and no mutation", value, err, len(runner.calls))
			}
		})
	}

	rt, runner := newMysqlRuntime(process.CommandResult{
		Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\n"),
	})
	value, err := (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db", CharacterSet: mysqlString("utf8mb4"), Collate: mysqlString("utf8mb4_0900_ai_ci")})
	if err == nil || value != nil || len(runner.calls) != 1 {
		t.Fatalf("short catalog = %#v, %v, calls=%d; want error and no mutation", value, err, len(runner.calls))
	}
}

const alterSeedReadbackQuery = "SELECT id, value FROM statekit_seed ORDER BY id"

type mysqlAlterStateRunner struct {
	calls            []process.Command
	characterSet     string
	collate          string
	nextCharset      string
	nextCollate      string
	expectedAlterSQL string
	seedValue        string
	rejectAlter      bool
}

func (r *mysqlAlterStateRunner) CommandAvailable(string) bool { return true }

func (r *mysqlAlterStateRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Redact = append([]string(nil), command.Redact...)
	command.Env = append([]string(nil), command.Env...)
	r.calls = append(r.calls, command)
	if len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 1}
	}
	statementArg := command.Args[len(command.Args)-1]
	query := strings.TrimPrefix(statementArg, "--execute=")
	switch query {
	case dbGetQuery:
		return process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\nstate_db\t" + r.characterSet + "\t" + r.collate + "\n")}
	case alterSeedReadbackQuery:
		return process.CommandResult{Stdout: []byte("id\tvalue\n1\t" + r.seedValue + "\n")}
	default:
		if statementArg != "--execute="+r.expectedAlterSQL {
			return process.CommandResult{ExitCode: 1}
		}
		if r.rejectAlter {
			return process.CommandResult{ExitCode: 1}
		}
		r.characterSet = r.nextCharset
		r.collate = r.nextCollate
		return process.CommandResult{ExitCode: 0}
	}
}

// TestMysqlAlterDatabasePostAlterReadbackPreservesSeed uses a stateful fake
// Runner to make the post-alter evidence explicit: ALTER changes only the
// database metadata, a subsequent fixed db_get reads the new metadata, and a
// separate fixed seed readback remains byte-for-byte unchanged.
func TestMysqlAlterDatabasePostAlterReadbackPreservesSeed(t *testing.T) {
	const explicitAlterSQL = "ALTER DATABASE `state_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"

	for _, tc := range []struct {
		name        string
		rejectAlter bool
		wantValue   bool
		wantCharset string
		wantCollate string
		nextCharset string
		nextCollate string
	}{
		{
			name:        "explicit transition",
			wantValue:   true,
			wantCharset: "utf8mb4",
			wantCollate: "utf8mb4_0900_ai_ci",
			nextCharset: "utf8mb4",
			nextCollate: "utf8mb4_0900_ai_ci",
		},
		{
			name:        "rejected explicit transition",
			rejectAlter: true,
			wantValue:   false,
			wantCharset: "latin1",
			wantCollate: "latin1_swedish_ci",
			nextCharset: "utf8mb4",
			nextCollate: "utf8mb4_0900_ai_ci",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &mysqlAlterStateRunner{
				characterSet:     "latin1",
				collate:          "latin1_swedish_ci",
				nextCharset:      tc.nextCharset,
				nextCollate:      tc.nextCollate,
				expectedAlterSQL: explicitAlterSQL,
				seedValue:        "seed-row",
				rejectAlter:      tc.rejectAlter,
			}
			rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
			value, err := (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{
				Name:         "state_db",
				CharacterSet: mysqlString("utf8mb4"),
				Collate:      mysqlString("utf8mb4_0900_ai_ci"),
			})
			if err != nil || value != tc.wantValue || len(runner.calls) != 2 {
				t.Fatalf("stateful alter = %#v, %v, calls=%d", value, err, len(runner.calls))
			}
			wantMutationArgv := []string{"mysql", "--batch", "--execute=" + explicitAlterSQL}
			if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, wantMutationArgv) {
				t.Fatalf("stateful alter argv = %#v, want %#v", got, wantMutationArgv)
			}

			metadata, err := dbGetCatalog(context.Background(), rt, &myConnection{}, "state_db")
			if err != nil || !reflect.DeepEqual(metadata, map[string]any{"character_set": tc.wantCharset, "collate": tc.wantCollate}) {
				t.Fatalf("post-alter metadata = %#v, %v", metadata, err)
			}
			header, rows, err := mysqlQueryRowsPreserve(context.Background(), rt, &myConnection{}, alterSeedReadbackQuery)
			if err != nil || !reflect.DeepEqual(header, []string{"id", "value"}) || !reflect.DeepEqual(rows, [][]batchField{{{value: "1"}, {value: "seed-row"}}}) {
				t.Fatalf("seed readback = header=%#v rows=%#v err=%v", header, rows, err)
			}
			if len(runner.calls) != 4 {
				t.Fatalf("post-alter readback calls=%d, want 4", len(runner.calls))
			}
			wantArgv := [][]string{
				{"mysql", "--batch", "--execute=" + dbGetQuery},
				wantMutationArgv,
				{"mysql", "--batch", "--execute=" + dbGetQuery},
				{"mysql", "--batch", "--execute=" + alterSeedReadbackQuery},
			}
			for i, want := range wantArgv {
				got := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("stateful alter call %d argv = %#v, want %#v", i, got, want)
				}
			}
		})
	}

	// Default preservation is a separate stateful case: omitted options dispatch
	// the modeled defaults, and the fake's modeled charset/collation stay
	// unchanged rather than simulating the explicit transition above.
	t.Run("default preservation", func(t *testing.T) {
		const defaultAlterSQL = "ALTER DATABASE `state_db` CHARACTER SET latin1 COLLATE latin1_swedish_ci;"
		runner := &mysqlAlterStateRunner{
			characterSet:     "latin1",
			collate:          "latin1_swedish_ci",
			nextCharset:      "latin1",
			nextCollate:      "latin1_swedish_ci",
			expectedAlterSQL: defaultAlterSQL,
			seedValue:        "seed-row",
		}
		rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
		value, err := (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "state_db"})
		if err != nil || value != true || len(runner.calls) != 2 {
			t.Fatalf("default-preserving alter = %#v, %v, calls=%d", value, err, len(runner.calls))
		}
		wantArgv := []string{"mysql", "--batch", "--execute=" + defaultAlterSQL}
		if got := append([]string{runner.calls[1].Name}, runner.calls[1].Args...); !reflect.DeepEqual(got, wantArgv) {
			t.Fatalf("default-preserving alter argv = %#v, want %#v", got, wantArgv)
		}
		metadata, err := dbGetCatalog(context.Background(), rt, &myConnection{}, "state_db")
		if err != nil || !reflect.DeepEqual(metadata, map[string]any{"character_set": "latin1", "collate": "latin1_swedish_ci"}) {
			t.Fatalf("default-preserving metadata = %#v, %v", metadata, err)
		}
		_, rows, err := mysqlQueryRowsPreserve(context.Background(), rt, &myConnection{}, alterSeedReadbackQuery)
		if err != nil || !reflect.DeepEqual(rows, [][]batchField{{{value: "1"}, {value: "seed-row"}}}) {
			t.Fatalf("default-preserving seed = %#v, %v", rows, err)
		}
	})
}

// TestMysqlAlterDatabaseBoundaries pins value-free validation, cancellation,
// output/timeout propagation, and redaction across both phases.
func TestMysqlAlterDatabaseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		key string
		set func(*AlterDbArgs, string)
	}{
		{key: "name", set: func(a *AlterDbArgs, value string) { a.Name = value }},
	} {
		for _, value := range []string{"", "bad\x00name", "bad\nname", "bad\x01name", "bad\x7fname"} {
			runner := &mysqlFakeRunner{}
			args := &AlterDbArgs{Name: "db"}
			tc.set(args, value)
			_, err := (alterDbFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, args)
			if !errors.Is(err, errMysqlInvalidArgument) || len(runner.calls) != 0 || (value != "" && strings.Contains(err.Error(), value)) {
				t.Fatalf("invalid %s %q: err=%v calls=%d", tc.key, value, err, len(runner.calls))
			}
		}
	}
	for _, tc := range []struct {
		key string
		set func(*AlterDbArgs, *string)
	}{
		{key: "character_set", set: func(a *AlterDbArgs, value *string) { a.CharacterSet = value }},
		{key: "collate", set: func(a *AlterDbArgs, value *string) { a.Collate = value }},
	} {
		marker := "alter-option-secret\nmarker"
		args := &AlterDbArgs{Name: "db"}
		tc.set(args, &marker)
		runner := &mysqlFakeRunner{}
		_, err := (alterDbFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, args)
		if !errors.Is(err, errMysqlInvalidArgument) || strings.Contains(err.Error(), marker) || len(runner.calls) != 0 {
			t.Fatalf("invalid %s: err=%v calls=%d", tc.key, err, len(runner.calls))
		}
	}

	// A transport timeout/limit at either phase is an error, never a false
	// success. A failed catalog phase is never followed by ALTER.
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   error
		calls  int
	}{
		{name: "preflight-timeout", result: process.CommandResult{Err: context.DeadlineExceeded}, want: context.DeadlineExceeded, calls: 1},
		{name: "preflight-output", result: process.CommandResult{StdoutTruncated: true}, want: process.ErrOutputLimit, calls: 1},
		{name: "mutation-timeout", result: process.CommandResult{Err: context.DeadlineExceeded}, want: context.DeadlineExceeded, calls: 2},
		{name: "mutation-output", result: process.CommandResult{StdoutTruncated: true}, want: process.ErrOutputLimit, calls: 2},
	} {
		results := []process.CommandResult{tc.result}
		if tc.calls == 2 {
			results = []process.CommandResult{
				{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8mb4\tutf8mb4_0900_ai_ci\n")},
				tc.result,
			}
		}
		rt, runner := newMysqlRuntime(results...)
		value, err := (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db"})
		if value != nil || !errors.Is(err, tc.want) || len(runner.calls) != tc.calls {
			t.Fatalf("alter_db %s = %#v, %v, calls=%d", tc.name, value, err, len(runner.calls))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := &mysqlFakeRunner{}
	value, err := (alterDbFunc{}).Execute(ctx, &runtime.Runtime{Runner: cancelled}, &AlterDbArgs{Name: "db"})
	if value != nil || !errors.Is(err, context.Canceled) || len(cancelled.calls) != 0 {
		t.Fatalf("alter_db cancelled before db_get = %#v, %v, calls=%d", value, err, len(cancelled.calls))
	}

	ctx, cancel = context.WithCancel(context.Background())
	base := &mysqlFakeRunner{results: []process.CommandResult{{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")}, {ExitCode: 0}}}
	cancelRunner := &mysqlCancelAfterRunner{base: base, cancel: cancel, after: 1}
	value, err = (alterDbFunc{}).Execute(ctx, &runtime.Runtime{Runner: cancelRunner}, &AlterDbArgs{Name: "db"})
	if value != nil || !errors.Is(err, context.Canceled) || len(base.calls) != 1 {
		t.Fatalf("alter_db cancelled after db_get = %#v, %v, calls=%d", value, err, len(base.calls))
	}

	marker := "alter_redaction_secret"
	rt, runner := newMysqlRuntime(
		process.CommandResult{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\ndb\tutf8\tutf8_general_ci\n")},
		process.CommandResult{Err: errors.New("alter failed " + marker), Stdout: []byte(marker), Stderr: []byte(marker)},
	)
	value, err = (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db", CharacterSet: mysqlString(marker)})
	if value != nil || err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 2 {
		t.Fatalf("alter_db redaction = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[1].RedactedString(), marker) || !containsAll(runner.calls[1].Redact, []string{marker}) {
		t.Fatalf("alter_db mutation redaction leaked marker: command=%q redact=%q", runner.calls[1].RedactedString(), runner.calls[1].Redact)
	}

	connectionMarker := "alter_connection_secret"
	rt, runner = newMysqlRuntime(process.CommandResult{
		Err:    errors.New("db_get failed " + connectionMarker),
		Stdout: []byte(connectionMarker),
		Stderr: []byte(connectionMarker),
	})
	value, err = (alterDbFunc{}).Execute(context.Background(), rt, &AlterDbArgs{Name: "db", Password: mysqlString(connectionMarker)})
	if value != nil || err == nil || strings.Contains(err.Error(), connectionMarker) || len(runner.calls) != 1 {
		t.Fatalf("alter_db preflight redaction = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[0].RedactedString(), connectionMarker) || !containsAll(runner.calls[0].Redact, []string{connectionMarker}) {
		t.Fatalf("alter_db preflight redaction leaked marker: command=%q redact=%q", runner.calls[0].RedactedString(), runner.calls[0].Redact)
	}
}

// TestMysqlAlterDatabaseThroughRegistry pins the public registry contract and
// keeps the source's db_get-before-mutation call order at that boundary.
func TestMysqlAlterDatabaseThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{results: []process.CommandResult{
		{Stdout: []byte("SCHEMA_NAME\tDEFAULT_CHARACTER_SET_NAME\tDEFAULT_COLLATION_NAME\nregistry_db\tutf8mb4\tutf8mb4_0900_ai_ci\n")},
		{ExitCode: 0},
	}}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	value, err := reg.Call(context.Background(), rt, "mysql.alter_db", &AlterDbArgs{Name: "registry_db"})
	if err != nil || value != true || len(runner.calls) != 2 {
		t.Fatalf("registry alter_db = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if !strings.Contains(runner.calls[0].Args[len(runner.calls[0].Args)-1], dbGetQuery) ||
		!strings.Contains(runner.calls[1].Args[len(runner.calls[1].Args)-1], "ALTER DATABASE `registry_db`") {
		t.Fatalf("registry alter_db order = %#v", runner.calls)
	}
}

// R9.3m source vectors pin the three exact SHOW statements and the DB-API
// DictRow/value shapes. The Runner is fake: no mysql client or server is
// contacted by the direct suite. A nonzero CLI exit is only a transport
// failure here: it cannot distinguish Salt's processlist connection failure
// from the connected processlist query-error branch.
func TestMysqlProcessAndReplicationStatusSourceVectors(t *testing.T) {
	processStdout := "Id\tUser\tHost\tdb\tCommand\tTime\tState\tInfo\tRows_sent\tRows_examined\tRows_read\n" +
		"39\troot\tlocalhost\tmysql\tQuery\t0\tNULL\tSHOW FULL PROCESSLIST\t0\t0\t1\n"
	rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte(processStdout)})
	password := "process-status-secret"
	value, err := (processlistFunc{}).Execute(context.Background(), rt, &ProcesslistArgs{
		User: mysqlString("test_user"), Host: mysqlString("test_host"),
		Port: mysqlString("3306"), Password: &password, DB: mysqlString("test_db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantProcess := []map[string]any{{
		"Id": int64(39), "User": "root", "Host": "localhost", "db": "mysql",
		"Command": "Query", "Time": int64(0), "State": nil,
		"Info": "SHOW FULL PROCESSLIST", "Rows_sent": int64(0),
		"Rows_examined": int64(0), "Rows_read": int64(1),
	}}
	if !reflect.DeepEqual(value, wantProcess) {
		t.Fatalf("processlist = %#v, want %#v", value, wantProcess)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("processlist calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, []string{
		"mysql", "--batch", "--user=test_user", "--host=test_host", "--port=3306",
		"--database=test_db", "--execute=SHOW FULL PROCESSLIST",
	}) {
		t.Fatalf("processlist argv = %#v", got)
	}
	if command.Timeout != commandTimeout || command.MaxStdoutBytes != outputLimit ||
		command.MaxStderrBytes != outputLimit || command.Shell ||
		!reflect.DeepEqual(command.Env, []string{"MYSQL_PWD=" + password}) ||
		!reflect.DeepEqual(command.Redact, []string{password}) {
		t.Fatalf("processlist transport = %#v", command)
	}
	if strings.Contains(command.RedactedString(), password) {
		t.Fatalf("processlist command leaked password: %q", command.RedactedString())
	}

	masterStdout := "File\tPosition\tBinlog_Do_DB\tBinlog_Ignore_DB\tExecuted_Gtid_Set\n" +
		"mysql-bin.000021\t107\t\t\tNULL\n"
	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: []byte(masterStdout)})
	value, err = (getMasterStatusFunc{}).Execute(context.Background(), rt, &GetMasterStatusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	wantMaster := map[string]any{
		"File": "mysql-bin.000021", "Position": int64(107),
		"Binlog_Do_DB": "", "Binlog_Ignore_DB": "", "Executed_Gtid_Set": nil,
	}
	if !reflect.DeepEqual(value, wantMaster) {
		t.Fatalf("get_master_status = %#v, want %#v", value, wantMaster)
	}
	if len(runner.calls) != 1 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SHOW MASTER STATUS" {
		t.Fatalf("master status transport = %#v", runner.calls)
	}

	slaveStdout := "Master_Port\tSeconds_Behind_Master\tLast_Error\tSlave_IO_Running\n" +
		"3306\tNULL\t\tYes\n"
	rt, _ = newMysqlRuntime(process.CommandResult{Stdout: []byte(slaveStdout)})
	value, err = (getSlaveStatusFunc{}).Execute(context.Background(), rt, &GetSlaveStatusArgs{})
	if err != nil {
		t.Fatal(err)
	}
	wantSlave := map[string]any{
		"Master_Port": int64(3306), "Seconds_Behind_Master": nil,
		"Last_Error": "", "Slave_IO_Running": "Yes",
	}
	if !reflect.DeepEqual(value, wantSlave) {
		t.Fatalf("get_slave_status = %#v, want %#v", value, wantSlave)
	}

	// The source appends an empty list for a successful status query with no
	// row. The CLI transport also maps every nonzero exit to an empty list,
	// which is source-compatible for connection failures and replication query
	// failures, but is an intentional defensive divergence for the connected
	// processlist query-error branch that Salt lets escape.
	for _, tc := range []struct {
		name string
		fn   runtime.ExecFunction
		args any
	}{
		{name: "master-empty", fn: getMasterStatusFunc{}, args: &GetMasterStatusArgs{}},
		{name: "slave-empty", fn: getSlaveStatusFunc{}, args: &GetSlaveStatusArgs{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := newMysqlRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("header\n")})
			got, err := tc.fn.Execute(context.Background(), rt, tc.args)
			if err != nil || !reflect.DeepEqual(got, []any{}) {
				t.Fatalf("empty status = %#v, %v", got, err)
			}
		})
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")})
	value, err = (getSlaveStatusFunc{}).Execute(context.Background(), rt, &GetSlaveStatusArgs{})
	if err != nil || !reflect.DeepEqual(value, []any{}) {
		t.Fatalf("nonzero slave status = %#v, %v", value, err)
	}
	rt, _ = newMysqlRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte("access denied")})
	value, err = (processlistFunc{}).Execute(context.Background(), rt, &ProcesslistArgs{})
	if err != nil || !reflect.DeepEqual(value, []map[string]any{}) {
		t.Fatalf("nonzero processlist = %#v, %v", value, err)
	}
}

// TestMysqlProcessAndReplicationStatusShortRows documents the defensive
// malformed-output boundary. Salt indexes every described column and raises
// IndexError for a short row; StateKit keeps the available prefix instead of
// panicking or fabricating a missing field.
func TestMysqlProcessAndReplicationStatusShortRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fn     runtime.ExecFunction
		args   any
		stdout string
		want   any
	}{
		{
			name:   "processlist",
			fn:     processlistFunc{},
			args:   &ProcesslistArgs{},
			stdout: "Id\tInfo\n39\n",
			want:   []map[string]any{{"Id": int64(39)}},
		},
		{
			name:   "master",
			fn:     getMasterStatusFunc{},
			args:   &GetMasterStatusArgs{},
			stdout: "File\tPosition\nmysql-bin.000021\n",
			want:   map[string]any{"File": "mysql-bin.000021"},
		},
		{
			name:   "slave",
			fn:     getSlaveStatusFunc{},
			args:   &GetSlaveStatusArgs{},
			stdout: "Master_Port\tLast_Error\n3306\n",
			want:   map[string]any{"Master_Port": int64(3306)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := newMysqlRuntime(process.CommandResult{Stdout: []byte(tc.stdout)})
			got, err := tc.fn.Execute(context.Background(), rt, tc.args)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("short row = %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
}

// TestMysqlProcessAndReplicationStatusNullRedactionOverlap verifies that raw
// native SHOW NULL classification precedes public redaction. A password equal
// to the client's NULL marker must preserve SQL NULL as nil, while an ordinary
// value containing the same marker remains redacted.
func TestMysqlProcessAndReplicationStatusNullRedactionOverlap(t *testing.T) {
	marker := "NULL"
	rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte(
		"Id\tState\tInfo\n1\tNULL\tquery-NULL-tail\n",
	)})
	value, err := (processlistFunc{}).Execute(context.Background(), rt, &ProcesslistArgs{
		Password: &marker,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{{
		"Id": int64(1), "State": nil, "Info": "query-***REDACTED***-tail",
	}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("NULL-overlap processlist = %#v, want %#v", value, want)
	}
	if len(runner.calls) != 1 || !containsAll(runner.calls[0].Redact, []string{marker}) ||
		strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("NULL-overlap transport = %#v", runner.calls)
	}
}

// TestMysqlProcessAndReplicationStatusTransport pins the shared cancellation,
// output-limit, and error-redaction controls on a newly registered SHOW path.
func TestMysqlProcessAndReplicationStatusTransport(t *testing.T) {
	marker := "status-transport-secret"
	rt, runner := newMysqlRuntime(process.CommandResult{
		Err:    errors.New("mysql failed " + marker),
		Stdout: []byte(marker), Stderr: []byte(marker),
	})
	value, err := (processlistFunc{}).Execute(context.Background(), rt, &ProcesslistArgs{Password: mysqlString(marker)})
	if value != nil || err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 {
		t.Fatalf("status redaction = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[0].RedactedString(), marker) || !containsAll(runner.calls[0].Redact, []string{marker}) {
		t.Fatalf("status command leaked marker: %q redact=%q", runner.calls[0].RedactedString(), runner.calls[0].Redact)
	}

	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: bytes.Repeat([]byte{'x'}, outputLimit+1)})
	value, err = (getMasterStatusFunc{}).Execute(context.Background(), rt, &GetMasterStatusArgs{})
	if value != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("status output limit = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	value, err = (getSlaveStatusFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &GetSlaveStatusArgs{})
	if value != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("status cancellation = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

// TestMysqlProcessAndReplicationStatusThroughRegistry pins registration and
// the single-row/empty-list public shapes at the registry boundary.
func TestMysqlProcessAndReplicationStatusThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{results: []process.CommandResult{
		{Stdout: []byte("Id\tUser\n1\troot\n")},
		{Stdout: []byte("File\tPosition\n")},
		{ExitCode: 1},
	}}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	value, err := reg.Call(context.Background(), rt, "mysql.processlist", &ProcesslistArgs{})
	if err != nil || !reflect.DeepEqual(value, []map[string]any{{"Id": int64(1), "User": "root"}}) {
		t.Fatalf("registry processlist = %#v, %v", value, err)
	}
	value, err = reg.Call(context.Background(), rt, "mysql.get_master_status", &GetMasterStatusArgs{})
	if err != nil || !reflect.DeepEqual(value, []any{}) {
		t.Fatalf("registry master status = %#v, %v", value, err)
	}
	value, err = reg.Call(context.Background(), rt, "mysql.get_slave_status", &GetSlaveStatusArgs{})
	if err != nil || !reflect.DeepEqual(value, []any{}) {
		t.Fatalf("registry slave status = %#v, %v", value, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("registry status calls = %d, want 3", len(runner.calls))
	}
}

// TestMysqlSlaveLagSourceVectors pins the scalar source decision ladder from
// salt/modules/mysql.py: a query/connection exit is -3, an empty status row is
// -1, a non-running IO thread is -2, and a running IO thread returns the
// Seconds_Behind_Master value including the native NULL shape. Malformed rows
// fail closed without indexing past the bounded batch row.
func TestMysqlSlaveLagSourceVectors(t *testing.T) {
	const header = "Slave_IO_Running\tSeconds_Behind_Master\n"
	for _, tc := range []struct {
		name    string
		result  process.CommandResult
		want    any
		wantErr error
	}{
		{name: "no-row", result: process.CommandResult{Stdout: []byte(header)}, want: int64(-1)},
		{name: "numeric", result: process.CommandResult{Stdout: []byte(header + "Yes\t37\n")}, want: int64(37)},
		{name: "null", result: process.CommandResult{Stdout: []byte(header + "Yes\tNULL\n")}, want: nil},
		{name: "broken-io", result: process.CommandResult{Stdout: []byte(header + "No\t37\n")}, want: int64(-2)},
		{name: "broken-io-short-row", result: process.CommandResult{Stdout: []byte(header + "No\n")}, want: int64(-2)},
		{name: "short-row", result: process.CommandResult{Stdout: []byte(header + "Yes\n")}, wantErr: errMysqlSlaveLagMalformed},
		{name: "missing-io-column", result: process.CommandResult{Stdout: []byte("Seconds_Behind_Master\n37\n")}, wantErr: errMysqlSlaveLagMalformed},
		{name: "malformed-numeric", result: process.CommandResult{Stdout: []byte(header + "Yes\tnot-a-number\n")}, wantErr: errMysqlSlaveLagMalformed},
		{name: "query-failure", result: process.CommandResult{ExitCode: 1, Stderr: []byte("ERROR 1064 (42000): removed SHOW SLAVE STATUS\n")}, want: int64(-3)},
		{name: "mysql-84-unsupported", result: process.CommandResult{ExitCode: 1, Stderr: []byte("ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SLAVE STATUS' at line 1\n")}, want: int64(-3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(tc.result)
			value, err := (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || value != nil {
					t.Fatalf("slave_lag = %#v, %v; want value-free %v", value, err, tc.wantErr)
				}
			} else if err != nil || !reflect.DeepEqual(value, tc.want) {
				t.Fatalf("slave_lag = %#v, %v; want %#v", value, err, tc.want)
			}
			if len(runner.calls) != 1 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SHOW SLAVE STATUS" {
				t.Fatalf("slave_lag query = %#v", runner.calls)
			}
		})
	}
}

// TestMysqlSlaveLagRedaction pins the scalar public boundary. A successful
// preserved batch row is raw until the parser has classified NULL; a numeric
// lag that overlaps the connection password is rendered as a redaction
// placeholder rather than leaking the credential through an int64 result.
func TestMysqlSlaveLagRedaction(t *testing.T) {
	marker := "42"
	rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte(
		"Slave_IO_Running\tSeconds_Behind_Master\nYes\t" + marker + "\n",
	)})
	value, err := (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{Password: &marker})
	if err != nil || value != "***REDACTED***" || strings.Contains(fmt.Sprint(value), marker) {
		t.Fatalf("redacted slave_lag = %#v, %v", value, err)
	}
	if len(runner.calls) != 1 || !containsAll(runner.calls[0].Redact, []string{marker}) || strings.Contains(runner.calls[0].RedactedString(), marker) {
		t.Fatalf("slave_lag redaction transport = %#v", runner.calls)
	}

	// A connection password equal to the native NULL marker must not change a
	// present SQL NULL into the redaction placeholder.
	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: []byte(
		"Slave_IO_Running\tSeconds_Behind_Master\nYes\tNULL\n",
	)})
	value, err = (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{Password: mysqlString("NULL")})
	if err != nil || value != nil || len(runner.calls) != 1 {
		t.Fatalf("NULL-overlap slave_lag = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

func TestMysqlSlaveLagInvalidSecretOverlap(t *testing.T) {
	for _, tc := range []struct {
		name string
		lag  string
	}{
		{name: "malformed", lag: "not-a-number"},
		{name: "overflow", lag: "9223372036854775808"},
		{name: "underflow", lag: "-9223372036854775809"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newMysqlRuntime(process.CommandResult{Stdout: []byte(
				"Slave_IO_Running\tSeconds_Behind_Master\nYes\t" + tc.lag + "\n",
			)})
			value, err := (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{Password: &tc.lag})
			if value != nil || !errors.Is(err, errMysqlSlaveLagMalformed) || strings.Contains(err.Error(), tc.lag) {
				t.Fatalf("secret-overlap slave_lag = %#v, %v; want value-free %v", value, err, errMysqlSlaveLagMalformed)
			}
			if len(runner.calls) != 1 || !containsAll(runner.calls[0].Redact, []string{tc.lag}) || strings.Contains(runner.calls[0].RedactedString(), tc.lag) {
				t.Fatalf("secret-overlap transport = %#v", runner.calls)
			}
		})
	}
}

// TestMysqlSlaveLagTransport pins the shared fail-closed Runner boundaries on
// the scalar path: errors are value-free, output is bounded, cancellation
// happens before a child process, and the command remains shell-free with the
// fixed timeout.
func TestMysqlSlaveLagTransport(t *testing.T) {
	marker := "slave-lag-transport-secret"
	rt, runner := newMysqlRuntime(process.CommandResult{
		Err:    errors.New("mysql failed " + marker),
		Stdout: []byte(marker), Stderr: []byte(marker),
	})
	value, err := (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{Password: &marker})
	if value != nil || err == nil || strings.Contains(err.Error(), marker) || len(runner.calls) != 1 {
		t.Fatalf("slave_lag transport error = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
	if strings.Contains(runner.calls[0].RedactedString(), marker) || !containsAll(runner.calls[0].Redact, []string{marker}) || runner.calls[0].Shell || runner.calls[0].Timeout != commandTimeout {
		t.Fatalf("slave_lag transport leaked marker: %#v", runner.calls[0])
	}

	rt, runner = newMysqlRuntime(process.CommandResult{Err: context.DeadlineExceeded})
	value, err = (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{})
	if value != nil || !errors.Is(err, context.DeadlineExceeded) || len(runner.calls) != 1 {
		t.Fatalf("slave_lag timeout = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	rt, runner = newMysqlRuntime(process.CommandResult{Stdout: bytes.Repeat([]byte{'x'}, outputLimit+1)})
	value, err = (slaveLagFunc{}).Execute(context.Background(), rt, &SlaveLagArgs{})
	if value != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("slave_lag output limit = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &mysqlFakeRunner{}
	value, err = (slaveLagFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, &SlaveLagArgs{})
	if value != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("slave_lag cancellation = %#v, %v, calls=%d", value, err, len(runner.calls))
	}

	runner = &mysqlFakeRunner{}
	value, err = (slaveLagFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, &SlaveLagArgs{Runas: mysqlString("mysql")})
	if value != nil || !errors.Is(err, errMysqlRunas) || len(runner.calls) != 0 {
		t.Fatalf("slave_lag runas = %#v, %v, calls=%d", value, err, len(runner.calls))
	}
}

// TestMysqlSlaveLagThroughRegistry pins direct registration and the CLI-sized
// scalar JSON shapes at the registry boundary.
func TestMysqlSlaveLagThroughRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &mysqlFakeRunner{results: []process.CommandResult{
		{Stdout: []byte("Slave_IO_Running\tSeconds_Behind_Master\nYes\t9\n")},
		{ExitCode: 1},
	}}
	rt := &runtime.Runtime{Runner: runner, Exec: reg, FS: runtime.NewMemoryFS()}
	value, err := reg.Call(context.Background(), rt, "mysql.slave_lag", &SlaveLagArgs{})
	if err != nil || value != int64(9) {
		t.Fatalf("registry slave_lag numeric = %#v, %v", value, err)
	}
	value, err = reg.Call(context.Background(), rt, "mysql.slave_lag", &SlaveLagArgs{})
	if err != nil || value != int64(-3) {
		t.Fatalf("registry slave_lag failure = %#v, %v", value, err)
	}
	if len(runner.calls) != 2 || runner.calls[0].Args[len(runner.calls[0].Args)-1] != "--execute=SHOW SLAVE STATUS" || runner.calls[1].Args[len(runner.calls[1].Args)-1] != "--execute=SHOW SLAVE STATUS" {
		t.Fatalf("registry slave_lag calls = %#v", runner.calls)
	}
}
