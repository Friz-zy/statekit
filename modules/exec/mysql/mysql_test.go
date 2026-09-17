package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

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

// TestMysqlRegistryNames pins the canonical registered names.
func TestMysqlRegistryNames(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("mysql.quote_identifier"); !ok {
		t.Fatal("mysql.quote_identifier not registered")
	}
	if _, ok := reg.Get("mysql.tokenize_grant"); !ok {
		t.Fatal("mysql.tokenize_grant not registered")
	}
	if reg.Len() != 2 {
		t.Fatalf("registry length = %d, want 2", reg.Len())
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
