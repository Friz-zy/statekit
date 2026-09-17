package cli

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
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
