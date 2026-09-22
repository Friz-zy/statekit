package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execsqlite3 "github.com/friz-zy/statekit/modules/exec/sqlite3"
)

func sqlite3CLIApp(t *testing.T) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
	}
	if err := execsqlite3.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

func TestSQLiteCLIExecutesCatalogFamily(t *testing.T) {
	app := sqlite3CLIApp(t)
	databasePath := filepath.Join(t.TempDir(), "cli.sqlite")

	for _, statement := range []string{
		"CREATE TABLE things(id INTEGER, label TEXT)",
		"CREATE INDEX things_label ON things(label)",
	} {
		code, out, errS := captureCode(t, app, "exec", "sqlite3.modify",
			"--db", databasePath, "--sql", statement, "-o", "json")
		if code != ExitOK || errS != "" || strings.TrimSpace(out) != "true" {
			t.Fatalf("modify(%q) code=%d out=%q err=%q", statement, code, out, errS)
		}
	}

	code, out, errS := captureCode(t, app, "exec", "sqlite3.tables", "--db", databasePath, "-o", "json")
	var tables [][]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tables) != nil ||
		!reflect.DeepEqual(tables, [][]any{{"things"}}) {
		t.Fatalf("tables code=%d out=%q err=%q", code, out, errS)
	}

	code, out, errS = captureCode(t, app, "exec", "sqlite3.indexes", "--db", databasePath, "-o", "json")
	var indexes [][]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &indexes) != nil ||
		!reflect.DeepEqual(indexes, [][]any{{"things_label"}}) {
		t.Fatalf("indexes code=%d out=%q err=%q", code, out, errS)
	}
}

func TestSQLiteCLIExposesVersionsAndSafeErrors(t *testing.T) {
	app := sqlite3CLIApp(t)
	code, out, errS := captureCode(t, app, "exec", "sqlite3.version", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != `"1.58.0"` {
		t.Fatalf("version code=%d out=%q err=%q", code, out, errS)
	}

	marker := "cli-sql-secret-marker"
	code, out, errS = captureCode(t, app, "exec", "sqlite3.fetch", "--db", ":memory:",
		"--sql", "SELECT missing FROM absent WHERE secret='"+marker+"'", "-o", "json")
	if code != ExitFailed || strings.Contains(out+errS, marker) {
		t.Fatalf("fetch error code=%d out=%q err=%q", code, out, errS)
	}
}

func TestSQLiteCLIUsesNilDatabaseCompatibilityShape(t *testing.T) {
	app := sqlite3CLIApp(t)
	code, out, errS := captureCode(t, app, "exec", "sqlite3.fetch", "--sql", "SELECT 1", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("fetch without db code=%d out=%q err=%q", code, out, errS)
	}
}
