package differential

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
	execsqlite3 "github.com/friz-zy/statekit/modules/exec/sqlite3"
)

func TestSQLiteDifferentialMockSurface(t *testing.T) {
	registry := runtime.NewExecRegistry()
	if err := execsqlite3.Register(registry); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for _, name := range []string{
		"sqlite3.modify",
		"sqlite3.fetch",
		"sqlite3.tables",
		"sqlite3.indices",
		"sqlite3.indexes",
	} {
		value, err := registry.Call(ctx, nil, name, argsForSQLiteName(name))
		if err != nil || value != false {
			t.Fatalf("%s missing-db shape = %#v, %v; want false", name, value, err)
		}
	}

	for _, name := range []string{"sqlite3.version", "sqlite3.sqlite_version"} {
		value, err := registry.Call(ctx, nil, name, argsForSQLiteName(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
			t.Fatalf("%s = %#v, want non-empty version string", name, value)
		}
	}

	// SQL is the only arbitrary input surface in this family. Its value must
	// not be reflected in a returned boundary error.
	marker := "differential-sql-marker"
	value, err := registry.Call(ctx, nil, "sqlite3.fetch", &execsqlite3.FetchArgs{
		DB:  stringPtrForSQLite(":memory:"),
		SQL: stringPtrForSQLite("SELECT missing FROM absent WHERE value='" + marker + "'"),
	})
	if err == nil || value != nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("SQL boundary = %#v, %v; want value-free error", value, err)
	}
}

func argsForSQLiteName(name string) any {
	switch name {
	case "sqlite3.modify":
		return &execsqlite3.ModifyArgs{}
	case "sqlite3.fetch":
		return &execsqlite3.FetchArgs{}
	case "sqlite3.tables":
		return &execsqlite3.TablesArgs{}
	case "sqlite3.indices", "sqlite3.indexes":
		return &execsqlite3.IndicesArgs{}
	case "sqlite3.version":
		return &execsqlite3.VersionArgs{}
	case "sqlite3.sqlite_version":
		return &execsqlite3.SQLiteVersionArgs{}
	default:
		panic("unknown sqlite3 test function " + name)
	}
}

func stringPtrForSQLite(value string) *string { return &value }
