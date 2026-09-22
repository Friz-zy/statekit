package sqlite3

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
	sqlitelib "modernc.org/sqlite/lib"
)

func stringPointer(value string) *string { return &value }

func TestVersionsExposePinnedDriverAndSQLiteVersions(t *testing.T) {
	driverVersion, err := (versionFunc{}).Execute(context.Background(), nil, &VersionArgs{})
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if driverVersion != pinnedDriverVersion {
		t.Fatalf("version = %#v, want %q", driverVersion, pinnedDriverVersion)
	}

	sqliteVersion, err := (sqliteVersionFunc{}).Execute(context.Background(), nil, &SQLiteVersionArgs{})
	if err != nil {
		t.Fatalf("sqlite_version: %v", err)
	}
	if sqliteVersion != sqlitelib.SQLITE_VERSION {
		t.Fatalf("sqlite_version = %#v, want %q", sqliteVersion, sqlitelib.SQLITE_VERSION)
	}
}

func TestMissingDatabaseKeepsSaltFalseShape(t *testing.T) {
	cases := []struct {
		name string
		call func() (any, error)
	}{
		{name: "modify", call: func() (any, error) {
			return (modifyFunc{}).Execute(context.Background(), nil, &ModifyArgs{SQL: stringPointer("CREATE TABLE ignored(value TEXT)")})
		}},
		{name: "fetch", call: func() (any, error) {
			return (fetchFunc{}).Execute(context.Background(), nil, &FetchArgs{SQL: stringPointer("SELECT 1")})
		}},
		{name: "tables", call: func() (any, error) {
			return (tablesFunc{}).Execute(context.Background(), nil, &TablesArgs{})
		}},
		{name: "indices", call: func() (any, error) {
			return (indicesFunc{}).Execute(context.Background(), nil, &IndicesArgs{})
		}},
		{name: "indexes", call: func() (any, error) {
			return (indexesFunc{}).Execute(context.Background(), nil, &IndexesArgs{})
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value, err := testCase.call()
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if value != false {
				t.Fatalf("value = %#v, want false", value)
			}
		})
	}
}

func TestModifyAndFetchPreserveExplicitSQLResults(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "records.sqlite")
	ctx := context.Background()

	for _, statement := range []string{
		"CREATE TABLE records(id INTEGER, label TEXT);",
		"INSERT INTO records(id, label) VALUES (1, 'one'), (2, 'two')",
	} {
		value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
			DB:  stringPointer(databasePath),
			SQL: stringPointer(statement),
		})
		if err != nil || value != true {
			t.Fatalf("modify(%q) = %#v, %v; want true", statement, value, err)
		}
	}

	value, err := (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("SELECT id, label FROM records ORDER BY id"),
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	want := [][]any{{int64(1), "one"}, {int64(2), "two"}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("fetch = %#v, want %#v", value, want)
	}
}

func TestSQLiteStatementValidationPreservesSQLiteLexicalBoundaries(t *testing.T) {
	valid := []string{
		"",
		"/* comment only */",
		"/* unterminated comment only",
		"; ; -- empty statements are accepted by cursor.execute\n",
		"SELECT 'first;second'; -- a trailing semicolon is comment data\n",
		"SELECT \"identifier;value\" /* a semicolon in a comment */;",
		"SELECT 'literal /* ; not a comment */' /* trailing unterminated comment",
		"SELECT \"identifier /* ; not a comment */\" /* trailing unterminated comment",
		"SELECT 1 /* ; SELECT 2 is still comment text",
		"SELECT 1; /* trailing unterminated comment",
		"CREATE TRIGGER records_insert AFTER INSERT ON records BEGIN INSERT INTO audit VALUES ('step;one'); UPDATE audit SET value = CASE WHEN value = 'step;one' THEN 'step;two' ELSE value END; END;",
	}
	for _, query := range valid {
		if err := validateSQL(query); err != nil {
			t.Errorf("validateSQL(%q) = %v, want valid", query, err)
		}
	}

	invalid := []string{
		"SELECT 1; SELECT 2",
		"SELECT 1; -- comment\n SELECT 2",
		"SELECT 1; /* trailing comment */ SELECT 2",
		"SELECT 1; SELECT 2 /* unterminated trailing comment",
		"INSERT INTO records(value) VALUES ('one'); INSERT INTO records(value) VALUES ('two')",
		"CREATE TRIGGER records_insert AFTER INSERT ON records BEGIN INSERT INTO audit VALUES ('one'); END; SELECT 2",
	}
	for _, query := range invalid {
		if err := validateSQL(query); !errors.Is(err, errSQLiteInvalidSQL) {
			t.Errorf("validateSQL(%q) = %v, want errSQLiteInvalidSQL", query, err)
		}
	}
}

func TestSQLiteUnterminatedTrailingBlockCommentExecutesOneStatement(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "unterminated-comment.sqlite")
	ctx := context.Background()
	if value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("CREATE TABLE records(value TEXT)"),
	}); err != nil || value != true {
		t.Fatalf("create table = %#v, %v", value, err)
	}

	for _, statement := range []string{
		"INSERT INTO records(value) VALUES ('literal;/* not a comment */') /* trailing comment",
		"INSERT INTO records(value) VALUES ('quoted ''value;''') -- line comment\n /* trailing comment",
	} {
		if value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
			DB:  stringPointer(databasePath),
			SQL: stringPointer(statement),
		}); err != nil || value != true {
			t.Fatalf("modify(%q) = %#v, %v; want true", statement, value, err)
		}
	}

	value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("INSERT INTO records(value) VALUES ('should-not-commit'); INSERT INTO records(value) VALUES ('also-should-not-commit') /* trailing comment"),
	})
	if value != nil || !errors.Is(err, errSQLiteInvalidSQL) {
		t.Fatalf("stacked mutation = %#v, %v; want nil and invalid SQL", value, err)
	}

	value, err = (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("SELECT value FROM records ORDER BY rowid /* trailing comment"),
	})
	want := [][]any{{"literal;/* not a comment */"}, {"quoted 'value;'"}}
	if err != nil || !reflect.DeepEqual(value, want) {
		t.Fatalf("rows after stacked mutation = %#v, %v; want %#v", value, err, want)
	}
}

func TestSQLiteMultiStatementMutationAndFetchHaveNoPartialSideEffects(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "single-statement.sqlite")
	ctx := context.Background()
	if value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)"),
	}); err != nil || value != true {
		t.Fatalf("create table = %#v, %v", value, err)
	}

	for _, call := range []struct {
		name string
		fn   func() (any, error)
	}{
		{
			name: "modify",
			fn: func() (any, error) {
				return (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
					DB:  stringPointer(databasePath),
					SQL: stringPointer("INSERT INTO records(value) VALUES ('one'); INSERT INTO records(value) VALUES ('two')"),
				})
			},
		},
		{
			name: "fetch",
			fn: func() (any, error) {
				return (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
					DB:  stringPointer(databasePath),
					SQL: stringPointer("INSERT INTO records(value) VALUES ('three'); SELECT value FROM records"),
				})
			},
		},
	} {
		t.Run(call.name, func(t *testing.T) {
			value, err := call.fn()
			if value != nil || !errors.Is(err, errSQLiteInvalidSQL) {
				t.Fatalf("multi-statement %s = %#v, %v; want nil and invalid SQL", call.name, value, err)
			}
		})
	}

	value, err := (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("SELECT count(*) FROM records"),
	})
	if err != nil || !reflect.DeepEqual(value, [][]any{{int64(0)}}) {
		t.Fatalf("multi-statement side effects = %#v, %v; want zero rows", value, err)
	}

	if value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("INSERT INTO records(value) VALUES ('literal;value') -- trailing ; is a comment\n"),
	}); err != nil || value != true {
		t.Fatalf("literal/comment statement = %#v, %v; want true", value, err)
	}
	value, err = (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("SELECT value FROM records /* ; not executable */"),
	})
	if err != nil || !reflect.DeepEqual(value, [][]any{{"literal;value"}}) {
		t.Fatalf("literal/comment fetch = %#v, %v", value, err)
	}
}

func TestSQLiteDatabasePathValidatesAfterNormalization(t *testing.T) {
	for _, databasePath := range []string{
		"./file:example",
		"parent/../file:example",
		"./:memory:",
		"parent/../:memory:",
		"file:example",
		"file::memory:",
	} {
		if normalized, err := safeDatabasePath(databasePath); err == nil || normalized != "" {
			t.Errorf("safeDatabasePath(%q) = %q, %v; want rejection", databasePath, normalized, err)
		}
	}

	for _, testCase := range []struct {
		input string
		want  string
	}{
		{input: ":memory:", want: ":memory:"},
		{input: "ordinary-relative.sqlite", want: "ordinary-relative.sqlite"},
		{input: "parent/../ordinary-relative.sqlite", want: "ordinary-relative.sqlite"},
		{input: "ordinary-directory/file:example", want: filepath.Join("ordinary-directory", "file:example")},
	} {
		normalized, err := safeDatabasePath(testCase.input)
		if err != nil || normalized != testCase.want {
			t.Errorf("safeDatabasePath(%q) = %q, %v; want %q", testCase.input, normalized, err, testCase.want)
		}
	}

	directory := t.TempDir()
	target := filepath.Join(directory, "target.sqlite")
	link := filepath.Join(directory, "link.sqlite")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if normalized, err := safeDatabasePath(link); err != nil || normalized != link {
		t.Fatalf("safeDatabasePath(symlink) = %q, %v; want unchanged symlink path", normalized, err)
	}
	if value, err := (modifyFunc{}).Execute(context.Background(), nil, &ModifyArgs{
		DB:  stringPointer(link),
		SQL: stringPointer("CREATE TABLE through_link(value TEXT)"),
	}); err != nil || value != true {
		t.Fatalf("symlink mutation = %#v, %v", value, err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was not created: %v", err)
	}
}

func TestSQLiteFetchAndCatalogLimitsRejectWithoutPartialResults(t *testing.T) {
	ctx := context.Background()
	marker := "sqlite-result-limit-marker"

	value, err := (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(":memory:"),
		SQL: stringPointer(fmt.Sprintf("SELECT zeroblob(%d)", maxSQLiteResultValueBytes+1)),
	})
	if value != nil || !errors.Is(err, errSQLiteResultValue) || strings.Contains(err.Error(), marker) {
		t.Fatalf("large value = %#v, %v; want value-free value-limit error", value, err)
	}

	rowQuery := fmt.Sprintf("WITH RECURSIVE numbers(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM numbers WHERE value < %d) SELECT value FROM numbers", maxSQLiteResultRows+1)
	value, err = (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(":memory:"),
		SQL: stringPointer(rowQuery),
	})
	if value != nil || !errors.Is(err, errSQLiteResultRows) {
		t.Fatalf("large fetch = %#v, %v; want value-free row-limit error", value, err)
	}

	valueSize := maxSQLiteResultValueBytes / 2
	rowCount := maxSQLiteResultBytes/valueSize + 2
	aggregateQuery := fmt.Sprintf("WITH RECURSIVE numbers(value) AS (VALUES(1) UNION ALL SELECT value + 1 FROM numbers WHERE value < %d) SELECT zeroblob(%d) FROM numbers", rowCount, valueSize)
	value, err = (fetchFunc{}).Execute(ctx, nil, &FetchArgs{
		DB:  stringPointer(":memory:"),
		SQL: stringPointer(aggregateQuery),
	})
	if value != nil || !errors.Is(err, errSQLiteResultBytes) {
		t.Fatalf("large encoded fetch = %#v, %v; want value-free size-limit error", value, err)
	}

	value, err = runCatalog(ctx, ":memory:", rowQuery)
	if value != nil || !errors.Is(err, errSQLiteResultRows) {
		t.Fatalf("large catalog = %#v, %v; want value-free row-limit error", value, err)
	}
}

func TestSQLiteLockedMutationHonorsCancellationAndReturnsNoValue(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "locked.sqlite")
	holder, err := sql.Open(driverName, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	holder.SetMaxOpenConns(1)
	if _, err := holder.ExecContext(context.Background(), "CREATE TABLE locked(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	tx, err := holder.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO locked(value) VALUES ('held')"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(databasePath),
		SQL: stringPointer("INSERT INTO locked(value) VALUES ('blocked')"),
	})
	if value != nil || (!errors.Is(err, errSQLiteModify) && !errors.Is(err, context.DeadlineExceeded)) {
		t.Fatalf("locked mutation = %#v, %v; want value-free lock/deadline error", value, err)
	}
}

func TestCatalogQueriesMatchSaltOrderAndAlias(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "catalog.sqlite")
	ctx := context.Background()
	for _, statement := range []string{
		"CREATE TABLE z_table(value TEXT)",
		"CREATE TABLE a_table(value TEXT)",
		"CREATE INDEX z_index ON z_table(value)",
		"CREATE INDEX a_index ON a_table(value)",
	} {
		if value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{DB: stringPointer(databasePath), SQL: stringPointer(statement)}); err != nil || value != true {
			t.Fatalf("modify(%q) = %#v, %v", statement, value, err)
		}
	}

	for _, testCase := range []struct {
		name string
		call func() (any, error)
	}{
		{name: "tables", call: func() (any, error) {
			return (tablesFunc{}).Execute(ctx, nil, &TablesArgs{DB: stringPointer(databasePath)})
		}},
		{name: "indices", call: func() (any, error) {
			return (indicesFunc{}).Execute(ctx, nil, &IndicesArgs{DB: stringPointer(databasePath)})
		}},
		{name: "indexes alias", call: func() (any, error) {
			return (indexesFunc{}).Execute(ctx, nil, &IndexesArgs{DB: stringPointer(databasePath)})
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value, err := testCase.call()
			if err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}
			var want [][]any
			switch testCase.name {
			case "tables":
				want = [][]any{{"a_table"}, {"z_table"}}
			default:
				want = [][]any{{"a_index"}, {"z_index"}}
			}
			if !reflect.DeepEqual(value, want) {
				t.Fatalf("%s = %#v, want %#v", testCase.name, value, want)
			}
		})
	}
}

func TestSQLiteInputErrorsAreValueFree(t *testing.T) {
	pathMarker := "sqlite-path-secret-marker"
	for _, databasePath := range []string{
		pathMarker + "\x00suffix",
		"file:" + pathMarker,
		pathMarker + "?mode=memory",
	} {
		if value, err := (tablesFunc{}).Execute(context.Background(), nil, &TablesArgs{DB: stringPointer(databasePath)}); err == nil || value != nil {
			t.Fatalf("unsafe path = %#v, %v; want value-free error", value, err)
		} else if strings.Contains(err.Error(), pathMarker) {
			t.Fatalf("unsafe path error leaked marker: %v", err)
		}
	}

	sqlMarker := "sqlite-sql-secret-marker"
	value, err := (fetchFunc{}).Execute(context.Background(), nil, &FetchArgs{
		DB:  stringPointer(":memory:"),
		SQL: stringPointer("SELECT missing FROM absent WHERE value = '" + sqlMarker + "'"),
	})
	if err == nil || value != nil {
		t.Fatalf("invalid SQL = %#v, %v; want value-free error", value, err)
	}
	if strings.Contains(err.Error(), sqlMarker) {
		t.Fatalf("SQL error leaked marker: %v", err)
	}
}

func TestSQLiteCancellationStopsBeforeOpeningDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err := (modifyFunc{}).Execute(ctx, nil, &ModifyArgs{
		DB:  stringPointer(":memory:"),
		SQL: stringPointer("CREATE TABLE should_not_open(value TEXT)"),
	})
	if value != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled modify = %#v, %v; want context.Canceled", value, err)
	}
}

func TestSQLiteRegistrySurfaceExcludesInternalConnect(t *testing.T) {
	registry := runtime.NewExecRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"sqlite3.fetch",
		"sqlite3.indexes",
		"sqlite3.indices",
		"sqlite3.modify",
		"sqlite3.sqlite_version",
		"sqlite3.tables",
		"sqlite3.version",
	}
	if got := registry.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("registered names = %#v, want %#v", got, want)
	}
	if _, ok := registry.Get("sqlite3._connect"); ok {
		t.Fatal("internal _connect must not be registered")
	}
}
