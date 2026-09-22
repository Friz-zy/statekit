// Package sqlite3 implements the public execution surface from the pinned
// Salt sqlite3 module.  It uses the CGO-free modernc.org/sqlite driver through
// database/sql, so the production binary does not depend on a system SQLite
// library or a separately installed client.
//
// The db argument is a local SQLite filename (or the SQLite :memory: sentinel),
// not a driver DSN.  URI/query forms are rejected so a caller cannot smuggle
// driver PRAGMAs or VFS settings through a filename.  The sql argument on
// modify and fetch is intentionally raw explicit user input, subject to the
// same one-executable-statement boundary enforced by Salt's cursor.execute:
// StateKit neither interpolates values into it nor constructs SQL from any
// other caller argument.  Callers must therefore treat those two functions as
// an explicit SQL execution boundary.
package sqlite3

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/runtime"
	_ "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

const (
	pinnedDriverVersion = "1.58.0"
	driverName          = "sqlite"
	operationTimeout    = 30 * time.Second
	maxSQLBytes         = runtime.MaxCommandInputBytes

	// SQLite's Python cursor.fetchall has no bounded-result mode. StateKit
	// keeps the source shape while imposing finite ceilings before returning a
	// result to the process boundary. The byte limits count both raw value
	// bytes and compact JSON-encoded value bytes and are checked incrementally.
	maxSQLiteResultRows             = 10_000
	maxSQLiteResultBytes      int64 = 8 << 20
	maxSQLiteResultValueBytes int64 = 1 << 20
)

var (
	errSQLiteInvalidPath = errors.New("sqlite3: invalid database path")
	errSQLiteInvalidSQL  = errors.New("sqlite3: invalid SQL input")
	errSQLiteOpen        = errors.New("sqlite3: database open failed")
	errSQLiteModify      = errors.New("sqlite3: modify failed")
	errSQLiteFetch       = errors.New("sqlite3: fetch failed")
	errSQLiteClose       = errors.New("sqlite3: database close failed")
	errSQLiteResultRows  = errors.New("sqlite3: result row limit exceeded")
	errSQLiteResultBytes = errors.New("sqlite3: result size limit exceeded")
	errSQLiteResultValue = errors.New("sqlite3: result value size limit exceeded")
)

// VersionArgs are the argument contract for sqlite3.version.
type VersionArgs struct{}

// SQLiteVersionArgs are the argument contract for sqlite3.sqlite_version.
type SQLiteVersionArgs struct{}

// ModifyArgs are the argument contract for sqlite3.modify.
type ModifyArgs struct {
	DB  *string `statekit:"name=db"`
	SQL *string `statekit:"name=sql"`
}

// FetchArgs are the argument contract for sqlite3.fetch.
type FetchArgs struct {
	DB  *string `statekit:"name=db"`
	SQL *string `statekit:"name=sql"`
}

// TablesArgs are the argument contract for sqlite3.tables.
type TablesArgs struct {
	DB *string `statekit:"name=db"`
}

// IndicesArgs are the argument contract for sqlite3.indices and
// sqlite3.indexes.
type IndicesArgs struct {
	DB *string `statekit:"name=db"`
}

// IndexesArgs is the compatibility alias used by sqlite3.indexes.
type IndexesArgs = IndicesArgs

type versionFunc struct{}

func (versionFunc) Name() string { return "sqlite3.version" }
func (versionFunc) Args() any    { return VersionArgs{} }
func (versionFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	if _, ok := args.(*VersionArgs); !ok {
		return nil, errSQLiteInvalidSQL
	}
	return pinnedDriverVersion, nil
}

type sqliteVersionFunc struct{}

func (sqliteVersionFunc) Name() string { return "sqlite3.sqlite_version" }
func (sqliteVersionFunc) Args() any    { return SQLiteVersionArgs{} }
func (sqliteVersionFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	if _, ok := args.(*SQLiteVersionArgs); !ok {
		return nil, errSQLiteInvalidSQL
	}
	return sqlitelib.SQLITE_VERSION, nil
}

type modifyFunc struct{}

func (modifyFunc) Name() string { return "sqlite3.modify" }
func (modifyFunc) Args() any    { return ModifyArgs{} }
func (modifyFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*ModifyArgs)
	if !ok {
		return nil, errSQLiteInvalidSQL
	}
	if a.DB == nil {
		return false, nil
	}
	if a.SQL == nil {
		return nil, errSQLiteInvalidSQL
	}
	if err := validateSQL(*a.SQL); err != nil {
		return nil, err
	}

	result, err := runDatabase(ctx, *a.DB, func(ctx context.Context, db *sql.DB) (any, error) {
		if _, err := db.ExecContext(ctx, *a.SQL); err != nil {
			return nil, operationError(errSQLiteModify, err)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

type fetchFunc struct{}

func (fetchFunc) Name() string { return "sqlite3.fetch" }
func (fetchFunc) Args() any    { return FetchArgs{} }
func (fetchFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*FetchArgs)
	if !ok {
		return nil, errSQLiteInvalidSQL
	}
	if a.DB == nil {
		return false, nil
	}
	if a.SQL == nil {
		return nil, errSQLiteInvalidSQL
	}
	if err := validateSQL(*a.SQL); err != nil {
		return nil, err
	}

	return runDatabase(ctx, *a.DB, func(ctx context.Context, db *sql.DB) (any, error) {
		rows, err := db.QueryContext(ctx, *a.SQL)
		if err != nil {
			return nil, operationError(errSQLiteFetch, err)
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			return nil, operationError(errSQLiteFetch, err)
		}
		result, err := collectRows(ctx, rows, columns)
		if err != nil {
			return nil, err
		}
		return result, nil
	})
}

type tablesFunc struct{}

func (tablesFunc) Name() string { return "sqlite3.tables" }
func (tablesFunc) Args() any    { return TablesArgs{} }
func (tablesFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*TablesArgs)
	if !ok {
		return nil, errSQLiteInvalidPath
	}
	if a.DB == nil {
		return false, nil
	}
	return runCatalog(ctx, *a.DB, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
}

type indicesFunc struct{}

func (indicesFunc) Name() string { return "sqlite3.indices" }
func (indicesFunc) Args() any    { return IndicesArgs{} }
func (indicesFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*IndicesArgs)
	if !ok {
		return nil, errSQLiteInvalidPath
	}
	if a.DB == nil {
		return false, nil
	}
	return runCatalog(ctx, *a.DB, "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
}

type indexesFunc struct{}

func (indexesFunc) Name() string { return "sqlite3.indexes" }
func (indexesFunc) Args() any    { return IndicesArgs{} }
func (indexesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return (indicesFunc{}).Execute(ctx, rt, args)
}

func runCatalog(ctx context.Context, databasePath, query string) (any, error) {
	return runDatabase(ctx, databasePath, func(ctx context.Context, db *sql.DB) (any, error) {
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return nil, operationError(errSQLiteFetch, err)
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			return nil, operationError(errSQLiteFetch, err)
		}
		result, err := collectRows(ctx, rows, columns)
		if err != nil {
			return nil, err
		}
		return result, nil
	})
}

// collectRows drains one SQLite result into the source-compatible [][]any
// shape. It never returns a prefix: a row, value, encoded-size, cancellation,
// or driver error discards the accumulated result and returns a value-free
// error instead.
func collectRows(ctx context.Context, rows *sql.Rows, columns []string) (result [][]any, err error) {
	defer rows.Close()

	result = make([][]any, 0)
	budget := sqliteResultBudget{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !rows.Next() {
			break
		}

		values := make([]any, len(columns))
		destinations := make([]any, len(values))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, operationError(errSQLiteFetch, err)
		}
		if err := budget.add(values); err != nil {
			return nil, err
		}
		result = append(result, values)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, operationError(errSQLiteFetch, err)
	}
	if err := rows.Close(); err != nil {
		return nil, operationError(errSQLiteFetch, err)
	}
	return result, nil
}

type sqliteResultBudget struct {
	rows         int
	rawBytes     int64
	encodedBytes int64
}

func (b *sqliteResultBudget) add(values []any) error {
	if b.rows >= maxSQLiteResultRows {
		return errSQLiteResultRows
	}

	var rawBytes, encodedBytes int64 = 2, 2 // row brackets
	for index, value := range values {
		raw, encoded, err := sqliteValueSizes(value)
		if err != nil {
			return err
		}
		if raw > maxSQLiteResultValueBytes || encoded > maxSQLiteResultValueBytes {
			return errSQLiteResultValue
		}
		if index > 0 {
			rawBytes++     // value separator
			encodedBytes++ // value separator
		}
		rawBytes += raw
		encodedBytes += encoded
	}
	if b.rows > 0 {
		rawBytes++     // row separator
		encodedBytes++ // row separator
	}
	if rawBytes > maxSQLiteResultBytes-b.rawBytes || encodedBytes > maxSQLiteResultBytes-b.encodedBytes {
		return errSQLiteResultBytes
	}
	b.rows++
	b.rawBytes += rawBytes
	b.encodedBytes += encodedBytes
	return nil
}

func sqliteValueSizes(value any) (rawBytes, encodedBytes int64, err error) {
	switch value := value.(type) {
	case nil:
		return 0, 4, nil // null
	case string:
		rawBytes = int64(len(value))
		if rawBytes > maxSQLiteResultValueBytes {
			return 0, 0, errSQLiteResultValue
		}
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return 0, 0, errSQLiteResultValue
		}
		return rawBytes, int64(len(encoded)), nil
	case []byte:
		if value == nil {
			return 0, 4, nil // null
		}
		rawBytes = int64(len(value))
		if rawBytes > maxSQLiteResultValueBytes {
			return 0, 0, errSQLiteResultValue
		}
		return rawBytes, int64(base64.StdEncoding.EncodedLen(len(value)) + 2), nil // JSON string quotes
	case int64:
		encoded := strconv.FormatInt(value, 10)
		return int64(len(encoded)), int64(len(encoded)), nil
	case float64:
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return 0, 0, errSQLiteResultValue
		}
		return int64(len(encoded)), int64(len(encoded)), nil
	default:
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return 0, 0, errSQLiteResultValue
		}
		return int64(len(encoded)), int64(len(encoded)), nil
	}
}

type databaseOperation func(context.Context, *sql.DB) (any, error)

func runDatabase(parent context.Context, databasePath string, operation databaseOperation) (result any, err error) {
	if parent == nil {
		parent = context.Background()
	}
	opCtx, cancel := context.WithTimeout(parent, operationTimeout)
	defer cancel()
	if err := opCtx.Err(); err != nil {
		return nil, err
	}

	dsn, err := safeDatabasePath(databasePath)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, errSQLiteOpen
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() {
		closeErr := db.Close()
		if err == nil && closeErr != nil {
			result = nil
			err = errSQLiteClose
		}
	}()

	return operation(opCtx, db)
}

func safeDatabasePath(databasePath string) (string, error) {
	if databasePath == "" || !utf8.ValidString(databasePath) {
		return "", errSQLiteInvalidPath
	}
	if databasePath == ":memory:" {
		return databasePath, nil
	}
	for _, r := range databasePath {
		if r < 0x20 || r == 0x7f {
			return "", errSQLiteInvalidPath
		}
	}
	// modernc.org/sqlite treats '?' as the beginning of a DSN query even for
	// an otherwise ordinary filename. Reject it and URI forms so a database
	// path cannot carry driver configuration or PRAGMA statements. Validation
	// is intentionally repeated after Clean: filepath.Clean("./file:x") and
	// filepath.Clean("./:memory:") must not become accepted driver inputs.
	normalized := filepath.Clean(databasePath)
	if normalized == ":memory:" || strings.HasPrefix(normalized, "file:") || strings.ContainsRune(normalized, '?') {
		return "", errSQLiteInvalidPath
	}
	return normalized, nil
}

func validateSQL(query string) error {
	if len(query) > maxSQLBytes || !utf8.ValidString(query) || strings.IndexByte(query, 0) >= 0 {
		return errSQLiteInvalidSQL
	}
	return validateSingleSQLiteStatement(query)
}

// validateSingleSQLiteStatement mirrors SQLite's lexical statement boundary
// rules instead of splitting on semicolons. Semicolons in string literals,
// quoted identifiers, and comments are data; trigger bodies are one SQLite
// statement even though their trigger steps are separated by semicolons.
func validateSingleSQLiteStatement(query string) error {
	index := 0
	sawStatement := false
	complete := false
	firstKeywords := make([]string, 0, 3)
	triggerCandidate := false
	triggerBody := false
	triggerEndCandidate := false
	parenDepth := 0
	caseDepth := 0

	for index < len(query) {
		if isSQLiteSpace(query[index]) {
			index++
			continue
		}
		if query[index] == '-' && index+1 < len(query) && query[index+1] == '-' {
			index = skipSQLiteLineComment(query, index+2)
			continue
		}
		if query[index] == '/' && index+1 < len(query) && query[index+1] == '*' {
			var ok bool
			index, ok = skipSQLiteBlockComment(query, index+2)
			if !ok {
				return errSQLiteInvalidSQL
			}
			continue
		}

		if complete {
			return errSQLiteInvalidSQL
		}

		switch query[index] {
		case '\'', '"', '`', '[':
			var ok bool
			index, ok = skipSQLiteQuoted(query, index)
			if !ok {
				return errSQLiteInvalidSQL
			}
			sawStatement = true
			triggerEndCandidate = false
			continue
		case ';':
			if !sawStatement {
				// Python's cursor.execute accepts empty statements and leading
				// semicolons. They do not count as executable statements.
				index++
				continue
			}
			if triggerBody {
				if triggerEndCandidate && parenDepth == 0 && caseDepth == 0 {
					triggerBody = false
					complete = true
				} else {
					triggerEndCandidate = false
				}
			} else {
				complete = true
			}
			index++
			continue
		case '(':
			parenDepth++
			triggerEndCandidate = false
			sawStatement = true
			index++
			continue
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			triggerEndCandidate = false
			sawStatement = true
			index++
			continue
		}

		if isSQLiteIdentifierStart(query[index]) {
			start := index
			index++
			for index < len(query) && isSQLiteIdentifierPart(query[index]) {
				index++
			}
			keyword := strings.ToUpper(query[start:index])
			sawStatement = true
			if len(firstKeywords) < cap(firstKeywords) {
				firstKeywords = append(firstKeywords, keyword)
				triggerCandidate = isSQLiteCreateTriggerPrefix(firstKeywords)
			}
			if triggerCandidate && keyword == "BEGIN" {
				triggerBody = true
				triggerEndCandidate = false
			}
			if triggerBody {
				switch keyword {
				case "CASE":
					caseDepth++
					triggerEndCandidate = false
				case "END":
					if caseDepth > 0 {
						caseDepth--
						triggerEndCandidate = false
					} else if parenDepth == 0 {
						triggerEndCandidate = true
					} else {
						triggerEndCandidate = false
					}
				default:
					if triggerEndCandidate {
						triggerEndCandidate = false
					}
				}
			}
			continue
		}

		// Operators, numbers, dots, parameters, and other punctuation cannot
		// introduce a statement boundary. Keep scanning so the SQLite driver
		// remains the syntax authority after this lexical safety check.
		sawStatement = true
		triggerEndCandidate = false
		index++
	}

	if triggerBody && !triggerEndCandidate {
		return errSQLiteInvalidSQL
	}
	return nil
}

func isSQLiteSpace(value byte) bool { return value == ' ' || (value >= '\t' && value <= '\r') }

func isSQLiteIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 0x80 ||
		(value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func isSQLiteIdentifierPart(value byte) bool {
	return isSQLiteIdentifierStart(value) || (value >= '0' && value <= '9')
}

func skipSQLiteLineComment(query string, index int) int {
	for index < len(query) && query[index] != '\n' && query[index] != '\r' {
		index++
	}
	return index
}

func skipSQLiteBlockComment(query string, index int) (int, bool) {
	for index+1 < len(query) {
		if query[index] == '*' && query[index+1] == '/' {
			return index + 2, true
		}
		index++
	}
	// At end-of-input, this boundary treats an unterminated block comment as
	// trailing comment text. The driver remains the syntax authority after
	// validation; an executable token after the comment is impossible because
	// the comment consumes the rest of the input.
	return len(query), true
}

func skipSQLiteQuoted(query string, index int) (int, bool) {
	quote := query[index]
	closing := quote
	if quote == '[' {
		closing = ']'
	}
	for index = index + 1; index < len(query); index++ {
		if query[index] != closing {
			continue
		}
		if closing != ']' && index+1 < len(query) && query[index+1] == closing {
			index++
			continue
		}
		return index + 1, true
	}
	return len(query), false
}

func isSQLiteCreateTriggerPrefix(keywords []string) bool {
	if len(keywords) < 2 || keywords[0] != "CREATE" {
		return false
	}
	if keywords[1] == "TRIGGER" {
		return true
	}
	return len(keywords) >= 3 && (keywords[1] == "TEMP" || keywords[1] == "TEMPORARY") && keywords[2] == "TRIGGER"
}

func operationError(sentinel, err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return sentinel
}

// Register installs the public sqlite3 family. _connect is deliberately kept
// internal because Salt exposes it only as a helper for this module's public
// functions, not as an execution surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		sqliteVersionFunc{},
		modifyFunc{},
		fetchFunc{},
		tablesFunc{},
		indicesFunc{},
		indexesFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
