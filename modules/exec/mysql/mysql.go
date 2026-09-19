// Package mysql implements slices of the pinned Salt mysql execution
// surface: the driver-free pure functions quote_identifier and
// tokenize_grant (R9.2a), the read-only catalog family db_list, db_exists,
// user_list, user_exists, db_get, and db_tables (R9.3a/R9.3d), the read-only
// server facts family version, status, showvariables, and showglobal (R9.3b),
// and the maintenance family db_check, db_repair, and db_optimize (R9.3c).
//
// Boundaries (R9.2a): no MySQL client driver or protocol, no new
// dependencies, no Runner spawns, no filesystem access, and no live MySQL
// server. The tokenizer is a faithful port of the pinned
// salt/modules/mysql.py _grant_to_tokens/tokenize_grant lexer, which is a
// Python shlex.shlex configured with quotes "'`", whitespace_split=False,
// empty commenters, and '"' appended to wordchars; the exact upstream
// shapes (including its read-ahead edge behavior) are preserved and pinned
// by source-derived test vectors.
//
// Boundaries (R9.3a): the pinned module speaks the MySQL client protocol
// through MySQLdb; StateKit links no database driver, so the four
// read-only functions run their fixed source queries through the mysql CLI
// client on the central shell-free Runner — never a live server, never
// network egress from tests. Caller names are matched client-side against
// the fixed catalogs, so no caller string reaches SQL. Batch stdout rows
// are framed by the bounded \n and \r\n splitter (the delimiter CR is
// dropped, a raw non-delimiter CR stays in its field) and decoded field by
// field after the tab split with the mysql client's own batch escaping
// (one bounded left-to-right pass), with SQL NULL carried by the fixed
// COALESCE sentinel the catalog queries select, so account names carrying
// backslashes, control bytes, or the literal spelling NULL match
// client-side exactly.
//
// Boundaries (R9.3c): the maintenance family db_check, db_repair, and
// db_optimize runs the pinned CHECK/REPAIR/OPTIMIZE TABLE statements per
// table through the same mysql CLI transport — REPAIR and OPTIMIZE are
// mutations, executed only through the (fake, in tests) Runner, never a
// live server. The database and table names are quoted with the committed
// quoteIdentifier and validated fail-closed value-free (no empty strings,
// NUL, or ASCII control bytes) before any Runner invocation; the pinned
// %%-escaping is unescaped exactly like the pinned _execute no-args path,
// so the --execute string is byte-identical to the SQL the pinned module
// sends through MySQLdb. The table=None flow reads the database's tables
// through a fixed information_schema.TABLES catalog query with the schema
// matched client-side, so no caller string reaches SQL; a nonzero mysql
// exit anywhere in the flow is an error, never compatibility data,
// because an unknown failure on a mutation surface must not answer a
// partial fake success.
//
// Boundaries (R9.3d): db_get and db_tables keep the pinned read-only
// compatibility shapes over fixed information_schema catalogs. Database and
// table names are matched or filtered client-side, so caller input never
// reaches SQL; SQL NULL is carried by the shared NUL sentinel and the batch
// decoder preserves LF/CRLF framing and escaped field bytes.
package mysql

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	// errGrantNoClosingQuotation mirrors shlex's ValueError("No closing
	// quotation") for a grant statement that ends inside a quoted section.
	errGrantNoClosingQuotation = errors.New("mysql: No closing quotation")
	// errGrantIndexOutOfRange mirrors the IndexError("list index out of
	// range") the pinned read-ahead raises when a statement ends while the
	// parser still expects a following token.
	errGrantIndexOutOfRange = errors.New("mysql: list index out of range")
	// errGrantKind rejects inputs that are neither a grant string nor a
	// pre-executed query dict.
	errGrantKind = errors.New("mysql: grant must be a string or a qry/args dict")
)

// ---------------------------------------------------------------------------
// quote_identifier — salt/modules/mysql.py:692-721 @ pinned revision.

// quoteIdentifier escapes an identifier (column, table, database, ...) by
// surrounding it with backticks, doubling embedded backticks, and doubling
// '%' for MySQLdb. for_grants additionally escapes '_' (but only makes
// sense for database-level grant wildcards, never table-level).
func quoteIdentifier(identifier string, forGrants bool) string {
	escaped := strings.ReplaceAll(identifier, "`", "``")
	if forGrants {
		escaped = strings.ReplaceAll(escaped, "_", `\_`)
	}
	return "`" + strings.ReplaceAll(escaped, "%", "%%") + "`"
}

// QuoteIdentifierArgs are the canonical mysql.quote_identifier arguments.
type QuoteIdentifierArgs struct {
	Identifier string `statekit:"required"`
	ForGrants  bool   `statekit:"name=for_grants"`
}

type quoteIdentifierFunc struct{}

func (quoteIdentifierFunc) Name() string { return "mysql.quote_identifier" }
func (quoteIdentifierFunc) Args() any    { return QuoteIdentifierArgs{} }

func (quoteIdentifierFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*QuoteIdentifierArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("mysql.quote_identifier: expected *arguments, got %T", args)
	}
	return quoteIdentifier(a.Identifier, a.ForGrants), nil
}

// ---------------------------------------------------------------------------
// Grant tokenizer — salt/modules/mysql.py:460-628 (_grant_to_tokens) and
// 2235-2249 (tokenize_grant) @ pinned revision.

// grantTokens is the dict shape returned by the pinned tokenizer:
// user, host, grant list, and database.
type grantTokens struct {
	User     string
	Host     string
	Grant    []string
	Database string
}

// asMap renders the tokens in the pinned dict key order.
func (g grantTokens) asMap() map[string]any {
	return map[string]any{
		"user":     g.User,
		"host":     g.Host,
		"grant":    g.Grant,
		"database": g.Database,
	}
}

// grantDictArgs mirrors the MySQLdb execute 'args' values for 'user' and
// 'host'. nil keeps the pinned "undefined" default.
type grantDictArgs struct {
	User *string
	Host *string
}

// grantDict is the dict-mode input of the pinned _grant_to_tokens: a
// pre-executed MySQLdb query with a 'qry' template (carrying MySQLdb '%%'
// escaping) and its args. It is package-internal future-round plumbing for
// grant_exists/user_grants; the public surface is string-mode only.
type grantDict struct {
	Qry  string
	Args grantDictArgs
}

func firstString(s *string) string {
	if s == nil {
		return "undefined"
	}
	return *s
}

// grantLexer reproduces shlex.shlex(instream) with quotes="'`",
// whitespace_split=False, commenters="", posix=False, and wordchars set to
// ASCII letters, digits, underscore, plus '"'. Runes are classified per
// Unicode code point like Python str iteration; escape is deliberately
// inert because the pinned configuration is non-posix.
type grantLexer struct {
	input string
	pos   int
}

func isGrantWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

func isGrantQuote(r rune) bool {
	return r == '\'' || r == '`'
}

func isGrantWordchar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '_' || r == '"'
}

// next returns the next token; ok is false at end of input.
func (l *grantLexer) next() (token string, ok bool, err error) {
	for l.pos < len(l.input) {
		r, size := utf8.DecodeRuneInString(l.input[l.pos:])
		if !isGrantWhitespace(r) {
			break
		}
		l.pos += size
	}
	if l.pos >= len(l.input) {
		return "", false, nil
	}
	r, size := utf8.DecodeRuneInString(l.input[l.pos:])
	switch {
	case isGrantQuote(r):
		// Non-posix quotes stay in the token; the closing quote ends it.
		quote := r
		l.pos += size
		var b strings.Builder
		b.WriteRune(quote)
		for {
			if l.pos >= len(l.input) {
				return "", false, errGrantNoClosingQuotation
			}
			ch, csize := utf8.DecodeRuneInString(l.input[l.pos:])
			l.pos += csize
			b.WriteRune(ch)
			if ch == quote {
				return b.String(), true, nil
			}
		}
	case isGrantWordchar(r):
		var b strings.Builder
		b.WriteRune(r)
		l.pos += size
		for l.pos < len(l.input) {
			ch, csize := utf8.DecodeRuneInString(l.input[l.pos:])
			// A quote inside a word is accumulated verbatim; it does not
			// open quoted mode outside token starts (non-posix shlex).
			if !isGrantWordchar(ch) && !isGrantQuote(ch) {
				break
			}
			b.WriteRune(ch)
			l.pos += csize
		}
		return b.String(), true, nil
	default:
		// Every other rune is a single-rune punctuation token.
		l.pos += size
		return string(r), true, nil
	}
}

func grantExplode(grantSQL string) ([]string, error) {
	lexer := &grantLexer{input: grantSQL}
	tokens := []string{}
	for {
		token, ok, err := lexer.next()
		if err != nil {
			return nil, err
		}
		if !ok {
			return tokens, nil
		}
		tokens = append(tokens, token)
	}
}

// grantToTokens ports the pinned _grant_to_tokens loop verbatim, including
// the read-ahead end-of-list failures, the pre-host UnboundLocalError
// fallback to an empty host, and the dict-mode early break in the user
// phrase. grant is either a string or a grantDict.
func grantToTokens(grant any) (grantTokens, error) {
	out := grantTokens{Grant: []string{}}
	dictMode := false
	var grantSQL, user, host string
	switch g := grant.(type) {
	case grantDict:
		dictMode = true
		// Dict input was made for a MySQLdb execute call and carries '%%'
		// escaping that must be removed here.
		grantSQL = strings.ReplaceAll(g.Qry, "%%", "%")
		host = firstString(g.Args.Host)
		user = firstString(g.Args.User)
	case string:
		grantSQL = g
		user = ""
	default:
		return out, errGrantKind
	}

	exploded, err := grantExplode(grantSQL)
	if err != nil {
		return out, err
	}

	// multiword accumulates multi-word privileges like LOCK TABLES;
	// positionTracker mirrors the upstream index tracker (it always equals
	// the index of the token under iteration).
	multiwordStatement := []string{}
	positionTracker := 1 // Skip the initial 'GRANT' word token.
	database := ""
	phrase := "grants"
	column := false
	currentGrant := ""

parse:
	for idx := 1; idx < len(exploded); idx++ {
		token := exploded[idx]

		if token == "," && phrase == "grants" {
			positionTracker++
			continue
		}

		if token == "(" && phrase == "grants" {
			positionTracker++
			column = true
			continue
		}

		if token == ")" && phrase == "grants" {
			positionTracker++
			column = false
			continue
		}

		if token == "ON" && phrase == "grants" {
			phrase = "db"
			positionTracker++
			continue
		} else if token == "TO" && phrase == "tables" {
			phrase = "user"
			positionTracker++
			continue
		} else if token == "@" && phrase == "pre-host" {
			phrase = "host"
			positionTracker++
			continue
		}

		switch phrase {
		case "grants":
			// Read-ahead.
			if positionTracker+1 >= len(exploded) {
				return out, errGrantIndexOutOfRange
			}
			next := exploded[positionTracker+1]
			if next == "," || next == "ON" || next == "(" || next == ")" {
				// End of token detected.
				if len(multiwordStatement) > 0 {
					multiwordStatement = append(multiwordStatement, token)
					out.Grant = append(out.Grant, strings.Join(multiwordStatement, " "))
					multiwordStatement = []string{}
				} else {
					if !column {
						currentGrant = token
					} else {
						token = currentGrant + "." + token
					}
					out.Grant = append(out.Grant, token)
				}
			} else { // This is a multi-word, ala LOCK TABLES.
				multiwordStatement = append(multiwordStatement, token)
			}

		case "db":
			// The shlex splitter may have split on special database
			// characters `.
			database += token
			// Read-ahead.
			if positionTracker+1 >= len(exploded) {
				break parse
			}
			if exploded[positionTracker+1] == "." {
				phrase = "tables"
			}

		case "tables":
			database += token

		case "user":
			if dictMode {
				break parse
			}
			user += token
			// Read-ahead.
			if positionTracker+1 >= len(exploded) {
				return out, errGrantIndexOutOfRange
			}
			if exploded[positionTracker+1] == "@" {
				phrase = "pre-host"
			}

		case "host":
			host = token
			break parse
		}

		positionTracker++
	}

	if !dictMode {
		user = strings.Trim(user, "'")
		host = strings.Trim(host, "'")
	}
	out.User = user
	out.Host = host
	out.Database = database
	return out, nil
}

// TokenizeGrantArgs are the canonical mysql.tokenize_grant arguments.
type TokenizeGrantArgs struct {
	Grant string `statekit:"required"`
}

type tokenizeGrantFunc struct{}

func (tokenizeGrantFunc) Name() string { return "mysql.tokenize_grant" }
func (tokenizeGrantFunc) Args() any    { return TokenizeGrantArgs{} }

func (tokenizeGrantFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*TokenizeGrantArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("mysql.tokenize_grant: expected *arguments, got %T", args)
	}
	tokens, err := grantToTokens(a.Grant)
	if err != nil {
		return nil, err
	}
	return tokens.asMap(), nil
}

// ---------------------------------------------------------------------------
// mysql CLI transport — the R9.3a/R9.3d read-only catalog families
// (salt/modules/mysql.py:1131-1161 db_list, 1270-1297 db_exists,
// 1397-1421 user_list, 1502-1605 user_exists, 1198-1267 db_get/db_tables
// @ pinned revision).

const (
	// mysqlCommand is the canonical client binary the R9.3a family runs.
	// Salt's pinned module speaks the MySQL client protocol through
	// MySQLdb; StateKit links no database driver, so the fixed catalog
	// queries travel through the mysql CLI client on the central Runner,
	// resolved via PATH discovery and failing closed when absent.
	mysqlCommand = "mysql"
	// commandTimeout bounds every mysql execution as a resource control;
	// the pinned module has no timeout (MySQLdb blocks on the server).
	commandTimeout = 30 * time.Second
	// outputLimit bounds captured stdout and stderr independently,
	// matching the R9.1/R9.2 CLI families.
	outputLimit = 4 << 20
	// nullSentinelSQL is the fixed SQL expression every catalog query
	// substitutes for SQL NULL through COALESCE: UNHEX('00'), exactly one
	// NUL byte. mysql --batch prints SQL NULL as a bare NULL marker that
	// is byte-identical to a value spelled NULL, so the fixed queries map
	// NULL to this sentinel server-side and only the sentinel decodes
	// back to null. UNHEX('00') is sql_mode-independent (no backslash
	// escape a NO_BACKSLASH_ESCAPES server would reinterpret), carries no
	// caller input, and MySQL and MariaDB identifiers cannot contain NUL,
	// so no database, user, or host value can ever collide with it.
	nullSentinelSQL = "UNHEX('00')"
	// batchNullSentinel is the decoded wire form of nullSentinelSQL: the
	// client batch-escapes the sentinel's single NUL byte as \0, and
	// decodeBatchField returns that one NUL byte, which
	// decodeCatalogField maps back to null.
	batchNullSentinel = "\x00"
	// showDatabasesQuery is the catalog reader of db_list and db_exists.
	// The pinned db_list runs SHOW DATABASES (mysql.py:1146); a SHOW
	// statement cannot wrap its columns in COALESCE, so the sentinel
	// mapping rides the privilege-equivalent information_schema.SCHEMATA
	// catalog the SHOW itself reads.
	showDatabasesQuery = "SELECT COALESCE(SCHEMA_NAME, " + nullSentinelSQL + ") FROM information_schema.SCHEMATA"
	// dbGetQuery is the fixed information_schema.SCHEMATA reader for db_get.
	// The pinned query filters on SCHEMA_NAME and binds the caller as a value;
	// StateKit selects the schema key as well and performs that equality check
	// client-side so the mysql CLI receives no caller-controlled SQL. Every
	// selected column is sentinel-mapped: the schema key cannot be a real NUL,
	// while the character-set and collation fields must retain MySQLdb's None
	// shape when the server supplies SQL NULL.
	dbGetQuery = "SELECT COALESCE(SCHEMA_NAME, " + nullSentinelSQL + ") AS SCHEMA_NAME, COALESCE(DEFAULT_CHARACTER_SET_NAME, " + nullSentinelSQL + ") AS DEFAULT_CHARACTER_SET_NAME, COALESCE(DEFAULT_COLLATION_NAME, " + nullSentinelSQL + ") AS DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA"
	// userListQuery is the catalog reader of user_list and user_exists:
	// the pinned SELECT User,Host FROM mysql.user (mysql.py:1412) with the
	// SQL NULL sentinel substituted column-wise — the User and Host
	// aliases keep the pinned DictRow header keys. Only the User and Host
	// columns are ever selected — no password column enters the catalog.
	userListQuery = "SELECT COALESCE(User, " + nullSentinelSQL + ") AS User, COALESCE(Host, " + nullSentinelSQL + ") AS Host FROM mysql.user"
	// defaultUserHost is the pinned user_exists host default.
	defaultUserHost = "localhost"
	// selectVersionQuery is the reader of version: the exact pinned
	// SELECT VERSION() (mysql.py:1027). The pinned module has no
	// `mysql --version` client-binary probe — the version is server-side.
	selectVersionQuery = "SELECT VERSION()"
	// showStatusQuery is the reader of status: the exact pinned
	// SHOW STATUS (mysql.py:993).
	showStatusQuery = "SHOW STATUS"
	// showVariablesQuery is the reader of showvariables: the exact pinned
	// SHOW VARIABLES (mysql.py:2981).
	showVariablesQuery = "SHOW VARIABLES"
	// showGlobalVariablesQuery is the reader of showglobal: the exact
	// pinned SHOW GLOBAL VARIABLES (mysql.py:3009) — global variables,
	// not global status, exactly like the pinned source.
	showGlobalVariablesQuery = "SHOW GLOBAL VARIABLES"
	// tableCatalogQuery is the table reader of the R9.3c maintenance
	// family's table=None path. The pinned db_tables runs SHOW TABLES IN
	// `name` (mysql.py:1253) — a SHOW statement that cannot wrap its
	// single column in the COALESCE NULL sentinel — so the sentinel
	// mapping rides the same information_schema catalog the SHOW itself
	// reads, exactly the db_list precedent over information_schema.
	// Every (schema, table) pair is selected with both columns
	// sentinel-mapped and the caller's schema is matched client-side, so
	// no caller string reaches SQL. TABLE_SCHEMA and TABLE_NAME are NOT
	// NULL in information_schema.TABLES, and the catalog lists exactly
	// the base tables and views SHOW TABLES lists for a schema, with the
	// same privilege filtering; rows arrive and are operated on in
	// result order. MySQL 8.0.44 sql/dd/info_schema/show.cc
	// build_show_tables_query orders the original TABLE_NAME column.
	// Qualify it here to retain that server column's collation rather than
	// ordering the COALESCE alias (UNHEX can give it binary collation).
	// Do not re-sort in Go: byte order need not match the server collation.
	tableCatalogQuery = "SELECT COALESCE(TABLE_SCHEMA, " + nullSentinelSQL + ") AS TABLE_SCHEMA, COALESCE(TABLE_NAME, " + nullSentinelSQL + ") AS TABLE_NAME FROM information_schema.TABLES ORDER BY information_schema.TABLES.TABLE_NAME"
)

var (
	errMysqlRunnerUnavailable = errors.New("mysql: runner unavailable")
	errMysqlClientUnavailable = errors.New("mysql: mysql client is unavailable")
	errMysqlRunas             = errors.New("mysql: runas is not supported by statekit")
	errMysqlInvalidArgument   = errors.New("mysql: invalid argument")
	// errMysqlDatabaseMissing is the pinned db_tables miss: db_tables
	// answers False when the database does not exist (mysql.py:1243-1245)
	// and the pinned db_check/db_repair/db_optimize then fail on
	// `for table in False:` with a TypeError Salt surfaces as a module
	// error. The port answers the same failed call with this value-free
	// error instead.
	errMysqlDatabaseMissing = errors.New("mysql: database does not exist")
	// errMysqlMaintenanceExit is the strict nonzero-exit abort of the
	// maintenance family: REPAIR and OPTIMIZE mutate server state, so a
	// mysql run completing nonzero is an error, never compatibility
	// data. The CLI transport cannot distinguish the pinned module's
	// _connect-None {} shape from its propagating OperationalError, and
	// an unknown failure answered as data would be partial fake success
	// — the same strict catalog divergence the R9.2s owner_to flow
	// made before its mutation.
	errMysqlMaintenanceExit = errors.New("mysql: maintenance run completed nonzero")
)

// myConnection is the transport half of the pinned **connection_args
// surface (salt/modules/mysql.py:362-457, _connect): salt reads
// connection_user, connection_host, connection_port, connection_pass,
// and connection_db — falling back to mysql.* config options, which
// StateKit has no surface for. Pointer fields keep Salt's None defaults:
// nil omits the corresponding mysql CLI flag or environment variable,
// exactly like _connect drops falsy connargs. The pinned _connect passes
// user/host/port/db straight to MySQLdb.connect; the StateKit transport
// passes them as mysql CLI flags and moves the password out of band into
// mysql's native MYSQL_PWD environment variable. runas is the
// StateKit-side elevation argument the single-user runtime rejects
// before any Runner invocation; the pinned module has none.
type myConnection struct {
	User     *string
	Host     *string
	Port     *string
	Password *string
	DB       *string
	Runas    *string
}

// runMysql is the central mysql CLI execution half shared by the whole
// R9.3a family: a shell-free, centrally executed mysql command with a
// finite timeout, bounded output, a clean child environment, and the
// connection password as the single Redact secret so it never appears in
// the rendered command, captured output, or returned errors. Cancellation,
// runas rejection, argv bounds, and client-unavailability all fail closed
// before any Runner invocation; a non-zero mysql exit stays compatibility
// data for the callers, exactly like the pinned module's logged error
// paths.
func runMysql(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection) (process.CommandResult, error) {
	return runMysqlResult(ctx, rt, argv, conn, nil)
}

// runMysqlResult optionally retains raw stdout for the two fixed maintenance
// catalogs only. Runner redaction must be deferred for those reads: identifiers
// can contain the redaction substring. The raw bytes never enter the safe result
// or errors, and are handed to the parser only after all transport checks pass.
func runMysqlResult(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, catalogStdout *[]byte) (process.CommandResult, error) {
	if catalogStdout != nil {
		*catalogStdout = nil
		if len(argv) == 0 || (argv[len(argv)-1] != "--execute="+showDatabasesQuery && argv[len(argv)-1] != "--execute="+tableCatalogQuery) {
			return process.CommandResult{ExitCode: -1}, errMysqlInvalidArgument
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errMysqlRunnerUnavailable
	}
	if conn == nil {
		conn = &myConnection{}
	}
	if err := rejectRunas(conn.Runas); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable(mysqlCommand) {
		// Fail closed: mysql discovery has no package-manager or other
		// fallback in this module.
		return process.CommandResult{ExitCode: -1}, errMysqlClientUnavailable
	}

	var secrets []string
	if conn.Password != nil {
		secrets = secretList(*conn.Password)
	}
	command := process.Command{
		Name:           argv[0],
		Args:           append([]string(nil), argv[1:]...),
		Timeout:        commandTimeout,
		MaxStdoutBytes: outputLimit,
		MaxStderrBytes: outputLimit,
		Env:            mysqlEnvironment(conn),
	}
	if len(secrets) > 0 && catalogStdout == nil {
		command.Redact = secrets
	}
	result := rt.Runner.Run(ctx, command)
	rawStdout := result.Stdout
	outputExceeded := len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit
	// Defend against custom Runners that do not sanitize their own results.
	result.Stdout = process.RedactBytes(secrets, result.Stdout)
	result.Stderr = process.RedactBytes(secrets, result.Stderr)
	if result.Err != nil {
		result.Err = redactedError(result.Err, secrets...)
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated || outputExceeded {
		return result, process.ErrOutputLimit
	}
	if catalogStdout != nil && result.ExitCode == 0 {
		*catalogStdout = rawStdout
	}
	return result, nil
}

// mysqlArgv builds the canonical batch-mode mysql client argv: the fixed
// --batch (tab-separated rows with one header line, non-interactive, no
// history file), then one joined long flag per supplied connection
// argument — the documented --user/--host/--port/--database spellings —
// and finally the caller's trailing arguments (the fixed query as
// --execute). Batch mode never prompts for credentials: the password
// travels out of band through MYSQL_PWD, and a server that demands one
// the environment does not carry answers a non-zero exit, never a hang.
// With every connection argument supplied, a trailing --execute query
// sits at argv index 6.
func mysqlArgv(user, host, port, database string, args ...string) []string {
	argv := []string{
		mysqlCommand,
		"--batch",
	}
	if user != "" {
		argv = append(argv, "--user="+user)
	}
	if host != "" {
		argv = append(argv, "--host="+host)
	}
	if port != "" {
		argv = append(argv, "--port="+port)
	}
	if database != "" {
		argv = append(argv, "--database="+database)
	}
	return append(argv, args...)
}

// mysqlQueryArgv assembles the fixed-query argv of the read-only family.
func mysqlQueryArgv(conn *myConnection, query string) []string {
	return mysqlArgv(
		pointerString(conn.User),
		pointerString(conn.Host),
		pointerString(conn.Port),
		pointerString(conn.DB),
		"--execute="+query,
	)
}

// mysqlEnvironment builds the clean child environment: only the
// connection password is exported, through mysql's native MYSQL_PWD, so
// the credential never enters argv. An unset password leaves the child
// with no inherited environment at all.
func mysqlEnvironment(conn *myConnection) []string {
	env := make([]string, 0, 1)
	if conn.Password != nil {
		env = append(env, "MYSQL_PWD="+*conn.Password)
	}
	return env
}

// mysqlQueryRows runs one fixed read-only query through the transport and
// decodes the --batch tab-separated stdout: the first non-empty line is
// the column header, every later line one row, and every data field is
// batch-decoded after the tab split. A positive mysql exit keeps the
// pinned compatibility data — the pinned _connect failure and
// OperationalError paths log an error and answer the empty result ([]) or
// False, never an exception — so only Runner failures, cancellation, and
// output-limit violations are errors here.
func mysqlQueryRows(ctx context.Context, rt *runtime.Runtime, conn *myConnection, query string) ([]string, [][]batchField, error) {
	result, err := runMysql(ctx, rt, mysqlQueryArgv(conn, query), conn)
	if err != nil {
		return nil, nil, err
	}
	if result.ExitCode > 0 {
		return []string{}, [][]batchField{}, nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	return header, rows, nil
}

// splitBatchRows frames mysql --batch stdout into raw row lines in one
// bounded left-to-right byte pass: "\n" and "\r\n" end a row — the CR of
// the \r\n delimiter is removed — while a CR that is not immediately
// followed by LF, including a trailing lone CR, is a raw field byte and
// stays in its row. Well-formed batch output is LF-framed (the client
// writes every non-escaped byte, carriage returns included, untouched); a
// client whose output carries CRLF framing — a text-mode layer around the
// same batch writer — is framed without leaving the delimiter CR glued to
// the last field of every row, header included. Rows alias the input and
// nothing beyond the output-limited stdout is allocated.
func splitBatchRows(stdout string) []string {
	rows := make([]string, 0, strings.Count(stdout, "\n")+1)
	start := 0
	for i := 0; i < len(stdout); i++ {
		switch stdout[i] {
		case '\n':
			rows = append(rows, stdout[start:i])
			start = i + 1
		case '\r':
			if i+1 < len(stdout) && stdout[i+1] == '\n' {
				rows = append(rows, stdout[start:i])
				i++ // consume the LF half of the \r\n delimiter
				start = i + 1
			}
			// A CR not followed by LF is a raw field byte: kept.
		}
	}
	if start < len(stdout) {
		rows = append(rows, stdout[start:])
	}
	return rows
}

// parseBatchRows splits the batch stdout into its header line and the
// decoded data rows after it. Rows are framed by the bounded \n/\r\n
// splitter; empty lines (the trailing newline batch output ends with) are
// skipped. Header cells stay verbatim after the split: the client prints
// column names through tee_fputs without the batch escaper, so decoding
// them would corrupt names that legitimately carry backslashes. Data
// fields run through decodeCatalogField.
func parseBatchRows(stdout string) ([]string, [][]batchField) {
	header := []string{}
	rows := [][]batchField{}
	seenHeader := false
	for _, line := range splitBatchRows(stdout) {
		if line == "" {
			continue
		}
		if !seenHeader {
			seenHeader = true
			header = strings.Split(line, "\t")
			continue
		}
		fields := strings.Split(line, "\t")
		row := make([]batchField, len(fields))
		for i, field := range fields {
			row[i] = decodeCatalogField(field)
		}
		rows = append(rows, row)
	}
	return header, rows
}

// batchField is one decoded mysql --batch field after the TSV split:
// value carries the decoded bytes, null marks the fixed SQL NULL sentinel.
type batchField struct {
	value string
	null  bool
}

// decodeCatalogField decodes one catalog data field and maps the fixed
// SQL NULL sentinel back to null. The catalog queries select every column
// through COALESCE(column, UNHEX('00')), so a decoded field of exactly
// one NUL byte can only be a SQL NULL the server mapped to the sentinel —
// MySQL and MariaDB identifiers cannot contain NUL, so no database,
// user, or host value can decode to it — while every other value,
// including one spelled NULL, stays the ordinary string it is.
func decodeCatalogField(field string) batchField {
	decoded := decodeBatchField(field)
	if decoded.value == batchNullSentinel {
		return batchField{null: true}
	}
	return decoded
}

// decodeBatchField decodes one mysql --batch field after the tab split.
//
// The batch encoder — safe_put_field over tee_write in client/mysql.cc of
// MySQL 5.7 and 8.0 and of MariaDB 10.x — escapes exactly NUL, tab,
// newline, and backslash as \0, \t, \n, and \\ and writes every other
// byte (carriage return included) untouched. The decoder accepts the wider
// backslash family the mysql batch tools document together with LOAD DATA
// (\0, \b, \n, \r, \t, \Z, and \\) so output from any client variant
// decodes. Decoding is one bounded left-to-right byte pass with an output
// never longer than the field: an encoded \\n is the two literal
// characters \ and n — a real newline only ever arrives as the two
// characters \ n. Unknown escapes and a trailing lone backslash are
// preserved verbatim: well-formed batch output never carries them, and
// preserving keeps malformed data observable instead of silently dropping
// the backslash the encoder never wrote. A field spelled NULL is the
// ordinary string NULL: the encoder prints SQL NULL exactly like it, so
// the catalog queries never let a bare NULL reach the wire — SQL NULL
// travels as the COALESCE sentinel decodeCatalogField maps instead.
func decodeBatchField(field string) batchField {
	if !strings.ContainsRune(field, '\\') {
		return batchField{value: field}
	}
	var b strings.Builder
	b.Grow(len(field))
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c != '\\' || i+1 >= len(field) {
			// Plain byte, or a trailing lone backslash the encoder never
			// wrote: kept as-is.
			b.WriteByte(c)
			continue
		}
		i++
		switch field[i] {
		case '0':
			b.WriteByte(0)
		case 'b':
			b.WriteByte('\b')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'Z':
			b.WriteByte(0x1a)
		case '\\':
			b.WriteByte('\\')
		default:
			// Unknown escape: preserved verbatim, backslash included.
			b.WriteByte('\\')
			b.WriteByte(field[i])
		}
	}
	return batchField{value: b.String()}
}

// ---------------------------------------------------------------------------
// db_get — salt/modules/mysql.py:1198-1230 @ pinned revision.

// DbGetArgs are the canonical mysql.db_get arguments: the pinned name
// positional plus the shared connection surface and StateKit runas rejection.
type DbGetArgs struct {
	Name     string  `statekit:"name=name,required"`
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *DbGetArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type dbGetFunc struct{}

func (dbGetFunc) Name() string { return "mysql.db_get" }
func (dbGetFunc) Args() any    { return DbGetArgs{} }

func (dbGetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbGetArgs](args, "mysql.db_get")
	if err != nil {
		return nil, err
	}
	return dbGetCatalog(ctx, rt, a.connection(), a.Name)
}

// dbGetCatalog ports the pinned db_get result shapes. A successful query with
// no matching SCHEMATA row answers {}, a matching row answers exactly the
// character_set/collate dict (with SQL NULL rendered as nil), and a nonzero
// mysql exit answers the pinned [] connection/query-failure shape. The fixed
// catalog makes the caller's name a client-side equality check rather than SQL
// interpolation. Short matching rows fail closed instead of panicking or
// fabricating a missing value.
func dbGetCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, name string) (any, error) {
	result, err := runMysql(ctx, rt, mysqlQueryArgv(conn, dbGetQuery), conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode > 0 {
		return []any{}, nil
	}
	_, rows := parseBatchRows(string(result.Stdout))
	for _, row := range rows {
		if len(row) == 0 || row[0].null || row[0].value != name {
			continue
		}
		if len(row) < 3 {
			return nil, errors.New("mysql.db_get: missing catalog column")
		}
		return map[string]any{
			"character_set": catalogValue(row[1]),
			"collate":       catalogValue(row[2]),
		}, nil
	}
	return map[string]any{}, nil
}

// catalogValue converts the fixed SQL NULL sentinel back to the None/nil
// value carried by MySQLdb rows while leaving literal strings untouched.
func catalogValue(field batchField) any {
	if field.null {
		return nil
	}
	return field.value
}

// ---------------------------------------------------------------------------
// db_tables — salt/modules/mysql.py:1233-1267 @ pinned revision.

// DbTablesArgs are the canonical mysql.db_tables arguments. Salt's pinned
// function exposes only name and connection_args; the optional table field is
// a StateKit client-side filter used by callers that share the (name,
// table=None) catalog shape with the maintenance family. It never changes the
// fixed SQL or reaches the Runner as SQL text.
type DbTablesArgs struct {
	Name     string  `statekit:"name=name,required"`
	Table    *string `statekit:"name=table"`
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *DbTablesArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type dbTablesFunc struct{}

func (dbTablesFunc) Name() string { return "mysql.db_tables" }
func (dbTablesFunc) Args() any    { return DbTablesArgs{} }

func (dbTablesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbTablesArgs](args, "mysql.db_tables")
	if err != nil {
		return nil, err
	}
	return dbTablesCatalog(ctx, rt, a.connection(), a.Name, a.Table)
}

// dbTablesCatalog ports db_tables' db_exists preflight and SHOW TABLES result
// order over the fixed information_schema.TABLES catalog already shared by
// the maintenance family. A missing database answers False, a present
// database answers a []string in source order, and a supplied table filters
// that list by exact client-side equality. SQL NULL sentinels and malformed
// short rows are skipped; a literal string NULL remains a table name.
func dbTablesCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, name string, table *string) (any, error) {
	databases, err := dbCatalog(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	found := false
	for _, database := range databases {
		if database == name {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	_, rows, err := mysqlQueryRows(ctx, rt, conn, tableCatalogQuery)
	if err != nil {
		return nil, err
	}
	tables := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 || row[0].null || row[1].null || row[0].value != name {
			continue
		}
		if table != nil && row[1].value != *table {
			continue
		}
		tables = append(tables, row[1].value)
	}
	return tables, nil
}

// ---------------------------------------------------------------------------
// db_list — salt/modules/mysql.py:1131-1161 @ pinned revision.

// DbListArgs are the canonical mysql.db_list arguments: the pinned
// **connection_args surface plus the StateKit runas rejection.
type DbListArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *DbListArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type dbListFunc struct{}

func (dbListFunc) Name() string { return "mysql.db_list" }
func (dbListFunc) Args() any    { return DbListArgs{} }

func (dbListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbListArgs](args, "mysql.db_list")
	if err != nil {
		return nil, err
	}
	return dbCatalog(ctx, rt, a.connection())
}

// dbCatalog is the shared database-name reader of db_list and db_exists:
// the sentinel-mapped catalog of what the pinned SHOW DATABASES reads
// runs verbatim and every row's first column is collected, exactly like
// the pinned ret.append(dbs[0]) loop. A sentinel — SQL NULL — first
// column, which SHOW DATABASES cannot answer and which no []string shape
// carries, is skipped rather than matched; a database actually named
// NULL stays the ordinary string NULL and is listed and matched like any
// other name. On a connection or query failure the pinned function logs
// and answers []; the transport maps those to the same empty list.
func dbCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection) ([]string, error) {
	_, rows, err := mysqlQueryRows(ctx, rt, conn, showDatabasesQuery)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 || row[0].null {
			continue
		}
		out = append(out, row[0].value)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// db_exists — salt/modules/mysql.py:1270-1297 @ pinned revision.

// DbExistsArgs are the canonical mysql.db_exists arguments: the pinned
// name positional plus the shared connection surface.
type DbExistsArgs struct {
	Name     string  `statekit:"name=name,required"`
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *DbExistsArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type dbExistsFunc struct{}

func (dbExistsFunc) Name() string { return "mysql.db_exists" }
func (dbExistsFunc) Args() any    { return DbExistsArgs{} }

func (dbExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbExistsArgs](args, "mysql.db_exists")
	if err != nil {
		return nil, err
	}
	// The pinned qry interpolates the caller's name into
	// "SHOW DATABASES LIKE %(dbname)s;" and answers cur.rowcount == 1.
	// StateKit keeps the same fixed database catalog of db_list (the
	// sentinel-mapped reader of what SHOW DATABASES lists) and matches
	// the name client-side, so no caller string reaches SQL: the catalog
	// lists each database exactly once, so an exact-name hit is the
	// pinned single row. The LIKE wildcard semantics (% and _) are
	// deliberately not reproduced — a pattern is matched literally, never
	// sent to the server.
	databases, err := dbCatalog(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	for _, database := range databases {
		if database == a.Name {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// user_list — salt/modules/mysql.py:1397-1421 @ pinned revision.

// UserListArgs are the canonical mysql.user_list arguments: the pinned
// **connection_args surface plus the StateKit runas rejection.
type UserListArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *UserListArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type userListFunc struct{}

func (userListFunc) Name() string { return "mysql.user_list" }
func (userListFunc) Args() any    { return UserListArgs{} }

func (userListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserListArgs](args, "mysql.user_list")
	if err != nil {
		return nil, err
	}
	return userCatalog(ctx, rt, a.connection())
}

// userCatalog runs the pinned qry — exactly the sentinel-mapped
// SELECT User,Host FROM mysql.user, never a password column — and renders
// every row as the pinned DictCursor fetchall shape: one map per row keyed
// by the result column names (the aliases keep the pinned User/Host
// keys), like the DictRow the pinned function returns and then
// log.debugs. StateKit modules have no logging surface, so nothing is
// ever logged. On a connection or query failure the pinned function logs
// and answers []; the transport maps those to the same empty list. Rows
// shorter than the header keep their zipped prefix exactly like
// dict(zip(header, row)), a decoded sentinel renders as nil — MySQLdb's
// Python None in the DictRow, which never equals a caller string in the
// user_exists match — and a user or host spelled NULL stays the ordinary
// string NULL.
func userCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection) ([]map[string]any, error) {
	header, rows, err := mysqlQueryRows(ctx, rt, conn, userListQuery)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		shared := len(header)
		if len(row) < shared {
			shared = len(row)
		}
		entry := make(map[string]any, shared)
		for i := 0; i < shared; i++ {
			if row[i].null {
				entry[header[i]] = nil
				continue
			}
			entry[header[i]] = row[i].value
		}
		out = append(out, entry)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// user_exists — salt/modules/mysql.py:1502-1605 @ pinned revision.

// UserExistsArgs are the canonical mysql.user_exists arguments, mirroring
// the pinned (user, host="localhost", password=None, password_hash=None,
// passwordless=False, unix_socket=False, password_column=None) signature
// plus the **connection_args surface and the StateKit runas rejection.
type UserExistsArgs struct {
	User           string  `statekit:"name=user,required"`
	Host           *string `statekit:"name=host"`
	Password       *string `statekit:"name=password"`
	PasswordHash   *string `statekit:"name=password_hash"`
	Passwordless   *bool   `statekit:"name=passwordless"`
	UnixSocket     *bool   `statekit:"name=unix_socket"`
	PasswordColumn *string `statekit:"name=password_column"`
	ConnUser       *string `statekit:"name=connection_user"`
	ConnHost       *string `statekit:"name=connection_host"`
	ConnPort       *string `statekit:"name=connection_port"`
	ConnPass       *string `statekit:"name=connection_pass"`
	ConnDB         *string `statekit:"name=connection_db"`
	Runas          *string `statekit:"name=runas"`
}

func (a *UserExistsArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.ConnUser,
		Host:     a.ConnHost,
		Port:     a.ConnPort,
		Password: a.ConnPass,
		DB:       a.ConnDB,
		Runas:    a.Runas,
	}
}

type userExistsFunc struct{}

func (userExistsFunc) Name() string { return "mysql.user_exists" }
func (userExistsFunc) Args() any    { return UserExistsArgs{} }

func (userExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserExistsArgs](args, "mysql.user_exists")
	if err != nil {
		return nil, err
	}
	// The pinned password-verification ladder is refused before any
	// Runner invocation; the bare existence path runs below.
	if err := a.verifyUnsupported(); err != nil {
		return nil, err
	}
	rows, err := userCatalog(ctx, rt, a.connection())
	if err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	for _, row := range rows {
		userValue, hasUser := row["User"]
		hostValue, hasHost := row["Host"]
		if !hasUser || !hasHost {
			// Salt's DictRow always carries both columns of the fixed
			// query; a row without them is the missing-column KeyError
			// precedent, answered value-free.
			return nil, fmt.Errorf("mysql.user_exists: missing column %q or %q", "User", "Host")
		}
		if userValue == a.User && hostValue == host {
			// (User, Host) is the mysql.user primary key, so a hit is the
			// pinned cur.rowcount == 1.
			return true, nil
		}
	}
	return false, nil
}

// verifyUnsupported rejects the pinned password-verification variants:
// the pinned ladder appends password-column comparisons —
// "AND <password_column> = PASSWORD(%(password)s)" or the hash/plugin
// forms — to the SQL, interpolating credential material into the query
// and depending on the version, password-column, and auth-plugin probes
// that the fixed User,Host catalog does not carry. StateKit refuses those
// variants with the deterministic value-free unsupported error before any
// Runner invocation instead of silently answering the bare existence
// check. The pinned truthiness is kept exactly: None and the empty
// string are both falsy for password and password_hash, so an explicit
// empty password stays on the supported bare path; password_column stays
// inert, exactly like the pinned source never reads it without one of
// the password arguments.
func (a *UserExistsArgs) verifyUnsupported() error {
	if pointerTruthy(a.Password) || pointerTruthy(a.PasswordHash) ||
		pointerBool(a.Passwordless) || pointerBool(a.UnixSocket) {
		return &runtime.UnsupportedError{Kind: "function", Name: "mysql.user_exists password verification"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// version — salt/modules/mysql.py:1009-1040 @ pinned revision.

// VersionArgs are the canonical mysql.version arguments: the pinned
// **connection_args surface plus the StateKit runas rejection.
type VersionArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *VersionArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type versionFunc struct{}

func (versionFunc) Name() string { return "mysql.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[VersionArgs](args, "mysql.version")
	if err != nil {
		return nil, err
	}
	return mysqlVersion(ctx, rt, a.connection())
}

// mysqlVersion runs the exact pinned qry SELECT VERSION() — the pinned
// module reads the server version, it never shells out to `mysql
// --version` — and answers the decoded first field of the first row. The
// pinned _connect-None and OperationalError paths log and answer "" and
// the pinned fetchone() IndexError answers "" for a rowless result: the
// transport maps all three to the empty string, never an error. The pinned
// module caches the answer in its per-run __context__; StateKit has no
// such context, so every call re-queries (documented divergence,
// observable only as the extra query).
func mysqlVersion(ctx context.Context, rt *runtime.Runtime, conn *myConnection) (string, error) {
	_, rows, err := mysqlQueryRows(ctx, rt, conn, selectVersionQuery)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		// The pinned fetchone() IndexError: no row, no first field.
		return "", nil
	}
	return rows[0][0].value, nil
}

// ---------------------------------------------------------------------------
// status — salt/modules/mysql.py:978-1006 @ pinned revision.

// StatusArgs are the canonical mysql.status arguments: the pinned
// **connection_args surface plus the StateKit runas rejection.
type StatusArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *StatusArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type statusFunc struct{}

func (statusFunc) Name() string { return "mysql.status" }
func (statusFunc) Args() any    { return StatusArgs{} }

func (statusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[StatusArgs](args, "mysql.status")
	if err != nil {
		return nil, err
	}
	return mysqlStatus(ctx, rt, a.connection())
}

// mysqlStatus runs the exact pinned qry SHOW STATUS and renders the pinned
// dict shape: one name→value entry per row — ret[row[0]] = row[1] — with
// later duplicates overwriting earlier exactly like the pinned assignment
// loop. The pinned _connect-None and OperationalError paths log and answer
// {}, which the transport's nonzero-exit compatibility mapping reproduces.
// Every field runs through the batch decoder, so escaped values
// (backslash, tab, newline, carriage return) and both row framings decode.
// A SHOW statement cannot carry the COALESCE sentinel of the R9.3a
// catalogs, and MySQL and MariaDB status variable values are never SQL
// NULL (the tables SHOW STATUS reads declare VARIABLE_VALUE NOT NULL and
// print unset values as the empty string), so a field spelled NULL stays
// the ordinary string — the one boundary a bare NULL marker cannot
// disambiguate on this surface, which the servers themselves never emit.
// Rows shorter than the fixed two columns — impossible from the real
// client — are skipped.
func mysqlStatus(ctx context.Context, rt *runtime.Runtime, conn *myConnection) (map[string]string, error) {
	_, rows, err := mysqlQueryRows(ctx, rt, conn, showStatusQuery)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		out[row[0].value] = row[1].value
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// showvariables / showglobal — salt/modules/mysql.py:2962-2987 and
// 2990-3015 @ pinned revision.

// ShowVariablesArgs are the canonical mysql.showvariables arguments: the
// pinned **connection_args surface plus the StateKit runas rejection. The
// pinned function takes no filter or name argument — it returns the full
// variables dict list.
type ShowVariablesArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *ShowVariablesArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type showVariablesFunc struct{}

func (showVariablesFunc) Name() string { return "mysql.showvariables" }
func (showVariablesFunc) Args() any    { return ShowVariablesArgs{} }

func (showVariablesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ShowVariablesArgs](args, "mysql.showvariables")
	if err != nil {
		return nil, err
	}
	return showCatalog(ctx, rt, a.connection(), showVariablesQuery)
}

// ShowGlobalArgs are the canonical mysql.showglobal arguments: the pinned
// **connection_args surface plus the StateKit runas rejection, identical
// to showvariables — the pinned pair differs only in its fixed query.
type ShowGlobalArgs struct {
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *ShowGlobalArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type showGlobalFunc struct{}

func (showGlobalFunc) Name() string { return "mysql.showglobal" }
func (showGlobalFunc) Args() any    { return ShowGlobalArgs{} }

func (showGlobalFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ShowGlobalArgs](args, "mysql.showglobal")
	if err != nil {
		return nil, err
	}
	return showCatalog(ctx, rt, a.connection(), showGlobalVariablesQuery)
}

// showCatalog runs one pinned SHOW VARIABLES-family query through the
// shape of the pinned __do_query_into_hash: the list of row dicts keyed by
// the result column names (Variable_name and Value on both pinned
// queries), rendered here as one map per row over the batch header with
// StateKit defensive prefix-zip divergence: ordinary complete rows are exact,
// but malformed short rows do not panic. The pinned Python helper indexes
// every described column and raises IndexError instead of truncating the row.
// The pinned empty-result quirk is preserved exactly: a successful query
// that answers no rows makes `if not rtnv: rtnv.append([])` return [[]] —
// a list whose single element is the empty list — while a connection the
// pinned _connect would answer None for returns the bare empty list. The
// CLI transport cannot distinguish a failed connection from a failed
// query, so the nonzero-exit compatibility mapping answers the pinned
// _connect-None shape — the bare empty list, the dominant real-world
// nonzero exit being an unreachable or denying server. The SHOW sentinel
// boundary of mysqlStatus applies to every value: system variable values
// are never SQL NULL, so a field spelled NULL stays the ordinary string.
func showCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, query string) ([]any, error) {
	result, err := runMysql(ctx, rt, mysqlQueryArgv(conn, query), conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode > 0 {
		// The pinned _connect-None path: the bare empty list.
		return []any{}, nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	if len(rows) == 0 {
		// The pinned `if not rtnv: rtnv.append([])` quirk: [[]].
		return []any{[]any{}}, nil
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		shared := len(header)
		if len(row) < shared {
			shared = len(row)
		}
		entry := make(map[string]string, shared)
		for i := 0; i < shared; i++ {
			entry[header[i]] = row[i].value
		}
		out = append(out, entry)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// db_check / db_repair / db_optimize — salt/modules/mysql.py:271-313
// (__check_table/__repair_table/__optimize_table), 1233-1267 (db_tables),
// and 2251-2319 (db_check/db_repair/db_optimize) @ pinned revision.

// validMaintenanceIdentifier reports whether identifier is safe for the
// fixed maintenance statements: non-empty and free of NUL and ASCII
// control bytes (the C0 controls 0x00-0x1F and DEL) — the bytes no MySQL
// or MariaDB identifier may carry and that cannot travel through a fixed
// argv unchanged. Every other byte stays inside quoteIdentifier's doubled
// backticks: backticks, percent signs, and non-ASCII names (legal in
// MySQL's BMP identifier range; the server enforces its own charset
// rules) render as quoted identifiers exactly like the pinned module.
// The rejection is value-free and raised before any Runner invocation,
// where no redaction pass could strip a caller secret the value embeds.
func validMaintenanceIdentifier(identifier string) bool {
	if identifier == "" {
		return false
	}
	for i := 0; i < len(identifier); i++ {
		if identifier[i] < 0x20 || identifier[i] == 0x7f {
			return false
		}
	}
	return true
}

// maintenanceIdentifierError is the fixed, value-free rejection for a
// name or table the fixed maintenance statements cannot carry: the
// argument key under the shared invalid-argument category, never the
// rejected value, so the message is a constant for a given key.
func maintenanceIdentifierError(key string) error {
	return fmt.Errorf("%w: unsupported identifier in %s", errMysqlInvalidArgument, key)
}

// maintenanceStatement builds the pinned maintenance statement: the
// committed quoteIdentifier quotes both identifiers — backtick doubling
// plus MySQLdb's doubled '%' — exactly like the pinned
// f"CHECK TABLE {s_name}.{s_table}", and the pinned _execute no-args
// unescape (mysql.py:734-737, qry.replace("%%", "%")) restores single
// percent signs, so the --execute string is byte-identical to the SQL
// the pinned module sends through MySQLdb.
func maintenanceStatement(verb, name, table string) string {
	statement := verb + " TABLE " + quoteIdentifier(name, false) + "." + quoteIdentifier(table, false)
	return strings.ReplaceAll(statement, "%%", "%")
}

// maintenanceRows runs one fixed read-side query of the maintenance flow
// under the strict nonzero-aborts policy the mutation family requires:
// Runner failures, cancellation, and output-limit violations propagate,
// and a mysql run completing nonzero answers errMysqlMaintenanceExit
// instead of the read-only family's empty-result compatibility data — a
// failed catalog read must never be mistaken for an empty catalog, which
// would answer a fake success.
func maintenanceRows(ctx context.Context, rt *runtime.Runtime, conn *myConnection, query string) ([]string, [][]batchField, error) {
	var rawStdout []byte
	result, err := runMysqlResult(ctx, rt, mysqlQueryArgv(conn, query), conn, &rawStdout)
	if err != nil {
		return nil, nil, err
	}
	if result.ExitCode != 0 {
		return nil, nil, errMysqlMaintenanceExit
	}
	header, rows := parseBatchRows(string(rawStdout))
	return header, rows, nil
}

// maintenanceTables ports the pinned db_tables contract for the
// maintenance family's table=None path: the pinned function first
// answers db_exists and returns False on a miss (the pinned wrappers
// then fail on `for table in False:`), and only then reads SHOW TABLES
// IN `name`. The port matches the database client-side over the same
// fixed SCHEMATA catalog of db_list/db_exists, then reads the fixed
// information_schema.TABLES catalog and collects the matched schema's
// table names in result order — the order the pinned SHOW TABLES
// returns and the pinned loop operates on. Rows whose schema or table
// column carries the SQL NULL sentinel (impossible from
// information_schema.TABLES, whose columns are NOT NULL) and short rows
// (impossible from the real client) are skipped rather than fabricating
// a table name, so the statement list can only ever shrink, never
// invent. Both catalog reads run under the strict nonzero-aborts policy.
func maintenanceTables(ctx context.Context, rt *runtime.Runtime, conn *myConnection, name string) ([]string, error) {
	_, rows, err := maintenanceRows(ctx, rt, conn, showDatabasesQuery)
	if err != nil {
		return nil, err
	}
	found := false
	for _, row := range rows {
		if len(row) > 0 && !row[0].null && row[0].value == name {
			found = true
			break
		}
	}
	if !found {
		return nil, errMysqlDatabaseMissing
	}
	_, rows, err = maintenanceRows(ctx, rt, conn, tableCatalogQuery)
	if err != nil {
		return nil, err
	}
	tables := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 || row[0].null || row[1].null {
			continue
		}
		if row[0].value != name {
			continue
		}
		tables = append(tables, row[1].value)
	}
	return tables, nil
}

// maintenanceOne runs one pinned maintenance statement and renders the
// pinned DictCursor fetchall shape: one map per row keyed by the result
// column names — Table, Op, Msg_type, and Msg_text from CHECK, REPAIR,
// and OPTIMIZE TABLE — exactly like the DictRow of the pinned
// __check_table/__repair_table/__optimize_table; the batch CLI mapping
// is therefore not distinct from the pinned dict-row shape, only its
// transport is. Batch rows decode field by field with the client's own
// escaping; a decoded sentinel renders as nil (the DictRow None) and a
// field spelled NULL stays the ordinary string — the servers never emit
// SQL NULL on these statements, so the sentinel mapping is inert but
// uniform with the catalog families. Short rows keep their zipped
// prefix like dict(zip(header, row)) and never panic (the defensive
// prefix-zip divergence). A rowless success answers the empty list,
// exactly like fetchall on an empty result, and a nonzero exit is the
// strict maintenance error, never data.
func maintenanceOne(ctx context.Context, rt *runtime.Runtime, conn *myConnection, verb, name, table string) ([]map[string]any, error) {
	statement := maintenanceStatement(verb, name, table)
	result, err := runMysql(ctx, rt, mysqlQueryArgv(conn, statement), conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, errMysqlMaintenanceExit
	}
	header, rows := parseBatchRows(string(result.Stdout))
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		shared := len(header)
		if len(row) < shared {
			shared = len(row)
		}
		entry := make(map[string]any, shared)
		for i := 0; i < shared; i++ {
			if row[i].null {
				entry[header[i]] = nil
				continue
			}
			entry[header[i]] = row[i].value
		}
		out = append(out, entry)
	}
	return out, nil
}

// dbMaintenance is the shared body of the pinned db_check, db_repair,
// and db_optimize wrappers (mysql.py:2252-2319): with table=None it
// lists the database's tables and appends one per-table result list in
// source order — the pinned ret.append(__check_table(...)) loop — and
// with a table it answers that single statement's result list directly,
// never wrapped. Both identifiers are validated value-free before any
// Runner invocation; a failed catalog or statement aborts with an error
// and no partial success value, exactly like the pinned module's
// propagating OperationalError (statements already executed stay
// executed, the pinned behavior). Cancellation between statements is
// caught by the transport's per-run context check.
func dbMaintenance(ctx context.Context, rt *runtime.Runtime, conn *myConnection, verb, name string, table *string) (any, error) {
	if !validMaintenanceIdentifier(name) {
		return nil, maintenanceIdentifierError("name")
	}
	if table != nil && !validMaintenanceIdentifier(*table) {
		return nil, maintenanceIdentifierError("table")
	}
	if table != nil {
		return maintenanceOne(ctx, rt, conn, verb, name, *table)
	}
	tables, err := maintenanceTables(ctx, rt, conn, name)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(tables))
	for _, one := range tables {
		rows, err := maintenanceOne(ctx, rt, conn, verb, name, one)
		if err != nil {
			return nil, err
		}
		out = append(out, rows)
	}
	return out, nil
}

// DbMaintenanceArgs are the canonical mysql.db_check, mysql.db_repair,
// and mysql.db_optimize arguments: the pinned (name, table=None)
// signature plus the shared connection surface and the StateKit runas
// rejection. A nil table keeps the pinned None default — the
// whole-database flow over every table db_tables lists.
type DbMaintenanceArgs struct {
	Name     string  `statekit:"name=name,required"`
	Table    *string `statekit:"name=table"`
	User     *string `statekit:"name=connection_user"`
	Host     *string `statekit:"name=connection_host"`
	Port     *string `statekit:"name=connection_port"`
	Password *string `statekit:"name=connection_pass"`
	DB       *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *DbMaintenanceArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		User:     a.User,
		Host:     a.Host,
		Port:     a.Port,
		Password: a.Password,
		DB:       a.DB,
		Runas:    a.Runas,
	}
}

type dbCheckFunc struct{}

func (dbCheckFunc) Name() string { return "mysql.db_check" }
func (dbCheckFunc) Args() any    { return DbMaintenanceArgs{} }

func (dbCheckFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbMaintenanceArgs](args, "mysql.db_check")
	if err != nil {
		return nil, err
	}
	return dbMaintenance(ctx, rt, a.connection(), "CHECK", a.Name, a.Table)
}

type dbRepairFunc struct{}

func (dbRepairFunc) Name() string { return "mysql.db_repair" }
func (dbRepairFunc) Args() any    { return DbMaintenanceArgs{} }

func (dbRepairFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbMaintenanceArgs](args, "mysql.db_repair")
	if err != nil {
		return nil, err
	}
	return dbMaintenance(ctx, rt, a.connection(), "REPAIR", a.Name, a.Table)
}

type dbOptimizeFunc struct{}

func (dbOptimizeFunc) Name() string { return "mysql.db_optimize" }
func (dbOptimizeFunc) Args() any    { return DbMaintenanceArgs{} }

func (dbOptimizeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[DbMaintenanceArgs](args, "mysql.db_optimize")
	if err != nil {
		return nil, err
	}
	return dbMaintenance(ctx, rt, a.connection(), "OPTIMIZE", a.Name, a.Table)
}

// ---------------------------------------------------------------------------
// shared helpers (postgres-module conventions).

func typedArgs[T any](args any, name string) (*T, error) {
	value, ok := args.(*T)
	if !ok || value == nil {
		return nil, fmt.Errorf("%s: expected *arguments, got %T", name, args)
	}
	return value, nil
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// pointerBool is the pinned is_true() over an optional bool argument: nil
// (Python None) is false.
func pointerBool(value *bool) bool {
	return value != nil && *value
}

// pointerTruthy is the pinned Python truthiness over an optional string
// argument: None and the empty string are both falsy, exactly like the
// pinned `elif password:` guards.
func pointerTruthy(value *string) bool {
	return value != nil && *value != ""
}

func rejectRunas(runas *string) error {
	if runas == nil || *runas == "" {
		return nil
	}
	if strings.IndexByte(*runas, 0) >= 0 || strings.ContainsAny(*runas, "\r\n") {
		return errMysqlInvalidArgument
	}
	return errMysqlRunas
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errMysqlInvalidArgument
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 || strings.ContainsAny(arg, "\r\n") {
			return errMysqlInvalidArgument
		}
		total += len(arg)
		if total > runtime.MaxCommandInputBytes {
			return runtime.ErrCommandInputLimit
		}
	}
	return nil
}

func secretList(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// redactedError strips every given secret from a Runner error, so no
// credential travels through returned errors. Empty secrets leave the
// error untouched.
func redactedError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	list := secretList(secrets...)
	if len(list) == 0 {
		return err
	}
	message := process.RedactString(list, err.Error())
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

// Register installs the mysql catalog slice: the R9.2a pure functions
// quote_identifier and tokenize_grant, the R9.3a/R9.3d read-only catalog
// family db_list, db_exists, user_list, user_exists, db_get, and db_tables,
// the R9.3b read-only server facts family version, status, showvariables, and
// showglobal, and the R9.3c maintenance family db_check, db_repair, and
// db_optimize over the central mysql CLI transport. The remainder of the
// mysql family needs the client protocol or mutation boundary and stays
// pending.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		quoteIdentifierFunc{},
		tokenizeGrantFunc{},
		dbListFunc{},
		dbExistsFunc{},
		dbGetFunc{},
		dbTablesFunc{},
		userListFunc{},
		userExistsFunc{},
		versionFunc{},
		statusFunc{},
		showVariablesFunc{},
		showGlobalFunc{},
		dbCheckFunc{},
		dbRepairFunc{},
		dbOptimizeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
