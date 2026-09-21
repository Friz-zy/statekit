// Package mysql implements slices of the pinned Salt mysql execution
// surface: the driver-free pure functions quote_identifier and
// tokenize_grant (R9.2a), the read-only catalog family db_list, db_exists,
// user_list, user_exists, user_info, db_get, and db_tables (R9.3a/R9.3d/R9.3e),
// the read-only server facts family version, status, showvariables, and
// showglobal (R9.3b), the maintenance family db_check, db_repair, and
// db_optimize (R9.3c), the fixed-query user_create/user_remove mutation
// family (R9.3e), the fixed-query grant_add/grant_exists/grant_revoke family
// (R9.3f), and the fixed-query user_grants reader (R9.3h).
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
//
// Boundaries (R9.3e): user_info reads an explicit, non-secret mysql.user
// column set and matches User/Host client-side; account mutations build only
// the pinned CREATE USER and DROP USER IF EXISTS forms with SQL string
// literals, allowlisted authentication-plugin tokens, the shared MYSQL_PWD
// connection transport, and bounded Runner cancellation/output controls.
// No database driver or live server is used by this package or its tests.
//
// Boundaries (R9.3f): grant mutations build only the pinned GRANT/REVOKE
// forms from separately validated database/table identifiers and SQL-literal
// account values. grant_exists reads the fixed SHOW GRANTS statement and, for
// an expanded global ALL grant, the fixed SHOW PRIVILEGES catalog; each grant
// is parsed with the existing source-compatible tokenizer. No caller-provided
// SQL is accepted. All three functions use the central shell-free mysql
// transport with bounded cancellation, output, argv, and redaction controls,
// and remain fake-Runner-only.
//
// Boundaries (R9.3h): user_grants issues only the fixed SHOW GRANTS statement
// with a SQL-literal account expression, decodes the bounded batch row list in
// source order, and preserves the pinned IDENTIFIED BY/GRANT OPTION cleanup.
// Backslashes are escaped by the fixed literal renderer for this read-only
// path, while NUL/control and invalid UTF-8 account data fail closed.
package mysql

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	// errMysqlGrant is deliberately value-free: grant text is pasted into a
	// fixed statement and must never travel through an error message.
	errMysqlGrant = errors.New("mysql: invalid grant")
	// errMysqlGrantIdentifier is also value-free because identifier text can
	// overlap a connection credential or another sensitive caller value.
	errMysqlGrantIdentifier = errors.New("mysql: invalid grant identifier")
)

// mysqlGrantPrivileges is the pinned __grants__ allow-list from mysql.py.
// Keeping the list local avoids accepting arbitrary SQL in the GRANT clause;
// the source list includes the MySQL and MariaDB spellings used by SHOW
// GRANTS on the supported server families.
var mysqlGrantPrivileges = map[string]struct{}{
	"ALL PRIVILEGES":             {},
	"ALTER":                      {},
	"ALTER ROUTINE":              {},
	"BACKUP_ADMIN":               {},
	"BINLOG_ADMIN":               {},
	"BINLOG ADMIN":               {},
	"BINLOG MONITOR":             {},
	"BINLOG REPLAY":              {},
	"CONNECTION_ADMIN":           {},
	"CONNECTION ADMIN":           {},
	"CREATE":                     {},
	"CREATE ROLE":                {},
	"CREATE ROUTINE":             {},
	"CREATE TABLESPACE":          {},
	"CREATE TEMPORARY TABLES":    {},
	"CREATE USER":                {},
	"CREATE VIEW":                {},
	"DELETE":                     {},
	"DELETE HISTORY":             {},
	"DROP":                       {},
	"DROP ROLE":                  {},
	"ENCRYPTION_KEY_ADMIN":       {},
	"EVENT":                      {},
	"EXECUTE":                    {},
	"FEDERATED ADMIN":            {},
	"FILE":                       {},
	"GRANT OPTION":               {},
	"GROUP_REPLICATION_ADMIN":    {},
	"INDEX":                      {},
	"INSERT":                     {},
	"LOCK TABLES":                {},
	"PERSIST_RO_VARIABLES_ADMIN": {},
	"PROCESS":                    {},
	"READ_ONLY ADMIN":            {},
	"REFERENCES":                 {},
	"RELOAD":                     {},
	"REPLICA MONITOR":            {},
	"REPLICATION CLIENT":         {},
	"REPLICATION MASTER ADMIN":   {},
	"REPLICATION REPLICA":        {},
	"REPLICATION SLAVE":          {},
	"REPLICATION_SLAVE_ADMIN":    {},
	"REPLICATION SLAVE ADMIN":    {},
	"RESOURCE_GROUP_ADMIN":       {},
	"RESOURCE_GROUP_USER":        {},
	"ROLE_ADMIN":                 {},
	"SELECT":                     {},
	"SET USER":                   {},
	"SET_USER_ID":                {},
	"SERVICE_CONNECTION_ADMIN":   {},
	"SHOW DATABASES":             {},
	"SHOW VIEW":                  {},
	"SHUTDOWN":                   {},
	"SLAVE MONITOR":              {},
	"SUPER":                      {},
	"SYSTEM_VARIABLES_ADMIN":     {},
	"TRIGGER":                    {},
	"UPDATE":                     {},
	"USAGE":                      {},
	"XA_RECOVER_ADMIN":           {},
}

// mysqlAllPrivileges is the pinned static fallback set used only for the
// eligible MySQL-8 global-ALL SHOW PRIVILEGES phase. A literal ALL PRIVILEGES
// row is never treated as a universal grant by ordinary-object matching.
var mysqlAllPrivileges = []string{
	"ALTER",
	"ALTER ROUTINE",
	"BACKUP_ADMIN",
	"BINLOG_ADMIN",
	"CONNECTION_ADMIN",
	"CREATE",
	"CREATE ROLE",
	"CREATE ROUTINE",
	"CREATE TABLESPACE",
	"CREATE TEMPORARY TABLES",
	"CREATE USER",
	"CREATE VIEW",
	"DELETE",
	"DROP",
	"DROP ROLE",
	"ENCRYPTION_KEY_ADMIN",
	"EVENT",
	"EXECUTE",
	"FILE",
	"GROUP_REPLICATION_ADMIN",
	"INDEX",
	"INSERT",
	"LOCK TABLES",
	"PERSIST_RO_VARIABLES_ADMIN",
	"PROCESS",
	"REFERENCES",
	"RELOAD",
	"REPLICATION CLIENT",
	"REPLICATION SLAVE",
	"REPLICATION_SLAVE_ADMIN",
	"RESOURCE_GROUP_ADMIN",
	"RESOURCE_GROUP_USER",
	"ROLE_ADMIN",
	"SELECT",
	"SET_USER_ID",
	"SHOW DATABASES",
	"SHOW VIEW",
	"SHUTDOWN",
	"SUPER",
	"SYSTEM_VARIABLES_ADMIN",
	"TRIGGER",
	"UPDATE",
	"XA_RECOVER_ADMIN",
}

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

// grantAccountParts is the canonical account representation used by the
// grant mutation surface.  The public grant functions accept one user value;
// it may be a bare user (which keeps Salt's localhost default), user@host, or
// a SQL-quoted user@host account.  Keeping the split here, rather than using
// strings.Fields, is important: MySQL permits quoted host values containing
// spaces, commas, apostrophes, and backticks.
type grantAccountParts struct {
	User string
	Host string
}

// grantSQLAccount is the account plus its byte span in a SHOW GRANTS
// statement.  The span is used only to give the legacy lexer a harmless
// placeholder when an SQL-escaped quote would otherwise split its tokens.
type grantSQLAccount struct {
	grantAccountParts
	Start int
	End   int
}

func grantSkipWhitespace(value string, pos int) int {
	for pos < len(value) && isGrantWhitespace(rune(value[pos])) {
		pos++
	}
	return pos
}

// grantScanAccountPart reads one SQL account component.  It understands both
// MySQL string literals and quoted identifiers, including doubled delimiters
// (two single quotes and two backticks) and the legacy backslash escape emitted by some SHOW GRANTS
// clients.  The returned value is unquoted and preserves all interior data.
func grantScanAccountPart(value string, pos int, stopAtAt bool) (string, int, bool) {
	pos = grantSkipWhitespace(value, pos)
	if pos >= len(value) {
		return "", pos, false
	}
	if value[pos] == '\'' || value[pos] == '`' {
		quote := value[pos]
		pos++
		var out strings.Builder
		for pos < len(value) {
			char := value[pos]
			if char == '\\' && pos+1 < len(value) {
				out.WriteByte(value[pos+1])
				pos += 2
				continue
			}
			if char == quote {
				if pos+1 < len(value) && value[pos+1] == quote {
					out.WriteByte(quote)
					pos += 2
					continue
				}
				return out.String(), pos + 1, true
			}
			out.WriteByte(char)
			pos++
		}
		return "", pos, false
	}

	start := pos
	for pos < len(value) {
		char := value[pos]
		if isGrantWhitespace(rune(char)) || char == ';' || (stopAtAt && char == '@') {
			break
		}
		pos++
	}
	if start == pos {
		return "", pos, false
	}
	return value[start:pos], pos, true
}

func grantKeywordIndex(value, keyword string) int {
	var quote byte
	for pos := 0; pos < len(value); pos++ {
		char := value[pos]
		if quote != 0 {
			if char == '\\' && pos+1 < len(value) {
				pos++
				continue
			}
			if char == quote {
				if pos+1 < len(value) && value[pos+1] == quote {
					pos++
					continue
				}
				quote = 0
			}
			continue
		}
		if char == '\'' || char == '`' {
			quote = char
			continue
		}
		if pos+len(keyword) > len(value) || !strings.EqualFold(value[pos:pos+len(keyword)], keyword) {
			continue
		}
		if pos > 0 && isGrantWordchar(rune(value[pos-1])) {
			continue
		}
		end := pos + len(keyword)
		if end < len(value) && isGrantWordchar(rune(value[end])) {
			continue
		}
		return pos
	}
	return -1
}

func firstGrantKeyword(value string) string {
	pos := grantSkipWhitespace(value, 0)
	start := pos
	for pos < len(value) && isGrantWordchar(rune(value[pos])) {
		pos++
	}
	return strings.ToUpper(value[start:pos])
}

// parseGrantSQLAccount extracts the account following the ordinary GRANT
// statement's TO keyword.  PROXY grants intentionally keep the pinned
// tokenizer's concatenated database shape and are excluded by the caller.
func parseGrantSQLAccount(value string) (grantSQLAccount, bool) {
	if firstGrantKeyword(value) == "PROXY" {
		return grantSQLAccount{}, false
	}
	to := grantKeywordIndex(value, "TO")
	if to < 0 {
		return grantSQLAccount{}, false
	}
	pos := grantSkipWhitespace(value, to+2)
	start := pos
	user, pos, ok := grantScanAccountPart(value, pos, true)
	if !ok {
		return grantSQLAccount{}, false
	}
	pos = grantSkipWhitespace(value, pos)
	if pos >= len(value) || value[pos] != '@' {
		return grantSQLAccount{}, false
	}
	pos++
	host, end, ok := grantScanAccountPart(value, pos, false)
	if !ok {
		return grantSQLAccount{}, false
	}
	return grantSQLAccount{grantAccountParts: grantAccountParts{User: user, Host: host}, Start: start, End: end}, true
}

func grantSQLAccountNeedsCanonical(account grantSQLAccount) bool {
	// Keep the source tokenizer's ordinary quoted/backslash shapes byte-for-
	// byte. Switch to the SQL-aware account values only when the account data
	// would otherwise be truncated: apostrophes, backticks, or commas in the
	// canonical user/host component.
	return strings.ContainsAny(account.User, "'`,") || strings.ContainsAny(account.Host, "'`,")
}

// parseGrantAccountInput parses the public user value.  A bare user keeps
// Salt's default localhost account host; an @ outside a SQL quote selects the
// supplied account host.  The function deliberately returns only fixed error
// categories, never the caller value.
func parseGrantAccountInput(value string) (grantAccountParts, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return grantAccountParts{}, errMysqlAccountArgument
	}
	user, pos, ok := grantScanAccountPart(trimmed, 0, true)
	if !ok {
		return grantAccountParts{}, errMysqlAccountArgument
	}
	pos = grantSkipWhitespace(trimmed, pos)
	host := defaultUserHost
	if pos < len(trimmed) {
		if trimmed[pos] != '@' {
			return grantAccountParts{}, errMysqlAccountArgument
		}
		pos++
		var hostOK bool
		host, pos, hostOK = grantScanAccountPart(trimmed, pos, false)
		if !hostOK {
			return grantAccountParts{}, errMysqlAccountArgument
		}
		if rest := strings.TrimSpace(trimmed[pos:]); rest != "" {
			return grantAccountParts{}, errMysqlAccountArgument
		}
	}
	if !validAccountPart(user) || !validAccountPart(host) {
		return grantAccountParts{}, errMysqlAccountArgument
	}
	return grantAccountParts{User: user, Host: host}, nil
}

// parseGrantAccount maps the StateKit account adapter onto Salt's separate
// user/host parameters. The existing user-first adapter remains compatible
// with the earlier StateKit surface when host is omitted: a bare user gets
// localhost and a user@host value is parsed as one account. Supplying host
// explicitly selects the pinned source mapping, so an @ in user remains user
// data instead of being interpreted as the adapter separator.
func parseGrantAccount(user string, host *string) (grantAccountParts, error) {
	if host == nil {
		return parseGrantAccountInput(user)
	}
	if strings.TrimSpace(user) == "" || !validAccountPart(user) || !validAccountPart(*host) {
		return grantAccountParts{}, errMysqlAccountArgument
	}
	return grantAccountParts{User: user, Host: *host}, nil
}

func rewriteGrantAccountForLexer(value string, account grantSQLAccount) string {
	return value[:account.Start] + "'u'@'h'" + value[account.End:]
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
	var sqlAccount grantSQLAccount
	var hasSQLAccount bool
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

	if !dictMode {
		sqlAccount, hasSQLAccount = parseGrantSQLAccount(grantSQL)
	}
	exploded, err := grantExplode(grantSQL)
	if err != nil && hasSQLAccount {
		// A doubled SQL quote is data to MySQL but two quote-delimited tokens to
		// the source-compatible shlex port. Retry only the lexer input with a
		// fixed account placeholder; the canonical account below still comes
		// from the SQL-aware parser and is never returned from the placeholder.
		exploded, err = grantExplode(rewriteGrantAccountForLexer(grantSQL, sqlAccount))
	}
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
		if hasSQLAccount && grantSQLAccountNeedsCanonical(sqlAccount) {
			user = sqlAccount.User
			host = sqlAccount.Host
		} else {
			user = strings.Trim(user, "'")
			host = strings.Trim(host, "'")
		}
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
	// userPluginQuery is the fixed post-mutation account catalog. User and
	// Host are matched in Go; the plugin is read only to decide whether the
	// pinned mysql_native_password verifier comparison is meaningful.
	userPluginQuery = "SELECT COALESCE(User, " + nullSentinelSQL + ") AS User, COALESCE(Host, " + nullSentinelSQL + ") AS Host, COALESCE(plugin, " + nullSentinelSQL + ") AS plugin FROM mysql.user"
	// userInfoQuery is deliberately explicit rather than SELECT *: these are
	// the stable account/privilege fields asserted by the pinned functional
	// tests. Authentication material is never selected. User and Host are
	// matched in Go, so no caller string reaches SQL or a WHERE clause.
	userInfoQuery = "SELECT COALESCE(User, " + nullSentinelSQL + ") AS User, COALESCE(Host, " + nullSentinelSQL + ") AS Host, COALESCE(Select_priv, " + nullSentinelSQL + ") AS Select_priv, COALESCE(Insert_priv, " + nullSentinelSQL + ") AS Insert_priv, COALESCE(Update_priv, " + nullSentinelSQL + ") AS Update_priv, COALESCE(Delete_priv, " + nullSentinelSQL + ") AS Delete_priv, COALESCE(Create_priv, " + nullSentinelSQL + ") AS Create_priv, COALESCE(Drop_priv, " + nullSentinelSQL + ") AS Drop_priv, COALESCE(Reload_priv, " + nullSentinelSQL + ") AS Reload_priv, COALESCE(Shutdown_priv, " + nullSentinelSQL + ") AS Shutdown_priv, COALESCE(Process_priv, " + nullSentinelSQL + ") AS Process_priv, COALESCE(File_priv, " + nullSentinelSQL + ") AS File_priv, COALESCE(Grant_priv, " + nullSentinelSQL + ") AS Grant_priv, COALESCE(References_priv, " + nullSentinelSQL + ") AS References_priv, COALESCE(Index_priv, " + nullSentinelSQL + ") AS Index_priv, COALESCE(Alter_priv, " + nullSentinelSQL + ") AS Alter_priv, COALESCE(Show_db_priv, " + nullSentinelSQL + ") AS Show_db_priv, COALESCE(Super_priv, " + nullSentinelSQL + ") AS Super_priv, COALESCE(Create_tmp_table_priv, " + nullSentinelSQL + ") AS Create_tmp_table_priv, COALESCE(Lock_tables_priv, " + nullSentinelSQL + ") AS Lock_tables_priv, COALESCE(Execute_priv, " + nullSentinelSQL + ") AS Execute_priv, COALESCE(Repl_slave_priv, " + nullSentinelSQL + ") AS Repl_slave_priv, COALESCE(Repl_client_priv, " + nullSentinelSQL + ") AS Repl_client_priv, COALESCE(Create_view_priv, " + nullSentinelSQL + ") AS Create_view_priv, COALESCE(Show_view_priv, " + nullSentinelSQL + ") AS Show_view_priv, COALESCE(Create_routine_priv, " + nullSentinelSQL + ") AS Create_routine_priv, COALESCE(Alter_routine_priv, " + nullSentinelSQL + ") AS Alter_routine_priv, COALESCE(Create_user_priv, " + nullSentinelSQL + ") AS Create_user_priv, COALESCE(Event_priv, " + nullSentinelSQL + ") AS Event_priv, COALESCE(Trigger_priv, " + nullSentinelSQL + ") AS Trigger_priv, COALESCE(Create_tablespace_priv, " + nullSentinelSQL + ") AS Create_tablespace_priv FROM mysql.user"
	// pluginStatusQuery is the fixed source plugin_status catalog. Plugin names
	// are matched in Go so the unix-socket preflight never interpolates a
	// caller token into SQL.
	pluginStatusQuery = "SELECT COALESCE(PLUGIN_NAME, " + nullSentinelSQL + ") AS PLUGIN_NAME, COALESCE(PLUGIN_STATUS, " + nullSentinelSQL + ") AS PLUGIN_STATUS FROM information_schema.PLUGINS"
	// passwordColumnQuery is the fixed __password_column schema probe. It
	// intentionally asks only whether the legacy Password column exists; an
	// empty successful result selects authentication_string in Go.
	passwordColumnQuery = "SELECT 1 AS HasPassword FROM information_schema.COLUMNS WHERE table_schema = 'mysql' AND table_name = 'user' AND column_name = 'Password'"
	// defaultUserHost is the pinned user_exists host default.
	defaultUserHost = "localhost"
	// selectVersionQuery is the reader of version: the exact pinned
	// SELECT VERSION() (mysql.py:1027). The pinned module has no
	// `mysql --version` client-binary probe — the version is server-side.
	selectVersionQuery = "SELECT VERSION()"
	// verifyLoginQuery is deliberately constant: the pinned verify_login
	// establishes a connection only, while batch mysql needs a non-interactive
	// fixed statement to complete and report that connection attempt.
	verifyLoginQuery = "SELECT 1"
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

var userInfoColumns = []string{
	"User", "Host", "Select_priv", "Insert_priv", "Update_priv", "Delete_priv",
	"Create_priv", "Drop_priv", "Reload_priv", "Shutdown_priv", "Process_priv",
	"File_priv", "Grant_priv", "References_priv", "Index_priv", "Alter_priv",
	"Show_db_priv", "Super_priv", "Create_tmp_table_priv", "Lock_tables_priv",
	"Execute_priv", "Repl_slave_priv", "Repl_client_priv", "Create_view_priv",
	"Show_view_priv", "Create_routine_priv", "Alter_routine_priv", "Create_user_priv",
	"Event_priv", "Trigger_priv", "Create_tablespace_priv",
}

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
	errMysqlMaintenanceExit    = errors.New("mysql: maintenance run completed nonzero")
	errMysqlUserInfoColumn     = errors.New("mysql.user_info: missing fixed column")
	errMysqlUserPluginColumn   = errors.New("mysql.user_create: missing plugin column")
	errMysqlAccountArgument    = errors.New("mysql: invalid account argument")
	errMysqlAuthPlugin         = errors.New("mysql: unsupported authentication plugin")
	errMysqlPasswordColumn     = errors.New("mysql: unsupported password column")
	errMysqlPasswordChangeExit = errors.New("mysql: password change run completed nonzero")
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
// R9.3 transport: a shell-free, centrally executed mysql command with a
// finite timeout, bounded output, a clean child environment, and the
// connection password as a Redact secret so it never appears in the
// rendered command, captured output, or returned errors. Mutation callers
// use runMysqlSecrets to add statement credentials to the same bounded
// redaction inventory. Cancellation, runas rejection, argv bounds, and
// client-unavailability all fail closed before any Runner invocation; a
// non-zero mysql exit stays compatibility data for read-only callers.
func runMysql(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, extraSecrets ...string) (process.CommandResult, error) {
	return runMysqlResultSecrets(ctx, rt, argv, conn, nil, false, extraSecrets...)
}

// runMysqlSecrets is the mutation-safe transport entry point. Extra secrets
// are statement values that must be redacted even though they are not the
// MYSQL_PWD connection credential.
func runMysqlSecrets(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, secrets ...string) (process.CommandResult, error) {
	return runMysqlResultSecrets(ctx, rt, argv, conn, nil, false, secrets...)
}

// runMysqlPreserve is limited to internal fixed-result parsers. The Runner
// keeps stdout raw only long enough for the caller to match it; command
// displays, stderr, and errors retain the normal redaction inventory.
func runMysqlPreserve(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, extraSecrets ...string) (process.CommandResult, error) {
	return runMysqlResultSecrets(ctx, rt, argv, conn, nil, true, extraSecrets...)
}

func runMysqlPreserveSecrets(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, secrets ...string) (process.CommandResult, error) {
	return runMysqlResultSecrets(ctx, rt, argv, conn, nil, true, secrets...)
}

// runMysqlResult optionally retains raw stdout for the two fixed maintenance
// catalogs only. Runner redaction must be deferred for those reads: identifiers
// can contain the redaction substring. The raw bytes never enter the safe result
// or errors, and are handed to the parser only after all transport checks pass.
func runMysqlResult(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, catalogStdout *[]byte) (process.CommandResult, error) {
	return runMysqlResultSecrets(ctx, rt, argv, conn, catalogStdout, false)
}

func runMysqlResultSecrets(ctx context.Context, rt *runtime.Runtime, argv []string, conn *myConnection, catalogStdout *[]byte, preserveStdout bool, extraSecrets ...string) (process.CommandResult, error) {
	return runMysqlInputResultSecrets(ctx, rt, argv, "", conn, catalogStdout, preserveStdout, extraSecrets...)
}

// runMysqlStatement keeps credential-bearing SQL out of the process argv.
func runMysqlStatement(ctx context.Context, rt *runtime.Runtime, conn *myConnection, statement string, secrets ...string) (process.CommandResult, error) {
	if conn == nil {
		conn = &myConnection{}
	}
	argv := mysqlQueryArgv(conn, "")
	return runMysqlInputResultSecrets(ctx, rt, argv[:len(argv)-1], statement, conn, nil, false, secrets...)
}

func runMysqlInputResultSecrets(ctx context.Context, rt *runtime.Runtime, argv []string, input string, conn *myConnection, catalogStdout *[]byte, preserveStdout bool, extraSecrets ...string) (process.CommandResult, error) {
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

	secrets := make([]string, 0, len(extraSecrets)+1)
	if conn.Password != nil {
		secrets = append(secrets, *conn.Password)
	}
	secrets = secretList(append(secrets, extraSecrets...)...)
	command, err := runtime.CommandWithInputBounded(argv, input)
	if err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	command.Timeout = commandTimeout
	command.MaxStdoutBytes = outputLimit
	command.MaxStderrBytes = outputLimit
	command.Env = mysqlEnvironment(conn)
	command.PreserveStdout = preserveStdout
	if len(secrets) > 0 && catalogStdout == nil {
		command.Redact = secrets
	}
	result := rt.Runner.Run(ctx, command)
	rawStdout := result.Stdout
	outputExceeded := len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit
	// Defend against custom Runners that do not sanitize their own results.
	if !preserveStdout {
		result.Stdout = process.RedactBytes(secrets, result.Stdout)
	}
	result.Stderr = process.RedactBytes(secrets, result.Stderr)
	if result.Err != nil {
		// PreserveStdout is an internal parser-only escape hatch. A failed
		// preserved run must still return a safe result to direct callers.
		if preserveStdout {
			result.Stdout = process.RedactBytes(secrets, result.Stdout)
		}
		result.Err = redactedError(result.Err, secrets...)
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		if preserveStdout {
			result.Stdout = process.RedactBytes(secrets, result.Stdout)
		}
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated || outputExceeded {
		if preserveStdout {
			result.Stdout = process.RedactBytes(secrets, result.Stdout)
		}
		return result, process.ErrOutputLimit
	}
	if preserveStdout && result.ExitCode != 0 {
		// Non-zero results are compatibility data, but their stdout is never
		// a parser input. Keep the returned result safe on this branch too.
		result.Stdout = process.RedactBytes(secrets, result.Stdout)
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
func mysqlQueryRows(ctx context.Context, rt *runtime.Runtime, conn *myConnection, query string, secrets ...string) ([]string, [][]batchField, error) {
	result, err := runMysql(ctx, rt, mysqlQueryArgv(conn, query), conn, secrets...)
	if err != nil {
		return nil, nil, err
	}
	if result.ExitCode > 0 {
		return []string{}, [][]batchField{}, nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	return header, rows, nil
}

func mysqlQueryRowsPreserve(ctx context.Context, rt *runtime.Runtime, conn *myConnection, query string, secrets ...string) ([]string, [][]batchField, error) {
	result, err := runMysqlPreserve(ctx, rt, mysqlQueryArgv(conn, query), conn, secrets...)
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
	return renderUserCatalog(header, rows, err)
}

func userCatalogRaw(ctx context.Context, rt *runtime.Runtime, conn *myConnection, secrets ...string) ([]map[string]any, error) {
	header, rows, err := mysqlQueryRowsPreserve(ctx, rt, conn, userListQuery, secrets...)
	return renderUserCatalog(header, rows, err)
}

func renderUserCatalog(header []string, rows [][]batchField, err error) ([]map[string]any, error) {
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

// userExistsCatalog matches the pinned bare User/Host existence check over
// the fixed user catalog. It intentionally accepts the requested pair only
// as Go values: the SQL sent to mysql is byte-identical for every caller.
func userExistsCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, user, host string, secrets ...string) (bool, error) {
	rows, err := userCatalogRaw(ctx, rt, conn, secrets...)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		userValue, hasUser := row["User"]
		hostValue, hasHost := row["Host"]
		if !hasUser || !hasHost {
			return false, fmt.Errorf("mysql.user_exists: missing column %q or %q", "User", "Host")
		}
		if userValue == user && hostValue == host {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// user_info — salt/modules/mysql.py:1608-1637 @ pinned revision.

// UserInfoArgs are the canonical mysql.user_info arguments. The pinned
// function has no return_password option; StateKit therefore keeps password
// and authentication_string out of the fixed projection rather than adding a
// new secret-returning API.
type UserInfoArgs struct {
	User     string  `statekit:"name=user,required"`
	Host     *string `statekit:"name=host"`
	ConnUser *string `statekit:"name=connection_user"`
	ConnHost *string `statekit:"name=connection_host"`
	ConnPort *string `statekit:"name=connection_port"`
	ConnPass *string `statekit:"name=connection_pass"`
	ConnDB   *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *UserInfoArgs) connection() *myConnection {
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

type userInfoFunc struct{}

func (userInfoFunc) Name() string { return "mysql.user_info" }
func (userInfoFunc) Args() any    { return UserInfoArgs{} }

// userInfoCatalog preserves the pinned result distinction: a nonzero mysql
// exit is the connection/query False shape, a successful missing account is
// None/nil, and a matching row is one fixed map. Malformed output fails
// closed instead of fabricating a partial account record.
func userInfoCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, user, host string) (any, error) {
	result, err := runMysqlPreserve(ctx, rt, mysqlQueryArgv(conn, userInfoQuery), conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	indexes := make(map[string]int, len(header))
	for i, column := range header {
		indexes[column] = i
	}
	userIndex, hasUser := indexes["User"]
	hostIndex, hasHost := indexes["Host"]
	if !hasUser || !hasHost {
		return nil, errMysqlUserInfoColumn
	}
	for _, column := range userInfoColumns {
		if _, ok := indexes[column]; !ok {
			return nil, errMysqlUserInfoColumn
		}
	}
	for _, row := range rows {
		if userIndex >= len(row) || hostIndex >= len(row) {
			return nil, errMysqlUserInfoColumn
		}
		if row[userIndex].null || row[hostIndex].null || row[userIndex].value != user || row[hostIndex].value != host {
			continue
		}
		out := make(map[string]any, len(userInfoColumns))
		for _, column := range userInfoColumns {
			i := indexes[column]
			if i >= len(row) {
				return nil, errMysqlUserInfoColumn
			}
			if mysqlSensitiveUserField(column) {
				continue
			}
			if row[i].null {
				out[column] = nil
			} else {
				out[column] = redactMysqlCatalogValue(conn, row[i].value)
			}
		}
		return out, nil
	}
	return nil, nil
}

func redactMysqlCatalogValue(conn *myConnection, value string) string {
	if conn == nil || conn.Password == nil || *conn.Password == "" {
		return value
	}
	return process.RedactString([]string{*conn.Password}, value)
}

func mysqlSensitiveUserField(column string) bool {
	switch strings.ToLower(column) {
	case "password", "password_hash", "authentication_string", "auth_string", "passwd":
		return true
	default:
		return false
	}
}

func (userInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserInfoArgs](args, "mysql.user_info")
	if err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	return userInfoCatalog(ctx, rt, a.connection(), a.User, host)
}

// mysqlPluginEnabled is the source plugin_status preflight used by both
// unix-socket CREATE USER paths. A row with any non-empty status is the Salt
// truthy result; a missing plugin, nonzero mysql exit, or SQL NULL is false.
func mysqlPluginEnabled(ctx context.Context, rt *runtime.Runtime, conn *myConnection, plugin string, secrets ...string) (bool, error) {
	header, rows, err := mysqlQueryRowsPreserve(ctx, rt, conn, pluginStatusQuery, secrets...)
	if err != nil {
		return false, err
	}
	nameIndex, statusIndex := -1, -1
	for i, column := range header {
		switch column {
		case "PLUGIN_NAME":
			nameIndex = i
		case "PLUGIN_STATUS":
			statusIndex = i
		}
	}
	if nameIndex < 0 || statusIndex < 0 {
		return false, errMysqlUserInfoColumn
	}
	for _, row := range rows {
		if nameIndex >= len(row) || statusIndex >= len(row) || row[nameIndex].null || row[statusIndex].null {
			continue
		}
		if row[nameIndex].value == plugin && row[statusIndex].value != "" {
			return true, nil
		}
	}
	return false, nil
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
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	return userExistsCatalog(ctx, rt, a.connection(), a.User, host)
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
// user_create/user_remove — salt/modules/mysql.py:1749-1889 and
// 2187-2230 @ pinned revision.

// UserCreateArgs mirrors the public user_create signature and the shared
// connection surface. Password values stay pointer-typed so nil (no value)
// remains distinct from an explicitly empty password, matching Salt's
// `is not None` clause selection.
type UserCreateArgs struct {
	User              string  `statekit:"name=user,required"`
	Host              *string `statekit:"name=host"`
	Password          *string `statekit:"name=password"`
	PasswordHash      *string `statekit:"name=password_hash"`
	AllowPasswordless *bool   `statekit:"name=allow_passwordless"`
	UnixSocket        *bool   `statekit:"name=unix_socket"`
	PasswordColumn    *string `statekit:"name=password_column"`
	AuthPlugin        *string `statekit:"name=auth_plugin"`
	ConnUser          *string `statekit:"name=connection_user"`
	ConnHost          *string `statekit:"name=connection_host"`
	ConnPort          *string `statekit:"name=connection_port"`
	ConnPass          *string `statekit:"name=connection_pass"`
	ConnDB            *string `statekit:"name=connection_db"`
	Runas             *string `statekit:"name=runas"`
}

func (a *UserCreateArgs) connection() *myConnection {
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

type userCreateFunc struct{}

func (userCreateFunc) Name() string { return "mysql.user_create" }
func (userCreateFunc) Args() any    { return UserCreateArgs{} }

// UserRemoveArgs mirrors user_remove(user, host="localhost", **connection)
// and keeps the connection credential out of argv through MYSQL_PWD.
type UserRemoveArgs struct {
	User     string  `statekit:"name=user,required"`
	Host     *string `statekit:"name=host"`
	ConnUser *string `statekit:"name=connection_user"`
	ConnHost *string `statekit:"name=connection_host"`
	ConnPort *string `statekit:"name=connection_port"`
	ConnPass *string `statekit:"name=connection_pass"`
	ConnDB   *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *UserRemoveArgs) connection() *myConnection {
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

type userRemoveFunc struct{}

func (userRemoveFunc) Name() string { return "mysql.user_remove" }
func (userRemoveFunc) Args() any    { return UserRemoveArgs{} }

// validAccountPart is intentionally smaller than MySQL's account-name
// grammar: printable UTF-8 remains valid SQL string data, while backslashes,
// NUL, and controls are rejected before any read-only preflight. Rejecting
// backslashes avoids changing account bytes when the server's
// NO_BACKSLASH_ESCAPES mode differs from the mode assumed by a literal.
// The rejection omits the value so embedded secrets cannot enter an error
// message.
func validAccountPart(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char == '\\' || char == 0 || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func accountArgumentError() error { return errMysqlAccountArgument }

// validateMysqlMutationInputs applies the same SQL-literal boundary to
// account parts and credential values. Quotes, percent signs, and valid
// Unicode remain ordinary literal data; backslashes and controls fail closed
// instead of relying on a session sql_mode that the CLI does not pin.
func validateMysqlMutationInputs(user, host string, password, passwordHash *string) error {
	if !validAccountPart(user) || !validAccountPart(host) {
		return accountArgumentError()
	}
	for _, credential := range []*string{password, passwordHash} {
		if credential != nil && !validAccountPart(*credential) {
			return accountArgumentError()
		}
	}
	return nil
}

// mysqlStringLiteral quotes a value for a MySQL string literal without ever
// treating it as SQL. Backslash escapes cover the default MySQL sql_mode;
// doubled quotes retain the standard SQL form. It is used only for fixed
// statements, never for caller-provided query text.
func mysqlStringLiteral(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`''`)
		case 0:
			b.WriteString(`\0`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case 0x1a:
			b.WriteString(`\Z`)
		default:
			b.WriteByte(value[i])
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// mysqlLiteralSecretForms returns every credential spelling that can occur in
// a fixed SQL statement: the raw value, the quote-doubled value, the
// quote-doubled literal, and both forms of the actual mysqlStringLiteral
// renderer (with and without its surrounding quotes). The unquoted renderer
// form matters because Runner errors and server output can expose only the
// literal body while retaining both doubled apostrophes and doubled
// backslashes. The forms are kept even when one contains another because
// Runner errors may quote only part of a statement.
func mysqlLiteralSecretForms(value string) []string {
	doubled := strings.ReplaceAll(value, "'", "''")
	literal := mysqlStringLiteral(value)
	escapedInner := ""
	if len(literal) >= 2 {
		escapedInner = literal[1 : len(literal)-1]
	}
	return []string{value, doubled, "'" + doubled + "'", escapedInner, literal}
}

// mysqlMutationSecretInventory is built before the first version/existence
// preflight. It deliberately includes connection credentials, raw password
// and hash inputs, SQL-escaped forms, and the native verifier forms so every
// preflight, retry, mutation, and post-check uses one complete inventory.
func mysqlMutationSecretInventory(conn *myConnection, password, passwordHash *string) []string {
	values := make([]string, 0, 16)
	if conn != nil && conn.Password != nil {
		values = append(values, *conn.Password)
		if *conn.Password != "" {
			values = append(values, mysqlLiteralSecretForms(*conn.Password)...)
			values = append(values, mysqlLiteralSecretForms(mysqlNativePasswordHash(*conn.Password))...)
		}
	}
	if password != nil {
		values = append(values, mysqlLiteralSecretForms(*password)...)
		nativeHash := mysqlNativePasswordHash(*password)
		values = append(values, mysqlLiteralSecretForms(nativeHash)...)
	}
	if passwordHash != nil {
		values = append(values, mysqlLiteralSecretForms(*passwordHash)...)
	}
	return secretList(values...)
}

// mysqlUserRemoveSecretInventory extends the credential inventory with every
// account spelling that can cross the user_remove transport boundary. The
// fixed User/Host catalog is preserved for matching, so the raw account
// values must remain available to the internal parser while their raw,
// quote-doubled, quoted-literal, and rendered account forms stay redacted on
// errors, stderr, and command displays. The shared inventory also carries the
// connection credential's derived literal forms and is normalized
// longest-first before the first Runner call.
func mysqlUserRemoveSecretInventory(conn *myConnection, user, host string) []string {
	values := mysqlMutationSecretInventory(conn, nil, nil)
	values = append(values, mysqlLiteralSecretForms(user)...)
	values = append(values, mysqlLiteralSecretForms(host)...)
	values = append(values, mysqlAccount(user, host))
	return secretList(values...)
}

// mysqlUserChpassSecretInventory covers every caller-controlled value that can
// cross a user_chpass transport boundary. The fixed catalog reads preserve
// stdout for internal account/plugin matching, so the raw, doubled, quoted,
// account, credential, hash, and connection-password forms must all be in the
// same inventory before the first preflight and on the mutation/flush calls.
func mysqlUserChpassSecretInventory(conn *myConnection, user, host string, password, passwordHash *string) []string {
	values := mysqlMutationSecretInventory(conn, password, passwordHash)
	values = append(values, mysqlLiteralSecretForms(user)...)
	values = append(values, mysqlLiteralSecretForms(host)...)
	values = append(values, mysqlAccount(user, host))
	return secretList(values...)
}

func mysqlAccount(user, host string) string {
	return mysqlStringLiteral(user) + "@" + mysqlStringLiteral(host)
}

func mysqlAuthPlugin(value *string) (string, error) {
	plugin := "mysql_native_password"
	if value != nil {
		plugin = *value
	}
	if plugin == "" {
		return "", errMysqlAuthPlugin
	}
	for i := 0; i < len(plugin); i++ {
		c := plugin[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' {
			return "", errMysqlAuthPlugin
		}
	}
	return plugin, nil
}

func versionAtLeast(version string, wantMajor, wantMinor, wantPatch int) bool {
	version = strings.TrimSpace(version)
	if dash := strings.IndexByte(version, '-'); dash >= 0 {
		version = version[:dash]
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	values := [3]int{}
	for i := 0; i < len(values) && i < len(parts); i++ {
		value, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		values[i] = value
	}
	if values[0] != wantMajor {
		return values[0] > wantMajor
	}
	if values[1] != wantMinor {
		return values[1] > wantMinor
	}
	return values[2] >= wantPatch
}

// mysqlCreateStatement is the fixed clause machine from the pinned
// _mysql_user_create/_mariadb_user_create helpers. It returns ok=false for
// Salt's source-level no-op cases (password required, or localhost required
// by unix_socket), never an arbitrary SQL fragment.
func mysqlCreateStatement(user, host, serverVersion string, password, passwordHash *string, allowPasswordless, unixSocket bool, authPlugin string) (statement string, secrets []string, ok bool) {
	if !validAccountPart(user) || !validAccountPart(host) {
		return "", nil, false
	}
	for _, credential := range []*string{password, passwordHash} {
		if credential != nil && !validAccountPart(*credential) {
			return "", nil, false
		}
	}
	if _, err := mysqlAuthPlugin(&authPlugin); err != nil {
		return "", nil, false
	}
	statement = "CREATE USER " + mysqlAccount(user, host)
	if unixSocket {
		if host != defaultUserHost {
			return "", nil, false
		}
		if strings.Contains(serverVersion, "MariaDB") {
			return statement + " IDENTIFIED VIA unix_socket", nil, true
		}
		return statement + " IDENTIFIED WITH auth_socket", nil, true
	}
	if allowPasswordless {
		// Salt treats allow_passwordless as an explicit bare-account mode;
		// even supplied password material is ignored by the CREATE clause.
		return statement, nil, true
	}
	if password != nil {
		literal := mysqlStringLiteral(*password)
		secrets = mysqlLiteralSecretForms(*password)
		if strings.Contains(serverVersion, "MariaDB") || !versionAtLeast(serverVersion, 8, 0, 11) {
			return statement + " IDENTIFIED BY " + literal, secrets, true
		}
		return statement + " IDENTIFIED WITH " + authPlugin + " BY " + literal, secrets, true
	}
	if passwordHash != nil {
		literal := mysqlStringLiteral(*passwordHash)
		secrets = mysqlLiteralSecretForms(*passwordHash)
		if strings.Contains(serverVersion, "MariaDB") || !versionAtLeast(serverVersion, 8, 0, 11) {
			return statement + " IDENTIFIED BY PASSWORD " + literal, secrets, true
		}
		return statement + " IDENTIFIED WITH " + authPlugin + " AS " + literal, secrets, true
	}
	return "", nil, false
}

// mysqlChangePasswordStatement is the fixed clause machine from the pinned
// _mysql_user_chpass/_mariadb_user_chpass helpers. Caller values are SQL
// literals only; plugin and legacy-column positions are allowlisted because
// mysql's CLI has no bound-parameter API. Password takes precedence over a
// hash even when it is explicitly empty, matching the source's `is not None`
// branches. The source's unsafe backslash/control policy is enforced before
// this builder is reached.
func mysqlChangePasswordStatement(user, host, serverVersion string, password, passwordHash *string, allowPasswordless, unixSocket bool, passwordColumn, authPlugin string) (statement string, secrets []string, ok bool) {
	if !validAccountPart(user) || !validAccountPart(host) {
		return "", nil, false
	}
	for _, credential := range []*string{password, passwordHash} {
		if credential != nil && !validAccountPart(*credential) {
			return "", nil, false
		}
	}
	column, err := mysqlPasswordColumn(&passwordColumn)
	if err != nil || column == "" {
		return "", nil, false
	}
	passwordColumn = column
	plugin, err := mysqlAuthPlugin(&authPlugin)
	if err != nil {
		return "", nil, false
	}

	passwordSQL := "''"
	if password != nil {
		literal := mysqlStringLiteral(*password)
		secrets = append(secrets, mysqlLiteralSecretForms(*password)...)
		if strings.Contains(serverVersion, "MariaDB") || !versionAtLeast(serverVersion, 8, 0, 11) {
			passwordSQL = "PASSWORD(" + literal + ")"
		} else {
			passwordSQL = literal
		}
	} else if passwordHash != nil {
		passwordSQL = mysqlStringLiteral(*passwordHash)
		secrets = append(secrets, mysqlLiteralSecretForms(*passwordHash)...)
	} else if !allowPasswordless {
		return "", nil, false
	}

	account := mysqlAccount(user, host)
	where := " WHERE User=" + mysqlStringLiteral(user) + " AND Host = " + mysqlStringLiteral(host) + ";"
	if allowPasswordless && unixSocket {
		if host != defaultUserHost {
			// A socket account is meaningful only for localhost. Unlike the
			// pinned logger-only branch, the CLI port fails closed rather than
			// silently applying the ordinary password clause to another host.
			return "", nil, false
		}
		if strings.Contains(serverVersion, "MariaDB") {
			return "UPDATE mysql.user SET " + passwordColumn + "=" + passwordSQL + ", plugin=" + mysqlStringLiteral("unix_socket") + where, secrets, true
		}
		if versionAtLeast(serverVersion, 8, 0, 11) {
			return "ALTER USER " + account + " IDENTIFIED WITH auth_socket AS " + mysqlStringLiteral(user) + ";", secrets, true
		}
		return "UPDATE mysql.user SET " + passwordColumn + "=" + passwordSQL + ", plugin=" + mysqlStringLiteral("auth_socket") + where, secrets, true
	}

	if strings.Contains(serverVersion, "MariaDB") {
		if versionAtLeast(serverVersion, 10, 4, 0) {
			return "ALTER USER " + account + " IDENTIFIED VIA " + plugin + " USING " + passwordSQL, secrets, true
		}
		return "UPDATE mysql.user SET " + passwordColumn + "=" + passwordSQL + where, secrets, true
	}
	if versionAtLeast(serverVersion, 8, 0, 11) {
		statement = "ALTER USER " + account + " IDENTIFIED WITH " + plugin
		if password != nil {
			statement += " BY " + passwordSQL
		} else if passwordHash != nil {
			statement += " AS " + passwordSQL
		} else {
			statement += " "
		}
		if password != nil || passwordHash != nil {
			statement += ";"
		}
		return statement, secrets, true
	}
	return "UPDATE mysql.user SET " + passwordColumn + "=" + passwordSQL + where, secrets, true
}

func mysqlPasswordColumn(requested *string) (string, error) {
	if requested != nil && *requested != "" {
		switch *requested {
		case "Password", "authentication_string":
			return *requested, nil
		default:
			return "", errMysqlPasswordColumn
		}
	}
	return "", nil
}

// mysqlResolvePasswordColumn mirrors Salt's __password_column probe without
// interpolating a caller column name. A failed connection returns the pinned
// legacy fallback Password; a successful empty schema result selects the
// modern authentication_string column.
func mysqlResolvePasswordColumn(ctx context.Context, rt *runtime.Runtime, conn *myConnection, requested *string, secrets ...string) (string, error) {
	if column, err := mysqlPasswordColumn(requested); err != nil || column != "" {
		return column, err
	}
	result, err := runMysqlPreserveSecrets(ctx, rt, mysqlQueryArgv(conn, passwordColumnQuery), conn, secrets...)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "Password", nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	if len(header) > 0 && len(rows) > 0 {
		return "Password", nil
	}
	return "authentication_string", nil
}

// mysqlNativePasswordHash is the legacy mysql_native_password verifier that
// the pinned user_exists path computes before comparing a modern account row.
// SHA-1 here is a compatibility algorithm selected by the MySQL plugin, not a
// new password-hashing policy.
func mysqlNativePasswordHash(password string) string {
	first := sha1.Sum([]byte(password))
	second := sha1.Sum(first[:])
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

func mysqlVerificationSucceeded(rows [][]batchField) bool {
	for _, row := range rows {
		if len(row) > 0 && !row[0].null && row[0].value == "1" {
			return true
		}
	}
	return false
}

// mysqlAccountPluginCatalog performs the post-create existence/plugin check
// over a fixed mysql.user projection. A missing or NULL plugin is treated as
// an unsupported/default plugin: existence is still observable, but no native
// password comparison is attempted.
func mysqlAccountPluginCatalog(ctx context.Context, rt *runtime.Runtime, conn *myConnection, user, host string, secrets ...string) (bool, string, error) {
	result, err := runMysqlPreserve(ctx, rt, mysqlQueryArgv(conn, userPluginQuery), conn, secrets...)
	if err != nil {
		return false, "", err
	}
	if result.ExitCode != 0 {
		return false, "", nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	userIndex, hostIndex, pluginIndex := -1, -1, -1
	for i, column := range header {
		switch strings.ToLower(column) {
		case "user":
			userIndex = i
		case "host":
			hostIndex = i
		case "plugin":
			pluginIndex = i
		}
	}
	if userIndex < 0 || hostIndex < 0 || pluginIndex < 0 {
		return false, "", errMysqlUserPluginColumn
	}
	for _, row := range rows {
		if userIndex >= len(row) || hostIndex >= len(row) || pluginIndex >= len(row) {
			return false, "", errMysqlUserPluginColumn
		}
		if row[userIndex].null || row[hostIndex].null || row[userIndex].value != user || row[hostIndex].value != host {
			continue
		}
		if row[pluginIndex].null {
			return true, "", nil
		}
		return true, row[pluginIndex].value, nil
	}
	return false, "", nil
}

// userExistsAfterCreate keeps the pinned post-create credential checks while
// remaining CLI-safe. The SQL shape is fixed; only the account literals and
// the source-approved password comparison value are added, and all of those
// values are redacted from command/error surfaces.
func userExistsAfterCreate(ctx context.Context, rt *runtime.Runtime, conn *myConnection, user, host, serverVersion, passwordColumn string, password, passwordHash *string, authPlugin string, secrets ...string) (bool, error) {
	exists, actualPlugin, err := mysqlAccountPluginCatalog(ctx, rt, conn, user, host, secrets...)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	// The native verifier is only meaningful for the actual plugin returned by
	// mysql.user. auth_socket, caching_sha2_password, and unknown/default
	// plugins are source-compatible existence/plugin successes; comparing a
	// mysql_native_password hash for them would fabricate a verification.
	if (!pointerTruthy(password) && !pointerTruthy(passwordHash)) || !strings.EqualFold(actualPlugin, "mysql_native_password") {
		return true, nil
	}
	statement := "SELECT 1 AS Verified FROM mysql.user WHERE User = " + mysqlStringLiteral(user) + " AND Host = " + mysqlStringLiteral(host)
	verificationSecrets := append([]string(nil), secrets...)
	if pointerTruthy(password) {
		literalPassword := mysqlStringLiteral(*password)
		verificationSecrets = append(verificationSecrets, mysqlLiteralSecretForms(*password)...)
		if strings.Contains(serverVersion, "MariaDB") || !versionAtLeast(serverVersion, 8, 0, 11) {
			statement += " AND " + passwordColumn + " = PASSWORD(" + literalPassword + ")"
		} else {
			hash := mysqlNativePasswordHash(*password)
			statement += " AND " + passwordColumn + " = " + mysqlStringLiteral(hash)
			verificationSecrets = append(verificationSecrets, mysqlLiteralSecretForms(hash)...)
		}
	} else {
		literalHash := mysqlStringLiteral(*passwordHash)
		statement += " AND " + passwordColumn + " = " + literalHash
		verificationSecrets = append(verificationSecrets, mysqlLiteralSecretForms(*passwordHash)...)
	}
	result, err := runMysqlPreserveSecrets(ctx, rt, mysqlQueryArgv(conn, statement), conn, verificationSecrets...)
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	_, rows := parseBatchRows(string(result.Stdout))
	return mysqlVerificationSucceeded(rows), nil
}

func (userCreateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserCreateArgs](args, "mysql.user_create")
	if err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	if err := validateMysqlMutationInputs(a.User, host, a.Password, a.PasswordHash); err != nil {
		return nil, err
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	plugin := "mysql_native_password"
	if !pointerBool(a.UnixSocket) && !pointerBool(a.AllowPasswordless) && (a.Password != nil || a.PasswordHash != nil) {
		plugin, err = mysqlAuthPlugin(a.AuthPlugin)
		if err != nil {
			return nil, err
		}
	}
	conn := a.connection()
	// Build this before the first version probe. The same complete inventory is
	// passed through every preflight, the connection-password retry, CREATE,
	// and the post-check; no credential-bearing error can escape an early call.
	secretInventory := mysqlMutationSecretInventory(conn, a.Password, a.PasswordHash)
	effectiveConn := conn
	serverVersion, err := mysqlVersionPreserve(ctx, rt, effectiveConn, secretInventory...)
	if err != nil {
		return nil, err
	}
	if serverVersion == "" && pointerTruthy(a.Password) {
		retry := *conn
		retry.Password = a.Password
		effectiveConn = &retry
		serverVersion, err = mysqlVersionPreserve(ctx, rt, effectiveConn, secretInventory...)
		if err != nil {
			return nil, err
		}
		if serverVersion == "" {
			return false, nil
		}
	}
	exists, err := userExistsCatalog(ctx, rt, effectiveConn, a.User, host, secretInventory...)
	if err != nil {
		return nil, err
	}
	if exists {
		return false, nil
	}
	passwordColumn, err := mysqlResolvePasswordColumn(ctx, rt, effectiveConn, a.PasswordColumn, secretInventory...)
	if err != nil {
		return nil, err
	}
	if pointerBool(a.UnixSocket) {
		pluginName := "auth_socket"
		if strings.Contains(serverVersion, "MariaDB") {
			pluginName = "unix_socket"
		}
		enabled, err := mysqlPluginEnabled(ctx, rt, effectiveConn, pluginName, secretInventory...)
		if err != nil {
			return nil, err
		}
		if !enabled {
			return false, nil
		}
	}
	statement, statementSecrets, ok := mysqlCreateStatement(
		a.User, host, serverVersion, a.Password, a.PasswordHash,
		pointerBool(a.AllowPasswordless), pointerBool(a.UnixSocket), plugin,
	)
	if !ok {
		return false, nil
	}
	mutationSecrets := append(append([]string(nil), secretInventory...), statementSecrets...)
	result, err := runMysqlSecrets(ctx, rt, mysqlQueryArgv(effectiveConn, statement), effectiveConn, mutationSecrets...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	postPassword, postPasswordHash := a.Password, a.PasswordHash
	if pointerBool(a.AllowPasswordless) || pointerBool(a.UnixSocket) {
		// The source clause is bare/plugin-only in these modes, even when
		// credential arguments were supplied and ignored by CREATE.
		postPassword, postPasswordHash = nil, nil
	}
	exists, err = userExistsAfterCreate(ctx, rt, effectiveConn, a.User, host, serverVersion, passwordColumn, postPassword, postPasswordHash, plugin, secretInventory...)
	if err != nil {
		return nil, err
	}
	return exists, nil
}

// UserChpassArgs mirrors user_chpass(user, host="localhost", password=None,
// password_hash=None, allow_passwordless=False, unix_socket=None,
// password_column=None, **connection_args). The connection credential is
// separate from the password being written and remains out of argv.
type UserChpassArgs struct {
	User              string  `statekit:"name=user,required"`
	Host              *string `statekit:"name=host"`
	Password          *string `statekit:"name=password"`
	PasswordHash      *string `statekit:"name=password_hash"`
	AllowPasswordless *bool   `statekit:"name=allow_passwordless"`
	UnixSocket        *bool   `statekit:"name=unix_socket"`
	PasswordColumn    *string `statekit:"name=password_column"`
	ConnUser          *string `statekit:"name=connection_user"`
	ConnHost          *string `statekit:"name=connection_host"`
	ConnPort          *string `statekit:"name=connection_port"`
	ConnPass          *string `statekit:"name=connection_pass"`
	ConnDB            *string `statekit:"name=connection_db"`
	Runas             *string `statekit:"name=runas"`
}

func (a *UserChpassArgs) connection() *myConnection {
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

type userChpassFunc struct{}

func (userChpassFunc) Name() string { return "mysql.user_chpass" }
func (userChpassFunc) Args() any    { return UserChpassArgs{} }

func (userChpassFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserChpassArgs](args, "mysql.user_chpass")
	if err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	if err := validateMysqlMutationInputs(a.User, host, a.Password, a.PasswordHash); err != nil {
		return nil, err
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	if _, err := mysqlPasswordColumn(a.PasswordColumn); err != nil {
		return nil, err
	}

	conn := a.connection()
	secretInventory := mysqlUserChpassSecretInventory(conn, a.User, host, a.Password, a.PasswordHash)
	effectiveConn := conn
	serverVersion, err := mysqlVersionPreserve(ctx, rt, effectiveConn, secretInventory...)
	if err != nil {
		return nil, err
	}
	if serverVersion == "" && pointerTruthy(a.Password) {
		// Match the source recovery path used when the account password was
		// changed by the same state run: retry the connection with the new
		// password, without mutating the caller's argument object.
		retry := *conn
		retry.Password = a.Password
		effectiveConn = &retry
		serverVersion, err = mysqlVersionPreserve(ctx, rt, effectiveConn, secretInventory...)
		if err != nil {
			return nil, err
		}
		if serverVersion == "" {
			return false, nil
		}
	}

	exists, err := userExistsCatalog(ctx, rt, effectiveConn, a.User, host, secretInventory...)
	if err != nil {
		return nil, err
	}
	if !exists {
		return false, nil
	}

	passwordColumn, err := mysqlResolvePasswordColumn(ctx, rt, effectiveConn, a.PasswordColumn, secretInventory...)
	if err != nil {
		return nil, err
	}
	exists, authPlugin, err := mysqlAccountPluginCatalog(ctx, rt, effectiveConn, a.User, host, secretInventory...)
	if err != nil {
		return nil, err
	}
	if !exists {
		return false, nil
	}
	if authPlugin == "" {
		// __get_auth_plugin defaults a missing/NULL row to the native plugin.
		authPlugin = "mysql_native_password"
	}
	if _, err := mysqlAuthPlugin(&authPlugin); err != nil {
		return nil, err
	}

	allowPasswordless := pointerBool(a.AllowPasswordless)
	unixSocket := pointerBool(a.UnixSocket)
	if allowPasswordless && unixSocket {
		plugin := "auth_socket"
		if strings.Contains(serverVersion, "MariaDB") {
			plugin = "unix_socket"
		}
		enabled, err := mysqlPluginEnabled(ctx, rt, effectiveConn, plugin, secretInventory...)
		if err != nil {
			return nil, err
		}
		if !enabled {
			return false, nil
		}
	}

	statement, statementSecrets, ok := mysqlChangePasswordStatement(
		a.User, host, serverVersion, a.Password, a.PasswordHash,
		allowPasswordless, unixSocket, passwordColumn, authPlugin,
	)
	if !ok {
		return false, nil
	}
	mutationSecrets := append(append([]string(nil), secretInventory...), statementSecrets...)
	// A password change performed through the account used by the current
	// connection must keep ALTER/UPDATE and FLUSH on one server session. A
	// second mysql process would authenticate with the old MYSQL_PWD after the
	// mutation and can therefore fail after already changing the password.
	selfPasswordChange := effectiveConn != nil && effectiveConn.User != nil &&
		*effectiveConn.User == a.User && !allowPasswordless && !unixSocket &&
		(a.Password != nil || a.PasswordHash != nil)
	if selfPasswordChange {
		if !strings.HasSuffix(statement, ";") {
			statement += ";"
		}
		statement += " FLUSH PRIVILEGES;"
		result, err := runMysqlStatement(ctx, rt, effectiveConn, statement, mutationSecrets...)
		if err != nil {
			return nil, err
		}
		if result.ExitCode != 0 {
			return false, nil
		}
		return true, nil
	}
	result, err := runMysqlStatement(ctx, rt, effectiveConn, statement, mutationSecrets...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}

	// Salt flushes privileges after a successful change. On the modern
	// branches it treats the statement result as successful regardless of the
	// affected-row count; the CLI can preserve that bool shape but cannot infer
	// an UPDATE rowcount on old servers. A failed flush is an execution error,
	// not a fabricated success.
	compareVersion := versionAtLeast(serverVersion, 8, 0, 11)
	if strings.Contains(serverVersion, "MariaDB") {
		compareVersion = versionAtLeast(serverVersion, 10, 4, 0)
	}
	if compareVersion || result.ExitCode == 0 {
		flush, flushErr := runMysqlSecrets(ctx, rt, mysqlQueryArgv(effectiveConn, "FLUSH PRIVILEGES;"), effectiveConn, mutationSecrets...)
		if flushErr != nil {
			return nil, flushErr
		}
		if flush.ExitCode != 0 {
			return nil, errMysqlPasswordChangeExit
		}
		return true, nil
	}
	return false, nil
}

// VerifyLoginArgs maps verify_login's connection surface. ConnUser and
// ConnPass are accepted for source-compatible **connection_args parsing but
// deliberately ignored: verify_login always overrides both with User and
// Password before connecting.
type VerifyLoginArgs struct {
	User     string  `statekit:"name=user,required"`
	Password *string `statekit:"name=password"`
	ConnUser *string `statekit:"name=connection_user"`
	ConnHost *string `statekit:"name=connection_host"`
	ConnPort *string `statekit:"name=connection_port"`
	ConnPass *string `statekit:"name=connection_pass"`
	ConnDB   *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *VerifyLoginArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return &myConnection{
		Host:  a.ConnHost,
		Port:  a.ConnPort,
		DB:    a.ConnDB,
		Runas: a.Runas,
	}
}

type verifyLoginFunc struct{}

func (verifyLoginFunc) Name() string { return "mysql.verify_login" }
func (verifyLoginFunc) Args() any    { return VerifyLoginArgs{} }

func (verifyLoginFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[VerifyLoginArgs](args, "mysql.verify_login")
	if err != nil {
		return nil, err
	}
	if a.Password != nil && strings.IndexByte(*a.Password, 0) >= 0 {
		return nil, errMysqlInvalidArgument
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	conn := a.connection()
	login := *conn
	login.User = &a.User
	login.Password = a.Password
	secrets := []string(nil)
	if a.Password != nil {
		secrets = mysqlLiteralSecretForms(*a.Password)
	}
	result, err := runMysqlSecrets(ctx, rt, mysqlQueryArgv(&login, verifyLoginQuery), &login, secrets...)
	if err != nil {
		return nil, err
	}
	// MySQLdb's _connect returns a boolean-compatible success/failure for
	// connection errors. The fixed SELECT is only the non-interactive CLI
	// completion mechanism; its exit status is the same bool surface.
	return result.ExitCode == 0, nil
}

func (userRemoveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserRemoveArgs](args, "mysql.user_remove")
	if err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	if !validAccountPart(a.User) || !validAccountPart(host) {
		return nil, accountArgumentError()
	}
	if err := rejectRunas(a.Runas); err != nil {
		return nil, err
	}
	conn := a.connection()
	// Build the complete account/credential inventory before the first
	// preflight. User or Host may equal the connection password, and an
	// apostrophe in either value is doubled in the DROP account literal. The
	// same inventory must reach the preserved catalog reads, DROP, and
	// post-check so no raw or escaped form can escape on an early failure.
	secretInventory := mysqlUserRemoveSecretInventory(conn, a.User, host)
	exists, err := userExistsCatalog(ctx, rt, conn, a.User, host, secretInventory...)
	if err != nil {
		return nil, err
	}
	if !exists {
		return false, nil
	}
	statement := "DROP USER IF EXISTS " + mysqlAccount(a.User, host)
	result, err := runMysqlSecrets(ctx, rt, mysqlQueryArgv(conn, statement), conn, secretInventory...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	exists, err = userExistsCatalog(ctx, rt, conn, a.User, host, secretInventory...)
	if err != nil {
		return nil, err
	}
	return !exists, nil
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

func mysqlVersionPreserve(ctx context.Context, rt *runtime.Runtime, conn *myConnection, secrets ...string) (string, error) {
	_, rows, err := mysqlQueryRowsPreserve(ctx, rt, conn, selectVersionQuery, secrets...)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
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
// grant_add, grant_exists, grant_revoke — salt/modules/mysql.py:2322-2761
// @ pinned revision (R9.3f).

// splitGrantSpecs separates comma-delimited privileges without splitting a
// column list. The source accepts column-bearing grants such as
// SELECT(col_a, col_b); the fixed statement boundary below accepts only that
// grammar, never arbitrary text.
func splitGrantSpecs(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errMysqlGrant
	}
	parts := make([]string, 0, 4)
	start, depth := 0, 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '(':
			depth++
			if depth > 1 {
				return nil, errMysqlGrant
			}
		case ')':
			if depth == 0 {
				return nil, errMysqlGrant
			}
			depth--
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(value[start:i])
				if part == "" {
					return nil, errMysqlGrant
				}
				parts = append(parts, part)
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, errMysqlGrant
	}
	last := strings.TrimSpace(value[start:])
	if last == "" {
		return nil, errMysqlGrant
	}
	return append(parts, last), nil
}

func validGrantColumn(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	if value[0] == '`' {
		if len(value) < 2 || value[len(value)-1] != '`' {
			return false
		}
		for i := 1; i < len(value)-1; i++ {
			if value[i] == 0 || unicode.IsControl(rune(value[i])) {
				return false
			}
			if value[i] == '`' {
				if i+1 >= len(value)-1 || value[i+1] != '`' {
					return false
				}
				i++
			}
		}
		return true
	}
	for _, char := range value {
		if !(unicode.IsLetter(char) || unicode.IsDigit(char) || char == '_' || char == '$') {
			return false
		}
	}
	return true
}

func normalizeGrantSpec(value string) (string, error) {
	value = strings.TrimSpace(value)
	open := strings.IndexByte(value, '(')
	if open < 0 {
		name := strings.ToUpper(value)
		if _, ok := mysqlGrantPrivileges[name]; !ok {
			return "", errMysqlGrant
		}
		return name, nil
	}
	if !strings.HasSuffix(value, ")") || strings.Count(value[open:], "(") != 1 {
		return "", errMysqlGrant
	}
	name := strings.TrimSpace(value[:open])
	if _, ok := mysqlGrantPrivileges[strings.ToUpper(name)]; !ok {
		return "", errMysqlGrant
	}
	columnsText := value[open+1 : len(value)-1]
	columns := strings.Split(columnsText, ",")
	for i := range columns {
		columns[i] = strings.TrimSpace(columns[i])
		if !validGrantColumn(columns[i]) {
			return "", errMysqlGrant
		}
	}
	return strings.ToUpper(name) + "(" + strings.ToUpper(strings.Join(columns, ", ")) + ")", nil
}

// normalizeGrantForAdd ports __grant_generate's uppercasing and comma
// spacing. normalizeGrantForRevoke deliberately keeps the caller's spelling
// and spacing after validation, matching __grant_normalize's REVOKE path.
func normalizeGrantForAdd(value string) (string, error) {
	parts, err := splitGrantSpecs(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(parts) == 1 && strings.EqualFold(strings.TrimSpace(value), "ALL") {
		return "ALL PRIVILEGES", nil
	}
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		one, err := normalizeGrantSpec(part)
		if err != nil {
			return "", err
		}
		normalized = append(normalized, one)
	}
	return strings.Join(normalized, ", "), nil
}

func normalizeGrantForRevoke(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if strings.EqualFold(trimmed, "ALL") {
		return "ALL PRIVILEGES", nil
	}
	parts, err := splitGrantSpecs(value)
	if err != nil {
		return "", err
	}
	for _, part := range parts {
		if _, err := normalizeGrantSpec(part); err != nil {
			return "", err
		}
	}
	return value, nil
}

func validGrantIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char == 0 || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validRawGrantIdentifier(value string) bool {
	if value == "*" {
		return true
	}
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if !(unicode.IsLetter(char) || unicode.IsDigit(char) || char == '_' || char == '$' || char == '%') {
			return false
		}
	}
	return true
}

func renderGrantIdentifier(value string, forGrants bool) string {
	return strings.ReplaceAll(quoteIdentifier(value, forGrants), "%%", "%")
}

func grantObject(database, table string, escape, revoke bool) (string, error) {
	if !validGrantIdentifier(database) || !validGrantIdentifier(table) {
		return "", errMysqlGrantIdentifier
	}
	if revoke {
		// The pinned grant_revoke implementation always quotes the object
		// positions; its escape argument is accepted but unused.
		databasePart := database
		if databasePart != "*" {
			databasePart = renderGrantIdentifier(databasePart, table == "*")
		}
		tablePart := table
		if tablePart != "*" {
			tablePart = renderGrantIdentifier(tablePart, false)
		}
		return databasePart + "." + tablePart, nil
	}
	if !escape {
		if !validRawGrantIdentifier(database) || !validRawGrantIdentifier(table) {
			return "", errMysqlGrantIdentifier
		}
		return database + "." + table, nil
	}
	databasePart := database
	if databasePart != "*" {
		databasePart = renderGrantIdentifier(databasePart, table == "*")
	}
	tablePart := table
	if tablePart != "*" {
		tablePart = renderGrantIdentifier(tablePart, false)
	}
	return databasePart + "." + tablePart, nil
}

func grantOptionValue(value *bool) bool { return value != nil && *value }

func grantHostValue(value *string) string {
	if value == nil {
		return defaultUserHost
	}
	return *value
}

func grantEscapeValue(value *bool) bool {
	if value == nil {
		return true
	}
	return *value
}

func validateGrantInputBounds(user, host, grant, database, table string, extra ...string) error {
	total := 0
	values := []string{user, host, grant, database, table}
	values = append(values, extra...)
	for _, value := range values {
		if len(value) > runtime.MaxCommandInputBytes-total {
			return runtime.ErrCommandInputLimit
		}
		total += len(value)
	}
	return nil
}

func grantContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func splitGrantDatabase(value string) (string, string, error) {
	separator := strings.LastIndexByte(value, '.')
	if separator <= 0 || separator >= len(value)-1 {
		return "", "", errMysqlGrantIdentifier
	}
	database, table := value[:separator], value[separator+1:]
	if !validGrantIdentifier(database) || !validGrantIdentifier(table) {
		return "", "", errMysqlGrantIdentifier
	}
	return database, table, nil
}

// normalizeGrantSSLOption ports the pinned list-of-single-entry-dicts DSL.
// Only the fixed REQUIRE keywords reach SQL; parameter values are SQL string
// literals, never caller-provided SQL fragments. The second return value is
// the raw/escaped forms needed by the grant redaction inventory.
func normalizeGrantSSLOption(value any) (string, []string, error) {
	if value == nil {
		return "", nil, nil
	}
	items := make([]any, 0)
	switch typed := value.(type) {
	case []any:
		items = typed
	case []map[string]any:
		for _, item := range typed {
			items = append(items, item)
		}
	case []map[string]string:
		for _, item := range typed {
			converted := make(map[string]any, len(item))
			for key, itemValue := range item {
				converted[key] = itemValue
			}
			items = append(items, converted)
		}
	case bool, string:
		// The pinned function only interprets a list. Keep the accepted scalar
		// forms as the false/no-clause compatibility path used by CLI flags.
		return "", nil, nil
	default:
		return "", nil, errMysqlGrant
	}
	clauses := make([]string, 0, len(items))
	secrets := make([]string, 0, len(items)*3)
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 1 {
			return "", nil, errMysqlGrant
		}
		var key string
		var rawValue any
		for candidate, candidateValue := range entry {
			key, rawValue = strings.ToUpper(strings.TrimSpace(candidate)), candidateValue
		}
		switch key {
		case "CIPHER", "ISSUER", "SUBJECT":
			text, ok := rawValue.(string)
			if !ok || !validAccountPart(text) {
				return "", nil, errMysqlGrant
			}
			clauses = append(clauses, key+" "+mysqlStringLiteral(text))
			secrets = append(secrets, mysqlLiteralSecretForms(text)...)
		case "SSL", "X509":
			truthy := false
			switch typedValue := rawValue.(type) {
			case bool:
				truthy = typedValue
			case string:
				truthy = typedValue != ""
			default:
				truthy = rawValue != nil
			}
			if truthy {
				clauses = append(clauses, key)
			}
		default:
			return "", nil, errMysqlGrant
		}
		secrets = append(secrets, key)
		if rawText, ok := rawValue.(string); ok {
			secrets = append(secrets, mysqlLiteralSecretForms(rawText)...)
		}
	}
	if len(clauses) == 0 {
		return "", secrets, nil
	}
	return " REQUIRE " + strings.Join(clauses, " AND "), secrets, nil
}

func grantStatementSSL(grant, database, table, user, host string, grantOption bool, escape bool, sslOption any) (string, []string, error) {
	if err := validateGrantInputBounds(user, host, grant, database, table); err != nil {
		return "", nil, err
	}
	if !validAccountPart(user) || !validAccountPart(host) {
		return "", nil, errMysqlAccountArgument
	}
	normalized, err := normalizeGrantForAdd(grant)
	if err != nil {
		return "", nil, err
	}
	object, err := grantObject(database, table, escape, false)
	if err != nil {
		return "", nil, err
	}
	sslClause, sslSecrets, err := normalizeGrantSSLOption(sslOption)
	if err != nil {
		return "", nil, err
	}
	if err := validateGrantInputBounds(user, host, grant, database, table, sslClause); err != nil {
		return "", nil, err
	}
	statement := "GRANT " + normalized + " ON " + object + " TO " + mysqlAccount(user, host)
	statement += sslClause
	if grantOption {
		statement += " WITH GRANT OPTION"
	}
	return statement, sslSecrets, nil
}

func revokeStatement(grant, database, table, user, host string, grantOption bool, escape bool) (string, error) {
	if err := validateGrantInputBounds(user, host, grant, database, table); err != nil {
		return "", err
	}
	if !validAccountPart(user) || !validAccountPart(host) {
		return "", errMysqlAccountArgument
	}
	normalized, err := normalizeGrantForRevoke(grant)
	if err != nil {
		return "", err
	}
	if grantOption {
		normalized += ", GRANT OPTION"
	}
	object, err := grantObject(database, table, escape, true)
	if err != nil {
		return "", err
	}
	return "REVOKE " + normalized + " ON " + object + " FROM " + mysqlAccount(user, host) + ";", nil
}

func grantSecretInventory(conn *myConnection, user, host, grant, database, table string, sslOptions ...any) []string {
	values := make([]string, 0, 64)
	add := func(value string) {
		if value == "" {
			return
		}
		values = append(values, value)
	}
	addLiteral := func(value string) {
		if value == "" {
			return
		}
		values = append(values, mysqlLiteralSecretForms(value)...)
		add(mysqlStringLiteral(value))
	}
	addIdentifier := func(value string, forGrants bool) {
		if value == "" {
			return
		}
		add(value)
		addLiteral(value)
		add(renderGrantIdentifier(value, forGrants))
		add(quoteIdentifier(value, forGrants))
	}
	addAccount := func(accountUser, accountHost string) {
		add(accountUser + "@" + accountHost)
		add(mysqlAccount(accountUser, accountHost))
		addLiteral(accountUser)
		addLiteral(accountHost)
	}
	if conn != nil && conn.Password != nil {
		addLiteral(*conn.Password)
		if *conn.Password != "" {
			addLiteral(mysqlNativePasswordHash(*conn.Password))
		}
	}
	addAccount(user, host)
	add(grant)
	add(strings.ToUpper(grant))
	addLiteral(grant)
	if normalized, err := normalizeGrantForAdd(grant); err == nil {
		add(normalized)
		addLiteral(normalized)
	}
	if normalized, err := normalizeGrantForRevoke(grant); err == nil {
		add(normalized)
		add(normalized + ", GRANT OPTION")
	}
	addIdentifier(database, table == "*")
	addIdentifier(table, false)
	addIdentifier(database+"."+table, false)
	add(renderGrantIdentifier(database, table == "*") + "." + renderGrantIdentifier(table, false))
	add(quoteIdentifier(database, table == "*") + "." + quoteIdentifier(table, false))
	if validGrantIdentifier(database) {
		add(renderGrantIdentifier(database, table == "*"))
		add(renderGrantIdentifier(database, false))
	}
	if validGrantIdentifier(table) && table != "*" {
		add(renderGrantIdentifier(table, false))
	}
	for _, option := range sslOptions {
		_, optionSecrets, err := normalizeGrantSSLOption(option)
		if err == nil {
			values = append(values, optionSecrets...)
		}
	}
	return secretList(values...)
}

func grantQuery(user, host string) string {
	return "SHOW GRANTS FOR " + mysqlAccount(user, host)
}

func showGrantStatements(stdout string) ([]string, error) {
	header, rows := parseBatchRows(stdout)
	if len(header) == 0 {
		return []string{}, nil
	}
	statements := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 || row[0].null {
			return nil, errMysqlGrant
		}
		statements = append(statements, row[0].value)
	}
	return statements, nil
}

func validUserGrantsAccountPart(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char == 0 || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// userGrantsSecretInventory covers every caller-controlled spelling that can
// occur in the fixed SHOW GRANTS account expression or in the MYSQL_PWD
// transport. The parser receives preserved stdout, so the inventory is also
// used to redact any credential that happens to overlap an account value in a
// Runner error or non-success stream.
func userGrantsSecretInventory(conn *myConnection, user, host string) []string {
	values := make([]string, 0, 16)
	add := func(value string) {
		if value != "" {
			values = append(values, value)
		}
	}
	addLiteral := func(value string) {
		if value == "" {
			return
		}
		values = append(values, mysqlLiteralSecretForms(value)...)
		add(mysqlStringLiteral(value))
	}
	if conn != nil && conn.Password != nil {
		addLiteral(*conn.Password)
	}
	add(user + "@" + host)
	add(mysqlAccount(user, host))
	addLiteral(user)
	addLiteral(host)
	return secretList(values...)
}

// userGrantsOutputSecrets is deliberately narrower than the command
// inventory: ordinary account names are part of the source return value and
// must stay byte-for-byte intact. Only the connection credential is secret in
// the returned grant list.
func userGrantsOutputSecrets(conn *myConnection) []string {
	if conn == nil || conn.Password == nil || *conn.Password == "" {
		return nil
	}
	values := mysqlLiteralSecretForms(*conn.Password)
	values = append(values, mysqlStringLiteral(*conn.Password))
	return secretList(values...)
}

func redactUserGrantStatement(statement string, secrets []string) string {
	// Preserve the source grant text, but never return a connection credential
	// merely because SHOW GRANTS emitted it in an unexpected unquoted field.
	// RedactBytes is bounded and is a no-op when none of the credential forms
	// occur, so this also covers raw and quote-doubled output safely.
	return string(process.RedactBytes(secrets, []byte(statement)))
}

// normalizeUserGrant ports the pinned user_grants cleanup exactly. SHOW
// GRANTS may place WITH GRANT OPTION after IDENTIFIED BY; the source removes
// the credential clause and appends that option back to the normalized grant.
func normalizeUserGrant(statement string) string {
	normalized := statement
	if cut := strings.Index(statement, " IDENTIFIED BY"); cut >= 0 {
		normalized = statement[:cut]
	}
	if strings.Contains(statement, "WITH GRANT OPTION") &&
		!strings.Contains(normalized, "WITH GRANT OPTION") {
		normalized += " WITH GRANT OPTION"
	}
	return normalized
}

func canonicalGrantPart(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return strings.Trim(value, "'")
	}
	quote := value[0]
	if (quote != '\'' && quote != '`' && quote != '"') || value[len(value)-1] != quote {
		return value
	}
	value = value[1 : len(value)-1]
	value = strings.ReplaceAll(value, string([]byte{quote, quote}), string(quote))
	return value
}

// canonicalGrantObject decodes the object spelling emitted by SHOW GRANTS.
// Backticks are syntax only at the outer delimiter; doubled backticks and the
// grant wildcard escapes are data and must survive canonical comparison.
func canonicalGrantObject(value string) string {
	var out strings.Builder
	quoted := false
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char == '`' {
			if quoted && i+1 < len(value) && value[i+1] == '`' {
				out.WriteByte('`')
				i++
				continue
			}
			quoted = !quoted
			continue
		}
		if quoted && char == '\\' && i+1 < len(value) && (value[i+1] == '_' || value[i+1] == '%') {
			out.WriteByte(value[i+1])
			i++
			continue
		}
		out.WriteByte(char)
	}
	return strings.TrimSpace(out.String())
}

func canonicalGrantToken(value, serverVersion string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !strings.Contains(strings.ToLower(serverVersion), "mariadb") {
		return value
	}
	if versionAtLeast(serverVersion, 10, 5, 1) && value == "REPLICATION REPLICA" {
		return "REPLICATION SLAVE"
	}
	if versionAtLeast(serverVersion, 10, 5, 2) && value == "REPLICATION CLIENT" {
		return "BINLOG MONITOR"
	}
	if versionAtLeast(serverVersion, 10, 5, 9) && value == "REPLICA MONITOR" {
		return "SLAVE MONITOR"
	}
	return value
}

func canonicalGrantTokens(values []string, serverVersion string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, canonicalGrantToken(value, serverVersion))
	}
	return out
}

// grantListCovers compares concrete privilege tokens.  In particular, a
// literal ALL PRIVILEGES row is not a universal wildcard here: the only
// expansion allowed by the pinned control flow is the explicit global-ALL
// target built from SHOW PRIVILEGES (or its static MySQL fallback).
func grantListCovers(actual, target []string, serverVersion string) bool {
	actualSet := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		actualSet[canonicalGrantToken(value, serverVersion)] = struct{}{}
	}
	targetSet := make(map[string]struct{}, len(target))
	for _, value := range target {
		targetSet[canonicalGrantToken(value, serverVersion)] = struct{}{}
	}
	for value := range targetSet {
		if _, ok := actualSet[value]; !ok {
			return false
		}
	}
	return true
}

// grantHasOptionClause recognizes only an unquoted WITH GRANT OPTION token
// sequence. A quoted account, database, table, or column name containing that
// phrase must not manufacture grant-option state.
func grantHasOptionClause(statement string) bool {
	words := make([]string, 0, 8)
	flush := func(word []byte) {
		if len(word) > 0 {
			words = append(words, strings.ToUpper(string(word)))
		}
	}
	word := make([]byte, 0, 8)
	var quote byte
	for i := 0; i < len(statement); i++ {
		char := statement[i]
		if quote != 0 {
			if char == '\\' && i+1 < len(statement) {
				i++
				continue
			}
			if char == quote {
				if i+1 < len(statement) && statement[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			flush(word)
			word = word[:0]
			quote = char
		default:
			if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || char == '_' {
				word = append(word, char)
				continue
			}
			flush(word)
			word = word[:0]
		}
	}
	flush(word)
	for i := 0; i+2 < len(words); i++ {
		if words[i] == "WITH" && words[i+1] == "GRANT" && words[i+2] == "OPTION" {
			return true
		}
	}
	return false
}

func grantRequestsAll(grant, database, table string) bool {
	if database != "*" || table != "*" {
		return false
	}
	// The pinned source uses ``"ALL" in grant.upper()`` rather than an
	// equality test. Keep that source condition after the object-level gate;
	// normalizeGrantForAdd still validates the complete privilege grammar
	// before any query is issued.
	return strings.Contains(strings.ToUpper(grant), "ALL")
}

func serverAllPrivileges(ctx context.Context, rt *runtime.Runtime, conn *myConnection, secrets ...string) ([]string, error) {
	result, err := runMysqlPreserveSecrets(ctx, rt, mysqlQueryArgv(conn, "SHOW PRIVILEGES"), conn, secrets...)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, nil
	}
	header, rows := parseBatchRows(string(result.Stdout))
	if len(header) == 0 {
		return nil, nil
	}
	privileges := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 || row[0].null || strings.TrimSpace(row[0].value) == "" {
			continue
		}
		name := strings.ToUpper(strings.TrimSpace(row[0].value))
		switch name {
		case "USAGE", "GRANT OPTION", "PROXY":
			continue
		default:
			privileges = append(privileges, name)
		}
	}
	if len(privileges) == 0 {
		return nil, nil
	}
	return privileges, nil
}

func grantExistsQuery(ctx context.Context, rt *runtime.Runtime, conn *myConnection, grant, database, user, host string, grantOption, escape bool, extraSecrets ...string) (bool, error) {
	if err := grantContextError(ctx); err != nil {
		return false, err
	}
	databaseName, tableName, err := splitGrantDatabase(database)
	if err != nil {
		return false, err
	}
	if !validAccountPart(user) || !validAccountPart(host) {
		return false, errMysqlAccountArgument
	}
	// Validate the requested privilege grammar before any server query. The
	// global ALL branch later replaces only the concrete target grant list.
	target, _, err := grantStatementSSL(grant, databaseName, tableName, user, host, grantOption, escape, nil)
	if err != nil {
		return false, err
	}
	targetTokens, err := grantToTokens(target)
	if err != nil {
		return false, err
	}
	query := grantQuery(user, host)
	secrets := grantSecretInventory(conn, user, host, grant, databaseName, tableName)
	secrets = secretList(append(secrets, extraSecrets...)...)
	// The pinned first operation is the server version probe. An empty or
	// nonzero version result is a false compatibility answer and must not fall
	// through to SHOW PRIVILEGES or SHOW GRANTS.
	serverVersion, err := mysqlVersionPreserve(ctx, rt, conn, secrets...)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(serverVersion) == "" {
		return false, nil
	}
	mariaDB := strings.Contains(strings.ToLower(serverVersion), "mariadb")
	globalAll := grantRequestsAll(grant, databaseName, tableName)
	if globalAll && versionAtLeast(serverVersion, 8, 0, 0) && !mariaDB {
		serverPrivileges, err := serverAllPrivileges(ctx, rt, conn, secrets...)
		if err != nil {
			return false, err
		}
		if len(serverPrivileges) == 0 {
			serverPrivileges = append([]string(nil), mysqlAllPrivileges...)
		}
		targetTokens.Grant = serverPrivileges
	}
	result, err := runMysqlPreserveSecrets(ctx, rt, mysqlQueryArgv(conn, query), conn, secrets...)
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	statements, err := showGrantStatements(string(result.Stdout))
	if err != nil {
		return false, err
	}

	type observedGrant struct {
		user        string
		host        string
		database    string
		privileges  []string
		grantOption bool
	}
	observed := make(map[string]*observedGrant)
	for _, statement := range statements {
		parsed, err := grantToTokens(statement)
		if err != nil {
			return false, err
		}
		key := canonicalGrantObject(parsed.Database)
		entry := observed[key]
		if entry == nil {
			entry = &observedGrant{
				user:     canonicalGrantPart(parsed.User),
				host:     canonicalGrantPart(parsed.Host),
				database: key,
			}
			observed[key] = entry
		}
		entry.privileges = append(entry.privileges, canonicalGrantTokens(parsed.Grant, serverVersion)...)
		if grantHasOptionClause(statement) {
			entry.grantOption = true
		}
	}
	// The public values are identifier data, not pre-quoted SQL. In particular
	// an embedded backtick is doubled by grantObject and must remain a literal
	// backtick in the target key rather than being mistaken for a delimiter.
	targetDatabase := databaseName + "." + tableName
	targetUser := canonicalGrantPart(user)
	targetHost := canonicalGrantPart(host)
	for _, entry := range observed {
		if entry.user != targetUser || entry.host != targetHost || entry.database != targetDatabase {
			continue
		}
		if grantOption && !entry.grantOption {
			continue
		}
		if grantListCovers(entry.privileges, targetTokens.Grant, serverVersion) {
			return true, nil
		}
	}
	return false, nil
}

// grantConnection keeps account arguments separate from the connection
// surface. The account host defaults to localhost in Execute, while nil
// connection fields retain the shared mysql CLI omission semantics.
func grantConnection(user, host, port, password, database, runas *string) *myConnection {
	return &myConnection{User: user, Host: host, Port: port, Password: password, DB: database, Runas: runas}
}

// GrantAddArgs maps Salt's grant_add(grant, database, user, host="localhost",
// grant_option=False, escape=True, ssl_option=False, **connection) surface to
// the existing StateKit user-first adapter. A bare user keeps Salt's
// localhost account-host default; user@host and SQL-quoted user@host values
// remain the explicit compatibility form when host is omitted.
type GrantAddArgs struct {
	User        string  `statekit:"name=user,required"`
	Database    string  `statekit:"name=database,required"`
	Grant       string  `statekit:"name=grant,required"`
	Host        *string `statekit:"name=host"`
	GrantOption *bool   `statekit:"name=grant_option"`
	Escape      *bool   `statekit:"name=escape"`
	SSLOption   any     `statekit:"name=ssl_option"`
	ConnUser    *string `statekit:"name=connection_user"`
	ConnHost    *string `statekit:"name=connection_host"`
	ConnPort    *string `statekit:"name=connection_port"`
	ConnPass    *string `statekit:"name=connection_pass"`
	ConnDB      *string `statekit:"name=connection_db"`
	Runas       *string `statekit:"name=runas"`
}

func (a *GrantAddArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return grantConnection(a.ConnUser, a.ConnHost, a.ConnPort, a.ConnPass, a.ConnDB, a.Runas)
}

type grantAddFunc struct{}

func (grantAddFunc) Name() string { return "mysql.grant_add" }
func (grantAddFunc) Args() any    { return GrantAddArgs{} }

func (grantAddFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GrantAddArgs](args, "mysql.grant_add")
	if err != nil {
		return nil, err
	}
	if err := grantContextError(ctx); err != nil {
		return false, err
	}
	if err := validateGrantInputBounds(a.User, grantHostValue(a.Host), a.Grant, a.Database, ""); err != nil {
		return false, err
	}
	account, err := parseGrantAccount(a.User, a.Host)
	if err != nil {
		return nil, err
	}
	database, table, err := splitGrantDatabase(a.Database)
	if err != nil {
		return nil, err
	}
	grantOption := grantOptionValue(a.GrantOption)
	escape := grantEscapeValue(a.Escape)
	statement, sslSecrets, err := grantStatementSSL(a.Grant, database, table, account.User, account.Host, grantOption, escape, a.SSLOption)
	if err != nil {
		return nil, err
	}
	conn := a.connection()
	secrets := grantSecretInventory(conn, account.User, account.Host, a.Grant, database, table, a.SSLOption)
	secrets = secretList(append(secrets, sslSecrets...)...)
	result, err := runMysqlSecrets(ctx, rt, mysqlQueryArgv(conn, statement), conn, secrets...)
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	return grantExistsQuery(ctx, rt, conn, a.Grant, a.Database, account.User, account.Host, grantOption, escape, secrets...)
}

// GrantExistsArgs maps Salt's grant_exists(grant, database, user,
// host="localhost", grant_option=False, escape=True, **connection) surface
// to the existing StateKit user-first adapter.
type GrantExistsArgs struct {
	User        string  `statekit:"name=user,required"`
	Database    string  `statekit:"name=database,required"`
	Grant       string  `statekit:"name=grant,required"`
	Host        *string `statekit:"name=host"`
	GrantOption *bool   `statekit:"name=grant_option"`
	Escape      *bool   `statekit:"name=escape"`
	ConnUser    *string `statekit:"name=connection_user"`
	ConnHost    *string `statekit:"name=connection_host"`
	ConnPort    *string `statekit:"name=connection_port"`
	ConnPass    *string `statekit:"name=connection_pass"`
	ConnDB      *string `statekit:"name=connection_db"`
	Runas       *string `statekit:"name=runas"`
}

func (a *GrantExistsArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return grantConnection(a.ConnUser, a.ConnHost, a.ConnPort, a.ConnPass, a.ConnDB, a.Runas)
}

type grantExistsFunc struct{}

func (grantExistsFunc) Name() string { return "mysql.grant_exists" }
func (grantExistsFunc) Args() any    { return GrantExistsArgs{} }

func (grantExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GrantExistsArgs](args, "mysql.grant_exists")
	if err != nil {
		return nil, err
	}
	if err := grantContextError(ctx); err != nil {
		return false, err
	}
	if err := validateGrantInputBounds(a.User, grantHostValue(a.Host), a.Grant, a.Database, ""); err != nil {
		return false, err
	}
	account, err := parseGrantAccount(a.User, a.Host)
	if err != nil {
		return nil, err
	}
	return grantExistsQuery(ctx, rt, a.connection(), a.Grant, a.Database, account.User, account.Host, grantOptionValue(a.GrantOption), grantEscapeValue(a.Escape))
}

// GrantRevokeArgs maps Salt's grant_revoke(grant, database, user,
// host="localhost", grant_option=False, escape=True, **connection) surface
// to the existing StateKit user-first adapter.
type GrantRevokeArgs struct {
	User        string  `statekit:"name=user,required"`
	Database    string  `statekit:"name=database,required"`
	Grant       string  `statekit:"name=grant,required"`
	Host        *string `statekit:"name=host"`
	GrantOption *bool   `statekit:"name=grant_option"`
	Escape      *bool   `statekit:"name=escape"`
	ConnUser    *string `statekit:"name=connection_user"`
	ConnHost    *string `statekit:"name=connection_host"`
	ConnPort    *string `statekit:"name=connection_port"`
	ConnPass    *string `statekit:"name=connection_pass"`
	ConnDB      *string `statekit:"name=connection_db"`
	Runas       *string `statekit:"name=runas"`
}

func (a *GrantRevokeArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return grantConnection(a.ConnUser, a.ConnHost, a.ConnPort, a.ConnPass, a.ConnDB, a.Runas)
}

type grantRevokeFunc struct{}

func (grantRevokeFunc) Name() string { return "mysql.grant_revoke" }
func (grantRevokeFunc) Args() any    { return GrantRevokeArgs{} }

func (grantRevokeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[GrantRevokeArgs](args, "mysql.grant_revoke")
	if err != nil {
		return nil, err
	}
	if err := grantContextError(ctx); err != nil {
		return false, err
	}
	if err := validateGrantInputBounds(a.User, grantHostValue(a.Host), a.Grant, a.Database, ""); err != nil {
		return false, err
	}
	account, err := parseGrantAccount(a.User, a.Host)
	if err != nil {
		return nil, err
	}
	database, table, err := splitGrantDatabase(a.Database)
	if err != nil {
		return nil, err
	}
	grantOption := grantOptionValue(a.GrantOption)
	escape := grantEscapeValue(a.Escape)
	statement, err := revokeStatement(a.Grant, database, table, account.User, account.Host, grantOption, escape)
	if err != nil {
		return nil, err
	}
	conn := a.connection()
	secrets := grantSecretInventory(conn, account.User, account.Host, a.Grant, database, table)
	result, err := runMysqlSecrets(ctx, rt, mysqlQueryArgv(conn, statement), conn, secrets...)
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	exists, err := grantExistsQuery(ctx, rt, conn, a.Grant, a.Database, account.User, account.Host, grantOption, escape, secrets...)
	if err != nil {
		return false, err
	}
	return !exists, nil
}

// UserGrantsArgs mirrors user_grants(user, host="localhost", **connection).
// Account values remain separate from the connection surface so a quoted
// host containing apostrophes, commas, or backticks is rendered by the same
// MySQL string-literal helper used by the grant family.
type UserGrantsArgs struct {
	User     string  `statekit:"name=user,required"`
	Host     *string `statekit:"name=host"`
	ConnUser *string `statekit:"name=connection_user"`
	ConnHost *string `statekit:"name=connection_host"`
	ConnPort *string `statekit:"name=connection_port"`
	ConnPass *string `statekit:"name=connection_pass"`
	ConnDB   *string `statekit:"name=connection_db"`
	Runas    *string `statekit:"name=runas"`
}

func (a *UserGrantsArgs) connection() *myConnection {
	if a == nil {
		return &myConnection{}
	}
	return grantConnection(a.ConnUser, a.ConnHost, a.ConnPort, a.ConnPass, a.ConnDB, a.Runas)
}

type userGrantsFunc struct{}

func (userGrantsFunc) Name() string { return "mysql.user_grants" }
func (userGrantsFunc) Args() any    { return UserGrantsArgs{} }

func (userGrantsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserGrantsArgs](args, "mysql.user_grants")
	if err != nil {
		return nil, err
	}
	if err := grantContextError(ctx); err != nil {
		return nil, err
	}
	host := defaultUserHost
	if a.Host != nil {
		host = *a.Host
	}
	// The pinned function permits anonymous users and arbitrary printable
	// account text; only bytes that cannot be represented safely in the fixed
	// SQL literal are rejected before Runner execution.
	if !validUserGrantsAccountPart(a.User) || !validUserGrantsAccountPart(host) {
		return nil, accountArgumentError()
	}
	if err := validateGrantInputBounds(a.User, host, "", "", ""); err != nil {
		return nil, err
	}
	conn := a.connection()
	secrets := userGrantsSecretInventory(conn, a.User, host)
	exists, err := userExistsCatalog(ctx, rt, conn, a.User, host, secrets...)
	if err != nil {
		return nil, err
	}
	if !exists {
		// The pinned user_grants flow returns False before SHOW GRANTS when
		// mysql.user has no matching account.
		return false, nil
	}
	query := grantQuery(a.User, host)
	result, err := runMysqlPreserveSecrets(ctx, rt, mysqlQueryArgv(conn, query), conn, secrets...)
	if err != nil {
		return nil, err
	}
	// SHOW GRANTS reports a missing account and query/connection failures via a
	// nonzero mysql exit. Salt exposes those paths as False, distinct from the
	// successful empty list.
	if result.ExitCode != 0 {
		return false, nil
	}
	statements, err := showGrantStatements(string(result.Stdout))
	if err != nil {
		return nil, err
	}
	outputSecrets := userGrantsOutputSecrets(conn)
	grants := make([]string, 0, len(statements))
	for _, statement := range statements {
		normalized := normalizeUserGrant(statement)
		normalized = redactUserGrantStatement(normalized, outputSecrets)
		grants = append(grants, normalized)
	}
	return grants, nil
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

// Register installs the mysql slice: the R9.2a pure functions, the
// R9.3a/R9.3d/R9.3e fixed-query catalog family, the R9.3b server facts, the
// R9.3c maintenance family, the R9.3e user account mutations, the R9.3f
// grant family, and the R9.3g password/login family over the central mysql
// CLI transport. The remainder of the mysql family stays pending behind its
// own source/transport boundary.
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
		userInfoFunc{},
		userCreateFunc{},
		userChpassFunc{},
		userRemoveFunc{},
		grantAddFunc{},
		grantExistsFunc{},
		grantRevokeFunc{},
		userGrantsFunc{},
		versionFunc{},
		statusFunc{},
		showVariablesFunc{},
		showGlobalFunc{},
		dbCheckFunc{},
		dbRepairFunc{},
		dbOptimizeFunc{},
		verifyLoginFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
