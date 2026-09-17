// Package mysql implements the driver-free pure slice of the pinned Salt
// mysql execution surface: quote_identifier and tokenize_grant.
//
// Boundaries (R9.2a): no MySQL client driver or protocol, no new
// dependencies, no Runner spawns, no filesystem access, and no live MySQL
// server. The tokenizer is a faithful port of the pinned
// salt/modules/mysql.py _grant_to_tokens/tokenize_grant lexer, which is a
// Python shlex.shlex configured with quotes "'`", whitespace_split=False,
// empty commenters, and '"' appended to wordchars; the exact upstream
// shapes (including its read-ahead edge behavior) are preserved and pinned
// by source-derived test vectors.
package mysql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

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

// Register installs the R9.2a pure mysql catalog slice. The remainder of
// the mysql family needs a driver protocol boundary and stays pending.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		quoteIdentifierFunc{},
		tokenizeGrantFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
