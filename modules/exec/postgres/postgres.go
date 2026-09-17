// Package postgres implements the pinned Salt postgres execution surface.
//
// R9.2b registers postgres.version, the psql-backed server version probe
// from salt/modules/postgres.py:309-332. R9.2c adds the five read-only
// catalog primitives db_list, db_exists, tablespace_list,
// tablespace_exists, and user_list (postgres.py:530-598, 768-837,
// 986-1101) on the internal COPY-to-CSV query transport ported from the
// pinned psql_query (postgres.py:433-524). Like Salt, every invocation is
// a shell-free psql argv executed through the central Runner; this
// package links no database driver or protocol client and never contacts
// a live server by itself. The catalog queries are fixed SQL fragments —
// no caller-controlled SQL or identifier is interpolated, so the generic
// psql_query surface stays pending for a later round. The pinned module's
// private helpers (_run_psql 179-235, _parsed_version 334-361, _psql_cmd
// 386-432, psql_query's CSV parse) are ported as internal functions
// without public registration.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	// psqlCommand is the canonical client binary. Salt resolves it through
	// _find_pg_binary (PATH plus the postgres.bins_dir config option);
	// StateKit has no module config surface, so resolution stays with the
	// Runner's PATH discovery and fails closed when psql is absent.
	psqlCommand = "psql"
	// commandTimeout bounds every psql execution. Salt's postgres.timeout
	// option defaults to 0 (unbounded); StateKit keeps a finite ceiling as
	// a resource control, matching the R9.1 rabbitmq CLI bound.
	commandTimeout = 30 * time.Second
	// outputLimit bounds captured stdout and stderr independently.
	outputLimit = 4 << 20
	// defaultMaintenanceDB mirrors the pinned _psql_cmd fallback when no
	// maintenance database is configured or supplied.
	defaultMaintenanceDB = "postgres"
	// serverVersionQuery is the exact SQL of the pinned version().
	serverVersionQuery = "SELECT setting FROM pg_catalog.pg_settings WHERE name = 'server_version'"
	// dbListQuery is the exact SQL of the pinned db_list()
	// (postgres.py:545-552): the Name-keyed catalog join over pg_database,
	// pg_roles, and pg_tablespace.
	dbListQuery = `SELECT datname as "Name", pga.rolname as "Owner", ` +
		`pg_encoding_to_char(encoding) as "Encoding", ` +
		`datcollate as "Collate", datctype as "Ctype", ` +
		`datacl as "Access privileges", spcname as "Tablespace" ` +
		`FROM pg_database pgd, pg_roles pga, pg_tablespace pgts ` +
		`WHERE pga.oid = pgd.datdba AND pgts.oid = pgd.dattablespace`
	// tablespaceListQuery is the exact SQL of the pinned tablespace_list()
	// (postgres.py:785-789).
	tablespaceListQuery = `SELECT spcname as "Name", pga.rolname as "Owner", spcacl as "ACL", ` +
		`spcoptions as "Opts", pg_tablespace_location(pgts.oid) as "Location" ` +
		`FROM pg_tablespace pgts, pg_roles pga WHERE pga.oid = pgts.spcowner`
	// userListQueryPrefix is the fixed head of the pinned user_list() query
	// (postgres.py:1034-1051) before the two version-dependent columns are
	// substituted for {0} (rolcatupdate) and {1} (rolreplication).
	userListQueryPrefix = `SELECT pg_roles.rolname as "name",pg_roles.rolsuper as "superuser",` +
		` pg_roles.rolinherit as "inherits privileges", pg_roles.rolcreaterole as` +
		` "can create roles", pg_roles.rolcreatedb as "can create databases", {0}` +
		` as "can update system catalogs", pg_roles.rolcanlogin as "can login", {1}` +
		` as "replication", pg_roles.rolconnlimit as "connections", (SELECT` +
		` array_agg(pg_roles2.rolname)    FROM pg_catalog.pg_auth_members    JOIN` +
		` pg_catalog.pg_roles pg_roles2 ON (pg_auth_members.roleid = pg_roles2.oid)` +
		`    WHERE pg_auth_members.member = pg_roles.oid) as` +
		` "groups",pg_roles.rolvaliduntil::timestamp(0) as "expiry time",` +
		` pg_roles.rolconfig  as "defaults variables" `
	// userListPasswordSelect/Joins are appended verbatim when Salt's
	// return_password=True sets the _x() segments (postgres.py:1030-1050).
	userListPasswordSelect = `, COALESCE(pg_shadow.passwd, pg_authid.rolpassword) as "password" `
	userListAuthidJoin     = `LEFT JOIN pg_authid ON pg_roles.oid = pg_authid.oid `
	userListShadowJoin     = `LEFT JOIN pg_shadow ON pg_roles.oid = pg_shadow.usesysid`
	// userFromClause is the pinned FROM segment closing the user_list query.
	userFromClause = `FROM pg_roles `
	// expiryTimeLayout is the pinned strptime format for "expiry time".
	expiryTimeLayout = "2006-01-02 15:04:05"
)

var (
	errPostgresRunnerUnavailable = errors.New("postgres: runner unavailable")
	errPostgresPsqlUnavailable   = errors.New("postgres: psql is unavailable")
	errPostgresRunas             = errors.New("postgres: runas is not supported by statekit")
	errPostgresInvalidArgument   = errors.New("postgres: invalid argument")
)

// ---------------------------------------------------------------------------
// version — salt/modules/postgres.py:309-332 @ pinned revision.

// VersionArgs are the canonical postgres.version arguments, mirroring the
// pinned version(user, host, port, maintenance_db, password, runas)
// signature. Pointer fields keep Salt's None defaults: nil omits the
// corresponding psql flag or environment variable.
type VersionArgs struct {
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

// connection projects the version signature onto the shared connection
// arguments consumed by the psql transport.
func (a *VersionArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type versionFunc struct{}

func (versionFunc) Name() string { return "postgres.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[VersionArgs](args, "postgres.version")
	if err != nil {
		return nil, err
	}
	// The pinned version() calls _psql_cmd("-c", query, "-t", ...) and then
	// _run_psql with the same connection arguments.
	argv := psqlArgv(
		pointerString(a.User),
		pointerString(a.Host),
		pointerString(a.Port),
		pointerString(a.MaintenanceDB),
		"-c", serverVersionQuery, "-t",
	)
	result, err := runPsql(ctx, rt, argv, a.connection())
	if err != nil {
		return nil, err
	}
	return firstOutputLine(string(result.Stdout)), nil
}

// firstOutputLine ports the pinned version() consumption of
// salt.utils.itertools.split(stdout, "\n"): with an explicit separator the
// generator yields the pre-newline prefix of the first match (possibly the
// empty string), but an exhausted string yields nothing at all, so an empty
// stdout makes the pinned function fall through to None.
func firstOutputLine(stdout string) any {
	if stdout == "" {
		return nil
	}
	if index := strings.IndexByte(stdout, '\n'); index >= 0 {
		return stdout[:index]
	}
	return stdout
}

// ---------------------------------------------------------------------------
// _psql_cmd — salt/modules/postgres.py:386-432 @ pinned revision.

// psqlArgv ports the pinned _psql_cmd: the fixed never-prompt flags, the
// optional connection flags, the maintenance database with its "postgres"
// fallback, and finally the caller's trailing arguments. With every
// connection argument supplied, the version query lands at argv index 14
// exactly as the pinned test_postgres.py test_version asserts. The pinned
// _connection_defaults config.option lookups have no StateKit equivalent,
// so empty arguments keep Salt's None meaning here.
func psqlArgv(user, host, port, maintenanceDB string, args ...string) []string {
	argv := []string{
		psqlCommand,
		"--no-align",
		"--no-readline",
		"--no-psqlrc",
		"--no-password", // Never prompt; credentials travel out of band.
	}
	if user != "" {
		argv = append(argv, "--username", user)
	}
	if host != "" {
		argv = append(argv, "--host", host)
	}
	if port != "" {
		argv = append(argv, "--port", port)
	}
	if maintenanceDB == "" {
		maintenanceDB = defaultMaintenanceDB
	}
	argv = append(argv, "--dbname", maintenanceDB)
	return append(argv, args...)
}

// ---------------------------------------------------------------------------
// _run_psql — salt/modules/postgres.py:179-235 @ pinned revision.

// pgConnection is the connection half shared by every postgres function
// signature: the pinned (user, host, port, maintenance_db, password,
// runas) tuple. Pointer fields keep Salt's None defaults: nil omits the
// corresponding psql flag or environment variable.
type pgConnection struct {
	User          *string
	Host          *string
	Port          *string
	MaintenanceDB *string
	Password      *string
	Runas         *string
}

// runPsql ports the pinned _run_psql execution half: a shell-free,
// centrally executed psql command with bounded output. The password half is
// adapted: Salt writes a temporary PGPASSFILE and chowns it to the runas
// user, but the StateKit runtime is single-user and has no elevation or
// file-chown contract, so credentials travel through psql's native
// PGPASSWORD (with PGUSER/PGHOST/PGPORT for the resolved connection) in an
// otherwise clean environment, matching Salt's clean_env=True. The password
// is a Redact secret: it never appears in the rendered command, captured
// output, or returned errors. A non-zero psql exit stays compatibility
// data, like Salt's logged-but-returned retcode.
func runPsql(ctx context.Context, rt *runtime.Runtime, argv []string, conn *pgConnection) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errPostgresRunnerUnavailable
	}
	if conn == nil {
		conn = &pgConnection{}
	}
	// Salt defaults runas to "postgres" for local-socket connections; the
	// central runtime is single-user, so an explicit runas is rejected
	// before any Runner invocation instead of being silently dropped.
	if err := rejectRunas(conn.Runas); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if err := validateArgv(argv); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable(psqlCommand) {
		// Fail closed: psql discovery has no package-manager or other
		// fallback in this module.
		return process.CommandResult{ExitCode: -1}, errPostgresPsqlUnavailable
	}

	command := process.Command{
		Name:           argv[0],
		Args:           append([]string(nil), argv[1:]...),
		Timeout:        commandTimeout,
		MaxStdoutBytes: outputLimit,
		MaxStderrBytes: outputLimit,
		Env:            psqlEnvironment(conn),
	}
	if conn.Password != nil {
		command.Redact = secretList(*conn.Password)
	}
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, redactedError(result.Err, conn.Password)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

// psqlEnvironment builds the clean child environment for psql. Salt runs
// psql with clean_env=True and passes credentials out of band, so only the
// resolved connection variables are exported; an empty result leaves the
// child with no inherited environment at all.
func psqlEnvironment(conn *pgConnection) []string {
	env := make([]string, 0, 4)
	if conn.Password != nil {
		env = append(env, "PGPASSWORD="+*conn.Password)
	}
	if value := pointerString(conn.User); value != "" {
		env = append(env, "PGUSER="+value)
	}
	if value := pointerString(conn.Host); value != "" {
		env = append(env, "PGHOST="+value)
	}
	if value := pointerString(conn.Port); value != "" {
		env = append(env, "PGPORT="+value)
	}
	return env
}

// ---------------------------------------------------------------------------
// _parsed_version — salt/modules/postgres.py:334-361 @ pinned revision.

// parsedVersion is the internal LooseVersion-equivalent returned by
// parsedServerVersion (the pinned _parsed_version helper). It tokenizes
// like LooseVersion — digit runs become integers, dots are discarded,
// and other pieces remain strings. Salt's override compares entire lists
// as strings (integers zero-filled to width 8) if either contains a string;
// otherwise it compares numeric lists. It is deliberately not registered:
// like the pinned helper it exists for internal callers only.
type parsedVersion struct {
	vstring    string
	components []looseToken
}

// looseToken is one LooseVersion component: an integer run or a literal
// string piece.
type looseToken struct {
	isInt bool
	num   *big.Int
	str   string
}

// looseSplitRE is distutils' _component_re: digit runs, lowercase alpha
// runs, and dots split the string; every unmatched chunk stays literal.
var looseSplitRE = regexp.MustCompile(`(\d+|[a-z]+|\.)`)

// parseLooseVersion tokenizes like distutils LooseVersion.parse: digit runs
// become integers (so "04" compares as 4), dots are discarded, and other
// chunks stay literal strings. Python integers have no fixed-width limit.
func parseLooseVersion(vstring string) parsedVersion {
	indices := looseSplitRE.FindAllStringIndex(vstring, -1)
	tokens := make([]looseToken, 0, len(indices)+1)
	appendPiece := func(piece string) {
		if piece == "" || piece == "." {
			return
		}
		if isASCIIDigits(piece) {
			num, _ := new(big.Int).SetString(piece, 10)
			tokens = append(tokens, looseToken{isInt: true, num: num})
			return
		}
		tokens = append(tokens, looseToken{str: piece})
	}
	prev := 0
	for _, loc := range indices {
		appendPiece(vstring[prev:loc[0]])
		appendPiece(vstring[loc[0]:loc[1]])
		prev = loc[1]
	}
	appendPiece(vstring[prev:])
	return parsedVersion{vstring: vstring, components: tokens}
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// String keeps the original version string, as distutils LooseVersion does.
func (v parsedVersion) String() string { return v.vstring }

// compare mirrors salt/utils/versions.py:73-101, including the whole-list
// string fallback and zfill(8), not generic distutils mixed-type behavior.
// The boolean remains true for all parsed versions; strict prefixes sort first.
func (v parsedVersion) compare(other parsedVersion) (int, bool) {
	stringMode := false
	for _, parts := range [][]looseToken{v.components, other.components} {
		for _, part := range parts {
			if !part.isInt {
				stringMode = true
			}
		}
	}
	stringPart := func(part looseToken) string {
		if !part.isInt {
			return part.str
		}
		s := part.num.String()
		if len(s) < 8 {
			s = strings.Repeat("0", 8-len(s)) + s
		}
		return s
	}
	shared := len(v.components)
	if len(other.components) < shared {
		shared = len(other.components)
	}
	for i := 0; i < shared; i++ {
		a, b := v.components[i], other.components[i]
		var order int
		if stringMode {
			order = strings.Compare(stringPart(a), stringPart(b))
		} else {
			order = a.num.Cmp(b.num)
		}
		if order != 0 {
			if order < 0 {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(v.components) < len(other.components):
		return -1, true
	case len(v.components) > len(other.components):
		return 1, true
	}
	return 0, true
}

// parsedServerVersion ports the pinned _parsed_version: it runs the public
// version probe and parses the reply, returning nil (Salt: None) when the
// server does not answer with a non-empty version. The pinned helper logs a
// warning in that case; StateKit modules do not log, so the nil result is
// the signal. Internal-only, with no registry entry.
func parsedServerVersion(ctx context.Context, rt *runtime.Runtime, conn *pgConnection) (*parsedVersion, error) {
	args := &VersionArgs{
		User:          conn.User,
		Host:          conn.Host,
		Port:          conn.Port,
		MaintenanceDB: conn.MaintenanceDB,
		Password:      conn.Password,
		Runas:         conn.Runas,
	}
	value, err := versionFunc{}.Execute(ctx, rt, args)
	if err != nil {
		return nil, err
	}
	version, ok := value.(string)
	if !ok || version == "" {
		return nil, nil
	}
	parsed := parseLooseVersion(version)
	return &parsed, nil
}

// ---------------------------------------------------------------------------
// psql_query (read-only transport) — salt/modules/postgres.py:433-524 @
// pinned revision, restricted to the write=False shape.

// psqlQueryRows ports the pinned psql_query reader for this module's fixed
// catalog queries: the query is wrapped in "COPY (...) TO STDOUT WITH CSV
// HEADER", run through the same _psql_cmd/_run_psql transport as version()
// with the pinned datestyle variable, and the CSV stdout is parsed with the
// pinned csv.reader semantics (comma delimiter, double-quote quotechar,
// empty rows skipped, first row the header, dict(zip(header,row)) rows).
// A positive psql retcode keeps Salt's empty-list compatibility data; only
// Runner failures, cancellation, and output-limit violations are errors.
// The generic query surface stays unregistered: callers pass fixed SQL
// fragments only.
func psqlQueryRows(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, query string) ([]map[string]string, error) {
	csvQuery := "COPY (" + strings.TrimRight(strings.TrimSpace(query), ";") + ") TO STDOUT WITH CSV HEADER"
	argv := psqlArgv(
		pointerString(conn.User),
		pointerString(conn.Host),
		pointerString(conn.Port),
		pointerString(conn.MaintenanceDB),
		"-v", "datestyle=ISO,MDY", "-c", csvQuery,
	)
	result, err := runPsql(ctx, rt, argv, conn)
	if err != nil {
		return nil, err
	}
	if result.ExitCode > 0 {
		return []map[string]string{}, nil
	}
	return parseCSVRows(string(result.Stdout))
}

// parseCSVRows ports the pinned io.StringIO + csv.reader loop
// (postgres.py:506-518). Rows shorter than the header keep only their zipped
// prefix and rows longer are truncated at the header, exactly like
// dict(zip(header, row)); empty records are skipped. The reader itself is the
// pyCSVReader port of the pinned Python csv module described below.
func parseCSVRows(stdout string) ([]map[string]string, error) {
	rows := []map[string]string{}
	reader := newPyCSVReader(stdout)
	var header []string
	for {
		record, err := reader.next()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			// Salt propagates csv.Error as a module exception.
			return nil, fmt.Errorf("postgres: csv parse: %w", err)
		}
		if len(record) == 0 {
			continue
		}
		if header == nil {
			header = record
			continue
		}
		shared := len(header)
		if len(record) < shared {
			shared = len(record)
		}
		row := make(map[string]string, shared)
		for i := 0; i < shared; i++ {
			row[header[i]] = record[i]
		}
		rows = append(rows, row)
	}
}

// ---------------------------------------------------------------------------
// pinned csv.reader — CPython Modules/_csv.c @ default dialect, non-strict.

// pyCSVFieldLimit mirrors the Python csv module's default field_size_limit:
// 131072 characters per field, beyond which the reader raises csv.Error.
const pyCSVFieldLimit = 131072

var (
	errPyCSVFieldLimit = errors.New("field larger than field limit (131072)")
	errPyCSVNewline    = errors.New("new-line character seen in unquoted field")
)

// pyCSVState names the reader states of the pinned CPython _csv.c state
// machine for the default dialect (comma delimiter, double-quote quotechar,
// doublequote, no escapechar, no skipinitialspace, strict=False).
type pyCSVState uint8

const (
	pyCSVStartRecord pyCSVState = iota
	pyCSVStartField
	pyCSVInField
	pyCSVInQuotedField
	pyCSVQuoteInQuotedField
	pyCSVEatCRNL
)

// pyCSVReader is a bounded port of the pinned Python csv.reader as the pinned
// psql_query and user_list use it: iteration over io.StringIO(stdout)
// (newline='\n', so lines split on '\n' only and '\r' stays a line
// character) and, for groups, a single-element [value] iterable. Both feeds
// share one char-level state machine:
//
//   - Inside a quoted field every character — comma, quote-backslash
//     sequences, lone '\r', '\r\n', '\n', and NUL — is literal data, so an
//     embedded CRLF survives byte-exact (Go's encoding/csv would normalize it
//     to LF, which is why it cannot be used here).
//   - A backslash is an ordinary character (escapechar is None), and after a
//     closing quote any regular character is appended without unquoting
//     (strict=False), so PostgreSQL's backslash-escaped array elements like
//     {"a\"b","x\\y"} decode exactly as the pinned Python reader decodes
//     them (["a\b\"", "x\\y"]) instead of being rejected.
//   - '\r' or '\n' outside a quoted field ends the record; a non-EOL
//     character after it is the pinned csv.Error "new-line character seen in
//     unquoted field".
//   - A record is returned at the end of any line that leaves the machine in
//     a record-complete state, and end of input saves the pending field —
//     even when empty ("db1," is ["db1", ""]) — unless no record is in
//     progress.
//
// The only bound beyond the already size-capped psql stdout is the pinned
// per-field limit of 131072 characters. Errors never embed input or field
// content, so no source, query, or credential material can leak through
// them.
type pyCSVReader struct {
	input    string
	pos      int
	single   bool
	state    pyCSVState
	fields   []string
	field    []byte
	fieldLen int
}

// newPyCSVReader mirrors csv.reader(io.StringIO(stdout)): the input is a
// '\n'-split line stream, and records are yielded until end of input.
func newPyCSVReader(input string) *pyCSVReader {
	return &pyCSVReader{input: input, state: pyCSVStartRecord}
}

// newPyCSVRecordReader mirrors csv.reader([value]): the whole string is one
// line — even when empty or containing '\n' — so exactly one record (or one
// error) is always produced.
func newPyCSVRecordReader(line string) *pyCSVReader {
	return &pyCSVReader{input: line, single: true, state: pyCSVStartRecord}
}

// next returns the next record. It mirrors the pinned Reader iteration: feed
// one '\n'-terminated line at a time, return a record whenever a line leaves
// the machine record-complete, and at end of input finish the pending record
// the way the non-strict Python reader does.
func (r *pyCSVReader) next() ([]string, error) {
	if r.single {
		return r.nextRecord()
	}
	for {
		if r.pos >= len(r.input) {
			if r.state == pyCSVStartRecord {
				return nil, io.EOF
			}
			r.saveField()
			return r.emit(), nil
		}
		lineEnd := strings.IndexByte(r.input[r.pos:], '\n')
		if lineEnd < 0 {
			lineEnd = len(r.input) - r.pos
		} else {
			lineEnd++ // the line keeps its '\n' terminator
		}
		segment := r.input[r.pos : r.pos+lineEnd]
		r.pos += lineEnd
		for _, c := range segment {
			if err := r.step(c); err != nil {
				return nil, err
			}
		}
		switch r.state {
		case pyCSVStartRecord, pyCSVEatCRNL:
			return r.emit(), nil
		}
		// The line ended inside an open record (quoted data or a final line
		// without its terminator); the next line continues the record.
	}
}

// nextRecord decodes the single-line feed: the entire input is one line, and
// its record — empty or not — is the one record the pinned one-element list
// iteration returns.
func (r *pyCSVReader) nextRecord() ([]string, error) {
	for _, c := range r.input {
		if err := r.step(c); err != nil {
			return nil, err
		}
	}
	switch r.state {
	case pyCSVStartRecord, pyCSVEatCRNL:
		return r.emit(), nil
	default:
		r.saveField()
		return r.emit(), nil
	}
}

// step advances the machine by one character.
func (r *pyCSVReader) step(c rune) error {
	switch r.state {
	case pyCSVStartRecord:
		if c == '\r' || c == '\n' {
			r.state = pyCSVEatCRNL
			return nil
		}
		r.state = pyCSVStartField
		fallthrough
	case pyCSVStartField:
		switch {
		case c == '"':
			r.state = pyCSVInQuotedField
		case c == ',':
			r.saveField()
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			if err := r.add(c); err != nil {
				return err
			}
			r.state = pyCSVInField
		}
	case pyCSVInField:
		switch {
		case c == ',':
			r.saveField()
			r.state = pyCSVStartField
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			return r.add(c)
		}
	case pyCSVInQuotedField:
		if c == '"' {
			r.state = pyCSVQuoteInQuotedField
			return nil
		}
		return r.add(c)
	case pyCSVQuoteInQuotedField:
		switch {
		case c == '"':
			// Doubled quote: "" inside a quoted field is one literal '"'.
			if err := r.add('"'); err != nil {
				return err
			}
			r.state = pyCSVInQuotedField
		case c == ',':
			r.saveField()
			r.state = pyCSVStartField
		case c == '\r' || c == '\n':
			r.saveField()
			r.state = pyCSVEatCRNL
		default:
			// Non-strict: keep appending after the closing quote.
			if err := r.add(c); err != nil {
				return err
			}
			r.state = pyCSVInField
		}
	case pyCSVEatCRNL:
		if c == '\r' || c == '\n' {
			return nil
		}
		return errPyCSVNewline
	}
	return nil
}

func (r *pyCSVReader) add(c rune) error {
	if r.fieldLen >= pyCSVFieldLimit {
		return errPyCSVFieldLimit
	}
	r.field = utf8.AppendRune(r.field, c)
	r.fieldLen++
	return nil
}

func (r *pyCSVReader) saveField() {
	r.fields = append(r.fields, string(r.field))
	r.field = r.field[:0]
	r.fieldLen = 0
}

// emit finishes the current record and resets the machine to a fresh one,
// returning a non-nil record like the Python reader's fresh list per row.
func (r *pyCSVReader) emit() []string {
	record := r.fields
	if record == nil {
		record = []string{}
	}
	r.fields = nil
	r.field = r.field[:0]
	r.fieldLen = 0
	r.state = pyCSVStartRecord
	return record
}

// ---------------------------------------------------------------------------
// db_list / db_exists — salt/modules/postgres.py:530-598 @ pinned revision.

// ListArgs are the canonical postgres.db_list and postgres.tablespace_list
// arguments, mirroring the pinned (user, host, port, maintenance_db,
// password, runas) signatures.
type ListArgs struct {
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *ListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

// ExistsArgs are the canonical postgres.db_exists and
// postgres.tablespace_exists arguments: the pinned name positional plus
// the shared connection tuple.
type ExistsArgs struct {
	Name          string  `statekit:"name=name,required"`
	User          *string `statekit:"name=user"`
	Host          *string `statekit:"name=host"`
	Port          *string `statekit:"name=port"`
	MaintenanceDB *string `statekit:"name=maintenance_db"`
	Password      *string `statekit:"name=password"`
	Runas         *string `statekit:"name=runas"`
}

func (a *ExistsArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type dbListFunc struct{}

func (dbListFunc) Name() string { return "postgres.db_list" }
func (dbListFunc) Args() any    { return ListArgs{} }

func (dbListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.db_list")
	if err != nil {
		return nil, err
	}
	return nameKeyedCatalog(ctx, rt, a.connection(), dbListQuery, "postgres.db_list")
}

type dbExistsFunc struct{}

func (dbExistsFunc) Name() string { return "postgres.db_exists" }
func (dbExistsFunc) Args() any    { return ExistsArgs{} }

func (dbExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.db_exists")
	if err != nil {
		return nil, err
	}
	// The pinned db_exists is exactly `name in db_list(...)`: the name is
	// matched client-side against the catalog and never reaches SQL.
	databases, err := nameKeyedCatalog(ctx, rt, a.connection(), dbListQuery, "postgres.db_exists")
	if err != nil {
		return nil, err
	}
	_, exists := databases[a.Name]
	return exists, nil
}

// nameKeyedCatalog ports the shared db_list/tablespace_list tail
// (postgres.py:564-568, 801-805): every row is stored under its "Name"
// column with that column removed, like the pinned
// ret[row["Name"]] = row; ret[row["Name"]].pop("Name").
func nameKeyedCatalog(ctx context.Context, rt *runtime.Runtime, conn *pgConnection, query, name string) (map[string]map[string]string, error) {
	rows, err := psqlQueryRows(ctx, rt, conn, query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		key, ok := row["Name"]
		if !ok {
			// Salt raises KeyError('Name') on a short row.
			return nil, fmt.Errorf(`%s: missing column "Name"`, name)
		}
		entry := make(map[string]string, len(row)-1)
		for column, value := range row {
			if column != "Name" {
				entry[column] = value
			}
		}
		out[key] = entry
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// tablespace_list / tablespace_exists — salt/modules/postgres.py:768-837 @
// pinned revision.

type tablespaceListFunc struct{}

func (tablespaceListFunc) Name() string { return "postgres.tablespace_list" }
func (tablespaceListFunc) Args() any    { return ListArgs{} }

func (tablespaceListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ListArgs](args, "postgres.tablespace_list")
	if err != nil {
		return nil, err
	}
	return nameKeyedCatalog(ctx, rt, a.connection(), tablespaceListQuery, "postgres.tablespace_list")
}

type tablespaceExistsFunc struct{}

func (tablespaceExistsFunc) Name() string { return "postgres.tablespace_exists" }
func (tablespaceExistsFunc) Args() any    { return ExistsArgs{} }

func (tablespaceExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[ExistsArgs](args, "postgres.tablespace_exists")
	if err != nil {
		return nil, err
	}
	tablespaces, err := nameKeyedCatalog(ctx, rt, a.connection(), tablespaceListQuery, "postgres.tablespace_exists")
	if err != nil {
		return nil, err
	}
	_, exists := tablespaces[a.Name]
	return exists, nil
}

// ---------------------------------------------------------------------------
// user_list — salt/modules/postgres.py:986-1101 @ pinned revision.

// UserListArgs are the canonical postgres.user_list arguments, mirroring
// the pinned signature including return_password=False.
type UserListArgs struct {
	User           *string `statekit:"name=user"`
	Host           *string `statekit:"name=host"`
	Port           *string `statekit:"name=port"`
	MaintenanceDB  *string `statekit:"name=maintenance_db"`
	Password       *string `statekit:"name=password"`
	Runas          *string `statekit:"name=runas"`
	ReturnPassword bool    `statekit:"name=return_password"`
}

func (a *UserListArgs) connection() *pgConnection {
	if a == nil {
		return &pgConnection{}
	}
	return &pgConnection{
		User:          a.User,
		Host:          a.Host,
		Port:          a.Port,
		MaintenanceDB: a.MaintenanceDB,
		Password:      a.Password,
		Runas:         a.Runas,
	}
}

type userListFunc struct{}

func (userListFunc) Name() string { return "postgres.user_list" }
func (userListFunc) Args() any    { return UserListArgs{} }

func (userListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, err := typedArgs[UserListArgs](args, "postgres.user_list")
	if err != nil {
		return nil, err
	}
	conn := a.connection()
	ver, err := parsedServerVersion(ctx, rt, conn)
	if err != nil {
		return nil, err
	}
	if ver == nil {
		// The pinned user_list returns False when the version probe cannot
		// reach a server (after logging an error); the boolean is the
		// compatibility result, not an exception.
		return false, nil
	}
	replicationColumn := "NULL"
	if order, ok := ver.compare(parseLooseVersion("9.1")); ok && order >= 0 {
		replicationColumn = "pg_roles.rolreplication"
	}
	rolcatupdateColumn := "pg_roles.rolcatupdate"
	if order, ok := ver.compare(parseLooseVersion("9.5")); ok && order >= 0 {
		rolcatupdateColumn = "NULL"
	}
	query := strings.Replace(userListQueryPrefix, "{0}", rolcatupdateColumn, 1)
	query = strings.Replace(query, "{1}", replicationColumn, 1)
	if a.ReturnPassword {
		// Salt's _x() appends the password select and its two LEFT JOINs
		// only when return_password is set, before and after FROM.
		query += userListPasswordSelect
	}
	query += userFromClause
	if a.ReturnPassword {
		query += userListAuthidJoin + userListShadowJoin
	}
	rows, err := psqlQueryRows(ctx, rt, conn, query)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(rows))
	for _, row := range rows {
		retrow := map[string]any{}
		for _, key := range []string{
			"superuser",
			"inherits privileges",
			"can create roles",
			"can create databases",
			"can update system catalogs",
			"can login",
			"replication",
			"connections",
		} {
			value, err := rowString(row, key, "postgres.user_list")
			if err != nil {
				return nil, err
			}
			retrow[key] = looseBool(value)
		}
		expiry, err := rowString(row, "expiry time", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		// The pinned strptime except ValueError maps any unparseable
		// value to None rather than an error.
		retrow["expiry time"] = nil
		if parsed, perr := time.Parse(expiryTimeLayout, expiry); perr == nil {
			retrow["expiry time"] = parsed
		}
		defaults, err := rowString(row, "defaults variables", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		retrow["defaults variables"] = defaults
		if a.ReturnPassword {
			password, err := rowString(row, "password", "postgres.user_list")
			if err != nil {
				return nil, err
			}
			retrow["password"] = password
		}
		groups, err := rowString(row, "groups", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		// use csv reader to handle quoted roles correctly
		retrow["groups"], err = parseGroups(groups)
		if err != nil {
			return nil, err
		}
		name, err := rowString(row, "name", "postgres.user_list")
		if err != nil {
			return nil, err
		}
		out[name] = retrow
	}
	return out, nil
}

// rowString fetches a column, mapping Salt's KeyError to an error.
func rowString(row map[string]string, key, name string) (string, error) {
	value, ok := row[key]
	if !ok {
		return "", fmt.Errorf("%s: missing column %q", name, key)
	}
	return value, nil
}

// looseBool ports the pinned get_bool: "t" is true, "f" is false, and
// anything else (including NULL's empty CSV field) is None.
func looseBool(value string) any {
	switch value {
	case "t":
		return true
	case "f":
		return false
	default:
		return nil
	}
}

// parseGroups ports the pinned groups decode (postgres.py:1097-1098):
// strip the PostgreSQL array braces with the pinned str.strip("{}")
// semantics, then decode the first csv.reader record over that single line.
// The pinned reader is the non-strict Python machine (pyCSVReader), so
// backslash-escaped array elements decode exactly like the pinned
// list(csv.reader([row["groups"].strip("{}")]))[0]: {"a\"b","x\\y"} is
// ["a\b\"", "x\\y"], doubled quotes collapse, NUL bytes are data, and a bare
// CR/LF outside quotes is the pinned csv.Error. An empty literal ({}, or a
// NULL groups column) is the empty list, matching the empty first record the
// pinned single-line reader returns.
func parseGroups(value string) ([]string, error) {
	record, err := newPyCSVRecordReader(strings.Trim(value, "{}")).next()
	if err != nil {
		return nil, fmt.Errorf("postgres: csv parse: %w", err)
	}
	return record, nil
}

// ---------------------------------------------------------------------------
// shared helpers (rabbitmq-module conventions).

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

func rejectRunas(runas *string) error {
	if runas == nil || *runas == "" {
		return nil
	}
	if strings.IndexByte(*runas, 0) >= 0 || strings.ContainsAny(*runas, "\r\n") {
		return errPostgresInvalidArgument
	}
	return errPostgresRunas
}

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return errPostgresInvalidArgument
	}
	total := 0
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 || strings.ContainsAny(arg, "\r\n") {
			return errPostgresInvalidArgument
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
	return out
}

func redactedError(err error, password *string) error {
	if err == nil {
		return nil
	}
	if password == nil || *password == "" {
		return err
	}
	message := process.RedactString([]string{*password}, err.Error())
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

// Register installs the R9.2c postgres slice: the version probe plus the
// five read-only catalog primitives. The remainder of the postgres family
// needs the generic psql query surface (psql_query itself stays pending;
// no arbitrary-query registration exists in this phase) and stays pending
// for later R9 rounds; the internal parsed-version and psql-query helpers
// are intentionally not registered, exactly like the pinned private
// functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		dbListFunc{},
		dbExistsFunc{},
		tablespaceListFunc{},
		tablespaceExistsFunc{},
		userListFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
