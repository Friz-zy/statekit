// Package postgres implements the pinned Salt postgres execution surface.
//
// R9.2b registers exactly one public function, postgres.version, the
// psql-backed server version probe from salt/modules/postgres.py:309-332.
// Like Salt, every invocation is a shell-free psql argv executed through
// the central Runner; this package links no database driver or protocol
// client and never contacts a live server by itself. The pinned module's
// private helpers (_run_psql 179-235, _parsed_version 334-361, _psql_cmd
// 386-432) are ported as internal functions without public registration.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

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
	result, err := runPsql(ctx, rt, argv, a)
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
func runPsql(ctx context.Context, rt *runtime.Runtime, argv []string, a *VersionArgs) (process.CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errPostgresRunnerUnavailable
	}
	// Salt defaults runas to "postgres" for local-socket connections; the
	// central runtime is single-user, so an explicit runas is rejected
	// before any Runner invocation instead of being silently dropped.
	if err := rejectRunas(a.Runas); err != nil {
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
		Env:            psqlEnvironment(a),
	}
	if a.Password != nil {
		command.Redact = secretList(*a.Password)
	}
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, redactedError(result.Err, a.Password)
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
func psqlEnvironment(a *VersionArgs) []string {
	env := make([]string, 0, 4)
	if a.Password != nil {
		env = append(env, "PGPASSWORD="+*a.Password)
	}
	if value := pointerString(a.User); value != "" {
		env = append(env, "PGUSER="+value)
	}
	if value := pointerString(a.Host); value != "" {
		env = append(env, "PGHOST="+value)
	}
	if value := pointerString(a.Port); value != "" {
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
func parsedServerVersion(ctx context.Context, rt *runtime.Runtime, args *VersionArgs) (*parsedVersion, error) {
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

// Register installs the R9.2b postgres slice: the single public version
// probe. The remainder of the postgres family needs the broader psql query
// surface and stays pending for later R9 rounds; the internal parsed-version
// helper is intentionally not registered, exactly like the pinned private
// function.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
