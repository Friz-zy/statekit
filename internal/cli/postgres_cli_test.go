package cli

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpostgres "github.com/friz-zy/statekit/modules/exec/postgres"
)

// postgresCLIMD5Hex renders the hex MD5 of the concatenated password+role
// input the pinned md5 verifier hashes, for asserting exact CLI digests.
func postgresCLIMD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// postgresCLIApp builds a CLI app whose runtime carries only the postgres
// module and a recording fake Runner: the R9.2b surface is mock-only and
// must never reach a real psql or database.
func postgresCLIApp(t *testing.T, runner process.Runner) *App {
	t.Helper()
	return postgresCLIAppFS(t, runner, nil)
}

// postgresCLIAppFS builds the same app with an optional filesystem seed
// so the R9.2p datadir family's Runtime.FS boundary stays testable
// end to end.
func postgresCLIAppFS(t *testing.T, runner process.Runner, seed func(fsys runtime.FileSystem)) *App {
	t.Helper()
	return postgresCLIAppConfigured(t, runner, func(rt *runtime.Runtime) {
		if seed != nil {
			seed(rt.FS)
		}
	})
}

// postgresCLIAppConfigured builds the app around a caller-configured
// runtime so the R9.2p kernel-mapped defaults (injected OpenBSD facts)
// and the pwfile fault-injecting filesystems stay testable through the
// full CLI path.
func postgresCLIAppConfigured(t *testing.T, runner process.Runner, configure func(rt *runtime.Runtime)) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if configure != nil {
		configure(rt)
	}
	if err := execpostgres.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestPostgresCLIVersion drives postgres.version end to end with the pinned
// test's arguments: exact argv and environment through the fake Runner, the
// JSON string rendering of the first stdout line, and no password anywhere
// in the rendered command or CLI output.
func TestPostgresCLIVersion(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1.9\n")},
	}}
	app := postgresCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "postgres.version",
		"--user", "test_user", "--host", "test_host", "--port", "test_port",
		"--maintenance-db", "test_maint", "--password", "test_pass", "-o", "json")
	var version string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &version) != nil || version != "9.1.9" {
		t.Fatalf("version code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 16 || argv[5] != "--username" || argv[6] != "test_user" ||
		argv[14] != "SELECT setting FROM pg_catalog.pg_settings WHERE name = 'server_version'" ||
		argv[15] != "-t" {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=test_pass" ||
		command.Env[1] != "PGUSER=test_user" || command.Env[2] != "PGHOST=test_host" ||
		command.Env[3] != "PGPORT=test_port" {
		t.Fatalf("env = %q", command.Env)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "test_pass" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") {
		t.Fatalf("rendered command leaks password: %q", rendered)
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}
}

// TestPostgresCLIVersionShapes pins the empty-stdout None rendering, the
// empty-first-line string rendering, the nonzero-exit compatibility data
// path, and the hyphenated maintenance_db flag spelling.
func TestPostgresCLIVersionShapes(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("\n16.2\n")},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.version", "--maintenance_db", "test_maint", "-o", "json")
	var empty string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &empty) != nil || empty != "" {
		t.Fatalf("empty first line code=%d out=%q err=%q", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.version", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("empty stdout code=%d out=%q err=%q, want null", code, out, errS)
	}

	// A failed psql connection keeps Salt's shape: no exception, an empty
	// (None) return.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.version", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want null", code, out, errS)
	}
}

// TestPostgresCLIVersionFailures pins the failure modes: runas rejection,
// redacted Runner errors, and the unregistered internal helper.
func TestPostgresCLIVersionFailures(t *testing.T) {
	runner := &cliRecordingRunner{}
	app := postgresCLIApp(t, runner)
	code, _, errS := captureCode(t, app, "exec", "postgres.version", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || strings.Contains(errS, "password") {
		t.Fatalf("runas code=%d err=%q", code, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runas run executed %d commands", len(runner.calls))
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: -1, Err: errors.New("exec psql: secret test_pass rejected")},
	}}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.version", "--password", "test_pass", "-o", "json")
	if code != ExitFailed {
		t.Fatalf("runner error code=%d, want ExitFailed", code)
	}
	if strings.Contains(errS, "test_pass") {
		t.Fatalf("CLI error leaks password: %q", errS)
	}

	// The internal parsed-version helper has no public registration.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres._parsed_version", "-o", "json")
	if code != ExitUnsupported {
		t.Fatalf("_parsed_version code=%d err=%q, want ExitUnsupported", code, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("_parsed_version executed %d commands", len(runner.calls))
	}
}

// pinnedCLIListDBCSV is the pinned get_test_list_db_csv fixture.
const pinnedCLIListDBCSV = `Name,Owner,Encoding,Collate,Ctype,Access privileges,Tablespace
template1,postgres,LATIN1,en_US,en_US,"{=c/postgres,postgres=CTc/postgres}",pg_default
test_db,postgres,LATIN1,en_US,en_US,,pg_default
`

// TestPostgresCLIDbList drives postgres.db_list end to end: the JSON map
// matches the pinned dictionary, the argv embeds the fixed SQL inside the
// COPY-to-CSV transport, and the password never reaches the rendered
// command or CLI output.
func TestPostgresCLIDbList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIListDBCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.db_list",
		"--user", "test_user", "--host", "test_host", "--port", "test_port",
		"--maintenance-db", "test_maint", "--password", "test_pass", "-o", "json")
	var databases map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil {
		t.Fatalf("db_list code=%d out=%q err=%q", code, out, errS)
	}
	if len(databases) != 2 || databases["test_db"]["Owner"] != "postgres" ||
		databases["test_db"]["Access privileges"] != "" ||
		databases["template1"]["Access privileges"] != "{=c/postgres,postgres=CTc/postgres}" {
		t.Fatalf("db_list JSON = %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if argv[0] != "psql" || argv[13] != "-v" || argv[14] != "datestyle=ISO,MDY" || argv[15] != "-c" ||
		argv[16] != "COPY (SELECT datname as \"Name\", pga.rolname as \"Owner\", pg_encoding_to_char(encoding) as \"Encoding\", datcollate as \"Collate\", datctype as \"Ctype\", datacl as \"Access privileges\", spcname as \"Tablespace\" FROM pg_database pgd, pg_roles pga, pg_tablespace pgts WHERE pga.oid = pgd.datdba AND pgts.oid = pgd.dattablespace) TO STDOUT WITH CSV HEADER" {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(command.RedactedString(), "test_pass") || strings.Contains(out+errS, "test_pass") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}
}

// TestPostgresCLIDbExists pins the CLI boolean rendering of db_exists for
// the present and absent names, the zero-execution unsupported surface,
// and the required-name validation.
func TestPostgresCLIDbExists(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"test_db", true},
		{"absent_db", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(pinnedCLIListDBCSV)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres.db_exists",
			"--name", tc.name, "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("db_exists(%q) code=%d out=%q err=%q", tc.name, code, out, errS)
		}
	}

	// The generic query surface stays unregistered (exit 3, no calls).
	runner := &cliRecordingRunner{}
	app := postgresCLIApp(t, runner)
	code, _, _ := captureCode(t, app, "exec", "postgres.psql_query", "--query", "SELECT 1", "-o", "json")
	if code != ExitUnsupported {
		t.Fatalf("psql_query code=%d, want ExitUnsupported", code)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("psql_query executed %d commands", len(runner.calls))
	}

	// db_exists without the required name fails validation before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS := captureCode(t, app, "exec", "postgres.db_exists", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLITablespaceListExists pins the tablespace_list JSON shape
// and the tablespace_exists boolean against the pinned fixture rows.
func TestPostgresCLITablespaceListExists(t *testing.T) {
	csv := `Name,Owner,ACL,Opts,Location
pg_default,postgres,,,
test_tablespace,testuser,,,/tmp/posgrest_test_tablespace
`
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(csv)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.tablespace_list",
		"--user", "testuser", "-o", "json")
	var tablespaces map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &tablespaces) != nil {
		t.Fatalf("tablespace_list code=%d out=%q err=%q", code, out, errS)
	}
	if tablespaces["test_tablespace"]["Location"] != "/tmp/posgrest_test_tablespace" ||
		tablespaces["pg_default"]["Owner"] != "postgres" {
		t.Fatalf("tablespace_list JSON = %q", out)
	}

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"test_tablespace", true},
		{"bad_test_tablespace", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(csv)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres.tablespace_exists",
			"--name", tc.name, "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("tablespace_exists(%q) code=%d out=%q err=%q", tc.name, code, out, errS)
		}
	}
}

// TestPostgresCLIUserList pins the end-to-end user_list contract: the
// version probe plus the role query, the typed JSON rendering (booleans,
// null connections, RFC3339 expiry, empty groups), the return_password
// surface, Salt's false on an unanswered version probe, and the runas
// rejection.
func TestPostgresCLIUserList(t *testing.T) {
	csv := `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_user,t,t,t,t,t,t,,-1,,2017-08-16 08:57:46,
`
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(csv)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.user_list",
		"--user", "test_user", "--host", "test_host", "--port", "test_port",
		"--maintenance-db", "test_maint", "--password", "test_pass", "-o", "json")
	var users map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &users) != nil {
		t.Fatalf("user_list code=%d out=%q err=%q", code, out, errS)
	}
	entry := users["test_user"]
	groups, hasGroups := entry["groups"].([]any)
	if entry["superuser"] != true || entry["connections"] != nil || !hasGroups || len(groups) != 0 {
		t.Fatalf("user_list JSON entry = %q", out)
	}
	if expiry, _ := entry["expiry time"].(string); expiry != "2017-08-16T08:57:46Z" {
		t.Fatalf("expiry time = %#v", entry["expiry time"])
	}
	if _, hasPassword := entry["password"]; hasPassword {
		t.Fatalf("user_list exposed password column: %q", out)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// return_password adds the password column and joins.
	passwordCSV := `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables,password
test_user,f,t,t,t,f,t,,10,"{admins}",,,"md5abcdef"
`
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("15.7\n")},
		{ExitCode: 0, Stdout: []byte(passwordCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_list",
		"--return-password", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("return_password code=%d out=%q err=%q", code, out, errS)
	}
	if json.Unmarshal([]byte(out), &users) != nil || users["test_user"]["password"] != "md5abcdef" {
		t.Fatalf("return_password JSON = %q", out)
	}
	joined := strings.Join(runner.calls[1].Args, "\x00")
	if !strings.Contains(joined, "pg_authid") || !strings.Contains(joined, "pg_shadow") {
		t.Fatalf("return_password query lacks the password joins: %q", joined)
	}

	// Salt's logged-error-then-False for an unanswered version probe
	// renders as JSON false after exactly one psql call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_list", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "false" {
		t.Fatalf("unanswered version code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unanswered version executed %d commands", len(runner.calls))
	}

	// runas is rejected before any Runner invocation.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_list", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// crlfCLIListDBCSV carries a database Name with an embedded CRLF, exactly as
// psql COPY CSV emits it (quoted field, literal CRLF inside).
const crlfCLIListDBCSV = "Name,Owner,Encoding,Collate,Ctype,Access privileges,Tablespace\r\n" +
	"db1,postgres,UTF8,C,C,,pg_default\r\n" +
	"\"r\r\ndb\",postgres,UTF8,C,C,,pg_default\n"

// TestPostgresCLICatalogCRLF pins the CLI half of the embedded-CRLF
// contract: db_list renders the byte-exact key in JSON, db_exists matches
// the original name against it, and neither the rendered command nor the
// CLI output leaks the password or echoes the lookup name as SQL.
func TestPostgresCLICatalogCRLF(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(crlfCLIListDBCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.db_list", "-o", "json")
	var databases map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &databases) != nil {
		t.Fatalf("db_list code=%d out=%q err=%q", code, out, errS)
	}
	if _, has := databases["r\r\ndb"]; !has || databases["r\r\ndb"]["Owner"] != "postgres" {
		t.Fatalf("db_list JSON = %q, want embedded-CRLF key", out)
	}
	if !strings.Contains(out, "r\\r\\ndb") {
		t.Fatalf("db_list JSON lacks the escaped CRLF key: %q", out)
	}
	if strings.Contains(out+errS, "COPY (SELECT") {
		t.Fatalf("CLI output leaks the source SQL: %q", out+errS)
	}

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"r\r\ndb", true},
		{"absent\r\ndb", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(crlfCLIListDBCSV)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres.db_exists",
			"--name", tc.name, "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("db_exists(%q) code=%d out=%q err=%q", tc.name, code, out, errS)
		}
		if strings.Contains(strings.Join(runner.calls[len(runner.calls)-1].Args, "\x00"), tc.name) {
			t.Fatalf("db_exists leaked the lookup name into argv: %q", tc.name)
		}
	}

	// user_list through the CLI: a CRLF groups element survives both CSV
	// layers and renders as JSON data.
	groupsCell := `"{""a` + "\r\n" + `b"",c}"`
	userCSV := "name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\n" +
		"test_user,t,t,t,t,t,t,t,-1," + groupsCell + ",,\n"
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_list", "-o", "json")
	var users map[string]map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &users) != nil {
		t.Fatalf("user_list code=%d out=%q err=%q", code, out, errS)
	}
	groups, ok := users["test_user"]["groups"].([]any)
	if !ok || len(groups) != 2 || groups[0] != "a\r\nb" || groups[1] != "c" {
		t.Fatalf("user_list groups JSON = %q", out)
	}
	if strings.Contains(out+errS, "test_pass") {
		t.Fatalf("CLI output leaks password: %q %q", out, errS)
	}
}

// pinnedCLIExtensionsCSV renders pg_available_extensions output as COPY CSV.
const pinnedCLIExtensionsCSV = `name,default_version,installed_version,comment
cube,1.2,,"geometric data type for points, lines, and boxes"
plpgsql,1.0,1.0,PL/pgSQL procedural language
`

// pinnedCLIInstalledExtensionsCSV renders the pg_extension × pg_namespace
// join of the pinned installed_extensions query as COPY CSV.
const pinnedCLIInstalledExtensionsCSV = `oid,extname,extowner,extnamespace,extrelocatable,extversion,extconfig,extcondition,schema_name
16386,plpgsql,10,11,f,1.0,,,pg_catalog
`

// TestPostgresCLIExtensions drives the six extension functions end to end:
// the JSON dictionaries match the parsed catalogs, get_* render the row
// object or null, is_* render the pinned booleans (case-insensitive
// available, exact-case installed), and the argv embeds the fixed SQL with
// no password leak.
func TestPostgresCLIExtensions(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIExtensionsCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.available_extensions",
		"--user", "test_user", "--host", "test_host", "--port", "test_port",
		"--maintenance-db", "test_maint", "--password", "test_pass", "-o", "json")
	var extensions map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &extensions) != nil {
		t.Fatalf("available_extensions code=%d out=%q err=%q", code, out, errS)
	}
	if len(extensions) != 2 || extensions["cube"]["default_version"] != "1.2" ||
		extensions["cube"]["comment"] != "geometric data type for points, lines, and boxes" ||
		extensions["plpgsql"]["installed_version"] != "1.0" {
		t.Fatalf("available_extensions JSON = %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if argv[13] != "-v" || argv[14] != "datestyle=ISO,MDY" || argv[15] != "-c" ||
		argv[16] != "COPY (select * from pg_available_extensions()) TO STDOUT WITH CSV HEADER" {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(command.RedactedString(), "test_pass") || strings.Contains(out+errS, "test_pass") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIInstalledExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.installed_extensions", "-o", "json")
	var installed map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &installed) != nil {
		t.Fatalf("installed_extensions code=%d out=%q err=%q", code, out, errS)
	}
	if len(installed) != 1 || installed["plpgsql"]["extversion"] != "1.0" ||
		installed["plpgsql"]["schema_name"] != "pg_catalog" {
		t.Fatalf("installed_extensions JSON = %q", out)
	}
	if strings.Contains(out+errS, "pg_namespace") {
		t.Fatalf("CLI output leaks the source SQL: %q", out+errS)
	}

	// get_available_extension: the row object for a hit, null for a miss.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.get_available_extension",
		"--name", "cube", "-o", "json")
	var row map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &row) != nil ||
		row["default_version"] != "1.2" || row["name"] != "cube" {
		t.Fatalf("get_available_extension code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.get_available_extension",
		"--name", "absent", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("get_available_extension(miss) code=%d out=%q err=%q, want null", code, out, errS)
	}

	// get_installed_extension mirrors the same contract.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIInstalledExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.get_installed_extension",
		"--name", "plpgsql", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &row) != nil ||
		row["extversion"] != "1.0" {
		t.Fatalf("get_installed_extension code=%d out=%q err=%q", code, out, errS)
	}

	// is_available_extension lowercases both sides (PLPGSQL matches);
	// is_installed_extension reads the installed catalog instead.
	for _, tc := range []struct {
		fn, name, csv string
		want          bool
	}{
		{"is_available_extension", "PLPGSQL", pinnedCLIExtensionsCSV, true},
		{"is_available_extension", "Cube", pinnedCLIExtensionsCSV, true},
		{"is_available_extension", "absent", pinnedCLIExtensionsCSV, false},
		{"is_installed_extension", "plpgsql", pinnedCLIInstalledExtensionsCSV, true},
		{"is_installed_extension", "PLPGSQL", pinnedCLIInstalledExtensionsCSV, false},
		{"is_installed_extension", "cube", pinnedCLIInstalledExtensionsCSV, false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(tc.csv)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres."+tc.fn,
			"--name", tc.name, "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("%s(%q) code=%d out=%q err=%q", tc.fn, tc.name, code, out, errS)
		}
		// The lookup name never reaches the SQL argument.
		args := runner.calls[0].Args
		if got := args[len(args)-1]; !strings.HasPrefix(got, "COPY (") || strings.Contains(got, tc.name) {
			t.Fatalf("%s(%q) SQL arg = %q, want the fixed catalog query", tc.fn, tc.name, got)
		}
	}

	// A failed query keeps Salt's compatibility shapes: empty catalogs,
	// null views, false predicates.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.available_extensions", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "{}" {
		t.Fatalf("failed available_extensions code=%d out=%q err=%q, want {}", code, out, errS)
	}

	// runas is rejected before any Runner invocation, and the required
	// name is validated.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.is_installed_extension",
		"--name", "plpgsql", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.get_available_extension", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// pinnedCLILanguageCSV is the pinned get_test_list_language_csv fixture.
const pinnedCLILanguageCSV = "Name\ninternal\nc\nsql\nplpgsql\n"

// TestPostgresCLILanguage pins the language functions end to end: the
// name→name JSON dictionary against the pinned fixture, the exact-case
// language_exists booleans, the required maintenance_db validation, and
// the fixed lanname SQL with no credential leak.
func TestPostgresCLILanguage(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.language_list",
		"--maintenance-db", "testdb", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--password", "foo", "-o", "json")
	var languages map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &languages) != nil {
		t.Fatalf("language_list code=%d out=%q err=%q", code, out, errS)
	}
	if len(languages) != 4 || languages["sql"] != "sql" || languages["plpgsql"] != "plpgsql" ||
		languages["internal"] != "internal" || languages["c"] != "c" {
		t.Fatalf("language_list JSON = %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if argv[5] != "--username" || argv[6] != "testuser" || argv[11] != "--dbname" || argv[12] != "testdb" ||
		argv[15] != "-c" || argv[16] != `COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER` {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(command.RedactedString(), "foo") || strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"sql", true},
		{"c", true},
		{"SQL", false},
		{"absent", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres.language_exists",
			"--name", tc.name, "--maintenance-db", "testdb", "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("language_exists(%q) code=%d out=%q err=%q", tc.name, code, out, errS)
		}
		args := runner.calls[0].Args
		if got := args[len(args)-1]; got != `COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER` {
			t.Fatalf("language_exists(%q) SQL arg = %q, want the fixed catalog query", tc.name, got)
		}
	}

	// The pinned maintenance_db positional is required: omitting it fails
	// validation before any run, for both language functions.
	for _, fn := range []string{"postgres.language_list", "postgres.language_exists"} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		args := []string{"exec", fn}
		if fn == "postgres.language_exists" {
			args = append(args, "--name", "sql")
		}
		args = append(args, "-o", "json")
		code, _, errS := captureCode(t, app, args...)
		if code != ExitInvalidInput || !strings.Contains(errS, "maintenance_db") || len(runner.calls) != 0 {
			t.Fatalf("%s missing maintenance_db code=%d err=%q calls=%d", fn, code, errS, len(runner.calls))
		}
	}

	// A failed query keeps Salt's compatibility shapes.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.language_list",
		"--maintenance-db", "testdb", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "{}" {
		t.Fatalf("failed language_list code=%d out=%q err=%q, want {}", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.language_exists",
		"--name", "sql", "--maintenance-db", "testdb", "-o", "json")
	var value bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("failed language_exists code=%d out=%q err=%q, want false", code, out, errS)
	}
}

// pinnedCLISchemaCSV is the pinned get_test_list_schema_csv fixture.
const pinnedCLISchemaCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n" +
	"pg_toast,postgres,\"\"\n"

// TestPostgresCLISchema pins the three schema functions end to end: the
// owner/acl JSON dictionary against the pinned fixture, the schema_get row
// object or null, the schema_exists booleans, the pinned db_* flag surface
// with the required dbname, and the fixed pg_namespace SQL with no
// credential leak.
func TestPostgresCLISchema(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLISchemaCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.schema_list",
		"--dbname", "maint_db", "--db_user", "testuser", "--db_host", "testhost",
		"--db_port", "testport", "--db_password", "foo", "-o", "json")
	var schemas map[string]map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &schemas) != nil {
		t.Fatalf("schema_list code=%d out=%q err=%q", code, out, errS)
	}
	if len(schemas) != 2 || schemas["public"]["acl"] != "{postgres=UC/postgres,=UC/postgres}" ||
		schemas["public"]["owner"] != "postgres" || schemas["pg_toast"]["acl"] != "" {
		t.Fatalf("schema_list JSON = %q", out)
	}
	if _, hasName := schemas["public"]["name"]; hasName {
		t.Fatalf("schema_list exposed the name column: %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if argv[0] != "psql" || argv[5] != "--username" || argv[6] != "testuser" ||
		argv[7] != "--host" || argv[8] != "testhost" || argv[9] != "--port" || argv[10] != "testport" ||
		argv[11] != "--dbname" || argv[12] != "maint_db" || argv[15] != "-c" ||
		argv[16] != `COPY (SELECT pg_namespace.nspname as "name",pg_namespace.nspacl as "acl", `+
			`pg_roles.rolname as "owner" FROM pg_namespace LEFT JOIN `+
			`pg_roles ON pg_roles.oid = pg_namespace.nspowner) TO STDOUT WITH CSV HEADER` {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(command.RedactedString(), "foo") || strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}
	if strings.Contains(out+errS, "pg_namespace") {
		t.Fatalf("CLI output leaks the source SQL: %q", out+errS)
	}

	// schema_get: the owner/acl row object for a hit, null for a miss.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLISchemaCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_get",
		"--dbname", "template1", "--name", "public", "-o", "json")
	var row map[string]string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &row) != nil ||
		row["owner"] != "postgres" || row["acl"] != "{postgres=UC/postgres,=UC/postgres}" {
		t.Fatalf("schema_get code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLISchemaCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_get",
		"--dbname", "template1", "--name", "pg_catalog", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("schema_get(miss) code=%d out=%q err=%q, want null", code, out, errS)
	}
	if joined := strings.Join(runner.calls[0].Args, "\x00"); strings.Contains(joined, "pg_catalog") {
		t.Fatalf("schema_get leaked the lookup name into argv: %q", joined)
	}

	// schema_exists: exact-case booleans, the lookup never reaching SQL.
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"public", true},
		{"pg_toast", true},
		{"PUBLIC", false},
		{"absent", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(pinnedCLISchemaCSV)},
		}}
		app := postgresCLIApp(t, runner)
		code, out, errS := captureCode(t, app, "exec", "postgres.schema_exists",
			"--dbname", "template1", "--name", tc.name, "-o", "json")
		var value bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != tc.want {
			t.Fatalf("schema_exists(%q) code=%d out=%q err=%q", tc.name, code, out, errS)
		}
		args := runner.calls[0].Args
		if got := args[len(args)-1]; !strings.HasPrefix(got, "COPY (SELECT pg_namespace.nspname") {
			t.Fatalf("schema_exists(%q) SQL arg = %q, want the fixed catalog query", tc.name, got)
		}
	}

	// The pinned dbname positional is required: omitting it fails
	// validation before any run, for all three schema functions.
	for _, fn := range []string{"postgres.schema_list", "postgres.schema_get", "postgres.schema_exists"} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		args := []string{"exec", fn}
		if fn != "postgres.schema_list" {
			args = append(args, "--name", "public")
		}
		args = append(args, "-o", "json")
		code, _, errS := captureCode(t, app, args...)
		if code != ExitInvalidInput || !strings.Contains(errS, "dbname") || len(runner.calls) != 0 {
			t.Fatalf("%s missing dbname code=%d err=%q calls=%d", fn, code, errS, len(runner.calls))
		}
	}

	// schema_get/schema_exists also require the name.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_get", "--dbname", "template1", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("schema_get missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// The pinned system-user argument is rejected as runas before any
	// Runner invocation.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_list",
		"--dbname", "maint_db", "--user", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("user code=%d err=%q calls=%d, want runas rejection", code, errS, len(runner.calls))
	}

	// A failed query keeps Salt's compatibility shapes: empty catalog,
	// null view, false predicate.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_list",
		"--dbname", "maint_db", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "{}" {
		t.Fatalf("failed schema_list code=%d out=%q err=%q, want {}", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_get",
		"--dbname", "template1", "--name", "public", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("failed schema_get code=%d out=%q err=%q, want null", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_exists",
		"--dbname", "template1", "--name", "public", "-o", "json")
	var value bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("failed schema_exists code=%d out=%q err=%q, want false", code, out, errS)
	}
}

// roleCLIUsersCSV is the two-role user_list catalog for the R9.2f CLI
// tests, with a second role whose row keeps the empty-string defaults.
const roleCLIUsersCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_user,t,t,t,t,t,t,,-1,,2017-08-16 08:57:46,
other_user,f,f,f,f,f,f,,10,,,
`

// TestPostgresCLIRoleGetUserExists drives role_get and user_exists end to
// end: the typed JSON row rendering, the null miss, Salt's null False
// catalog, the boolean user_exists shapes, the required name, and the
// runas rejection — with no password in any rendered output.
func TestPostgresCLIRoleGetUserExists(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(roleCLIUsersCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.role_get",
		"--name", "test_user", "--user", "test_user", "--host", "test_host",
		"--port", "test_port", "--maintenance-db", "test_maint",
		"--password", "test_pass", "-o", "json")
	var row map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &row) != nil {
		t.Fatalf("role_get code=%d out=%q err=%q", code, out, errS)
	}
	if row["superuser"] != true || row["connections"] != nil {
		t.Fatalf("role_get JSON row = %q", out)
	}
	if _, hasPassword := row["password"]; hasPassword {
		t.Fatalf("role_get exposed password column: %q", out)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("role_get calls = %d, want 2", len(runner.calls))
	}
	if strings.Contains(out+errS, "test_pass") ||
		strings.Contains(runner.calls[0].RedactedString(), "test_pass") {
		t.Fatalf("password leaked: %q %q", out+errS, runner.calls[0].RedactedString())
	}

	// A miss renders null; the unanswered version probe (Salt's False
	// catalog through the pinned AttributeError branch) renders null too.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(roleCLIUsersCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.role_get", "--name", "absent_user", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("role_get miss code=%d out=%q err=%q, want null", code, out, errS)
	}

	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.role_get", "--name", "test_user", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("role_get unanswered code=%d out=%q err=%q, want null", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("role_get unanswered calls = %d, want 1", len(runner.calls))
	}

	// user_exists renders the bool(dict(role_get)) shapes.
	for _, tc := range []struct {
		name  string
		want  string
		calls int
	}{
		{"test_user", "true", 2},
		{"absent_user", "false", 2},
	} {
		runner = &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("9.1\n")},
			{ExitCode: 0, Stdout: []byte(roleCLIUsersCSV)},
		}}
		app = postgresCLIApp(t, runner)
		code, out, errS = captureCode(t, app, "exec", "postgres.user_exists", "--name", tc.name, "-o", "json")
		if code != ExitOK || errS != "" || strings.TrimSpace(out) != tc.want {
			t.Fatalf("user_exists(%q) code=%d out=%q err=%q, want %s", tc.name, code, out, errS, tc.want)
		}
		if len(runner.calls) != tc.calls {
			t.Fatalf("user_exists(%q) calls = %d, want %d", tc.name, len(runner.calls), tc.calls)
		}
	}

	// The name argument is required.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.role_get", "-o", "json")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("role_get without name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// runas is rejected before any Runner invocation.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_exists", "--name", "test_user",
		"--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("user_exists runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// ownerCLITableCSV and privCLITableCSV carry the fixed table owner and
// privilege catalogs for the CLI has_privileges flow; the ACL string is
// the pinned get_test_privileges_list_table_csv payload verbatim.
const (
	ownerCLITableCSV = `schemaname,tablename,name
public,awl,postgres
public,other_table,postgres
`
	privCLITableCSV = `nspname,relname,relkind,name
public,awl,r,"{baruwatest=arwdDxtm/baruwatest,bayestest=arwd/baruwatest,baruwa=a*r*w*d*D*x*t*m*/baruwatest}"
`
	privCLIGroupCSV = `member_of,rolname,admin_option
admin,baruwa,f
admin,baruwatest2,t
`
)

// TestPostgresCLIHasPrivileges drives has_privileges end to end for the
// table and group flows: the two fixed catalog queries, the boolean JSON
// rendering, the grant-option flag, validation failures before any psql
// call, and the nonzero-exit compatibility shape.
func TestPostgresCLIDefaultPrivilegesListValidationRedaction(t *testing.T) {
	const marker = "synthetic_defpriv_list_marker"
	for _, objectType := range []string{marker, "invalid_" + marker + "_type"} {
		t.Run(objectType, func(t *testing.T) {
			runner := &cliRecordingRunner{}
			app := postgresCLIApp(t, runner)
			code, out, errS := captureCode(t, app, "exec", "postgres.default_privileges_list",
				"--name", "awl", "--object-type", objectType, "--password", marker, "-o", "json")
			if code != ExitFailed || out != "" || errS != "statekit: postgres: invalid argument: invalid object_type\n" {
				t.Fatal("expected exit failure, empty stdout and stable value-free stderr")
			}
			if strings.Contains(out+errS, marker) || len(runner.calls) != 0 {
				t.Fatal("validation leaked input or invoked Runner")
			}
		})
	}
}

func TestPostgresCLIPrivilegesValidationRedaction(t *testing.T) {
	const marker = "synthetic_privilege_marker"
	for _, function := range []string{"postgres.privileges_grant", "postgres.privileges_revoke", "postgres.has_privileges"} {
		for _, field := range []string{"privileges", "object_type"} {
			t.Run(function+"/"+field, func(t *testing.T) {
				objectType, privileges := "table", "SELECT,"+marker
				if field == "object_type" {
					objectType, privileges = marker, "SELECT"
				}
				runner := &cliRecordingRunner{}
				app := postgresCLIApp(t, runner)
				code, out, errS := captureCode(t, app, "exec", function,
					"--name", "baruwa", "--object-name", "awl", "--object-type", objectType,
					"--privileges", privileges, "--password", marker, "-o", "json")
				if code != ExitFailed || errS != "statekit: postgres: invalid argument: invalid "+field+"\n" {
					t.Fatal("expected stable CLI invalid-argument failure")
				}
				if out != "" || strings.Contains(out+errS, marker) || len(runner.calls) != 0 {
					t.Fatal("CLI validation leaked input or invoked Runner")
				}
			})
		}
	}
}

func TestPostgresCLIHasPrivileges(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLITableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.has_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "SELECT,INSERT", "--grant-option",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var value bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != true {
		t.Fatalf("has_privileges code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("has_privileges calls = %d, want 2", len(runner.calls))
	}
	for i, call := range runner.calls {
		sqlArg := call.Args[len(call.Args)-1]
		if !strings.HasPrefix(sqlArg, "COPY (SELECT ") {
			t.Fatalf("call %d SQL = %q", i, sqlArg)
		}
		if strings.Contains(sqlArg, "awl") || strings.Contains(sqlArg, "baruwa") {
			t.Fatalf("call %d leaked a lookup string into SQL: %q", i, sqlArg)
		}
	}
	if strings.Contains(out+errS, "COPY (SELECT") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("CLI output leaked SQL or password: %q %q", out, errS)
	}

	// The subset miss renders false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLITableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_privileges",
		"--name", "bayestest", "--object-name", "awl", "--object-type", "table",
		"--privileges", "SELECT,INSERT,TRUNCATE", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("has_privileges miss code=%d out=%q err=%q", code, out, errS)
	}

	// The group flow: one call, membership true, admin check false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_privileges",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group",
		"-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != true {
		t.Fatalf("group membership code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_privileges",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group",
		"--grant-option", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("group admin check code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("group calls = %d, want 1", len(runner.calls))
	}

	// Validation failures surface as exit 1 before any psql call.
	for _, argv := range [][]string{
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "bogus", "--privileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--privileges", "BOGUS"},
		{"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "--privileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.has_privileges"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || len(runner.calls) != 0 {
			t.Fatalf("validation %v code=%d err=%q calls=%d", argv, code, errS, len(runner.calls))
		}
	}

	// A failed connection keeps Salt's shape: no exception, false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "SELECT", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}
}

// defCLIHasTableCSV renders the fixed pg_default_acl table catalog with
// the R9.2l grant-starred payload: baruwa holds every table privilege
// with the grant option, baruwatest the plain subset.
const defCLIHasTableCSV = `nspname,name
public,"{baruwatest=arwd/baruwatest,baruwa=a*r*w*d*D*x*t*/public}"
`

// TestPostgresCLIHasDefaultPrivileges drives the R9.2q read-only check
// end to end: the two fixed catalog queries with no caller string inside
// the SQL, the boolean JSON rendering with and without the grant-option
// flag, the group membership and admin_option flows, the pinned ALL
// comparison surfacing as the stable value-free failure, validation
// failures before any psql call, and the nonzero-exit compatibility
// shape.
func TestPostgresCLIHasDefaultPrivileges(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIHasTableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT,INSERT", "--grant-option",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var value bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != true {
		t.Fatalf("has_default_privileges code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("has_default_privileges calls = %d, want 2", len(runner.calls))
	}
	for i, call := range runner.calls {
		sqlArg := call.Args[len(call.Args)-1]
		if !strings.HasPrefix(sqlArg, "COPY (SELECT ") {
			t.Fatalf("call %d SQL = %q", i, sqlArg)
		}
		if strings.Contains(sqlArg, "awl") || strings.Contains(sqlArg, "baruwa") {
			t.Fatalf("call %d leaked a lookup string into SQL: %q", i, sqlArg)
		}
	}
	if strings.Contains(out+errS, "COPY (SELECT") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("CLI output leaked SQL or password: %q %q", out, errS)
	}

	// The subset miss renders false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIHasTableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "bayestest", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("has_default_privileges miss code=%d out=%q err=%q", code, out, errS)
	}

	// The grant-option dict equality: the plain-row grantee answers
	// false under the flag.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLITableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT,INSERT", "--grant-option", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("grant-option miss code=%d out=%q err=%q", code, out, errS)
	}

	// The pinned ALL comparison against a grantee holding a default ACL
	// entry is the stable value-free failure; against an absent grantee
	// it is the false preflight miss.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIHasTableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "ALL", "-o", "json")
	if code != ExitFailed || out != "" ||
		errS != "statekit: postgres: invalid argument: default privileges all comparison unavailable\n" {
		t.Fatalf("held ALL code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "ALL", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("absent ALL code=%d out=%q err=%q", code, out, errS)
	}

	// The group flow: one call, membership true, admin check false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group",
		"-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != true {
		t.Fatalf("group membership code=%d out=%q err=%q", code, out, errS)
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group",
		"--grant-option", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("group admin check code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("group calls = %d, want 1", len(runner.calls))
	}

	// Validation failures surface as exit 1 before any psql call,
	// including the default-privilege allowlist rejections.
	for _, argv := range [][]string{
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "bogus", "--defprivileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "BOGUS"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "CONNECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "TEMPORARY"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "MAINTAIN"},
		{"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "--defprivileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.has_default_privileges"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || len(runner.calls) != 0 {
			t.Fatalf("validation %v code=%d err=%q calls=%d", argv, code, errS, len(runner.calls))
		}
	}

	// The required positionals are validated before any psql call.
	for _, argv := range [][]string{
		{"--object-name", "awl", "--object-type", "table", "--defprivileges", "SELECT"},
		{"--name", "baruwa", "--object-type", "table", "--defprivileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--defprivileges", "SELECT"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.has_default_privileges"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
			len(runner.calls) != 0 {
			t.Fatalf("required %v code=%d err=%q calls=%d", argv, code, errS, len(runner.calls))
		}
	}

	// A failed connection keeps Salt's shape: no exception, false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.has_default_privileges",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &value) != nil || value != false {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}
}

// metaCLIRelocatableCSV renders the installed-extensions catalog with a
// relocatable foo row for the R9.2r lifecycle flags.
const metaCLIRelocatableCSV = `oid,extname,extowner,extnamespace,extrelocatable,extversion,extconfig,extcondition,schema_name
16386,foo,10,11,t,0.8,,,foo
`

// TestPostgresCLICreateMetadata drives the R9.2r read-only check end to
// end: the single fixed catalog query with no caller string inside the
// SQL, the flag-list JSON rendering for the miss and every lifecycle
// combination, the pinned empty-string quirks, the exact-case lookup,
// validation failures before any psql call, and the nonzero-exit
// compatibility shape.
func TestPostgresCLICreateMetadata(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(metaCLIRelocatableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.create_metadata",
		"--name", "foo", "--ext-version", "1.4", "--schema", "b",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var flags []string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &flags) != nil ||
		!reflect.DeepEqual(flags, []string{"EXTENSION INSTALLED", "EXTENSION TO UPGRADE", "EXTENSION TO MOVE"}) {
		t.Fatalf("create_metadata code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("create_metadata calls = %d, want 1", len(runner.calls))
	}
	call := runner.calls[0]
	sqlArg := call.Args[len(call.Args)-1]
	if sqlArg != "COPY (select a.*, b.nspname as schema_name from pg_extension a,  pg_namespace b where a.extnamespace = b.oid) TO STDOUT WITH CSV HEADER" {
		t.Fatalf("create_metadata SQL = %q", sqlArg)
	}
	// Neither the extension name, the requested version, nor the requested
	// schema ever reaches the argv; the password stays out of band.
	joined := strings.Join(call.Args, "\x00")
	for _, leaked := range []string{"foo", "--name", "--ext-version", "--schema", "1.4", "testpassword"} {
		if strings.Contains(joined, leaked) {
			t.Fatalf("argv leaked %q: %q", leaked, joined)
		}
	}
	if !strings.Contains(joined, "--dbname\x00db_name") {
		t.Fatalf("argv misses the maintenance database: %q", joined)
	}
	if strings.Contains(out+errS, "COPY (select") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("CLI output leaked SQL or password: %q %q", out, errS)
	}

	// The miss renders the single NOT_INSTALLED flag.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIInstalledExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_metadata",
		"--name", "cube", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &flags) != nil ||
		!reflect.DeepEqual(flags, []string{"EXTENSION NOT INSTALLED"}) {
		t.Fatalf("create_metadata miss code=%d out=%q err=%q", code, out, errS)
	}

	// The installed lookup is exact-case: PLPGSQL misses the plpgsql row.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLIInstalledExtensionsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_metadata",
		"--name", "PLPGSQL", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &flags) != nil ||
		!reflect.DeepEqual(flags, []string{"EXTENSION NOT INSTALLED"}) {
		t.Fatalf("create_metadata case miss code=%d out=%q err=%q", code, out, errS)
	}

	// The upgrade flag alone, and the pinned empty-string quirks: an
	// explicit empty --ext-version keeps the INSTALLED-only answer while
	// an explicit empty --schema moves the relocatable row.
	for _, tc := range []struct {
		label string
		argv  []string
		want  []string
	}{
		{"upgrade only", []string{"--name", "foo", "--ext-version", "1.4"},
			[]string{"EXTENSION INSTALLED", "EXTENSION TO UPGRADE"}},
		{"empty ext_version", []string{"--name", "foo", "--ext-version", ""},
			[]string{"EXTENSION INSTALLED"}},
		{"empty schema moves", []string{"--name", "foo", "--schema", ""},
			[]string{"EXTENSION INSTALLED", "EXTENSION TO MOVE"}},
	} {
		runner = &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte(metaCLIRelocatableCSV)},
		}}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.create_metadata"}, tc.argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, out, errS = captureCode(t, app, fullArgv...)
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &flags) != nil ||
			!reflect.DeepEqual(flags, tc.want) {
			t.Fatalf("%s code=%d out=%q err=%q, want %q", tc.label, code, out, errS, tc.want)
		}
	}

	// The required name is validated before any psql call.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.create_metadata",
		"--ext-version", "1.4", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
		len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// runas is rejected before any Runner invocation.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.create_metadata",
		"--name", "foo", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// A failed connection keeps Salt's shape: no exception, the empty
	// catalog answers the single NOT_INSTALLED flag.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_metadata",
		"--name", "foo", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &flags) != nil ||
		!reflect.DeepEqual(flags, []string{"EXTENSION NOT INSTALLED"}) {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want NOT_INSTALLED", code, out, errS)
	}
}

// TestPostgresCLIPrivilegesList drives privileges_list end to end for the
// table and group flows: the pinned dictionaries render as nested JSON,
// the single fixed catalog query embeds no caller string, the required
// arguments are validated before any psql call, and the nonzero-exit
// compatibility shape stays the empty dictionary.
func TestPostgresCLIPrivilegesList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLITableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.privileges_list",
		"--name", "awl", "--object-type", "table", "--prepend", "public",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var table map[string]map[string]bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &table) != nil {
		t.Fatalf("privileges_list code=%d out=%q err=%q", code, out, errS)
	}
	if len(table) != 3 || table["baruwa"]["INSERT"] != true || table["baruwa"]["MAINTAIN"] != true ||
		table["baruwatest"]["TRUNCATE"] != false || table["bayestest"]["DELETE"] != false {
		t.Fatalf("privileges_list table JSON = %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("privileges_list calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if argv[15] != "-c" || argv[16] != `COPY (SELECT nspname, relname, relkind, relacl AS name FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE relkind in ('r', 'v') ORDER BY relname) TO STDOUT WITH CSV HEADER` {
		t.Fatalf("argv SQL = %q", argv)
	}
	if strings.Contains(argv[16], "awl") || strings.Contains(argv[16], "public") {
		t.Fatalf("SQL leaked a lookup string: %q", argv[16])
	}
	if strings.Contains(command.RedactedString(), "testpassword") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}
	if strings.Contains(out+errS, "COPY (SELECT") {
		t.Fatalf("CLI output leaked the source SQL: %q %q", out, errS)
	}

	// The group flow: each member renders as its admin_option boolean.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_list",
		"--name", "admin", "--object-type", "group", "-o", "json")
	var group map[string]bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &group) != nil {
		t.Fatalf("group code=%d out=%q err=%q", code, out, errS)
	}
	if len(group) != 2 || group["baruwa"] != false || group["baruwatest2"] != true {
		t.Fatalf("group JSON = %q", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("group calls = %d, want 1", len(runner.calls))
	}

	// The two required positionals are validated before any psql call.
	for _, argv := range [][]string{
		{"--object-type", "table"},
		{"--name", "awl"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.privileges_list"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
			len(runner.calls) != 0 {
			t.Fatalf("required %v code=%d err=%q calls=%d", argv, code, errS, len(runner.calls))
		}
	}

	// An unknown object type and runas fail before any psql call.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.privileges_list",
		"--name", "awl", "--object-type", "bogus", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "object_type") || len(runner.calls) != 0 {
		t.Fatalf("bogus object_type code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.privileges_list",
		"--name", "awl", "--object-type", "table", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// A failed connection keeps Salt's shape: no exception, the empty
	// dictionary.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 2, Stderr: []byte("psql: error: connection refused")},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_list",
		"--name", "awl", "--object-type", "table", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "{}" {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want {}", code, out, errS)
	}
}

// TestPostgresCLIDbCreate drives the R9.2h write path end to end: the
// pinned CREATE DATABASE statement through the fake Runner, the JSON true
// rendering, the retcode-false compatibility shape, the fail-closed
// identifier boundary, the required name, and the runas rejection, with no
// password anywhere in the rendered command or CLI output.
func TestPostgresCLIDbCreate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.db_create",
		"--name", "dbname", "--tablespace", "testspace", "--owner", "otheruser",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("db_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `CREATE DATABASE "dbname" WITH TABLESPACE = "testspace" OWNER = "otheruser"` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=foo" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "foo") || strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A rejected CREATE keeps Salt's retcode boolean: exit OK, JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: database "dbname" already exists`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.db_create", "--name", "dbname", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// Injection attempts fail closed before any psql call, with the
	// value-free stable errors naming the argument key only.
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"name quote", []string{"--name", `db"; DROP DATABASE x; --`}, "postgres: invalid argument: unsupported quote character in name"},
		{"template sqli", []string{"--name", "db", "--template", "tpl; DROP DATABASE x"}, "postgres: invalid argument: unsupported template identifier"},
		{"literal sqli", []string{"--name", "db", "--lc-collate", "foo' ENCODING='utf8"}, "postgres: invalid argument: unsupported quote character in lc_collate"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append(append([]string{"exec", "postgres.db_create"}, tc.argv...), "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || !strings.Contains(errS, tc.want) || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}

	// The required name is validated before any psql call, and runas is
	// rejected the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_create", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_create",
		"--name", "dbname", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIDbRemove drives the R9.2h removal flow end to end: the
// three pinned statements in order, the JSON true rendering, the
// first-nonzero abort with its retcode-only error, the fail-closed name
// boundary, and no password in any rendered or CLI output.
func TestPostgresCLIDbRemove(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
		{ExitCode: 0},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.db_remove",
		"--name", "test_db", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("db_remove code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	wantStatements := []string{
		`REVOKE CONNECT ON DATABASE "test_db" FROM public;`,
		"SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'test_db' AND pid <> pg_backend_pid();",
		`DROP DATABASE "test_db";`,
	}
	for i, command := range runner.calls {
		argv := append([]string{command.Name}, command.Args...)
		if len(argv) != 15 || argv[13] != "-c" || argv[14] != wantStatements[i] {
			t.Fatalf("call %d argv = %q", i, argv)
		}
		if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
			t.Fatalf("call %d unsafe command: %#v", i, command)
		}
		if strings.Contains(command.RedactedString(), "foo") {
			t.Fatalf("call %d rendered command leaks password: %q", i, command.RedactedString())
		}
	}
	if strings.Contains(out+errS, "foo") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// A missing database aborts on the first statement with the pinned
	// Failed shape and never reaches the DROP.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: database "test_db" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_remove", "--name", "test_db", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "Failed: retcode=1") || len(runner.calls) != 1 {
		t.Fatalf("missing db code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	if strings.Contains(errS, "does not exist") {
		t.Fatalf("error embeds captured stderr: %q", errS)
	}

	// Injection attempts fail closed before any psql call, with the exact
	// value-free stable error.
	for _, name := range []string{`x'; DROP DATABASE postgres; --`, `x" `} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		code, _, errS = captureCode(t, app, "exec", "postgres.db_remove", "--name", name, "-o", "json")
		if code != ExitFailed ||
			!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in name") ||
			len(runner.calls) != 0 {
			t.Fatalf("injected name %q code=%d err=%q calls=%d", name, code, errS, len(runner.calls))
		}
	}

	// The required name is validated before any psql call.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_remove", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIDbAlter drives the R9.2n mutation end to end: the two
// pinned statements in the pinned order through the fake Runner, the JSON
// true rendering, the no-op True without any psql call, the retcode-false
// compatibility shape with its stop, the owner_recurse delegation into
// the registered owner_to flow, the fail-closed identifier boundary, the
// required name, and the runas rejection, with no password anywhere in
// the rendered command or CLI output.
func TestPostgresCLIDbAlter(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.db_alter",
		"--name", "dbname", "--owner", "otheruser", "--tablespace", "testspace",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var altered bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &altered) != nil || !altered {
		t.Fatalf("db_alter code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	wantStatements := []string{
		`ALTER DATABASE "dbname" OWNER TO "otheruser"`,
		`ALTER DATABASE "dbname" SET TABLESPACE "testspace"`,
	}
	for i, command := range runner.calls {
		argv := append([]string{command.Name}, command.Args...)
		if len(argv) != 15 || argv[13] != "-c" || argv[14] != wantStatements[i] {
			t.Fatalf("call %d argv = %q", i, argv)
		}
		if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
			t.Fatalf("call %d unsafe command: %#v", i, command)
		}
		if strings.Contains(command.RedactedString(), "foo") {
			t.Fatalf("call %d rendered command leaks password: %q", i, command.RedactedString())
		}
	}
	if strings.Contains(out+errS, "foo") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// The pinned no-op head: neither owner nor tablespace answers the
	// True without any psql call (an explicit empty string is Python-falsy
	// the same way).
	for _, argv := range [][]string{
		{"--name", "dbname"},
		{"--name", "dbname", "--owner", "", "--tablespace", ""},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.db_alter"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, out, errS = captureCode(t, app, fullArgv...)
		var noop bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &noop) != nil || !noop {
			t.Fatalf("noop %v code=%d out=%q err=%q", argv, code, out, errS)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("noop %v executed %d commands", argv, len(runner.calls))
		}
	}

	// A rejected first statement keeps Salt's retcode boolean — exit OK,
	// JSON false — and the stop means the TABLESPACE statement never runs.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: database "dbname" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.db_alter",
		"--name", "dbname", "--owner", "otheruser", "--tablespace", "testspace", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("nonzero exit calls = %d, want the stop after 1", len(runner.calls))
	}

	// owner_recurse delegates to the registered owner_to (R9.2s): the
	// five catalog queries run against the dbname — db_alter's
	// maintenance_db is dropped exactly like the pinned projection — and
	// the single -f - stdin script is the only mutation; the shallow ALTER
	// statements never run, whatever the tablespace argument carries.
	ownerToResults := []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("n\npublic\n")},
		{ExitCode: 0, Stdout: []byte("n\npublic.accounts\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0},
	}
	runner = &cliRecordingRunner{results: ownerToResults}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.db_alter",
		"--name", "dbname", "--owner", "otheruser", "--owner-recurse",
		"--tablespace", "testspace", "--maintenance-db", "maint_db", "-o", "json")
	var recursed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &recursed) != nil || !recursed {
		t.Fatalf("owner_recurse code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("owner_recurse calls = %d, want the owner_to flow", len(runner.calls))
	}
	for i := 0; i < 5; i++ {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if argv[5] != "--dbname" || argv[6] != "dbname" {
			t.Fatalf("owner_recurse catalog %d runs against %q, want the dbname", i, argv[6])
		}
	}
	delegated := append([]string{runner.calls[5].Name}, runner.calls[5].Args...)
	if delegated[len(delegated)-3] != "--set=ON_ERROR_STOP=on" ||
		delegated[len(delegated)-2] != "-f" || delegated[len(delegated)-1] != "-" {
		t.Fatalf("owner_recurse script argv = %q", delegated)
	}
	wantScript := "begin;\n" +
		"alter database \"dbname\" owner to \"otheruser\";\n" +
		"alter schema public owner to otheruser;\n" +
		"alter table public.accounts owner to otheruser;\n" +
		"commit;\n"
	if string(runner.calls[5].Stdin) != wantScript {
		t.Fatalf("owner_recurse script = %q, want %q", runner.calls[5].Stdin, wantScript)
	}
	for i, command := range runner.calls {
		argv := append([]string{command.Name}, command.Args...)
		for _, arg := range argv {
			if strings.Contains(strings.ToUpper(arg), "TABLESPACE") {
				t.Fatalf("owner_recurse call %d carries a shallow statement: %q", i, arg)
			}
		}
	}

	// Injection attempts fail closed before any psql call, with the exact
	// value-free stable errors naming the argument key only.
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"name quote", []string{"--name", `db"; DROP DATABASE x; --`, "--owner", "own"}, "postgres: invalid argument: unsupported quote character in name"},
		{"owner quote", []string{"--name", "db", "--owner", `oth"; DROP DATABASE x; --`}, "postgres: invalid argument: unsupported quote character in owner"},
		{"tablespace quote", []string{"--name", "db", "--tablespace", `ts"; DROP DATABASE x; --`}, "postgres: invalid argument: unsupported quote character in tablespace"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.db_alter"}, tc.argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || !strings.Contains(errS, tc.want) || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}

	// The required name is validated before any psql call, and runas is
	// rejected the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_alter",
		"--owner", "otheruser", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.db_alter",
		"--name", "dbname", "--owner", "otheruser", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIOwnerTo drives the R9.2s ownership mutation end to end:
// the five catalog queries and the single -f - stdin transaction script
// (with ON_ERROR_STOP before it) through the fake Runner, the JSON
// run_all mapping {retcode, stdout, stderr}, the password redaction, the
// retcode compatibility shape of a rejected script, the fail-closed
// identifier boundary (the quote-carrying dbname and the non-bare
// ownername), the required arguments, the runas rejection, and the
// redacted catalog failure.
func TestPostgresCLIOwnerTo(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("n\npublic\n")},
		{ExitCode: 0, Stdout: []byte("n\npublic.accounts\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("ALTER DATABASE\nALTER SCHEMA\n")},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.owner_to",
		"--dbname", "dbname", "--ownername", "otheruser",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--password", "foo", "-o", "json")
	var runAll map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &runAll) != nil ||
		len(runAll) != 3 || runAll["retcode"] != float64(0) ||
		runAll["stdout"] != "ALTER DATABASE\nALTER SCHEMA\n" || runAll["stderr"] != "" {
		t.Fatalf("owner_to code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("runner calls = %d, want 5 catalogs + 1 script", len(runner.calls))
	}
	wantCatalogSQL := []string{
		"COPY (select quote_ident(schema_name) as n from information_schema.schemata) TO STDOUT WITH CSV HEADER",
		"COPY (select quote_ident(table_schema)||'.'||quote_ident(table_name) as n from information_schema.tables where table_schema not in ('pg_catalog', 'information_schema')) TO STDOUT WITH CSV HEADER",
		"COPY (select p.oid::regprocedure::text as n from pg_catalog.pg_proc p join pg_catalog.pg_namespace ns on p.pronamespace=ns.oid where ns.nspname not in ('pg_catalog', 'information_schema')  and not p.proisagg) TO STDOUT WITH CSV HEADER",
		"COPY (select p.oid::regprocedure::text as n from pg_catalog.pg_proc p join pg_catalog.pg_namespace ns on p.pronamespace=ns.oid where ns.nspname not in ('pg_catalog', 'information_schema') and p.proisagg) TO STDOUT WITH CSV HEADER",
		"COPY (select quote_ident(sequence_schema)||'.'||quote_ident(sequence_name) as n from information_schema.sequences) TO STDOUT WITH CSV HEADER",
	}
	for i := 0; i < 5; i++ {
		argv := append([]string{runner.calls[i].Name}, runner.calls[i].Args...)
		if len(argv) != 17 || argv[13] != "-v" || argv[14] != "datestyle=ISO,MDY" ||
			argv[15] != "-c" || argv[16] != wantCatalogSQL[i] {
			t.Fatalf("catalog %d argv = %q", i, argv)
		}
		if command := runner.calls[i]; command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
			t.Fatalf("catalog %d unsafe command: %#v", i, command)
		}
		if strings.Contains(runner.calls[i].RedactedString(), "foo") {
			t.Fatalf("catalog %d rendered command leaks password", i)
		}
	}
	script := append([]string{runner.calls[5].Name}, runner.calls[5].Args...)
	if len(script) != 16 || script[13] != "--set=ON_ERROR_STOP=on" ||
		script[14] != "-f" || script[15] != "-" {
		t.Fatalf("script argv = %q", script)
	}
	wantScript := "begin;\n" +
		"alter database \"dbname\" owner to \"otheruser\";\n" +
		"alter schema public owner to otheruser;\n" +
		"alter table public.accounts owner to otheruser;\n" +
		"commit;\n"
	if string(runner.calls[5].Stdin) != wantScript {
		t.Fatalf("script stdin = %q, want %q", runner.calls[5].Stdin, wantScript)
	}
	if command := runner.calls[5]; command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("script unsafe command: %#v", command)
	}
	if strings.Contains(runner.calls[5].RedactedString(), "foo") {
		t.Fatal("script rendered command leaks password")
	}
	if strings.Contains(out+errS, "foo") {
		t.Fatalf("CLI output leaks password: out=%q err=%q", out, errS)
	}

	// A rejected script keeps the pinned run_all shape — exit OK with
	// the retcode and captured stderr as compatibility data — after the
	// full catalog pass.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR:  role "otheruser" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.owner_to",
		"--dbname", "dbname", "--ownername", "otheruser", "-o", "json")
	var rejected map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &rejected) != nil ||
		len(rejected) != 3 || rejected["retcode"] != float64(1) ||
		rejected["stdout"] != "" ||
		rejected["stderr"] != `psql: error: ERROR:  role "otheruser" does not exist` {
		t.Fatalf("rejected script code=%d out=%q err=%q, want the run_all mapping", code, out, errS)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("rejected script calls = %d", len(runner.calls))
	}

	// A script stderr echoing the password is scrubbed out of the JSON
	// mapping: the transport's redaction covers the run_all fields.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 0, Stdout: []byte("n\n")},
		{ExitCode: 3, Stderr: []byte(`psql: error: FATAL: password authentication failed <foo>`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.owner_to",
		"--dbname", "dbname", "--ownername", "otheruser", "--password", "foo", "-o", "json")
	var leaked map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &leaked) != nil ||
		leaked["retcode"] != float64(3) {
		t.Fatalf("redacted script code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out+errS, "foo") {
		t.Fatalf("redacted mapping leaks password: out=%q err=%q", out, errS)
	}

	// A failing catalog (Runner error or nonzero psql exit) surfaces the
	// redacted value-free error and never reaches the mutation run.
	for _, catalog := range []process.CommandResult{
		{ExitCode: -1, Err: errors.New("owner-to catalog boom")},
		{ExitCode: 2, Stderr: []byte(`psql: error: connection refused`)},
	} {
		runner = &cliRecordingRunner{results: []process.CommandResult{catalog}}
		app = postgresCLIApp(t, runner)
		code, _, errS = captureCode(t, app, "exec", "postgres.owner_to",
			"--dbname", "dbname", "--ownername", "otheruser", "-o", "json")
		wantErr := "owner-to catalog boom"
		if catalog.ExitCode == 2 {
			wantErr = "postgres.owner_to: catalog query failed with retcode 2"
		}
		if code != ExitFailed || !strings.Contains(errS, wantErr) || len(runner.calls) != 1 {
			t.Fatalf("catalog failure code=%d err=%q calls=%d", code, errS, len(runner.calls))
		}
	}

	// Injection attempts fail closed before any psql call, with the exact
	// value-free stable errors naming the argument key only.
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"dbname quote", []string{"--dbname", `db"; DROP DATABASE x; --`, "--ownername", "own"},
			"statekit: postgres: invalid argument: unsupported quote character in dbname\n"},
		{"ownername quote", []string{"--dbname", "db", "--ownername", `own"; DROP DATABASE x; --`},
			"statekit: postgres: invalid argument: unsupported ownername identifier\n"},
		{"ownername space", []string{"--dbname", "db", "--ownername", "own er"},
			"statekit: postgres: invalid argument: unsupported ownername identifier\n"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.owner_to"}, tc.argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || errS != tc.want || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}

	// Both required positionals are validated before any psql call, and
	// runas is rejected the same way.
	for _, argv := range [][]string{
		{"--ownername", "own"},
		{"--dbname", "db"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.owner_to"}, argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("required %v code=%d err=%q calls=%d", argv, code, errS, len(runner.calls))
		}
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.owner_to",
		"--dbname", "dbname", "--ownername", "otheruser", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIDbValidationRedaction loops every rejected db_create,
// db_remove, and db_alter field through the CLI with the rejected value
// embedding the same synthetic marker as --password: exit 1 must carry
// exactly the stable statekit-prefixed validation error — never the
// rejected value, so the marker cannot appear in any output — and no
// Runner call may happen.
func TestPostgresCLIDbValidationRedaction(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn   string
		argv []string
		want string
	}{
		{"postgres.db_create", []string{"--name", `db-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.db_create", []string{"--name", "db", "--tablespace", `ts-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in tablespace\n"},
		{"postgres.db_create", []string{"--name", "db", "--owner", `own-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in owner\n"},
		{"postgres.db_create", []string{"--name", "db", "--template", `tpl-` + marker},
			"statekit: postgres: invalid argument: unsupported template identifier\n"},
		{"postgres.db_create", []string{"--name", "db", "--encoding", `enc-` + marker + `'`},
			"statekit: postgres: invalid argument: unsupported quote character in encoding\n"},
		{"postgres.db_create", []string{"--name", "db", "--lc-collate", `lcc-` + marker + `'`},
			"statekit: postgres: invalid argument: unsupported quote character in lc_collate\n"},
		{"postgres.db_create", []string{"--name", "db", "--lc-ctype", `lct-` + marker + `'`},
			"statekit: postgres: invalid argument: unsupported quote character in lc_ctype\n"},
		{"postgres.db_remove", []string{"--name", `x'-` + marker},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.db_remove", []string{"--name", `x"-` + marker},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.db_alter", []string{"--name", `db-` + marker + `"`, "--owner", "own"},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.db_alter", []string{"--name", "db", "--owner", `own-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in owner\n"},
		{"postgres.db_alter", []string{"--name", "db", "--tablespace", `ts-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in tablespace\n"},
		{"postgres.tablespace_create", []string{"--name", `ts-` + marker + `"`, "--location", "/srv/ts"},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.tablespace_create", []string{"--name", "ts", "--location", "/srv/ts", "--owner", `own-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in owner\n"},
		{"postgres.tablespace_create", []string{"--name", "ts", "--location", `/srv/` + marker + `'`},
			"statekit: postgres: invalid argument: unsupported quote character in location\n"},
		{"postgres.tablespace_create", []string{"--name", "ts", "--location", marker + "/ts"},
			"statekit: postgres: invalid argument: invalid tablespace location\n"},
		{"postgres.tablespace_alter", []string{"--name", `ts-` + marker + `"`, "--new-owner", "own"},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.tablespace_alter", []string{"--name", "ts", "--new-name", `x-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in new_name\n"},
		{"postgres.tablespace_alter", []string{"--name", "ts", "--new-owner", `x-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in new_owner\n"},
		{"postgres.tablespace_alter", []string{"--name", "ts", "--reset-option", marker},
			"statekit: postgres: invalid argument: unsupported tablespace option name\n"},
		{"postgres.tablespace_remove", []string{"--name", `ts-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
	} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		argv := append([]string{"exec", tc.fn, "--password", marker}, tc.argv...)
		argv = append(argv, "-o", "json")
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitFailed || errS != tc.want || len(runner.calls) != 0 {
			t.Fatalf("%s %s code=%d err=%q calls=%d, want err %q",
				tc.fn, tc.argv, code, errS, len(runner.calls), tc.want)
		}
		if strings.Contains(out+errS, marker) {
			t.Fatalf("%s %s output leaks the rejected value: out=%q err=%q",
				tc.fn, tc.argv, out, errS)
		}
	}
}

// TestPostgresCLITablespaceCreate drives the R9.2o create path end to
// end with the pinned test_tablespace_create arguments as flags (the
// pinned runas rejected by the single-user runtime): the byte-exact full
// pinned argv (psql binary, connection flags and order, maintenance_db,
// -c SQL) with no password token, the JSON true rendering,
// the db_password redaction, the structured-input options map with its
// sorted-key WITH tail, the retcode-false compatibility shape, the
// fail-closed name/location boundaries, and the required arguments.
func TestPostgresCLITablespaceCreate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "test_tablespace", "--location", "/tmp/postgres_test_tablespace",
		"--owner", "otheruser",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("tablespace_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	wantArgv := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser", "--host", "testhost", "--port", "testport",
		"--dbname", "maint_db",
		"-c", `CREATE TABLESPACE "test_tablespace" OWNER "otheruser" LOCATION '/tmp/postgres_test_tablespace' `,
	}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %q, want %q", argv, wantArgv)
	}
	if strings.Contains(strings.Join(argv, "\x00"), "foo") {
		t.Fatalf("argv carries the password token: %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=foo" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "foo") || strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// The options map travels through structured input only and renders
	// the pinned WITH tail in the deterministic sorted-key order.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "test_tablespace", "--location", "/tmp/postgres_test_tablespace",
		"--config", `{"options":{"opt1":"1.0","opt2":"4.0"}}`, "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("options code=%d out=%q err=%q", code, out, errS)
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got !=
		`CREATE TABLESPACE "test_tablespace"  LOCATION '/tmp/postgres_test_tablespace' WITH ( opt1 = 1.0, opt2 = 4.0 )` {
		t.Fatalf("options statement = %q", got)
	}

	// An option token outside the bare classes fails closed through the
	// structured path too, value-free.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "ts", "--location", "/srv/ts",
		"--config", `{"options":{"seq_page_cost":"1.1) ; DROP TABLESPACE x; --"}}`, "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported tablespace option value") ||
		len(runner.calls) != 0 {
		t.Fatalf("options value code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// A rejected CREATE keeps Salt's retcode boolean: exit OK, JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: directory "/tmp/postgres_test_tablespace" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "ts", "--location", "/srv/ts", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// The fail-closed boundaries reject before any psql call, and the
	// required name and location fail validation first.
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"name quote", []string{"--name", `ts"; DROP TABLESPACE x; --`, "--location", "/srv/ts"},
			"postgres: invalid argument: unsupported quote character in name"},
		{"location relative", []string{"--name", "ts", "--location", "srv/ts"},
			"postgres: invalid argument: invalid tablespace location"},
		{"location traversal", []string{"--name", "ts", "--location", "/srv/../etc"},
			"postgres: invalid argument: invalid tablespace location"},
		{"location quote", []string{"--name", "ts", "--location", "/srv/ts'"},
			"postgres: invalid argument: unsupported quote character in location"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append(append([]string{"exec", "postgres.tablespace_create"}, tc.argv...), "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || !strings.Contains(errS, tc.want) || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--location", "/srv/ts", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "ts", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "location") || len(runner.calls) != 0 {
		t.Fatalf("missing location code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_create",
		"--name", "ts", "--location", "/srv/ts", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLITablespaceAlter drives the R9.2o alter path end to end:
// the pinned new_owner statement byte-for-byte on the full pinned argv
// (psql binary, connection flags and order, maintenance_db, -c SQL, no
// password token) and the pinned new_name statement, the
// structured-input set_option and the flag-borne reset_option
// statements, the pinned four-clause order, the no-op True
// without any psql call, the retcode-false stop, the multi-entry
// set_option rejection, and the required name.
func TestPostgresCLITablespaceAlter(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "test_tablespace", "--new-owner", "testuser",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var altered bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &altered) != nil || !altered {
		t.Fatalf("tablespace_alter code=%d out=%q err=%q", code, out, errS)
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	wantArgv := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser", "--host", "testhost", "--port", "testport",
		"--dbname", "maint_db",
		"-c", `ALTER TABLESPACE "test_tablespace" OWNER TO "testuser"`,
	}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("owner argv = %q, want %q", argv, wantArgv)
	}
	if strings.Contains(strings.Join(argv, "\x00"), "foo") {
		t.Fatalf("owner argv carries the password token: %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "foo") ||
		strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked")
	}

	// The pinned new_name statement on the same transport.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "test_tablespace", "--new-name", "test_tablespace2", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &altered) != nil || !altered {
		t.Fatalf("new_name code=%d out=%q err=%q", code, out, errS)
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-1]; got !=
		`ALTER TABLESPACE "test_tablespace" RENAME TO "test_tablespace2"` {
		t.Fatalf("new_name statement = %q", got)
	}

	// set_option arrives through structured input, reset_option as a
	// flag; all four clauses keep the pinned order.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
		{ExitCode: 0},
		{ExitCode: 0},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "test_tablespace", "--reset-option", "seq_page_cost",
		"--config", `{"set_option":{"seq_page_cost":"1.1"},"new_name":"test_tablespace2","new_owner":"testuser"}`,
		"-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &altered) != nil || !altered {
		t.Fatalf("four clauses code=%d out=%q err=%q", code, out, errS)
	}
	wantStatements := []string{
		`ALTER TABLESPACE "test_tablespace" RENAME TO "test_tablespace2"`,
		`ALTER TABLESPACE "test_tablespace" OWNER TO "testuser"`,
		`ALTER TABLESPACE "test_tablespace" SET (seq_page_cost = 1.1)`,
		`ALTER TABLESPACE "test_tablespace" RESET (seq_page_cost)`,
	}
	if len(runner.calls) != 4 {
		t.Fatalf("four clauses calls = %d, want 4", len(runner.calls))
	}
	for i, command := range runner.calls {
		if got := command.Args[len(command.Args)-1]; got != wantStatements[i] {
			t.Fatalf("clause %d statement = %q, want %q", i, got, wantStatements[i])
		}
		if command.Shell {
			t.Fatalf("clause %d must run without a shell", i)
		}
	}

	// The pinned no-op head: exit OK, JSON true, zero psql calls.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "test_tablespace", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &altered) != nil || !altered {
		t.Fatalf("no-op code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("no-op calls = %d, want 0", len(runner.calls))
	}

	// A rejected first clause answers JSON false and stops the flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: tablespace "test_tablespace" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "test_tablespace", "--new-owner", "testuser",
		"--new-name", "test_tablespace2", "-o", "json")
	var rejected bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &rejected) != nil || rejected {
		t.Fatalf("rejected clause code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("rejected clause calls = %d, want 1", len(runner.calls))
	}

	// A multi-entry set_option is the value-free ambiguity rejection
	// before any psql call.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_alter",
		"--name", "ts", "--config", `{"set_option":{"seq_page_cost":"1.1","random_page_cost":"4.0"}}`,
		"-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: set_option must carry exactly one tablespace option") ||
		len(runner.calls) != 0 {
		t.Fatalf("multi set_option code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// The required name is validated before any psql call.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_alter", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLITablespaceRemove drives the R9.2o remove path end to
// end: the byte-exact full pinned argv (psql binary, connection flags
// and order, maintenance_db, -c SQL) with no password token carrying
// the pinned DROP TABLESPACE statement, the JSON true rendering, the
// no-preflight missing-tablespace boolean false, the fail-closed name
// boundary, and the required name.
func TestPostgresCLITablespaceRemove(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.tablespace_remove",
		"--name", "test_tablespace",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--maintenance-db", "maint_db", "--password", "foo", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("tablespace_remove code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	wantArgv := []string{
		"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password",
		"--username", "testuser", "--host", "testhost", "--port", "testport",
		"--dbname", "maint_db",
		"-c", `DROP TABLESPACE "test_tablespace"`,
	}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %q, want %q", argv, wantArgv)
	}
	if strings.Contains(strings.Join(argv, "\x00"), "foo") {
		t.Fatalf("argv carries the password token: %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=foo" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "foo") || strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A missing tablespace keeps the pinned no-preflight shape: one
	// statement, the server rejection in the JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: tablespace "test_tablespace" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.tablespace_remove",
		"--name", "test_tablespace", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing calls = %d, want 1 (no preflight)", len(runner.calls))
	}

	// Injection attempts fail closed before any psql call, and the
	// required name is validated first.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_remove",
		"--name", `ts"; DROP TABLESPACE x; --`, "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in name") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.tablespace_remove", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// userMutationsCSV is the user_list catalog for the R9.2i CLI mutation
// flows: test_username exists as a non-superuser, super_role as a
// superuser, and created names are absent.
const userMutationsCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
test_username,f,f,f,f,f,f,,-1,,,
super_role,t,t,f,f,f,t,,-1,,,
`

// groupMutationsCSV is the user_list catalog for the R9.2j CLI group
// flows: testgroup exists as a non-superuser group role, super_role a
// superuser, and created names are absent.
const groupMutationsCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
testgroup,f,t,f,f,f,f,,-1,,,
super_role,t,t,f,f,f,t,,-1,,,
`

// groupAbsentCSV is a catalog whose only role is super_role, so CLI
// create flows for testgroup reach their statement.
const groupAbsentCSV = `name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables
super_role,t,t,f,f,f,t,,-1,,,
`

// TestPostgresCLIUserCreate drives the R9.2i create path end to end with
// the pinned test_user_create arguments as flags: the pinned CREATE ROLE
// statement on the full argv after the preflight pair, both passwords in
// the Redact list and neither in any rendered or CLI output, and the JSON
// true rendering.
func TestPostgresCLIUserCreate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.user_create",
		"--username", "testuser", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_test",
		"--password", "test_pass", "--login", "--createdb=false",
		"--createroles=false", "--superuser=false",
		"--replication=false", "--rolepassword", "test_role_pass",
		"--valid-until", "2042-07-01", "--groups", "test_groups",
		"--config", `{"encrypted": false}`, "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("user_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `CREATE ROLE "testuser" WITH  INHERIT NOCREATEDB NOCREATEROLE `+
			`NOSUPERUSER NOREPLICATION LOGIN UNENCRYPTED PASSWORD `+
			`'test_role_pass' VALID UNTIL '2042-07-01'; GRANT "test_groups" TO "testuser"` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=test_pass" ||
		command.Shell || len(command.Redact) != 3 ||
		command.Redact[0] != "'test_role_pass'" ||
		command.Redact[1] != "test_role_pass" || command.Redact[2] != "test_pass" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "test_pass") ||
		strings.Contains(rendered, "test_role_pass") ||
		strings.Contains(rendered, "'test_role_pass'") {
		t.Fatalf("rendered command leaks a password: %q", rendered)
	}
	if strings.Contains(out+errS, "test_pass") || strings.Contains(out+errS, "test_role_pass") {
		t.Fatalf("CLI output leaks a password: out=%q err=%q", out, errS)
	}
}

// TestPostgresCLIUserCreateShapes pins the remaining CLI create contract:
// the default INHERIT LOGIN statement, the boolean-typed rolepassword
// NOPASSWORD shape, an existing role answering false after the preflight,
// a rejected CREATE answering the retcode boolean, the md5 default
// verifier with the plaintext redacted, and the required-username and
// runas rejections before any psql call.
func TestPostgresCLIUserCreateShapes(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--connlimit", "10", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("defaults code=%d out=%q err=%q", code, out, errS)
	}
	defaults := runner.calls[2].Args
	if got := defaults[len(defaults)-1]; got != `CREATE ROLE "newuser" WITH  INHERIT LOGIN CONNECTION LIMIT 10` {
		t.Fatalf("defaults statement = %q", got)
	}

	// --rolepassword=false through structured input is Salt's boolean
	// False: NOPASSWORD, no literal.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--config", `{"rolepassword": false}`, "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("nopassword code=%d out=%q err=%q", code, out, errS)
	}
	nopassword := runner.calls[2].Args
	if got := nopassword[len(nopassword)-1]; got != `CREATE ROLE "newuser" WITH  INHERIT LOGIN NOPASSWORD` {
		t.Fatalf("nopassword statement = %q", got)
	}

	// --rolepassword true as a flag is the exact string "true": a literal
	// password hashed by the default md5 algorithm, its digest and the
	// string itself both Redact secrets, and never the bare PASSWORD the
	// boolean true renders.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--rolepassword", "true", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("string-true code=%d out=%q err=%q", code, out, errS)
	}
	stringTrue := runner.calls[2].Args
	digest := "md5" + postgresCLIMD5Hex("truenewuser")
	if got := stringTrue[len(stringTrue)-1]; got != `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD '`+digest+`'` {
		t.Fatalf("string-true statement = %q", got)
	}
	if len(runner.calls[2].Redact) != 3 || runner.calls[2].Redact[0] != "'"+digest+"'" ||
		runner.calls[2].Redact[1] != digest || runner.calls[2].Redact[2] != "true" {
		t.Fatalf("string-true redact = %q", runner.calls[2].Redact)
	}
	if strings.Contains(runner.calls[2].RedactedString(), digest) ||
		strings.Contains(out+errS, digest) {
		t.Fatalf("string-true path leaks the digest: %q %q",
			runner.calls[2].RedactedString(), out+errS)
	}

	// --encrypted false as a flag is the exact string "false": the pinned
	// source rejects it as an unknown algorithm with the value-free
	// error after the read-only preflight pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--encrypted", "false",
		"--rolepassword", "pw", "-o", "json")
	if code != ExitFailed ||
		errS != "statekit: postgres: invalid argument: unknown password algorithm\n" ||
		len(runner.calls) != 2 {
		t.Fatalf("encrypted-false code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	if strings.Contains(out+errS, "false") || strings.Contains(out+errS, "pw") {
		t.Fatalf("encrypted-false output leaks a value: out=%q err=%q", out, errS)
	}

	// The groups flag keeps the raw string: no trimming and no empty
	// element dropping, exactly like the pinned split.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--groups", "grp_a,,grp_b ", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("groups-flag code=%d out=%q err=%q", code, out, errS)
	}
	groupsFlag := runner.calls[2].Args
	if got := groupsFlag[len(groupsFlag)-1]; got != `CREATE ROLE "newuser" WITH  INHERIT LOGIN`+
		`; GRANT "grp_a" TO "newuser"; GRANT "" TO "newuser"; GRANT "grp_b " TO "newuser"` {
		t.Fatalf("groups-flag statement = %q", got)
	}

	// Structured groups decoding retains the raw string the same way.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--config", `{"groups": "x ,y"}`, "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("groups-structured code=%d out=%q err=%q", code, out, errS)
	}
	groupsStructured := runner.calls[2].Args
	if got := groupsStructured[len(groupsStructured)-1]; got != `CREATE ROLE "newuser" WITH  INHERIT LOGIN`+
		`; GRANT "x " TO "newuser"; GRANT "y" TO "newuser"` {
		t.Fatalf("groups-structured statement = %q", got)
	}

	// An existing role is false after exactly the preflight pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "test_username", "-o", "json")
	var exists bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &exists) != nil || exists {
		t.Fatalf("existing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("existing calls = %d, want 2", len(runner.calls))
	}

	// A rejected CREATE keeps the retcode boolean.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: role "newuser" already exists`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// The default md5 verifier hides the plaintext everywhere.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--rolepassword", "cli_secret", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("md5 code=%d out=%q err=%q", code, out, errS)
	}
	md5Args := runner.calls[2].Args
	statement := md5Args[len(md5Args)-1]
	if !strings.HasPrefix(statement, `CREATE ROLE "newuser" WITH  INHERIT LOGIN ENCRYPTED PASSWORD 'md5`) ||
		strings.Contains(statement, "cli_secret") {
		t.Fatalf("md5 statement = %q", statement)
	}
	if strings.Contains(runner.calls[2].RedactedString(), "cli_secret") ||
		strings.Contains(out+errS, "cli_secret") {
		t.Fatalf("md5 path leaks the plaintext: %q %q",
			runner.calls[2].RedactedString(), out+errS)
	}

	// The required username fails validation before any run, and runas is
	// rejected the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_create", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "username") || len(runner.calls) != 0 {
		t.Fatalf("missing username code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_create",
		"--username", "newuser", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIUserUpdate drives the R9.2i update path end to end with
// the pinned test_user_update arguments as flags: the exact pinned ALTER
// ROLE statement, the rolepassword redaction, the missing-role false
// shape, and the value-free identifier rejection.
func TestPostgresCLIUserUpdate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.user_update",
		"--username", "test_username", "--user", "test_user", "--host", "test_host",
		"--port", "test_port", "--maintenance-db", "test_maint",
		"--password", "test_pass", "--createdb=false", "--createroles=false",
		"--inherit", "--login", "--replication=false",
		"--rolepassword", "test_role_pass", "--valid-until", "2017-07-01",
		"--groups", "test_groups", "--config", `{"encrypted": false}`, "-o", "json")
	var updated bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &updated) != nil || !updated {
		t.Fatalf("user_update code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `ALTER ROLE "test_username" WITH  INHERIT NOCREATEDB NOCREATEROLE `+
			`NOREPLICATION LOGIN UNENCRYPTED PASSWORD 'test_role_pass' `+
			`VALID UNTIL '2017-07-01'; GRANT "test_groups" TO "test_username"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 3 ||
		command.Redact[0] != "'test_role_pass'" ||
		command.Redact[1] != "test_role_pass" || command.Redact[2] != "test_pass" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "test_role_pass") ||
		strings.Contains(out+errS, "test_role_pass") {
		t.Fatalf("rolepassword leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A missing role answers false after the preflight pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_update",
		"--username", "absent_user", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing calls = %d, want 2", len(runner.calls))
	}

	// Injection attempts fail closed before any psql call with the exact
	// value-free stable error.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_update",
		"--username", `u"; DROP ROLE postgres; --`, "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in username") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected username code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// The required username fails validation before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_update", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "username") || len(runner.calls) != 0 {
		t.Fatalf("missing username code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIUserRemove drives the R9.2i remove path end to end: the
// pinned five-call flow (preflight pair, DROP ROLE, post-check pair), the
// JSON true/false renderings, the missing-role no-op, and the unsupported
// group family exiting 3 with zero calls.
func TestPostgresCLIUserRemove(t *testing.T) {
	goneCSV := "name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\n" +
		"super_role,t,t,f,f,f,t,,-1,,,\n"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 0}, // DROP ROLE (retcode ignored by the pinned flow)
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(goneCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.user_remove",
		"--username", "test_username", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "testpassword", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("user_remove code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("runner calls = %d, want 5", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `DROP ROLE "test_username"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A missing role answers false after the preflight pair, with no DROP.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(goneCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_remove",
		"--username", "test_username", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing calls = %d, want 2", len(runner.calls))
	}

	// The failed DROP that leaves the role present answers false after
	// the full flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
		{ExitCode: 1, Stderr: []byte("psql: error: ERROR: role cannot be dropped")},
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.user_remove",
		"--username", "test_username", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("failed drop code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("failed drop calls = %d, want 5", len(runner.calls))
	}

	// The required username fails validation before any run, and an
	// injected name fails closed the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_remove", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "username") || len(runner.calls) != 0 {
		t.Fatalf("missing username code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.user_remove",
		"--username", `x"-`+"pgmark", "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in username") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIGroupCreate drives the R9.2j group create path end to end
// with the pinned test_group_create arguments as flags: the pinned
// group-typed INHERIT NOLOGIN CREATE ROLE statement on the full argv after
// the preflight pair, both passwords in the Redact list and neither in any
// rendered or CLI output, the default INHERIT NOLOGIN shape, and the
// JSON true rendering.
func TestPostgresCLIGroupCreate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupAbsentCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.group_create",
		"--groupname", "testgroup", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "foo", "--createdb=false", "--superuser=false",
		"--replication=false", "--rolepassword", "testrolepass",
		"--groups", "testgroup", "--config", `{"encrypted": false}`, "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("group_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `CREATE ROLE "testgroup" WITH  INHERIT NOCREATEDB `+
			`NOSUPERUSER NOREPLICATION NOLOGIN UNENCRYPTED PASSWORD `+
			`'testrolepass'; GRANT "testgroup" TO "testgroup"` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=foo" ||
		command.Shell || len(command.Redact) != 3 ||
		command.Redact[0] != "'testrolepass'" ||
		command.Redact[1] != "testrolepass" || command.Redact[2] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if rendered := command.RedactedString(); strings.Contains(rendered, "foo") ||
		strings.Contains(rendered, "testrolepass") ||
		strings.Contains(rendered, "'testrolepass'") {
		t.Fatalf("rendered command leaks a password: %q", rendered)
	}
	if strings.Contains(out+errS, "foo") || strings.Contains(out+errS, "testrolepass") {
		t.Fatalf("CLI output leaks a password: out=%q err=%q", out, errS)
	}

	// The default group statement is exactly the pinned group-typed
	// INHERIT NOLOGIN defaults: no connlimit or valid_until exists.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupAbsentCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.group_create",
		"--groupname", "newgroup", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("defaults code=%d out=%q err=%q", code, out, errS)
	}
	defaults := runner.calls[2].Args
	if got := defaults[len(defaults)-1]; got != `CREATE ROLE "newgroup" WITH  INHERIT NOLOGIN` {
		t.Fatalf("defaults statement = %q", got)
	}

	// An existing role answers false after exactly the preflight pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.group_create",
		"--groupname", "testgroup", "-o", "json")
	var exists bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &exists) != nil || exists {
		t.Fatalf("existing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("existing calls = %d, want 2", len(runner.calls))
	}

	// The required groupname fails validation before any run, and runas
	// is rejected the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_create", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "groupname") || len(runner.calls) != 0 {
		t.Fatalf("missing groupname code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_create",
		"--groupname", "newgroup", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIGroupUpdate drives the R9.2j group update path end to end
// with the pinned test_group_update arguments as flags: the exact pinned
// ALTER ROLE statement with the db_role superuser skip, no inherit/login
// defaults, the rolepassword redaction, the missing-group false shape,
// and the value-free identifier rejection.
func TestPostgresCLIGroupUpdate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.group_update",
		"--groupname", "testgroup", "--user", `"testuser"`, "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "foo", "--createdb=false", "--replication=false",
		"--rolepassword", "test_role_pass", "--groups", "testgroup",
		"--config", `{"encrypted": false}`, "-o", "json")
	var updated bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &updated) != nil || !updated {
		t.Fatalf("group_update code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `ALTER ROLE "testgroup" WITH  NOCREATEDB NOREPLICATION `+
			`UNENCRYPTED PASSWORD 'test_role_pass'; GRANT "testgroup" TO "testgroup"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 3 ||
		command.Redact[0] != "'test_role_pass'" ||
		command.Redact[1] != "test_role_pass" || command.Redact[2] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "test_role_pass") ||
		strings.Contains(out+errS, "test_role_pass") {
		t.Fatalf("rolepassword leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A missing group answers false after the preflight pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.group_update",
		"--groupname", "absent_group", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing calls = %d, want 2", len(runner.calls))
	}

	// Injection attempts fail closed before any psql call with the exact
	// value-free stable error naming the groupname key.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_update",
		"--groupname", `g"; DROP ROLE postgres; --`, "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in groupname") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected groupname code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}

	// The required groupname fails validation before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_update", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "groupname") || len(runner.calls) != 0 {
		t.Fatalf("missing groupname code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIGroupRemove drives the R9.2j group remove path end to
// end: the pinned five-call flow (preflight pair, DROP ROLE, post-check
// pair), the exact pinned DROP argv, the JSON true/false renderings, the
// missing-group no-op, and the value-free identifier rejection.
func TestPostgresCLIGroupRemove(t *testing.T) {
	goneCSV := "name,superuser,inherits privileges,can create roles,can create databases,can update system catalogs,can login,replication,connections,groups,expiry time,defaults variables\n" +
		"super_role,t,t,f,f,f,t,,-1,,,\n"
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
		{ExitCode: 0}, // DROP ROLE (retcode ignored by the pinned flow)
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(goneCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.group_remove",
		"--groupname", "testgroup", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "foo", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("group_remove code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("runner calls = %d, want 5", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `DROP ROLE "testgroup"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "foo" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "foo") ||
		strings.Contains(out+errS, "foo") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// A missing group answers false after the preflight pair, with no DROP.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(goneCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.group_remove",
		"--groupname", "testgroup", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("missing calls = %d, want 2", len(runner.calls))
	}

	// The failed DROP that leaves the group present answers false after
	// the full flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
		{ExitCode: 1, Stderr: []byte("psql: error: ERROR: role cannot be dropped")},
		{ExitCode: 0, Stdout: []byte("9.1\n")},
		{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.group_remove",
		"--groupname", "testgroup", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("failed drop code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("failed drop calls = %d, want 5", len(runner.calls))
	}

	// The required groupname fails validation before any run, and an
	// injected name fails closed the same way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_remove", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "groupname") || len(runner.calls) != 0 {
		t.Fatalf("missing groupname code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.group_remove",
		"--groupname", `g"-`+"pgmark", "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in groupname") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIUserValidationRedaction loops every rejected user-family
// field through the CLI with the rejected value embedding the same
// synthetic marker as --password: exit 1 carries exactly the stable
// value-free error, no Runner call happens beyond the read-only preflight
// pair the pinned flow runs first, and no output carries the marker.
func TestPostgresCLIUserValidationRedaction(t *testing.T) {
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn      string
		argv    []string
		want    string
		calls   int
		results []process.CommandResult
	}{
		{"postgres.user_create", []string{"--username", `u-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in username\n", 0, nil},
		{"postgres.user_create", []string{"--username", "u", "--groups", `g-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.user_create", []string{"--username", "u", "--groups", `ok,g-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.user_create", []string{"--username", "u", "--encrypted", marker, "--rolepassword", marker},
			"statekit: postgres: invalid argument: unknown password algorithm\n", 2,
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte("9.1\n")},
				{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
			}},
		{"postgres.user_update", []string{"--username", `u-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in username\n", 0, nil},
		{"postgres.user_update", []string{"--username", "u", "--groups", `g,` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.user_update", []string{"--username", "test_username", "--encrypted", marker, "--rolepassword", marker},
			"statekit: postgres: invalid argument: unknown password algorithm\n", 2,
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte("9.1\n")},
				{ExitCode: 0, Stdout: []byte(userMutationsCSV)},
			}},
		{"postgres.user_remove", []string{"--username", `u"-` + marker},
			"statekit: postgres: invalid argument: unsupported quote character in username\n", 0, nil},
		{"postgres.group_create", []string{"--groupname", `g-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groupname\n", 0, nil},
		{"postgres.group_create", []string{"--groupname", "g", "--groups", `m-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.group_create", []string{"--groupname", "g", "--groups", `ok,m-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.group_create", []string{"--groupname", "g", "--encrypted", marker, "--rolepassword", marker},
			"statekit: postgres: invalid argument: unknown password algorithm\n", 2,
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte("9.1\n")},
				{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
			}},
		{"postgres.group_update", []string{"--groupname", `g-` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groupname\n", 0, nil},
		{"postgres.group_update", []string{"--groupname", "g", "--groups", `m,` + marker + `"`},
			"statekit: postgres: invalid argument: unsupported quote character in groups\n", 0, nil},
		{"postgres.group_update", []string{"--groupname", "testgroup", "--encrypted", marker, "--rolepassword", marker},
			"statekit: postgres: invalid argument: unknown password algorithm\n", 2,
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte("9.1\n")},
				{ExitCode: 0, Stdout: []byte(groupMutationsCSV)},
			}},
		{"postgres.group_remove", []string{"--groupname", `g"-` + marker},
			"statekit: postgres: invalid argument: unsupported quote character in groupname\n", 0, nil},
	} {
		runner := &cliRecordingRunner{results: tc.results}
		app := postgresCLIApp(t, runner)
		argv := append([]string{"exec", tc.fn, "--password", marker}, tc.argv...)
		argv = append(argv, "-o", "json")
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitFailed || errS != tc.want || len(runner.calls) != tc.calls {
			t.Fatalf("%s %s code=%d err=%q calls=%d, want err %q with %d calls",
				tc.fn, tc.argv, code, errS, len(runner.calls), tc.want, tc.calls)
		}
		if strings.Contains(out+errS, marker) {
			t.Fatalf("%s %s output leaks the rejected value: out=%q err=%q",
				tc.fn, tc.argv, out, errS)
		}
	}
}

// statementLeakRunner deliberately ignores Command.Redact and reports the
// actual SQL and environment. Only synthetic test credentials are used.
type statementLeakRunner struct {
	calls   []process.Command
	results []process.CommandResult
	raw     string
}

func (r *statementLeakRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) > 0 {
		result := r.results[0]
		r.results = r.results[1:]
		return result
	}
	r.raw = strings.Join(command.Args, " ") + " " + strings.Join(command.Env, " ")
	return process.CommandResult{ExitCode: -1, Err: errors.New("statement leak: " + r.raw), Stdout: []byte(r.raw), Stderr: []byte(r.raw)}
}

func TestPostgresCLIUserRawStatementRedaction(t *testing.T) {
	for _, function := range []string{"postgres.user_create", "postgres.user_update",
		"postgres.group_create", "postgres.group_update"} {
		for _, tc := range []struct {
			name, password string
			encrypted      any
			prefix         string
		}{
			{"plaintext", "synthetic'role", false, ""},
			{"md5", "synthetic'role", "md5", "md5"},
			{"scram", "synthetic'role", "scram-sha-256", "SCRAM-SHA-256$"},
			{"supplied-md5", "md5deadbeef", "md5", "md5"},
			{"supplied-scram", "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy", "scram-sha-256", "SCRAM-SHA-256$"},
		} {
			t.Run(function+"/"+tc.name, func(t *testing.T) {
				const connection = "synthetic_connection_marker"
				catalog := userMutationsCSV
				if strings.HasPrefix(function, "postgres.group_") {
					catalog = groupMutationsCSV
				}
				runner := &statementLeakRunner{results: []process.CommandResult{
					{ExitCode: 0, Stdout: []byte("9.1\n")}, {ExitCode: 0, Stdout: []byte(catalog)},
				}}
				nameFlag, roleName, verb := "--username", "testuser", "CREATE ROLE"
				if function == "postgres.user_update" {
					roleName, verb = "test_username", "ALTER ROLE"
				}
				if function == "postgres.group_create" {
					roleName = "newgroup"
				}
				if function == "postgres.group_update" {
					nameFlag, roleName, verb = "--groupname", "testgroup", "ALTER ROLE"
				}
				if strings.HasPrefix(function, "postgres.group_") {
					nameFlag = "--groupname"
				}
				config, err := json.Marshal(map[string]any{"encrypted": tc.encrypted, "rolepassword": tc.password})
				if err != nil {
					t.Fatal(err)
				}
				code, stdout, stderr := captureCode(t, postgresCLIApp(t, runner), "exec", function,
					nameFlag, roleName, "--password", connection, "--config", string(config), "-o", "json")
				if code != ExitFailed || stdout != "" || stderr == "" || len(runner.calls) != 3 {
					t.Fatal("CLI did not report the injected statement error")
				}
				command := runner.calls[2]
				sql := command.Args[len(command.Args)-1]
				if !strings.HasPrefix(sql, verb) || !strings.Contains(runner.raw, sql) || !strings.Contains(runner.raw, connection) {
					t.Fatal("runner error did not contain the actual SQL and connection password")
				}
				_, literal, ok := strings.Cut(sql, "PASSWORD '")
				if !ok || !strings.HasSuffix(literal, "'") {
					t.Fatal("missing password clause")
				}
				verifier := strings.TrimSuffix(literal, "'")
				doubled := strings.ReplaceAll(tc.password, "'", "''")
				if tc.prefix == "" && verifier != doubled || tc.prefix != "" && !strings.HasPrefix(verifier, tc.prefix) {
					t.Fatal("wrong SQL password form")
				}
				for _, secret := range []string{tc.password, doubled, verifier, "'" + verifier + "'", connection} {
					if strings.Contains(stdout+stderr, secret) || strings.Contains(command.RedactedString(), secret) {
						t.Fatal("CLI or rendered command leaked a secret form")
					}
				}
				for _, secret := range []string{tc.password, verifier, "'" + verifier + "'", connection} {
					found := false
					for _, redacted := range command.Redact {
						if redacted == secret {
							found = true
						}
					}
					if !found {
						t.Fatal("command redaction missing required secret")
					}
				}
				if command.Shell || !strings.Contains(stderr, process.RedactedPlaceholder) || !strings.Contains(command.RedactedString(), process.RedactedPlaceholder) {
					t.Fatal("command/error redaction not exercised")
				}
			})
		}
	}
}

// privCLIGrantTableCSV renders the table privilege catalog where baruwa
// holds nothing on awl (only bayestest does), so the grant preflight
// answers false and the mutation runs.
const privCLIGrantTableCSV = `nspname,relname,relkind,name
public,awl,r,"{bayestest=arwd/baruwatest}"
`

// ownerCLIFunctionCSV renders the function owner catalog: fawl is owned
// by postgres so the preflight continues past the owner shortcut.
const ownerCLIFunctionCSV = `nspname,regprocedure,name
public,fawl,postgres
`

// privCLIGrantFunctionCSV renders the function privilege catalog where
// baruwa lacks EXECUTE on fawl.
const privCLIGrantFunctionCSV = `nspname,regprocedure,name
public,fawl,"{bayestest=X/baruwatest}"
`

// privCLIGrantGroupCSV renders the group membership catalog where baruwa
// is not a member of admins.
const privCLIGrantGroupCSV = `member_of,rolname,admin_option
admins,baruwatest,f
`

// TestPostgresCLIPrivilegesGrant drives the R9.2k grant path end to end:
// the pinned GRANT statements through the fake Runner after the preflight
// pair (including the ALL TABLES IN SCHEMA, function, and group variants
// with and without the option suffixes), the JSON true rendering, and no
// password anywhere in the rendered command or CLI output.
func TestPostgresCLIPrivilegesGrant(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "ALL", "--grant-option",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var granted bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
		t.Fatalf("grant code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("grant calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `GRANT ALL ON TABLE public."awl" TO "baruwa" WITH GRANT OPTION` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=testpassword" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	for _, tc := range []struct {
		label     string
		argv      []string
		results   []process.CommandResult
		statement string
	}{
		{
			"table no option", []string{"--object-name", "awl", "--object-type", "table", "--privileges", "ALL"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
				{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
				{ExitCode: 0},
			},
			`GRANT ALL ON TABLE public."awl" TO "baruwa"`,
		},
		{
			"all tables in schema", []string{"--object-name", "ALL", "--object-type", "table", "--privileges", "SELECT"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
				{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
				{ExitCode: 0},
			},
			`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "baruwa"`,
		},
		{
			"function with option", []string{"--object-name", "fawl", "--object-type", "function",
				"--privileges", "ALL", "--grant-option"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLIFunctionCSV)},
				{ExitCode: 0, Stdout: []byte(privCLIGrantFunctionCSV)},
				{ExitCode: 0},
			},
			`GRANT ALL ON FUNCTION public."fawl" TO "baruwa" WITH GRANT OPTION`,
		},
	} {
		runner := &cliRecordingRunner{results: tc.results}
		app := postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.privileges_grant", "--name", "baruwa"}, tc.argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, out, errS := captureCode(t, app, fullArgv...)
		var granted bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
			t.Fatalf("%s code=%d out=%q err=%q", tc.label, code, out, errS)
		}
		if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != tc.statement {
			t.Fatalf("%s statement = %q, want %q", tc.label, got, tc.statement)
		}
	}

	// The group grant: one membership preflight, then the raw membership
	// GRANT with ADMIN OPTION.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGrantGroupCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_grant",
		"--name", "baruwa", "--object-name", "admins", "--object-type", "group",
		"--grant-option", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
		t.Fatalf("group grant code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("group grant calls = %d, want 2", len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != `GRANT admins TO "baruwa" WITH ADMIN OPTION` {
		t.Fatalf("group grant statement = %q", got)
	}
}

// TestPostgresCLIPrivilegesRevoke drives the R9.2k revoke path end to
// end: the pinned REVOKE statements — including the raw role name of the
// REVOKE tail — after a preflight pair that answers held, the JSON true
// rendering, the group form, and no password in any rendered or CLI
// output.
func TestPostgresCLIPrivilegesRevoke(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLITableCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.privileges_revoke",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "ALL", "--maintenance-db", "db_name",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var revoked bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &revoked) != nil || !revoked {
		t.Fatalf("revoke code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("revoke calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `REVOKE ALL ON TABLE public."awl" FROM baruwa` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Redact) != 1 || command.Redact[0] != "testpassword" ||
		command.Shell ||
		strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("unsafe command or leak: %#v %q %q", command, out, errS)
	}

	// The group form: one membership preflight where baruwa is a member,
	// then the raw REVOKE.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_revoke",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &revoked) != nil || !revoked {
		t.Fatalf("group revoke code=%d out=%q err=%q", code, out, errS)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "REVOKE admin FROM baruwa" {
		t.Fatalf("group revoke statement = %q", got)
	}
}

// TestPostgresCLIPrivilegesMutationFailures pins the CLI failure and
// no-op surface of both mutations: the already-granted and nothing-held
// no-ops answering JSON false without a mutation call, the fail-closed
// identifier boundary with the value-free stable errors, the pinned
// validation failures, the required arguments, the runas rejection, the
// nonzero-exit retcode boolean, and the redacted mutation-time Runner
// error.
func TestPostgresCLIPrivilegesMutationFailures(t *testing.T) {
	// Grant to the role that already holds everything: false after the
	// preflight pair, no third call.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLITableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "ALL", "-o", "json")
	var noop bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &noop) != nil || noop {
		t.Fatalf("already-granted code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("already-granted calls = %d, want 2", len(runner.calls))
	}

	// Revoke from a role that holds nothing: false after the preflight
	// pair, no third call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_revoke",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "ALL", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &noop) != nil || noop {
		t.Fatalf("nothing-held code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("nothing-held calls = %d, want 2", len(runner.calls))
	}

	// A rejected statement keeps the pinned retcode boolean: exit OK,
	// JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: relation "awl" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "ALL", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// Injection attempts fail closed before any psql call, with the exact
	// value-free stable errors naming the argument key only.
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn   string
		argv []string
		want string
	}{
		{"postgres.privileges_grant", []string{"--name", `baruwa-` + marker + `"`,
			"--object-name", "awl", "--object-type", "table", "--privileges", "SELECT"},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.privileges_grant", []string{"--name", "baruwa", "--object-name", `aw` + marker + `"`,
			"--object-type", "table", "--privileges", "SELECT"},
			"statekit: postgres: invalid argument: unsupported quote character in object_name\n"},
		{"postgres.privileges_grant", []string{"--name", "baruwa", "--object-name", `admins; ` + marker,
			"--object-type", "group"},
			"statekit: postgres: invalid argument: unsupported identifier in object_name\n"},
		{"postgres.privileges_grant", []string{"--name", "baruwa", "--object-name", "awl",
			"--object-type", "table", "--privileges", "SELECT", "--prepend", `pub ` + marker},
			"statekit: postgres: invalid argument: unsupported identifier in prepend\n"},
		{"postgres.privileges_revoke", []string{"--name", `baruwa; ` + marker, "--object-name", "awl",
			"--object-type", "table", "--privileges", "SELECT"},
			"statekit: postgres: invalid argument: unsupported identifier in name\n"},
		{"postgres.privileges_revoke", []string{"--name", "baruwa", "--object-name", `admi` + marker,
			"--object-type", "group"},
			"statekit: postgres: invalid argument: unsupported identifier in object_name\n"},
	} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		argv := append([]string{"exec", tc.fn, "--password", marker}, tc.argv...)
		argv = append(argv, "-o", "json")
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitFailed || errS != tc.want || len(runner.calls) != 0 {
			t.Fatalf("%s %v code=%d err=%q calls=%d, want err %q",
				tc.fn, tc.argv, code, errS, len(runner.calls), tc.want)
		}
		if strings.Contains(out+errS, marker) {
			t.Fatalf("%s output leaks the rejected value: out=%q err=%q", tc.fn, out, errS)
		}
	}

	// The pinned validation failures also fail before any psql call.
	for _, argv := range [][]string{
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "bogus", "--privileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--privileges", "BOGUS"},
		{"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "--privileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table"},
	} {
		for _, fn := range []string{"postgres.privileges_grant", "postgres.privileges_revoke"} {
			runner := &cliRecordingRunner{}
			app := postgresCLIApp(t, runner)
			fullArgv := append([]string{"exec", fn}, argv...)
			fullArgv = append(fullArgv, "-o", "json")
			code, _, errS := captureCode(t, app, fullArgv...)
			if code != ExitFailed || len(runner.calls) != 0 {
				t.Fatalf("%s validation %v code=%d err=%q calls=%d", fn, argv, code, errS, len(runner.calls))
			}
		}
	}

	// The three required positionals are validated before any psql call.
	for _, missing := range []string{"--name", "--object-name", "--object-type"} {
		for _, fn := range []string{"postgres.privileges_grant", "postgres.privileges_revoke"} {
			runner := &cliRecordingRunner{}
			app := postgresCLIApp(t, runner)
			argv := []string{"exec", fn}
			for _, flag := range []string{"--name", "--object-name", "--object-type"} {
				if flag == missing {
					continue
				}
				argv = append(argv, flag, "value")
			}
			argv = append(argv, "-o", "json")
			code, _, errS := captureCode(t, app, argv...)
			if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
				len(runner.calls) != 0 {
				t.Fatalf("%s missing %s code=%d err=%q calls=%d", fn, missing, code, errS, len(runner.calls))
			}
		}
	}

	// runas is rejected before any Runner invocation.
	for _, fn := range []string{"postgres.privileges_grant", "postgres.privileges_revoke"} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		code, _, errS := captureCode(t, app, "exec", fn,
			"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
			"--privileges", "SELECT", "--runas", "postgres", "-o", "json")
		if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
			t.Fatalf("%s runas code=%d err=%q calls=%d", fn, code, errS, len(runner.calls))
		}
	}

	// A mutation-time Runner failure whose raw text embeds argv and the
	// environment surfaces redacted through the CLI.
	leak := &statementLeakRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(privCLIGrantTableCSV)},
	}}
	app = postgresCLIApp(t, leak)
	code, out, errS = captureCode(t, app, "exec", "postgres.privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--privileges", "SELECT", "--password", "testpassword", "-o", "json")
	if code != ExitFailed || out != "" || errS == "" {
		t.Fatalf("runner failure code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out+errS, "testpassword") || !strings.Contains(errS, process.RedactedPlaceholder) {
		t.Fatalf("CLI error was not redacted: %q", errS)
	}
	if strings.Contains(leak.calls[2].RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks password: %q", leak.calls[2].RedactedString())
	}
}

// defCLITableCSV renders the fixed pg_default_acl table catalog where
// baruwa holds the plain SELECT,INSERT subset, for the CLI default-
// privilege flows.
const defCLITableCSV = `nspname,name
public,"{baruwa=ar/public}"
`

// defCLIGrantTableCSV renders the catalog where baruwa holds nothing, so
// the CLI grant preflight answers false.
const defCLIGrantTableCSV = `nspname,name
public,"{bayestest=arw/baruwatest}"
`

// TestPostgresCLIDefaultPrivilegesList drives the R9.2l list path end to
// end: the fixed COPY-wrapped pg_default_acl catalog query on the full
// argv, the JSON dictionary rendering with the decoded bool-maps, the
// pinned prepend default, and no password anywhere in the rendered
// command or CLI output.
func TestPostgresCLIDefaultPrivilegesList(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(defCLITableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.default_privileges_list",
		"--name", "awl", "--object-type", "table",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var listed map[string]map[string]bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &listed) != nil ||
		len(listed) != 1 {
		t.Fatalf("list code=%d out=%q err=%q", code, out, errS)
	}
	if entry, ok := listed["baruwa"]; !ok || entry["INSERT"] || entry["SELECT"] {
		t.Fatalf("list decode = %q, want baruwa's plain INSERT/SELECT pair", out)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("list calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 17 || argv[11] != "--dbname" || argv[12] != "db_name" ||
		argv[13] != "-v" || argv[15] != "-c" ||
		!strings.Contains(argv[16], "pg_default_acl") ||
		!strings.Contains(argv[16], "defaclobjtype ='r'") ||
		!strings.HasPrefix(argv[16], "COPY (") {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=testpassword" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// The group form maps members to their admin_option booleans.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_list",
		"--name", "admin", "--object-type", "group", "-o", "json")
	var members map[string]bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &members) != nil ||
		len(members) != 2 || members["baruwa"] || !members["baruwatest2"] {
		t.Fatalf("group list code=%d out=%q err=%q", code, out, errS)
	}
}

// TestPostgresCLIDefaultPrivilegesGrant drives the R9.2l grant path end
// to end: the pinned ALTER DEFAULT PRIVILEGES statements after the
// owner-plus-catalog preflight pair (including the grant_option branch
// whose IN SCHEMA carries the on-part, the ALL TABLES IN SCHEMA variant,
// and the group ADMIN OPTION form), the JSON true rendering, and no
// password anywhere in the rendered command or CLI output.
func TestPostgresCLIDefaultPrivilegesGrant(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.default_privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "ALL", "--grant-option",
		"--maintenance-db", "db_name", "--user", "testuser",
		"--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var granted bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
		t.Fatalf("grant code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("grant calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `ALTER DEFAULT PRIVILEGES IN SCHEMA public."awl" GRANT ALL ON TABLES TO "baruwa" WITH GRANT OPTION` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Env) != 4 || command.Env[0] != "PGPASSWORD=testpassword" ||
		command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") || strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	for _, tc := range []struct {
		label     string
		argv      []string
		results   []process.CommandResult
		statement string
	}{
		{
			"table plain", []string{"--object-name", "awl", "--object-type", "table", "--defprivileges", "ALL"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
				{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
				{ExitCode: 0},
			},
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "baruwa"`,
		},
		{
			"all tables in schema", []string{"--object-name", "ALL", "--object-type", "table", "--defprivileges", "SELECT"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
				{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
				{ExitCode: 0},
			},
			`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "baruwa"`,
		},
		{
			"function with option", []string{"--object-name", "fawl", "--object-type", "function",
				"--defprivileges", "EXECUTE", "--grant-option"},
			[]process.CommandResult{
				{ExitCode: 0, Stdout: []byte(ownerCLIFunctionCSV)},
				{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
				{ExitCode: 0},
			},
			`ALTER DEFAULT PRIVILEGES IN SCHEMA fawl GRANT EXECUTE ON FUNCTIONS TO "baruwa" WITH GRANT OPTION`,
		},
	} {
		runner := &cliRecordingRunner{results: tc.results}
		app := postgresCLIApp(t, runner)
		fullArgv := append([]string{"exec", "postgres.default_privileges_grant", "--name", "baruwa"}, tc.argv...)
		fullArgv = append(fullArgv, "-o", "json")
		code, out, errS := captureCode(t, app, fullArgv...)
		var granted bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
			t.Fatalf("%s code=%d out=%q err=%q", tc.label, code, out, errS)
		}
		if got := runner.calls[2].Args[len(runner.calls[2].Args)-1]; got != tc.statement {
			t.Fatalf("%s statement = %q, want %q", tc.label, got, tc.statement)
		}
	}

	// The group grant: one membership preflight, then the raw membership
	// GRANT with ADMIN OPTION.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGrantGroupCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_grant",
		"--name", "baruwa", "--object-name", "admins", "--object-type", "group",
		"--grant-option", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &granted) != nil || !granted {
		t.Fatalf("group grant code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("group grant calls = %d, want 2", len(runner.calls))
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != `ALTER DEFAULT PRIVILEGES GRANT admins TO "baruwa" WITH ADMIN OPTION` {
		t.Fatalf("group grant statement = %q", got)
	}
}

// TestPostgresCLIDefaultPrivilegesRevoke drives the R9.2l revoke path
// end to end: the pinned REVOKE statements — including the raw role name
// of the REVOKE tail — after a preflight pair that answers held, the
// group form, the JSON true rendering, and no password in any rendered
// or CLI output.
func TestPostgresCLIDefaultPrivilegesRevoke(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLITableCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.default_privileges_revoke",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT,INSERT", "--maintenance-db", "db_name",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var revoked bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &revoked) != nil || !revoked {
		t.Fatalf("revoke code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("revoke calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" ||
		argv[14] != `ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT,INSERT ON TABLES FROM baruwa` {
		t.Fatalf("argv = %q", argv)
	}
	if len(command.Redact) != 1 || command.Redact[0] != "testpassword" ||
		command.Shell ||
		strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("unsafe command or leak: %#v %q %q", command, out, errS)
	}

	// The group form: one membership preflight where baruwa is a member,
	// then the raw REVOKE.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(privCLIGroupCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_revoke",
		"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &revoked) != nil || !revoked {
		t.Fatalf("group revoke code=%d out=%q err=%q", code, out, errS)
	}
	if got := runner.calls[1].Args[len(runner.calls[1].Args)-1]; got != "ALTER DEFAULT PRIVILEGES REVOKE admin FROM baruwa" {
		t.Fatalf("group revoke statement = %q", got)
	}
}

// TestPostgresCLIDefaultPrivilegesMutationFailures pins the CLI failure
// and no-op surface of both mutations: the already-granted and
// nothing-held no-ops answering JSON false without a mutation call, the
// fail-closed identifier boundary with the value-free stable errors, the
// pinned validation failures, the required arguments, the runas
// rejection, the nonzero-exit retcode boolean, and the redacted
// mutation-time Runner error.
func TestPostgresCLIDefaultPrivilegesMutationFailures(t *testing.T) {
	// Grant to the role that already holds the subset: false after the
	// preflight pair, no third call.
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLITableCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.default_privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT", "-o", "json")
	var noop bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &noop) != nil || noop {
		t.Fatalf("already-granted code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("already-granted calls = %d, want 2", len(runner.calls))
	}

	// Revoke from a role that holds nothing: false after the preflight
	// pair, no third call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_revoke",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT,INSERT", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &noop) != nil || noop {
		t.Fatalf("nothing-held code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("nothing-held calls = %d, want 2", len(runner.calls))
	}

	// A rejected statement keeps the pinned retcode boolean: exit OK,
	// JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
		{ExitCode: 1, Stderr: []byte(`psql: error: ERROR: relation "awl" does not exist`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// Injection attempts fail closed before any psql call, with the exact
	// value-free stable errors naming the argument key only.
	const marker = "pgmark-7f3c-secret"
	for _, tc := range []struct {
		fn   string
		argv []string
		want string
	}{
		{"postgres.default_privileges_grant", []string{"--name", `baruwa-` + marker + `"`,
			"--object-name", "awl", "--object-type", "table", "--defprivileges", "SELECT"},
			"statekit: postgres: invalid argument: unsupported quote character in name\n"},
		{"postgres.default_privileges_grant", []string{"--name", "baruwa", "--object-name", `admins; ` + marker,
			"--object-type", "group"},
			"statekit: postgres: invalid argument: unsupported identifier in object_name\n"},
		{"postgres.default_privileges_grant", []string{"--name", "baruwa", "--object-name", "awl",
			"--object-type", "table", "--defprivileges", "SELECT", "--prepend", `pub ` + marker},
			"statekit: postgres: invalid argument: unsupported identifier in prepend\n"},
		{"postgres.default_privileges_revoke", []string{"--name", `baruwa; ` + marker, "--object-name", "awl",
			"--object-type", "table", "--defprivileges", "SELECT"},
			"statekit: postgres: invalid argument: unsupported identifier in name\n"},
		{"postgres.default_privileges_revoke", []string{"--name", "baruwa", "--object-name", `admi` + marker,
			"--object-type", "group"},
			"statekit: postgres: invalid argument: unsupported identifier in object_name\n"},
	} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		argv := append([]string{"exec", tc.fn, "--password", marker}, tc.argv...)
		argv = append(argv, "-o", "json")
		code, out, errS := captureCode(t, app, argv...)
		if code != ExitFailed || errS != tc.want || len(runner.calls) != 0 {
			t.Fatalf("%s %v code=%d err=%q calls=%d, want err %q",
				tc.fn, tc.argv, code, errS, len(runner.calls), tc.want)
		}
		if strings.Contains(out+errS, marker) {
			t.Fatalf("%s output leaks the rejected value: out=%q err=%q", tc.fn, out, errS)
		}
	}

	// The pinned validation failures also fail before any psql call.
	for _, argv := range [][]string{
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "bogus", "--defprivileges", "SELECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "BOGUS"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table", "--defprivileges", "CONNECT"},
		{"--name", "baruwa", "--object-name", "awl", "--object-type", "table"},
		{"--name", "baruwa", "--object-name", "admin", "--object-type", "group", "--defprivileges", "SELECT"},
	} {
		for _, fn := range []string{"postgres.default_privileges_grant", "postgres.default_privileges_revoke"} {
			runner := &cliRecordingRunner{}
			app := postgresCLIApp(t, runner)
			fullArgv := append([]string{"exec", fn}, argv...)
			fullArgv = append(fullArgv, "-o", "json")
			code, _, errS := captureCode(t, app, fullArgv...)
			if code != ExitFailed || len(runner.calls) != 0 {
				t.Fatalf("%s validation %v code=%d err=%q calls=%d", fn, argv, code, errS, len(runner.calls))
			}
		}
	}

	// The three required positionals are validated before any psql call.
	for _, missing := range []string{"--name", "--object-name", "--object-type"} {
		for _, fn := range []string{"postgres.default_privileges_grant", "postgres.default_privileges_revoke"} {
			runner := &cliRecordingRunner{}
			app := postgresCLIApp(t, runner)
			argv := []string{"exec", fn}
			for _, flag := range []string{"--name", "--object-name", "--object-type"} {
				if flag == missing {
					continue
				}
				argv = append(argv, flag, "value")
			}
			argv = append(argv, "-o", "json")
			code, _, errS := captureCode(t, app, argv...)
			if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
				len(runner.calls) != 0 {
				t.Fatalf("%s missing %s code=%d err=%q calls=%d", fn, missing, code, errS, len(runner.calls))
			}
		}
	}

	// The default_privileges_list required positionals too.
	for _, missing := range []string{"--name", "--object-type"} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		argv := []string{"exec", "postgres.default_privileges_list"}
		for _, flag := range []string{"--name", "--object-type"} {
			if flag == missing {
				continue
			}
			argv = append(argv, flag, "value")
		}
		argv = append(argv, "-o", "json")
		code, _, errS := captureCode(t, app, argv...)
		if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") ||
			len(runner.calls) != 0 {
			t.Fatalf("list missing %s code=%d err=%q calls=%d", missing, code, errS, len(runner.calls))
		}
	}

	// runas is rejected before any Runner invocation.
	for _, fn := range []string{"postgres.default_privileges_grant", "postgres.default_privileges_revoke"} {
		runner := &cliRecordingRunner{}
		app := postgresCLIApp(t, runner)
		code, _, errS := captureCode(t, app, "exec", fn,
			"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
			"--defprivileges", "SELECT", "--runas", "postgres", "-o", "json")
		if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
			t.Fatalf("%s runas code=%d err=%q calls=%d", fn, code, errS, len(runner.calls))
		}
	}

	// A mutation-time Runner failure whose raw text embeds argv and the
	// environment surfaces redacted through the CLI.
	leak := &statementLeakRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(ownerCLITableCSV)},
		{ExitCode: 0, Stdout: []byte(defCLIGrantTableCSV)},
	}}
	app = postgresCLIApp(t, leak)
	code, out, errS = captureCode(t, app, "exec", "postgres.default_privileges_grant",
		"--name", "baruwa", "--object-name", "awl", "--object-type", "table",
		"--defprivileges", "SELECT", "--password", "testpassword", "-o", "json")
	if code != ExitFailed || out != "" || errS == "" {
		t.Fatalf("runner failure code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out+errS, "testpassword") || !strings.Contains(errS, process.RedactedPlaceholder) {
		t.Fatalf("CLI error was not redacted: %q", errS)
	}
	if strings.Contains(leak.calls[2].RedactedString(), "testpassword") {
		t.Fatalf("rendered command leaks password: %q", leak.calls[2].RedactedString())
	}
}

// cliSchemaAbsentCSV is the schema catalog without testschema: the
// schema_create preflight miss and the schema_remove post-check miss.
const cliSchemaAbsentCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n"

// cliSchemaMutationCSV is the same catalog with testschema present.
const cliSchemaMutationCSV = "name,owner,acl\n" +
	"public,postgres,\"{postgres=UC/postgres,=UC/postgres}\"\n" +
	"testschema,postgres,\"\"\n"

// TestPostgresCLISchemaCreate drives the R9.2m schema create path end to
// end with the pinned test_schema_create flags (the pinned runas="user"
// rejected by the single-user runtime): the pinned CREATE SCHEMA statement
// on the full argv after the catalog preflight, the db_password redaction,
// the AUTHORIZATION owner clause, and the existing-schema false shape.
func TestPostgresCLISchemaCreate(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaAbsentCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "maint_db", "--name", "testschema",
		"--db-user", "testuser", "--db-host", "testhost",
		"--db-port", "testport", "--db-password", "testpassword", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("schema_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	command := runner.calls[1]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `CREATE SCHEMA "testschema"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// The owner clause renders on the same pinned argv.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaAbsentCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "maint_db", "--name", "testschema",
		"--owner", "owner_role", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("owner code=%d out=%q err=%q", code, out, errS)
	}
	ownerArgs := runner.calls[1].Args
	if got := ownerArgs[len(ownerArgs)-1]; got != `CREATE SCHEMA "testschema" AUTHORIZATION "owner_role"` {
		t.Fatalf("owner statement = %q", got)
	}

	// An existing schema answers false after exactly the preflight call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaMutationCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "test_db", "--name", "testschema", "-o", "json")
	var exists bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &exists) != nil || exists {
		t.Fatalf("existing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("existing calls = %d, want 1", len(runner.calls))
	}

	// The required dbname and name fail validation before any run, an
	// injected name fails closed the same value-free way, and runas (the
	// pinned user argument) rejects before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_create", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "dbname") || len(runner.calls) != 0 {
		t.Fatalf("missing dbname code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "d", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "d", "--name", `x"-`+"pgmark", "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in name") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_create",
		"--dbname", "d", "--name", "s", "--user", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("user code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLISchemaRemove drives the R9.2m schema remove path end to
// end: the pinned DROP SCHEMA statement on the full argv between the
// preflight and post-check catalog calls, the missing-schema false shape,
// and the failed-drop false shape.
func TestPostgresCLISchemaRemove(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaMutationCSV)},
		{ExitCode: 0}, // DROP SCHEMA (retcode ignored by the pinned flow)
		{ExitCode: 0, Stdout: []byte(cliSchemaAbsentCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.schema_remove",
		"--dbname", "maint_db", "--name", "testschema",
		"--db-user", "testuser", "--db-host", "testhost",
		"--db-port", "testport", "--db-password", "testpassword", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("schema_remove code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[1]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `DROP SCHEMA "testschema"` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}

	// A missing schema answers false after one catalog call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaAbsentCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_remove",
		"--dbname", "test_db", "--name", "testschema", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing calls = %d, want 1", len(runner.calls))
	}

	// The failed DROP that leaves the schema present answers false after
	// the full three-call flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliSchemaMutationCSV)},
		{ExitCode: 1, Stderr: []byte("psql: error: ERROR: dependent objects")},
		{ExitCode: 0, Stdout: []byte(cliSchemaMutationCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.schema_remove",
		"--dbname", "maint_db", "--name", "testschema", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("failed drop code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("failed drop calls = %d, want 3", len(runner.calls))
	}

	// An injected name fails closed before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.schema_remove",
		"--dbname", "d", "--name", `x"-`+"pgmark", "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported quote character in name") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// cliExtAvailableCSV names foo in the available catalog.
const cliExtAvailableCSV = "name,default_version,comment\nfoo,1.4,foo extension\n"

// cliExtHeaderCSV is an empty installed-extensions catalog.
const cliExtHeaderCSV = "extname,extversion,extrelocatable,schema_name\n"

// cliExtInstalledCSV carries the relocatable, older foo row.
const cliExtInstalledCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,0.8,t,foo\n"

// cliExtCurrentCSV carries the settled foo row (target schema and version).
const cliExtCurrentCSV = "extname,extversion,extrelocatable,schema_name\n" +
	"foo,1.4,t,b\n"

// TestPostgresCLICreateExtension drives the R9.2m create_extension path
// end to end: the pinned CREATE EXTENSION statement (default IF NOT
// EXISTS, the full WITH clause set, the explicit --if-not-exists=false),
// the ALTER move+upgrade shape, and the unavailable false shape.
func TestPostgresCLICreateExtension(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)}, // metadata
		{ExitCode: 0, Stdout: []byte(cliExtAvailableCSV)},
		{ExitCode: 0}, // CREATE EXTENSION
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "testpassword", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("create_extension code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("runner calls = %d, want 4", len(runner.calls))
	}
	command := runner.calls[2]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `CREATE EXTENSION IF NOT EXISTS "foo" ;` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// The full WITH clause set on the same flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
		{ExitCode: 0, Stdout: []byte(cliExtAvailableCSV)},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--schema", "b", "--ext-version", "1.4",
		"--from-version", "unpackaged", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("full options code=%d out=%q err=%q", code, out, errS)
	}
	if got := lastCommandArg(runner, 2); got != `CREATE EXTENSION IF NOT EXISTS "foo" WITH SCHEMA "b" VERSION 1.4 FROM unpackaged ;` {
		t.Fatalf("full options statement = %q", got)
	}

	// --if-not-exists=false drops the clause.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
		{ExitCode: 0, Stdout: []byte(cliExtAvailableCSV)},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--if-not-exists=false", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("if-not-exists=false code=%d out=%q err=%q", code, out, errS)
	}
	if got := lastCommandArg(runner, 2); got != `CREATE EXTENSION "foo" ;` {
		t.Fatalf("if-not-exists=false statement = %q", got)
	}

	// The installed branch renders the pinned ALTER pair.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtInstalledCSV)},
		{ExitCode: 0, Stdout: []byte(cliExtAvailableCSV)},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--schema", "b", "--ext-version", "1.4", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("alter code=%d out=%q err=%q", code, out, errS)
	}
	if got := lastCommandArg(runner, 2); got != `ALTER EXTENSION "foo" SET SCHEMA "b"; ALTER EXTENSION "foo" UPDATE TO 1.4;` {
		t.Fatalf("alter statement = %q", got)
	}

	// An unavailable extension issues no statement and answers false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
		{ExitCode: 0, Stdout: []byte("name,default_version\nbar,1.0\n")},
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "-o", "json")
	var unavailable bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &unavailable) != nil || unavailable {
		t.Fatalf("unavailable code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("unavailable calls = %d, want 3 (no statement)", len(runner.calls))
	}

	// The required name fails validation before any run, an injected
	// version token fails closed value-free, and runas rejects the same
	// way.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.create_extension", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--ext-version", "1.0; "+strings.Repeat("pgmark", 1), "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported identifier in ext_version") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected version code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.create_extension",
		"--name", "foo", "--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 0 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIDropExtension drives the R9.2m drop_extension path end
// to end: the default CASCADE statement with the pinned space before the
// semicolon, the IF EXISTS variant, the never-installed true shape with no
// statement, and the still-installed false shape.
func TestPostgresCLIDropExtension(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.drop_extension",
		"--name", "foo", "--user", "testuser", "--host", "testhost",
		"--port", "testport", "--maintenance-db", "maint_db",
		"--password", "testpassword", "-o", "json")
	var dropped bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &dropped) != nil || !dropped {
		t.Fatalf("drop_extension code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3", len(runner.calls))
	}
	command := runner.calls[1]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != `DROP EXTENSION foo CASCADE ;` {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}
	if strings.Contains(command.RedactedString(), "testpassword") ||
		strings.Contains(out+errS, "testpassword") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// IF EXISTS renders before the raw name.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.drop_extension",
		"--name", "foo", "--if-exists", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &dropped) != nil || !dropped {
		t.Fatalf("if-exists code=%d out=%q err=%q", code, out, errS)
	}
	if got := lastCommandArg(runner, 1); got != `DROP EXTENSION IF EXISTS foo CASCADE ;` {
		t.Fatalf("if-exists statement = %q", got)
	}

	// A never-installed extension answers true with no statement.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
		{ExitCode: 0, Stdout: []byte(cliExtHeaderCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.drop_extension",
		"--name", "foo", "-o", "json")
	var absent bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &absent) != nil || !absent {
		t.Fatalf("absent code=%d out=%q err=%q, want true", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("absent calls = %d, want 2 (no statement)", len(runner.calls))
	}

	// A still-installed extension answers false after the full flow.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
		{ExitCode: 1, Stderr: []byte("psql: error: ERROR: dependent objects")},
		{ExitCode: 0, Stdout: []byte(cliExtCurrentCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.drop_extension",
		"--name", "foo", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("failed code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("failed calls = %d, want 3", len(runner.calls))
	}

	// An injected raw name fails closed before any run.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.drop_extension",
		"--name", "foo; "+strings.Repeat("pgmark", 1), "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported identifier in name") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLILanguageMutations drives the R9.2m language create and
// remove paths end to end with the pinned test arguments: the pinned
// CREATE/DROP LANGUAGE statements on the full argv after the
// connection-less preflight, the existing/missing no-op false shapes, and
// the value-free identifier rejection.
func TestPostgresCLILanguageMutations(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.language_create",
		"--name", "plpythonu", "--maintenance-db", "testdb",
		"--user", "testuser", "--host", "testhost", "--port", "testport",
		"--password", "testpassword", "-o", "json")
	var created bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &created) != nil || !created {
		t.Fatalf("language_create code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	// The pinned preflight passes only (name, maintenance_db): the
	// catalog call carries no connection flags.
	preflight := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	joined := strings.Join(preflight, " ")
	for _, flag := range []string{"--username", "--host", "--port"} {
		if strings.Contains(joined, flag) {
			t.Fatalf("preflight argv carries %s: %q", flag, preflight)
		}
	}
	command := runner.calls[1]
	argv := append([]string{command.Name}, command.Args...)
	if len(argv) != 15 || argv[13] != "-c" || argv[14] != "CREATE LANGUAGE plpythonu" {
		t.Fatalf("argv = %q", argv)
	}
	if command.Shell || len(command.Redact) != 1 || command.Redact[0] != "testpassword" {
		t.Fatalf("unsafe command: %#v", command)
	}

	// The existing-language no-op answers false after one catalog call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.language_create",
		"--name", "plpgsql", "--maintenance-db", "testdb", "-o", "json")
	var exists bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &exists) != nil || exists {
		t.Fatalf("existing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("existing calls = %d, want 1", len(runner.calls))
	}

	// The remove flow mirrors create on the pinned DROP argv.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.language_remove",
		"--name", "plpgsql", "--maintenance-db", "testdb", "-o", "json")
	var removed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &removed) != nil || !removed {
		t.Fatalf("language_remove code=%d out=%q err=%q", code, out, errS)
	}
	if got := lastCommandArg(runner, 1); got != "DROP LANGUAGE plpgsql" {
		t.Fatalf("statement = %q", got)
	}

	// The missing-language no-op answers false after one catalog call.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.language_remove",
		"--name", "plpythonu", "--maintenance-db", "testdb", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("missing calls = %d, want 1", len(runner.calls))
	}

	// The required name and maintenance_db fail validation before any
	// run, an injected name fails closed value-free, and runas rejects
	// after the connection-less preflight exactly like the module test.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.language_create", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.language_create",
		"--name", "plpythonu", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "maintenance_db") || len(runner.calls) != 0 {
		t.Fatalf("missing maintenance_db code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.language_remove",
		"--name", "plpgsql; "+strings.Repeat("pgmark", 1), "--maintenance-db", "d", "-o", "json")
	if code != ExitFailed ||
		!strings.Contains(errS, "postgres: invalid argument: unsupported identifier in name") ||
		len(runner.calls) != 0 {
		t.Fatalf("injected name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(pinnedCLILanguageCSV)},
	}}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.language_create",
		"--name", "plpythonu", "--maintenance-db", "testdb",
		"--runas", "postgres", "-o", "json")
	if code != ExitFailed || !strings.Contains(errS, "runas") || len(runner.calls) != 1 {
		t.Fatalf("runas code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

func TestPostgresCLILanguagePreflightRedaction(t *testing.T) {
	const marker = "synthetic-language-preflight-marker"
	for _, fn := range []string{"postgres.language_create", "postgres.language_remove"} {
		for _, db := range []string{"maintenance", "db_" + marker + "_overlap"} {
			runner := &cliRecordingRunner{results: []process.CommandResult{{
				Err:    errors.New("first catalog failure: " + marker + " " + db),
				Stdout: []byte(marker), Stderr: []byte(marker),
			}}}
			code, out, errS := captureCode(t, postgresCLIApp(t, runner), "exec", fn,
				"--name", "plpgsql", "--maintenance-db", db, "--password", marker,
				"--user", "ignored-user", "--host", "ignored-host", "--port", "1234", "--runas", "ignored-runas", "-o", "json")
			if code != ExitFailed || strings.TrimSpace(out) != "" || strings.Contains(out+errS, marker) || !strings.Contains(errS, "first catalog failure") {
				t.Fatal("CLI must return the redacted first catalog error without stdout")
			}
			if len(runner.calls) != 1 {
				t.Fatalf("%s calls = %d, want one catalog and zero mutations", fn, len(runner.calls))
			}
			cmd := runner.calls[0]
			want := []string{"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password", "--dbname", db,
				"-v", "datestyle=ISO,MDY", "-c", `COPY (SELECT lanname AS "Name" FROM pg_language) TO STDOUT WITH CSV HEADER`}
			if !reflect.DeepEqual(append([]string{cmd.Name}, cmd.Args...), want) || cmd.Shell {
				t.Fatal("pinned catalog argv changed")
			}
			if cmd.Env == nil || len(cmd.Env) != 0 {
				t.Fatal("preflight must not authenticate or inherit environment")
			}
			if !reflect.DeepEqual(cmd.Redact, []string{marker}) || strings.Contains(cmd.RedactedString(), marker) {
				t.Fatal("catalog command leaks synthetic marker")
			}
		}
	}
}

func TestPostgresCLICreateExtensionEmptyVersions(t *testing.T) {
	for _, flags := range [][]string{nil, {"--ext-version="}, {"--from-version="}, {"--ext-version=", "--from-version="}} {
		for _, installed := range []bool{false, true} {
			first := cliExtHeaderCSV
			if installed {
				first = cliExtCurrentCSV
			}
			results := []process.CommandResult{{Stdout: []byte(first)}, {Stdout: []byte(cliExtAvailableCSV)}}
			queries := []string{
				"COPY (select a.*, b.nspname as schema_name from pg_extension a,  pg_namespace b where a.extnamespace = b.oid) TO STDOUT WITH CSV HEADER",
				"COPY (select * from pg_available_extensions()) TO STDOUT WITH CSV HEADER",
			}
			if !installed {
				results = append(results, process.CommandResult{})
				queries = append(queries, `CREATE EXTENSION IF NOT EXISTS "foo" ;`)
			}
			results = append(results, process.CommandResult{Stdout: []byte(cliExtCurrentCSV)})
			queries = append(queries, queries[0])
			runner := &cliRecordingRunner{results: results}
			args := []string{"exec", "postgres.create_extension", "--name", "foo", "--user", "u", "--host", "h", "--port", "5432", "--maintenance-db", "d", "-o", "json"}
			args = append(args, flags...)
			code, out, errS := captureCode(t, postgresCLIApp(t, runner), args...)
			if code != ExitOK || strings.TrimSpace(out) != "true" || errS != "" {
				t.Fatalf("flags=%q installed=%t code=%d out=%q err=%q", flags, installed, code, out, errS)
			}
			if len(runner.calls) != len(queries) {
				t.Fatalf("calls = %d, want %d", len(runner.calls), len(queries))
			}
			for i, query := range queries {
				want := []string{"psql", "--no-align", "--no-readline", "--no-psqlrc", "--no-password", "--username", "u", "--host", "h", "--port", "5432", "--dbname", "d"}
				if strings.HasPrefix(query, "COPY") {
					want = append(want, "-v", "datestyle=ISO,MDY")
				}
				want = append(want, "-c", query)
				cmd := runner.calls[i]
				if !reflect.DeepEqual(append([]string{cmd.Name}, cmd.Args...), want) || cmd.Shell {
					t.Fatalf("call %d = %q, want %q", i, cmd.Args, want)
				}
			}
		}
	}
	// Nonempty unsafe tokens still fail value-free before any catalog call.
	for _, field := range []string{"ext-version", "from-version"} {
		runner := &cliRecordingRunner{}
		code, out, errS := captureCode(t, postgresCLIApp(t, runner), "exec", "postgres.create_extension", "--name", "foo", "--"+field, "synthetic-version-marker;", "-o", "json")
		if code != ExitFailed || strings.Contains(out+errS, "synthetic-version-marker") || !strings.Contains(errS, "unsupported identifier in "+strings.ReplaceAll(field, "-", "_")) || len(runner.calls) != 0 {
			t.Fatal("unsafe nonempty version must fail value-free without execution")
		}
	}
}

// lastCommandArg returns the trailing argument (the SQL statement) of the
// runner's call at the given index.
func lastCommandArg(runner *cliRecordingRunner, call int) string {
	args := runner.calls[call].Args
	return args[len(args)-1]
}

// cliSeedDatadir seeds both pinned datadir marker files under dir.
func cliSeedDatadir(t *testing.T, dir string) func(fsys runtime.FileSystem) {
	return func(fsys runtime.FileSystem) {
		if err := fsys.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{"PG_VERSION", "postgresql.conf"} {
			if err := fsys.WriteFile(dir+"/"+marker, []byte("9.6\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestPostgresCLIDatadirExists drives the R9.2p datadir_exists path end
// to end over the CLI's fake FS: the JSON true/false marker shapes, the
// value-free path rejections, the required name, and zero Runner calls on
// every path (the probe is read-only and never touches a Runner).
func TestPostgresCLIDatadirExists(t *testing.T) {
	runner := &cliRecordingRunner{}
	app := postgresCLIAppFS(t, runner, cliSeedDatadir(t, "/var/lib/pgsql/data"))
	code, out, errS := captureCode(t, app, "exec", "postgres.datadir_exists",
		"--name", "/var/lib/pgsql/data", "-o", "json")
	var exists bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &exists) != nil || !exists {
		t.Fatalf("datadir_exists code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("probe executed %d commands", len(runner.calls))
	}

	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.datadir_exists",
		"--name", "/var/lib/pgsql/data", "-o", "json")
	var missing bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &missing) != nil || missing {
		t.Fatalf("missing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("missing probe executed %d commands", len(runner.calls))
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"relative name", "var/lib/pgsql/data"},
		{"traversal name", "/var/lib/pgsql/../data"},
		{"trailing slash", "/var/lib/pgsql/data/"},
		{"control byte", "/var/lib/pgsql/da\tta"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		code, _, errS = captureCode(t, app, "exec", "postgres.datadir_exists",
			"--name", tc.path, "-o", "json")
		if code != ExitFailed ||
			!strings.Contains(errS, "postgres: invalid argument: invalid data directory path") ||
			strings.Contains(errS, tc.path) ||
			len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}

	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.datadir_exists", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// TestPostgresCLIDatadirInit drives the R9.2p datadir_init path end to
// end with the pinned test_datadir_init and test__run_initdb_with_timeout
// vectors (the pinned runas rejected by the single-user runtime, so the
// --username it would have contributed is supplied directly): the
// byte-exact pinned argv with no password token, the pwfile transport and
// db_password redaction, the existing-datadir false no-op with no
// statement, the retcode-false compatibility shape, the value-free path
// and waldir rejections, and the required name.
func TestPostgresCLIDatadirInit(t *testing.T) {
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app := postgresCLIApp(t, runner)
	code, out, errS := captureCode(t, app, "exec", "postgres.datadir_init",
		"--name", "/var/lib/pgsql/data",
		"--user", "postgres", "--password", "test", "-o", "json")
	var initialized bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &initialized) != nil || !initialized {
		t.Fatalf("datadir_init code=%d out=%q err=%q", code, out, errS)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.calls))
	}
	command := runner.calls[0]
	argv := append([]string{command.Name}, command.Args...)
	wantHead := []string{
		"initdb",
		"--pgdata=/var/lib/pgsql/data",
		"--username=postgres",
		"--auth=password",
		"--encoding=UTF8",
	}
	if len(argv) != 6 || !reflect.DeepEqual(argv[:5], wantHead) {
		t.Fatalf("argv = %q, want %q plus one pwfile entry", argv, wantHead)
	}
	if !strings.HasPrefix(argv[5], "--pwfile=/tmp/") {
		t.Fatalf("pwfile entry = %q", argv[5])
	}
	if strings.Contains(strings.Join(argv, "\x00"), "test") {
		t.Fatalf("argv carries the password token: %q", argv)
	}
	if len(command.Env) != 0 || command.Shell || len(command.Stdin) != 0 {
		t.Fatalf("unsafe command: %#v", command)
	}
	if len(command.Redact) != 1 || command.Redact[0] != "test" {
		t.Fatalf("redact = %q, want the password", command.Redact)
	}
	if strings.Contains(command.RedactedString(), "test") || strings.Contains(out+errS, "test") {
		t.Fatalf("password leaked: %q %q", command.RedactedString(), out+errS)
	}

	// The full pinned option set: auth, encoding, locale, the short -X
	// waldir pair, checksums, and the user override.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.datadir_init",
		"--name", "/var/lib/pgsql/data",
		"--auth", "md5", "--user", "testuser", "--encoding", "LATIN1",
		"--locale", "en_US.UTF-8", "--waldir", "/var/lib/postgresql/wal",
		"--checksums", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &initialized) != nil || !initialized {
		t.Fatalf("full flags code=%d out=%q err=%q", code, out, errS)
	}
	argv = append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
	wantFull := []string{
		"initdb",
		"--pgdata=/var/lib/pgsql/data",
		"--username=testuser",
		"--auth=md5",
		"--encoding=LATIN1",
		"--locale=en_US.UTF-8",
		"-X", "/var/lib/postgresql/wal",
		"--data-checksums",
	}
	if !reflect.DeepEqual(argv[:len(wantFull)], wantFull) {
		t.Fatalf("full argv = %q, want %q", argv, wantFull)
	}
	if argv[len(argv)-1] != "--data-checksums" {
		t.Fatalf("no-password argv tail = %q, want --data-checksums last", argv[len(argv)-1])
	}

	// An initialized datadir answers the pinned logged-and-False no-op
	// with no statement at all.
	runner = &cliRecordingRunner{}
	app = postgresCLIAppFS(t, runner, cliSeedDatadir(t, "/var/lib/pgsql/data"))
	code, out, errS = captureCode(t, app, "exec", "postgres.datadir_init",
		"--name", "/var/lib/pgsql/data", "-o", "json")
	var existsFalse bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &existsFalse) != nil || existsFalse {
		t.Fatalf("existing code=%d out=%q err=%q, want false", code, out, errS)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("existing datadir executed %d commands", len(runner.calls))
	}

	// A rejected initdb keeps Salt's retcode boolean: exit OK, JSON false.
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{ExitCode: 1, Stderr: []byte(`initdb: error: directory "/var/lib/pgsql/data" contains files`)},
	}}
	app = postgresCLIApp(t, runner)
	code, out, errS = captureCode(t, app, "exec", "postgres.datadir_init",
		"--name", "/var/lib/pgsql/data", "-o", "json")
	var failed bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &failed) != nil || failed {
		t.Fatalf("nonzero exit code=%d out=%q err=%q, want false", code, out, errS)
	}

	// The fail-closed path boundaries reject before any initdb call.
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"relative name", []string{"--name", "var/lib/pgsql/data"},
			"postgres: invalid argument: invalid data directory path"},
		{"traversal name", []string{"--name", "/var/lib/../pgsql/data"},
			"postgres: invalid argument: invalid data directory path"},
		{"relative waldir", []string{"--name", "/var/lib/pgsql/data", "--waldir", "wal"},
			"postgres: invalid argument: invalid wal directory path"},
		{"waldir traversal", []string{"--name", "/var/lib/pgsql/data", "--waldir", "/wal/../x"},
			"postgres: invalid argument: invalid wal directory path"},
		{"runas", []string{"--name", "/var/lib/pgsql/data", "--runas", "postgres"},
			"runas"},
	} {
		runner = &cliRecordingRunner{}
		app = postgresCLIApp(t, runner)
		fullArgv := append(append([]string{"exec", "postgres.datadir_init"}, tc.argv...), "-o", "json")
		code, _, errS = captureCode(t, app, fullArgv...)
		if code != ExitFailed || !strings.Contains(errS, tc.want) || len(runner.calls) != 0 {
			t.Fatalf("%s code=%d err=%q calls=%d", tc.name, code, errS, len(runner.calls))
		}
	}

	// The required name fails validation first.
	runner = &cliRecordingRunner{}
	app = postgresCLIApp(t, runner)
	code, _, errS = captureCode(t, app, "exec", "postgres.datadir_init", "-o", "json")
	if code != ExitInvalidInput || !strings.Contains(errS, "name") || len(runner.calls) != 0 {
		t.Fatalf("missing name code=%d err=%q calls=%d", code, errS, len(runner.calls))
	}
}

// cliPostgresFaultFS wraps the CLI runtime's memory filesystem with the
// R9.2p pwfile fault injections; the injected raw errors carry synthetic
// password, path, and stderr markers the CLI error path must not echo.
type cliPostgresFaultFS struct {
	runtime.FileSystem
	failMkdir    bool
	failWrite    bool
	failRemove   bool
	failMkdirErr error
	failWriteErr error
}

func (f *cliPostgresFaultFS) MkdirTemp(dir, pattern string) (string, error) {
	if f.failMkdir {
		if f.failMkdirErr != nil {
			return "", f.failMkdirErr
		}
		return "", &fs.PathError{Op: "mkdirtemp", Path: dir, Err: syscall.EACCES}
	}
	return f.FileSystem.MkdirTemp(dir, pattern)
}

func (f *cliPostgresFaultFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if f.failWrite {
		if f.failWriteErr != nil {
			return f.failWriteErr
		}
		return &fs.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return f.FileSystem.WriteFile(name, data, perm)
}

func (f *cliPostgresFaultFS) RemoveAll(pathName string) error {
	if f.failRemove {
		return &fs.PathError{Op: "remove", Path: pathName, Err: syscall.EACCES}
	}
	return f.FileSystem.RemoveAll(pathName)
}

// TestPostgresCLIDatadirInitPwfileErrorRedaction pins the CLI half of the
// value-free pwfile preparation passthrough: fault-injected filesystem
// errors carrying synthetic password, path, and stderr markers surface as
// the exact fixed sentinel stderr lines (the joined write-plus-cleanup
// shape when both fail), with empty stdout, zero Runner invocations, and
// no marker anywhere in the CLI output.
func TestPostgresCLIDatadirInitPwfileErrorRedaction(t *testing.T) {
	const (
		passwordMarker = "synthetic-cli-pwfile-password"
		pathMarker     = "/synthetic/cli-pwfile-path"
		stderrMarker   = "synthetic cli pwfile stderr"
	)
	for _, tc := range []struct {
		label string
		stub  *cliPostgresFaultFS
		want  string
	}{
		{"mkdirtemp failure", &cliPostgresFaultFS{
			failMkdir:    true,
			failMkdirErr: fmt.Errorf("mkdir %s: %s: %s", pathMarker, passwordMarker, stderrMarker),
		}, "statekit: postgres: password file temp directory failed\n"},
		{"write failure", &cliPostgresFaultFS{
			failWrite:    true,
			failWriteErr: fmt.Errorf("open %s/pwfile: %s: %s", pathMarker, passwordMarker, stderrMarker),
		}, "statekit: postgres: password file write failed\n"},
		{"double failure", &cliPostgresFaultFS{
			failWrite:    true,
			failRemove:   true,
			failWriteErr: fmt.Errorf("open %s/pwfile: %s: %s", pathMarker, passwordMarker, stderrMarker),
		}, "statekit: postgres: password file write failed\npostgres: password file cleanup failed\n"},
	} {
		runner := &cliRecordingRunner{}
		tc.stub.FileSystem = runtime.NewMemoryFS()
		app := postgresCLIAppConfigured(t, runner, func(rt *runtime.Runtime) { rt.FS = tc.stub })
		code, out, errS := captureCode(t, app, "exec", "postgres.datadir_init",
			"--name", "/var/lib/pgsql/data", "--password", passwordMarker, "-o", "json")
		if code != ExitFailed || out != "" || errS != tc.want {
			t.Fatalf("%s code=%d out=%q err=%q, want the exact %q", tc.label, code, out, errS, tc.want)
		}
		for _, marker := range []string{passwordMarker, pathMarker, stderrMarker} {
			if strings.Contains(out+errS, marker) {
				t.Fatalf("%s leaks the marker %q: out=%q err=%q", tc.label, marker, out, errS)
			}
		}
		if len(runner.calls) != 0 {
			t.Fatalf("%s executed %d commands", tc.label, len(runner.calls))
		}
	}
}

// TestPostgresCLIDatadirInitKernelDefaultUser pins the CLI half of the
// pinned kernel-mapped runas default of _run_initdb: an OpenBSD-facts
// runtime renders --username=_postgresql, FreeBSD and Linux-family
// runtimes keep --username=postgres, and an explicit --user flag
// overrides on every kernel including the pinned empty-string shape —
// argv vectors only, with no native initdb execution claimed for any
// kernel.
func TestPostgresCLIDatadirInitKernelDefaultUser(t *testing.T) {
	for _, tc := range []struct {
		label   string
		family  string
		userArg []string
		want    string
	}{
		{"openbsd default", facts.FamilyOpenBSD, nil, "--username=_postgresql"},
		{"openbsd explicit user", facts.FamilyOpenBSD, []string{"--user", "pgadmin"}, "--username=pgadmin"},
		{"openbsd explicit empty", facts.FamilyOpenBSD, []string{"--user="}, "--username="},
		{"debian linux default", facts.FamilyDebian, nil, "--username=postgres"},
		{"freebsd default", facts.FamilyFreeBSD, nil, "--username=postgres"},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0}}}
		app := postgresCLIAppConfigured(t, runner, func(rt *runtime.Runtime) {
			rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: tc.family}})
		})
		argv := append([]string{"exec", "postgres.datadir_init", "--name", "/var/lib/pgsql/data"}, tc.userArg...)
		argv = append(argv, "-o", "json")
		code, out, errS := captureCode(t, app, argv...)
		var initialized bool
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &initialized) != nil || !initialized {
			t.Fatalf("%s code=%d out=%q err=%q", tc.label, code, out, errS)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("%s runner calls = %d, want 1", tc.label, len(runner.calls))
		}
		if got := runner.calls[0].Args[1]; got != tc.want {
			t.Fatalf("%s argv username = %q, want %q", tc.label, got, tc.want)
		}
	}
}
