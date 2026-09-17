package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpostgres "github.com/friz-zy/statekit/modules/exec/postgres"
)

// postgresCLIApp builds a CLI app whose runtime carries only the postgres
// module and a recording fake Runner: the R9.2b surface is mock-only and
// must never reach a real psql or database.
func postgresCLIApp(t *testing.T, runner *cliRecordingRunner) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
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
