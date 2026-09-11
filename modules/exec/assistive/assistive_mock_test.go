package assistive

// R6.10 mock tests for the Darwin TCC assistive surface, mapped onto
// saltstack/salt/modules/mac_assistive.py @ pinned revision
// 8b63e700637e and tests/pytests/unit/modules/test_mac_assistive.py:
// exact sqlite3 argv/order, per-schema query texts, sqlite error shapes,
// schema-detection boundaries, enabled-value coercion and the registry
// matrix. All Runner output is scripted; no real sqlite3 binary is
// required.

import (
	"context"
	"crypto/sha1" // mirrors production's schema digest, not a security use
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// shortDigest mirrors detectSchema's sha1[:10] schema fingerprint so the
// unknown-structure error text can be asserted without magic constants.
func shortDigest(text string) string {
	digest := sha1.Sum([]byte(text))
	return hex.EncodeToString(digest[:])[:10]
}

// scriptAssistiveRunner returns scripted CommandResults in order and
// records every command for argv assertions.
type scriptAssistiveRunner struct {
	script []process.CommandResult
	calls  []process.Command
}

func (r *scriptAssistiveRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := r.script[0]
	r.script = r.script[1:]
	return next
}

func assistiveRows(rows []map[string]any) process.CommandResult {
	data, _ := json.Marshal(rows)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func assistiveSchema(t *testing.T, schema schemaKind) *runtime.Runtime {
	t.Helper()
	runner := &scriptAssistiveRunner{}
	oldDetector := schemaDetector
	schemaDetector = func(context.Context, *runtime.Runtime) (schemaKind, error) { return schema, nil }
	t.Cleanup(func() { schemaDetector = oldDetector })
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func argvOf(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), "\x00")
}

// ---------------------------------------------------------------------------
// sqlite argv and query text

func TestSqliteArgvOrderAndDefaultPath(t *testing.T) {
	oldPath := tccDBPath
	tccDBPath = "/custom/TCC.db"
	t.Cleanup(func() { tccDBPath = oldPath })
	rt := &runtime.Runtime{Runner: &scriptAssistiveRunner{}, FS: runtime.NewMemoryFS()}
	if _, err := sqliteQuery(ctxBG(), rt, "SELECT 1;"); err != nil {
		t.Fatal(err)
	}
	if err := sqliteExec(ctxBG(), rt, "DELETE;"); err != nil {
		t.Fatal(err)
	}
	runner := rt.Runner.(*scriptAssistiveRunner)
	if got := argvOf(runner.calls[0]); got != "sqlite3\x00-json\x00/custom/TCC.db\x00SELECT 1;" {
		t.Fatalf("query argv = %q", got)
	}
	if got := argvOf(runner.calls[1]); got != "sqlite3\x00/custom/TCC.db\x00DELETE;" {
		t.Fatalf("exec argv = %q", got)
	}
	if defaultTCCDBPath != "/Library/Application Support/com.apple.TCC/TCC.db" {
		t.Fatalf("default TCC path = %q", defaultTCCDBPath)
	}
}

func ctxBG() context.Context { return context.Background() }

func TestInstalledAndEnabledQueryTexts(t *testing.T) {
	for _, schema := range []schemaKind{schemaMojaveCatalina, schemaBigSur, schemaSonoma} {
		rt := assistiveSchema(t, schema)
		runner := rt.Runner.(*scriptAssistiveRunner)
		runner.script = []process.CommandResult{
			assistiveRows([]map[string]any{{"present": float64(1)}}),
			assistiveRows([]map[string]any{{"enabled": float64(1)}}),
		}
		if _, err := queryInstalled(ctxBG(), rt, "com.example.app"); err != nil {
			t.Fatal(err)
		}
		if _, err := queryEnabled(ctxBG(), rt, "com.example.app"); err != nil {
			t.Fatal(err)
		}
		wantColumn := "allowed"
		if schema != schemaMojaveCatalina {
			wantColumn = "auth_value"
		}
		wantQuery := "SELECT 1 AS present FROM access WHERE client='com.example.app' AND service='kTCCServiceAccessibility' LIMIT 1;"
		if got := runner.calls[0].Args[2]; got != wantQuery {
			t.Fatalf("%s installed query = %q", schema, got)
		}
		wantEnabled := "SELECT " + wantColumn + " AS enabled FROM access WHERE client='com.example.app' AND service='kTCCServiceAccessibility' LIMIT 1;"
		if got := runner.calls[1].Args[2]; got != wantEnabled {
			t.Fatalf("%s enabled query = %q", schema, got)
		}
	}
}

func TestInstallUpdateRemoveQueryTexts(t *testing.T) {
	// installQuery pins Salt's per-schema INSERT statements verbatim
	// (client type 0 = bundle id, auth slot carries enable).
	vectors := []struct {
		schema schemaKind
		want   string
	}{
		{schemaMojaveCatalina, "INSERT OR REPLACE INTO access VALUES ('kTCCServiceAccessibility','com.example.app',0,1,1,NULL,NULL,NULL,'UNUSED',NULL,0,0);"},
		{schemaBigSur, "INSERT OR REPLACE INTO access VALUES ('kTCCServiceAccessibility','com.example.app',0,1,4,1,NULL,NULL,0,'UNUSED',NULL,0,0);"},
		{schemaSonoma, "INSERT OR REPLACE INTO access VALUES ('kTCCServiceAccessibility','com.example.app',0,1,4,1,NULL,NULL,NULL,'UNUSED',NULL,0,0,0,0,'UNUSED',strftime('%s','now'));"},
	}
	for _, vector := range vectors {
		got, err := installQuery(vector.schema, "com.example.app", true)
		if err != nil || got != vector.want {
			t.Fatalf("%s install query = %q %v", vector.schema, got, err)
		}
	}
	disabled, err := installQuery(schemaBigSur, "/usr/bin/osascript", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(disabled, "'/usr/bin/osascript',1,0,4,1") {
		t.Fatalf("disabled command install = %q", disabled)
	}
	if _, err := installQuery(schemaKind("bogus"), "x", true); err == nil ||
		err.Error() != `unknown TCC schema "bogus"` {
		t.Fatalf("unknown install schema = %v", err)
	}
	update, err := updateEnabledQuery(schemaMojaveCatalina, "com.example.app", false)
	if err != nil {
		t.Fatal(err)
	}
	if update != "UPDATE access SET allowed=0 WHERE client='com.example.app' AND service IS 'kTCCServiceAccessibility';" {
		t.Fatalf("mojave update = %q", update)
	}
	update, err = updateEnabledQuery(schemaSonoma, "com.example.app", true)
	if err != nil {
		t.Fatal(err)
	}
	if update != "UPDATE access SET auth_value=1 WHERE client='com.example.app' AND service IS 'kTCCServiceAccessibility';" {
		t.Fatalf("sonoma update = %q", update)
	}
	if _, err := updateEnabledQuery(schemaKind("bogus"), "x", true); err == nil {
		t.Fatal("unknown update schema must fail")
	}
}

func TestSqlQuoteAndClientType(t *testing.T) {
	if got := sqlQuote("it's"); got != "'it''s'" {
		t.Fatalf("sqlQuote = %q", got)
	}
	if _, err := clientType(""); err == nil || err.Error() != "app_id cannot be empty" {
		t.Fatalf("empty app_id = %v", err)
	}
	if query, err := installQuery(schemaBigSur, "", true); err == nil || query != "" {
		t.Fatalf("install with empty app id = %q %v", query, err)
	}
}

// ---------------------------------------------------------------------------
// enable/remove flow argv and short-circuits

func TestEnableFlowArgvAndMissingShortCircuit(t *testing.T) {
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{
		assistiveRows([]map[string]any{{"present": float64(1)}}), // installed probe
		process.CommandResult{ExitCode: 0},                       // UPDATE
	}
	ok, err := enableImpl(ctxBG(), rt, "com.example.app", true)
	if err != nil || !ok {
		t.Fatalf("enable = %v %v", ok, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("enable calls = %d", len(runner.calls))
	}
	if got := argvOf(runner.calls[1]); got != "sqlite3\x00/Library/Application Support/com.apple.TCC/TCC.db\x00UPDATE access SET auth_value=1 WHERE client='com.example.app' AND service IS 'kTCCServiceAccessibility';" {
		t.Fatalf("update argv = %q", got)
	}
	// enable for a missing app: no UPDATE is sent and the result is false
	// without error (Salt enable_false contract).
	runner.script = []process.CommandResult{assistiveRows(nil)}
	ok, err = enableImpl(ctxBG(), rt, "ghost", true)
	if err != nil || ok {
		t.Fatalf("missing enable = %v %v", ok, err)
	}
	if strings.Contains(argvOf(runner.calls[len(runner.calls)-1]), "UPDATE") {
		t.Fatal("missing app must not reach UPDATE")
	}
}

func TestRemoveFlowArgvAndMissingShortCircuit(t *testing.T) {
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{
		assistiveRows([]map[string]any{{"present": float64(1)}}),
		process.CommandResult{ExitCode: 0},
	}
	ok, err := removeImpl(ctxBG(), rt, "com.example.app")
	if err != nil || !ok {
		t.Fatalf("remove = %v %v", ok, err)
	}
	if got := argvOf(runner.calls[1]); got != "sqlite3\x00/Library/Application Support/com.apple.TCC/TCC.db\x00DELETE FROM access WHERE client IS 'com.example.app' AND service IS 'kTCCServiceAccessibility';" {
		t.Fatalf("delete argv = %q", got)
	}
	runner.script = []process.CommandResult{assistiveRows(nil)}
	ok, err = removeImpl(ctxBG(), rt, "ghost")
	if err != nil || ok {
		t.Fatalf("missing remove = %v %v", ok, err)
	}
	if strings.Contains(argvOf(runner.calls[len(runner.calls)-1]), "DELETE") {
		t.Fatal("missing app must not reach DELETE")
	}
}

// ---------------------------------------------------------------------------
// enabled value coercion (sqlite -json may hand back floats, bools or text)

func TestQueryEnabledValueCoercion(t *testing.T) {
	vectors := []struct {
		payload any
		want    bool
	}{
		{float64(0), false},
		{float64(2), true},
		{true, true},
		{false, false},
		{"0", false},
		{"", false},
		{"1", true},
		{"yes", true},
	}
	for _, vector := range vectors {
		rt := assistiveSchema(t, schemaBigSur)
		runner := rt.Runner.(*scriptAssistiveRunner)
		runner.script = []process.CommandResult{
			assistiveRows([]map[string]any{{"enabled": vector.payload}}),
		}
		got, err := queryEnabled(ctxBG(), rt, "app")
		if err != nil || got != vector.want {
			t.Fatalf("enabled coercion %#v = %v %v", vector.payload, got, err)
		}
	}
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{assistiveRows([]map[string]any{{}})}
	got, err := queryEnabled(ctxBG(), rt, "app")
	if err != nil || got {
		t.Fatalf("missing enabled key = %v %v", got, err)
	}
}

// ---------------------------------------------------------------------------
// error shapes

func TestSqliteErrorShapes(t *testing.T) {
	// nonzero exit maps to the "sqlite3: <stderr>" CommandExecutionError text
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("no such table: access\n")},
	}
	_, err := sqliteQuery(ctxBG(), rt, "SELECT 1;")
	if err == nil || err.Error() != "sqlite3: no such table: access" {
		t.Fatalf("sqlite query error = %v", err)
	}
	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("locked")}}
	if err = sqliteExec(ctxBG(), rt, "DELETE;"); err == nil || err.Error() != "sqlite3: locked" {
		t.Fatalf("sqlite exec error = %v", err)
	}
	// runner-level failures (cancel/limit) propagate untouched
	canceled := errors.New("context canceled")
	runner.script = []process.CommandResult{{ExitCode: -1, Err: canceled}}
	if _, err = sqliteQuery(ctxBG(), rt, "SELECT 1;"); !errors.Is(err, canceled) {
		t.Fatalf("runner error = %v", err)
	}
	// invalid JSON output surfaces the unmarshal error
	runner.script = []process.CommandResult{{ExitCode: 0, Stdout: []byte("not json")}}
	if _, err = sqliteQuery(ctxBG(), rt, "SELECT 1;"); err == nil {
		t.Fatal("invalid json must fail")
	}
	// empty output is an empty row set, not an error
	runner.script = []process.CommandResult{{ExitCode: 0, Stdout: []byte("  \n")}}
	rows, err := sqliteQuery(ctxBG(), rt, "SELECT 1;")
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty output rows = %#v %v", rows, err)
	}
}

func TestPublicWrapperErrorTexts(t *testing.T) {
	// Salt wraps every TccDB failure as Error <verb> app(<id>): <cause>;
	// the port keeps the same texts.
	rt := &runtime.Runtime{
		Runner: &scriptAssistiveRunner{script: []process.CommandResult{
			{ExitCode: 1, Stderr: []byte("boom")},
		}},
		FS: runtime.NewMemoryFS(),
	}
	_, err := (installedFunc{}).Execute(ctxBG(), rt, &installedArgs{AppID: "foo"})
	if err == nil || err.Error() != "Error checking if app(foo) is installed: sqlite3: boom" {
		t.Fatalf("installed wrapper = %v", err)
	}
	rt2 := &runtime.Runtime{
		Runner: &scriptAssistiveRunner{script: []process.CommandResult{
			{ExitCode: 1, Stderr: []byte("boom")},
		}},
		FS: runtime.NewMemoryFS(),
	}
	_, err = (enabledFunc{}).Execute(ctxBG(), rt2, &enabledArgs{AppID: "foo"})
	if err == nil || err.Error() != "Error checking if app(foo) is enabled: sqlite3: boom" {
		t.Fatalf("enabled wrapper = %v", err)
	}
}

func TestEnableWrapperErrorText(t *testing.T) {
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{
		assistiveRows([]map[string]any{{"present": float64(1)}}),
		{ExitCode: 1, Stderr: []byte("readonly")},
	}
	_, err := (enableFunc{}).Execute(ctxBG(), rt, &enableArgs{AppID: "foo", Enabled: ptrBoolA(false)})
	if err == nil || err.Error() != "Error setting enable to false on app(foo): sqlite3: readonly" {
		t.Fatalf("enable wrapper = %v", err)
	}
}

func TestInstallWrapperErrorTextAndDefaultTries(t *testing.T) {
	oldSleep := assistiveSleep
	slept := 0
	assistiveSleep = func(time.Duration) { slept++ }
	t.Cleanup(func() { assistiveSleep = oldSleep })
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("attempt to write a readonly database")},
		{ExitCode: 1, Stderr: []byte("attempt to write a readonly database")},
		{ExitCode: 1, Stderr: []byte("attempt to write a readonly database")},
	}
	_, err := (installFunc{}).Execute(ctxBG(), rt, &installArgs{AppID: "foo"})
	if err == nil || err.Error() != "Error installing app(foo): sqlite3: attempt to write a readonly database" {
		t.Fatalf("install wrapper = %v", err)
	}
	if len(runner.calls) != 3 || slept != 2 {
		t.Fatalf("default tries: calls=%d slept=%d", len(runner.calls), slept)
	}
	// non-readonly failures do not retry
	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("syntax error")}}
	slept = 0
	_, err = (installFunc{}).Execute(ctxBG(), rt, &installArgs{AppID: "foo"})
	if err == nil || len(runner.calls) != 4 || slept != 0 {
		t.Fatalf("non-readonly retry: calls=%d slept=%d err=%v", len(runner.calls), slept, err)
	}
	// tries<1 clamps to a single attempt
	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("attempt to write a readonly database")}}
	_, err = (installFunc{}).Execute(ctxBG(), rt, &installArgs{AppID: "foo", Tries: ptrIntA(0), Wait: ptrIntA(0)})
	if err == nil || len(runner.calls) != 5 {
		t.Fatalf("tries clamp: calls=%d err=%v", len(runner.calls), err)
	}
}

func ptrBoolA(value bool) *bool { return &value }
func ptrIntA(value int) *int    { return &value }

// ---------------------------------------------------------------------------
// schema detection boundaries

func TestDetectSchemaBoundaries(t *testing.T) {
	rt := &runtime.Runtime{Runner: &scriptAssistiveRunner{}, FS: runtime.NewMemoryFS()}
	runner := rt.Runner.(*scriptAssistiveRunner)
	// missing access table
	runner.script = []process.CommandResult{assistiveRows(nil)}
	if _, err := detectSchema(ctxBG(), rt); err == nil || err.Error() != "TCC access table not found" {
		t.Fatalf("missing table = %v", err)
	}
	// unknown structure reports the computed short digest
	unknownSQL := "CREATE TABLE access (weird columns);"
	runner.script = []process.CommandResult{assistiveRows([]map[string]any{{"sql": unknownSQL}})}
	_, err := detectSchema(ctxBG(), rt)
	want := fmt.Sprintf("TCC Database structure unknown for digest '%s'", shortDigest(unknownSQL))
	if err == nil || err.Error() != want {
		t.Fatalf("unknown digest = %v; want %q", err, want)
	}
	// sqlite failure propagates with the sqlite3: prefix
	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("malformed")}}
	if _, err = detectSchema(ctxBG(), rt); err == nil || err.Error() != "sqlite3: malformed" {
		t.Fatalf("sqlite error = %v", err)
	}
	// column mapping table
	for schema, want := range map[schemaKind]string{
		schemaMojaveCatalina: "allowed",
		schemaBigSur:         "auth_value",
		schemaSonoma:         "auth_value",
	} {
		column, err := columnForSchema(schema)
		if err != nil || column != want {
			t.Fatalf("columnForSchema(%s) = %q %v", schema, column, err)
		}
	}
	if _, err := columnForSchema(schemaKind("bogus")); err == nil {
		t.Fatal("unknown schema column must fail")
	}
}

// ---------------------------------------------------------------------------
// registry matrix

func TestAssistiveRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"assistive.enable",
		"assistive.enabled",
		"assistive.install",
		"assistive.installed",
		"assistive.remove",
	}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt := assistiveSchema(t, schemaBigSur)
	runner := rt.Runner.(*scriptAssistiveRunner)
	runner.script = []process.CommandResult{assistiveRows(nil)}
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(ctxBG(), rt, "assistive.installed", &installedArgs{AppID: "ghost"})
		if err != nil || res != false {
			t.Fatalf("dispatch = %v %v", res, err)
		}
	} else if _, err := rt.Exec.Call(ctxBG(), rt, "assistive.installed", &installedArgs{AppID: "ghost"}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
