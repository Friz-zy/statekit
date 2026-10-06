// Package tests hosts plan-level porting-debt regression tests
// (plans/porting.md §7: PTD-TEST-0001 through PTD-TEST-0006).
package tests

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	executimezone "github.com/friz-zy/statekit/modules/exec/timezone"

	"gopkg.in/yaml.v3"
)

type recordingRunner struct {
	calls [][]string
}

func (r *recordingRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.calls = append(r.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: 0}
}

// countName reports how many times name occurs in names.
func countName(names []string, name string) int {
	n := 0
	for _, candidate := range names {
		if candidate == name {
			n++
		}
	}
	return n
}

// TestBuildRuntimeRegistersSystemPowerFunctions is the PTD-TEST-0001
// regression: BuildRuntime Names contains exactly the five system.*
// functions from system.Register, lookup-only enumeration spawns no
// processes, and default system.reboot runs `shutdown -r now` once.
func TestBuildRuntimeRegistersSystemPowerFunctions(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingRunner{}
	rt.Runner = rec

	var systemNames []string
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "system.") {
			systemNames = append(systemNames, name)
		}
	}
	want := []string{"system.halt", "system.init", "system.poweroff", "system.reboot", "system.shutdown"}
	if !reflect.DeepEqual(systemNames, want) {
		t.Fatalf("system.* names = %v, want %v", systemNames, want)
	}

	if len(rec.calls) != 0 {
		t.Fatalf("lookup-only enumeration spawned %d processes: %v", len(rec.calls), rec.calls)
	}

	proto, err := rt.Exec.ResolveArgs(rt, "system.reboot")
	if err != nil {
		t.Fatal(err)
	}
	value, err := rt.Exec.Call(context.Background(), rt, "system.reboot",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("system.reboot = %v, want true", value)
	}
	if len(rec.calls) != 1 || !reflect.DeepEqual(rec.calls[0], []string{"shutdown", "-r", "now"}) {
		t.Fatalf("runner calls = %v, want one `shutdown -r now`", rec.calls)
	}
}

// TestBuildRuntimeRegistersTestSleepFromOwningPackage is the PTD-TEST-0002
// regression: BuildRuntime resolves test.sleep from the owning
// modules/exec/test registration, invoking length 0 returns success once,
// and no status.test_sleep or duplicate registration exists.
func TestBuildRuntimeRegistersTestSleepFromOwningPackage(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	var testNames []string
	sleepCount := 0
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "test.") {
			testNames = append(testNames, name)
		}
		if name == "test.sleep" {
			sleepCount++
		}
		if strings.HasPrefix(name, "status.test") {
			t.Fatalf("status package leaked test-namespace name %q", name)
		}
	}
	want := []string{"test.echo", "test.ping", "test.sleep"}
	if !reflect.DeepEqual(testNames, want) {
		t.Fatalf("test.* names = %v, want %v", testNames, want)
	}
	if sleepCount != 1 {
		t.Fatalf("test.sleep registered %d times, want exactly 1", sleepCount)
	}

	proto, err := rt.Exec.ResolveArgs(rt, "test.sleep")
	if err != nil {
		t.Fatal(err)
	}
	// Zero-value args mean length 0: the wait fires immediately and the
	// call returns success exactly once.
	value, err := rt.Exec.Call(context.Background(), rt, "test.sleep",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("test.sleep length 0 = %v, want true", value)
	}
}

// TestFileMakedirsRegistersCanonicalSaltAlias is the PTD-TEST-0003
// regression: the pinned saltstack/salt/modules/file.py __func_alias__ maps
// the makedirs_ source function to the loader name makedirs, so Exec Names
// must contain file.makedirs (not file.makedirs_) and dispatching
// file.makedirs must reach the makedirs_ source contract: create the PARENT
// chain of path, then report the already-exists message on repeat.
func TestFileMakedirsRegistersCanonicalSaltAlias(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rt.FS = runtime.NewMemoryFS()

	if got := countName(rt.Exec.Names(), "file.makedirs"); got != 1 {
		t.Fatalf("file.makedirs registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "file.makedirs_"); got != 0 {
		t.Fatalf("superseded alias file.makedirs_ registered %d times, want 0", got)
	}

	proto, err := rt.Exec.ResolveArgs(rt, "file.makedirs")
	if err != nil {
		t.Fatal(err)
	}
	args := reflect.New(reflect.TypeOf(proto)).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Path").SetString("/testbed/alias/a/b")
	if _, err := rt.Exec.Call(context.Background(), rt, "file.makedirs", args); err != nil {
		t.Fatal(err)
	}
	info, err := rt.FS.Stat("/testbed/alias/a")
	if err != nil || !info.IsDir() {
		t.Fatalf("file.makedirs parent chain = (%v, %v), want directory /testbed/alias/a", info, err)
	}

	// Repeat dispatch: the declared default reply for an existing parent
	// directory is the source message, not an error. (The Windows
	// registration returns true instead of the message; this matrix targets
	// the POSIX source contract.)
	args = reflect.New(reflect.TypeOf(proto)).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Path").SetString("/testbed/alias/a/b")
	value, err := rt.Exec.Call(context.Background(), rt, "file.makedirs", args)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.CurrentGOOS() != "windows" {
		if msg, _ := value.(string); msg != "Directory '/testbed/alias/a' already exists" {
			t.Fatalf("file.makedirs repeat = %q, want already-exists message", msg)
		}
	} else if value != true {
		t.Fatalf("file.makedirs repeat = %v, want true", value)
	}
}

// TestLogrotateSetRegistersCanonicalAliasInExecAndState is the PTD-TEST-0004
// regression: the pinned saltstack/salt/modules/logrotate.py and
// saltstack/salt/states/logrotate.py __func_alias__ both map set_ to the
// loader name set, so each registry exposes logrotate.set exactly once,
// rejects logrotate.set_, and both canonical lookups dispatch successfully.
func TestLogrotateSetRegistersCanonicalAliasInExecAndState(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rt.FS = runtime.NewMemoryFS()
	// MemoryFS.WriteFile requires the parent directory to exist, so seed
	// the default logrotate conf location like a provisioned host.
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/logrotate.conf", []byte("weekly\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := countName(rt.Exec.Names(), "logrotate.set"); got != 1 {
		t.Fatalf("exec logrotate.set registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "logrotate.set_"); got != 0 {
		t.Fatalf("exec superseded alias logrotate.set_ registered %d times, want 0", got)
	}
	if got := countName(rt.States.Names(), "logrotate.set"); got != 1 {
		t.Fatalf("state logrotate.set registered %d times, want exactly 1", got)
	}
	if got := countName(rt.States.Names(), "logrotate.set_"); got != 0 {
		t.Fatalf("state superseded alias logrotate.set_ registered %d times, want 0", got)
	}

	// Canonical exec dispatch through the registry with source arguments.
	value, err := rt.Exec.Call(context.Background(), rt, "logrotate.set",
		&execlogrotate.SetArgs{Key: "compress", Value: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if value != true {
		t.Fatalf("logrotate.set = %v, want true", value)
	}
	data, err := rt.FS.ReadFile("/etc/logrotate.conf")
	if err != nil || !strings.Contains(string(data), "compress 1") {
		t.Fatalf("logrotate.set conf = (%q, %v), want compress 1 line", data, err)
	}
	// Canonical state dispatch: resolve the prototype, set the source
	// fields, and apply through the state registry.
	fn, ok := rt.States.Get("logrotate.set")
	if !ok {
		t.Fatal("state registry lost logrotate.set")
	}
	proto := reflect.New(reflect.TypeOf(fn.Args())).Interface()
	rv := reflect.ValueOf(proto).Elem()
	rv.FieldByName("Name").SetString("conf")
	rv.FieldByName("Key").SetString("weekly")
	rv.FieldByName("Value").SetString("2")
	res, err := rt.States.Apply(context.Background(), rt, "logrotate.set", proto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result == nil || !*res.Result {
		t.Fatalf("logrotate.set state result = %v, want true", res.Result)
	}
	if res.Comment != "Set command 'weekly' value: 2" {
		t.Fatalf("logrotate.set state comment = %q", res.Comment)
	}
}

// TestStatusTimeRegistersCanonicalSaltAlias is the PTD-TEST-0005
// regression: the pinned saltstack/salt/modules/status.py __func_alias__
// maps time_ to the loader name time, so Exec Names contains status.time
// exactly once, rejects status.time_, and dispatch keeps the pinned time_
// signature: default format "%A, %d. %B %Y %I:%M%p" and optional format.
func TestStatusTimeRegistersCanonicalSaltAlias(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	if got := countName(rt.Exec.Names(), "status.time"); got != 1 {
		t.Fatalf("status.time registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "status.time_"); got != 0 {
		t.Fatalf("superseded alias status.time_ registered %d times, want 0", got)
	}

	// Zero-value args exercise the pinned default format.
	proto, err := rt.Exec.ResolveArgs(rt, "status.time")
	if err != nil {
		t.Fatal(err)
	}
	value, err := rt.Exec.Call(context.Background(), rt, "status.time",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	rendered, _ := value.(string)
	if _, perr := time.Parse("Monday, 02. January 2006 03:04PM", rendered); perr != nil {
		t.Fatalf("status.time default = %q, want pinned default strftime layout: %v", rendered, perr)
	}

	// Explicit format dispatch through the same canonical name.
	proto, err = rt.Exec.ResolveArgs(rt, "status.time")
	if err != nil {
		t.Fatal(err)
	}
	args := reflect.New(reflect.TypeOf(proto)).Interface()
	field := reflect.ValueOf(args).Elem().FieldByName("Format")
	field.Set(reflect.New(field.Type().Elem()))
	field.Elem().SetString("%Y")
	value, err = rt.Exec.Call(context.Background(), rt, "status.time", args)
	if err != nil {
		t.Fatal(err)
	}
	rendered, _ = value.(string)
	if !regexp.MustCompile(`^20\d{2}$`).MatchString(rendered) {
		t.Fatalf("status.time %%Y = %q, want a 4-digit year", rendered)
	}
}

// TestPortingDebtExecUdevExportdbCanonicalRegistrationPTD_EXEC_1639 is the
// PTD-EXEC-1639 / PTD-TEST-1674 regression: the udev family surface is
// registered exactly once per canonical name (six names, no superseded
// aliases; links/name/path landed with PTD-EXEC-1640/1641/1642), the
// exportdb catalog entry declares exactly
// the source signature exportdb(subsystems=None), the mapped Salt fixture
// parses through the registry, the subsystem filter mirrors
// test_udev_subsystem_filter, and failures keep the fixed value-free
// error shapes without dispatching on invalid arguments.
func TestPortingDebtExecUdevExportdbCanonicalRegistrationPTD_EXEC_1639(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	var udevNames []string
	counts := map[string]int{}
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "udev.") {
			udevNames = append(udevNames, name)
			counts[name]++
		}
	}
	want := []string{"udev.env", "udev.exportdb", "udev.info", "udev.links", "udev.name", "udev.path"}
	if !reflect.DeepEqual(udevNames, want) {
		t.Fatalf("udev.* names = %v, want %v", udevNames, want)
	}
	for _, name := range want {
		if counts[name] != 1 {
			t.Fatalf("%s registered %d times, want exactly 1", name, counts[name])
		}
	}

	// Catalog-declared parameters must match the source signature
	// exportdb(subsystems=None).
	catalogData, err := os.ReadFile(filepath.Join("..", "docs", "catalog", "exec", "udev.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct {
			Function   string `yaml:"function"`
			Parameters []struct {
				Name    string  `yaml:"name"`
				Default *string `yaml:"default"`
			} `yaml:"parameters"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	var exportdbEntry *struct {
		Function   string `yaml:"function"`
		Parameters []struct {
			Name    string  `yaml:"name"`
			Default *string `yaml:"default"`
		} `yaml:"parameters"`
	}
	for i := range catalog.Functions {
		if catalog.Functions[i].Function == "exportdb" {
			exportdbEntry = &catalog.Functions[i]
		}
	}
	if exportdbEntry == nil {
		t.Fatal("catalog has no exportdb entry")
	}
	if len(exportdbEntry.Parameters) != 1 || exportdbEntry.Parameters[0].Name != "subsystems" {
		t.Fatalf("exportdb parameters = %#v, want exactly subsystems", exportdbEntry.Parameters)
	}
	if exportdbEntry.Parameters[0].Default == nil || *exportdbEntry.Parameters[0].Default != "None" {
		t.Fatalf("subsystems default = %#v, want None", exportdbEntry.Parameters[0].Default)
	}

	// Registry dispatch over the mapped Salt fixture: the pinned
	// test_exportdb three-record database parses in order.
	fixtureRunner := &udevFixtureRunner{stdout: udevExportDBFixture}
	rt.Runner = fixtureRunner
	proto, err := rt.Exec.ResolveArgs(rt, "udev.exportdb")
	if err != nil {
		t.Fatal(err)
	}
	value, err := rt.Exec.Call(context.Background(), rt, "udev.exportdb",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err != nil {
		t.Fatal(err)
	}
	records, ok := value.([]map[string]any)
	if !ok || len(records) != 3 {
		t.Fatalf("exportdb fixture records = %#v", value)
	}
	first, ok := records[0]["E"].(map[string]any)
	if !ok || first["SUBSYSTEM"] != "acpi" || first["DRIVER"] != "button" {
		t.Fatalf("first fixture record E = %#v", records[0]["E"])
	}
	if records[2]["N"] != "input/event2" {
		t.Fatalf("third fixture record N = %#v", records[2]["N"])
	}

	// The subsystem filter mirrors test_udev_subsystem_filter: ["acpi",
	// "usb"] keeps exactly the first record.
	args := reflect.New(reflect.TypeOf(proto)).Interface()
	filter := []string{"acpi", "usb"}
	reflect.ValueOf(args).Elem().FieldByName("Subsystems").Set(reflect.ValueOf(&filter))
	value, err = rt.Exec.Call(context.Background(), rt, "udev.exportdb", args)
	if err != nil {
		t.Fatal(err)
	}
	records, ok = value.([]map[string]any)
	if !ok || len(records) != 1 || records[0]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
		t.Fatalf("filtered fixture records = %#v", value)
	}
	if fixtureRunner.calls != 2 {
		t.Fatalf("runner calls = %d, want one per registry dispatch", fixtureRunner.calls)
	}

	// Failure shape: a nonzero udevadm exit surfaces the fixed value-free
	// error, not udevadm's stderr.
	fixtureRunner = &udevFixtureRunner{result: process.CommandResult{
		ExitCode: 1, Stderr: []byte("secret-udevadm-stderr")}}
	rt.Runner = fixtureRunner
	_, err = rt.Exec.Call(context.Background(), rt, "udev.exportdb",
		reflect.New(reflect.TypeOf(proto)).Interface())
	if err == nil || err.Error() != "udev.exportdb: command failed" {
		t.Fatalf("nonzero exit err = %v", err)
	}
	if strings.Contains(err.Error(), "secret-udevadm-stderr") {
		t.Fatal("nonzero exit error leaked udevadm stderr")
	}

	// Validation before dispatch: an over-ceiling filter never starts a
	// process.
	fixtureRunner = &udevFixtureRunner{stdout: udevExportDBFixture}
	rt.Runner = fixtureRunner
	tooMany := make([]string, 257)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	args = reflect.New(reflect.TypeOf(proto)).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Subsystems").Set(reflect.ValueOf(&tooMany))
	if _, err := rt.Exec.Call(context.Background(), rt, "udev.exportdb", args); err == nil {
		t.Fatal("over-ceiling filter must fail")
	}
	if fixtureRunner.calls != 0 {
		t.Fatalf("invalid filter dispatched %d commands, want 0", fixtureRunner.calls)
	}
}

// udevFixtureRunner answers every dispatch with the same fixed result.
type udevFixtureRunner struct {
	calls  int
	stdout string
	result process.CommandResult
}

func (r *udevFixtureRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	r.calls++
	if r.result.ExitCode != 0 || r.result.Stdout != nil {
		return r.result
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte(r.stdout)}
}

// udevExportDBFixture is the pinned three-record database from
// saltstack/tests/pytests/unit/modules/test_udev.py.
const udevExportDBFixture = `
P: /devices/LNXSYSTM:00/LNXPWRBN:00
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00
E: DRIVER=button
E: MODALIAS=acpi:LNXPWRBN:
E: SUBSYSTEM=acpi

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: EV=3
E: ID_INPUT=1
E: SUBSYSTEM=input

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2
N: input/event2
E: DEVNAME=/dev/input/event2
E: MAJOR=13
E: MINOR=66
E: SUBSYSTEM=input
`

// udevNamePathLinksFixture is a single-record `udevadm info --export`
// payload in the pinned upstream fixture style — scalar P and N, a
// multi-value S list, and an E map — covering every section the
// name/path/links wrappers extract via Salt's .get(section, None).
const udevNamePathLinksFixture = `P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2
N: input/event2
S: input/by-path/platform-LNXPWRBN:00-event
S: input/by-id/usb-LNXPWRBN-event
E: DEVNAME=/dev/input/event2
E: MAJOR=13
E: MINOR=66
E: SUBSYSTEM=input
`

// udevAbsentSectionsFixture carries only an E section: the record is
// valid through its E section while N, P, and S are absent, so each
// wrapper's .get(section, None) maps to nil.
const udevAbsentSectionsFixture = "E: SUBSYSTEM=input\n"

// udevRecordingRunner answers every dispatch like udevFixtureRunner and
// additionally records each dispatched argv so the wrappers' exact fixed
// `udevadm info` command shape is asserted.
type udevRecordingRunner struct {
	udevFixtureRunner
	argv [][]string
}

func (r *udevRecordingRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	r.argv = append(r.argv, append([]string{cmd.Name}, cmd.Args...))
	return r.udevFixtureRunner.Run(ctx, cmd)
}

// udevCatalogParam is one declared parameter of a catalog function entry.
type udevCatalogParam struct {
	Name    string  `yaml:"name"`
	Default *string `yaml:"default"`
}

// udevCatalogParameters returns the declared parameters of one function
// entry in docs/catalog/exec/udev.yaml, failing the test when the entry
// is missing.
func udevCatalogParameters(t *testing.T, function string) []udevCatalogParam {
	t.Helper()
	catalogData, err := os.ReadFile(filepath.Join("..", "docs", "catalog", "exec", "udev.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct {
			Function   string             `yaml:"function"`
			Parameters []udevCatalogParam `yaml:"parameters"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Functions {
		if entry.Function == function {
			return entry.Parameters
		}
	}
	t.Fatalf("catalog has no %s entry", function)
	return nil
}

// TestPortingDebtExecUdevLinksCanonicalRegistrationPTD_EXEC_1640 is the
// PTD-EXEC-1640 / PTD-TEST-1675 regression: the udev.links loader name is
// registered exactly once (no superseded udev.links_ alias), the args
// schema is exactly the source signature links(dev) with required dev and
// no default, and registry dispatch answers the source contract over a
// fake runner: a multi-value S section stays an ordered []any, an absent
// S maps to nil (Salt .get("S", None)), empty udevadm output keeps info's
// "no device found for <dev>" failure, and missing dev is rejected by the
// decode gate before any Runner dispatch. No dedicated upstream unit test
// exists for this wrapper; coverage here is statekit regression, not an
// upstream test port.
func TestPortingDebtExecUdevLinksCanonicalRegistrationPTD_EXEC_1640(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	if got := countName(rt.Exec.Names(), "udev.links"); got != 1 {
		t.Fatalf("udev.links registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "udev.links_"); got != 0 {
		t.Fatalf("superseded alias udev.links_ registered %d times, want 0", got)
	}

	// Catalog signature: links(dev) with exactly one parameter and no
	// declared default, matching the pinned source.
	params := udevCatalogParameters(t, "links")
	if len(params) != 1 || params[0].Name != "dev" || params[0].Default != nil {
		t.Fatalf("catalog links parameters = %#v, want exactly dev with no default", params)
	}

	// Args schema: exactly one required string dev field with no default
	// and no optional fields; the canonical argument name is proven by
	// the missing-required error text.
	proto, err := rt.Exec.ResolveArgs(rt, "udev.links")
	if err != nil {
		t.Fatal(err)
	}
	argsType := reflect.TypeOf(proto)
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 1 {
		t.Fatalf("udev.links args type = %s with %d fields, want a one-field struct", argsType, argsType.NumField())
	}
	devField := argsType.Field(0)
	if devField.Name != "Dev" || devField.Type.Kind() != reflect.String || devField.Tag.Get("statekit") != "required" {
		t.Fatalf("udev.links dev field = %s %s tag %q, want string Dev tagged exactly required", devField.Name, devField.Type, devField.Tag.Get("statekit"))
	}
	uncalled := &udevFixtureRunner{}
	rt.Runner = uncalled
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err == nil || err.Error() != `missing required argument "dev"` {
		t.Fatalf("missing dev err = %v, want missing required argument \"dev\"", err)
	}
	if uncalled.calls != 0 {
		t.Fatalf("missing dev gate dispatched %d commands, want 0", uncalled.calls)
	}

	// Value dispatch through the registry over the fake runner: a sys
	// dev switches the shared info dispatch to the path query, and the
	// multi-value S section stays an ordered []any.
	rec := &udevRecordingRunner{udevFixtureRunner: udevFixtureRunner{stdout: udevNamePathLinksFixture}}
	rt.Runner = rec
	args := reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("/sys/class/input/event2")
	value, err := rt.Exec.Call(context.Background(), rt, "udev.links", args)
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"udevadm", "info", "--export", "--query=all", "--path=/sys/class/input/event2"}
	if rec.calls != 1 || len(rec.argv) != 1 || !reflect.DeepEqual(rec.argv[0], wantArgv) {
		t.Fatalf("udev.links argv = %v (calls %d), want exactly %v", rec.argv, rec.calls, wantArgv)
	}
	links, ok := value.([]any)
	if !ok || !reflect.DeepEqual(links, []any{"input/by-path/platform-LNXPWRBN:00-event", "input/by-id/usb-LNXPWRBN-event"}) {
		t.Fatalf("udev.links = %#v, want the two S values as an ordered []any", value)
	}

	// Absent section: .get("S", None) maps to nil, not an error or an
	// empty string.
	absent := &udevFixtureRunner{stdout: udevAbsentSectionsFixture}
	rt.Runner = absent
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("/sys/class/input/event2")
	value, err = rt.Exec.Call(context.Background(), rt, "udev.links", args)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("udev.links without S = %#v, want nil", value)
	}
	if absent.calls != 1 {
		t.Fatalf("absent dispatch ran %d commands, want 1", absent.calls)
	}

	// Empty udevadm output keeps info's fixed failure shape.
	empty := &udevFixtureRunner{}
	rt.Runner = empty
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("/sys/class/input/event2")
	_, err = rt.Exec.Call(context.Background(), rt, "udev.links", args)
	if err == nil || err.Error() != "no device found for /sys/class/input/event2" {
		t.Fatalf("empty stdout err = %v, want no device found for /sys/class/input/event2", err)
	}
	if empty.calls != 1 {
		t.Fatalf("empty dispatch ran %d commands, want 1", empty.calls)
	}
}

// TestPortingDebtExecUdevNameCanonicalRegistrationPTD_EXEC_1641 is the
// PTD-EXEC-1641 / PTD-TEST-1676 regression: the udev.name loader name is
// registered exactly once (no superseded udev.name_ alias), the args
// schema is exactly the source signature name(dev) with required dev and
// no default, and registry dispatch answers the source contract over a
// fake runner: a single-value N section collapses to the scalar name, an
// absent N maps to nil (Salt .get("N", None)), empty udevadm output
// keeps info's "no device found for <dev>" failure, and missing dev is
// rejected by the decode gate before any Runner dispatch. No dedicated
// upstream unit test exists for this wrapper; coverage here is statekit
// regression, not an upstream test port.
func TestPortingDebtExecUdevNameCanonicalRegistrationPTD_EXEC_1641(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	if got := countName(rt.Exec.Names(), "udev.name"); got != 1 {
		t.Fatalf("udev.name registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "udev.name_"); got != 0 {
		t.Fatalf("superseded alias udev.name_ registered %d times, want 0", got)
	}

	// Catalog signature: name(dev) with exactly one parameter and no
	// declared default, matching the pinned source.
	params := udevCatalogParameters(t, "name")
	if len(params) != 1 || params[0].Name != "dev" || params[0].Default != nil {
		t.Fatalf("catalog name parameters = %#v, want exactly dev with no default", params)
	}

	// Args schema: exactly one required string dev field with no default
	// and no optional fields; the canonical argument name is proven by
	// the missing-required error text.
	proto, err := rt.Exec.ResolveArgs(rt, "udev.name")
	if err != nil {
		t.Fatal(err)
	}
	argsType := reflect.TypeOf(proto)
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 1 {
		t.Fatalf("udev.name args type = %s with %d fields, want a one-field struct", argsType, argsType.NumField())
	}
	devField := argsType.Field(0)
	if devField.Name != "Dev" || devField.Type.Kind() != reflect.String || devField.Tag.Get("statekit") != "required" {
		t.Fatalf("udev.name dev field = %s %s tag %q, want string Dev tagged exactly required", devField.Name, devField.Type, devField.Tag.Get("statekit"))
	}
	uncalled := &udevFixtureRunner{}
	rt.Runner = uncalled
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err == nil || err.Error() != `missing required argument "dev"` {
		t.Fatalf("missing dev err = %v, want missing required argument \"dev\"", err)
	}
	if uncalled.calls != 0 {
		t.Fatalf("missing dev gate dispatched %d commands, want 0", uncalled.calls)
	}

	// Value dispatch through the registry over the fake runner: a plain
	// dev queries through the name query type and the single-value N
	// section collapses to the scalar name.
	rec := &udevRecordingRunner{udevFixtureRunner: udevFixtureRunner{stdout: udevNamePathLinksFixture}}
	rt.Runner = rec
	args := reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	value, err := rt.Exec.Call(context.Background(), rt, "udev.name", args)
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"udevadm", "info", "--export", "--query=all", "--name=input/event2"}
	if rec.calls != 1 || len(rec.argv) != 1 || !reflect.DeepEqual(rec.argv[0], wantArgv) {
		t.Fatalf("udev.name argv = %v (calls %d), want exactly %v", rec.argv, rec.calls, wantArgv)
	}
	name, ok := value.(string)
	if !ok || name != "input/event2" {
		t.Fatalf("udev.name = %#v, want the scalar N value input/event2", value)
	}

	// Absent section: .get("N", None) maps to nil, not an error or an
	// empty string.
	absent := &udevFixtureRunner{stdout: udevAbsentSectionsFixture}
	rt.Runner = absent
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	value, err = rt.Exec.Call(context.Background(), rt, "udev.name", args)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("udev.name without N = %#v, want nil", value)
	}
	if absent.calls != 1 {
		t.Fatalf("absent dispatch ran %d commands, want 1", absent.calls)
	}

	// Empty udevadm output keeps info's fixed failure shape.
	empty := &udevFixtureRunner{}
	rt.Runner = empty
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	_, err = rt.Exec.Call(context.Background(), rt, "udev.name", args)
	if err == nil || err.Error() != "no device found for input/event2" {
		t.Fatalf("empty stdout err = %v, want no device found for input/event2", err)
	}
	if empty.calls != 1 {
		t.Fatalf("empty dispatch ran %d commands, want 1", empty.calls)
	}
}

// TestPortingDebtExecUdevPathCanonicalRegistrationPTD_EXEC_1642 is the
// PTD-EXEC-1642 / PTD-TEST-1677 regression: the udev.path loader name is
// registered exactly once (no superseded udev.path_ alias), the args
// schema is exactly the source signature path(dev) with required dev and
// no default, and registry dispatch answers the source contract over a
// fake runner: a single-value P section collapses to the scalar device
// path, an absent P maps to nil (Salt .get("P", None)), empty udevadm
// output keeps info's "no device found for <dev>" failure, and missing
// dev is rejected by the decode gate before any Runner dispatch. No
// dedicated upstream unit test exists for this wrapper; coverage here is
// statekit regression, not an upstream test port.
func TestPortingDebtExecUdevPathCanonicalRegistrationPTD_EXEC_1642(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	if got := countName(rt.Exec.Names(), "udev.path"); got != 1 {
		t.Fatalf("udev.path registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "udev.path_"); got != 0 {
		t.Fatalf("superseded alias udev.path_ registered %d times, want 0", got)
	}

	// Catalog signature: path(dev) with exactly one parameter and no
	// declared default, matching the pinned source.
	params := udevCatalogParameters(t, "path")
	if len(params) != 1 || params[0].Name != "dev" || params[0].Default != nil {
		t.Fatalf("catalog path parameters = %#v, want exactly dev with no default", params)
	}

	// Args schema: exactly one required string dev field with no default
	// and no optional fields; the canonical argument name is proven by
	// the missing-required error text.
	proto, err := rt.Exec.ResolveArgs(rt, "udev.path")
	if err != nil {
		t.Fatal(err)
	}
	argsType := reflect.TypeOf(proto)
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 1 {
		t.Fatalf("udev.path args type = %s with %d fields, want a one-field struct", argsType, argsType.NumField())
	}
	devField := argsType.Field(0)
	if devField.Name != "Dev" || devField.Type.Kind() != reflect.String || devField.Tag.Get("statekit") != "required" {
		t.Fatalf("udev.path dev field = %s %s tag %q, want string Dev tagged exactly required", devField.Name, devField.Type, devField.Tag.Get("statekit"))
	}
	uncalled := &udevFixtureRunner{}
	rt.Runner = uncalled
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err == nil || err.Error() != `missing required argument "dev"` {
		t.Fatalf("missing dev err = %v, want missing required argument \"dev\"", err)
	}
	if uncalled.calls != 0 {
		t.Fatalf("missing dev gate dispatched %d commands, want 0", uncalled.calls)
	}

	// Value dispatch through the registry over the fake runner: a plain
	// dev queries through the name query type and the single-value P
	// section collapses to the scalar device path.
	rec := &udevRecordingRunner{udevFixtureRunner: udevFixtureRunner{stdout: udevNamePathLinksFixture}}
	rt.Runner = rec
	args := reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	value, err := rt.Exec.Call(context.Background(), rt, "udev.path", args)
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"udevadm", "info", "--export", "--query=all", "--name=input/event2"}
	if rec.calls != 1 || len(rec.argv) != 1 || !reflect.DeepEqual(rec.argv[0], wantArgv) {
		t.Fatalf("udev.path argv = %v (calls %d), want exactly %v", rec.argv, rec.calls, wantArgv)
	}
	path, ok := value.(string)
	if !ok || path != "/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2" {
		t.Fatalf("udev.path = %#v, want the scalar P value /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2", value)
	}

	// Absent section: .get("P", None) maps to nil, not an error or an
	// empty string.
	absent := &udevFixtureRunner{stdout: udevAbsentSectionsFixture}
	rt.Runner = absent
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	value, err = rt.Exec.Call(context.Background(), rt, "udev.path", args)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("udev.path without P = %#v, want nil", value)
	}
	if absent.calls != 1 {
		t.Fatalf("absent dispatch ran %d commands, want 1", absent.calls)
	}

	// Empty udevadm output keeps info's fixed failure shape.
	empty := &udevFixtureRunner{}
	rt.Runner = empty
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("Dev").SetString("input/event2")
	_, err = rt.Exec.Call(context.Background(), rt, "udev.path", args)
	if err == nil || err.Error() != "no device found for input/event2" {
		t.Fatalf("empty stdout err = %v, want no device found for input/event2", err)
	}
	if empty.calls != 1 {
		t.Fatalf("empty dispatch ran %d commands, want 1", empty.calls)
	}
}

// TestWindowsFileMakedirsListsCanonicalAliasOnly is the PTD-TEST-0006
// regression: the pinned saltstack/salt/modules/win_file.py __func_alias__
// also maps makedirs_ to makedirs, so the Windows-only registration in
// modules/exec/file/windows.go must declare the canonical file.makedirs
// literal and never the superseded file.makedirs_. The registration itself
// is compiled only on Windows, so the source contract is asserted on every
// platform and the registry matrix runs when GOOS is windows.
func TestWindowsFileMakedirsListsCanonicalAliasOnly(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "modules", "exec", "file", "windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	nameRe := regexp.MustCompile(`func \(winMakedirsFunc\) Name\(\) string\s*\{\s*return "([^"]+)"`)
	matches := nameRe.FindAllStringSubmatch(string(src), -1)
	if len(matches) != 1 {
		t.Fatalf("winMakedirsFunc Name literals = %d, want exactly 1", len(matches))
	}
	if matches[0][1] != "file.makedirs" {
		t.Fatalf("winMakedirsFunc Name = %q, want canonical file.makedirs", matches[0][1])
	}
	if strings.Contains(string(src), `return "file.makedirs_"`) {
		t.Fatal("windows.go still declares the superseded file.makedirs_ loader name")
	}

	if runtime.CurrentGOOS() == "windows" {
		reg := runtime.NewExecRegistry()
		if err := execfile.Register(reg); err != nil {
			t.Fatal(err)
		}
		if got := countName(reg.Names(), "file.makedirs"); got != 1 {
			t.Fatalf("windows file registration exposes file.makedirs %d times, want 1", got)
		}
		if got := countName(reg.Names(), "file.makedirs_"); got != 0 {
			t.Fatalf("windows file registration exposes superseded file.makedirs_ %d times, want 0", got)
		}
	}
}

// TestPortingDebtExecTimezoneZoneCompareCanonicalRegistrationPTD_EXEC_1638 is
// the PTD-EXEC-1638 / PTD-TEST-1673 regression for the PARTIAL
// Linux-generic sub-slice of timezone.zone_compare: the loader name is
// registered exactly once with no superseded alias and Linux-only
// platform gating, the catalog entry declares exactly the source
// signature zone_compare(timezone), and registry dispatch answers the
// pinned Salt fixtures (test_zone_compare_arch equal by name,
// test_zone_compare_unequal, test_zone_compare_equal bytes, and the
// test_zone_compare_nonexistent / test_missing_localtime error
// categories) over a hermetic MemoryFS without Runner dispatch. The
// mac/windows partial variants and the Solaris/AIX rows are tracked by
// their own phase records; this test pins the Linux filesystem
// contract.
func TestPortingDebtExecTimezoneZoneCompareCanonicalRegistrationPTD_EXEC_1638(t *testing.T) {
	if runtime.CurrentGOOS() != "linux" {
		t.Skip("timezone.zone_compare landed as the Linux-generic sub-slice only")
	}
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	// Canonical registration: the family surface gains exactly
	// timezone.zone_compare, once, with no superseded alias (the
	// surface grew to seven names with PTD-EXEC-1631's
	// timezone.get_zonecode, mirrored in the want list below).
	var timezoneNames []string
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "timezone.") {
			timezoneNames = append(timezoneNames, name)
		}
	}
	want := []string{
		"timezone.get_hwclock", "timezone.get_offset", "timezone.get_zone",
		"timezone.get_zonecode", "timezone.set_hwclock", "timezone.set_zone",
		"timezone.zone_compare",
	}
	if !reflect.DeepEqual(timezoneNames, want) {
		t.Fatalf("timezone.* names = %v, want %v", timezoneNames, want)
	}
	if got := countName(rt.Exec.Names(), "timezone.zone_compare"); got != 1 {
		t.Fatalf("timezone.zone_compare registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "timezone.zone_compare_"); got != 0 {
		t.Fatalf("superseded alias timezone.zone_compare_ registered %d times, want 0", got)
	}

	// Catalog signature: zone_compare(timezone) with exactly one
	// parameter and no declared default, matching the pinned source.
	catalogData, err := os.ReadFile(filepath.Join("..", "docs", "catalog", "exec", "timezone.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct {
			Function   string `yaml:"function"`
			Parameters []struct {
				Name    string  `yaml:"name"`
				Default *string `yaml:"default"`
			} `yaml:"parameters"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	var zoneCompareEntry *struct {
		Function   string `yaml:"function"`
		Parameters []struct {
			Name    string  `yaml:"name"`
			Default *string `yaml:"default"`
		} `yaml:"parameters"`
	}
	for i := range catalog.Functions {
		if catalog.Functions[i].Function == "zone_compare" {
			zoneCompareEntry = &catalog.Functions[i]
		}
	}
	if zoneCompareEntry == nil {
		t.Fatal("catalog has no zone_compare entry")
	}
	if len(zoneCompareEntry.Parameters) != 1 || zoneCompareEntry.Parameters[0].Name != "timezone" {
		t.Fatalf("zone_compare parameters = %#v, want exactly timezone", zoneCompareEntry.Parameters)
	}
	if zoneCompareEntry.Parameters[0].Default != nil {
		t.Fatalf("timezone default = %#v, want none", zoneCompareEntry.Parameters[0].Default)
	}

	// Args schema: exactly one required string timezone field; the
	// canonical argument name is proven by the missing-required error
	// text, and the gate rejects before any filesystem access or
	// dispatch.
	proto, err := rt.Exec.ResolveArgs(rt, "timezone.zone_compare")
	if err != nil {
		t.Fatal(err)
	}
	argsType := reflect.TypeOf(proto)
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 1 {
		t.Fatalf("zone_compare args type = %s with %d fields, want a one-field struct", argsType, argsType.NumField())
	}
	zoneField := argsType.Field(0)
	if zoneField.Name != "TimeZone" || zoneField.Type.Kind() != reflect.String || zoneField.Tag.Get("statekit") != "required,name=timezone" {
		t.Fatalf("zone_compare timezone field = %s %s tag %q, want string TimeZone tagged required,name=timezone", zoneField.Name, zoneField.Type, zoneField.Tag.Get("statekit"))
	}
	uncalled := &recordingRunner{}
	rt.Runner = uncalled
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err == nil || err.Error() != `missing required argument "timezone"` {
		t.Fatalf("missing timezone err = %v, want missing required argument \"timezone\"", err)
	}
	if len(uncalled.calls) != 0 {
		t.Fatalf("missing timezone gate dispatched %d commands, want 0", len(uncalled.calls))
	}

	// test_zone_compare_arch (get_zone succeeds): exact name equality
	// answers true; unequal answers false without a byte fallback.
	rt.FS = runtime.NewMemoryFS()
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/timezone", []byte("Europe/Berlin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("Europe/Berlin")
	value, err := rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if err != nil || value != true {
		t.Fatalf("zone_compare name-equal = %v, %v, want true, nil", value, err)
	}
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("europe/berlin")
	value, err = rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if err != nil || value != false {
		t.Fatalf("zone_compare name-unequal = %v, %v, want false, nil", value, err)
	}

	// test_zone_compare_equal / test_zone_compare_unequal (get_zone
	// fails, deep byte compare): regular /etc/localtime versus the
	// zoneinfo file.
	rt.FS = runtime.NewMemoryFS()
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/usr/share/zoneinfo/Region", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/localtime", []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/usr/share/zoneinfo/Region/City", []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("Region/City")
	value, err = rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if err != nil || value != true {
		t.Fatalf("zone_compare byte-equal = %v, %v, want true, nil", value, err)
	}
	if err := rt.FS.WriteFile("/usr/share/zoneinfo/Region/City", []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("Region/City")
	value, err = rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if err != nil || value != false {
		t.Fatalf("zone_compare byte-unequal = %v, %v, want false, nil", value, err)
	}

	// test_zone_compare_nonexistent: the requested zone file is the
	// invocation-category failure (SaltInvocationError analog) with a
	// fixed value-free text.
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("Secret/Nonexistent")
	_, err = rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if !errors.Is(err, executimezone.ErrUnknownUnsafeZone) {
		t.Fatalf("nonexistent zone err = %v, want executimezone.ErrUnknownUnsafeZone", err)
	}
	if err.Error() != "unknown/unsafe zone" || strings.Contains(err.Error(), "Secret") {
		t.Fatalf("nonexistent zone err text = %q", err.Error())
	}

	// test_missing_localtime: the unreadable current localtime is the
	// execution-category failure (CommandExecutionError analog).
	rt.FS = runtime.NewMemoryFS()
	if err := rt.FS.MkdirAll("/usr/share/zoneinfo/Region", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/usr/share/zoneinfo/Region/City", []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	args = reflect.New(argsType).Interface()
	reflect.ValueOf(args).Elem().FieldByName("TimeZone").SetString("Region/City")
	_, err = rt.Exec.Call(context.Background(), rt, "timezone.zone_compare", args)
	if !errors.Is(err, executimezone.ErrCannotDetermineZone) {
		t.Fatalf("missing localtime err = %v, want executimezone.ErrCannotDetermineZone", err)
	}
	if err.Error() != "cannot determine current zone" {
		t.Fatalf("missing localtime err text = %q", err.Error())
	}

	// The whole contract is filesystem-only: no Runner dispatch.
	if len(uncalled.calls) != 0 {
		t.Fatalf("zone_compare dispatched %v", uncalled.calls)
	}
}

// TestPortingDebtExecTimezoneZoneCompareWindowsPartialPTD_EXEC_1638 is
// the PTD-EXEC-1638 / PTD-TEST-1673 canonical partial evidence for the
// Windows slice of timezone.zone_compare (win_timezone.py). It is a
// host-independent regression pin: the catalog entry declares exactly
// the source signature zone_compare(timezone), and the canonical
// family registration through BuildRuntime keeps exactly one entry per
// canonical timezone.* name on every variant host (linux/darwin/
// windows) with timezone.zone_compare once and no superseded alias. The behavioral
// contract of the windows variant — the 134-pair source-parity oracle
// against pinned saltstack/salt/modules/win_timezone.py, the mapped
// test_win_timezone.py fixture shapes (India/Calcutta true,
// Mountain/Denver with _dstoff true, FLE/Kiev, unknown-current false,
// tzutil error categories), the WZC-01..16 acceptance matrix, and the
// zero-mutation/single-dispatch invariants — is pinned hermetically in
// modules/exec/timezone/winzone_test.go, where the unexported variant
// and its resolver seam are reachable; the aggregate rows stay
// PARTIAL/OPEN (Solaris/AIX and native/CI validation remain).
func TestPortingDebtExecTimezoneZoneCompareWindowsPartialPTD_EXEC_1638(t *testing.T) {
	// Catalog signature: docs/catalog/exec/win_timezone.yaml declares
	// zone_compare with exactly one timezone parameter and no default,
	// matching the pinned source signature.
	catalogData, err := os.ReadFile(filepath.Join("..", "docs", "catalog", "exec", "win_timezone.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct {
			Function   string `yaml:"function"`
			Parameters []struct {
				Name    string  `yaml:"name"`
				Default *string `yaml:"default"`
			} `yaml:"parameters"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	var entry *struct {
		Function   string `yaml:"function"`
		Parameters []struct {
			Name    string  `yaml:"name"`
			Default *string `yaml:"default"`
		} `yaml:"parameters"`
	}
	for i := range catalog.Functions {
		if catalog.Functions[i].Function == "zone_compare" {
			entry = &catalog.Functions[i]
		}
	}
	if entry == nil {
		t.Fatal("win_timezone catalog has no zone_compare entry")
	}
	if len(entry.Parameters) != 1 || entry.Parameters[0].Name != "timezone" {
		t.Fatalf("win zone_compare parameters = %#v, want exactly timezone", entry.Parameters)
	}
	if entry.Parameters[0].Default != nil {
		t.Fatalf("win timezone default = %#v, want none", entry.Parameters[0].Default)
	}

	// Args schema (WZC-BACKEND-01): the windows variant prototype is
	// the unexported winZoneCompareArgs, unreachable from this package
	// off a windows host (the QA-MZC-BLOCK-01 lesson forbids a
	// GOOS-gated duplicate), so the schema is pinned from the module
	// source itself: exactly one TimeZone field of type *string tagged
	// required,name=timezone — the required pointer making a missing
	// argument (nil, rejected by the required gate before any
	// resolver/Runner work) differ from an explicit empty string
	// (nonnil, gate passes, Execute answers the fixed invalid-zone
	// sentinel) — with the tag name matching the catalog parameter.
	sourcePath := filepath.Join("..", "modules", "exec", "timezone", "timezone.go")
	file, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "winZoneCompareArgs" {
			return true
		}
		found = true
		strct, ok := spec.Type.(*ast.StructType)
		if !ok || strct.Fields.NumFields() != 1 {
			t.Fatalf("winZoneCompareArgs is not a one-field struct")
		}
		field := strct.Fields.List[0]
		star, ok := field.Type.(*ast.StarExpr)
		if !ok || len(field.Names) != 1 || field.Names[0].Name != "TimeZone" {
			t.Fatalf("winZoneCompareArgs field = %v, want TimeZone *string", field.Type)
		}
		if elem, ok := star.X.(*ast.Ident); !ok || elem.Name != "string" {
			t.Fatalf("winZoneCompareArgs TimeZone element = %v, want string", star.X)
		}
		if field.Tag == nil || strings.Trim(field.Tag.Value, "`") != `statekit:"required,name=timezone"` {
			t.Fatalf("winZoneCompareArgs TimeZone tag = %v, want statekit:\"required,name=timezone\"", field.Tag)
		}
		if entry.Parameters[0].Name != "timezone" {
			t.Fatalf("tag name timezone does not match catalog parameter %q", entry.Parameters[0].Name)
		}
		return false
	})
	if !found {
		t.Fatalf("%s declares no winZoneCompareArgs type", sourcePath)
	}

	// Canonical registration: the windows variant lands through the
	// same single timezone.zone_compare name, so the family surface on
	// every variant host keeps exactly one entry per canonical name —
	// never a windows alias and never a duplicate. The surface is
	// GOOS-dependent: seven names on linux (base 5 + zone_compare +
	// the Linux get_zonecode of PTD-EXEC-1631), twelve on darwin (base
	// 5 + zone_compare + the four Mac systemsetup getters + the Mac
	// get_zonecode of PTD-EXEC-1631 + the Mac list_zones of
	// PTD-EXEC-1633), seven on
	// windows (base 5 + zone_compare + the Windows timezone.list of
	// PTD-EXEC-1632).
	switch runtime.CurrentGOOS() {
	case "linux", "darwin", "windows":
	default:
		t.Skip("timezone.zone_compare variants register on linux/darwin/windows hosts only")
	}
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	var timezoneNames []string
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "timezone.") {
			timezoneNames = append(timezoneNames, name)
		}
	}
	want := []string{
		"timezone.get_hwclock", "timezone.get_offset", "timezone.get_zone",
		"timezone.list", "timezone.set_hwclock", "timezone.set_zone",
		"timezone.zone_compare",
	}
	switch runtime.CurrentGOOS() {
	case "linux":
		want = []string{
			"timezone.get_hwclock", "timezone.get_offset", "timezone.get_zone",
			"timezone.get_zonecode", "timezone.set_hwclock", "timezone.set_zone",
			"timezone.zone_compare",
		}
	case "darwin":
		want = []string{
			"timezone.get_date", "timezone.get_time", "timezone.get_time_server",
			"timezone.get_using_network_time", "timezone.get_hwclock",
			"timezone.get_offset", "timezone.get_zone", "timezone.get_zonecode",
			"timezone.list_zones", "timezone.set_hwclock", "timezone.set_zone",
			"timezone.zone_compare",
		}
	}
	if !reflect.DeepEqual(timezoneNames, want) {
		t.Fatalf("timezone.* names = %v, want %v", timezoneNames, want)
	}
	if got := countName(rt.Exec.Names(), "timezone.zone_compare"); got != 1 {
		t.Fatalf("timezone.zone_compare registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "timezone.zone_compare_"); got != 0 {
		t.Fatalf("superseded alias timezone.zone_compare_ registered %d times, want 0", got)
	}
}

// zonecodeRunner is the fake Runner for the get_zonecode registration
// evidence: it records the exact process.Command of every dispatch and
// replies with one fixed CommandResult. The real date binary is never
// invoked.
type zonecodeRunner struct {
	cmds  []process.Command
	reply process.CommandResult
}

func (r *zonecodeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.cmds = append(r.cmds, cmd)
	return r.reply
}

// TestPortingDebtExecTimezoneGetZonecodeCanonicalRegistrationPTD_EXEC_1631
// is the PTD-EXEC-1631 / PTD-TEST-1666 regression for the Linux-generic
// slice of timezone.get_zonecode: the loader name is registered exactly
// once with no superseded alias and Linux-only platform gating, the
// catalog entry declares the zero-parameter source signature
// get_zonecode(), the args schema is a zero-field struct with no
// required gate, and registry dispatch answers the pinned source
// contract over a fake Runner with the exact fixed `date +%Z` command
// (parent-PATH executable name, Dir "/", LC_ALL=C plus caller TZ only
// when set, 30s deadline, 64 KiB per-stream caps) and the Python
// stdout rstrip, failing closed with the fixed value-free
// ErrZonecodeQuery on nonzero exit. The mac date and Windows
// ZoneInfo/TzMapper variants stay tracked by their own open rows; this
// test pins the Linux generic contract. Upstream ships no
// get_zonecode unit test, so the fixtures are transcribed from the
// pinned source, not ported Salt tests.
func TestPortingDebtExecTimezoneGetZonecodeCanonicalRegistrationPTD_EXEC_1631(t *testing.T) {
	if runtime.CurrentGOOS() != "linux" {
		t.Skip("timezone.get_zonecode landed as the Linux-generic slice only")
	}
	// Deterministic child-env expectation: TZ set to a sentinel means
	// the dispatch Env must be exactly LC_ALL=C plus TZ=<sentinel>.
	t.Setenv("TZ", "Zonecode/Sentinel")
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}

	// Canonical registration: exactly once, no superseded alias, with
	// the Linux family surface at seven names.
	if got := countName(rt.Exec.Names(), "timezone.get_zonecode"); got != 1 {
		t.Fatalf("timezone.get_zonecode registered %d times, want exactly 1", got)
	}
	if got := countName(rt.Exec.Names(), "timezone.get_zonecode_"); got != 0 {
		t.Fatalf("superseded alias timezone.get_zonecode_ registered %d times, want 0", got)
	}
	var timezoneNames []string
	for _, name := range rt.Exec.Names() {
		if strings.HasPrefix(name, "timezone.") {
			timezoneNames = append(timezoneNames, name)
		}
	}
	want := []string{
		"timezone.get_hwclock", "timezone.get_offset", "timezone.get_zone",
		"timezone.get_zonecode", "timezone.set_hwclock", "timezone.set_zone",
		"timezone.zone_compare",
	}
	if !reflect.DeepEqual(timezoneNames, want) {
		t.Fatalf("timezone.* names = %v, want %v", timezoneNames, want)
	}

	// Catalog signature: docs/catalog/exec/timezone.yaml declares
	// get_zonecode with zero parameters, matching the pinned
	// zero-argument source signature.
	catalogData, err := os.ReadFile(filepath.Join("..", "docs", "catalog", "exec", "timezone.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct {
			Function   string `yaml:"function"`
			Parameters []struct {
				Name    string  `yaml:"name"`
				Default *string `yaml:"default"`
			} `yaml:"parameters"`
		} `yaml:"functions"`
	}
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatal(err)
	}
	var zonecodeEntry *struct {
		Function   string `yaml:"function"`
		Parameters []struct {
			Name    string  `yaml:"name"`
			Default *string `yaml:"default"`
		} `yaml:"parameters"`
	}
	for i := range catalog.Functions {
		if catalog.Functions[i].Function == "get_zonecode" {
			zonecodeEntry = &catalog.Functions[i]
		}
	}
	if zonecodeEntry == nil {
		t.Fatal("catalog has no get_zonecode entry")
	}
	if len(zonecodeEntry.Parameters) != 0 {
		t.Fatalf("get_zonecode parameters = %#v, want none", zonecodeEntry.Parameters)
	}

	// Args schema: a zero-field struct prototype with no required
	// gate; the canonical zero-argument call decodes through it.
	proto, err := rt.Exec.ResolveArgs(rt, "timezone.get_zonecode")
	if err != nil {
		t.Fatal(err)
	}
	argsType := reflect.TypeOf(proto)
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 0 {
		t.Fatalf("get_zonecode args type = %s with %d fields, want a zero-field struct", argsType, argsType.NumField())
	}
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err != nil {
		t.Fatalf("zero-field args failed the required gate: %v", err)
	}

	// Registry dispatch over the fake Runner: the exact fixed `date
	// +%Z` command — parent-PATH executable name (user-authorized,
	// caller-owned trust), shell-free, Dir "/", child Env exactly
	// LC_ALL=C plus the caller's TZ, 30s cancellation deadline, and
	// equal 64 KiB capture ceilings — with the Python stdout rstrip.
	rec := &zonecodeRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")}}
	rt.Runner = rec
	value, err := rt.Exec.Call(context.Background(), rt, "timezone.get_zonecode",
		reflect.New(argsType).Interface())
	if err != nil {
		t.Fatal(err)
	}
	if value != "PST" {
		t.Fatalf("get_zonecode = %v, want PST", value)
	}
	if len(rec.cmds) != 1 {
		t.Fatalf("get_zonecode dispatched %d commands, want exactly 1", len(rec.cmds))
	}
	wantCmd := process.Command{
		Name:           "date",
		Args:           []string{"+%Z"},
		Dir:            "/",
		Env:            []string{"LC_ALL=C", "TZ=Zonecode/Sentinel"},
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 64 << 10,
		MaxStderrBytes: 64 << 10,
	}
	if !reflect.DeepEqual(rec.cmds[0], wantCmd) {
		t.Fatalf("get_zonecode command = %#v, want %#v", rec.cmds[0], wantCmd)
	}

	// Failure shape: a nonzero date exit fails closed with the fixed
	// value-free sentinel — no stdout, stderr, or exit status in the
	// error (Salt's cmd.run would return the stdout; StateKit fails
	// closed instead).
	failing := &zonecodeRunner{reply: process.CommandResult{
		ExitCode: 1, Stdout: []byte("PST\n"), Stderr: []byte("secret-zonecode-stderr")}}
	rt.Runner = failing
	_, err = rt.Exec.Call(context.Background(), rt, "timezone.get_zonecode",
		reflect.New(argsType).Interface())
	if !errors.Is(err, executimezone.ErrZonecodeQuery) {
		t.Fatalf("nonzero exit err = %v, want executimezone.ErrZonecodeQuery", err)
	}
	if err.Error() != "timezone zonecode query failed" {
		t.Fatalf("nonzero exit err text = %q", err.Error())
	}
	if strings.Contains(err.Error(), "secret-zonecode-stderr") {
		t.Fatal("nonzero exit error leaked date stderr")
	}
	if len(failing.cmds) != 1 {
		t.Fatalf("failing get_zonecode dispatched %d commands, want 1 (never retried)", len(failing.cmds))
	}
}
