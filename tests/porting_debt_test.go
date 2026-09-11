// Package tests hosts plan-level porting-debt regression tests
// (plans/porting.md §7: PTD-TEST-0001 through PTD-TEST-0006).
package tests

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
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
