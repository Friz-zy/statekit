package user

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
`

type fakeRunner struct {
	calls        [][]string
	commands     []process.Command
	resolveCalls []string
	path         string
	resolveErr   error
	results      []process.CommandResult
	code         int
	beforeRun    func(process.Command)
	afterRun     func(process.Command)
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	f.commands = append(f.commands, cmd)
	if f.beforeRun != nil {
		f.beforeRun(cmd)
	}
	if f.afterRun != nil {
		f.afterRun(cmd)
	}
	if len(f.results) > 0 {
		result := f.results[0]
		f.results = f.results[1:]
		return result
	}
	return process.CommandResult{ExitCode: f.code}
}

func (f *fakeRunner) ResolveTrustedCommand(name string) (string, error) {
	f.resolveCalls = append(f.resolveCalls, name)
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return f.path, nil
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{path: "/usr/sbin/usermod"}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/passwd", []byte(passwdFixture), 0o644)
	if err := execuser.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

type trackedStateFS struct {
	runtime.FileSystem
	boundedReads  int
	boundedPaths  []string
	boundedLimits []int64
	unboundedRead int
}

func (f *trackedStateFS) ReadFile(name string) ([]byte, error) {
	f.unboundedRead++
	return f.FileSystem.ReadFile(name)
}

func (f *trackedStateFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	f.boundedReads++
	f.boundedPaths = append(f.boundedPaths, name)
	f.boundedLimits = append(f.boundedLimits, limit)
	return runtime.ReadFileBounded(f.FileSystem, name, limit)
}

const otherManagedPasswd = "synthetic:x:1000:1000:first,last,room,work,old:/home/old:/bin/false\n"

func newOtherManagedRT(t *testing.T) (*runtime.Runtime, *trackedStateFS, *fakeRunner) {
	t.Helper()
	rt, runner := newRT()
	if err := rt.FS.WriteFile("/etc/passwd", []byte(otherManagedPasswd), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys := &trackedStateFS{FileSystem: rt.FS}
	rt.FS = fsys
	runner.afterRun = func(cmd process.Command) {
		if cmd.Name != "/usr/sbin/usermod" || len(cmd.Args) != 3 || cmd.Args[0] != "-c" {
			return
		}
		data, err := fsys.FileSystem.ReadFile("/etc/passwd")
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		for i, line := range lines {
			fields := strings.SplitN(line, ":", 7)
			if len(fields) == 7 && fields[0] == cmd.Args[2] {
				fields[4] = cmd.Args[1]
				lines[i] = strings.Join(fields, ":")
			}
		}
		_ = fsys.FileSystem.WriteFile("/etc/passwd", []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}
	return rt, fsys, runner
}

func stateOther(value any) *any { return &value }

func TestPresentCreateUpdateNoop(t *testing.T) {
	rt, runner := newRT()

	pending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "bob", UID: "1001", Shell: "/bin/sh", Test: true,
	})
	if pending.Result != nil || pending.Changes["new"] != "bob" {
		t.Fatalf("create test mode wrong: %+v", pending)
	}

	applied := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "bob", UID: "1001", Shell: "/bin/sh",
	})
	if !applied.Succeeded() || applied.Changes["new"] != "bob" {
		t.Fatalf("create wrong: %+v", applied)
	}
	// Simulate useradd having persisted the account.
	rt.FS.WriteFile("/etc/passwd", []byte(
		passwdFixture+"bob:x:1001:1001::/home/bob:/bin/sh\n"), 0o644)

	noOp := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "bob"})
	if !noOp.Succeeded() || noOp.Changed() {
		t.Fatalf("no-op wrong: %+v", noOp)
	}

	updatePending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "alice", Shell: "/bin/bash", Test: true,
	})
	if updatePending.Result != nil {
		t.Fatal("update test mode must pend")
	}
	delta := updatePending.Changes["shell"].(map[string]any)
	if delta["old"] != "/bin/zsh" || delta["new"] != "/bin/bash" {
		t.Fatalf("shell delta wrong: %+v", delta)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "usermod") && len(updatePending.Changes) > 0 {
			continue
		}
	}
	updated := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "alice", Shell: "/bin/bash",
	})
	if !updated.Succeeded() || !updated.Changed() {
		t.Fatalf("update wrong: %+v", updated)
	}
	lastCall := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if lastCall != "usermod -s /bin/bash alice" {
		t.Fatalf("chshell argv = %q", lastCall)
	}
}

func TestAbsentSemantics(t *testing.T) {
	rt, runner := newRT()
	gone := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "ghost"})
	if !gone.Succeeded() || gone.Changed() {
		t.Fatalf("already-absent wrong: %+v", gone)
	}

	testRes := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "alice", Test: true})
	if testRes.Result != nil || testRes.Changes["removed"] != "alice" {
		t.Fatalf("test removal wrong: %+v", testRes)
	}
	data, _ := rt.FS.ReadFile("/etc/passwd")
	if !strings.Contains(string(data), "alice") {
		t.Fatal("test mode removed the user")
	}

	applied := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "alice"})
	if !applied.Succeeded() {
		t.Fatalf("removal failed: %+v", applied)
	}
	lastCall := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if lastCall != "userdel alice" {
		t.Fatalf("userdel argv = %q", lastCall)
	}
}

func TestPresentOtherNullIsUnmanagedAndEmptyClears(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	noOther := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic"})
	if !noOther.Succeeded() || noOther.Changed() || fsys.boundedReads != 0 || fsys.unboundedRead != 2 {
		t.Fatalf("omitted other changed legacy behavior: result=%+v bounded=%d unbounded=%d", noOther, fsys.boundedReads, fsys.unboundedRead)
	}

	rt, fsys, runner = newOtherManagedRT(t)
	null := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther(nil)})
	if !null.Succeeded() || null.Changed() || fsys.boundedReads != 0 || fsys.unboundedRead != 2 || len(runner.commands) != 0 {
		t.Fatalf("null other must be unmanaged: result=%+v bounded=%d unbounded=%d commands=%v", null, fsys.boundedReads, fsys.unboundedRead, runner.commands)
	}

	rt, fsys, runner = newOtherManagedRT(t)
	clear := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("")})
	if !clear.Succeeded() || !clear.Changed() || !reflect.DeepEqual(clear.Changes, map[string]any{"other": map[string]any{"changed": true}}) {
		t.Fatalf("explicit empty clear changes = %+v", clear)
	}
	if fsys.boundedReads != 3 || fsys.unboundedRead != 0 || len(runner.commands) != 1 || len(runner.resolveCalls) != 1 {
		t.Fatalf("clear effects bounded=%d unbounded=%d resolve=%v commands=%v", fsys.boundedReads, fsys.unboundedRead, runner.resolveCalls, runner.calls)
	}
	if !reflect.DeepEqual(runner.commands[0].Args, []string{"-c", "first,last,room,work", "synthetic"}) {
		t.Fatalf("clear usermod argv = %v", runner.commands[0].Args)
	}
}

func TestPresentOtherTypedNilAndInvalidInputsRejectBeforeEffects(t *testing.T) {
	var typedNil any = (*int)(nil)
	for _, tc := range []struct {
		name string
		args *presentArgs
	}{
		{"typed nil other", &presentArgs{Name: "synthetic", Other: &typedNil}},
		{"wrong other type", &presentArgs{Name: "synthetic", Other: stateOther(false)}},
		{"JSON float other", &presentArgs{Name: "synthetic", Other: stateOther(float64(0))}},
		{"colon other", &presentArgs{Name: "synthetic", Other: stateOther("bad:value")}},
		{"oversized other", &presentArgs{Name: "synthetic", Other: stateOther(strings.Repeat("x", 4097))}},
		{"invalid UID", &presentArgs{Name: "synthetic", UID: "4294967295", Other: stateOther("new")}},
		{"signed GID", &presentArgs{Name: "synthetic", GID: "+1", Other: stateOther("new")}},
		{"control home", &presentArgs{Name: "synthetic", Home: "/bad\nhome", Other: stateOther("new")}},
		{"oversized shell", &presentArgs{Name: "synthetic", Shell: strings.Repeat("s", 4097), Other: stateOther("new")}},
		{"invalid name", &presentArgs{Name: "-synthetic", Other: stateOther("new")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newOtherManagedRT(t)
			res := presentFunc{}.Apply(context.Background(), rt, tc.args)
			if res.Result == nil || *res.Result || len(res.Changes) != 0 || fsys.boundedReads != 0 || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 {
				t.Fatalf("invalid other-managed input caused effects: result=%+v reads=%d/%d calls=%v resolve=%v", res, fsys.boundedReads, fsys.unboundedRead, runner.calls, runner.resolveCalls)
			}
			if strings.Contains(res.Comment, "synthetic-marker") || strings.Contains(res.Comment, "new") {
				t.Fatalf("failure comment contains input: %q", res.Comment)
			}
		})
	}
}

func TestPresentOtherBoundedPrecheckPrecedesCreationAndSiblingActions(t *testing.T) {
	for _, testMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply", true: "test"}[testMode], func(t *testing.T) {
			rt, fsys, runner := newOtherManagedRT(t)
			if err := fsys.FileSystem.WriteFile("/etc/passwd", []byte("other:x:1:2:g:h:s\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
				Name: "synthetic", UID: "1001", GID: "1002", Home: "/home/new", Shell: "/bin/sh", Other: stateOther("new"), Test: testMode,
			})
			if res.Result == nil || *res.Result || len(res.Changes) != 0 {
				t.Fatalf("missing account must fail without create proposal: %+v", res)
			}
			if fsys.boundedReads != 1 || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 {
				t.Fatalf("precheck failure effects bounded=%d unbounded=%d calls=%v resolve=%v", fsys.boundedReads, fsys.unboundedRead, runner.calls, runner.resolveCalls)
			}
		})
	}
}

func TestPresentOtherTestModeIsMetadataOnlyAndMutationFree(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	pending := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "synthetic", UID: "1001", GID: "1002", Home: "/home/new", Shell: "/bin/sh",
		Other: stateOther("marker-value"), Test: true,
	})
	if pending.Result != nil {
		t.Fatalf("test result = %v, want pending", *pending.Result)
	}
	want := map[string]any{
		"uid":   map[string]any{"old": "1000", "new": "1001"},
		"gid":   map[string]any{"old": "1000", "new": "1002"},
		"home":  map[string]any{"old": "/home/old", "new": "/home/new"},
		"shell": map[string]any{"old": "/bin/false", "new": "/bin/sh"},
		"other": map[string]any{"changed": true},
	}
	if !reflect.DeepEqual(pending.Changes, want) {
		t.Fatalf("test mode changes = %#v, want %#v", pending.Changes, want)
	}
	if fsys.boundedReads != 1 || !reflect.DeepEqual(fsys.boundedPaths, []string{"/etc/passwd"}) || !reflect.DeepEqual(fsys.boundedLimits, []int64{1 << 20}) || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 || strings.Contains(pending.Comment, "marker-value") {
		t.Fatalf("test mode effects/output: bounded=%d unbounded=%d calls=%v resolve=%v comment=%q", fsys.boundedReads, fsys.unboundedRead, runner.calls, runner.resolveCalls, pending.Comment)
	}
}

func TestPresentOtherAppliedOrderAndMetadataOnlyOutput(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	runner.beforeRun = func(cmd process.Command) {
		wantReads := 1
		if cmd.Name == "/usr/sbin/usermod" {
			wantReads = 2
		}
		if fsys.boundedReads != wantReads || fsys.unboundedRead != 0 {
			t.Errorf("action %q started after bounded/unbounded reads %d/%d, want bounded=%d and no unbounded reads", cmd.Name, fsys.boundedReads, fsys.unboundedRead, wantReads)
		}
	}
	applied := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "synthetic", UID: "1001", GID: "1002", Home: "/home/new", Shell: "/bin/sh", Other: stateOther("marker-value"),
	})
	if !applied.Succeeded() || !applied.Changed() {
		t.Fatalf("applied result = %+v", applied)
	}
	if !reflect.DeepEqual(applied.Changes["other"], map[string]any{"changed": true}) {
		t.Fatalf("other output exposes values: %#v", applied.Changes["other"])
	}
	wantCalls := [][]string{
		{"usermod", "-u", "1001", "synthetic"},
		{"usermod", "-g", "1002", "synthetic"},
		{"usermod", "-d", "/home/new", "synthetic"},
		{"usermod", "-s", "/bin/sh", "synthetic"},
		{"/usr/sbin/usermod", "-c", "first,last,room,work,marker-value", "synthetic"},
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) || !reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) {
		t.Fatalf("action order = %v resolver=%v, want %v", runner.calls, runner.resolveCalls, wantCalls)
	}
	if fsys.boundedReads != 3 || !reflect.DeepEqual(fsys.boundedPaths, []string{"/etc/passwd", "/etc/passwd", "/etc/passwd"}) || !reflect.DeepEqual(fsys.boundedLimits, []int64{1 << 20, 1 << 20, 1 << 20}) || fsys.unboundedRead != 0 || strings.Contains(applied.Comment, "marker-value") || strings.Contains(applied.Comment, "first,last") {
		t.Fatalf("applied bounded/output contract: reads=%d/%d comment=%q", fsys.boundedReads, fsys.unboundedRead, applied.Comment)
	}
	if !reflect.DeepEqual(runner.commands[4].Args, []string{"-c", "first,last,room,work,marker-value", "synthetic"}) || runner.commands[4].Shell {
		t.Fatalf("other command = %+v", runner.commands[4])
	}
}

func TestPresentOtherNoopAndStatePlatformGate(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	noOp := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("old")})
	if !noOp.Succeeded() || noOp.Changed() || fsys.boundedReads != 1 || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 {
		t.Fatalf("equal other result=%+v reads=%d/%d calls=%v resolver=%v", noOp, fsys.boundedReads, fsys.unboundedRead, runner.calls, runner.resolveCalls)
	}

	rt, fsys, runner = newOtherManagedRT(t)
	rejected := applyPresentForGOOS(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("new")}, "darwin")
	if rejected.Result == nil || *rejected.Result || fsys.boundedReads != 0 || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 {
		t.Fatalf("non-Linux other state gate = %+v reads=%d/%d calls=%v", rejected, fsys.boundedReads, fsys.unboundedRead, runner.calls)
	}
}

func TestPresentOtherSiblingValidationBoundaries(t *testing.T) {
	for _, value := range []string{"", "0", "0007", "4294967294"} {
		if !validPresentID(value) {
			t.Fatalf("valid requested UID/GID %q rejected", value)
		}
	}
	for _, value := range []string{"+1", "-1", " 1", "1.0", "١", "4294967295", "4294967296"} {
		if validPresentID(value) {
			t.Fatalf("invalid requested UID/GID %q accepted", value)
		}
	}
	for _, value := range []string{"", "/home/synthetic", "/path:with:colon", strings.Repeat("x", 4096), strings.Repeat("é", 2048)} {
		if !validPresentText(value) {
			t.Fatalf("valid requested home/shell text with %d bytes rejected", len(value))
		}
	}
	for _, value := range []string{strings.Repeat("x", 4097), strings.Repeat("é", 2049), "bad\x00text", "bad\ntext", "bad\x7ftext", string([]byte{0xff})} {
		if validPresentText(value) {
			t.Fatalf("invalid requested home/shell text with %d bytes accepted", len(value))
		}
	}
}

func TestPresentOtherResolverFailureUsesFixedComment(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	runner.resolveErr = errors.New("synthetic-marker")
	res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("new")})
	if res.Result == nil || *res.Result || len(res.Changes) != 0 || !reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) || len(runner.calls) != 0 {
		t.Fatalf("resolver failure = %+v calls=%v resolve=%v", res, runner.calls, runner.resolveCalls)
	}
	if strings.Contains(res.Comment, "synthetic-marker") || fsys.unboundedRead != 0 || fsys.boundedReads != 2 {
		t.Fatalf("resolver failure leaked data or used wrong path: comment=%q reads=%d/%d", res.Comment, fsys.boundedReads, fsys.unboundedRead)
	}
}

func TestPresentOtherSiblingSuccessThenChotherResolverFailureLeavesPartialEffect(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	runner.resolveErr = errors.New("synthetic resolver marker")
	runner.afterRun = func(cmd process.Command) {
		if cmd.Name != "usermod" || !reflect.DeepEqual(cmd.Args, []string{"-u", "1001", "synthetic"}) {
			return
		}
		data, err := fsys.FileSystem.ReadFile("/etc/passwd")
		if err != nil {
			t.Errorf("read synthetic passwd for sibling mutation: %v", err)
			return
		}
		fields := strings.SplitN(strings.TrimSuffix(string(data), "\n"), ":", 7)
		fields[2] = "1001"
		if err := fsys.FileSystem.WriteFile("/etc/passwd", []byte(strings.Join(fields, ":")+"\n"), 0o644); err != nil {
			t.Errorf("write synthetic sibling mutation: %v", err)
		}
	}

	res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "synthetic", UID: "1001", Other: stateOther("new"),
	})
	if res.Result == nil || *res.Result || len(res.Changes) != 0 || res.Comment != otherManagedFailure {
		t.Fatalf("chother resolver failure result = %+v", res)
	}
	if !reflect.DeepEqual(runner.calls, [][]string{{"usermod", "-u", "1001", "synthetic"}}) ||
		!reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) || len(runner.commands) != 1 ||
		runner.commands[0].Dir != "" || runner.commands[0].Env != nil {
		t.Fatalf("partial-effect order = calls %v, resolver %v, commands %+v", runner.calls, runner.resolveCalls, runner.commands)
	}
	if fsys.boundedReads != 2 || fsys.unboundedRead != 0 ||
		!strings.Contains(string(readStatePasswd(t, fsys)), "synthetic:x:1001:1000:first,last,room,work,old:") ||
		strings.Contains(res.Comment, "synthetic resolver marker") {
		t.Fatalf("partial-effect boundary: reads=%d/%d passwd=%s comment=%q", fsys.boundedReads, fsys.unboundedRead, readStatePasswd(t, fsys), res.Comment)
	}
}

func TestPresentOtherEqualValueDispatchesSiblingWithoutChotherResolver(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "synthetic", UID: "1001", Other: stateOther("old"),
	})
	if !res.Succeeded() || !res.Changed() || fsys.boundedReads != 1 || fsys.unboundedRead != 0 {
		t.Fatalf("equal-other sibling result=%+v reads=%d/%d", res, fsys.boundedReads, fsys.unboundedRead)
	}
	if !reflect.DeepEqual(runner.calls, [][]string{{"usermod", "-u", "1001", "synthetic"}}) ||
		len(runner.resolveCalls) != 0 || len(runner.commands) != 1 || runner.commands[0].Name != "usermod" ||
		runner.commands[0].Dir != "" || runner.commands[0].Env != nil {
		t.Fatalf("equal-other sibling dispatch = calls %v resolve %v commands %+v", runner.calls, runner.resolveCalls, runner.commands)
	}
}

func TestPresentOtherFailuresStopWithoutRollbackClaimsOrRetry(t *testing.T) {
	cases := []struct {
		name      string
		results   []process.CommandResult
		removeRun bool
		calls     int
	}{
		{"first sibling fails", []process.CommandResult{{ExitCode: 9}}, false, 1},
		{"shell sibling fails", []process.CommandResult{{ExitCode: 0}, {ExitCode: 0}, {ExitCode: 0}, {ExitCode: 9}}, false, 4},
		{"chother command fails", []process.CommandResult{{ExitCode: 0}, {ExitCode: 0}, {ExitCode: 0}, {ExitCode: 0}, {ExitCode: 9}}, false, 5},
		{"chother false nil", nil, true, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newOtherManagedRT(t)
			runner.results = append([]process.CommandResult(nil), tc.results...)
			if tc.removeRun {
				runner.afterRun = nil
			}
			res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
				Name: "synthetic", UID: "1001", GID: "1002", Home: "/home/new", Shell: "/bin/sh", Other: stateOther("SECRET-GECOS-MARKER"),
			})
			if res.Result == nil || *res.Result || len(res.Changes) != 0 || len(runner.calls) != tc.calls {
				t.Fatalf("failure result=%+v calls=%v; want %d calls", res, runner.calls, tc.calls)
			}
			if strings.Contains(res.Comment, "SECRET-GECOS-MARKER") || strings.Contains(res.Comment, "synthetic-marker") || strings.Contains(res.Comment, "usermod exited") {
				t.Fatalf("failure comment leaked data/cause: %q", res.Comment)
			}
			if len(runner.calls) == 5 && runner.calls[4][0] != "/usr/sbin/usermod" {
				t.Fatalf("last action was not chother: %v", runner.calls)
			}
			if tc.name == "chother false nil" && fsys.boundedReads != 3 {
				t.Fatalf("false readback should use state precheck plus exec pre/readback, got %d", fsys.boundedReads)
			}
		})
	}
}

func TestPresentOtherDoesNotFallbackToUserInfoOrCreate(t *testing.T) {
	rt, fsys, runner := newOtherManagedRT(t)
	if err := fsys.FileSystem.WriteFile("/etc/passwd", []byte("malformed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{
		Name: "synthetic", UID: "1001", GID: "1002", Home: "/home/new", Shell: "/bin/sh", Other: stateOther("new"),
	})
	if res.Result == nil || *res.Result || len(res.Changes) != 0 || fsys.boundedReads != 1 || fsys.unboundedRead != 0 || len(runner.calls) != 0 || len(runner.resolveCalls) != 0 {
		t.Fatalf("malformed account fell back or acted: result=%+v reads=%d/%d calls=%v resolver=%v", res, fsys.boundedReads, fsys.unboundedRead, runner.calls, runner.resolveCalls)
	}
}

func TestPresentOtherSyntheticLostUpdateAndSameNameRetargeting(t *testing.T) {
	// During the command, simulate a competing update to the first four
	// GECOS fields. usermod's complete-comment argv replays the earlier
	// snapshot; a matching fifth-field readback does not preserve that edit.
	rt, fsys, runner := newOtherManagedRT(t)
	runner.afterRun = func(cmd process.Command) {
		if cmd.Name != "/usr/sbin/usermod" || len(cmd.Args) != 3 {
			return
		}
		_ = fsys.FileSystem.WriteFile("/etc/passwd", []byte("synthetic:x:1000:1000:competing,identity,fields,here,old:/home/old:/bin/false\n"), 0o644)
		_ = fsys.FileSystem.WriteFile("/etc/passwd", []byte("synthetic:x:1000:1000:"+cmd.Args[1]+":/home/old:/bin/false\n"), 0o644)
	}
	res := presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("new")})
	if !res.Succeeded() || !res.Changed() || !strings.Contains(string(readStatePasswd(t, fsys)), "first,last,room,work,new") {
		t.Fatalf("expected full-comment lost-update interleaving, result=%+v passwd=%s", res, readStatePasswd(t, fsys))
	}

	// A same-name record can be replaced during the operation and still
	// pass fifth-field readback. This pins the identity-retargeting ceiling;
	// it does not claim that a UID reread would make the sequence atomic.
	rt, fsys, runner = newOtherManagedRT(t)
	runner.afterRun = func(cmd process.Command) {
		if cmd.Name != "/usr/sbin/usermod" || len(cmd.Args) != 3 {
			return
		}
		_ = fsys.FileSystem.WriteFile("/etc/passwd", []byte("synthetic:x:9999:8888:"+cmd.Args[1]+":/home/recreated:/bin/false\n"), 0o644)
	}
	res = presentFunc{}.Apply(context.Background(), rt, &presentArgs{Name: "synthetic", Other: stateOther("new")})
	if !res.Succeeded() || !res.Changed() || !strings.Contains(string(readStatePasswd(t, fsys)), "synthetic:x:9999:8888:") {
		t.Fatalf("same-name recreation interleaving not exposed: result=%+v passwd=%s", res, readStatePasswd(t, fsys))
	}
}

func readStatePasswd(t *testing.T, fsys *trackedStateFS) []byte {
	t.Helper()
	data, err := fsys.FileSystem.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	return data
}
