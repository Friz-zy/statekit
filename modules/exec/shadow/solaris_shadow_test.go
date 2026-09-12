package shadow

// R8.2 mock tests for the Solaris solaris_shadow virtual shadow
// surface, mapped onto saltstack/salt/modules/solaris_shadow.py @
// pinned revision 8b63e700637e and tests/pytests/unit/modules/
// test_solaris_shadow.py: the info() fallback contract (getent
// existence, /etc/shadow hash, passwd -s aging columns incl. the
// two-field and non-zero-retcode early returns), set_maxdays /
// set_mindays / set_warndays pre-post verification (including the
// pinned set_maxdays None tail), del_password, set_password's
// /etc/shadow rewrite with the pinned fixture, gen_password vectors
// from tests/pytests/unit/utils/test_pycrypto.py and the Drepper
// crypt reference examples, cancellation and binary-missing
// boundaries, auditing-filesystem read errors, non-zero cmd.run
// post-state handling, and the solaris registry matrix. The runner is a fake
// getent/passwd store over an in-memory filesystem; no real binary
// runs and no hashing shells out.

import (
	"context"
	"crypto/sha512"
	"errors"
	"hash"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// sunShadowRunner simulates the Solaris tool surface the module uses:
// `getent passwd name` existence checks, `passwd -s name` aging reads,
// and the passwd -x/-n/-w/-d mutators. Mutations update the runner's
// passwd -s state and (for -d) the shared in-memory /etc/shadow;
// frozen=true makes them succeed without applying changes.
type sunShadowRunner struct {
	users         map[string]bool
	ps            map[string]string
	frozen        bool
	missing       bool
	retcode       int
	retcodeStdout []byte
	retcodeStderr []byte
	calls         []process.Command
	fs            *runtime.MemoryFS
}

type sunShadowAuditFS struct {
	*runtime.MemoryFS
	cancelAfterRead context.CancelFunc
	reads           int
	writes          int
	readErr         error
	readErrors      []error
}

func (f *sunShadowAuditFS) ReadFile(name string) ([]byte, error) {
	f.reads++
	var data []byte
	var err error
	if len(f.readErrors) > 0 {
		err = f.readErrors[0]
		f.readErrors = f.readErrors[1:]
		if err == nil {
			data, err = f.MemoryFS.ReadFile(name)
		}
	} else if f.readErr != nil {
		err = f.readErr
	} else {
		data, err = f.MemoryFS.ReadFile(name)
	}
	if err != nil {
		data = nil
	}
	if f.cancelAfterRead != nil {
		f.cancelAfterRead()
		f.cancelAfterRead = nil
	}
	return data, err
}

func (f *sunShadowAuditFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	f.writes++
	return f.MemoryFS.WriteFile(name, data, perm)
}

func newSunShadowRunner() (*sunShadowRunner, *runtime.Runtime) {
	runner := &sunShadowRunner{
		users: map[string]bool{"root": true, "alice": true, "roscivs": true, "wayne": true},
		ps: map[string]string{
			"root":  "root NL",
			"alice": "alice PS 06/12/2026 7 90 14",
		},
	}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	runner.fs = rt.FS.(*runtime.MemoryFS)
	return runner, rt
}

func sunWriteShadow(t *testing.T, rt *runtime.Runtime, content string) {
	t.Helper()
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(sunShadowPath, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
}

func (r *sunShadowRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	missing := process.CommandResult{
		Err:      errors.New("exec: executable file not found in $PATH"),
		ExitCode: -1,
	}
	if r.missing || (command.Name != "getent" && command.Name != "passwd") {
		return missing
	}
	argv := append([]string{command.Name}, command.Args...)
	switch {
	case command.Name == "getent" && len(argv) == 3:
		if r.users[argv[2]] {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(argv[2] + ":x:1001:10::/home/" + argv[2] + ":/bin/sh\n")}
		}
		return process.CommandResult{ExitCode: 2}
	case len(argv) == 3 && argv[1] == "-s":
		if line, ok := r.ps[argv[2]]; ok {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(line)}
		}
		return process.CommandResult{ExitCode: 1}
	case len(argv) == 4 && (argv[1] == "-x" || argv[1] == "-n" || argv[1] == "-w"):
		if !r.frozen {
			r.sunUpdatePS(argv[3], argv[1], argv[2])
		}
		return process.CommandResult{ExitCode: r.retcode, Stdout: r.retcodeStdout, Stderr: r.retcodeStderr}
	case len(argv) == 3 && argv[1] == "-d":
		if !r.frozen {
			r.sunClearShadowField(argv[2])
		}
		return process.CommandResult{ExitCode: r.retcode, Stdout: r.retcodeStdout, Stderr: r.retcodeStderr}
	}
	return missing
}

func (r *sunShadowRunner) sunUpdatePS(name, flag, value string) {
	line, ok := r.ps[name]
	if !ok {
		return
	}
	fields := strings.Fields(line)
	if len(fields) != 6 {
		return
	}
	switch flag {
	case "-x":
		fields[4] = value
	case "-n":
		fields[3] = value
	case "-w":
		fields[5] = value
	}
	r.ps[name] = strings.Join(fields, " ")
}

func (r *sunShadowRunner) sunClearShadowField(name string) {
	data, err := r.fs.ReadFile(sunShadowPath)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		comps := strings.Split(strings.TrimSpace(line), ":")
		if len(comps) >= 2 && comps[0] == name {
			comps[1] = ""
			lines[i] = strings.Join(comps, ":")
		}
	}
	_ = r.fs.WriteFile(sunShadowPath, []byte(strings.Join(lines, "\n")), 0o400)
}

func sunArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func sunOnlyCalls(runner *sunShadowRunner, verb string) [][]string {
	var out [][]string
	for _, call := range runner.calls {
		if strings.HasPrefix(strings.Join(sunArgv(call), " "), verb) {
			out = append(out, sunArgv(call))
		}
	}
	return out
}

func TestSunShadowDefaultHash(t *testing.T) {
	got, err := sunDefaultHashFunc{}.Execute(context.Background(), nil, &sunDefaultHashArgs{})
	if err != nil || got != "!" {
		t.Fatalf("default_hash = %v err=%v", got, err)
	}
}

func TestSunShadowInfo(t *testing.T) {
	ctx := context.Background()

	_, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, "root:9sHZCrzLVOgs:18148::::::\nalice:$6$rounds=65601$goodsalt$lZFhiN5M8RTLd9WKDin50H4lF4F8HGMIdwvKs:17000:7:90:14:::\n")
	got, err := sunInfoFunc{}.Execute(ctx, rt, &sunInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name":   "alice",
		"passwd": "$6$rounds=65601$goodsalt$lZFhiN5M8RTLd9WKDin50H4lF4F8HGMIdwvKs",
		"lstchg": "06/12/2026",
		"min":    7,
		"max":    90,
		"warn":   14,
		"inact":  "",
		"expire": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("info = %#v, want %#v", got, want)
	}

	// Two-field passwd -s output ("root NL") returns before the aging
	// parse, keeping the shadow hash.
	got, err = sunInfoFunc{}.Execute(ctx, rt, &sunInfoArgs{Name: "root"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"name": "root", "passwd": "9sHZCrzLVOgs", "lstchg": "", "min": "",
		"max": "", "warn": "", "inact": "", "expire": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("root info = %#v, want %#v", got, want)
	}

	// Unknown user: the all-empty dict.
	got, err = sunInfoFunc{}.Execute(ctx, rt, &sunInfoArgs{Name: "ghost"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"name": "", "passwd": "", "lstchg": "", "min": "",
		"max": "", "warn": "", "inact": "", "expire": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ghost info = %#v, want %#v", got, want)
	}

	// No /etc/shadow: the record stops at the name.
	_, rt2 := newSunShadowRunner()
	got, err = sunInfoFunc{}.Execute(ctx, rt2, &sunInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want["name"] = "alice"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no-shadow info = %#v, want %#v", got, want)
	}

	// passwd -s failing (retcode != 0) is data: the early return keeps
	// name and hash only.
	runner3, rt3 := newSunShadowRunner()
	sunWriteShadow(t, rt3, "wayne:waynehash:18148::::::\n")
	runner3.ps = nil
	got, err = sunInfoFunc{}.Execute(ctx, rt3, &sunInfoArgs{Name: "wayne"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"name": "wayne", "passwd": "waynehash", "lstchg": "", "min": "",
		"max": "", "warn": "", "inact": "", "expire": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ps-fail info = %#v, want %#v", got, want)
	}

	// Name missing from /etc/shadow keeps passwd empty.
	_, rt4 := newSunShadowRunner()
	sunWriteShadow(t, rt4, "other:otherhash:18148::::::\n")
	got, err = sunInfoFunc{}.Execute(ctx, rt4, &sunInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if got.(map[string]any)["passwd"] != "" {
		t.Fatalf("absent passwd = %#v", got)
	}

	// Malformed aging output surfaces as errors (the pinned int()
	// conversions raise); the shadow file must exist so info reaches
	// the passwd -s parse.
	runner5, rt5 := newSunShadowRunner()
	sunWriteShadow(t, rt5, "alice:$6$salt$hash:17000:7:90:14:::\n")
	runner5.ps["alice"] = "alice PS 06/12/2026 x 90 14"
	if _, err := (sunInfoFunc{}).Execute(ctx, rt5, &sunInfoArgs{Name: "alice"}); err == nil {
		t.Fatal("non-numeric min must error")
	}
	runner6, rt6 := newSunShadowRunner()
	sunWriteShadow(t, rt6, "alice:$6$salt$hash:17000:7:90:14:::\n")
	runner6.ps["alice"] = "alice PS 06/12/2026 7 90"
	if _, err := (sunInfoFunc{}).Execute(ctx, rt6, &sunInfoArgs{Name: "alice"}); err == nil {
		t.Fatal("short passwd -s row must error")
	}
}

func TestSunShadowInfoAuditsFilesystemErrors(t *testing.T) {
	cases := []struct {
		name      string
		readErr   error
		withFile  bool
		wantError bool
	}{
		{"missing", nil, false, false},
		{"permission", fs.ErrPermission, true, true},
		{"io", errors.New("audit io failure"), true, true},
		{"oversize", runtime.ErrReadLimit, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rt := newSunShadowRunner()
			memory := rt.FS.(*runtime.MemoryFS)
			if tc.withFile {
				sunWriteShadow(t, rt, "alice:secret-hash:17000:7:90:14:::\n")
			}
			audit := &sunShadowAuditFS{MemoryFS: memory, readErr: tc.readErr}
			rt.FS = audit
			got, err := sunInfo(context.Background(), rt, "alice")
			if tc.wantError {
				if got != nil || err == nil {
					t.Fatalf("info = %#v err=%v, want opaque read error", got, err)
				}
				if tc.readErr != nil && !errors.Is(err, tc.readErr) {
					t.Fatalf("info err=%v, want %v", err, tc.readErr)
				}
				return
			}
			if err != nil || got == nil || got["name"] != "alice" || got["passwd"] != "" {
				t.Fatalf("missing info = %#v err=%v, want empty shadow branch", got, err)
			}
		})
	}

	_, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:secret-hash:17000:7:90:14:::\n")
	ctx, cancel := context.WithCancel(context.Background())
	audit := &sunShadowAuditFS{MemoryFS: rt.FS.(*runtime.MemoryFS), cancelAfterRead: cancel}
	rt.FS = audit
	got, err := sunInfo(ctx, rt, "alice")
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled info = %#v err=%v, want nil/context.Canceled", got, err)
	}
}

func TestSunShadowSetAgeDays(t *testing.T) {
	ctx := context.Background()
	// The pinned info() reads /etc/shadow before passwd -s, so every
	// case needs the file present for the aging fields to populate.
	shadow := "alice:$6$salt$hash:17000:7:90:14:::\n"

	// set_maxdays: same value short-circuits without a passwd -x.
	runner, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	got, err := sunSetMaxdaysFunc{}.Execute(ctx, rt, &sunSetMaxdaysArgs{Name: "alice", Maxdays: "90"})
	if err != nil || got != true {
		t.Fatalf("set_maxdays same = %v err=%v", got, err)
	}
	if len(sunOnlyCalls(runner, "passwd -x")) != 0 {
		t.Fatalf("same-value mutated: %#v", runner.calls)
	}

	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	got, err = (sunSetMaxdaysFunc{}).Execute(ctx, rt, &sunSetMaxdaysArgs{Name: "alice", Maxdays: "60"})
	if err != nil || got != true {
		t.Fatalf("set_maxdays change = %v err=%v", got, err)
	}
	if want := [][]string{{"passwd", "-x", "60", "alice"}}; !reflect.DeepEqual(sunOnlyCalls(runner, "passwd -x"), want) {
		t.Fatalf("argv = %v", sunOnlyCalls(runner, "passwd -x"))
	}

	// Frozen store: post == pre and the pinned set_maxdays falls off
	// the end returning None.
	runner, rt = newSunShadowRunner()
	runner.frozen = true
	got, err = sunSetMaxdaysFunc{}.Execute(ctx, rt, &sunSetMaxdaysArgs{Name: "alice", Maxdays: "60"})
	if err != nil || got != nil {
		t.Fatalf("set_maxdays frozen = %v err=%v, want nil/nil", got, err)
	}

	// set_mindays.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	if got, err = (sunSetMindaysFunc{}).Execute(ctx, rt, &sunSetMindaysArgs{Name: "alice", Mindays: "7"}); err != nil || got != true {
		t.Fatalf("set_mindays same = %v err=%v", got, err)
	}
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	if got, err = (sunSetMindaysFunc{}).Execute(ctx, rt, &sunSetMindaysArgs{Name: "alice", Mindays: "1"}); err != nil || got != true {
		t.Fatalf("set_mindays change = %v err=%v", got, err)
	}
	if want := [][]string{{"passwd", "-n", "1", "alice"}}; !reflect.DeepEqual(sunOnlyCalls(runner, "passwd -n"), want) {
		t.Fatalf("argv = %v", sunOnlyCalls(runner, "passwd -n"))
	}
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	runner.frozen = true
	if got, err = (sunSetMindaysFunc{}).Execute(ctx, rt, &sunSetMindaysArgs{Name: "alice", Mindays: "1"}); err != nil || got != false {
		t.Fatalf("set_mindays frozen = %v err=%v, want false", got, err)
	}

	// set_warndays.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	if got, err = (sunSetWarndaysFunc{}).Execute(ctx, rt, &sunSetWarndaysArgs{Name: "alice", Warndays: "14"}); err != nil || got != true {
		t.Fatalf("set_warndays same = %v err=%v", got, err)
	}
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	if got, err = (sunSetWarndaysFunc{}).Execute(ctx, rt, &sunSetWarndaysArgs{Name: "alice", Warndays: "7"}); err != nil || got != true {
		t.Fatalf("set_warndays change = %v err=%v", got, err)
	}
	if want := [][]string{{"passwd", "-w", "7", "alice"}}; !reflect.DeepEqual(sunOnlyCalls(runner, "passwd -w"), want) {
		t.Fatalf("argv = %v", sunOnlyCalls(runner, "passwd -w"))
	}
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, shadow)
	runner.frozen = true
	if got, err = (sunSetWarndaysFunc{}).Execute(ctx, rt, &sunSetWarndaysArgs{Name: "alice", Warndays: "7"}); err != nil || got != false {
		t.Fatalf("set_warndays frozen = %v err=%v, want false", got, err)
	}
}

func TestSunShadowDelPassword(t *testing.T) {
	runner, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:$6$salt$hash:17000:7:90:14:::\n")
	got, err := sunDelPasswordFunc{}.Execute(context.Background(), rt, &sunDelPasswordArgs{Name: "alice"})
	if err != nil || got != true {
		t.Fatalf("del_password = %v err=%v", got, err)
	}
	if want := [][]string{{"passwd", "-d", "alice"}}; !reflect.DeepEqual(sunOnlyCalls(runner, "passwd -d"), want) {
		t.Fatalf("argv = %v", sunOnlyCalls(runner, "passwd -d"))
	}
	data, _ := rt.FS.ReadFile(sunShadowPath)
	if !strings.Contains(string(data), "alice::17000:7:90:14:::") {
		t.Fatalf("passwd -d did not clear the hash: %q", string(data))
	}

	// Frozen: the hash survives, so the verification reports false.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:$6$salt$hash:17000:7:90:14:::\n")
	runner.frozen = true
	got, err = sunDelPasswordFunc{}.Execute(context.Background(), rt, &sunDelPasswordArgs{Name: "alice"})
	if err != nil || got != false {
		t.Fatalf("del_password frozen = %v err=%v", got, err)
	}

	// A missing shadow file is the info() empty branch, but verification must
	// not turn that read failure into a successful deletion.
	runner, rt = newSunShadowRunner()
	got, err = sunDelPasswordFunc{}.Execute(context.Background(), rt, &sunDelPasswordArgs{Name: "alice"})
	if err != nil || got != false {
		t.Fatalf("del_password missing shadow = %v err=%v, want false/nil", got, err)
	}
}

func TestSunShadowSetPassword(t *testing.T) {
	// Missing /etc/shadow returns the empty dict without touching the
	// runner.
	runner, rt := newSunShadowRunner()
	got, err := sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "fnord", Password: "blarp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("no-shadow set_password = %#v", got)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("no-shadow set_password spawned %#v", runner.calls)
	}

	// Pinned fixture from test_solaris_shadow.py: the matching line is
	// rewritten in place, the others keep their bytes.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "foo:bar:bang\nwhatever:is:shadow\nroscivs:bottia:bloop\n")
	got, err = sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "roscivs", Password: "bottia2"})
	if err != nil || got != true {
		t.Fatalf("set_password = %v err=%v", got, err)
	}
	data, _ := rt.FS.ReadFile(sunShadowPath)
	want := "foo:bar:bang\nwhatever:is:shadow\nroscivs:bottia2:bloop\n"
	if string(data) != want {
		t.Fatalf("shadow = %q, want %q", string(data), want)
	}

	// A user unknown to getent verifies through the empty info dict
	// and reports false even though the file was rewritten.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "roscivs:bottia:bloop\n")
	delete(runner.users, "roscivs")
	got, err = sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "roscivs", Password: "newhash"})
	if err != nil || got != false {
		t.Fatalf("set_password unknown = %v err=%v", got, err)
	}
	data, _ = rt.FS.ReadFile(sunShadowPath)
	if !strings.Contains(string(data), "roscivs:newhash:bloop") {
		t.Fatalf("shadow = %q", string(data))
	}
}

func TestSunShadowVerificationPropagatesReadErrors(t *testing.T) {
	for _, readErr := range []error{fs.ErrPermission, errors.New("audit io failure"), runtime.ErrReadLimit} {
		runner, rt := newSunShadowRunner()
		audit := &sunShadowAuditFS{MemoryFS: rt.FS.(*runtime.MemoryFS), readErr: readErr}
		rt.FS = audit
		got, err := sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "alice", Password: "newhash"})
		if got != nil || !errors.Is(err, readErr) || audit.reads != 1 || audit.writes != 0 || len(runner.calls) != 0 {
			t.Fatalf("set_password initial read=%v got=%#v err=%v reads=%d writes=%d calls=%d", readErr, got, err, audit.reads, audit.writes, len(runner.calls))
		}
	}

	// set_password must expose neither the partial record nor success when the
	// post-write verification read fails.
	runner, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:oldhash:17000:7:90:14:::\n")
	memory := rt.FS.(*runtime.MemoryFS)
	audit := &sunShadowAuditFS{MemoryFS: memory, readErrors: []error{nil, fs.ErrPermission}}
	rt.FS = audit
	got, err := sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "alice", Password: "newhash"})
	if got != nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("set_password verification = %#v err=%v, want nil/permission", got, err)
	}
	if audit.reads != 2 || audit.writes != 1 {
		t.Fatalf("set_password verification filesystem activity reads=%d writes=%d", audit.reads, audit.writes)
	}
	if len(runner.calls) != 1 || runner.calls[0].Name != "getent" {
		t.Fatalf("set_password verification commands: %#v", runner.calls)
	}

	// The missing-file branch is also not a successful post-write
	// verification, even when the requested hash is empty.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:oldhash:17000:7:90:14:::\n")
	audit = &sunShadowAuditFS{MemoryFS: rt.FS.(*runtime.MemoryFS), readErrors: []error{nil, fs.ErrNotExist}}
	rt.FS = audit
	got, err = sunSetPasswordFunc{}.Execute(context.Background(), rt, &sunSetPasswordArgs{Name: "alice", Password: ""})
	if got != false || err != nil {
		t.Fatalf("set_password missing verification = %#v err=%v, want false/nil", got, err)
	}

	// del_password has no pre-read; its verification read error must also
	// propagate instead of reporting a successful delete.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:oldhash:17000:7:90:14:::\n")
	memory = rt.FS.(*runtime.MemoryFS)
	audit = &sunShadowAuditFS{MemoryFS: memory, readErr: errors.New("audit io failure")}
	rt.FS = audit
	got, err = sunDelPasswordFunc{}.Execute(context.Background(), rt, &sunDelPasswordArgs{Name: "alice"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "audit io failure") {
		t.Fatalf("del_password verification = %#v err=%v, want nil/read error", got, err)
	}

	// Cancellation observed after the verification read is an error and never
	// a successful delete.
	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:oldhash:17000:7:90:14:::\n")
	ctx, cancel := context.WithCancel(context.Background())
	audit = &sunShadowAuditFS{MemoryFS: rt.FS.(*runtime.MemoryFS), cancelAfterRead: cancel}
	rt.FS = audit
	got, err = sunDelPasswordFunc{}.Execute(ctx, rt, &sunDelPasswordArgs{Name: "alice"})
	if got != nil || !errors.Is(err, context.Canceled) || audit.reads != 1 {
		t.Fatalf("del_password cancellation = %#v err=%v reads=%d, want nil/cancel/one read", got, err, audit.reads)
	}
}

func TestSunShadowMutatorsKeepNonZeroResultDataAndVerify(t *testing.T) {
	runner, rt := newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:$6$salt$hash:17000:7:90:14:::\n")
	runner.retcode = 7
	runner.retcodeStdout = []byte("passwd warning\n")
	got, err := sunSetMindaysFunc{}.Execute(context.Background(), rt, &sunSetMindaysArgs{Name: "alice", Mindays: "1"})
	if err != nil || got != true {
		t.Fatalf("non-zero set_mindays post-state = %v err=%v", got, err)
	}
	result, err := sunRunStrict(context.Background(), rt, "passwd", "-n", "2", "alice")
	if err != nil || result.ExitCode != 7 || string(result.Stdout) != "passwd warning\n" || len(result.Stderr) != 0 {
		t.Fatalf("sunRunStrict result = %#v err=%v, want non-zero stdout data", result, err)
	}

	runner, rt = newSunShadowRunner()
	sunWriteShadow(t, rt, "alice:$6$salt$hash:17000:7:90:14:::\n")
	runner.retcode = 9
	runner.retcodeStdout = []byte("passwd delete warning\n")
	got, err = sunDelPasswordFunc{}.Execute(context.Background(), rt, &sunDelPasswordArgs{Name: "alice"})
	if err != nil || got != true {
		t.Fatalf("non-zero del_password post-state = %v err=%v", got, err)
	}
}

func TestSunShadowSetPasswordCancellationIsReadWriteAtomic(t *testing.T) {
	content := "alice:oldhash:17000:7:90:14:::\n"
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile(sunShadowPath, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}

	// A canceled call must not even read the shadow file.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	audit := &sunShadowAuditFS{MemoryFS: memory}
	rt := &runtime.Runtime{Runner: &sunShadowRunner{}, FS: audit}
	got, err := (sunSetPasswordFunc{}).Execute(ctx, rt, &sunSetPasswordArgs{Name: "alice", Password: "newhash"})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel got=%#v err=%v, want nil/context.Canceled", got, err)
	}
	if audit.reads != 0 || audit.writes != 0 {
		t.Fatalf("pre-cancel filesystem activity reads=%d writes=%d", audit.reads, audit.writes)
	}

	// Cancellation observed by the read must be caught immediately before
	// WriteFile, preserving the original bytes and producing zero writes.
	ctx, cancel = context.WithCancel(context.Background())
	audit = &sunShadowAuditFS{MemoryFS: memory, cancelAfterRead: cancel}
	rt.FS = audit
	got, err = (sunSetPasswordFunc{}).Execute(ctx, rt, &sunSetPasswordArgs{Name: "alice", Password: "newhash"})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("read-cancel got=%#v err=%v, want nil/context.Canceled", got, err)
	}
	if audit.reads != 1 || audit.writes != 0 {
		t.Fatalf("read-cancel filesystem activity reads=%d writes=%d", audit.reads, audit.writes)
	}
	data, readErr := memory.ReadFile(sunShadowPath)
	if readErr != nil || string(data) != content {
		t.Fatalf("canceled set_password changed shadow: %q err=%v", string(data), readErr)
	}
}

func TestSunGenPasswordVectors(t *testing.T) {
	// Ground truth: tests/pytests/unit/utils/test_pycrypto.py
	// (test_password / goodsalt family) and the Drepper crypt
	// reference examples (Hello world! / saltstring).
	vectors := []struct {
		password string
		salt     string
		alg      string
		want     string
	}{
		{
			"test_password", "rounds=65601$goodsalt", "sha512",
			"$6$rounds=65601$goodsalt$lZFhiN5M8RTLd9WKDin50H4lF4F8HGMIdwvKs.nTG7f8F0Y4P447Zb9/E8SkUWjY.K10QT3NuHZNDgc/P/NjT1",
		},
		{
			"Hello world!", "saltstring", "sha512",
			"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		},
		{
			"test_password", "rounds=53501$goodsalt", "sha256",
			"$5$rounds=53501$goodsalt$W.uoco0wMfGLDOlsbW52E6raFS1Nhj0McfUTj2vORt7",
		},
		{
			// glibc crypt-verified (the paper-typed variant in my
			// notes was wrong; confirmed in-container against
			// libcrypt before pinning).
			"Hello world!", "saltstring", "sha256",
			"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		},
		{
			"test_password", "goodsalt", "md5",
			"$1$goodsalt$4XQMx4a4e1MpBB8xzz.TQ0",
		},
		{
			"test_password", "10$goodsaltgoodsaltgoodsa", "blowfish",
			"$2b$10$goodsaltgoodsaltgoodsObFfGrJwfV.13QddrZIh2w1ccESmvj8K",
		},
	}
	for _, tc := range vectors {
		got, err := sunGenPasswordFunc{}.Execute(context.Background(), nil,
			&sunGenPasswordArgs{Password: tc.password, CryptSalt: tc.salt, Algorithm: tc.alg})
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if got != tc.want {
			t.Fatalf("%s vector =\n  got  %s\n  want %s", tc.alg, got, tc.want)
		}
		// The pinned badsalt assertion: a different salt must not
		// reproduce the hash.
		badsalt := map[string]string{
			"sha512": "badsalt", "sha256": "badsalt", "md5": "badsalt",
			"blowfish": "11$goodsaltgoodsaltgoodsa",
		}[tc.alg]
		other, err := sunGenPasswordFunc{}.Execute(context.Background(), nil,
			&sunGenPasswordArgs{Password: tc.password, CryptSalt: badsalt, Algorithm: tc.alg})
		if err != nil {
			t.Fatalf("%s badsalt: %v", tc.alg, err)
		}
		if other == tc.want {
			t.Fatalf("%s badsalt reproduced the hash", tc.alg)
		}
	}
}

func TestSunGenPasswordRandomSalt(t *testing.T) {
	// Default algorithm is sha512; an empty crypt_salt derives a random
	// 16-character salt.
	got, err := sunGenPasswordFunc{}.Execute(context.Background(), nil, &sunGenPasswordArgs{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	s := got.(string)
	if !strings.HasPrefix(s, "$6$") || len(s) != len("$6$")+16+1+86 {
		t.Fatalf("random sha512 shape = %q (len %d)", s, len(s))
	}
	again, _ := sunGenPasswordFunc{}.Execute(context.Background(), nil, &sunGenPasswordArgs{Password: "pw"})
	if again.(string) == s {
		t.Fatalf("random salt repeated: %q", s)
	}

	for _, tc := range []struct {
		alg   string
		prefx string
		total int
	}{{"md5", "$1$", 3 + 8 + 1 + 22}, {"blowfish", "$2b$10$", 7 + 22 + 31}, {"sha256", "$5$", 3 + 16 + 1 + 43}} {
		got, err := sunGenPasswordFunc{}.Execute(context.Background(), nil,
			&sunGenPasswordArgs{Password: "pw", Algorithm: tc.alg})
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if s := got.(string); !strings.HasPrefix(s, tc.prefx) || len(s) != tc.total {
			t.Fatalf("%s random shape = %q (len %d, want %d)", tc.alg, s, len(s), tc.total)
		}
	}

	// Rounds below the source minimum still clamp to 1000; excessive work is
	// rejected before any expensive digest loop starts.
	got, err = sunGenPasswordFunc{}.Execute(context.Background(), nil,
		&sunGenPasswordArgs{Password: "pw", CryptSalt: "rounds=1$goodsalt", Algorithm: "sha512"})
	if err != nil || !strings.HasPrefix(got.(string), "$6$rounds=1000$goodsalt$") {
		t.Fatalf("clamped rounds = %v err=%v", got, err)
	}
	if got, err := (sunGenPasswordFunc{}).Execute(context.Background(), nil,
		&sunGenPasswordArgs{Password: "pw", CryptSalt: "rounds=1000001$goodsalt", Algorithm: "sha512"}); got != "" {
		t.Fatalf("excessive rounds returned partial result %q err=%v", got, err)
	} else {
		var limitErr *ResourceLimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("excessive rounds err=%v, want ResourceLimitError", err)
		}
	}
	if _, err := (sunGenPasswordFunc{}).Execute(context.Background(), nil,
		&sunGenPasswordArgs{Password: "pw", Algorithm: "crypt"}); err == nil ||
		!strings.Contains(err.Error(), "Cannot hash using 'crypt'") {
		t.Fatalf("crypt algorithm err=%v", err)
	}
}

func TestSunGenPasswordLimitsAndCancellation(t *testing.T) {
	password := strings.Repeat("p", sunCryptPasswordMaxBytes+1)
	for _, algorithm := range []string{"sha512", "sha256", "md5", "blowfish"} {
		t.Run(algorithm+" password limit", func(t *testing.T) {
			got, err := (sunGenPasswordFunc{}).Execute(context.Background(), nil,
				&sunGenPasswordArgs{Password: password, CryptSalt: "goodsaltgoodsaltgoodsa", Algorithm: algorithm})
			var limitErr *ResourceLimitError
			if got != "" || !errors.As(err, &limitErr) {
				t.Fatalf("got=%#v err=%v, want empty ResourceLimitError", got, err)
			}
			if strings.Contains(err.Error(), password) {
				t.Fatalf("password leaked in limit error: %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		salt string
		want string
	}{
		{"sha rounds", "rounds=1000001$goodsalt", "sha rounds"},
		{"bcrypt cost", "17$goodsaltgoodsaltgoodsa", "bcrypt cost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			algorithm := "sha512"
			if tc.name == "bcrypt cost" {
				algorithm = "blowfish"
			}
			got, err := sunGenPasswordFunc{}.Execute(context.Background(), nil,
				&sunGenPasswordArgs{Password: "pw", CryptSalt: tc.salt, Algorithm: algorithm})
			var limitErr *ResourceLimitError
			if got != "" || !errors.As(err, &limitErr) || limitErr.Resource != tc.want {
				t.Fatalf("got=%#v err=%v, want %s ResourceLimitError", got, err, tc.want)
			}
		})
	}

	// The public execution path returns context.Canceled without exposing a
	// partial hash or password-bearing error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := sunGenPasswordFunc{}.Execute(ctx, nil,
		&sunGenPasswordArgs{Password: "secret-password", CryptSalt: "goodsalt", Algorithm: "sha512"})
	if got != "" || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "secret-password") {
		t.Fatalf("pre-cancel hash got=%#v err=%v", got, err)
	}

	// Cancel after the first SHA round to prove checks occur between rounds.
	ctx, cancel = context.WithCancel(context.Background())
	created := 0
	newHash := func() hash.Hash {
		created++
		if created == 5 { // B, A, DP, DS, then the first round.
			cancel()
		}
		return sha512.New()
	}
	gotHash, err := sunSHACryptContext(ctx, "pw", "goodsalt", "$6$", 64, newHash, sunSHA512Permutation)
	if gotHash != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-round cancel got=%q err=%v", gotHash, err)
	}

	// A low bcrypt cost keeps this deterministic while the context cancels
	// between expensive key-schedule iterations.
	checkCtx := &sunCancelAfterContext{Context: context.Background(), cancelAt: 4}
	gotHash, err = sunBlowfishCryptContext(checkCtx, "pw", "4$goodsaltgoodsaltgoodsa")
	if gotHash != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("bcrypt iteration cancel got=%q err=%v", gotHash, err)
	}
}

type sunCancelAfterContext struct {
	context.Context
	checks   int
	cancelAt int
}

func (c *sunCancelAfterContext) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestSunBlowfishRejectsMalformedSaltsWithoutPanic(t *testing.T) {
	valid := "goodsaltgoodsaltgoodsa"
	cases := []struct {
		name string
		salt string
	}{
		{"short", "10$" + strings.Repeat(".", sunBcryptSaltChars-1)},
		{"long", "10$" + strings.Repeat(".", sunBcryptSaltChars+1)},
		{"invalid character", "10$" + strings.Repeat(".", sunBcryptSaltChars-1) + "!"},
		{"excessive cost", "17$" + valid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("malformed salt panicked: %v", recovered)
				}
			}()
			got, err := sunBlowfishCrypt("pw", tc.salt)
			if got != "" || err == nil {
				t.Fatalf("got=%q err=%v, want empty error", got, err)
			}
		})
	}
}

func TestSunShadowCancellationAndMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner, rt := newSunShadowRunner()
	if _, err := (sunInfoFunc{}).Execute(ctx, rt, &sunInfoArgs{Name: "alice"}); err == nil {
		t.Fatal("canceled context must error before the Runner starts")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled context spawned %#v", runner.calls)
	}

	runner, rt = newSunShadowRunner()
	runner.missing = true
	if _, err := (sunSetMindaysFunc{}).Execute(context.Background(), rt, &sunSetMindaysArgs{Name: "alice", Mindays: "1"}); err == nil {
		t.Fatal("binary-missing set_mindays must error")
	}
}

// ---------------------------------------------------------------------------
// registry matrix

var sunShadowRegistryNames = []string{
	"shadow.default_hash",
	"shadow.del_password",
	"shadow.gen_password",
	"shadow.info",
	"shadow.set_maxdays",
	"shadow.set_mindays",
	"shadow.set_password",
	"shadow.set_warndays",
}

func TestSunShadowRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(sunShadowRegistryNames) {
		t.Fatalf("registered %d functions, want %d", reg.Len(), len(sunShadowRegistryNames))
	}
	for _, name := range sunShadowRegistryNames {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing from solaris registration", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "solaris" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
		if !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s does not support solaris", name)
		}
		if runtime.SupportsPlatform(fn, "linux") {
			t.Fatalf("%s must not support linux", name)
		}
	}
	if runtime.CurrentGOOS() != "solaris" && len(reg.Names()) != 0 {
		t.Fatalf("host registry leaked solaris shadow names: %v", reg.Names())
	}
	if runtime.CurrentGOOS() != "solaris" {
		_, err := reg.Call(context.Background(), &runtime.Runtime{}, "shadow.set_password", &sunSetPasswordArgs{})
		var unsupported *runtime.UnsupportedError
		if !errors.As(err, &unsupported) {
			t.Fatalf("shadow.set_password on host err=%v, want UnsupportedError", err)
		}
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatalf("duplicate solaris registration accepted")
	}

	// The linux Register path stays canonical: shadow.info only, no
	// solaris additions.
	if runtime.CurrentGOOS() != "solaris" {
		linux := runtime.NewExecRegistry()
		if err := Register(linux); err != nil {
			t.Fatal(err)
		}
		if _, exists := linux.Get("shadow.set_password"); exists {
			t.Fatal("linux registry unexpectedly carries solaris-only shadow.set_password")
		}
		if _, exists := linux.Get("shadow.info"); !exists {
			t.Fatal("linux registry lost shadow.info")
		}
	}
}
