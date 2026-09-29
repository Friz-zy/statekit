package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

// updateLessFS hides the bounded-update capability by embedding the
// FileSystem INTERFACE (only the base method set is promoted), so the
// dispatcher's no-fallback contract can be pinned.
type updateLessFS struct{ FileSystem }

// secretFault is a value-carrying callback/fault error: it carries a
// payload string and a custom type, proving that neither the text nor
// the value is extractable through the opaque capability boundary.
type secretFault struct{ payload string }

func (s *secretFault) Error() string { return "SECRET-MARKER-" + s.payload }

// hostileUpdateError is the malicious callback error (R103B-SEC-06):
// EVERY method — Error, Is, As, Unwrap, and the fmt.Formatter hook —
// both counts its invocation and PANICS. If the capability boundary
// inspected a dropped callback error in any way (formatted it,
// classified through it, walked its chain, or extracted a value), the
// test would panic and the counter would move; a conforming boundary
// leaves the counter at zero. It also embeds a context sentinel in its
// chain so an inspecting boundary could fabricate a cancellation
// classification, and carries a payload so an inspecting errors.As
// could leak a value.
type hostileUpdateError struct {
	calls   *int
	payload string
}

func (h *hostileUpdateError) touch() {
	*h.calls++
	panic("hostile callback error method invoked: " + h.payload)
}

func (h *hostileUpdateError) Error() string          { h.touch(); return "HOSTILE-" + h.payload }
func (h *hostileUpdateError) Is(error) bool          { h.touch(); return true }
func (h *hostileUpdateError) As(any) bool            { h.touch(); return true }
func (h *hostileUpdateError) Unwrap() error          { h.touch(); return context.Canceled }
func (h *hostileUpdateError) Format(fmt.State, rune) { h.touch() }
func (h *hostileUpdateError) GoString() string       { h.touch(); return "HOSTILE-GOSTRING" }

// assertOpaqueTransformSentinel pins the full cause-free contract of a
// dropped callback error: no hostile method was invoked, the fixed
// sentinel text is the whole answer under every format verb,
// errors.Is matches ONLY the fixed sentinel identity (no arbitrary
// sentinel fabrication, no callback-fabricated context classification),
// errors.As cannot extract the payload, and Unwrap answers nil.
func assertOpaqueTransformSentinel(t *testing.T, err error, calls *int, sentinel error) {
	t.Helper()
	if *calls != 0 {
		t.Fatalf("callback error methods were invoked (%d calls)", *calls)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the fixed sentinel %v", err, sentinel)
	}
	if err.Error() != sentinel.Error() {
		t.Fatalf("err text = %q, want the constant %q", err.Error(), sentinel.Error())
	}
	// No arbitrary sentinel fabrication: neither the hostile chain's
	// embedded context.Canceled nor any other fixed identity
	// classifies, and a second sentinel is not fabricated either.
	for _, target := range []error{context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF} {
		if errors.Is(err, target) {
			t.Fatalf("err = %v, must not classify as %v", err, target)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("sentinel exposes a chain through Unwrap: %v", errors.Unwrap(err))
	}
	var extracted *hostileUpdateError
	if errors.As(err, &extracted) {
		t.Fatalf("errors.As extracted the callback payload: %#v", extracted)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if formatted := fmt.Sprintf(verb, err); strings.Contains(formatted, "HOSTILE") ||
			strings.Contains(formatted, "SECRET") || !strings.Contains(formatted, sentinel.Error()) {
			t.Fatalf("formatting %q = %q, want the fixed sentinel text only", verb, formatted)
		}
	}
}

func newUpdateLessMemory(t *testing.T) (*MemoryFS, *updateLessFS) {
	t.Helper()
	mem := NewMemoryFS()
	return mem, &updateLessFS{FileSystem: mem}
}

func TestUpdateFileBoundedValidatesLimitsAndTransform(t *testing.T) {
	mem := NewMemoryFS()
	pass := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }
	for _, limits := range []UpdateLimits{
		{MaxReadBytes: 0, MaxWriteBytes: 16},
		{MaxReadBytes: -1, MaxWriteBytes: 16},
		{MaxReadBytes: 16, MaxWriteBytes: 0},
		{MaxReadBytes: 16, MaxWriteBytes: -4},
		{MaxReadBytes: MaxBoundedReadLimit + 1, MaxWriteBytes: 16},
		{MaxReadBytes: 16, MaxWriteBytes: MaxBoundedWriteLimit + 1},
	} {
		if err := UpdateFileBounded(mem, context.Background(), "/f", limits, true, pass); !errors.Is(err, ErrInvalidUpdateLimit) {
			t.Fatalf("limits %+v err = %v, want ErrInvalidUpdateLimit", limits, err)
		}
	}
	if err := UpdateFileBounded(mem, context.Background(), "/f", UpdateLimits{1, 1}, true, nil); !errors.Is(err, ErrInvalidUpdateTransform) {
		t.Fatalf("nil transform err = %v", err)
	}
}

func TestUpdateFileBoundedCapabilityAbsentFailsClosed(t *testing.T) {
	mem, legacy := newUpdateLessMemory(t)
	if err := mem.WriteFile("/f", []byte("orig"), 0o644); err != nil {
		t.Fatal(err)
	}
	pass := func(existing []byte, exists bool) ([]byte, error) { return []byte("new"), nil }
	err := UpdateFileBounded(legacy, context.Background(), "/f", UpdateLimits{16, 16}, true, pass)
	if !errors.Is(err, ErrUpdateUnsupported) {
		t.Fatalf("capability-absent err = %v, want ErrUpdateUnsupported", err)
	}
	data, err := mem.ReadFile("/f")
	if err != nil || string(data) != "orig" {
		t.Fatalf("capability-absent left %q (err %v); no WriteFile fallback may run", data, err)
	}
}

func TestMemoryUpdateReplacesExistingAndPreservesMode(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/etc/hosts", []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	seen := ""
	transform := func(existing []byte, exists bool) ([]byte, error) {
		if !exists || string(existing) != "old" {
			t.Fatalf("transform saw %q exists=%v", existing, exists)
		}
		seen = "called"
		return []byte("new contents"), nil
	}
	if err := mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, false, transform); err != nil {
		t.Fatal(err)
	}
	if seen != "called" {
		t.Fatal("transform never ran")
	}
	data, err := mem.ReadFile("/etc/hosts")
	if err != nil || string(data) != "new contents" {
		t.Fatalf("updated content = %q (err %v)", data, err)
	}
	info, err := mem.Stat("/etc/hosts")
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode after update = %v (err %v), want 0640 preserved", info.Mode(), err)
	}
}

func TestMemoryUpdateCreatesWith0644AndRefusesWithoutAllowCreate(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	absent := false
	transform := func(existing []byte, exists bool) ([]byte, error) {
		absent = !exists
		if existing != nil {
			t.Fatalf("absent target passed %q", existing)
		}
		return []byte("fresh"), nil
	}
	if err := mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, true, transform); err != nil {
		t.Fatal(err)
	}
	if !absent {
		t.Fatal("create path must report exists=false")
	}
	info, err := mem.Stat("/etc/hosts")
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("created mode = %v (err %v), want 0644", info.Mode(), err)
	}
	if err := mem.UpdateFileBounded(context.Background(), "/missing/x", UpdateLimits{64, 64}, false, transform); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no-create missing err = %v, want fs.ErrNotExist", err)
	}
	if _, err := mem.Stat("/missing/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no-create attempt created the target: %v", err)
	}
}

func TestMemoryUpdateValidationRejections(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/d/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/d/file", []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/d/big", []byte(strings.Repeat("x", 33)), 0o644); err != nil {
		t.Fatal(err)
	}
	identity := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }
	big := func([]byte, bool) ([]byte, error) { return []byte(strings.Repeat("y", 33)), nil }

	// Oversized existing content and oversized replacement both leave
	// the target unchanged.
	if err := mem.UpdateFileBounded(context.Background(), "/d/big", UpdateLimits{32, 32}, false, identity); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("oversized read err = %v", err)
	}
	if err := mem.UpdateFileBounded(context.Background(), "/d/file", UpdateLimits{32, 32}, false, big); !errors.Is(err, ErrWriteLimit) {
		t.Fatalf("oversized write err = %v", err)
	}
	if data, _ := mem.ReadFile("/d/file"); string(data) != "data" {
		t.Fatalf("target mutated by rejected update: %q", data)
	}

	// Transform errors abort untouched, and the callback error is never
	// INSPECTED: the fixed cause-free ErrUpdateTransform sentinel is
	// the entire answer — constant text, no Unwrap, no custom Is, no
	// callback identity (R103B-SEC-06). A plain marker error therefore
	// no longer classifies through the boundary at all.
	boom := errors.New("SECRET-MARKER-transform")
	fail := func([]byte, bool) ([]byte, error) { return nil, boom }
	err := mem.UpdateFileBounded(context.Background(), "/d/file", UpdateLimits{32, 32}, false, fail)
	if !errors.Is(err, ErrUpdateTransform) {
		t.Fatalf("transform error err = %v, want ErrUpdateTransform", err)
	}
	if errors.Is(err, boom) {
		t.Fatalf("transform err = %v, must not classify the callback identity", err)
	}
	if err.Error() != ErrUpdateTransform.Error() || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("transform error text = %q, want the fixed sentinel text only", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("transform sentinel must not expose the cause through Unwrap: %v", errors.Unwrap(err))
	}

	// Symlinked or special final components and non-directory parents
	// are rejected; directories answer EISDIR.
	if err := mem.Symlink("/d/file", "/d/link"); err != nil {
		t.Fatal(err)
	}
	if err := mem.Symlink("/d", "/d-dirlink"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]error{
		"/d/link":       ErrNonRegularFile,
		"/d-dirlink":    ErrNonRegularFile,
		"/d-dirlink/f":  ErrNonRegularFile,
		"/d":            syscall.EISDIR,
		"/d/file/inner": ErrNonRegularFile, // file as parent
	} {
		if err := mem.UpdateFileBounded(context.Background(), name, UpdateLimits{32, 32}, false, identity); !errors.Is(err, want) {
			t.Fatalf("%s err = %v, want %v", name, err, want)
		}
	}
	if err := mem.UpdateFileBounded(context.Background(), "/no/such", UpdateLimits{32, 32}, false, identity); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing parent err = %v", err)
	}

	// Every error is value-free: no path bytes travel in it.
	err = mem.UpdateFileBounded(context.Background(), "/d-dirlink/f", UpdateLimits{32, 32}, false, identity)
	if err != nil && strings.Contains(err.Error(), "/d-dirlink") {
		t.Fatalf("error leaks the path: %v", err)
	}
}

func TestMemoryUpdateFaultInjection(t *testing.T) {
	write := func(content string) *MemoryFS {
		mem := NewMemoryFS()
		if err := mem.WriteFile("/f", []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return mem
	}
	identity := func(existing []byte, exists bool) ([]byte, error) { return []byte("replaced"), nil }

	// Commit-stage fault: the tree stays untouched, and the injected
	// fault is DROPPED at the boundary — the fixed ErrUpdateStageHook
	// sentinel answers with no marker text, no marker identity, and no
	// Unwrap (R103B-REGATE-01).
	commitMarker := errors.New("SECRET-MARKER-commit-fault")
	mem := write("orig")
	mem.updateHook = func(stage string) error {
		if stage == "commit" {
			return commitMarker
		}
		return nil
	}
	err := mem.UpdateFileBounded(context.Background(), "/f", UpdateLimits{16, 16}, false, identity)
	if !errors.Is(err, ErrUpdateStageHook) {
		t.Fatalf("commit fault err = %v, want ErrUpdateStageHook", err)
	}
	if err.Error() != ErrUpdateStageHook.Error() || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("commit fault text = %q, want the fixed sentinel text only", err)
	}
	if errors.Is(err, commitMarker) || errors.Is(err, ErrUpdateTransform) {
		t.Fatalf("commit fault err = %v, must not classify the injected fault identity", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("commit fault err exposes a chain through Unwrap: %v", errors.Unwrap(err))
	}
	if data, _ := mem.ReadFile("/f"); string(data) != "orig" {
		t.Fatalf("commit fault mutated target: %q", data)
	}

	// A commit-stage fault whose error carries a VALUE (a custom type
	// with data) is unreachable through errors.As: the sentinel is the
	// only thing that answers.
	mem = write("orig")
	mem.updateHook = func(stage string) error {
		if stage == "start" {
			return &secretFault{payload: "SECRET-MARKER-value"}
		}
		return nil
	}
	err = mem.UpdateFileBounded(context.Background(), "/f", UpdateLimits{16, 16}, false, identity)
	if !errors.Is(err, ErrUpdateStageHook) {
		t.Fatalf("start fault err = %v, want ErrUpdateStageHook", err)
	}
	var extracted *secretFault
	if errors.As(err, &extracted) {
		t.Fatalf("errors.As extracted the fault value: %#v", extracted)
	}
	if data, _ := mem.ReadFile("/f"); string(data) != "orig" {
		t.Fatalf("start fault mutated target: %q", data)
	}
	// Durability-stage fault: content IS committed, outcome distinct.
	mem = write("orig")
	mem.updateHook = func(stage string) error {
		if stage == "durability" {
			return errors.New("injected durability fault")
		}
		return nil
	}
	if err := mem.UpdateFileBounded(context.Background(), "/f", UpdateLimits{16, 16}, false, identity); !errors.Is(err, ErrUpdateCommittedUncertain) {
		t.Fatalf("durability fault err = %v, want ErrUpdateCommittedUncertain", err)
	}
	if data, _ := mem.ReadFile("/f"); string(data) != "replaced" {
		t.Fatalf("durability fault rolled back commit: %q", data)
	}

	// A start-stage fault whose callback returns a context sentinel is
	// answered by the fixed stage-hook sentinel: the seam is NOT the
	// actual context, so it must not masquerade as a real
	// cancellation — real cancellation classification comes only from
	// the runtime's independent ctx checks (pinned below).
	mem = write("orig")
	mem.updateHook = func(stage string) error {
		if stage == "start" {
			return context.Canceled
		}
		return nil
	}
	if err := mem.UpdateFileBounded(context.Background(), "/f", UpdateLimits{16, 16}, false, identity); !errors.Is(err, ErrUpdateStageHook) {
		t.Fatalf("start fault returning a context sentinel err = %v, want ErrUpdateStageHook", err)
	}
	if data, _ := mem.ReadFile("/f"); string(data) != "orig" {
		t.Fatalf("start fault mutated target: %q", data)
	}

	// A pre-canceled context aborts before publication (the runtime's
	// own check answers the real context sentinel).
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	mem = write("orig")
	if err := mem.UpdateFileBounded(canceled, "/f", UpdateLimits{16, 16}, false, identity); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx err = %v", err)
	}
	if data, _ := mem.ReadFile("/f"); string(data) != "orig" {
		t.Fatalf("canceled ctx mutated target: %q", data)
	}
}

// dispatchCountingFS counts UpdateFileBounded dispatches to prove the
// dispatcher rejects invalid paths before any filesystem access.
type dispatchCountingFS struct {
	*MemoryFS
	dispatches int
}

func (c *dispatchCountingFS) UpdateFileBounded(ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error {
	c.dispatches++
	return c.MemoryFS.UpdateFileBounded(ctx, name, limits, allowCreate, transform)
}

// TestUpdatePathValidationOriginalComponents pins R103B-SEC-01: the
// ORIGINAL path is rejected at the runtime API (dispatcher and the
// MemoryFS implementation) before any filesystem or map access — NUL
// bytes, the 4096-byte cap, any ".." component OUTRIGHT (no lexical
// cancellation: symlink-then-.., missing-then-.., and non-dir-then-..
// never reach resolution), and trailing-slash / terminal "/."
// directory syntax for a file target.
func TestUpdatePathValidationOriginalComponents(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/d/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/d/file", []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/d/target", []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.Symlink("/d/sub", "/d/link"); err != nil {
		t.Fatal(err)
	}
	identity := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }

	rejects := map[string]string{
		"symlink-then-dotdot": "/d/link/../target",
		"missing-then-dotdot": "/missing/../target",
		"non-dir-then-dotdot": "/d/file/../target",
		"leading-dotdot":      "../target",
		"trailing-dotdot":     "/d/target/..",
		"trailing-slash":      "/d/target/",
		"dot-suffix":          "/d/target/.",
		"bare-dot":            ".",
		"empty":               "",
		"nul-byte":            "/d/ta\x00rget",
		"cap-over-4096":       "/" + strings.Repeat("p", MaxUpdatePathBytes),
	}
	for name, path := range rejects {
		if err := UpdateFileBounded(mem, context.Background(), path, UpdateLimits{16, 16}, true, identity); !errors.Is(err, ErrInvalidUpdatePath) {
			t.Fatalf("%s dispatcher err = %v, want ErrInvalidUpdatePath", name, err)
		}
		// The MemoryFS method re-validates on its own (defense in
		// depth for direct method callers).
		if err := mem.UpdateFileBounded(context.Background(), path, UpdateLimits{16, 16}, true, identity); !errors.Is(err, ErrInvalidUpdatePath) {
			t.Fatalf("%s memory err = %v, want ErrInvalidUpdatePath", name, err)
		}
	}
	// None of the rejected vectors touched the tree.
	if data, _ := mem.ReadFile("/d/target"); string(data) != "stable" {
		t.Fatalf("rejected vectors mutated the target: %q", data)
	}

	// Zero-dispatch proof: the dispatcher rejects before the
	// filesystem is reached at all (the counting wrapper never sees
	// the invalid paths, but does see the at-cap path).
	counting := &dispatchCountingFS{MemoryFS: mem}
	for _, path := range rejects {
		if err := UpdateFileBounded(counting, context.Background(), path, UpdateLimits{16, 16}, true, identity); !errors.Is(err, ErrInvalidUpdatePath) {
			t.Fatalf("counting dispatcher err = %v", err)
		}
	}
	if counting.dispatches != 0 {
		t.Fatalf("invalid paths reached the filesystem (%d dispatches)", counting.dispatches)
	}
	// The 4096-byte boundary is exact: a path of exactly
	// MaxUpdatePathBytes passes validation (it then simply misses).
	atCap := "/" + strings.Repeat("p", MaxUpdatePathBytes-1)
	if len(atCap) != MaxUpdatePathBytes {
		t.Fatalf("at-cap path length = %d", len(atCap))
	}
	if err := UpdateFileBounded(counting, context.Background(), atCap, UpdateLimits{16, 16}, false, identity); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("at-cap err = %v, want fs.ErrNotExist (validation passed)", err)
	}
	if counting.dispatches != 1 {
		t.Fatalf("at-cap dispatches = %d, want 1", counting.dispatches)
	}
}

// TestMemoryUpdateCallbackErrorNeverInspected pins R103B-SEC-06 at the
// MemoryFS implementation with a MALICIOUS callback error: a transform
// error and a start/commit hook fault whose Error, Is, As, Unwrap,
// Formatter, and GoString methods all count invocations and panic are
// dropped without a single method invocation — the fixed cause-free
// sentinels answer alone, with fixed text under every format verb, no
// arbitrary sentinel fabrication, and no errors.As payload extraction.
func TestMemoryUpdateCallbackErrorNeverInspected(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/etc/hosts", []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	identity := func(existing []byte, exists bool) ([]byte, error) { return []byte("replaced"), nil }

	// (a) Hostile TRANSFORM error.
	calls := 0
	hostile := &hostileUpdateError{calls: &calls, payload: "memory-transform"}
	hostileTransform := func([]byte, bool) ([]byte, error) { return nil, hostile }
	err := mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, false, hostileTransform)
	assertOpaqueTransformSentinel(t, err, &calls, ErrUpdateTransform)
	if data, _ := mem.ReadFile("/etc/hosts"); string(data) != "stable" {
		t.Fatalf("hostile transform mutated target: %q", data)
	}

	// (b) A callback error that IS context.Canceled maps to the fixed
	// sentinel only: real cancellation is classified exclusively by the
	// runtime's independent ctx checks (pinned by
	// TestMemoryUpdateCancellationAfterTransform).
	ctxTransform := func([]byte, bool) ([]byte, error) { return nil, context.Canceled }
	err = mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, false, ctxTransform)
	if !errors.Is(err, ErrUpdateTransform) || errors.Is(err, context.Canceled) {
		t.Fatalf("callback context sentinel err = %v, want ErrUpdateTransform only", err)
	}

	// (c) Hostile START-hook fault.
	calls = 0
	mem.updateHook = func(stage string) error {
		if stage == "start" {
			return hostile
		}
		return nil
	}
	err = mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, false, identity)
	assertOpaqueTransformSentinel(t, err, &calls, ErrUpdateStageHook)
	if data, _ := mem.ReadFile("/etc/hosts"); string(data) != "stable" {
		t.Fatalf("hostile start fault mutated target: %q", data)
	}

	// (d) Hostile COMMIT-hook fault: the tree stays untouched.
	calls = 0
	mem.updateHook = func(stage string) error {
		if stage == "commit" {
			return hostile
		}
		return nil
	}
	err = mem.UpdateFileBounded(context.Background(), "/etc/hosts", UpdateLimits{64, 64}, false, identity)
	assertOpaqueTransformSentinel(t, err, &calls, ErrUpdateStageHook)
	if data, _ := mem.ReadFile("/etc/hosts"); string(data) != "stable" {
		t.Fatalf("hostile commit fault mutated target: %q", data)
	}
}

// TestMemoryUpdateCancellationAfterTransform pins R103B-GATE-02/
// R103B-SEC-03: when the context is canceled by the transform itself,
// the recheck AFTER the transform and commit hook — immediately
// before the node replacement — aborts with the target's contents AND
// metadata unchanged.
func TestMemoryUpdateCancellationAfterTransform(t *testing.T) {
	mem := NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/etc/hosts", []byte("stable"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := mem.Stat("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	beforeCtime := before.Sys().(memStat).Ctim

	canceled, cancel := context.WithCancel(context.Background())
	transform := func([]byte, bool) ([]byte, error) {
		cancel() // deterministic: the transform cancels the context
		return []byte("changed"), nil
	}
	if err := mem.UpdateFileBounded(canceled, "/etc/hosts", UpdateLimits{64, 64}, false, transform); !errors.Is(err, context.Canceled) {
		t.Fatalf("transform-cancels err = %v, want context.Canceled", err)
	}
	data, err := mem.ReadFile("/etc/hosts")
	if err != nil || string(data) != "stable" {
		t.Fatalf("contents after cancellation = %q (err %v), want unchanged", data, err)
	}
	after, err := mem.Stat("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("mode after cancellation = %v, want %v", after.Mode(), before.Mode())
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("modTime after cancellation = %v, want %v", after.ModTime(), before.ModTime())
	}
	if after.Sys().(memStat).Ctim != beforeCtime {
		t.Fatalf("ctime after cancellation = %v, want %v", after.Sys().(memStat).Ctim, beforeCtime)
	}
}
