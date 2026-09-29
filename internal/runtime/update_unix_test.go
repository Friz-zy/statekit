//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Every fixture lives inside t.TempDir() — hermetic, no host /etc/hosts
// or zone file is touched, and no test leaves the directory.

func updateWrite(t *testing.T, path, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func updateRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func updateEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestOSUpdateExistingReplacesAtomicallyAndPreservesMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "orig", 0o640)
	before := updateEntryNames(t, dir)

	identity := func(existing []byte, exists bool) ([]byte, error) {
		if !exists || string(existing) != "orig" {
			t.Fatalf("transform saw %q exists=%v", existing, exists)
		}
		return []byte("replacement"), nil
	}
	var fsys OSFileSystem
	if err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{1024, 1024}, false, identity); err != nil {
		t.Fatal(err)
	}
	if got := updateRead(t, target); got != "replacement" {
		t.Fatalf("content = %q", got)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v (err %v), want preserved 0640", info.Mode(), err)
	}
	if after := updateEntryNames(t, dir); len(after) != len(before) {
		t.Fatalf("staging leftovers: %v (before %v)", after, before)
	}
}

func TestOSUpdateCreatesAbsentTarget0644(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new-hosts")
	absent := false
	transform := func(existing []byte, exists bool) ([]byte, error) {
		absent = !exists
		if existing != nil {
			t.Fatalf("absent target passed %q", existing)
		}
		return []byte("\n127.0.0.1 fresh"), nil
	}
	var fsys OSFileSystem
	err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{1024, 1024}, true, transform)
	// Platforms without the atomic no-replace primitive (solaris) FAIL
	// CLOSED for an initially-absent target before anything is staged:
	// a native solaris run validates that contract here instead of the
	// creation outcome, which is unreachable (and must stay
	// unreached) there.
	if !updateNoReplaceSupported {
		if !errors.Is(err, ErrUpdateCreateUnsupported) {
			t.Fatalf("no-replace-unsupported create err = %v, want ErrUpdateCreateUnsupported", err)
		}
		if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("fail-closed create left the target behind: %v", statErr)
		}
		if names := updateEntryNames(t, dir); len(names) != 0 {
			t.Fatalf("fail-closed create left staging files: %v", names)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !absent {
		t.Fatal("create path must report exists=false")
	}
	if got := updateRead(t, target); got != "\n127.0.0.1 fresh" {
		t.Fatalf("created content = %q", got)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("created mode = %v (err %v), want 0644", info.Mode(), err)
	}
	if names := updateEntryNames(t, dir); len(names) != 1 {
		t.Fatalf("staging leftovers after create: %v", names)
	}
}

func TestOSUpdateReadAndWriteBounds(t *testing.T) {
	dir := t.TempDir()
	var fsys OSFileSystem
	identity := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }
	grow := func([]byte, bool) ([]byte, error) { return []byte(strings.Repeat("y", 17)), nil }

	// Existing content at and over the read ceiling.
	at := filepath.Join(dir, "at")
	updateWrite(t, at, strings.Repeat("x", 16), 0o644)
	if err := fsys.UpdateFileBounded(context.Background(), at, UpdateLimits{16, 16}, false, identity); err != nil {
		t.Fatalf("at-bound read err = %v", err)
	}
	over := filepath.Join(dir, "over")
	updateWrite(t, over, strings.Repeat("x", 17), 0o644)
	if err := fsys.UpdateFileBounded(context.Background(), over, UpdateLimits{16, 16}, false, identity); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("over-bound read err = %v, want ErrReadLimit", err)
	}
	if got := updateRead(t, over); got != strings.Repeat("x", 17) {
		t.Fatalf("over-bound read mutated target: %q", got)
	}

	// Replacement at and over the write ceiling.
	ok := filepath.Join(dir, "ok")
	updateWrite(t, ok, "0123456789abcdef", 0o644)
	if err := fsys.UpdateFileBounded(context.Background(), ok, UpdateLimits{16, 16}, false, grow); !errors.Is(err, ErrWriteLimit) {
		t.Fatalf("over-bound write err = %v, want ErrWriteLimit", err)
	}
	if got := updateRead(t, ok); got != "0123456789abcdef" {
		t.Fatalf("over-bound write mutated target: %q", got)
	}
	exact := func([]byte, bool) ([]byte, error) { return []byte(strings.Repeat("y", 16)), nil }
	if err := fsys.UpdateFileBounded(context.Background(), ok, UpdateLimits{16, 16}, false, exact); err != nil {
		t.Fatalf("at-bound write err = %v", err)
	}
}

func TestOSUpdateRejectsSymlinksDirectoriesAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	updateWrite(t, real, "data", 0o644)
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "escape")
	updateWrite(t, outsideFile, "outside", 0o644)
	inside := filepath.Join(dir, "inside")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	updateWrite(t, filepath.Join(inside, "f"), "inner", 0o644)
	if err := os.Symlink(outside, filepath.Join(dir, "redirect")); err != nil {
		t.Fatal(err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "final-link")); err != nil {
		t.Fatal(err)
	}
	var fsys OSFileSystem
	identity := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }
	escape := filepath.Join(dir, "redirect", "escape")

	// The no-follow walk rejects every symlinked component (final and
	// intermediate — Linux answers ELOOP for the final open and ENOTDIR
	// for the O_DIRECTORY|O_NOFOLLOW parent open), EISDIR for a
	// directory target, and the sentinel ErrNonRegularFile for a FIFO
	// opened O_NONBLOCK.
	for name, want := range map[string][]error{
		filepath.Join(dir, "final-link"): {syscall.ELOOP},
		escape:                           {syscall.ELOOP, syscall.ENOTDIR},
		inside:                           {syscall.EISDIR},
		fifo:                             {ErrNonRegularFile},
	} {
		err := fsys.UpdateFileBounded(context.Background(), name, UpdateLimits{64, 64}, true, identity)
		matched := err != nil
		if matched {
			matched = false
			for _, candidate := range want {
				if errors.Is(err, candidate) {
					matched = true
					break
				}
			}
		}
		if !matched {
			t.Fatalf("%s err = %v, want one of %v", name, err, want)
		}
	}
	if got := updateRead(t, outsideFile); got != "outside" {
		t.Fatalf("parent-symlink vector escaped: %q", got)
	}
	// A dangling final symlink is rejected too — and allowCreate must
	// not create through it.
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := fsys.UpdateFileBounded(context.Background(), dangling, UpdateLimits{64, 64}, true, identity); err == nil {
		t.Fatal("dangling symlink accepted")
	}
	if _, statErr := os.Lstat(filepath.Join(dir, "nope")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("dangling vector created through the symlink: %v", statErr)
	}
	// Value-free failures: no path bytes in the errors.
	err := fsys.UpdateFileBounded(context.Background(), escape, UpdateLimits{64, 64}, true, identity)
	if err != nil && strings.Contains(err.Error(), dir) {
		t.Fatalf("error leaks the path: %v", err)
	}
}

func TestOSUpdateFaultsLeaveOriginalUnchanged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "original\ncontents", 0o644)
	var fsys OSFileSystem
	transform := func(existing []byte, exists bool) ([]byte, error) {
		return append(append([]byte{}, existing...), "\nappended"...), nil
	}

	cases := map[string]func(){
		"write":    func() { osUpdateSeams.write = func(int, []byte) (int, error) { return 0, syscall.EIO } },
		"fsync":    func() { osUpdateSeams.fsync = func(int) error { return syscall.EIO } },
		"close":    func() { osUpdateSeams.close = func(int) error { return syscall.EIO } },
		"rename":   func() { osUpdateSeams.renameat = func(int, string, int, string) error { return syscall.EIO } },
		"staging":  func() { osUpdateSeams.stage = func(string) error { return syscall.EIO } },
		"identity": func() { osUpdateSeams.stage = func(string) error { return ErrUpdateConflict } },
	}
	for name, inject := range cases {
		orig := osUpdateSeams
		inject()
		t.Cleanup(func() { osUpdateSeams = orig })
		err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{1024, 1024}, false, transform)
		osUpdateSeams = orig
		if err == nil {
			t.Fatalf("%s fault: update succeeded", name)
		}
		if got := updateRead(t, target); got != "original\ncontents" {
			t.Fatalf("%s fault mutated target: %q", name, got)
		}
		for _, entry := range updateEntryNames(t, dir) {
			if strings.HasPrefix(entry, ".statekit-update-") {
				t.Fatalf("%s fault left staging file %s", name, entry)
			}
		}
		if errors.Is(err, ErrUpdateCommittedUncertain) {
			t.Fatalf("%s fault misclassified as committed-uncertain", name)
		}
	}
}

func TestOSUpdateShortWriteHandling(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "old", 0o644)
	var fsys OSFileSystem

	orig := osUpdateSeams
	calls := 0
	osUpdateSeams.write = func(fd int, p []byte) (int, error) {
		calls++
		if calls == 1 && len(p) > 1 {
			half := len(p) / 2
			n, err := unix.Write(fd, p[:half])
			if err != nil {
				return n, err
			}
			if n != half {
				t.Fatalf("short-write seam wrote %d of %d", n, half)
			}
			return n, nil
		}
		return unix.Write(fd, p)
	}
	t.Cleanup(func() { osUpdateSeams = orig })

	payload := "replacement-line-0123456789"
	transform := func([]byte, bool) ([]byte, error) { return []byte(payload), nil }
	if err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{1024, 1024}, false, transform); err != nil {
		t.Fatal(err)
	}
	if got := updateRead(t, target); got != payload {
		t.Fatalf("short-write content = %q, want %q", got, payload)
	}
	if calls < 2 {
		t.Fatalf("short write not exercised (%d write calls)", calls)
	}
}

func TestOSUpdateStagingCollisionCleansUp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "keep", 0o644)
	colliding := filepath.Join(dir, ".statekit-update-collide")
	updateWrite(t, colliding, "occupied", 0o644)

	orig := osUpdateSeams
	osUpdateSeams.staging = func() string { return ".statekit-update-collide" }
	t.Cleanup(func() { osUpdateSeams = orig })

	var fsys OSFileSystem
	identity := func(existing []byte, exists bool) ([]byte, error) { return []byte("new"), nil }
	err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, identity)
	if err == nil || !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("staging collision err = %v, want EEXIST", err)
	}
	if got := updateRead(t, target); got != "keep" {
		t.Fatalf("collision mutated target: %q", got)
	}
	if got := updateRead(t, colliding); got != "occupied" {
		t.Fatalf("collision clobbered the occupied staging name: %q", got)
	}
	if names := updateEntryNames(t, dir); len(names) != 2 {
		t.Fatalf("collision left files behind: %v", names)
	}
}

func TestOSUpdateNoReplaceCollisionAndIdentitySwap(t *testing.T) {
	dir := t.TempDir()
	var fsys OSFileSystem
	appender := func(existing []byte, exists bool) ([]byte, error) { return []byte("mine"), nil }

	// Initially-absent target occupied before publication: the racing
	// creator's file must survive untouched. On platforms without the
	// atomic no-replace primitive (solaris) the transaction fails
	// closed BEFORE anything is staged — the publish hook never fires,
	// no racer is written, and no staging file can exist — so a native
	// solaris run validates the fail-closed outcome here instead.
	raced := filepath.Join(dir, "raced")
	orig := osUpdateSeams
	osUpdateSeams.stage = func(stage string) error {
		if stage == "publish" {
			updateWrite(t, raced, "racer", 0o644)
		}
		return nil
	}
	err := fsys.UpdateFileBounded(context.Background(), raced, UpdateLimits{64, 64}, true, appender)
	osUpdateSeams = orig
	if !updateNoReplaceSupported {
		if !errors.Is(err, ErrUpdateCreateUnsupported) {
			t.Fatalf("no-replace-unsupported collision err = %v, want ErrUpdateCreateUnsupported", err)
		}
		if names := updateEntryNames(t, dir); len(names) != 0 {
			t.Fatalf("fail-closed collision left files behind: %v", names)
		}
	} else {
		if !errors.Is(err, ErrUpdateConflict) {
			t.Fatalf("no-replace collision err = %v, want ErrUpdateConflict", err)
		}
		if got := updateRead(t, raced); got != "racer" {
			t.Fatalf("racing creator clobbered: %q", got)
		}
		for _, entry := range updateEntryNames(t, dir) {
			if strings.HasPrefix(entry, ".statekit-update-") {
				t.Fatalf("conflict left staging file %s", entry)
			}
		}
	}

	// Existing target swapped between open and revalidation: the
	// replacement inode must win, the update aborts.
	swapped := filepath.Join(dir, "swapped")
	updateWrite(t, swapped, "first", 0o644)
	osUpdateSeams = orig
	osUpdateSeams.stage = func(stage string) error {
		if stage == "revalidate" {
			updateWrite(t, filepath.Join(dir, "incoming"), "second", 0o644)
			if err := os.Rename(filepath.Join(dir, "incoming"), swapped); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	t.Cleanup(func() { osUpdateSeams = orig })
	err = fsys.UpdateFileBounded(context.Background(), swapped, UpdateLimits{64, 64}, false, appender)
	osUpdateSeams = orig
	if !errors.Is(err, ErrUpdateConflict) {
		t.Fatalf("identity swap err = %v, want ErrUpdateConflict", err)
	}
	if got := updateRead(t, swapped); got != "second" {
		t.Fatalf("swapped inode clobbered: %q", got)
	}
}

func TestOSUpdateDirFsyncFailureIsCommittedUncertain(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "before", 0o644)

	orig := osUpdateSeams
	osUpdateSeams.dirfsync = func(int) error { return syscall.EIO }
	t.Cleanup(func() { osUpdateSeams = orig })

	var fsys OSFileSystem
	transform := func([]byte, bool) ([]byte, error) { return []byte("after"), nil }
	err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, transform)
	if !errors.Is(err, ErrUpdateCommittedUncertain) {
		t.Fatalf("dir-fsync failure err = %v, want ErrUpdateCommittedUncertain", err)
	}
	if got := updateRead(t, target); got != "after" {
		t.Fatalf("committed-uncertain content = %q, want the published content", got)
	}
}

func TestOSUpdateCancellationBeforePublication(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "stable", 0o644)

	canceled, cancel := context.WithCancel(context.Background())
	var fsys OSFileSystem
	transform := func([]byte, bool) ([]byte, error) {
		cancel() // cancel mid-transaction, after the transform started
		return []byte("changed"), nil
	}
	err := fsys.UpdateFileBounded(canceled, target, UpdateLimits{64, 64}, false, transform)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if got := updateRead(t, target); got != "stable" {
		t.Fatalf("cancellation mutated target: %q", got)
	}
	for _, entry := range updateEntryNames(t, dir) {
		if strings.HasPrefix(entry, ".statekit-update-") {
			t.Fatalf("cancellation left staging file %s", entry)
		}
	}
}

// TestOSUpdatePathValidationRejectsTraversal pins R103B-SEC-01 at the
// OS implementation: the ORIGINAL path is rejected before any
// filesystem access — ".." components outright (symlink-then-..,
// missing-then-.., and non-dir-then-.. never reach resolution because
// there is no lexical cancellation), trailing-slash and "/." directory
// syntax, NUL bytes, and the 4096-byte cap — with the target left
// untouched.
func TestOSUpdatePathValidationRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "escape")
	updateWrite(t, outsideFile, "outside", 0o644)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	updateWrite(t, filepath.Join(dir, "sub", "target"), "stable", 0o644)
	updateWrite(t, filepath.Join(dir, "file"), "plain", 0o644)
	if err := os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	var fsys OSFileSystem
	identity := func(existing []byte, exists bool) ([]byte, error) { return existing, nil }

	// The paths are built by concatenation, NOT filepath.Join: Join
	// cleans ".." away lexically, and the whole point of these vectors
	// is that the ORIGINAL components must be rejected before any
	// cleaning or resolution happens.
	for name, path := range map[string]string{
		"symlink-then-dotdot": dir + "/link/../sub/target",
		"missing-then-dotdot": dir + "/missing/../sub/target",
		"non-dir-then-dotdot": dir + "/file/../sub/target",
		"trailing-slash":      dir + "/sub/target/",
		"dot-suffix":          dir + "/sub/target/.",
		"nul-byte":            dir + "/sub\x00/target",
		"cap-over-4096":       strings.Repeat("p", MaxUpdatePathBytes+1),
	} {
		if err := fsys.UpdateFileBounded(context.Background(), path, UpdateLimits{64, 64}, true, identity); !errors.Is(err, ErrInvalidUpdatePath) {
			t.Fatalf("%s err = %v, want ErrInvalidUpdatePath", name, err)
		}
	}
	if got := updateRead(t, filepath.Join(dir, "sub", "target")); got != "stable" {
		t.Fatalf("rejected vectors mutated the target: %q", got)
	}
	if got := updateRead(t, outsideFile); got != "outside" {
		t.Fatalf("rejected vectors escaped through the symlink: %q", got)
	}
	// The dispatcher rejects the same shapes before any capability
	// dispatch (a counting filesystem proves zero updates).
	counting := &osDispatchCountingFS{OSFileSystem: fsys}
	for _, path := range []string{
		dir + "/link/../sub/target",
		dir + "/sub/target/",
	} {
		if err := UpdateFileBounded(counting, context.Background(), path, UpdateLimits{64, 64}, true, identity); !errors.Is(err, ErrInvalidUpdatePath) {
			t.Fatalf("dispatcher err = %v, want ErrInvalidUpdatePath", err)
		}
	}
	if counting.dispatches != 0 {
		t.Fatalf("invalid paths reached the OS filesystem (%d dispatches)", counting.dispatches)
	}
}

// osDispatchCountingFS counts dispatches at the OS implementation.
type osDispatchCountingFS struct {
	OSFileSystem
	dispatches int
}

func (c *osDispatchCountingFS) UpdateFileBounded(ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error {
	c.dispatches++
	return c.OSFileSystem.UpdateFileBounded(ctx, name, limits, allowCreate, transform)
}

// TestOSUpdateTransformErrorBoundary pins R103B-REGATE-02/R103B-SEC-06
// at the OS implementation: a transform error is NEVER inspected — the
// fixed CAUSE-FREE ErrUpdateTransform sentinel is the entire answer
// (constant Error text, no Unwrap, no custom Is — errors.Is matches
// only the fixed sentinel, a callback-fabricated context sentinel or
// module identity never classifies, errors.As cannot extract the
// payload) — and a MALICIOUS callback error whose Error/Is/As/Unwrap
// count invocations and panic is dropped without a single method call;
// the target is untouched.
func TestOSUpdateTransformErrorBoundary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	updateWrite(t, target, "stable", 0o644)
	var fsys OSFileSystem
	marker := errors.New("SECRET-MARKER-os-transform")
	fail := func([]byte, bool) ([]byte, error) { return nil, marker }
	err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, fail)
	if !errors.Is(err, ErrUpdateTransform) {
		t.Fatalf("transform err = %v, want ErrUpdateTransform", err)
	}
	if errors.Is(err, marker) {
		t.Fatalf("transform err = %v, must not classify the callback identity", err)
	}
	if err.Error() != ErrUpdateTransform.Error() || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("transform text = %q, want the fixed sentinel text only", err)
	}
	// The original error chain is inaccessible: no Unwrap, and a
	// different instance with the same text is not classified.
	if errors.Unwrap(err) != nil {
		t.Fatalf("transform sentinel must not expose the cause through Unwrap: %v", errors.Unwrap(err))
	}
	lookalike := errors.New("SECRET-MARKER-os-transform")
	if errors.Is(err, lookalike) {
		t.Fatal("transform sentinel classified a text-identical but distinct error")
	}

	// A callback error carrying a VALUE (a custom type with data) is
	// unreachable through errors.As: the sentinel exposes no chain.
	cause := &secretFault{payload: "value-os-transform"}
	failing := func([]byte, bool) ([]byte, error) { return nil, cause }
	err = fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, failing)
	var extracted *secretFault
	if errors.As(err, &extracted) {
		t.Fatalf("errors.As extracted the callback value: %#v", extracted)
	}
	if err.Error() != ErrUpdateTransform.Error() || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("value-carrying transform text = %q, want the fixed sentinel text only", err)
	}

	// A callback error whose chain embeds a context sentinel is NOT
	// classified as cancellation: any callback error — including
	// context.Canceled itself — maps to the fixed sentinel only. Real
	// cancellation is detected exclusively by the runtime's independent
	// ctx checks (pinned by TestOSUpdateCancellationBeforePublication).
	wrappedCtx := func([]byte, bool) ([]byte, error) {
		return nil, fmt.Errorf("SECRET-MARKER-ctx: %w", context.DeadlineExceeded)
	}
	err = fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, wrappedCtx)
	if !errors.Is(err, ErrUpdateTransform) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("callback context sentinel err = %v, want ErrUpdateTransform only", err)
	}
	if err.Error() != ErrUpdateTransform.Error() || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("callback context sentinel text = %q, want the fixed sentinel text only", err)
	}

	// The MALICIOUS callback error: every method counts invocations and
	// panics; a conforming boundary never touches it.
	calls := 0
	hostile := &hostileUpdateError{calls: &calls, payload: "os-transform"}
	hostileTransform := func([]byte, bool) ([]byte, error) { return nil, hostile }
	err = fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, hostileTransform)
	assertOpaqueTransformSentinel(t, err, &calls, ErrUpdateTransform)
	if got := updateRead(t, target); got != "stable" {
		t.Fatalf("hostile transform mutated target: %q", got)
	}
}

// TestOSUpdateStageHookErrorBoundary pins R103B-REGATE-01/R103B-SEC-06
// at the OS implementation: EVERY non-nil osUpdateSeams stage-hook
// error (staging, revalidate, publish) is DROPPED at the capability
// boundary without invoking a single fault method and answered by the
// fixed value-free ErrUpdateStageHook
// sentinel — no fault-seam string (and no secret a fault might embed)
// escapes through Error, Unwrap, errors.As, formatting, or an
// errors.Is identity — the target stays byte-identical, and no staging
// residue is left. The publish-stage fault is a PRE-publication abort:
// it is never misclassified as the post-publication residue or
// committed-uncertain classes, and with a failing staging cleanup it
// maps through the existing checked-cleanup contract
// (ErrUpdateCleanupFailed, target still unchanged).
func TestOSUpdateStageHookErrorBoundary(t *testing.T) {
	for _, stage := range []string{"staging", "revalidate", "publish"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "hosts")
			updateWrite(t, target, "original", 0o644)
			orig := osUpdateSeams
			marker := errors.New("SECRET-MARKER-stage-hook-" + stage)
			osUpdateSeams.stage = func(s string) error {
				if s == stage {
					return marker
				}
				return nil
			}
			t.Cleanup(func() { osUpdateSeams = orig })
			var fsys OSFileSystem
			replace := func([]byte, bool) ([]byte, error) { return []byte("replacement"), nil }
			err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, replace)
			// The fixed stage-hook sentinel answers: fixed text, the
			// one safe errors.Is identity, and nothing else — the
			// injected marker is unreachable through Error, Unwrap,
			// errors.As, formatting, and classification.
			if !errors.Is(err, ErrUpdateStageHook) {
				t.Fatalf("%s hook err = %v, want ErrUpdateStageHook", stage, err)
			}
			if err.Error() != ErrUpdateStageHook.Error() {
				t.Fatalf("%s hook text = %q, want the fixed sentinel text only", stage, err)
			}
			if errors.Is(err, marker) || errors.Is(err, ErrUpdateTransform) {
				t.Fatalf("%s hook err = %v, must not classify the injected fault identity", stage, err)
			}
			if errors.Unwrap(err) != nil {
				t.Fatalf("%s hook err exposes a chain through Unwrap: %v", stage, errors.Unwrap(err))
			}
			if formatted := fmt.Sprintf("%v|%+v|%s", err, err, err); strings.Contains(formatted, "SECRET-MARKER") {
				t.Fatalf("%s hook fault text escapes formatting: %q", stage, formatted)
			}
			if errors.Is(err, ErrUpdateCleanupFailed) || errors.Is(err, ErrUpdateStagingResidue) ||
				errors.Is(err, ErrUpdateCommittedUncertain) {
				t.Fatalf("%s hook err = %v, must stay a plain stage-hook abort", stage, err)
			}
			if got := updateRead(t, target); got != "original" {
				t.Fatalf("%s hook mutated target: %q", stage, got)
			}
			for _, entry := range updateEntryNames(t, dir) {
				if strings.HasPrefix(entry, ".statekit-update-") {
					t.Fatalf("%s hook left staging file %s", stage, entry)
				}
			}

			// The MALICIOUS stage-hook fault: every method counts
			// invocations and panics; the boundary never touches it.
			calls := 0
			hostile := &hostileUpdateError{calls: &calls, payload: "os-stage-" + stage}
			osUpdateSeams.stage = func(s string) error {
				if s == stage {
					return hostile
				}
				return nil
			}
			err = fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, replace)
			assertOpaqueTransformSentinel(t, err, &calls, ErrUpdateStageHook)
			if got := updateRead(t, target); got != "original" {
				t.Fatalf("%s hostile fault mutated target: %q", stage, got)
			}

			// The publish-stage fault with a FAILING staging cleanup
			// maps through the existing checked-cleanup contract: the
			// distinct ErrUpdateCleanupFailed sentinel replaces the
			// fault (the original failure class is deliberately not
			// reported) and the target is still unchanged.
			if stage != "publish" {
				return
			}
			osUpdateSeams.unlinkat = func(int, string, int) error { return syscall.EIO }
			err = fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, replace)
			if !errors.Is(err, ErrUpdateCleanupFailed) {
				t.Fatalf("publish hook + cleanup failure err = %v, want ErrUpdateCleanupFailed", err)
			}
			if errors.Is(err, ErrUpdateStageHook) || errors.Is(err, ErrUpdateStagingResidue) ||
				errors.Is(err, ErrUpdateCommittedUncertain) {
				t.Fatalf("publish hook + cleanup failure err = %v, wrong outcome class", err)
			}
			if got := updateRead(t, target); got != "original" {
				t.Fatalf("publish hook + cleanup failure mutated target: %q", got)
			}
		})
	}
}

// TestOSUpdateCleanupContract pins R103B-GATE-03/R103B-SEC-07: the
// staging Unlinkat result is checked and the three outcomes are
// distinct fixed sentinels.
func TestOSUpdateCleanupContract(t *testing.T) {
	transform := func([]byte, bool) ([]byte, error) { return []byte("replacement"), nil }

	// (a) Pre-publication failure with successful cleanup: unchanged
	// target, the original error class, no staging residue.
	func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "hosts")
		updateWrite(t, target, "original", 0o644)
		orig := osUpdateSeams
		osUpdateSeams.renameat = func(int, string, int, string) error { return syscall.EIO }
		t.Cleanup(func() { osUpdateSeams = orig })
		var fsys OSFileSystem
		err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, transform)
		if !errors.Is(err, syscall.EIO) {
			t.Fatalf("(a) err = %v, want the original EIO class", err)
		}
		if errors.Is(err, ErrUpdateCleanupFailed) || errors.Is(err, ErrUpdateStagingResidue) {
			t.Fatalf("(a) err = %v, must not be a cleanup/residue sentinel", err)
		}
		if got := updateRead(t, target); got != "original" {
			t.Fatalf("(a) target mutated: %q", got)
		}
		for _, entry := range updateEntryNames(t, dir) {
			if strings.HasPrefix(entry, ".statekit-update-") {
				t.Fatalf("(a) staging residue %s", entry)
			}
		}
	}(t)

	// (b) Pre-publication failure whose cleanup ALSO fails: unchanged
	// target, the distinct value-free ErrUpdateCleanupFailed sentinel.
	func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "hosts")
		updateWrite(t, target, "original", 0o644)
		orig := osUpdateSeams
		osUpdateSeams.staging = func() string { return ".statekit-update-fixed" }
		osUpdateSeams.renameat = func(int, string, int, string) error { return syscall.EIO }
		osUpdateSeams.unlinkat = func(int, string, int) error { return syscall.EIO }
		t.Cleanup(func() { osUpdateSeams = orig })
		var fsys OSFileSystem
		err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, false, transform)
		if !errors.Is(err, ErrUpdateCleanupFailed) {
			t.Fatalf("(b) err = %v, want ErrUpdateCleanupFailed", err)
		}
		if err.Error() != ErrUpdateCleanupFailed.Error() || strings.Contains(err.Error(), dir) {
			t.Fatalf("(b) err text = %q, want the fixed value-free sentinel", err)
		}
		if errors.Is(err, ErrUpdateStagingResidue) || errors.Is(err, ErrUpdateCommittedUncertain) {
			t.Fatalf("(b) err = %v, must not be residue/committed classes", err)
		}
		if got := updateRead(t, target); got != "original" {
			t.Fatalf("(b) target mutated: %q", got)
		}
	}(t)

	// (c) Post-publication staging-unlink failure on the no-replace
	// path: the content IS committed under the target, the distinct
	// ErrUpdateStagingResidue sentinel answers (never a rollback, and
	// not the committed-uncertain durability class), and the staging
	// name is the residue that remains. This outcome exists only on
	// platforms WITH the atomic no-replace primitive — on solaris the
	// transaction fails closed before anything is staged, so a native
	// run validates the fail-closed outcome instead.
	func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "fresh")
		orig := osUpdateSeams
		osUpdateSeams.staging = func() string { return ".statekit-update-fixed" }
		osUpdateSeams.unlinkat = func(int, string, int) error { return syscall.EIO }
		t.Cleanup(func() { osUpdateSeams = orig })
		var fsys OSFileSystem
		err := fsys.UpdateFileBounded(context.Background(), target, UpdateLimits{64, 64}, true, transform)
		if !updateNoReplaceSupported {
			if !errors.Is(err, ErrUpdateCreateUnsupported) {
				t.Fatalf("(c) no-replace-unsupported err = %v, want ErrUpdateCreateUnsupported", err)
			}
			if names := updateEntryNames(t, dir); len(names) != 0 {
				t.Fatalf("(c) fail-closed outcome left files behind: %v", names)
			}
			return
		}
		if !errors.Is(err, ErrUpdateStagingResidue) {
			t.Fatalf("(c) err = %v, want ErrUpdateStagingResidue", err)
		}
		if errors.Is(err, ErrUpdateCleanupFailed) || errors.Is(err, ErrUpdateCommittedUncertain) {
			t.Fatalf("(c) err = %v, must not be cleanup/durability classes", err)
		}
		if got := updateRead(t, target); got != "replacement" {
			t.Fatalf("(c) committed content = %q, want the published replacement", got)
		}
		if got := updateRead(t, filepath.Join(dir, ".statekit-update-fixed")); got != "replacement" {
			t.Fatalf("(c) staging residue missing or wrong: %q", got)
		}
	}(t)
}
