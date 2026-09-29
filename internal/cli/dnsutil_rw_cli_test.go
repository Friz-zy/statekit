package cli

// dnsutil hosts_append / hosts_remove CLI tests (untagged: hosts
// mutation never dispatches dig, touches DNS or the network, and every
// file vector runs over runtime.MemoryFS — no host /etc/hosts write).
// Pins the exact pinned result strings on stdout, the JSON null
// transport shape of the Python None success, byte-exact file
// contents, and the value-free nonzero-exit error surface with no
// partial writes.

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execdnsutil "github.com/friz-zy/statekit/modules/exec/dnsutil"
)

func dnsutilRWApp(t *testing.T, hostsContent string) (*App, *runtime.MemoryFS) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/hosts", []byte(hostsContent), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     fs,
	}
	if err := execdnsutil.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil }), fs
}

func dnsutilRWFile(t *testing.T, fs *runtime.MemoryFS) string {
	t.Helper()
	data, err := fs.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDNSUtilCLIHostsAppend(t *testing.T) {
	app, fs := dnsutilRWApp(t, "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n")

	code, out, errS := captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--hostsfile", "/etc/hosts", "--ip-addr", "127.0.0.2",
		"--entries", "ad1.yuk.co", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("hosts_append code=%d out=%q err=%q", code, out, errS)
	}
	var message string
	if err := json.Unmarshal([]byte(out), &message); err != nil ||
		message != "The following line was added to /etc/hosts:\n127.0.0.2 ad1.yuk.co" {
		t.Fatalf("hosts_append out = %q (decoded %q, err %v)", out, message, err)
	}
	wantFile := "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n" +
		"\n127.0.0.2 ad1.yuk.co"
	if got := dnsutilRWFile(t, fs); got != wantFile {
		t.Fatalf("hosts_append file = %q, want %q", got, wantFile)
	}

	// No-op append of the now-present alias: the exact pinned string,
	// file byte-identical.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--hostsfile", "/etc/hosts", "--ip-addr", "127.0.0.2",
		"--entries", "ad1.yuk.co", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("hosts_append no-op code=%d err=%q", code, errS)
	}
	if err := json.Unmarshal([]byte(out), &message); err != nil ||
		message != "No additional hosts were added to /etc/hosts" {
		t.Fatalf("hosts_append no-op out = %q (decoded %q, err %v)", out, message, err)
	}
	if got := dnsutilRWFile(t, fs); got != wantFile {
		t.Fatalf("hosts_append no-op mutated the file: %q", got)
	}
}

func TestDNSUtilCLIHostsRemove(t *testing.T) {
	app, fs := dnsutilRWApp(t, "127.0.0.1 ad1 ad2 web\n# keep me\n\n9.9.9.9\n")

	// The Python None success travels as JSON null on a zero exit.
	code, out, errS := captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--hostsfile", "/etc/hosts", "--entries", "ad2,ad1,web", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("hosts_remove code=%d out=%q err=%q", code, out, errS)
	}
	if strings.TrimSpace(out) != "null" {
		t.Fatalf("hosts_remove out = %q, want null", out)
	}
	// Full normalization: the emptied line is deleted, the comment and
	// the blank line AFTER it survive in order, and the pre-existing
	// address-only line drops even though nothing matched it.
	wantFile := "# keep me\n\n"
	if got := dnsutilRWFile(t, fs); got != wantFile {
		t.Fatalf("hosts_remove file = %q, want %q", got, wantFile)
	}

	// A second removal of an absent alias is still a nil success.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--entries", "nomatch.example", "-o", "json")
	if code != ExitOK || errS != "" || strings.TrimSpace(out) != "null" {
		t.Fatalf("hosts_remove absent code=%d out=%q err=%q", code, out, errS)
	}
	if got := dnsutilRWFile(t, fs); got != wantFile {
		t.Fatalf("hosts_remove absent mutated the file: %q", got)
	}
}

func TestDNSUtilCLIHostsErrorsValueFreeNoPartialWrites(t *testing.T) {
	app, fs := dnsutilRWApp(t, "127.0.0.1 ad1\n")
	if err := fs.Symlink("/etc/hosts", "/etc/hosts-link"); err != nil {
		t.Fatal(err)
	}
	original := dnsutilRWFile(t, fs)

	// A symlinked destination answers the fixed value-free error on a
	// nonzero exit, with empty stdout, no path or content bytes on
	// stderr, and no write through the link.
	code, out, errS := captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--hostsfile", "/etc/hosts-link", "--ip-addr", "10.0.0.1",
		"--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("symlink append code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: hosts update failed") {
		t.Fatalf("symlink append err = %q", errS)
	}
	for _, leak := range []string{"/etc/hosts", "ad1", "10.0.0.1", "127.0.0.1"} {
		if strings.Contains(errS, leak) {
			t.Fatalf("append err leaks %q: %q", leak, errS)
		}
	}

	// hosts_remove on an explicitly missing path fails closed
	// value-free too (the default /etc/hosts exists in this fixture),
	// and the FILE-READ category precedes the entries diagnosis at the
	// CLI as well: a missing path with NO --entries flag (entries nil,
	// the pinned None.split position) answers the same plain update
	// class, never an argument class.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--hostsfile", "/no/such/hosts", "--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("missing remove code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: hosts update failed") {
		t.Fatalf("missing remove err = %q", errS)
	}
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--hostsfile", "/no/such/hosts", "-o", "json")
	if code == ExitOK || out != "" || errS != "statekit: dnsutil: hosts update failed\n" {
		t.Fatalf("missing remove + nil entries code=%d out=%q err=%q", code, out, errS)
	}

	// An existing file with NO --entries flag (entries nil) answers the
	// fixed missing-entry class AFTER the read — fixed value-free text,
	// no path bytes, no publish (the file stays byte-identical).
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--hostsfile", "/etc/hosts", "-o", "json")
	if code == ExitOK || out != "" || errS != "statekit: dnsutil: invalid argument\n" {
		t.Fatalf("existing remove + nil entries code=%d out=%q err=%q", code, out, errS)
	}
	if strings.Contains(errS, "/etc/hosts") {
		t.Fatalf("nil-entries remove err leaks the path: %q", errS)
	}

	// Invalid arguments (a linebreak inside entries) reject at argument
	// decode with the fixed value-free class.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--ip-addr", "10.0.0.1", "--entries", "a\nb", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("linebreak entries code=%d out=%q err=%q", code, out, errS)
	}

	// Traversal and directory-syntax hostsfile paths (R103B-SEC-01)
	// answer the fixed value-free error on a nonzero exit with no path
	// bytes on stderr — the capability rejects the ORIGINAL path
	// before any filesystem access.
	for _, hostsfile := range []string{"/etc/../hosts", "/etc/hosts/", "/etc/hosts/."} {
		code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
			"--hostsfile", hostsfile, "--ip-addr", "10.0.0.1",
			"--entries", "ad1", "-o", "json")
		if code == ExitOK || out != "" || errS == "" {
			t.Fatalf("traversal %q code=%d out=%q err=%q", hostsfile, code, out, errS)
		}
		if !strings.Contains(errS, "dnsutil: hosts update failed") {
			t.Fatalf("traversal %q err = %q", hostsfile, errS)
		}
		if strings.Contains(errS, hostsfile) || strings.Contains(errS, "/etc/hosts") {
			t.Fatalf("traversal %q err leaks the path: %q", hostsfile, errS)
		}
	}

	// Nothing above performed a partial write.
	if got := dnsutilRWFile(t, fs); got != original {
		t.Fatalf("file mutated by rejected CLI calls: %q", got)
	}
}

// dnsutilRWAppFS builds a CLI app over an arbitrary filesystem so
// capability-outcome fakes can drive the CLI surface.
func dnsutilRWAppFS(t *testing.T, fs runtime.FileSystem) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     fs,
	}
	if err := execdnsutil.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// hostsOutcomeCLIFS mirrors the module tests' capability-outcome fake:
// a committed-class outcome (staging residue, durability) runs the
// transform and publishes the replacement before answering the
// capability sentinel; every other outcome leaves the tree unchanged.
type hostsOutcomeCLIFS struct {
	*runtime.MemoryFS
	outcome error
}

func (f *hostsOutcomeCLIFS) UpdateFileBounded(ctx context.Context, name string, limits runtime.UpdateLimits, allowCreate bool, transform runtime.UpdateTransform) error {
	if errors.Is(f.outcome, runtime.ErrUpdateStagingResidue) || errors.Is(f.outcome, runtime.ErrUpdateCommittedUncertain) {
		existing, readErr := f.MemoryFS.ReadFile(name)
		exists := readErr == nil
		if !exists {
			if !allowCreate {
				return fs.ErrNotExist
			}
			existing = nil
		}
		replacement, err := transform(existing, exists)
		if err != nil {
			return err
		}
		if int64(len(replacement)) > limits.MaxWriteBytes {
			return runtime.ErrWriteLimit
		}
		if err := f.MemoryFS.WriteFile(name, replacement, 0o644); err != nil {
			return err
		}
	}
	return f.outcome
}

// TestDNSUtilCLIHostsOutcomePropagation pins R103B-REGATE-02/
// R103B-SEC-07 at the CLI surface: all FOUR capability outcomes —
// clean abort, cleanup-failed, staging-residue, and
// committed-uncertain — each surface as its OWN fixed value-free
// stderr line (exactly the exported module sentinel's fixed text
// behind the fixed "statekit: " stderr prefix) on a
// nonzero exit with empty stdout — mutually distinguishable, never
// each other's class, with no path/alias/content bytes — and with the
// committed-content contract intact (the residue case leaves the new
// bytes in the target; the abort cases leave it unchanged or absent).
func TestDNSUtilCLIHostsOutcomePropagation(t *testing.T) {
	newFS := func(content string, outcome error) (*hostsOutcomeCLIFS, *App) {
		mem := runtime.NewMemoryFS()
		if err := mem.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if content != "" {
			if err := mem.WriteFile("/etc/hosts", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		fake := &hostsOutcomeCLIFS{MemoryFS: mem, outcome: outcome}
		return fake, dnsutilRWAppFS(t, fake)
	}
	// The four fixed module classes (exact fixed texts, asserted as the
	// whole stderr line — value-free, no paths, aliases, or content).
	cleanupText := "statekit: " + execdnsutil.ErrHostsUpdateCleanupFailed.Error() + "\n"
	residueText := "statekit: " + execdnsutil.ErrHostsUpdateCommittedWithResidue.Error() + "\n"
	durabilityText := "statekit: " + execdnsutil.ErrHostsUpdateCommittedDurabilityUncertain.Error() + "\n"
	plainText := "statekit: " + execdnsutil.ErrHostsUpdateFailed.Error() + "\n"
	allTexts := []string{cleanupText, residueText, durabilityText, plainText}

	// Clean abort (a pre-publication foreign failure with successful
	// cleanup): the plain class, target byte-identical.
	fake, app := newFS("SECRET-CONTENT-cli0\n", syscall.EIO)
	code, out, errS := captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--ip-addr", "10.0.0.1", "--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS != plainText {
		t.Fatalf("clean-abort code=%d out=%q err=%q", code, out, errS)
	}
	for _, text := range []string{cleanupText, residueText, durabilityText} {
		if strings.Contains(errS, strings.TrimSpace(text)) {
			t.Fatalf("clean-abort err crosses classes: %q", errS)
		}
	}
	for _, leak := range []string{"/etc/hosts", "ad1", "10.0.0.1", "SECRET-CONTENT"} {
		if strings.Contains(errS, leak) {
			t.Fatalf("clean-abort err leaks %q: %q", leak, errS)
		}
	}
	if got := dnsutilRWFile(t, fake.MemoryFS); got != "SECRET-CONTENT-cli0\n" {
		t.Fatalf("clean-abort mutated the file: %q", got)
	}

	// Cleanup-failed: distinct class, target byte-identical.
	fake, app = newFS("SECRET-CONTENT-cli1\n", runtime.ErrUpdateCleanupFailed)
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--ip-addr", "10.0.0.1", "--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS != cleanupText {
		t.Fatalf("cleanup-failed code=%d out=%q err=%q", code, out, errS)
	}
	for _, text := range []string{residueText, durabilityText, plainText} {
		if strings.Contains(errS, strings.TrimSpace(text)) {
			t.Fatalf("cleanup-failed err crosses classes: %q", errS)
		}
	}
	for _, leak := range []string{"/etc/hosts", "ad1", "10.0.0.1", "SECRET-CONTENT"} {
		if strings.Contains(errS, leak) {
			t.Fatalf("cleanup-failed err leaks %q: %q", leak, errS)
		}
	}
	if got := dnsutilRWFile(t, fake.MemoryFS); got != "SECRET-CONTENT-cli1\n" {
		t.Fatalf("cleanup-failed mutated the file: %q", got)
	}

	// Staging residue: distinct committed class (never "rollback"),
	// new bytes live in the target.
	fake, app = newFS("", runtime.ErrUpdateStagingResidue)
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--ip-addr", "10.0.0.1", "--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS != residueText {
		t.Fatalf("residue code=%d out=%q err=%q", code, out, errS)
	}
	for _, text := range []string{cleanupText, durabilityText, plainText} {
		if strings.Contains(errS, strings.TrimSpace(text)) {
			t.Fatalf("residue err crosses classes: %q", errS)
		}
	}
	if strings.Contains(errS, "rollback") {
		t.Fatalf("residue err described as a rollback: %q", errS)
	}
	for _, leak := range []string{"/etc/hosts", "ad1", "10.0.0.1"} {
		if strings.Contains(errS, leak) {
			t.Fatalf("residue err leaks %q: %q", leak, errS)
		}
	}
	if got := dnsutilRWFile(t, fake.MemoryFS); got != "\n10.0.0.1 ad1" {
		t.Fatalf("residue outcome must leave the new bytes live, file = %q", got)
	}

	// Committed-but-durability-uncertain: the fourth distinct class
	// with the content live.
	fake, app = newFS("1.2.3.4 a\n", runtime.ErrUpdateCommittedUncertain)
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_append",
		"--ip-addr", "10.0.0.1", "--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS != durabilityText {
		t.Fatalf("durability code=%d out=%q err=%q", code, out, errS)
	}
	for _, text := range []string{cleanupText, residueText, plainText} {
		if strings.Contains(errS, strings.TrimSpace(text)) {
			t.Fatalf("durability err crosses classes: %q", errS)
		}
	}
	for _, leak := range []string{"/etc/hosts", "ad1", "10.0.0.1"} {
		if strings.Contains(errS, leak) {
			t.Fatalf("durability err leaks %q: %q", leak, errS)
		}
	}
	if got := dnsutilRWFile(t, fake.MemoryFS); got != "1.2.3.4 a\n\n10.0.0.1 ad1" {
		t.Fatalf("durability outcome must leave the content live, file = %q", got)
	}

	// Generic foreign failure on an absent target: the plain class,
	// target absent, no committed/cleanup class text anywhere.
	fake, app = newFS("", syscall.EIO)
	code, out, errS = captureCode(t, app, "exec", "dnsutil.hosts_remove",
		"--entries", "ad1", "-o", "json")
	if code == ExitOK || out != "" || errS != plainText {
		t.Fatalf("generic code=%d out=%q err=%q", code, out, errS)
	}
	for _, text := range []string{cleanupText, residueText, durabilityText} {
		if strings.Contains(errS, strings.TrimSpace(text)) {
			t.Fatalf("generic err crosses into a committed/cleanup class: %q", errS)
		}
	}
	if strings.Contains(strings.Join(allTexts, "\x00"), "SECRET") {
		t.Fatal("sentinel texts must be value-free")
	}
	if _, statErr := fake.Stat("/etc/hosts"); statErr == nil {
		t.Fatal("generic abort must leave the target absent")
	}
}
