package dnsutil

// R10.3b hosts_append / hosts_remove unit tests (untagged: no dig
// binary, no DNS, no network, no host /etc/hosts write — every file
// vector runs over runtime.MemoryFS, and the OS-capability vectors
// live in internal/runtime). Every expected value reproduces the
// pinned saltstack/salt/modules/dnsutil.py source semantics exactly
// (including the list-mutation-during-iteration skipping quirk of
// hosts_append, the address==alias first-occurrence removal of
// hosts_remove, and the always-prefix-LF never-terminal-LF append
// line); vectors marked divergence pin the documented safe
// divergences of this port (fail-closed read errors, value-free
// argument validation, inherited parser ceilings, atomic publication).

import (
	"context"
	"errors"
	iofs "io/fs"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

func hostsRWMemory(t *testing.T, content string) (*runtime.MemoryFS, string) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/hosts", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return fs, "/etc/hosts"
}

func hostsFileContent(t *testing.T, fs *runtime.MemoryFS, path string) string {
	t.Helper()
	data, err := fs.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustCallAppend(t *testing.T, rt *runtime.Runtime, args *HostsAppendArgs) any {
	t.Helper()
	value, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append", args)
	if err != nil {
		t.Fatalf("hosts_append: %v", err)
	}
	return value
}

func mustCallRemove(t *testing.T, rt *runtime.Runtime, args *HostsRemoveArgs) any {
	t.Helper()
	value, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_remove", args)
	if err != nil {
		t.Fatalf("hosts_remove: %v", err)
	}
	return value
}

func hostsRWRuntime(fs runtime.FileSystem) *runtime.Runtime {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		panic(err)
	}
	return &runtime.Runtime{Exec: reg, FS: fs}
}

func str(v string) *string { return &v }

// ---------------------------------------------------------------------------
// hosts_append semantics

func TestHostsAppendPinnedSourceVectors(t *testing.T) {
	cases := []struct {
		name       string
		existing   string
		ip         *string
		entries    string
		wantResult string
		wantFile   string
	}{
		{
			name:       "new-ip-two-entries",
			existing:   "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n",
			ip:         str("127.0.0.2"),
			entries:    "ad1.yuk.co,ad2.yuk.co",
			wantResult: "The following line was added to /etc/hosts:\n127.0.0.2 ad1.yuk.co ad2.yuk.co",
			wantFile:   "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n\n127.0.0.2 ad1.yuk.co ad2.yuk.co",
		},
		{
			name:       "existing-ip-aliases-filtered",
			existing:   "127.0.0.1 ad1\n",
			ip:         str("127.0.0.1"),
			entries:    "ad1,ad2",
			wantResult: "The following line was added to /etc/hosts:\n127.0.0.1 ad2",
			wantFile:   "127.0.0.1 ad1\n\n127.0.0.1 ad2",
		},
		{
			name:       "all-aliases-present-no-op",
			existing:   "127.0.0.1 ad1\n",
			ip:         str("127.0.0.1"),
			entries:    "ad1",
			wantResult: "No additional hosts were added to /etc/hosts",
			wantFile:   "127.0.0.1 ad1\n",
		},
		{
			// Repeated IP lines accumulate aliases per IP in the
			// parse_hosts map, so an entry matching ANY line filters.
			name:       "repeated-ip-lines-accumulate",
			existing:   "1.2.3.4 a\n1.2.3.4 b\n",
			ip:         str("1.2.3.4"),
			entries:    "b",
			wantResult: "No additional hosts were added to /etc/hosts",
			wantFile:   "1.2.3.4 a\n1.2.3.4 b\n",
		},
		{
			// Pinned quirk: removing from host_list while iterating it
			// skips the element shifted into the current index. With
			// [a,a] and a present, one removal ends the loop and one a
			// SURVIVES.
			name:       "duplicate-adjacent-alias-iteration-skip",
			existing:   "1.2.3.4 a\n",
			ip:         str("1.2.3.4"),
			entries:    "a,a",
			wantResult: "The following line was added to /etc/hosts:\n1.2.3.4 a",
			wantFile:   "1.2.3.4 a\n\n1.2.3.4 a",
		},
		{
			// Same quirk with distinct entries: removing a at i=0
			// shifts b to index 0, the incremented i reads index 1 and
			// the shrunken list ends the loop — b is never examined.
			name:       "two-present-entries-second-skipped",
			existing:   "1.2.3.4 a\n1.2.3.4 b\n",
			ip:         str("1.2.3.4"),
			entries:    "a,b",
			wantResult: "The following line was added to /etc/hosts:\n1.2.3.4 b",
			wantFile:   "1.2.3.4 a\n1.2.3.4 b\n\n1.2.3.4 b",
		},
		{
			// No dedup of NEW aliases: a repeated fresh entry appends
			// twice.
			name:       "repeated-new-alias-no-dedup",
			existing:   "1.2.3.4 a\n",
			ip:         str("5.6.7.8"),
			entries:    "x,x",
			wantResult: "The following line was added to /etc/hosts:\n5.6.7.8 x x",
			wantFile:   "1.2.3.4 a\n\n5.6.7.8 x x",
		},
		{
			// entries="" splits to [""], which is never an existing
			// alias, so the pinned join renders the trailing space.
			name:       "empty-entries-empty-token",
			existing:   "1.2.3.4 a\n",
			ip:         str("5.6.7.8"),
			entries:    "",
			wantResult: "The following line was added to /etc/hosts:\n5.6.7.8 ",
			wantFile:   "1.2.3.4 a\n\n5.6.7.8 ",
		},
		{
			name:       "comma-only-entries-two-empty-tokens",
			existing:   "1.2.3.4 a\n",
			ip:         str("5.6.7.8"),
			entries:    ",",
			wantResult: "The following line was added to /etc/hosts:\n5.6.7.8  ",
			wantFile:   "1.2.3.4 a\n\n5.6.7.8  ",
		},
		{
			// An existing empty file still gets the leading LF, so the
			// result starts with a blank line.
			name:       "empty-file-blank-first-line",
			existing:   "",
			ip:         str("10.0.0.1"),
			entries:    "ad1",
			wantResult: "The following line was added to /etc/hosts:\n10.0.0.1 ad1",
			wantFile:   "\n10.0.0.1 ad1",
		},
		{
			// The pinned append always prefixes an LF and never writes
			// a terminal LF: a file without one gets a single
			// separator...
			name:       "no-terminal-lf-single-separator",
			existing:   "127.0.0.1 localhost",
			ip:         str("10.0.0.1"),
			entries:    "ad1",
			wantResult: "The following line was added to /etc/hosts:\n10.0.0.1 ad1",
			wantFile:   "127.0.0.1 localhost\n10.0.0.1 ad1",
		},
		{
			// ...while a file WITH one keeps it and gains a blank
			// separator line (the pinned quirk).
			name:       "terminal-lf-blank-separator-quirk",
			existing:   "127.0.0.1 localhost\n",
			ip:         str("10.0.0.1"),
			entries:    "ad1",
			wantResult: "The following line was added to /etc/hosts:\n10.0.0.1 ad1",
			wantFile:   "127.0.0.1 localhost\n\n10.0.0.1 ad1",
		},
		{
			// Python str.format renders a None ip_addr as the literal
			// "None"...
			name:       "nil-ip-renders-none",
			existing:   "1.2.3.4 a\n",
			ip:         nil,
			entries:    "ad1",
			wantResult: "The following line was added to /etc/hosts:\nNone ad1",
			wantFile:   "1.2.3.4 a\n\nNone ad1",
		},
		{
			// ...but the pinned membership check uses the None KEY, not
			// the string "None": a file line whose first token is the
			// literal "None" must NOT match a nil ip_addr (the alias is
			// appended, not filtered).
			name:       "nil-ip-never-matches-literal-none-key",
			existing:   "None ghost\n",
			ip:         nil,
			entries:    "ghost",
			wantResult: "The following line was added to /etc/hosts:\nNone ghost",
			wantFile:   "None ghost\n\nNone ghost",
		},
		{
			// An explicit "None" ip_addr DOES match the literal key and
			// filters its aliases.
			name:       "explicit-none-ip-matches-key",
			existing:   "None ghost\n",
			ip:         str("None"),
			entries:    "ghost",
			wantResult: "No additional hosts were added to /etc/hosts",
			wantFile:   "None ghost\n",
		},
		{
			// Comments and col-0 '#' IP keys behave exactly like the
			// R10.3a parser (an inline '#' becomes an alias token); the
			// iteration-skip quirk leaves the hostList's own '#' behind
			// after removing 'note' at index 0.
			name:       "pound-alias-membership",
			existing:   "1.2.3.4 a # note\n",
			ip:         str("1.2.3.4"),
			entries:    "note,#",
			wantResult: "The following line was added to /etc/hosts:\n1.2.3.4 #",
			wantFile:   "1.2.3.4 a # note\n\n1.2.3.4 #",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, path := hostsRWMemory(t, tc.existing)
			rt := hostsRWRuntime(fs)
			value := mustCallAppend(t, rt, &HostsAppendArgs{
				Hostsfile: &path, IpAddr: tc.ip, Entries: &tc.entries})
			if value != tc.wantResult {
				t.Fatalf("result = %q, want %q", value, tc.wantResult)
			}
			if got := hostsFileContent(t, fs, path); got != tc.wantFile {
				t.Fatalf("file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

func TestHostsAppendDefaultPathAndCreate(t *testing.T) {
	// Default hostsfile is exactly /etc/hosts.
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/hosts", []byte("127.0.0.1 localhost"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := hostsRWRuntime(fs)
	entries := "web"
	value := mustCallAppend(t, rt, &HostsAppendArgs{IpAddr: str("10.0.0.9"), Entries: &entries})
	if value != "The following line was added to /etc/hosts:\n10.0.0.9 web" {
		t.Fatalf("default-path result = %q", value)
	}
	if got := hostsFileContent(t, fs, "/etc/hosts"); got != "127.0.0.1 localhost\n10.0.0.9 web" {
		t.Fatalf("default-path file = %q", got)
	}

	// A missing file is created exactly like the pinned fopen(..., "a")
	// (the leading LF lands in the fresh file).
	fs2 := runtime.NewMemoryFS()
	if err := fs2.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	rt2 := hostsRWRuntime(fs2)
	value = mustCallAppend(t, rt2, &HostsAppendArgs{IpAddr: str("10.9.9.9"), Entries: &entries})
	if value != "The following line was added to /etc/hosts:\n10.9.9.9 web" {
		t.Fatalf("create result = %q", value)
	}
	if got := hostsFileContent(t, fs2, "/etc/hosts"); got != "\n10.9.9.9 web" {
		t.Fatalf("create file = %q", got)
	}
	info, err := fs2.Stat("/etc/hosts")
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("created mode = %v (err %v), want 0644", info.Mode(), err)
	}
}

func TestHostsAppendFailClosedDivergences(t *testing.T) {
	entries := "ad1"

	// Read failures fail closed (divergence: the pinned source writes
	// a fresh file after the parse_hosts error string).
	fs, _ := hostsRWMemory(t, "1.2.3.4 a\n")
	if err := fs.Symlink("/etc/hosts", "/etc/hosts-link"); err != nil {
		t.Fatal(err)
	}
	rt := hostsRWRuntime(fs)
	link := "/etc/hosts-link"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &link, IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("symlink destination err = %v, want ErrHostsUpdateFailed", err)
	}
	// Missing parent: fail closed, nothing created.
	missing := "/no/such/hosts"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &missing, IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("missing parent err = %v", err)
	}
	if _, statErr := fs.Stat("/no"); statErr == nil || !errors.Is(statErr, iofs.ErrNotExist) {
		t.Fatalf("missing-parent vector created directories: %v", statErr)
	}

	// Oversized existing file (1 MiB + 1) rejects value-free.
	big := make([]byte, maxSourceBytes+1)
	for i := range big {
		big[i] = '#'
	}
	if err := fs.WriteFile("/etc/big", big, 0o644); err != nil {
		t.Fatal(err)
	}
	bigPath := "/etc/big"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &bigPath, IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("oversized err = %v, want ErrHostsUpdateFailed", err)
	}

	// Inherited R10.3a parser ceilings (documented divergence): 4097
	// input records reject with the parser-limit class even though the
	// byte ceiling would admit the file.
	var rows strings.Builder
	for i := 0; i < maxInputRecords+1; i++ {
		rows.WriteString("10.0.0.1 h\n")
	}
	if err := fs.WriteFile("/etc/many", []byte(rows.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	many := "/etc/many"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &many, IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, errParseLimit) {
		t.Fatalf("inherited ceiling err = %v, want errParseLimit", err)
	}

	// A replacement over the 1 MiB write ceiling rejects value-free
	// with the file unchanged.
	exact := strings.Repeat("#", maxSourceBytes-1) + "\n"
	if err := fs.WriteFile("/etc/full", []byte(exact), 0o644); err != nil {
		t.Fatal(err)
	}
	full := "/etc/full"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &full, IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("write ceiling err = %v, want errInputTooLarge", err)
	}
	if got := hostsFileContent(t, fs, full); got != exact {
		t.Fatalf("write ceiling mutated file (%d bytes → %d)", len(exact), len(got))
	}

	// A durability-stage fault answers the distinct committed-but-
	// uncertain error while the content IS live.
	faulty := runtime.NewMemoryFS()
	if err := faulty.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := faulty.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	faulty.SetUpdateHook(func(stage string) error {
		if stage == "durability" {
			return errors.New("injected durability fault")
		}
		return nil
	})
	rtFaulty := hostsRWRuntime(faulty)
	if _, err := rtFaulty.Exec.Call(context.Background(), rtFaulty, "dnsutil.hosts_append",
		&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries}); !errors.Is(err, ErrHostsUpdateCommittedDurabilityUncertain) {
		t.Fatalf("durability err = %v, want ErrHostsUpdateCommittedDurabilityUncertain", err)
	}
	if got := hostsFileContent(t, faulty, "/etc/hosts"); got != "1.2.3.4 a\n\n10.0.0.1 ad1" {
		t.Fatalf("durability file = %q", got)
	}
}

func TestHostsAppendArgumentValidation(t *testing.T) {
	fs, path := hostsRWMemory(t, "1.2.3.4 a\n")
	rt := hostsRWRuntime(fs)

	// entries=None is the pinned AttributeError crash position.
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append", &HostsAppendArgs{}); !errors.Is(err, errArgumentInvalid) {
		t.Fatalf("nil entries err = %v", err)
	}
	for _, entries := range []string{"a\nb", "a\rb", "a\x00b", "a\u2028b", "a\u0085b"} {
		e := entries
		if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
			&HostsAppendArgs{Hostsfile: &path, IpAddr: str("10.0.0.1"), Entries: &e}); !errors.Is(err, errArgumentInvalid) {
			t.Fatalf("entries %q err = %v, want errArgumentInvalid", entries, err)
		}
	}
	badIP := "a\nb"
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &path, IpAddr: &badIP, Entries: str("a")}); !errors.Is(err, errArgumentInvalid) {
		t.Fatalf("linebreak ip err = %v", err)
	}
	longPath := "/" + strings.Repeat("p", maxPathBytes)
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &longPath, IpAddr: str("10.0.0.1"), Entries: str("a")}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("oversize path err = %v", err)
	}
	longEntries := strings.Repeat("a", maxEntriesBytes+1)
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &path, IpAddr: str("10.0.0.1"), Entries: &longEntries}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("oversize entries err = %v", err)
	}
	longIP := strings.Repeat("a", maxIPBytes+1)
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &path, IpAddr: &longIP, Entries: str("a")}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("oversize ip err = %v", err)
	}

	// Nothing above reached the filesystem: the file is untouched.
	if got := hostsFileContent(t, fs, path); got != "1.2.3.4 a\n" {
		t.Fatalf("validation mutated file: %q", got)
	}
}

// countingUpdateFS counts UpdateFileBounded dispatches to prove the
// path cap rejects before any filesystem access.
type countingUpdateFS struct {
	*runtime.MemoryFS
	updates int
}

func (c *countingUpdateFS) UpdateFileBounded(ctx context.Context, name string, limits runtime.UpdateLimits, allowCreate bool, transform runtime.UpdateTransform) error {
	c.updates++
	return c.MemoryFS.UpdateFileBounded(ctx, name, limits, allowCreate, transform)
}

func TestHostsAppendPathCapRejectsBeforeFS(t *testing.T) {
	mem := runtime.NewMemoryFS()
	counting := &countingUpdateFS{MemoryFS: mem}
	rt := hostsRWRuntime(counting)
	longPath := "/" + strings.Repeat("p", maxPathBytes+1)
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{Hostsfile: &longPath, IpAddr: str("10.0.0.1"), Entries: str("a")}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("path cap err = %v", err)
	}
	if counting.updates != 0 {
		t.Fatalf("path cap reached the filesystem (%d updates)", counting.updates)
	}
}

func TestHostsAppendCapabilityAbsent(t *testing.T) {
	// A filesystem without the bounded-update capability fails closed
	// with the fixed value-free error (no ReadFile/WriteFile
	// fallback), value-free at the module surface.
	legacy := struct{ runtime.FileSystem }{runtime.NewMemoryFS()}
	rt := hostsRWRuntime(legacy)
	entries := "ad1"
	_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
		&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
	if !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("capability-absent err = %v, want ErrHostsUpdateFailed", err)
	}
	if err != nil && (strings.Contains(err.Error(), "/etc/hosts") || strings.Contains(err.Error(), "ad1")) {
		t.Fatalf("capability-absent error leaks values: %v", err)
	}
	_, err = rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &entries})
	if !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("remove capability-absent err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// hosts_remove semantics

func TestHostsRemovePinnedSourceVectors(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		entries  string
		wantFile string
	}{
		{
			name:     "one-alias",
			existing: "127.0.0.1 ad1 ad2\n",
			entries:  "ad1",
			wantFile: "127.0.0.1 ad2\n",
		},
		{
			name:     "last-alias-deletes-line",
			existing: "127.0.0.1 ad1\n10.0.0.1 other\n",
			entries:  "ad1",
			wantFile: "10.0.0.1 other\n",
		},
		{
			// Absent alias: no match anywhere, but the rewrite still
			// normalizes — the pre-existing address-only line is
			// dropped, blank and whitespace-prefixed comment lines are
			// preserved verbatim, the whitespace-only line drops, and a
			// missing terminal LF is added.
			name:     "absent-alias-normalizes",
			existing: "10.0.0.1\n\n# comment\n  # indented comment\n \t \n1.2.3.4 x",
			entries:  "nomatch.example",
			wantFile: "\n# comment\n  # indented comment\n1.2.3.4 x\n",
		},
		{
			// A requested entry equal to the ADDRESS token never
			// matches: membership tests comps[1:] only, so the line is
			// kept unchanged.
			name:     "address-token-match-is-noop",
			existing: "1.2.3.4 web\n",
			entries:  "1.2.3.4",
			wantFile: "1.2.3.4 web\n",
		},
		{
			// The token-as-address-and-alias edge: comps.remove takes
			// the FIRST occurrence — the address — so the remaining
			// single alias token drops the whole line.
			name:     "address-equals-alias-first-occurrence",
			existing: "web web\n1.2.3.4 keep\n",
			entries:  "web",
			wantFile: "1.2.3.4 keep\n",
		},
		{
			// Each requested entry removes at most one occurrence:
			// "a" once leaves the second alias, "a,a" removes both.
			name:     "one-entry-one-occurrence",
			existing: "1.2.3.4 a a b\n",
			entries:  "a",
			wantFile: "1.2.3.4 a b\n",
		},
		{
			name:     "repeated-entry-removes-repeated-aliases",
			existing: "1.2.3.4 a a b\n",
			entries:  "a,a",
			wantFile: "1.2.3.4 b\n",
		},
		{
			// Multiple hosts across lines, comma-separated entries.
			name:     "multi-entry-multi-line",
			existing: "127.0.0.1 ad1.yuk.co ad2.yuk.co web\n::1 localhost\n",
			entries:  "ad2.yuk.co,web",
			wantFile: "127.0.0.1 ad1.yuk.co\n::1 localhost\n",
		},
		{
			// Empty entries split to [""] which never matches a token;
			// only the normalization applies.
			name:     "empty-entries-normalization-only",
			existing: "1.2.3.4 web\n9.9.9.9\n",
			entries:  "",
			wantFile: "1.2.3.4 web\n",
		},
		{
			// Python splitlines() boundaries: \r\n is one boundary and
			// \r alone is a boundary; every kept line is re-joined with
			// a single \n.
			name:     "python-line-boundaries",
			existing: "1.2.3.4 x\r\n1.2.3.4 y\r1.2.3.4 z",
			entries:  "nomatch",
			wantFile: "1.2.3.4 x\n1.2.3.4 y\n1.2.3.4 z\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, path := hostsRWMemory(t, tc.existing)
			rt := hostsRWRuntime(fs)
			value := mustCallRemove(t, rt, &HostsRemoveArgs{Hostsfile: &path, Entries: &tc.entries})
			if value != nil {
				t.Fatalf("result = %#v, want nil (Python None)", value)
			}
			if got := hostsFileContent(t, fs, path); got != tc.wantFile {
				t.Fatalf("file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

func TestHostsRemoveFailClosedDivergences(t *testing.T) {
	entries := "ad1"

	// Missing file: the pinned fopen(..., "r") raises IOError; this
	// port fails closed with the fixed value-free error.
	fs := runtime.NewMemoryFS()
	rt := hostsRWRuntime(fs)
	if _, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("missing file err = %v, want ErrHostsUpdateFailed", err)
	}

	// A symlinked destination is rejected without writing through it.
	fs2, _ := hostsRWMemory(t, "1.2.3.4 ad1\n")
	if err := fs2.Symlink("/etc/hosts", "/etc/hosts-link"); err != nil {
		t.Fatal(err)
	}
	rt2 := hostsRWRuntime(fs2)
	link := "/etc/hosts-link"
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Hostsfile: &link, Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("symlink err = %v, want ErrHostsUpdateFailed", err)
	}
	if got := hostsFileContent(t, fs2, "/etc/hosts"); got != "1.2.3.4 ad1\n" {
		t.Fatalf("symlink vector wrote through: %q", got)
	}

	// Oversized content (1 MiB + 1) rejects value-free, unchanged.
	big := make([]byte, maxSourceBytes+1)
	for i := range big {
		big[i] = '#'
	}
	if err := fs2.WriteFile("/etc/big", big, 0o644); err != nil {
		t.Fatal(err)
	}
	bigPath := "/etc/big"
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Hostsfile: &bigPath, Entries: &entries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("oversized err = %v", err)
	}

	// Argument classes after the read (pinned source order) and the
	// path class before the FS: with the file present the transform
	// runs, so nil entries (the pinned None.split position) and a
	// linebreak inside entries answer the fixed argument class, and
	// nothing is published (the file stays byte-identical).
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{}); !errors.Is(err, errArgumentInvalid) {
		t.Fatalf("nil entries err = %v", err)
	}
	badEntries := "a\nb"
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &badEntries}); !errors.Is(err, errArgumentInvalid) {
		t.Fatalf("linebreak entries err = %v", err)
	}
	if got := hostsFileContent(t, fs2, "/etc/hosts"); got != "1.2.3.4 ad1\n" {
		t.Fatalf("argument-class vectors mutated the file: %q", got)
	}
	longPath := "/" + strings.Repeat("p", maxPathBytes+1)
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Hostsfile: &longPath, Entries: &entries}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("oversize path err = %v", err)
	}
	longEntries := strings.Repeat("a", maxEntriesBytes+1)
	if _, err := rt2.Exec.Call(context.Background(), rt2, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &longEntries}); !errors.Is(err, errInputTooLarge) {
		t.Fatalf("oversize entries err = %v, want errInputTooLarge (after the read)", err)
	}
	if got := hostsFileContent(t, fs2, "/etc/hosts"); got != "1.2.3.4 ad1\n" {
		t.Fatalf("entries-ceiling vector mutated the file: %q", got)
	}
}

// TestHostsRemoveSourceOrder pins the pinned source ordering at the
// module surface: the bounded file read (fopen "r") precedes every
// entries diagnosis — including the entries=None AttributeError
// position — while the path safety/bounds check intentionally precedes
// the file open (it reads no file bytes). Missing file + nil entries
// answers the FILE-READ category first; an existing file + nil entries
// answers the fixed missing-entry error with NO publish; an empty
// string entries triggers the exact source rewrite behavior; and the
// capability's four outcomes stay distinctly mapped.
func TestHostsRemoveSourceOrder(t *testing.T) {
	// (a) Missing file + nil entries → file-read category FIRST (the
	// pinned IOError precedes None.split), never the argument class.
	missing := runtime.NewMemoryFS()
	rtMissing := hostsRWRuntime(missing)
	_, err := rtMissing.Exec.Call(context.Background(), rtMissing, "dnsutil.hosts_remove",
		&HostsRemoveArgs{})
	if !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("(a) missing file + nil entries err = %v, want ErrHostsUpdateFailed", err)
	}
	if err != nil && (strings.Contains(err.Error(), "invalid argument") || strings.Contains(err.Error(), "/etc/hosts")) {
		t.Fatalf("(a) error must stay the value-free file-read class: %v", err)
	}
	// Same precedence for a bad-entries argument: the read error wins.
	bad := "a\nb"
	if _, err := rtMissing.Exec.Call(context.Background(), rtMissing, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &bad}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("(a) missing file + linebreak entries err = %v, want ErrHostsUpdateFailed", err)
	}
	// An oversize entries argument cannot precede the file read either.
	longEntries := strings.Repeat("a", maxEntriesBytes+1)
	if _, err := rtMissing.Exec.Call(context.Background(), rtMissing, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: &longEntries}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("(a) missing file + oversize entries err = %v, want ErrHostsUpdateFailed", err)
	}

	// (b) Existing file + nil entries → the fixed missing-entry class
	// AFTER the read, with NO publish (file byte-identical).
	fs, _ := hostsRWMemory(t, "1.2.3.4 ad1\n")
	rt := hostsRWRuntime(fs)
	_, missingEntriesErr := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_remove",
		&HostsRemoveArgs{})
	if !errors.Is(missingEntriesErr, errArgumentInvalid) {
		t.Fatalf("(b) existing file + nil entries err = %v, want errArgumentInvalid", missingEntriesErr)
	}
	if missingEntriesErr.Error() != errArgumentInvalid.Error() {
		t.Fatalf("(b) missing-entry error text = %q, want the fixed value-free class", missingEntriesErr)
	}
	if got := hostsFileContent(t, fs, "/etc/hosts"); got != "1.2.3.4 ad1\n" {
		t.Fatalf("(b) missing-entry vector published: %q", got)
	}

	// (c) Empty string entries splits to [""] (Python ''.split(',')) and
	// keeps the pinned normal-rewrite semantics: no token matches, only
	// the normalization applies (address-only line dropped, terminal LF
	// normalized in), and the Python None success maps to Go nil.
	fsEmpty, pathEmpty := hostsRWMemory(t, "1.2.3.4 web\n9.9.9.9\n")
	rtEmpty := hostsRWRuntime(fsEmpty)
	value := mustCallRemove(t, rtEmpty, &HostsRemoveArgs{Hostsfile: &pathEmpty, Entries: str("")})
	if value != nil {
		t.Fatalf("(c) empty-entries result = %#v, want nil (Python None)", value)
	}
	if got := hostsFileContent(t, fsEmpty, pathEmpty); got != "1.2.3.4 web\n" {
		t.Fatalf("(c) empty-entries rewrite = %q, want the pinned normalization only", got)
	}

	// (d) The four capability outcomes stay distinctly mapped for
	// hosts_remove: clean abort, cleanup-failed, staging residue, and
	// committed-uncertain each keep their own fixed value-free class.
	fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateCleanupFailed}
	if err := fake.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fake.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtFake := hostsRWRuntime(fake)
	if _, err := rtFake.Exec.Call(context.Background(), rtFake, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: str("a")}); !errors.Is(err, ErrHostsUpdateCleanupFailed) {
		t.Fatalf("(d) cleanup-failed err = %v, want ErrHostsUpdateCleanupFailed", err)
	}
	if got := hostsFileContent(t, fake.MemoryFS, "/etc/hosts"); got != "1.2.3.4 a\n" {
		t.Fatalf("(d) cleanup-failed mutated the file: %q", got)
	}
	residue := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateStagingResidue}
	if err := residue.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := residue.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtResidue := hostsRWRuntime(residue)
	_, err = rtResidue.Exec.Call(context.Background(), rtResidue, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: str("a")})
	if !errors.Is(err, ErrHostsUpdateCommittedWithResidue) {
		t.Fatalf("(d) residue err = %v, want ErrHostsUpdateCommittedWithResidue", err)
	}
	if err != nil && (strings.Contains(err.Error(), "rollback") || strings.Contains(err.Error(), "1.2.3.4")) {
		t.Fatalf("(d) residue error must say committed, never rollback, and stay value-free: %v", err)
	}
	if got := hostsFileContent(t, residue.MemoryFS, "/etc/hosts"); got != "" {
		t.Fatalf("(d) residue outcome must leave the rewritten content live, file = %q", got)
	}
	uncertain := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateCommittedUncertain}
	if err := uncertain.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := uncertain.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtUncertain := hostsRWRuntime(uncertain)
	if _, err := rtUncertain.Exec.Call(context.Background(), rtUncertain, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: str("a")}); !errors.Is(err, ErrHostsUpdateCommittedDurabilityUncertain) {
		t.Fatalf("(d) durability err = %v, want ErrHostsUpdateCommittedDurabilityUncertain", err)
	}
	if got := hostsFileContent(t, uncertain.MemoryFS, "/etc/hosts"); got != "" {
		t.Fatalf("(d) durability outcome must leave the rewritten content live, file = %q", got)
	}
	// The clean abort (foreign pre-publication failure with successful
	// cleanup) stays the plain class with the file byte-identical.
	clean := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: syscall.EIO}
	if err := clean.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := clean.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtClean := hostsRWRuntime(clean)
	if _, err := rtClean.Exec.Call(context.Background(), rtClean, "dnsutil.hosts_remove",
		&HostsRemoveArgs{Entries: str("a")}); !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("(d) clean-abort err = %v, want ErrHostsUpdateFailed", err)
	}
	if got := hostsFileContent(t, clean.MemoryFS, "/etc/hosts"); got != "1.2.3.4 a\n" {
		t.Fatalf("(d) clean abort mutated the file: %q", got)
	}
}

func TestHostsRegisteredNamesAndValueFreeErrors(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dnsutil.hosts_append", "dnsutil.hosts_remove"} {
		if _, ok := reg.Get(name); !ok {
			t.Fatalf("missing %s", name)
		}
	}
	names := reg.Names()
	if !reflect.DeepEqual(names, []string{
		"dnsutil.A", "dnsutil.AAAA", "dnsutil.MX", "dnsutil.NS", "dnsutil.SPF",
		"dnsutil.check_ip", "dnsutil.hosts_append", "dnsutil.hosts_remove",
		"dnsutil.parse_hosts", "dnsutil.parse_zone",
	}) {
		t.Fatalf("registered names = %v", names)
	}

	// Every error surface of the mutation pair is value-free: no path,
	// argument, or content bytes.
	fs, path := hostsRWMemory(t, "SECRET-CONTENT-9f1e\n")
	rt := hostsRWRuntime(fs)
	symlinked := "/etc/hosts-link"
	if err := fs.Symlink(path, symlinked); err != nil {
		t.Fatal(err)
	}
	entries := "a\nb"
	for name, args := range map[string]any{
		"dnsutil.hosts_append": &HostsAppendArgs{Hostsfile: &symlinked, IpAddr: str("10.0.0.1"), Entries: &entries},
		"dnsutil.hosts_remove": &HostsRemoveArgs{Hostsfile: &symlinked, Entries: &entries},
	} {
		_, err := rt.Exec.Call(context.Background(), rt, name, args)
		if err == nil {
			t.Fatalf("%s succeeded on a symlink", name)
		}
		for _, leak := range []string{symlinked, "/etc/hosts", "SECRET-CONTENT", "a\\nb", "10.0.0.1"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("%s error leaks %q: %v", name, leak, err)
			}
		}
	}
}

// TestHostsUpdateErrorBoundaryAndTraversal pins R103B-SEC-06 and the
// R103B-SEC-01 traversal rejection at the MODULE surface: an injected
// transaction-fault marker and a dot-dot hostsfile path both answer
// the fixed value-free module errors with no marker, path, or content
// bytes escaping, and the file is untouched.
func TestHostsUpdateErrorBoundaryAndTraversal(t *testing.T) {
	// A commit-hook fault whose error carries a synthetic secret
	// marker: the capability boundary fixes the text and the module
	// boundary maps it to its own fixed error.
	faulty := runtime.NewMemoryFS()
	if err := faulty.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := faulty.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	faulty.SetUpdateHook(func(stage string) error {
		if stage == "commit" {
			return errors.New("SECRET-MARKER-module-fault")
		}
		return nil
	})
	rtFaulty := hostsRWRuntime(faulty)
	entries := "ad1"
	_, err := rtFaulty.Exec.Call(context.Background(), rtFaulty, "dnsutil.hosts_append",
		&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
	if !errors.Is(err, ErrHostsUpdateFailed) {
		t.Fatalf("commit-fault err = %v, want ErrHostsUpdateFailed", err)
	}
	if err != nil && (strings.Contains(err.Error(), "SECRET-MARKER") || strings.Contains(err.Error(), "/etc/hosts")) {
		t.Fatalf("commit-fault error leaks values: %v", err)
	}
	if got := hostsFileContent(t, faulty, "/etc/hosts"); got != "1.2.3.4 a\n" {
		t.Fatalf("commit-fault mutated file: %q", got)
	}

	// Traversal and directory-syntax hostsfile paths are rejected by
	// the runtime capability's ORIGINAL-path validation (no lexical
	// cancellation) and surface as the fixed value-free update error.
	// A NUL byte is caught even earlier by the module's own argument
	// validation with its own fixed class.
	fs, _ := hostsRWMemory(t, "1.2.3.4 a\n")
	rt := hostsRWRuntime(fs)
	for _, tc := range []struct {
		hostsfile string
		want      error
	}{
		{hostsfile: "/etc/../hosts", want: ErrHostsUpdateFailed},
		{hostsfile: "/etc/hosts/", want: ErrHostsUpdateFailed},
		{hostsfile: "/etc/hosts/.", want: ErrHostsUpdateFailed},
		{hostsfile: "/etc/ho\x00sts", want: errArgumentInvalid},
	} {
		path := tc.hostsfile
		for name, args := range map[string]any{
			"dnsutil.hosts_append": &HostsAppendArgs{Hostsfile: &path, IpAddr: str("10.0.0.1"), Entries: &entries},
			"dnsutil.hosts_remove": &HostsRemoveArgs{Hostsfile: &path, Entries: &entries},
		} {
			_, err := rt.Exec.Call(context.Background(), rt, name, args)
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s %q err = %v, want %v", name, tc.hostsfile, err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), tc.hostsfile) {
				t.Fatalf("%s %q error leaks the path: %v", name, tc.hostsfile, err)
			}
		}
	}
	if got := hostsFileContent(t, fs, "/etc/hosts"); got != "1.2.3.4 a\n" {
		t.Fatalf("rejected paths mutated the file: %q", got)
	}
}

// hostsOutcomeFS simulates the OS capability's distinct failure
// outcomes at the module boundary: for a configured committed-class
// outcome (ErrUpdateStagingResidue, ErrUpdateCommittedUncertain) it
// runs the caller's transform and publishes the replacement through
// the real MemoryFS before answering the capability sentinel (the
// content IS live); for every other outcome the tree is left exactly
// as it was (the target unchanged or absent).
type hostsOutcomeFS struct {
	*runtime.MemoryFS
	outcome error
	updates int
}

func (f *hostsOutcomeFS) UpdateFileBounded(ctx context.Context, name string, limits runtime.UpdateLimits, allowCreate bool, transform runtime.UpdateTransform) error {
	f.updates++
	if f.outcome == nil {
		return f.MemoryFS.UpdateFileBounded(ctx, name, limits, allowCreate, transform)
	}
	if errors.Is(f.outcome, runtime.ErrUpdateStagingResidue) || errors.Is(f.outcome, runtime.ErrUpdateCommittedUncertain) {
		existing, readErr := f.MemoryFS.ReadFile(name)
		exists := readErr == nil
		if !exists {
			if !allowCreate {
				return iofs.ErrNotExist
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

// TestHostsUpdateOutcomeMapping pins R103B-REGATE-02/R103B-SEC-07 at
// the registry surface: all FOUR capability outcomes — clean abort,
// cleanup-failed, staging-residue, and committed-uncertain — each
// surface as their OWN fixed value-free module error, all classes are
// mutually distinguishable via errors.Is, and the committed-content
// contract holds — the residue and durability outcomes leave the new
// bytes in the target while the abort outcomes leave it unchanged or
// absent.
func TestHostsUpdateOutcomeMapping(t *testing.T) {
	entries := "ad1"

	// (a) Pre-publication failure whose staging cleanup also fails:
	// the distinct cleanup-failed class, target byte-identical.
	func(t *testing.T) {
		fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateCleanupFailed}
		if err := fake.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fake.WriteFile("/etc/hosts", []byte("SECRET-CONTENT-a1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rt := hostsRWRuntime(fake)
		_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
			&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
		if !errors.Is(err, ErrHostsUpdateCleanupFailed) {
			t.Fatalf("(a) err = %v, want ErrHostsUpdateCleanupFailed", err)
		}
		if err != nil && (err.Error() != ErrHostsUpdateCleanupFailed.Error() ||
			strings.Contains(err.Error(), "SECRET-CONTENT") || strings.Contains(err.Error(), "/etc/hosts")) {
			t.Fatalf("(a) err text = %q, want the fixed value-free class", err)
		}
		if got := hostsFileContent(t, fake.MemoryFS, "/etc/hosts"); got != "SECRET-CONTENT-a1\n" {
			t.Fatalf("(a) cleanup-failed mutated the file: %q", got)
		}
		if fake.updates != 1 {
			t.Fatalf("(a) update dispatches = %d", fake.updates)
		}
	}(t)

	// (b) Post-publication staging-unlink failure on the create path:
	// the distinct residue class with the content LIVE — never
	// described as a rollback, and answered before the
	// parent-directory fsync, so crash durability is unconfirmed (the
	// class text says "committed", not "rollback").
	func(t *testing.T) {
		fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateStagingResidue}
		if err := fake.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		rt := hostsRWRuntime(fake)
		_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
			&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
		if !errors.Is(err, ErrHostsUpdateCommittedWithResidue) {
			t.Fatalf("(b) err = %v, want ErrHostsUpdateCommittedWithResidue", err)
		}
		if err != nil && (err.Error() != ErrHostsUpdateCommittedWithResidue.Error() || strings.Contains(err.Error(), "rollback") ||
			strings.Contains(err.Error(), "/etc/hosts") || strings.Contains(err.Error(), "10.0.0.1")) {
			t.Fatalf("(b) err text = %q, want the fixed value-free committed class", err)
		}
		if got := hostsFileContent(t, fake.MemoryFS, "/etc/hosts"); got != "\n10.0.0.1 ad1" {
			t.Fatalf("(b) residue outcome must leave the new bytes live, file = %q", got)
		}
	}(t)

	// (c) Post-publication parent-directory fsync failure: the
	// distinct durability class with the content live.
	func(t *testing.T) {
		fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: runtime.ErrUpdateCommittedUncertain}
		if err := fake.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fake.WriteFile("/etc/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rt := hostsRWRuntime(fake)
		_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
			&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
		if !errors.Is(err, ErrHostsUpdateCommittedDurabilityUncertain) {
			t.Fatalf("(c) err = %v, want ErrHostsUpdateCommittedDurabilityUncertain", err)
		}
		if got := hostsFileContent(t, fake.MemoryFS, "/etc/hosts"); got != "1.2.3.4 a\n\n10.0.0.1 ad1" {
			t.Fatalf("(c) durability outcome must leave the content live, file = %q", got)
		}
	}(t)

	// (d) The CLEAN-ABORT outcome — a pre-publication failure whose
	// staging cleanup succeeded (the capability answers the original
	// foreign error class) — collapses to the plain update-failed class
	// with the target byte-identical, and the full four-class matrix
	// stays mutually distinguishable via errors.Is.
	func(t *testing.T) {
		fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: syscall.EIO}
		if err := fake.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := fake.WriteFile("/etc/hosts", []byte("SECRET-CONTENT-d1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rt := hostsRWRuntime(fake)
		_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_append",
			&HostsAppendArgs{IpAddr: str("10.0.0.1"), Entries: &entries})
		if !errors.Is(err, ErrHostsUpdateFailed) {
			t.Fatalf("(d) err = %v, want ErrHostsUpdateFailed", err)
		}
		if err != nil && (err.Error() != ErrHostsUpdateFailed.Error() ||
			strings.Contains(err.Error(), "SECRET-CONTENT") || strings.Contains(err.Error(), "/etc/hosts") ||
			strings.Contains(err.Error(), "10.0.0.1") || strings.Contains(err.Error(), "ad1")) {
			t.Fatalf("(d) err text = %q, want the fixed value-free class", err)
		}
		// Unchanged-vs-committed: the clean abort leaves the file
		// byte-identical.
		if got := hostsFileContent(t, fake.MemoryFS, "/etc/hosts"); got != "SECRET-CONTENT-d1\n" {
			t.Fatalf("(d) clean abort mutated the file: %q", got)
		}
		for name, outcomeErr := range map[string]error{
			"cleanup-failed": ErrHostsUpdateCleanupFailed,
			"residue":        ErrHostsUpdateCommittedWithResidue,
			"durability":     ErrHostsUpdateCommittedDurabilityUncertain,
		} {
			if errors.Is(err, outcomeErr) {
				t.Fatalf("(d) clean-abort err = %v, must not classify as the %s class", err, name)
			}
		}
	}(t)

	// (e) A generic foreign filesystem failure on an absent target
	// collapses to the plain update-failed class with the target absent,
	// and every mapped class is distinct from the plain class.
	func(t *testing.T) {
		fake := &hostsOutcomeFS{MemoryFS: runtime.NewMemoryFS(), outcome: syscall.EIO}
		rt := hostsRWRuntime(fake)
		_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.hosts_remove",
			&HostsRemoveArgs{Entries: &entries})
		if !errors.Is(err, ErrHostsUpdateFailed) {
			t.Fatalf("(e) err = %v, want ErrHostsUpdateFailed", err)
		}
		if _, statErr := fake.Stat("/etc/hosts"); statErr == nil {
			t.Fatalf("(e) generic abort must leave the target absent")
		}
		for name, outcomeErr := range map[string]error{
			"cleanup-failed": ErrHostsUpdateCleanupFailed,
			"residue":        ErrHostsUpdateCommittedWithResidue,
			"durability":     ErrHostsUpdateCommittedDurabilityUncertain,
		} {
			if errors.Is(err, outcomeErr) {
				t.Fatalf("(e) generic err = %v, must not classify as the %s class", err, name)
			}
		}
		// Cross-class distinguishability of every committed/cleanup
		// class against the others and against the plain class.
		plain := mapHostsUpdateError(syscall.EIO)
		a := mapHostsUpdateError(runtime.ErrUpdateCleanupFailed)
		b := mapHostsUpdateError(runtime.ErrUpdateStagingResidue)
		c := mapHostsUpdateError(runtime.ErrUpdateCommittedUncertain)
		for name, pair := range map[string][2]error{
			"plain-vs-cleanup":      {plain, a},
			"plain-vs-residue":      {plain, b},
			"plain-vs-durability":   {plain, c},
			"cleanup-vs-residue":    {a, b},
			"cleanup-vs-durability": {a, c},
			"residue-vs-durability": {b, c},
		} {
			if errors.Is(pair[0], pair[1]) || errors.Is(pair[1], pair[0]) || pair[0].Error() == pair[1].Error() {
				t.Fatalf("(e) %s classes are not distinct: %q vs %q", name, pair[0], pair[1])
			}
		}
	}(t)
}
