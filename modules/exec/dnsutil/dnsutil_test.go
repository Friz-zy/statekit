package dnsutil

// R10.3a dnsutil unit tests (untagged: no dig binary, no DNS, no
// network, no host /etc/hosts read — file vectors run over
// runtime.MemoryFS and the dig delegation vectors run over fake dig
// registry functions). Every expected value in this file was produced
// by the pinned saltstack/salt/modules/dnsutil.py source executed as a
// local Python oracle (the splitlines/strip/split/int semantics
// included); vectors marked divergence pin the documented divergences
// of this port (whitespace-only hosts lines skip instead of crashing,
// crash positions map to fixed value-free errors, |v|>2^63-1
// saturates).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
)

// ---------------------------------------------------------------------------
// parse_hosts

const pinnedHostsFixture = "##\n" +
	"# Host Database\n" +
	"#\n" +
	"# localhost is used to configure the loopback interface\n" +
	"# when the system is booting.  Do not change this entry.\n" +
	"##\n" +
	"127.0.0.1\tlocalhost\n" +
	"255.255.255.255\tbroadcasthost\n" +
	"::1             localhost\n" +
	"fe80::1%lo0\tlocalhost"

func TestParseHostsPinnedFixture(t *testing.T) {
	pinned := pinnedHostsFixture
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &pinned})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"127.0.0.1":       {"localhost"},
		"255.255.255.255": {"broadcasthost"},
		"::1":             {"localhost"},
		"fe80::1%lo0":     {"localhost"},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_hosts fixture = %#v", value)
	}
}

func TestParseHostsDuplicatesCommentsAndBareIP(t *testing.T) {
	// Oracle vector: duplicate aliases accumulate in encounter order
	// with duplicates kept, an inline '#' becomes an alias token, a
	// col-0 '#' line is a comment line whose first token becomes an IP
	// key, and a bare IP answers an allocated empty alias list.
	inline := "1.2.3.4 a b\n1.2.3.4 c a\n5.6.7.8 d\n9.9.9.9\n1.2.3.4 host # note\n # col0"
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"1.2.3.4": {"a", "b", "c", "a", "host", "#", "note"},
		"5.6.7.8": {"d"},
		"9.9.9.9": {},
		"#":       {"col0"},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_hosts dups = %#v", value)
	}
	// A Python list is never null: the bare-IP alias list must render
	// as JSON [] and never null.
	encoded, jerr := json.Marshal(value)
	if jerr != nil || strings.Contains(string(encoded), "null") {
		t.Fatalf("parse_hosts json = %q err=%v", encoded, jerr)
	}
}

func TestParseHostsWhitespaceOnlyLineSkips(t *testing.T) {
	// Divergence pin: a whitespace-only line raises IndexError in the
	// pinned source; this port skips it.
	inline := "1.2.3.4 a\n \t \n1.2.3.4 b"
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string][]string{"1.2.3.4": {"a", "b"}}) {
		t.Fatalf("parse_hosts whitespace = %#v", value)
	}
}

func TestParseHostsDefaultPathAndFileRead(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/hosts", []byte(pinnedHostsFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: fs}

	// Default arguments: hosts is nil (Python None, falsy) and the
	// default hostsfile /etc/hosts is read through the bounded path.
	value, err := parseHostsFunc{}.Execute(context.Background(), rt, &ParseHostsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string][]string); !ok {
		t.Fatalf("parse_hosts default = %#v", value)
	}
	if got := value.(map[string][]string)["127.0.0.1"]; !reflect.DeepEqual(got, []string{"localhost"}) {
		t.Fatalf("parse_hosts default 127.0.0.1 = %#v", got)
	}

	// Explicit empty inline hosts is Python-falsy too: the file read
	// still happens.
	empty := ""
	value, err = parseHostsFunc{}.Execute(context.Background(), rt, &ParseHostsArgs{Hosts: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string][]string); !ok {
		t.Fatalf("parse_hosts empty hosts = %#v", value)
	}
}

func TestParseHostsDefaultPathMissingAnswersPinnedMessage(t *testing.T) {
	// MemoryFS has no /etc/hosts: the default read fails and the exact
	// pinned result string answers (no error, no path in the result).
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS()}
	value, err := parseHostsFunc{}.Execute(context.Background(), rt, &ParseHostsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts missing = %#v", value)
	}
}

func TestParseHostsTruthyInlineSkipsFile(t *testing.T) {
	// A truthy inline value must never touch the (missing) file.
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS()}
	inline := "   \n1.2.3.4 a\n"
	value, err := parseHostsFunc{}.Execute(context.Background(), rt, &ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string][]string{"1.2.3.4": {"a"}}) {
		t.Fatalf("parse_hosts truthy inline = %#v", value)
	}
	// Empty inline + missing explicit path: pinned message.
	empty := ""
	missing := "/definitely/not/here"
	value, err = parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &missing, Hosts: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts missing path = %#v", value)
	}
}

func TestParseHostsBoundedNoFollowReadBoundary(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/fixture", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/fixture/hosts", []byte("1.2.3.4 a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The read boundary requires a regular file and never follows a
	// final-component symlink; the pinned try/except answers the exact
	// not-found message for both.
	if err := fs.Symlink("/fixture/hosts", "/fixture/hosts-link"); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: fs}

	link := "/fixture/hosts-link"
	value, err := parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &link, Hosts: nil})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts symlink = %#v", value)
	}

	// A directory is not a regular file either.
	dir := "/fixture"
	value, err = parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &dir, Hosts: nil})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts dir = %#v", value)
	}

	// Oversized input (1 MiB + 1 bytes) is rejected by the bounded
	// read and answers the pinned message, never a partial parse.
	big := make([]byte, maxSourceBytes+1)
	for i := range big {
		big[i] = '#'
	}
	if err := fs.WriteFile("/fixture/big", big, 0o644); err != nil {
		t.Fatal(err)
	}
	bigPath := "/fixture/big"
	value, err = parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &bigPath, Hosts: nil})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts oversized = %#v", value)
	}

	// Exactly at the bound still parses.
	atBound := strings.Repeat("#", maxSourceBytes-1) + "\n"
	if err := fs.WriteFile("/fixture/at-bound", []byte(atBound), 0o644); err != nil {
		t.Fatal(err)
	}
	atBoundPath := "/fixture/at-bound"
	value, err = parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &atBoundPath, Hosts: nil})
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := value.(map[string][]string)
	if !ok || len(parsed) != 0 {
		t.Fatalf("parse_hosts at-bound = %#v", value)
	}

	// No filesystem at all answers the pinned message value-free.
	none := runtime.Runtime{}
	value, err = parseHostsFunc{}.Execute(context.Background(), &none, &ParseHostsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts no fs = %#v", value)
	}
}

func TestParseHostsPythonSplitlines(t *testing.T) {
	// Python splitlines() boundaries: \r, \r\n, \v, \f, U+001C..U+001E,
	// U+0085, U+2028, U+2029 — but NOT U+001F, which stays inside the
	// line and splits as whitespace tokens.
	inline := "1.2.3.4 a\r5.6.7.8 b\r\n7.7.7.7 c\v8.8.8.8 d\f9.9.9.9 e\n 1.1.1.1 f"
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"1.2.3.4": {"a"},
		"5.6.7.8": {"b"},
		"7.7.7.7": {"c"},
		"8.8.8.8": {"d"},
		"9.9.9.9": {"e"},
		"1.1.1.1": {"f"},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_hosts splitlines = %#v", value)
	}

	keep := "2.2.2.2\x1fhost"
	value, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &keep})
	if err != nil {
		t.Fatal(err)
	}
	// U+001F is NOT a splitlines boundary but IS split() whitespace:
	// one line, two tokens.
	if !reflect.DeepEqual(value, map[string][]string{"2.2.2.2": {"host"}}) {
		t.Fatalf("parse_hosts u+001f = %#v", value)
	}
}

// ---------------------------------------------------------------------------
// parse_zone

const pinnedSOAZone = "$TTL 3D\n" +
	"@               IN      SOA     land-5.com. root.land-5.com. (\n" +
	"199609203       ; Serial\n" +
	"28800   ; Refresh\n" +
	"7200    ; Retry\n" +
	"604800  ; Expire\n" +
	"86400)  ; Minimum TTL\n" +
	"@               IN      NS      land-5.com.\n" +
	"www             3600    IN      A       192.0.2.1\n" +
	"www2            IN      A       192.0.2.2\n" +
	"@               IN      TXT     \"v=spf1 -all\"\n" +
	"@               IN      CAA     0 issue \"letsencrypt.org\"\n" +
	"mail            IN      MX      10 mail.example.com.\n" +
	"mail            IN      MX      20 mail2.example.com.\n" +
	"ns1             IN      AAAA    2001:db8::1\n"

func TestParseZonePinnedSOAOracleVector(t *testing.T) {
	pinned := pinnedSOAZone
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &pinned})
	if err != nil {
		t.Fatal(err)
	}
	// Oracle-pinned (Python dict, keys sorted for the comparison).
	want := map[string]any{
		"TTL":     "3D",
		"ORIGIN":  "@",
		"NETWORK": "IN",
		"SOURCE":  "land-5.com.",
		"CONTACT": "root@land-5.com.",
		"SERIAL":  "199609203",
		"REFRESH": int64(28800),
		"RETRY":   int64(7200),
		"EXPIRE":  int64(604800),
		"MINTTL":  int64(86400),
		"NS":      []string{"land-5.com."},
		"A": map[string]any{
			"www.@": map[string]string{"TARGET": "192.0.2.1", "TTL": "3600"},
			// The 4-token owner IN A addr form carries no TTL and
			// stores the bare string through the generic bucket.
			"www2.@": "192.0.2.2",
		},
		"AAAA": map[string]any{"ns1.@": "2001:db8::1"},
		"TXT":  map[string]any{"@.@": "\"v=spf1"},
		"CAA":  map[string]any{"@.@": "0"},
		"MX":   []map[string]string{{"priority": "10", "host": "mail.example.com."}},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_zone soa =\n%#v\nwant\n%#v", value, want)
	}
}

func TestParseZoneORIGINDirectiveVector(t *testing.T) {
	inline := "$ORIGIN example.com.\nwww IN A 192.0.2.10\n@ IN NS ns1.example.com.\n"
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ORIGIN": "example.com.",
		"A":      map[string]any{"www.example.com.": "192.0.2.10"},
		"NS":     []string{"ns1.example.com."},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_zone origin = %#v", value)
	}
}

func TestParseZoneSOAPopAndNamedOriginVectors(t *testing.T) {
	// Oracle vector: a single-line SOA with both parens and comps[1]
	// != "IN" pops the second token and shifts every field.
	popZone := "@ SOA a. b. ( 1 2 3 4 5 6 7 8 )"
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &popZone})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"ORIGIN":  "@",
		"NETWORK": "a.",
		"SOURCE":  "(",
		"CONTACT": "1",
		"SERIAL":  "2",
		"REFRESH": int64(3),
		"RETRY":   int64(4),
		"EXPIRE":  int64(5),
		"MINTTL":  int64(6),
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_zone soa-pop = %#v", value)
	}

	named := "$ORIGIN example.com.\nexample.com. IN SOA ns root.example.com. ( 1 2 3 4 5 6 7 8 )"
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &named})
	if err != nil {
		t.Fatal(err)
	}
	parsed := value.(map[string]any)
	if parsed["CONTACT"] != "root@example.com." || parsed["SOURCE"] != "ns" ||
		parsed["ORIGIN"] != "example.com." || parsed["SERIAL"] != "(" {
		t.Fatalf("parse_zone named-origin = %#v", parsed)
	}
}

func TestParseZoneUnterminatedMultiReturnsPartial(t *testing.T) {
	// Oracle vector: an unclosed '(' swallows the rest of the zone and
	// the already-captured directives answer — no error, exactly like
	// the pinned parser.
	inline := "$TTL 1D\n@ IN SOA a. b. (\n1"
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, map[string]any{"TTL": "1D"}) {
		t.Fatalf("parse_zone unterminated = %#v", value)
	}
}

func TestParseZoneEmptyAndMissing(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS()}
	value, err := parseZoneFunc{}.Execute(context.Background(), rt, &ParseZoneArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if value != zoneNotFoundMessage {
		t.Fatalf("parse_zone empty = %#v", value)
	}

	// zonefile read failure silently falls back to the inline zone
	// (pinned try/except pass).
	missing := "/definitely/not/here"
	inline := "$ORIGIN example.com.\nwww IN A 192.0.2.10\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &missing, Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("parse_zone fallback = %#v", value)
	}
}

func TestParseZoneFileReplacesInlineAndEmptyFileWins(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/zones", 0o755); err != nil {
		t.Fatal(err)
	}
	fileZone := "$ORIGIN file.example.\nwww IN A 192.0.2.1\n"
	if err := fs.WriteFile("/zones/z", []byte(fileZone), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/zones/empty", []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: fs}

	// A successful read replaces the inline value entirely.
	path := "/zones/z"
	inline := "$ORIGIN inline.example.\nwww IN A 192.0.2.2\n"
	value, err := parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &path, Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(map[string]any)["ORIGIN"]; got != "file.example." {
		t.Fatalf("parse_zone file precedence = %#v", value)
	}

	// A successful read of EMPTY content replaces the inline value and
	// answers the pinned not-found result: the inline fallback applies
	// only to read failures.
	emptyPath := "/zones/empty"
	value, err = parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &emptyPath, Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if value != zoneNotFoundMessage {
		t.Fatalf("parse_zone empty file = %#v", value)
	}
}

func TestParseZoneBoundedNoFollowBoundary(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/zones", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/zones/real", []byte("$TTL 1D\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Symlink("/zones/real", "/zones/link"); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, maxSourceBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := fs.WriteFile("/zones/big", big, 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: fs}

	// Symlink read fails -> inline fallback (pinned except: pass).
	link := "/zones/link"
	inline := "$TTL 2D\n"
	value, err := parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &link, Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(map[string]any)["TTL"]; got != "2D" {
		t.Fatalf("parse_zone symlink fallback = %#v", value)
	}

	// Oversized read fails -> inline fallback, never a partial parse.
	bigPath := "/zones/big"
	value, err = parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &bigPath, Zone: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(map[string]any)["TTL"]; got != "2D" {
		t.Fatalf("parse_zone oversized fallback = %#v", value)
	}
}

func TestParseZoneCrashPositionsMapToValueFreeError(t *testing.T) {
	soa := "@ IN SOA a. b. ( 1 2 3 4 5 6 7 8 )"
	vectors := map[string]string{
		// Pinned IndexError: a 2-token NS line.
		"short-ns": soa + "\nNS land-5.com.",
		// Pinned KeyError: record before any ORIGIN is known.
		"no-origin": "www IN A 1.2.3.4",
		// Pinned IndexError: 3-token record hits comps[3].
		"ptr3": soa + "\n1 PTR localhost.",
		// Pinned IndexError: directive without a value.
		"directive-short": "$TTL",
		// Pinned IndexError: MX row without a host token.
		"mx-short": soa + "\n@ IN MX 10",
		// Pinned TypeError: $A made the A bucket a string.
		"collision-A": soa + "\n$A 1\nwww 60 IN A 1.2.3.4",
		// Pinned TypeError: $TXT made the TXT bucket a string.
		"collision-TXT": soa + "\n$TXT v\n@ IN TXT hello",
		// Pinned AttributeError: $NS made the NS list a string.
		"collision-NS": soa + "\n$NS x\n@ IN NS y.",
		// Pinned ValueError through _to_seconds' H branch.
		"bad-refresh": "@ IN SOA a. b. ( 4XH 2 3 4 5 6 7 8 )",
	}
	for name, zone := range vectors {
		value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
			&ParseZoneArgs{Zone: &zone})
		if err == nil {
			t.Fatalf("%s: expected the fixed malformed error, got %#v", name, value)
		}
		if !errors.Is(err, errZoneMalformed) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if msg := err.Error(); strings.Contains(msg, "SOA") || strings.Contains(msg, "example") {
			t.Fatalf("%s: error leaks zone bytes: %q", name, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// R103A-FINAL-01 / R10.3A-SEC-01 remediation vectors

// rejectingFS is a fake bounded filesystem (R10.3A-SEC-01 tests): every
// bounded read reports the oversize rejection without holding data,
// and any other filesystem use fails loudly through the embedded nil
// interface.
type rejectingFS struct {
	runtime.FileSystem // embedded nil: unexpected use panics
	reads              int
}

func (f *rejectingFS) ReadFileBounded(string, int64) ([]byte, error) {
	f.reads++
	return nil, runtime.ErrReadLimit
}

func TestParseZoneMalformedMultilineNeverPanics(t *testing.T) {
	// R103A-FINAL-01: a '('…')' continuation join can strip every token
	// (whitespace-only or empty join); the pinned parser raises
	// IndexError reading comps[0]. The port answers the exact fixed
	// value-free malformed-zone error — never a panic, never a partial
	// result — at the direct surface.
	for name, zone := range map[string]string{
		"empty-group":        "(\n)\n",
		"empty-group-no-nl":  "(\n)",
		"spaced-group":       "( \n )\n",
		"blank-continuation": "(\n\n)\n",
		"directive-then":     "$TTL 1D\n(\n)\n",
		"soa-then-group":     "@ IN SOA a. b. ( 1 2 3 4 5 6 7 8 )\n(\n)\n",
	} {
		value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
			&ParseZoneArgs{Zone: &zone})
		if !errors.Is(err, errZoneMalformed) {
			t.Fatalf("%s: err = %v, want the fixed malformed error", name, err)
		}
		if err.Error() != "dnsutil: malformed zone data" {
			t.Fatalf("%s: err text = %q", name, err.Error())
		}
		if value != nil {
			t.Fatalf("%s: partial value = %#v", name, value)
		}
	}
}

func TestParseZoneMalformedMultilineRegistryZeroDigDispatch(t *testing.T) {
	// R103A-FINAL-01 at the registry surface: the malformed join
	// rejects through dnsutil.parse_zone with zero dig invocation (the
	// parsing surface never reaches the delegation).
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	digA := &fakeDigFunc{name: "dig.A"}
	if err := reg.Register(digA); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS(), Runner: digResolverRunner{path: "/usr/bin/dig"}}

	zone := "(\n)\n"
	value, err := reg.Call(context.Background(), rt, "dnsutil.parse_zone", &ParseZoneArgs{Zone: &zone})
	if err == nil || !errors.Is(err, errZoneMalformed) {
		t.Fatalf("registry parse_zone err = %v value = %#v", err, value)
	}
	if value != nil {
		t.Fatalf("registry parse_zone partial value = %#v", value)
	}
	if digA.calls != 0 {
		t.Fatalf("dig invocations = %d, want 0", digA.calls)
	}
}

func TestParseHostsZoneInlineByteCap(t *testing.T) {
	// R10.3A-SEC-01 shared inline ceiling, exact boundary: a value of
	// exactly maxSourceBytes parses (a single comment line answers the
	// empty result) and one byte over rejects value-free with no
	// partial result.
	hostsAt := strings.Repeat("#", maxSourceBytes-1) + "\n"
	hostsOver := strings.Repeat("#", maxSourceBytes) + "\n"

	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &hostsAt})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, ok := value.(map[string][]string); !ok || len(parsed) != 0 {
		t.Fatalf("parse_hosts at-bound = %#v", value)
	}

	value, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &hostsOver})
	if !errors.Is(err, errInputTooLarge) {
		t.Fatalf("parse_hosts over-bound err = %v", err)
	}
	if value != nil || err.Error() != "dnsutil: input exceeds limit" {
		t.Fatalf("parse_hosts over-bound value = %#v err = %q", value, err)
	}

	zoneAt := strings.Repeat(";", maxSourceBytes-1) + "\n"
	zoneOver := strings.Repeat(";", maxSourceBytes) + "\n"

	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &zoneAt})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, ok := value.(map[string]any); !ok || len(parsed) != 0 {
		t.Fatalf("parse_zone at-bound = %#v", value)
	}

	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &zoneOver})
	if !errors.Is(err, errInputTooLarge) {
		t.Fatalf("parse_zone over-bound err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound partial value = %#v", value)
	}
}

func TestParseHostsZonePathCapAndFakeBoundedFS(t *testing.T) {
	// R10.3A-SEC-01: a path argument over maxPathBytes is rejected
	// BEFORE the filesystem is touched (the fake counts bounded reads)
	// and answers the pinned read-failure compatibility shapes; a path
	// at exactly the bound still reaches the FS, where the fake
	// bounded filesystem reports oversize (no data held) and the same
	// compatibility shapes answer.
	fs := &rejectingFS{}
	rt := &runtime.Runtime{FS: fs}

	longPath := "/" + strings.Repeat("p", maxPathBytes)
	if len(longPath) != maxPathBytes+1 {
		t.Fatalf("longPath length = %d", len(longPath))
	}
	value, err := parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &longPath})
	if err != nil || value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts long path = %#v err = %v", value, err)
	}
	if fs.reads != 0 {
		t.Fatalf("long path reached the filesystem: %d reads", fs.reads)
	}

	zone := "$TTL 2D\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &longPath, Zone: &zone})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(map[string]any)["TTL"]; got != "2D" {
		t.Fatalf("parse_zone long path fallback = %#v", value)
	}
	if fs.reads != 0 {
		t.Fatalf("long path reached the filesystem: %d reads", fs.reads)
	}

	atBoundPath := strings.Repeat("p", maxPathBytes)
	value, err = parseHostsFunc{}.Execute(context.Background(), rt,
		&ParseHostsArgs{Hostsfile: &atBoundPath})
	if err != nil || value != hostsNotFoundMessage {
		t.Fatalf("parse_hosts at-bound path = %#v err = %v", value, err)
	}
	if fs.reads != 1 {
		t.Fatalf("at-bound path reads = %d, want 1", fs.reads)
	}

	zoneInline := "$TTL 3D\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), rt,
		&ParseZoneArgs{Zonefile: &atBoundPath, Zone: &zoneInline})
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(map[string]any)["TTL"]; got != "3D" {
		t.Fatalf("parse_zone at-bound path fallback = %#v", value)
	}
	if fs.reads != 2 {
		t.Fatalf("at-bound path reads = %d, want 2", fs.reads)
	}
}

func TestParseHostsInputRecordBoundary(t *testing.T) {
	// R10.3A-SEC-01 input-record ceiling, exact boundary: 4096 unique
	// rows parse (4096 keys + 4096 aliases = exactly 8192 result
	// items); row 4097 rejects value-free with no partial map.
	build := func(records int) string {
		var b strings.Builder
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "10.%d.%d.4 host\n", (i>>8)&0xff, i&0xff)
		}
		return b.String()
	}

	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: ptr(build(maxInputRecords))})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, ok := value.(map[string][]string); !ok || len(parsed) != maxInputRecords {
		t.Fatalf("parse_hosts at-bound records = %#v", value)
	}

	value, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: ptr(build(maxInputRecords + 1))})
	if !errors.Is(err, errParseLimit) {
		t.Fatalf("parse_hosts over-bound records err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_hosts over-bound partial value = %#v", value)
	}
}

func TestParseHostsResultItemAndCellBoundaries(t *testing.T) {
	// Result-item ceiling (R103A-GATE-02), exact boundary: one IP key
	// plus 8191 aliases = exactly 8192 retained items (one object
	// member plus 8191 list elements); one more alias rejects with the
	// fixed item error and no partial result.
	aliases := func(count int) string {
		var b strings.Builder
		b.WriteString("1.2.3.4")
		for i := 0; i < count; i++ {
			b.WriteString(" h")
		}
		b.WriteString("\n")
		return b.String()
	}
	_, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: ptr(aliases(maxResultItems - 1))})
	if err != nil {
		t.Fatalf("parse_hosts at-bound items err = %v", err)
	}
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: ptr(aliases(maxResultItems))})
	if !errors.Is(err, errResultItems) {
		t.Fatalf("parse_hosts over-bound items err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_hosts over-bound items partial value = %#v", value)
	}

	// Cell ceiling, exact boundary: a token of exactly maxCellBytes
	// parses; one byte over rejects.
	cellAt := "1.2.3.4 " + strings.Repeat("a", maxCellBytes) + "\n"
	cellOver := "1.2.3.4 " + strings.Repeat("a", maxCellBytes+1) + "\n"
	_, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &cellAt})
	if err != nil {
		t.Fatalf("parse_hosts at-bound cell err = %v", err)
	}
	value, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: &cellOver})
	if !errors.Is(err, errParseLimit) {
		t.Fatalf("parse_hosts over-bound cell err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_hosts over-bound cell partial value = %#v", value)
	}
}

func TestParseZoneInputRecordAndCellBoundaries(t *testing.T) {
	// Input-record ceiling, exact boundary: the $ORIGIN directive plus
	// 4095 record lines = exactly 4096 records; one more record line
	// rejects value-free with no partial map.
	build := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN example.com.\n")
		for i := 0; i < records; i++ {
			b.WriteString("www IN A 127.0.0.1\n")
		}
		return b.String()
	}
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(build(maxInputRecords - 1))})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("parse_zone at-bound records = %#v", value)
	}
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(build(maxInputRecords))})
	if !errors.Is(err, errParseLimit) {
		t.Fatalf("parse_zone over-bound records err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound records partial value = %#v", value)
	}

	// Cell ceiling, exact boundary through a directive token: an
	// origin of exactly maxCellBytes parses; one byte over rejects.
	zoneAt := "$ORIGIN " + strings.Repeat("o", maxCellBytes-1) + ".\n@ IN TXT v\n"
	_, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &zoneAt})
	if err != nil {
		t.Fatalf("parse_zone at-bound cell err = %v", err)
	}
	zoneOver := "$ORIGIN " + strings.Repeat("o", maxCellBytes) + ".\n@ IN TXT v\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: &zoneOver})
	if !errors.Is(err, errParseLimit) {
		t.Fatalf("parse_zone over-bound cell err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound cell partial value = %#v", value)
	}
}

func TestParseZoneOriginExpansionGuard(t *testing.T) {
	// R10.3A-SEC-01 '@'→ORIGIN expansion guard, exact boundary without
	// allocating the expansion: a dot-terminated maxCellBytes origin
	// with spaced '@' tokens decides on the exact pre-expansion size
	// len(line)+matches*(len(origin)-1). 255 matches (509 + 255*4095 =
	// 1,044,734 bytes) stays within the 1 MiB source ceiling and
	// parses; 256 matches (511 + 256*4095 = 1,048,831 bytes) rejects
	// value-free before any expansion output is allocated.
	origin := strings.Repeat("o", maxCellBytes-1) + "."
	build := func(matches int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN ")
		b.WriteString(origin)
		b.WriteString("\n")
		for i := 0; i < matches; i++ {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString("@")
		}
		b.WriteString("\n")
		return b.String()
	}

	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(build(255))})
	if err != nil {
		t.Fatalf("parse_zone at-bound expansion err = %v", err)
	}
	parsed, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("parse_zone at-bound expansion = %#v", value)
	}
	// Every token expanded to the origin, so the generic bucket is
	// keyed by the origin itself: zonedict[origin] = {origin: origin}.
	bucket, ok := parsed[origin].(map[string]any)
	if !ok || bucket[origin] != origin {
		t.Fatalf("parse_zone at-bound expansion bucket = %#v", parsed[origin])
	}

	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(build(256))})
	if !errors.Is(err, errInputTooLarge) {
		t.Fatalf("parse_zone over-bound expansion err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound expansion partial value = %#v", value)
	}
}

func TestParseZoneOutputAggregateBoundary(t *testing.T) {
	// R103A-GATE-01 exact byte ceiling with escaping amplification:
	// every "@ IN TXT <1000x \\x01>" record retains ~6 KiB of JSON (the
	// value's control bytes escape to six-byte \\u0001 forms), so ~700
	// records cross the 4 MiB complete-representation ceiling from an
	// input well under 1 MiB. The boundary is located against a
	// manually built oracle map measured with encoding/json: the
	// largest record count whose encoding fits the ceiling parses and
	// answers the exact oracle shape, and one more record rejects with
	// the fixed value-free byte error and no partial map.
	origin := "o."
	payload := strings.Repeat("\x01", 1000)
	build := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN ")
		b.WriteString(origin)
		b.WriteString("\n")
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "w%d IN TXT %s\n", i, payload)
		}
		return b.String()
	}
	oracle := func(records int) map[string]any {
		m := map[string]any{"ORIGIN": origin}
		bucket := map[string]any{}
		for i := 0; i < records; i++ {
			bucket[fmt.Sprintf("w%d.%s", i, origin)] = payload
		}
		m["TXT"] = bucket
		return m
	}
	encoded := func(m map[string]any) int {
		enc, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return len(enc)
	}

	lo, hi := 1, 3000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if encoded(oracle(mid)) <= maxEncodedBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if encoded(oracle(lo)) > maxEncodedBytes || encoded(oracle(lo+1)) <= maxEncodedBytes {
		t.Fatalf("boundary search failed at %d records", lo)
	}

	at := build(lo)
	parsed, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &at})
	if err != nil {
		t.Fatalf("parse_zone at-bound output (%d records) err = %v", lo, err)
	}
	if !reflect.DeepEqual(parsed, oracle(lo)) {
		t.Fatalf("parse_zone at-bound output shape mismatch")
	}
	if size := encoded(parsed.(map[string]any)); size > maxEncodedBytes {
		t.Fatalf("parse_zone at-bound encoded = %d bytes", size)
	}
	over := build(lo + 1)
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &over})
	if !errors.Is(err, errResultBytes) {
		t.Fatalf("parse_zone over-bound output err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound output partial value = %#v", value)
	}
}

// ---------------------------------------------------------------------------
// R103A-GATE-01/02 / R103A-SEC-FINAL-01 result-budget gate probes

func TestJSONStringLengthMatchesEncoder(t *testing.T) {
	// Oracle parity for the budget's length oracle (R103A-GATE-01): for
	// every escaping class — quotes, backslash, the five short escapes,
	// the remaining control bytes, DEL, the HTML triplet, non-ASCII,
	// astral planes, U+2028/U+2029, and invalid UTF-8 — the computed
	// length equals the exact json.Marshal output length. U+2028 and
	// U+2029 cannot survive pythonSplitlines into a parser cell (they
	// are line boundaries), so their budget coverage is proven here at
	// the string-encoding level the budget consumes.
	vectors := []string{
		"", "plain", "a b\tc", `"quoted"`, `back\slash`, "\n\r\t",
		"\b\f", "\x00\x01\x1b", "\x7f", "<html>&</html>",
		"café", "２４", "ẖ", "line\u2028sep\u2029end", "\u2028\u2029",
		"\xff\xfe", "mixed\"\x01\\é", strings.Repeat("\x01", 1000),
		strings.Repeat("a\x01<", 700),
	}
	for _, s := range vectors {
		enc, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := jsonStringLength(s); got != int64(len(enc)) {
			t.Fatalf("jsonStringLength(%q) = %d, want the encoded %d", s, got, len(enc))
		}
	}
}

func TestParseZoneResultByteCeilingExpandedBucketKeys(t *testing.T) {
	// R103A-GATE-01 probe: origin = 3999 'a' chars + dot, 1024 records
	// "x. IN @<i> @" — a ~17 KiB input whose retained answer repeats
	// the 4000-byte origin in every expanded generic-bucket key AND in
	// every value (~8.2 MB of JSON before the fix; the old budget
	// counted only the selected owner and value bytes and missed the
	// expanded key entirely). The exact budget rejects with the fixed
	// value-free byte error and nil result while the item count
	// (2 per record + 1) is still far under its own ceiling.
	origin := strings.Repeat("a", 3999) + "."
	build := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN ")
		b.WriteString(origin)
		b.WriteString("\n")
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "x. IN @%d @\n", i)
		}
		return b.String()
	}
	oracle := func(records int) map[string]any {
		m := map[string]any{"ORIGIN": origin}
		for i := 0; i < records; i++ {
			m[origin+fmt.Sprintf("%d", i)] = map[string]any{"x.": origin}
		}
		return m
	}
	encoded := func(m map[string]any) int {
		enc, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return len(enc)
	}

	zone := build(1024)
	if size := len(zone); size > 20*1024 {
		t.Fatalf("probe input grew to %d bytes", size)
	}
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &zone})
	if !errors.Is(err, errResultBytes) || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("probe partial value = %#v", value)
	}

	// The exact boundary: the largest record count whose oracle
	// encoding fits the ceiling parses and answers the oracle shape;
	// one more record rejects before its bucket key is inserted.
	lo, hi := 1, 1024
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if encoded(oracle(mid)) <= maxEncodedBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if encoded(oracle(lo)) > maxEncodedBytes || encoded(oracle(lo+1)) <= maxEncodedBytes {
		t.Fatalf("boundary search failed at %d records", lo)
	}
	at := build(lo)
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &at})
	if err != nil {
		t.Fatalf("parse_zone at-bound probe (%d records) err = %v", lo, err)
	}
	if !reflect.DeepEqual(value, oracle(lo)) {
		t.Fatalf("parse_zone at-bound probe shape mismatch")
	}
	if size := encoded(value.(map[string]any)); size > maxEncodedBytes {
		t.Fatalf("parse_zone at-bound probe encoded = %d bytes", size)
	}
	over := build(lo + 1)
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &over})
	if !errors.Is(err, errResultBytes) {
		t.Fatalf("parse_zone over-bound probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound probe partial value = %#v", value)
	}
}

func TestParseZoneResultByteCeilingExpandedTypeKeys(t *testing.T) {
	// R103A-GATE-01 probe: origin = 4080 chars + dot with 1100 distinct
	// type keys "t<i>@", each expanding into a top-level bucket key of
	// ~4086 bytes — the expanded keys ALONE exceed the 4 MiB ceiling
	// while the item count stays under 8192. Rejection happens before
	// the bucket is inserted: fixed value-free byte error, nil result,
	// no partial map.
	origin := strings.Repeat("o", 4080) + "."
	build := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN ")
		b.WriteString(origin)
		b.WriteString("\n")
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "x. y t%d@ v\n", i)
		}
		return b.String()
	}

	zone := build(1100)
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &zone})
	if !errors.Is(err, errResultBytes) {
		t.Fatalf("probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("probe partial value = %#v", value)
	}

	// An under-ceiling prefix parses: 900 records retain ~3.7 MB and
	// the measured encoding stays within the cap.
	at := build(900)
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &at})
	if err != nil {
		t.Fatalf("parse_zone under-limit type keys err = %v", err)
	}
	enc, jerr := json.Marshal(value)
	if jerr != nil || len(enc) > maxEncodedBytes {
		t.Fatalf("parse_zone under-limit type keys encoded = %d bytes (err %v)", len(enc), jerr)
	}
}

func TestParseZoneResultItemCeilingNestedEntries(t *testing.T) {
	// R103A-GATE-02 probe: 4095 unique owner-TTL-IN-A rows retain
	// 12,287 nested items — ORIGIN + the A bucket member + 3 per row
	// (owner member, TARGET, TTL) — far over the 8192 ceiling while the
	// byte total stays small. The exact boundary is 2730 rows (8192
	// items exactly); 2731 rejects with the fixed value-free item
	// error and nil result.
	build := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN example.com.\n")
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "h%d 60 IN A 127.0.0.1\n", i)
		}
		return b.String()
	}

	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(build(4095))})
	if !errors.Is(err, errResultItems) {
		t.Fatalf("probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("probe partial value = %#v", value)
	}

	at := build(2730)
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &at})
	if err != nil {
		t.Fatalf("parse_zone at-bound items err = %v", err)
	}
	bucket, ok := value.(map[string]any)["A"].(map[string]any)
	if !ok || len(bucket) != 2730 {
		t.Fatalf("parse_zone at-bound items bucket = %#v", value)
	}
	over := build(2731)
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &over})
	if !errors.Is(err, errResultItems) {
		t.Fatalf("parse_zone over-bound items err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound items partial value = %#v", value)
	}
}

func TestParseZoneReplacementItemAccountingBoundaries(t *testing.T) {
	// R103A-GATE-02 regression: retained item accounting must replace
	// a key/member's old retained subtree with the new subtree's exact
	// item delta on every shape-changing replacement. Every count below
	// is computed independently of the parser: one owner-TTL-IN-A row
	// retains 3 items (owner member, TARGET, TTL), a plain-string owner
	// retains 1, a scalar top-level member retains 1, and a bucket or
	// list member retains 1 plus its contents.

	// Gate regression (scalar -> object, the count grows through the
	// ceiling): $ORIGIN + two generic A strings for x0/x1 + the two
	// owner-TTL-IN-A rewrites of x0/x1 (+2 each) + 2729 fresh
	// owner-TTL-IN-A rows. Final retained items = ORIGIN(1) + the A
	// bucket member(1) + 2731 object owner subtrees(8193) = 8195, over
	// the 8192 ceiling: the fixed value-free item error and nil result.
	// Pre-fix, the two scalar->object replacements reserved zero items,
	// the counter read 8191, and the 8195-item result escaped.
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseZoneArgs{Zone: ptr(gate02ReplacementZone())})
	if !errors.Is(err, errResultItems) || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("gate regression err = %v", err)
	}
	if value != nil {
		t.Fatalf("gate regression partial value = %#v", value)
	}

	// The separate 2730-row structure without replacements retains
	// exactly 8192 items (ORIGIN + A member + 3 per row) and passes.
	rows := func(records int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN example.com.\n")
		for i := 0; i < records; i++ {
			fmt.Fprintf(&b, "h%d 60 IN A 127.0.0.1\n", i)
		}
		return b.String()
	}
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(rows(2730))})
	if err != nil {
		t.Fatalf("exact-8192 structure err = %v", err)
	}
	if bucket, ok := value.(map[string]any)["A"].(map[string]any); !ok || len(bucket) != 2730 {
		t.Fatalf("exact-8192 structure bucket = %#v", value)
	}

	// Top-level replacement (object -> scalar, the count shrinks): a
	// 100-owner TXT bucket (ORIGIN + TXT member + 100 owners = 102
	// items) is flattened by the $TXT directive to the single scalar
	// member (the 101-item subtree becomes 1, -100), so 2729 fresh
	// owner-TTL-IN-A rows (the A member plus 3 per row) plus one
	// two-item generic TXT2 record land on exactly 8192 items and
	// pass. Pre-fix the removed descendants were never subtracted and
	// the same fill falsely rejected mid-way through the A rows.
	txtRows := func(w *strings.Builder) {
		for i := 0; i < 100; i++ {
			fmt.Fprintf(w, "t%d. IN TXT v\n", i)
		}
	}
	var shrink strings.Builder
	shrink.WriteString("$ORIGIN example.com.\n")
	txtRows(&shrink)
	shrink.WriteString("$TXT s\n")
	shrink.WriteString(rows(2729))
	shrink.WriteString("z. IN TXT2 q\n")
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(shrink.String())})
	if err != nil {
		t.Fatalf("top-level shrink fill err = %v", err)
	}
	parsed, ok := value.(map[string]any)
	if !ok || parsed["TXT"] != "s" {
		t.Fatalf("top-level shrink TXT = %#v", value)
	}
	if bucket, ok := parsed["A"].(map[string]any); !ok || len(bucket) != 2729 {
		t.Fatalf("top-level shrink A = %#v", parsed["A"])
	}
	// One more TXT2 owner (+1) reaches 8193: still rejected.
	var shrinkOver strings.Builder
	shrinkOver.WriteString("$ORIGIN example.com.\n")
	txtRows(&shrinkOver)
	shrinkOver.WriteString("$TXT s\n")
	shrinkOver.WriteString(rows(2729))
	shrinkOver.WriteString("z. IN TXT2 q\nz2. IN TXT2 q2\n")
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(shrinkOver.String())})
	if !errors.Is(err, errResultItems) {
		t.Fatalf("top-level shrink over err = %v", err)
	}
	if value != nil {
		t.Fatalf("top-level shrink over partial value = %#v", value)
	}

	// Nested replacement (object -> scalar, the count shrinks): 2730
	// A rows land on exactly 8192 items, the generic rewrite of owner
	// h0.example.com. returns the TARGET/TTL object's two items (-2),
	// and one new TXT row (+2) lands back on exactly 8192 and passes.
	// Pre-fix the -2 never applied and the same zone falsely rejected.
	nested := rows(2730) + "h0 y A v\nz. IN TXT q\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(nested)})
	if err != nil {
		t.Fatalf("nested shrink err = %v", err)
	}
	parsed, ok = value.(map[string]any)
	if !ok {
		t.Fatalf("nested shrink value = %#v", value)
	}
	if bucket, ok := parsed["A"].(map[string]any); !ok || bucket["h0.example.com."] != "v" || len(bucket) != 2730 {
		t.Fatalf("nested shrink A = %#v", parsed["A"])
	}
	if txt, ok := parsed["TXT"].(map[string]any); !ok || txt["z."] != "q" {
		t.Fatalf("nested shrink TXT = %#v", parsed["TXT"])
	}
	// One more TXT owner (+1) reaches 8193: rejected with nil result.
	nestedOver := rows(2730) + "h0 y A v\nz. IN TXT q\nz2. IN TXT q2\n"
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(nestedOver)})
	if !errors.Is(err, errResultItems) {
		t.Fatalf("nested shrink over err = %v", err)
	}
	if value != nil {
		t.Fatalf("nested shrink over partial value = %#v", value)
	}
}

// gate02ReplacementZone builds the R103A-GATE-02 shape-changing-
// replacement regression zone shared by the unit and contract
// surfaces: $ORIGIN, two generic A strings under owners x0/x1, the
// two owner-TTL-IN-A rewrites of those owners (each scalar->object
// replacement gains the TARGET and TTL members' two items), and 2729
// fresh owner-TTL-IN-A rows — 8195 final retained items, three over
// the 8192 ceiling (the pre-fix budget missed the four replacement
// items and let this 8195-item result through at a counter reading of
// 8191).
func gate02ReplacementZone() string {
	var b strings.Builder
	b.WriteString("$ORIGIN example.com.\n")
	b.WriteString("x0 y A v0\n")
	b.WriteString("x1 y A v1\n")
	b.WriteString("x0 60 IN A 127.0.0.1\n")
	b.WriteString("x1 60 IN A 127.0.0.1\n")
	for i := 0; i < 2729; i++ {
		fmt.Fprintf(&b, "h%d 60 IN A 127.0.0.1\n", i)
	}
	return b.String()
}

// nestedExactByteBoundary locates, against an independently built
// encoding/json oracle, the padded nested A/AAAA result whose exact
// compact encoding is exactly maxEncodedBytes (R103A-FINAL-BYTES-01)
// and returns the at-bound zone plus the one-encoded-byte-over zone.
// Each pad 'a' grows the exact encoding by exactly one byte, so the
// size passes through every integer across the bracketed range.
func nestedExactByteBoundary(t testing.TB) (at, over string) {
	t.Helper()
	origin := "example.com."
	payload := strings.Repeat("\x01", 2000)
	padOwner := func(pad int) string { return "z\"<\\" + strings.Repeat("a", pad) }
	build := func(pad int) string {
		var b strings.Builder
		b.WriteString("$ORIGIN ")
		b.WriteString(origin)
		b.WriteString("\n")
		for i := 0; i < 347; i++ {
			fmt.Fprintf(&b, "w%d 60 IN A %s\n", i, payload)
		}
		fmt.Fprintf(&b, "%s <6> IN AAAA %s\n", padOwner(pad), payload)
		return b.String()
	}
	oracle := func(pad int) map[string]any {
		m := map[string]any{"ORIGIN": origin, "A": map[string]any{}, "AAAA": map[string]any{}}
		for i := 0; i < 347; i++ {
			m["A"].(map[string]any)[fmt.Sprintf("w%d.%s", i, origin)] =
				map[string]string{"TARGET": payload, "TTL": "60"}
		}
		m["AAAA"].(map[string]any)[padOwner(pad)+"."+origin] =
			map[string]string{"TARGET": payload, "TTL": "<6>"}
		return m
	}
	encoded := func(pad int) int {
		enc, err := json.Marshal(oracle(pad))
		if err != nil {
			t.Fatal(err)
		}
		return len(enc)
	}
	lo, hi := 0, 3900
	if encoded(lo) > maxEncodedBytes || encoded(hi) <= maxEncodedBytes {
		t.Fatalf("exact byte boundary not bracketed: size(0)=%d size(%d)=%d", encoded(lo), hi, encoded(hi))
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if encoded(mid) <= maxEncodedBytes {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	// lo is the first pad count over the ceiling; lo-1 is exact.
	if pad := lo - 1; encoded(pad) != maxEncodedBytes || encoded(pad+1) != maxEncodedBytes+1 {
		t.Fatalf("exact byte boundary not located: size(%d)=%d size(%d)=%d",
			pad, encoded(pad), pad+1, encoded(pad+1))
	}
	return build(lo - 1), build(lo)
}

func TestParseZoneNestedEntryStructuralBytesOracle(t *testing.T) {
	// R103A-FINAL-BYTES-01: the nested TARGET/TTL object contributes
	// exactly 18 structural bytes excluding the encoded values —
	// {"TARGET":t,"TTL":l} is {, "TARGET"(8), :, ,, "TTL"(5), :, } —
	// not 19; the pre-fix budget overcounted one structural byte per
	// nested A/AAAA entry at both calculation sites. The unit oracle
	// sweeps escape-heavy TARGET/TTL pairs against encoding/json, and
	// the exact boundary locates a nested A/AAAA result whose complete
	// compact encoding is exactly maxEncodedBytes: accepted with the
	// exact oracle shape and byte length, and one encoded byte above
	// rejected before insertion with the fixed value-free byte error
	// and a nil result. Keys and values carry quote, backslash,
	// control, and HTML-triplet escape classes, and the oracle counts
	// every map-member delimiter, colon, and comma.
	for _, v := range []map[string]string{
		{"TARGET": "127.0.0.1", "TTL": "60"},
		{"TARGET": "2001:db8::1", "TTL": "3600"},
		{"TARGET": "\"q\\", "TTL": "<6>"},
		{"TARGET": "\x01\x1b\x7f", "TTL": "café"},
		{"TARGET": "\x00\"\\\b\f\n\r\t", "TTL": "２４"},
	} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		size, zerr := zoneEntrySize(v)
		if zerr != nil || size != int64(len(enc)) {
			t.Fatalf("zoneEntrySize(%#v) = %d, want the encoded %d (err %v)", v, size, len(enc), zerr)
		}
		if zoneEntryItems(v) != 2 {
			t.Fatalf("zoneEntryItems(%#v) = %d, want 2", v, zoneEntryItems(v))
		}
	}
	plain := "anything"
	if zoneEntryItems(plain) != 0 {
		t.Fatalf("zoneEntryItems(scalar) = %d, want 0", zoneEntryItems(plain))
	}

	at, over := nestedExactByteBoundary(t)
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(at)})
	if err != nil {
		t.Fatalf("parse_zone exact-4MiB err = %v", err)
	}
	enc, merr := json.Marshal(value)
	if merr != nil || len(enc) != maxEncodedBytes {
		t.Fatalf("parse_zone exact-4MiB encoded = %d bytes (err %v), want exactly %d", len(enc), merr, maxEncodedBytes)
	}
	var shape map[string]any
	if derr := json.Unmarshal(enc, &shape); derr != nil {
		t.Fatalf("parse_zone exact-4MiB decode: %v", derr)
	}
	if a, ok := shape["A"].(map[string]any); !ok || len(a) != 347 {
		t.Fatalf("parse_zone exact-4MiB A = %#v", shape["A"])
	}
	if aaaa, ok := shape["AAAA"].(map[string]any); !ok || len(aaaa) != 1 {
		t.Fatalf("parse_zone exact-4MiB AAAA = %#v", shape["AAAA"])
	}
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: ptr(over)})
	if !errors.Is(err, errResultBytes) || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone one-byte-over err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone one-byte-over partial value = %#v", value)
	}
}

func TestParseZoneResultEscapingUnderCeiling(t *testing.T) {
	// R103A-SEC-FINAL-01 probe: under-limit distinct buckets whose keys
	// and values carry quotes, backslash, control bytes, DEL, the HTML
	// triplet, and non-ASCII parse successfully; the measured
	// encoding/json output (the test oracle) stays within the ceiling
	// and matches the exact retained shape. U+2028/U+2029 cannot appear
	// in a parser cell (pythonSplitlines boundaries — proven at the
	// string oracle in TestJSONStringLengthMatchesEncoder).
	origin := `"o\\b` + "\x01\x1b\x7f" + `.` + "café２４."
	zone := "$ORIGIN " + origin + "\n" +
		"\"ow\\q\"\x01. 60 IN A 127.0.0.1\n" +
		"<mx>&\x7f. 61 IN AAAA 2001:db8::1\n" +
		"\"v\\q\"<>&. IN TXT \"val\\ue\"\x01\n" +
		"h\x01\x1b. IN MX 10 <mx>&.\n"

	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &zone})
	if err != nil {
		t.Fatalf("parse_zone escaping err = %v", err)
	}
	enc, jerr := json.Marshal(value)
	if jerr != nil {
		t.Fatalf("parse_zone escaping json: %v", jerr)
	}
	if len(enc) > maxEncodedBytes {
		t.Fatalf("parse_zone escaping encoded = %d bytes", len(enc))
	}
	if !strings.Contains(string(enc), `\u0001`) || !strings.Contains(string(enc), `\u003c`) {
		t.Fatalf("parse_zone escaping encoding misses expected escapes: %.80s", enc)
	}
	want := map[string]any{
		"ORIGIN": origin,
		// The owners end with '.', so the pinned origin-suffix branch
		// never fires; their exact bytes (quotes, backslash, control,
		// DEL, HTML triplet) become the retained nested keys.
		"A": map[string]any{
			"\"ow\\q\"\x01.": map[string]string{"TARGET": "127.0.0.1", "TTL": "60"},
		},
		"AAAA": map[string]any{
			"<mx>&\x7f.": map[string]string{"TARGET": "2001:db8::1", "TTL": "61"},
		},
		"TXT": map[string]any{
			"\"v\\q\"<>&.": "\"val\\ue\"\x01",
		},
		"MX": []map[string]string{{"priority": "10", "host": "<mx>&."}},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_zone escaping =\n%#v\nwant\n%#v", value, want)
	}
}

func TestParseHostsResultByteCeilingEscaping(t *testing.T) {
	// R103A-GATE-01 on parse_hosts: control-byte aliases amplify six to
	// one (each 4096-byte \x01 alias retains 24,578 JSON bytes), so 200
	// aliases cross the 4 MiB complete-representation ceiling while
	// the item counter (201) and the input (~800 KiB) stay well within
	// their own ceilings; 100 aliases parse and measure under the cap.
	alias := strings.Repeat("\x01", maxCellBytes)
	build := func(count int) string {
		var b strings.Builder
		b.WriteString("1.2.3.4")
		for i := 0; i < count; i++ {
			b.WriteString(" ")
			b.WriteString(alias)
		}
		b.WriteString("\n")
		return b.String()
	}

	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{},
		&ParseHostsArgs{Hosts: ptr(build(200))})
	if !errors.Is(err, errResultBytes) {
		t.Fatalf("parse_hosts escaping over err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_hosts escaping over partial value = %#v", value)
	}

	at := build(100)
	value, err = parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseHostsArgs{Hosts: &at})
	if err != nil {
		t.Fatalf("parse_hosts escaping at err = %v", err)
	}
	enc, jerr := json.Marshal(value)
	if jerr != nil || len(enc) > maxEncodedBytes {
		t.Fatalf("parse_hosts escaping at encoded = %d bytes (err %v)", len(enc), jerr)
	}
	if !strings.Contains(string(enc), `\u0001`) {
		t.Fatalf("parse_hosts escaping at encoding misses \\u0001 escapes")
	}
}

// ptr is a small helper for addressable inline literals.
func ptr(v string) *string { return &v }

// ---------------------------------------------------------------------------
// _to_seconds

func TestToSecondsOracleVectors(t *testing.T) {
	vectors := []struct {
		in   string
		want int64
	}{
		{"4H", 14400}, {"1D", 86400}, {"2W", 604800}, {"", 604800},
		{"604801", 604800}, {"604800", 604800}, {"4h", 14400}, {"1d", 86400},
		{"w", 604800}, {"abcW", 604800}, {"abc", 604800}, {"-2H", -7200},
		{" 12 H ", 43200}, {"２４H", 86400}, {"٢٤H", 86400}, {"2_4H", 86400},
		{"+2H", 7200}, {"0", 0}, {"0H", 0}, {"168H", 604800}, {"7D", 604800},
		{"-1", -1}, {"\x1c24\x1f", 604800},
		// Positive magnitudes beyond int64 still cap to one week.
		{"99999999999999999999999H", 604800},
		{"99999999999999999999999", 604800},
	}
	for _, v := range vectors {
		got, err := toSeconds(v.in)
		if err != nil {
			t.Fatalf("_to_seconds(%q) err = %v", v.in, err)
		}
		if got != v.want {
			t.Fatalf("_to_seconds(%q) = %d, want %d", v.in, got, v.want)
		}
	}
}

func TestToSecondsCrashPositionsAreErrors(t *testing.T) {
	// The pinned H/D branches crash on ValueError (no except wraps
	// them) and int() rejects these literals; U+001C is whitespace for
	// isspace but not for int().
	for _, in := range []string{"4XH", "_24H", "2\x1c4H", "２´H"} {
		if _, err := toSeconds(in); !errors.Is(err, errZoneMalformed) {
			t.Fatalf("_to_seconds(%q) err = %v, want the fixed malformed error", in, err)
		}
	}
}

func TestToSecondsNegativeSaturationDivergence(t *testing.T) {
	// Documented divergence: Python keeps the exact arbitrary-precision
	// negative; int64 saturates to math.MinInt64 for |v| > 2^63-1.
	got, err := toSeconds("-99999999999999999999999")
	if err != nil {
		t.Fatal(err)
	}
	if got != -9223372036854775808 {
		t.Fatalf("_to_seconds negative saturation = %d", got)
	}
}

// ---------------------------------------------------------------------------
// dig delegation (fake registry functions; no dig binary, no dispatch)

// fakeDigFunc records the exact argument struct one delegation carried
// and answers scripted values.
type fakeDigFunc struct {
	name  string
	args  any
	value any
	err   error
	calls int
}

func (f *fakeDigFunc) Name() string { return f.name }
func (f *fakeDigFunc) Args() any    { return nil }

func (f *fakeDigFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	f.calls++
	f.args = args
	return f.value, f.err
}

func TestParseHostsAndZoneNeedNoRunner(t *testing.T) {
	// The parsing functions are pure: no Runner, no Exec, no FS reads
	// for inline data.
	rt := &runtime.Runtime{}
	inline := "1.2.3.4 a\n"
	value, err := parseHostsFunc{}.Execute(context.Background(), rt, &ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(map[string][]string); !ok {
		t.Fatalf("parse_hosts pure = %#v", value)
	}
}

func TestDelegationForwardsExactArgumentsAndDefaults(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	digA := &fakeDigFunc{name: "dig.A", value: []string{"192.0.2.1"}}
	digAAAA := &fakeDigFunc{name: "dig.AAAA", value: []string{"2001:db8::1"}}
	digNS := &fakeDigFunc{name: "dig.NS", value: []string{"192.0.2.53"}}
	digSPF := &fakeDigFunc{name: "dig.SPF", value: []string{"198.60.22.0/24"}}
	digMX := &fakeDigFunc{name: "dig.MX", value: [][]string{{"10", "mail."}}}
	digCheckIP := &fakeDigFunc{name: "dig.check_ip", value: true}
	for _, fn := range []*fakeDigFunc{digA, digAAAA, digNS, digSPF, digMX, digCheckIP} {
		if err := reg.Register(fn); err != nil {
			t.Fatal(err)
		}
	}
	rt := &runtime.Runtime{Exec: reg, Runner: digResolverRunner{path: "/usr/bin/dig"}}

	// A forwards host and the absent nameserver (nil) exactly.
	value, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, []string{"192.0.2.1"}) {
		t.Fatalf("dnsutil.A = %#v", value)
	}
	forwarded, ok := digA.args.(*execdig.AArgs)
	if !ok || forwarded.Host != "www.example.com" || forwarded.Nameserver != nil {
		t.Fatalf("dnsutil.A forwarded = %#v", digA.args)
	}

	// An explicit nameserver pointer forwards as the same value.
	ns := "192.0.2.53"
	_, err = reg.Call(context.Background(), rt, "dnsutil.AAAA", &AAAAArgs{Host: "www.example.com", Nameserver: &ns})
	if err != nil {
		t.Fatal(err)
	}
	forwardedAAAA, ok := digAAAA.args.(*execdig.AAAAArgs)
	if !ok || forwardedAAAA.Nameserver == nil || *forwardedAAAA.Nameserver != ns {
		t.Fatalf("dnsutil.AAAA forwarded = %#v", digAAAA.args)
	}

	// NS forwards resolve with the pinned True default.
	_, err = reg.Call(context.Background(), rt, "dnsutil.NS", &NSArgs{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	forwardedNS, ok := digNS.args.(*execdig.NSArgs)
	if !ok || forwardedNS.Resolve == nil || *forwardedNS.Resolve != true {
		t.Fatalf("dnsutil.NS default resolve = %#v", digNS.args)
	}
	// Explicit resolve=false forwards exactly.
	falseVal := false
	if _, err = reg.Call(context.Background(), rt, "dnsutil.NS", &NSArgs{Domain: "example.com", Resolve: &falseVal}); err != nil {
		t.Fatal(err)
	}
	if forwarded, ok := digNS.args.(*execdig.NSArgs); !ok || forwarded.Resolve == nil || *forwarded.Resolve {
		t.Fatalf("dnsutil.NS explicit resolve = %#v", digNS.args)
	}

	// SPF forwards record with the pinned "SPF" default.
	_, err = reg.Call(context.Background(), rt, "dnsutil.SPF", &SPFArgs{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	forwardedSPF, ok := digSPF.args.(*execdig.SPFArgs)
	if !ok || forwardedSPF.Record == nil || *forwardedSPF.Record != "SPF" {
		t.Fatalf("dnsutil.SPF default record = %#v", digSPF.args)
	}
	// Explicit TXT forwards exactly.
	txt := "TXT"
	if _, err = reg.Call(context.Background(), rt, "dnsutil.SPF", &SPFArgs{Domain: "example.com", Record: &txt}); err != nil {
		t.Fatal(err)
	}
	if forwarded, ok := digSPF.args.(*execdig.SPFArgs); !ok || forwarded.Record == nil || *forwarded.Record != "TXT" {
		t.Fatalf("dnsutil.SPF explicit record = %#v", digSPF.args)
	}

	// MX forwards resolve with the pinned False default.
	_, err = reg.Call(context.Background(), rt, "dnsutil.MX", &MXArgs{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	forwardedMX, ok := digMX.args.(*execdig.MXArgs)
	if !ok || forwardedMX.Resolve == nil || *forwardedMX.Resolve {
		t.Fatalf("dnsutil.MX default resolve = %#v", digMX.args)
	}

	// check_ip delegates and propagates the exact bool result shape.
	value, err = reg.Call(context.Background(), rt, "dnsutil.check_ip", &CheckIPArgs{Addr: "127.0.0.1"})
	if err != nil || value != true {
		t.Fatalf("dnsutil.check_ip = %#v err = %v", value, err)
	}
	forwardedIP, ok := digCheckIP.args.(*execdig.CheckIPArgs)
	if !ok || forwardedIP.Addr != "127.0.0.1" {
		t.Fatalf("dnsutil.check_ip forwarded = %#v", digCheckIP.args)
	}
}

func TestDelegationPropagatesUnderlyingErrorValueFree(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	underlying := fmt.Errorf("dig: command timed out")
	digA := &fakeDigFunc{name: "dig.A", err: underlying}
	if err := reg.Register(digA); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, Runner: digResolverRunner{path: "/usr/bin/dig"}}

	_, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "leak.example"})
	if err == nil || err.Error() != underlying.Error() {
		t.Fatalf("dnsutil.A propagated err = %v", err)
	}
	if strings.Contains(err.Error(), "leak.example") {
		t.Fatalf("dnsutil.A error leaks the query value: %q", err)
	}
}

func TestDelegationGateAnswersPinnedMessageWithoutDig(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	digA := &fakeDigFunc{name: "dig.A"}
	if err := reg.Register(digA); err != nil {
		t.Fatal(err)
	}

	// No Runner at all: unavailable (the deferred socket-fallback
	// divergence answers the pinned string, not an error).
	rt := &runtime.Runtime{Exec: reg}
	value, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "www.example.com"})
	if err != nil || value != digUnavailableMessage {
		t.Fatalf("dnsutil.A no runner = %#v err = %v", value, err)
	}
	// A capability-less Runner cannot verify dig: same pinned answer.
	rt = &runtime.Runtime{Exec: reg, Runner: capabilitylessRunner{}}
	value, err = reg.Call(context.Background(), rt, "dnsutil.check_ip", &CheckIPArgs{Addr: "127.0.0.1"})
	if err != nil || value != digUnavailableMessage {
		t.Fatalf("dnsutil.check_ip capability-less = %#v err = %v", value, err)
	}
	// A failing resolver: same pinned answer.
	rt = &runtime.Runtime{Exec: reg, Runner: digResolverRunner{err: fmt.Errorf("untrusted")}}
	value, err = reg.Call(context.Background(), rt, "dnsutil.MX", &MXArgs{Domain: "example.com"})
	if err != nil || value != digUnavailableMessage {
		t.Fatalf("dnsutil.MX gated = %#v err = %v", value, err)
	}
	if digA.calls != 0 {
		t.Fatalf("gated dispatches = %d, want 0", digA.calls)
	}
}

func TestDelegationRegistryMissIsFixedUnavailableError(t *testing.T) {
	// The gate passes but the registry carries no dig function: the
	// pinned __salt__ lookup crash position maps to one fixed
	// value-free error.
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, Runner: digResolverRunner{path: "/usr/bin/dig"}}
	for name, args := range map[string]any{
		"dnsutil.A":        &AArgs{Host: "www.example.com"},
		"dnsutil.AAAA":     &AAAAArgs{Host: "www.example.com"},
		"dnsutil.NS":       &NSArgs{Domain: "example.com"},
		"dnsutil.SPF":      &SPFArgs{Domain: "example.com"},
		"dnsutil.MX":       &MXArgs{Domain: "example.com"},
		"dnsutil.check_ip": &CheckIPArgs{Addr: "127.0.0.1"},
	} {
		value, err := reg.Call(context.Background(), rt, name, args)
		if err == nil || !errors.Is(err, errDigFunctionUnavailable) {
			t.Fatalf("%s registry-miss = %#v err = %v", name, value, err)
		}
		if strings.Contains(err.Error(), "www.example.com") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("%s registry-miss error leaks a value: %q", name, err)
		}
	}
}

func TestDelegationPropagatesCallerCancellation(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	canceled := &fakeDigFunc{name: "dig.A", err: context.Canceled}
	if err := reg.Register(canceled); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, Runner: digResolverRunner{path: "/usr/bin/dig"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := reg.Call(ctx, rt, "dnsutil.A", &AArgs{Host: "www.example.com"})
	if err == nil {
		t.Fatal("dnsutil.A canceled ctx returned nil error")
	}
}

// digResolverRunner opens the hasDig trusted-resolution seam.
type digResolverRunner struct {
	path string
	err  error
}

func (r digResolverRunner) Run(context.Context, process.Command) process.CommandResult {
	return process.CommandResult{}
}

func (r digResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

// capabilitylessRunner has no resolver capability.
type capabilitylessRunner struct{}

func (capabilitylessRunner) Run(context.Context, process.Command) process.CommandResult {
	return process.CommandResult{}
}

func TestParseZoneOverwritesAndDuplicatesMatchOracle(t *testing.T) {
	// R103A-GATE-01/02 retained-output accounting under collisions,
	// overwrites, and duplicate rows: directive re-assignment replaces
	// value bytes without new items, an owner written by the A/AAAA
	// form and re-written by the generic form replaces the TARGET/TTL
	// object with the plain string (and back), duplicate NS rows keep
	// appending, and the measured encoding/json size equals the
	// manually built oracle byte for byte (shape and size) — no
	// accounting drift through any overwrite path.
	zone := "$ORIGIN example.com.\n" +
		"$TTL 1D\n" +
		"$TTL 2D\n" + // directive overwrite: replaces value bytes, no item
		"@ IN SOA ns. root. ( 1 2 3 4 5 6 7 8 )\n" + // ORIGIN overwrites the directive value
		"w 60 IN A 192.0.2.1\n" + // owner w.example.com. -> TARGET/TTL object
		"w. y TXT v\n" + // hmm: different owner (w. keeps no suffix); generic TXT bucket
		"w 90 IN A 192.0.2.2\n" + // A-form overwrite of the same owner: replaces entry bytes
		"@ IN NS a.\n" +
		"@ IN NS a.\n" + // duplicate NS row: appended, counted, order kept
		"@ IN NS b.\n"
	value, err := parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &zone})
	if err != nil {
		t.Fatalf("parse_zone overwrites err = %v", err)
	}
	// The single-line SOA with both parens keeps the literal paren
	// tokens (the pinned quirk TestParseZoneSOAPopAndNamedOriginVectors
	// pins), so the fields shift exactly as the pinned source shifts
	// them; the '@' owner was already expanded to the $ORIGIN value.
	want := map[string]any{
		"ORIGIN":  "example.com.",
		"NETWORK": "IN",
		"SOURCE":  "ns.",
		"CONTACT": "root@",
		"SERIAL":  "(",
		"REFRESH": int64(1),
		"RETRY":   int64(2),
		"EXPIRE":  int64(3),
		"MINTTL":  int64(4),
		"TTL":     "2D",
		"A": map[string]any{
			"w.example.com.": map[string]string{"TARGET": "192.0.2.2", "TTL": "90"},
		},
		"TXT": map[string]any{"w.": "v"},
		"NS":  []string{"a.", "a.", "b."},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_zone overwrites =\n%#v\nwant\n%#v", value, want)
	}
	got, merr := json.Marshal(value)
	if merr != nil {
		t.Fatal(merr)
	}
	oracle, merr := json.Marshal(want)
	if merr != nil {
		t.Fatal(merr)
	}
	if len(got) != len(oracle) {
		t.Fatalf("parse_zone overwrites encoded %d bytes, oracle %d", len(got), len(oracle))
	}

	// The A-form -> generic-form -> A-form replacement cycle through
	// the SAME bucket and owner (the generic record "x.o. t A v" puts
	// the owner of bucket "A" into the plain-string form; the next
	// owner-TTL-IN-A record replaces it with the TARGET/TTL object).
	cycle := "$ORIGIN o.\n" +
		"x.o. 60 IN A 192.0.2.1\n" + // A-form: TARGET/TTL object under owner x.o.
		"x.o. t A v\n" + // generic form into the same bucket: owner -> plain string
		"x.o. 61 IN A 192.0.2.3\n" // A-form again: object replaces the string
	value, err = parseZoneFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseZoneArgs{Zone: &cycle})
	if err != nil {
		t.Fatalf("parse_zone cycle err = %v", err)
	}
	bucket := value.(map[string]any)["A"].(map[string]any)
	entry, ok := bucket["x.o."].(map[string]string)
	if !ok || entry["TARGET"] != "192.0.2.3" || entry["TTL"] != "61" {
		t.Fatalf("parse_zone cycle bucket = %#v", bucket)
	}
	if _, merr := json.Marshal(value); merr != nil {
		t.Fatal(merr)
	}
}

func TestParseHostsDuplicatesMatchOracle(t *testing.T) {
	// Duplicate-appended aliases count toward both budgets and keep
	// encounter order; the measured encoding matches the exact oracle.
	inline := "1.2.3.4 a b a\n5.6.7.8 c\n1.2.3.4 b a c\n9.9.9.9\n"
	value, err := parseHostsFunc{}.Execute(context.Background(), &runtime.Runtime{}, &ParseHostsArgs{Hosts: &inline})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"1.2.3.4": {"a", "b", "a", "b", "a", "c"},
		"5.6.7.8": {"c"},
		"9.9.9.9": {},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_hosts duplicates = %#v", value)
	}
	got, merr := json.Marshal(value)
	if merr != nil {
		t.Fatal(merr)
	}
	oracle, merr := json.Marshal(want)
	if merr != nil {
		t.Fatal(merr)
	}
	if len(got) != len(oracle) {
		t.Fatalf("parse_hosts duplicates encoded %d bytes, oracle %d", len(got), len(oracle))
	}
}
