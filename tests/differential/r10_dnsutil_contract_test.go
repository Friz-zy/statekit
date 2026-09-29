//go:build dns_contract

package differential

// R10.3a dnsutil behavioral differential tests, behind the dns_contract
// build tag: the dig delegation vectors run over the real dig family
// with the scripted fake Runner (exact argv, shell-free dispatch, no
// dig binary, no DNS, no network), the parse vectors run over the
// bootstrap registry with MemoryFS fixtures, and the pending-ledger
// vector pins the bounded-slice registration inventory. Every expected
// parse shape was oracle-verified against the pinned
// saltstack/salt/modules/dnsutil.py source executed locally.

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
	execdnsutil "github.com/friz-zy/statekit/modules/exec/dnsutil"
)

// r10DNSUtilPinnedHosts is the pinned tests/pytests/unit/modules/
// test_dnsutil.py parse_hosts fixture (mock_hosts_file).
const r10DNSUtilPinnedHosts = "##\n" +
	"# Host Database\n" +
	"#\n" +
	"# localhost is used to configure the loopback interface\n" +
	"# when the system is booting.  Do not change this entry.\n" +
	"##\n" +
	"127.0.0.1\tlocalhost\n" +
	"255.255.255.255\tbroadcasthost\n" +
	"::1             localhost\n" +
	"fe80::1%lo0\tlocalhost"

// buildR10DNSUtilRuntime registers the real dig and dnsutil families
// over the scripted fake runner (the r10DigRunner/r10DigResolverRunner
// seams from r10_dig_contract_test.go, shared here).
func buildR10DNSUtilRuntime(t *testing.T, runner *r10DigResolverRunner) *runtime.Runtime {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := execdig.Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := execdnsutil.Register(reg); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS(), Runner: runner}
}

// TestR10DNSUtilPinnedSourceVectors runs the pinned
// tests/pytests/unit/modules/test_dnsutil.py vectors (the parse_hosts
// fixture answer and the five _to_seconds vectors) plus the oracle-
// verified parse_zone shapes through the bootstrap registry.
func TestR10DNSUtilPinnedSourceVectors(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rt.FS = runtime.NewMemoryFS()

	hosts := r10DNSUtilPinnedHosts
	value, err := rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{Hosts: &hosts})
	if err != nil {
		t.Fatalf("parse_hosts: %v", err)
	}
	want := map[string][]string{
		"127.0.0.1":       {"localhost"},
		"255.255.255.255": {"broadcasthost"},
		"::1":             {"localhost"},
		"fe80::1%lo0":     {"localhost"},
	}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("parse_hosts pinned fixture = %#v", value)
	}

	// The pinned _to_seconds unit vectors ride the SOA fields (a
	// token containing H/D/W letters enters that unit's branch — the
	// pinned crash quirk — so the unparsable-value vector uses a
	// letter-free token): 2W→604800 (REFRESH), 4H→14400 (RETRY),
	// 1D→86400 (EXPIRE), and the 604801→604800 cap (MINTTL).
	zone := "@ IN SOA a. b. ( 2W 4H 1D 604801 )"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: &zone})
	if err != nil {
		t.Fatalf("parse_zone: %v", err)
	}
	parsed := value.(map[string]any)
	if parsed["REFRESH"] != int64(604800) {
		t.Fatalf("parse_zone REFRESH = %#v, want 604800 (2W)", parsed["REFRESH"])
	}
	if parsed["RETRY"] != int64(14400) {
		t.Fatalf("parse_zone RETRY = %#v, want 14400 (4H)", parsed["RETRY"])
	}
	if parsed["EXPIRE"] != int64(86400) {
		t.Fatalf("parse_zone EXPIRE = %#v, want 86400 (1D)", parsed["EXPIRE"])
	}
	if parsed["MINTTL"] != int64(604800) {
		t.Fatalf("parse_zone MINTTL = %#v, want the 604800 cap (604801)", parsed["MINTTL"])
	}

	// The unparsable plain value answers one week (the pinned except
	// ValueError) and a token whose uppercase contains the unit letter
	// is the pinned ValueError crash position mapped to the fixed
	// value-free error.
	zone = "@ IN SOA a. b. ( 9 zz 4H 1D 604801 )"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: &zone})
	if err != nil {
		t.Fatalf("parse_zone unparsable: %v", err)
	}
	if value.(map[string]any)["RETRY"] != int64(604800) {
		t.Fatalf("parse_zone unparsable RETRY = %#v, want the one-week fallback",
			value.(map[string]any)["RETRY"])
	}
	zone = "@ IN SOA a. b. ( 9 abcdef 4H 1D 604801 )"
	if _, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: &zone}); err == nil {
		t.Fatal("parse_zone D-containing unparsable token must map the pinned ValueError crash")
	}

	// A failed default read answers the pinned result string without
	// touching the host /etc/hosts (the MemoryFS carries none).
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if value != "Error: hosts data was not found" {
		t.Fatalf("parse_hosts default = %#v", value)
	}
}

// TestR10DNSUtilParserBoundsAndMalformedJoins pins the R103A-FINAL-01
// malformed-multiline mapping and the R10.3A-SEC-01 /
// R103A-GATE-01/02 parser ceilings at the bootstrap registry surface
// with exact boundaries and small inputs: the empty '('…')' join
// answers the fixed value-free malformed-zone error with no partial
// result, the shared 1 MiB inline ceiling rejects one byte over, 4096
// hosts rows parse and 4097 reject, the '@'→ORIGIN expansion estimate
// rejects an over-1-MiB expansion before allocation, the complete
// serialized result representation is capped at 4 MiB (the ~17 KiB
// gate-probe zone whose expanded bucket keys and values retain ~8.2 MB
// rejects with the fixed byte error and no partial map), the 8192
// retained nested-item ceiling rejects the 4095 owner-TTL-IN-A fanout
// (12,287 items) with the fixed item error, the R103A-GATE-02
// shape-changing-replacement regressions pin the exact subtree
// replacement (the 8195-item scalar->object gate vector rejects while
// the top-level bucket->directive shrink admits the exact-8192 fill
// that the stale counter falsely rejected), and the
// R103A-FINAL-BYTES-01 exact nested-entry byte boundary accepts a
// nested A/AAAA result whose exact compact encoding is exactly
// 4,194,304 bytes and rejects one encoded byte above before insertion.
// No dig binary, DNS, network, or host file is touched (zero
// dispatch).
func TestR10DNSUtilParserBoundsAndMalformedJoins(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	rt.FS = runtime.NewMemoryFS()

	// R103A-FINAL-01: the multi-line join strips every token; the
	// pinned IndexError maps to the fixed value-free error, no partial
	// result, no panic.
	zone := "(\n)\n"
	value, err := rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: &zone})
	if err == nil || err.Error() != "dnsutil: malformed zone data" {
		t.Fatalf("parse_zone malformed-multiline value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone malformed-multiline partial value = %#v", value)
	}

	// R10.3A-SEC-01 inline ceiling, exact boundary: exactly 1 MiB of
	// comment parses; one byte over rejects value-free.
	hostsAt := strings.Repeat("#", (1<<20)-1) + "\n"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{Hosts: &hostsAt})
	if err != nil {
		t.Fatalf("parse_hosts at-bound: %v", err)
	}
	if hosts, ok := value.(map[string][]string); !ok || len(hosts) != 0 {
		t.Fatalf("parse_hosts at-bound value = %#v", value)
	}
	hostsOver := strings.Repeat("#", 1<<20) + "\n"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{Hosts: &hostsOver})
	if err == nil || err.Error() != "dnsutil: input exceeds limit" {
		t.Fatalf("parse_hosts over-bound value = %#v err = %v", value, err)
	}

	// Input-record ceiling, exact boundary: 4096 rows parse; 4097
	// reject value-free with no partial map.
	rows := func(count int) string {
		var b strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, "10.%d.%d.4 host\n", (i>>8)&0xff, i&0xff)
		}
		return b.String()
	}
	at := rows(4096)
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{Hosts: &at})
	if err != nil {
		t.Fatalf("parse_hosts 4096 rows: %v", err)
	}
	if hosts, ok := value.(map[string][]string); !ok || len(hosts) != 4096 {
		t.Fatalf("parse_hosts 4096 rows value = %#v", value)
	}
	over := rows(4097)
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_hosts",
		&execdnsutil.ParseHostsArgs{Hosts: &over})
	if err == nil || err.Error() != "dnsutil: parser limit exceeded" {
		t.Fatalf("parse_hosts 4097 rows value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_hosts 4097 rows partial value = %#v", value)
	}

	// '@'→ORIGIN expansion guard, exact boundary: a dot-terminated
	// 4096-byte origin with 255 spaced '@' tokens stays within the
	// 1 MiB source ceiling (509 + 255*4095 = 1,044,734 bytes) and
	// parses; 256 tokens (511 + 256*4095 = 1,048,831 bytes) reject
	// before any expansion output is allocated.
	origin := strings.Repeat("o", 4095) + "."
	atOrigin := func(matches int) string {
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
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(atOrigin(255))})
	if err != nil {
		t.Fatalf("parse_zone at-bound expansion: %v", err)
	}
	if _, ok := value.(map[string]any); !ok {
		t.Fatalf("parse_zone at-bound expansion value = %#v", value)
	}
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(atOrigin(256))})
	if err == nil || err.Error() != "dnsutil: input exceeds limit" {
		t.Fatalf("parse_zone over-bound expansion value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone over-bound expansion partial value = %#v", value)
	}

	// R103A-GATE-01 complete-representation byte ceiling: origin =
	// 3999 'a' + dot with 1024 records "x. IN @<i> @" — a ~17 KiB input
	// whose retained answer repeats the 4000-byte origin in every
	// expanded generic-bucket key and value (~8.2 MB of JSON before
	// the fix; the input stays well under the 1 MiB source ceiling).
	// Rejection is the fixed value-free byte error with no partial map.
	gateOrigin := strings.Repeat("a", 3999) + "."
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(gateProbeZone(gateOrigin, 1024))})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone gate-01 value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-01 partial value = %#v", value)
	}
	// An under-ceiling prefix of the same shape parses and its
	// encoding/json size stays within the cap.
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(gateProbeZone(gateOrigin, 400))})
	if err != nil {
		t.Fatalf("parse_zone gate-01 under-limit err = %v", err)
	}
	if encoded, jerr := json.Marshal(value); jerr != nil || len(encoded) > 4<<20 {
		t.Fatalf("parse_zone gate-01 under-limit encoded = %d bytes (err %v)", len(encoded), jerr)
	}

	// R103A-GATE-01 expanded type keys: 1100 distinct "t<i>@" type
	// keys over a 4081-byte origin expand to bucket keys that alone
	// exceed the ceiling; rejection happens before insertion.
	typeOrigin := strings.Repeat("o", 4080) + "."
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(typeProbeZone(typeOrigin, 1100))})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone gate-01 type-keys value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-01 type-keys partial value = %#v", value)
	}

	// R103A-GATE-02 retained nested-item ceiling: 4095 unique
	// owner-TTL-IN-A rows retain 12,287 items — ORIGIN + the A bucket
	// member + owner/TARGET/TTL per row — over the 8192 ceiling while
	// the byte total stays small.
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(itemProbeZone(4095))})
	if err == nil || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("parse_zone gate-02 value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-02 partial value = %#v", value)
	}

	// R103A-GATE-02 shape-changing-replacement regression: $ORIGIN +
	// two generic A strings for x0/x1 + the two owner-TTL-IN-A rewrites
	// of those owners (+2 items each) + 2729 fresh owner-TTL-IN-A rows
	// retain 8195 final items (ORIGIN + the A bucket member + 2731
	// three-item owner subtrees), three over the 8192 ceiling — the
	// pre-fix budget reserved zero items for the scalar->TARGET/TTL
	// replacements and let the 8195-item result escape at a counter
	// reading of 8191. The separate 2730-row structure without
	// replacements retains exactly 8192 items and parses.
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(gate02ReplacementProbeZone())})
	if err == nil || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("parse_zone gate-02 replacement value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-02 replacement partial value = %#v", value)
	}
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(itemProbeZone(2730))})
	if err != nil {
		t.Fatalf("parse_zone gate-02 exact-8192 err = %v", err)
	}
	if bucket, ok := value.(map[string]any)["A"].(map[string]any); !ok || len(bucket) != 2730 {
		t.Fatalf("parse_zone gate-02 exact-8192 bucket = %#v", value)
	}

	// R103A-GATE-02 top-level replacement (the count shrinks): a
	// 100-owner TXT bucket is flattened by the $TXT directive (the
	// 101-item subtree becomes one item), and the exact fill — 2729
	// fresh owner-TTL-IN-A rows plus one two-item generic TXT2 record
	// landing on exactly 8192 items — parses; the pre-fix budget never
	// subtracted the removed descendants and falsely rejected the same
	// zone mid-fill. One TXT2 owner more still rejects.
	shrink := "$ORIGIN example.com.\n"
	for i := 0; i < 100; i++ {
		shrink += fmt.Sprintf("t%d. IN TXT v\n", i)
	}
	shrink += "$TXT s\n" + itemProbeZone(2729) + "z. IN TXT2 q\n"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(shrink)})
	if err != nil {
		t.Fatalf("parse_zone gate-02 shrink err = %v", err)
	}
	if parsed, ok := value.(map[string]any); !ok || parsed["TXT"] != "s" {
		t.Fatalf("parse_zone gate-02 shrink TXT = %#v", value)
	}
	shrinkOver := "$ORIGIN example.com.\n"
	for i := 0; i < 100; i++ {
		shrinkOver += fmt.Sprintf("t%d. IN TXT v\n", i)
	}
	shrinkOver += "$TXT s\n" + itemProbeZone(2729) + "z. IN TXT2 q\nz2. IN TXT2 q2\n"
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(shrinkOver)})
	if err == nil || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("parse_zone gate-02 shrink-over value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-02 shrink-over partial value = %#v", value)
	}

	// R103A-FINAL-BYTES-01 exact nested-entry byte boundary: the
	// nested TARGET/TTL object contributes exactly 18 structural bytes
	// (not 19), so a nested A/AAAA zone whose exact compact
	// encoding/json result is exactly 4,194,304 bytes parses (asserted
	// against an independently built oracle map), and exactly one
	// encoded byte above rejects before insertion with the fixed
	// value-free byte error and no partial map.
	atZone, overZone := nestedExactByteBoundaryZone(t)
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(atZone)})
	if err != nil {
		t.Fatalf("parse_zone exact-4MiB err = %v", err)
	}
	if encoded, jerr := json.Marshal(value); jerr != nil || len(encoded) != 4<<20 {
		t.Fatalf("parse_zone exact-4MiB encoded = %d bytes (err %v), want exactly %d", len(encoded), jerr, 4<<20)
	}
	value, err = rt.Exec.Call(context.Background(), rt, "dnsutil.parse_zone",
		&execdnsutil.ParseZoneArgs{Zone: ptrString(overZone)})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone one-byte-over value = %#v err = %v", value, err)
	}
	if value != nil {
		t.Fatalf("parse_zone one-byte-over partial value = %#v", value)
	}
}

// gateProbeZone builds the R103A-GATE-01 probe: a $ORIGIN directive
// over origin followed by records "x. IN @<i> @" whose '@'→ORIGIN
// expansion repeats origin in the generic bucket key and the value.
func gateProbeZone(origin string, records int) string {
	var b strings.Builder
	b.WriteString("$ORIGIN ")
	b.WriteString(origin)
	b.WriteString("\n")
	for i := 0; i < records; i++ {
		fmt.Fprintf(&b, "x. IN @%d @\n", i)
	}
	return b.String()
}

// typeProbeZone builds the R103A-GATE-01 expanded-type-key probe:
// records "x. y t<i>@ v" create distinct bucket keys "t<i>"+origin.
func typeProbeZone(origin string, records int) string {
	var b strings.Builder
	b.WriteString("$ORIGIN ")
	b.WriteString(origin)
	b.WriteString("\n")
	for i := 0; i < records; i++ {
		fmt.Fprintf(&b, "x. y t%d@ v\n", i)
	}
	return b.String()
}

// itemProbeZone builds the R103A-GATE-02 probe: records unique
// owner-TTL-IN-A rows, each retaining three nested items (owner,
// TARGET, TTL) beside the ORIGIN and A bucket members.
func itemProbeZone(records int) string {
	var b strings.Builder
	b.WriteString("$ORIGIN example.com.\n")
	for i := 0; i < records; i++ {
		fmt.Fprintf(&b, "h%d 60 IN A 127.0.0.1\n", i)
	}
	return b.String()
}

// gate02ReplacementProbeZone builds the R103A-GATE-02
// shape-changing-replacement probe: two generic A strings under owners
// x0/x1, the two owner-TTL-IN-A rewrites of those owners (each
// scalar->TARGET/TTL replacement gains the two nested members), and
// 2729 fresh owner-TTL-IN-A rows — 8195 final retained items, three
// over the 8192 ceiling.
func gate02ReplacementProbeZone() string {
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

// nestedExactByteBoundaryZone locates, against an independently built
// encoding/json oracle, the padded nested A/AAAA zone whose exact
// compact result encoding is exactly 4,194,304 bytes
// (R103A-FINAL-BYTES-01: the nested TARGET/TTL object contributes 18
// structural bytes, not 19) and returns the at-bound zone plus the
// one-encoded-byte-over zone. Each pad 'a' grows the exact encoding by
// exactly one byte, so the size passes through every integer across
// the bracketed range; keys and values carry quote, backslash,
// control, and HTML-triplet escape classes and the oracle counts every
// map-member delimiter, colon, and comma.
func nestedExactByteBoundaryZone(t *testing.T) (at, over string) {
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
	if encoded(lo) > 4<<20 || encoded(hi) <= 4<<20 {
		t.Fatalf("exact byte boundary not bracketed: size(0)=%d size(%d)=%d", encoded(lo), hi, encoded(hi))
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if encoded(mid) <= 4<<20 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if pad := lo - 1; encoded(pad) != 4<<20 || encoded(pad+1) != 4<<20+1 {
		t.Fatalf("exact byte boundary not located: size(%d)=%d size(%d)=%d",
			pad, encoded(pad), pad+1, encoded(pad+1))
	}
	return build(lo - 1), build(lo)
}

// ptrString keeps the inline literals addressable.
func ptrString(v string) *string { return &v }

// TestR10DNSUtilDelegationArgv drives the delegation through the real
// dig family with the scripted fake Runner: the exact argument
// pass-through becomes the exact fixed dig argv with the exact
// environment allowlist, and the dig result shape reaches the dnsutil
// caller unchanged.
func TestR10DNSUtilDelegationArgv(t *testing.T) {
	runner := &r10DigResolverRunner{inner: &r10DigRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {
			{Stdout: []byte("74.125.193.104\n74.125.193.105\n"), ExitCode: 0},
		},
	}}, path: "/usr/bin/dig"}
	rt := buildR10DNSUtilRuntime(t, runner)

	value, err := rt.Exec.Call(context.Background(), rt, "dnsutil.A",
		&execdnsutil.AArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatalf("dnsutil.A: %v", err)
	}
	if !reflect.DeepEqual(value, []string{"74.125.193.104", "74.125.193.105"}) {
		t.Fatalf("dnsutil.A value = %#v", value)
	}
	cmd := runner.inner.commands[0]
	joined := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
	if joined != "/usr/bin/dig -r +short -q www.google.com -t A" {
		t.Fatalf("dnsutil.A argv = %q", joined)
	}
	if cmd.Shell {
		t.Fatal("dnsutil.A dispatched through a shell")
	}
	wantEnv := []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
	if !reflect.DeepEqual(cmd.Env, wantEnv) {
		t.Fatalf("dnsutil.A env = %q, want %q", cmd.Env, wantEnv)
	}
}

// TestR10DNSUtilGateAndPendingLedger pins the availability gate matrix
// and the bounded-slice registration inventory: the gate answers the
// pinned unavailable string with zero dispatch, the registry-miss
// class answers the fixed value-free error, and exactly the eight
// R10.3a public names are registered while hosts_append, hosts_remove,
// and serial stay absent.
func TestR10DNSUtilGateAndPendingLedger(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := execdnsutil.Register(reg); err != nil {
		t.Fatal(err)
	}

	// Gate matrix over a registry without dig functions: a failing
	// resolver answers the pinned string for every dig-backed name
	// with zero dispatch.
	gated := &r10DigResolverRunner{inner: &r10DigRunner{}, err: context.DeadlineExceeded}
	rt := &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS(), Runner: gated}
	for name, args := range map[string]any{
		"dnsutil.A":        &execdnsutil.AArgs{Host: "www.google.com"},
		"dnsutil.AAAA":     &execdnsutil.AAAAArgs{Host: "www.google.com"},
		"dnsutil.NS":       &execdnsutil.NSArgs{Domain: "example.com"},
		"dnsutil.SPF":      &execdnsutil.SPFArgs{Domain: "example.com"},
		"dnsutil.MX":       &execdnsutil.MXArgs{Domain: "example.com"},
		"dnsutil.check_ip": &execdnsutil.CheckIPArgs{Addr: "127.0.0.1"},
	} {
		value, err := rt.Exec.Call(context.Background(), rt, name, args)
		if err != nil || value != "This function requires dig, which is not currently available" {
			t.Fatalf("%s gated = %#v err = %v", name, value, err)
		}
	}
	if len(gated.inner.commands) != 0 {
		t.Fatalf("gated dispatches = %d", len(gated.inner.commands))
	}

	// Registry miss with the gate open: one fixed value-free error
	// that carries no query value.
	open := &r10DigResolverRunner{inner: &r10DigRunner{}, path: "/usr/bin/dig"}
	rt = &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS(), Runner: open}
	_, err := rt.Exec.Call(context.Background(), rt, "dnsutil.A", &execdnsutil.AArgs{Host: "www.google.com"})
	if err == nil || !strings.Contains(err.Error(), "dnsutil: dig function unavailable") {
		t.Fatalf("dnsutil.A registry-miss err = %v", err)
	}
	if strings.Contains(err.Error(), "www.google.com") {
		t.Fatalf("registry-miss error leaks the query value: %q", err)
	}

	// Bounded-slice inventory: exactly the eight public names exist;
	// the three pending names stay unregistered everywhere.
	full, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"dnsutil.parse_hosts", "dnsutil.parse_zone", "dnsutil.check_ip",
		"dnsutil.A", "dnsutil.AAAA", "dnsutil.NS", "dnsutil.SPF", "dnsutil.MX",
	} {
		if _, ok := full.Exec.Get(name); !ok {
			t.Fatalf("missing %s", name)
		}
	}
	for _, pending := range []string{"dnsutil.hosts_append", "dnsutil.hosts_remove", "dnsutil.serial"} {
		if _, ok := full.Exec.Get(pending); ok {
			t.Fatalf("pending %s unexpectedly registered", pending)
		}
	}
}
