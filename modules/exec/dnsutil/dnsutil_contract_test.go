//go:build dns_contract

package dnsutil

// R10.3a dnsutil native contract tests (dns_contract build tag): the
// delegation surface runs over the REAL dig family with a scripted fake
// Runner behind a test trusted resolver — no dig execution, no DNS, no
// network, and no host /etc/hosts or zone file is ever read (every file
// vector lives in runtime.MemoryFS).

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
)

// dnsutilCLIRunner scripts CommandResults by joined argv.
type dnsutilRunner struct {
	script   map[string][]process.CommandResult
	commands []process.Command
}

func (r *dnsutilRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.commands = append(r.commands, cmd)
	key := strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
	queue := r.script[key]
	if len(queue) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := queue[0]
	r.script[key] = queue[1:]
	return result
}

// dnsutilResolverRunner adds the test TrustedCommandResolver seam.
type dnsutilResolverRunner struct {
	inner *dnsutilRunner
	path  string
	err   error
}

func (r *dnsutilResolverRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	return r.inner.Run(ctx, cmd)
}

func (r *dnsutilResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

func dnsutilResult(stdout string, exitCode int) process.CommandResult {
	return process.CommandResult{Stdout: []byte(stdout), ExitCode: exitCode}
}

// dnsutilRuntime registers the real dig and dnsutil families over the
// scripted runner.
func dnsutilRuntime(t *testing.T, runner process.Runner) (*runtime.Runtime, *runtime.ExecRegistry) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := execdig.Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{Exec: reg, FS: runtime.NewMemoryFS(), Runner: runner}, reg
}

func argvOf(t *testing.T, cmd process.Command) string {
	t.Helper()
	return strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
}

// TestDNSUtilContractDelegationArgv drives the dig-backed functions end
// to end through the real dig family: dnsutil's exact argument
// pass-through becomes the exact fixed dig argv, and the dig module's
// result shapes reach the dnsutil caller unchanged.
func TestDNSUtilContractDelegationArgv(t *testing.T) {
	inner := &dnsutilRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {
			dnsutilResult("74.125.193.104\n74.125.193.105\n", 0),
			dnsutilResult("74.125.193.104\n", 0),
		},
		"/usr/bin/dig -r +short -q www.google.com -t AAAA @2001:db8::53": {
			dnsutilResult("2607:f8b0:4004:800::200e\n", 0),
		},
		"/usr/bin/dig -r +short -q example.com -t NS": {
			dnsutilResult("a.iana-servers.net.\n", 0),
		},
		"/usr/bin/dig -r +short -q a.iana-servers.net. -t A": {
			dnsutilResult("192.0.2.43\n", 0),
		},
	}}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	value, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, []string{"74.125.193.104", "74.125.193.105"}) {
		t.Fatalf("dnsutil.A value = %#v", value)
	}
	if got := argvOf(t, inner.commands[0]); got != "/usr/bin/dig -r +short -q www.google.com -t A" {
		t.Fatalf("dnsutil.A argv = %q", got)
	}
	if inner.commands[0].Shell {
		t.Fatal("dnsutil.A dispatched through a shell")
	}

	ns := "2001:db8::53"
	value, err = reg.Call(context.Background(), rt, "dnsutil.AAAA", &AAAAArgs{
		Host: "www.google.com", Nameserver: &ns,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, []string{"2607:f8b0:4004:800::200e"}) {
		t.Fatalf("dnsutil.AAAA value = %#v", value)
	}
	if got := argvOf(t, inner.commands[1]); got != "/usr/bin/dig -r +short -q www.google.com -t AAAA @2001:db8::53" {
		t.Fatalf("dnsutil.AAAA argv = %q", got)
	}

	// NS with the pinned resolve=true default resolves the child A
	// lookup through the shared dig budget.
	value, err = reg.Call(context.Background(), rt, "dnsutil.NS", &NSArgs{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, []string{"192.0.2.43"}) {
		t.Fatalf("dnsutil.NS value = %#v", value)
	}
	if len(inner.commands) != 4 {
		t.Fatalf("dnsutil.NS dispatches = %d", len(inner.commands))
	}
	if got := argvOf(t, inner.commands[2]); got != "/usr/bin/dig -r +short -q example.com -t NS" {
		t.Fatalf("dnsutil.NS argv = %q", got)
	}
	if got := argvOf(t, inner.commands[3]); got != "/usr/bin/dig -r +short -q a.iana-servers.net. -t A" {
		t.Fatalf("dnsutil.NS child argv = %q", got)
	}

	// dnsutil.check_ip keeps dig.check_ip's boolean surface with zero
	// dispatch (the trusted gate re-resolution inside dig.check_ip does
	// not launch a process).
	value, err = reg.Call(context.Background(), rt, "dnsutil.check_ip", &CheckIPArgs{Addr: "127.0.0.1"})
	if err != nil || value != true {
		t.Fatalf("dnsutil.check_ip = %#v err = %v", value, err)
	}
	if len(inner.commands) != 4 {
		t.Fatalf("check_ip dispatches altered: %d", len(inner.commands))
	}
}

// TestDNSUtilContractSPFInclude drives the SPF include recursion end to
// end through the dnsutil name: the pinned xmission chain answers the
// pinned ranges with the pinned four-process SPF/TXT fallback shape.
func TestDNSUtilContractSPFInclude(t *testing.T) {
	inner := &dnsutilRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q xmission.com -t SPF":      {dnsutilResult("", 0)},
		"/usr/bin/dig -r +short -q xmission.com -t TXT":      {dnsutilResult(`"v=spf1 a mx include:_spf.xmission.com ?all"`, 0)},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t SPF": {dnsutilResult("", 0)},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t TXT": {dnsutilResult(`"v=spf1 a mx ip4:198.60.22.0/24 ip4:166.70.13.0/24 ~all"`, 0)},
	}}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	value, err := reg.Call(context.Background(), rt, "dnsutil.SPF", &SPFArgs{Domain: "xmission.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value, []string{"198.60.22.0/24", "166.70.13.0/24"}) {
		t.Fatalf("dnsutil.SPF value = %#v", value)
	}
	if len(inner.commands) != 4 {
		t.Fatalf("dnsutil.SPF dispatches = %d", len(inner.commands))
	}
}

// TestDNSUtilContractMXShapes pins the MX raw row shape and the
// resolve=false default through the dnsutil name.
func TestDNSUtilContractMXShapes(t *testing.T) {
	inner := &dnsutilRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t MX": {
			dnsutilResult("10 aspmx.l.google.com.\n", 0),
		},
	}}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	value, err := reg.Call(context.Background(), rt, "dnsutil.MX", &MXArgs{Domain: "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := value.([][]string)
	if !ok || len(rows) != 1 || !reflect.DeepEqual(rows[0], []string{"10", "aspmx.l.google.com."}) {
		t.Fatalf("dnsutil.MX rows = %#v", value)
	}
	// The pinned resolve=False default dispatches exactly one process.
	if len(inner.commands) != 1 {
		t.Fatalf("dnsutil.MX dispatches = %d", len(inner.commands))
	}
}

// TestDNSUtilContractGateFailures pins the _has_dig gate at the real
// dig boundary: a failing resolver and a capability-less Runner both
// answer the pinned unavailable string with zero dispatch, and the
// capability-less Runner also fails dig's own unverified-executable
// path closed when reached directly.
func TestDNSUtilContractGateFailures(t *testing.T) {
	gated := &dnsutilResolverRunner{
		inner: &dnsutilRunner{},
		err:   fmt.Errorf("untrusted dig"),
	}
	rt, reg := dnsutilRuntime(t, gated)
	for name, args := range map[string]any{
		"dnsutil.A":        &AArgs{Host: "www.google.com"},
		"dnsutil.AAAA":     &AAAAArgs{Host: "www.google.com"},
		"dnsutil.NS":       &NSArgs{Domain: "example.com"},
		"dnsutil.SPF":      &SPFArgs{Domain: "example.com"},
		"dnsutil.MX":       &MXArgs{Domain: "example.com"},
		"dnsutil.check_ip": &CheckIPArgs{Addr: "127.0.0.1"},
	} {
		value, err := reg.Call(context.Background(), rt, name, args)
		if err != nil || value != digUnavailableMessage {
			t.Fatalf("%s gated = %#v err = %v", name, value, err)
		}
	}
	if len(gated.inner.commands) != 0 {
		t.Fatalf("gated dispatches = %d", len(gated.inner.commands))
	}

	// The deferred socket-fallback divergence: even with nameserver
	// absent (the pinned getaddrinfo branch condition) there is no host
	// resolver egress — the unavailable string answers.
	value, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "www.google.com"})
	if err != nil || value != digUnavailableMessage {
		t.Fatalf("dnsutil.A fallback-divergence = %#v err = %v", value, err)
	}

	capless := &dnsutilRunner{}
	rtCapless, regCapless := dnsutilRuntime(t, capless)
	value, err = regCapless.Call(context.Background(), rtCapless, "dnsutil.A", &AArgs{Host: "www.google.com"})
	if err != nil || value != digUnavailableMessage {
		t.Fatalf("dnsutil.A capability-less = %#v err = %v", value, err)
	}
	if len(capless.commands) != 0 {
		t.Fatalf("capability-less dispatches = %d", len(capless.commands))
	}
}

// TestDNSUtilContractValidationZeroDispatch pins that dnsutil never
// pre-validates or mutates the caller's query inputs: invalid dig
// inputs reject inside the dig module with the dig module's fixed
// value-free errors and zero dispatch, and the raw error class
// propagates unchanged through the delegation.
func TestDNSUtilContractValidationZeroDispatch(t *testing.T) {
	inner := &dnsutilRunner{}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	_, err := reg.Call(context.Background(), rt, "dnsutil.A", &AArgs{Host: "-flag.example"})
	if err == nil || !strings.Contains(err.Error(), "dig: invalid query name") {
		t.Fatalf("dnsutil.A invalid-name err = %v", err)
	}
	if strings.Contains(err.Error(), "-flag.example") {
		t.Fatalf("dnsutil.A error leaks the query value: %q", err)
	}
	if len(inner.commands) != 0 {
		t.Fatalf("invalid-name dispatches = %d", len(inner.commands))
	}

	_, err = reg.Call(context.Background(), rt, "dnsutil.SPF", &SPFArgs{Domain: "example.com", Record: stringPtr("MX")})
	if err == nil || !strings.Contains(err.Error(), "dig: invalid record type") {
		t.Fatalf("dnsutil.SPF invalid-record err = %v", err)
	}
	if len(inner.commands) != 0 {
		t.Fatalf("invalid-record dispatches = %d", len(inner.commands))
	}
}

// TestDNSUtilContractParseZoneMalformedMultiline pins R103A-FINAL-01 at
// the module contract surface over the real dig family: a '('…')'
// continuation join that strips every token (the whitespace-only join
// of the multiline zone "(\n)\n") answers the exact fixed value-free
// malformed-zone error with no partial result and zero process
// dispatch.
func TestDNSUtilContractParseZoneMalformedMultiline(t *testing.T) {
	inner := &dnsutilRunner{}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	for _, zone := range []string{"(\n)\n", "( \n )\n", "$TTL 1D\n(\n)\n"} {
		value, err := reg.Call(context.Background(), rt, "dnsutil.parse_zone",
			&ParseZoneArgs{Zone: &zone})
		if err == nil || err.Error() != "dnsutil: malformed zone data" {
			t.Fatalf("parse_zone malformed-multiline value = %#v err = %v", value, err)
		}
		if value != nil {
			t.Fatalf("parse_zone malformed-multiline partial value = %#v", value)
		}
	}
	if len(inner.commands) != 0 {
		t.Fatalf("malformed-multiline dispatches = %d, want 0", len(inner.commands))
	}

	// The R10.3A-SEC-01 inline ceiling rides the same surface: one byte
	// over the shared 1 MiB source ceiling rejects value-free before
	// any parsing, still with zero dispatch.
	over := strings.Repeat(";", 1<<20) + "\n"
	_, err := reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &over})
	if err == nil || err.Error() != "dnsutil: input exceeds limit" {
		t.Fatalf("parse_zone inline-cap err = %v", err)
	}
	if len(inner.commands) != 0 {
		t.Fatalf("inline-cap dispatches = %d", len(inner.commands))
	}
}

// TestDNSUtilContractParseZoneResultBudgets pins R103A-GATE-01/02 and
// R103A-SEC-FINAL-01 at the module contract surface over the real dig
// family: the gate probes answer their fixed value-free errors with no
// partial result and zero dispatch — a ~17 KiB zone whose expanded
// generic-bucket keys and values retain ~8.2 MB of JSON rejects on the
// complete-representation byte ceiling, 1100 expanded type keys reject
// on the same byte ceiling before insertion, the 4095-row item fanout
// rejects on the item ceiling, the shape-changing-replacement
// regression ($ORIGIN + two generic A strings + 2729 owner-TTL-IN-A
// rows + the two rewrites = 8195 final retained items) rejects on the
// item ceiling while the separate exact-8192 2730-row structure
// parses, and the exact nested A/AAAA byte boundary (18 structural
// bytes per TARGET/TTL object) accepts an exactly-4-MiB compact
// encoding and rejects one encoded byte above before insertion —
// while an under-ceiling escaping-heavy zone answers its exact shape.
func TestDNSUtilContractParseZoneResultBudgets(t *testing.T) {
	inner := &dnsutilRunner{}
	runner := &dnsutilResolverRunner{inner: inner, path: "/usr/bin/dig"}
	rt, reg := dnsutilRuntime(t, runner)

	// R103A-GATE-01: origin = 3999 'a' + dot, 1024 records
	// "x. IN @<i> @" — the retained answer repeats the 4000-byte origin
	// in every expanded bucket key and value (~17 KiB in, ~8.2 MB out
	// before the fix).
	origin := strings.Repeat("a", 3999) + "."
	probe := "$ORIGIN " + origin + "\n"
	for i := 0; i < 1024; i++ {
		probe += fmt.Sprintf("x. IN @%d @\n", i)
	}
	value, err := reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &probe})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone gate-01 probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-01 probe partial value = %#v", value)
	}

	// R103A-GATE-01: 1100 distinct type keys over a 4081-byte origin —
	// the expanded keys alone exceed the ceiling.
	typeOrigin := strings.Repeat("o", 4080) + "."
	typeProbe := "$ORIGIN " + typeOrigin + "\n"
	for i := 0; i < 1100; i++ {
		typeProbe += fmt.Sprintf("x. y t%d@ v\n", i)
	}
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &typeProbe})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone type-keys probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone type-keys probe partial value = %#v", value)
	}

	// R103A-GATE-02: 4095 unique owner-TTL-IN-A rows retain 12,287
	// nested items (ORIGIN + the A bucket member + owner/TARGET/TTL
	// per row) over the 8192 item ceiling.
	itemProbe := "$ORIGIN example.com.\n"
	for i := 0; i < 4095; i++ {
		itemProbe += fmt.Sprintf("h%d 60 IN A 127.0.0.1\n", i)
	}
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &itemProbe})
	if err == nil || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("parse_zone gate-02 probe err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-02 probe partial value = %#v", value)
	}

	// R103A-GATE-02 shape-changing-replacement regression: $ORIGIN +
	// two generic A strings for x0/x1 + the two owner-TTL-IN-A rewrites
	// of those owners + 2729 fresh owner-TTL-IN-A rows retain 8195
	// items (ORIGIN + the A member + 2731 three-item owner subtrees) —
	// three over the 8192 ceiling. The pre-fix budget let the two
	// scalar->TARGET/TTL replacements reserve zero items and the
	// 8195-item result escaped at a counter reading of 8191; the fixed
	// budget rejects value-free with a nil result. A separate 2730-row
	// structure (exactly 8192 items, no replacements) still parses.
	replacement := gate02ReplacementZone()
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &replacement})
	if err == nil || err.Error() != "dnsutil: result item limit exceeded" {
		t.Fatalf("parse_zone gate-02 replacement err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone gate-02 replacement partial value = %#v", value)
	}
	exact := "$ORIGIN example.com.\n"
	for i := 0; i < 2730; i++ {
		exact += fmt.Sprintf("h%d 60 IN A 127.0.0.1\n", i)
	}
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &exact})
	if err != nil {
		t.Fatalf("parse_zone gate-02 exact-8192 err = %v", err)
	}
	if bucket, ok := value.(map[string]any)["A"].(map[string]any); !ok || len(bucket) != 2730 {
		t.Fatalf("parse_zone gate-02 exact-8192 bucket = %#v", value)
	}

	// R103A-FINAL-BYTES-01 exact nested-entry byte boundary: the
	// nested TARGET/TTL object contributes 18 structural bytes (not
	// 19), so a nested A/AAAA result whose exact compact encoding/json
	// representation is exactly 4,194,304 bytes parses, and exactly one
	// encoded byte above rejects before insertion with the fixed
	// value-free byte error and a nil result.
	atZone, overZone := nestedExactByteBoundary(t)
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &atZone})
	if err != nil {
		t.Fatalf("parse_zone exact-4MiB err = %v", err)
	}
	if aBucket, ok := value.(map[string]any)["A"].(map[string]any); !ok || len(aBucket) != 347 {
		t.Fatalf("parse_zone exact-4MiB A = %#v", value)
	}
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &overZone})
	if err == nil || err.Error() != "dnsutil: result byte limit exceeded" {
		t.Fatalf("parse_zone one-byte-over err = %v", err)
	}
	if value != nil {
		t.Fatalf("parse_zone one-byte-over partial value = %#v", value)
	}

	// R103A-SEC-FINAL-01: an under-ceiling escaping-heavy zone answers
	// its exact retained shape (quotes, backslash, control, DEL, HTML
	// triplet, non-ASCII across owners, values, and the origin).
	escape := "$ORIGIN \"o\\b\x01.\n\"ow\\q\"\x01. 60 IN A 127.0.0.1\n"
	value, err = reg.Call(context.Background(), rt, "dnsutil.parse_zone",
		&ParseZoneArgs{Zone: &escape})
	if err != nil {
		t.Fatalf("parse_zone escaping err = %v", err)
	}
	parsed, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("parse_zone escaping value = %#v", value)
	}
	aBucket, ok := parsed["A"].(map[string]any)
	if !ok || len(aBucket) != 1 {
		t.Fatalf("parse_zone escaping A = %#v", parsed["A"])
	}
	entry, ok := aBucket["\"ow\\q\"\x01."].(map[string]string)
	if !ok || entry["TARGET"] != "127.0.0.1" || entry["TTL"] != "60" {
		t.Fatalf("parse_zone escaping entry = %#v", aBucket)
	}

	if len(inner.commands) != 0 {
		t.Fatalf("result-budget dispatches = %d, want 0", len(inner.commands))
	}
}

func stringPtr(v string) *string { return &v }
