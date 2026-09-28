//go:build dns_contract

package dig

// Native dig contract tests. The whole file carries the dns_contract
// build tag so the repo's default host CI (`go test ./...`) does not
// execute it: every vector runs against a scripted fake Runner and no
// test resolves DNS, executes the dig binary, or touches the network.
// The local quality gate runs this file with -tags=dns_contract.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// ---------------------------------------------------------------------------
// fake Runner (the availability seam)

// digFakeRunner scripts CommandResults by joined argv, mirroring the
// pinned SpfValues fixture: unmatched argv answers a successful empty
// stdout. It deliberately exposes no capability of its own; tests that
// want dispatch wrap it in digResolverRunner so the trusted-resolution
// gate opens against a synthetic absolute path, and the vectors in
// TestDigRunnerWithoutCapabilityFailsClosed pin that a bare
// capability-less Runner never reaches a dispatch (no LookPath, no
// bare-name PATH fallback).
type digFakeRunner struct {
	script   map[string][]process.CommandResult
	commands []process.Command
}

func (r *digFakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
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

// digResolverRunner adds a test TrustedCommandResolver seam to any fake
// Runner: path and err drive ResolveTrustedCommand ("dig" only), so the
// trusted native boundary is exercisable without any real binary.
type digResolverRunner struct {
	inner interface {
		Run(context.Context, process.Command) process.CommandResult
	}
	path string
	err  error
}

func (r *digResolverRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	return r.inner.Run(ctx, cmd)
}

func (r *digResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

// fakeDigPath is the synthetic trusted dig path every scripted test
// resolver answers: an absolute path string only — no test ever
// resolves through, stats, or executes a real dig binary.
const fakeDigPath = "/usr/bin/dig"

// wantDigEnv is the exact command environment allowlist a dig dispatch
// must carry (no inherited parent environment).
var wantDigEnv = []string{
	"HOME=/nonexistent",
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/bin:/bin",
	"TZ=UTC",
}

func digResult(stdout string, exitCode int) process.CommandResult {
	return process.CommandResult{Stdout: []byte(stdout), ExitCode: exitCode}
}

func newDigRuntime(script map[string][]process.CommandResult) (*runtime.Runtime, *digFakeRunner) {
	// Clone the queues: several vectors reuse one scripted map across
	// fresh runtimes and each runtime must see a full queue.
	cloned := make(map[string][]process.CommandResult, len(script))
	for key, queue := range script {
		cloned[key] = append([]process.CommandResult(nil), queue...)
	}
	runner := &digFakeRunner{script: cloned}
	// The default test runtime opens the trusted-resolution gate over
	// the synthetic absolute path; scripted keys are joined argv and
	// therefore start with fakeDigPath.
	rt := &runtime.Runtime{Runner: &digResolverRunner{inner: runner, path: fakeDigPath}, FS: runtime.NewMemoryFS()}
	return rt, runner
}

func digString(v string) *string { return &v }
func digBool(v bool) *bool       { return &v }

// lastArgv returns the argv of the nth dispatched command (0-based).
func argvOf(t *testing.T, runner *digFakeRunner, n int) []string {
	t.Helper()
	if n >= len(runner.commands) {
		t.Fatalf("dispatch %d missing (have %d)", n, len(runner.commands))
	}
	cmd := runner.commands[n]
	return append([]string{cmd.Name}, cmd.Args...)
}

// ---------------------------------------------------------------------------
// check_ip

func TestDigCheckIPPinnedVectors(t *testing.T) {
	vectors := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"1111:2222:3333:4444:5555:6666:7777:8888", true},
		{"2607:fa18:0:3::4", true},
		{"-127.0.0.1", false},
		{"", false},
		// Prefix ranges: IPv4 1..32, IPv6 8..128, no host-bit
		// alignment (the address half is only a literal check).
		{"192.168.0.0/24", true},
		{"74.125.193.104/31", true},
		{"10.0.0.1/1", true},
		{"10.0.0.1/0", false},
		{"10.0.0.1/32", true},
		{"10.0.0.1/33", false},
		{"10.0.0.1/ 24 ", true}, // Python int() strips whitespace
		{"10.0.0.1/+24", true},  // and accepts a sign
		{"10.0.0.1/-24", false},
		{"10.0.0.1/abc", false},
		{"10.0.0.1/", false},
		// Python base-10 int() grammar (R102-F2): Unicode Nd digits,
		// single underscores strictly between digits, outer int()
		// whitespace — ASCII whitespace plus non-ASCII Python spaces.
		{"192.0.2.1/2_4", true},
		{"192.0.2.1/２４", true}, // fullwidth digits parse as 24
		{"192.0.2.1/٢٤", true}, // Arabic-Indic digits parse as 24
		{"2001:db8::/3_2", true},
		{"192.0.2.1/_24", false},
		{"192.0.2.1/24_", false},
		{"192.0.2.1/2__4", false},
		{"192.0.2.1/2_4_", false},
		{"192.0.2.1/+_24", false},
		{"192.0.2.1/2_4x", false},
		{"192.0.2.1/2 4", false}, // interior whitespace is not stripped
		// U+001C..U+001F are str.isspace() whitespace (rstrip/split
		// keep them) but int() rejects them: int('\x1c24\x1f') raises
		// ValueError in the runtime oracle (R102-F2 correction).
		{"192.0.2.1/\x1c24\x1f", false},
		{"192.0.2.1/\x1d24", false},
		{"192.0.2.1/24\x1e", false},
		{"192.0.2.1/　24", true}, // U+3000 ideographic space: int() accepts it
		{"192.0.2.1/\u00a024", true},
		{"192.0.2.1/\r\n24\t\v\f ", true}, // the full ASCII whitespace set
		{"192.0.2.1/+000024", true},
		{"::1/1_2_8", true},
		{"192.0.2.1/999999999999999999999999", false}, // magnitude fails the range like Python
		{"2001:db8::/32", true},
		{"::1/8", true},
		{"::1/7", false},
		{"::1/128", true},
		{"::1/129", false},
		// rsplit on the LAST slash only: the address half must be a
		// bare literal.
		{"1.2.3.4/5/6", false},
		{"::1/24/6", false},
		// Python ip_address semantics over netip (R102-F2).
		{"010.1.1.1", false},      // leading-zero octets invalid
		{"127.1", false},          // short v4 invalid
		{"1.2.3.4%eth0", false},   // zoned IPv4 invalid
		{"fe80::1%eth0", true},    // scoped IPv6 valid (Python >= 3.9)
		{"fe80::1%eth0/64", true}, // zoned literal keeps the v6 ranges
		// R102-BACKEND-FINAL-01: Python ip_address rejects IPv6 scope
		// text with more than one percent delimiter while Go
		// netip.ParseAddr accepts it, so the shared guard rejects more
		// than one '%' before parsing (the address half before the last
		// "/" is guarded; a valid single zone stays accepted above).
		{"fe80::1%eth0%extra", false},
		{"fe80::1%%eth0", false},
		{"fe80::1%eth0%extra%more", false},
		{"fe80::1%eth0%extra/64", false}, // the guard covers the address half only
		{"1.2.3.4%eth0%extra", false},    // multi-% stays invalid for v4 too
		{"fe80::1%", false},              // empty zone invalid in both parsers
		{"::ffff:1.2.3.4", true},
		{"::ffff:1.2.3.4/96", true}, // v4-in-v6 reports IPv6
		{"::ffff:1.2.3.4/64", true},
		{"::ffff:1.2.3.4/129", false},
		{"256.1.1.1", false},
		{"not-an-ip", false},
	}
	for _, v := range vectors {
		if got := checkIP(v.addr); got != v.want {
			t.Errorf("check_ip(%q) = %v, want %v", v.addr, got, v.want)
		}
	}
}

func TestDigCheckIPRegistryShape(t *testing.T) {
	rt, _ := newDigRuntime(nil)
	value, err := checkIPFunc{}.Execute(context.Background(), rt, &CheckIPArgs{Addr: "127.0.0.1"})
	if err != nil || value != true {
		t.Fatalf("check_ip = %#v err = %v", value, err)
	}
	value, err = checkIPFunc{}.Execute(context.Background(), rt, &CheckIPArgs{Addr: "-127.0.0.1"})
	if err != nil || value != false {
		t.Fatalf("check_ip neg = %#v err = %v", value, err)
	}
	if _, err := (checkIPFunc{}).Execute(context.Background(), rt, &AArgs{}); err == nil {
		t.Fatal("check_ip accepts wrong argument type")
	}
}

// ---------------------------------------------------------------------------
// argv / transport contract

func TestDigArgvContract(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {digResult("74.125.193.104\n", 0)},
	})
	if _, err := (aFunc{}).Execute(context.Background(), rt, &AArgs{Host: "www.google.com"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
	cmd := runner.commands[0]
	want := []string{fakeDigPath, "-r", "+short", "-q", "www.google.com", "-t", "A"}
	if strings.Join(append([]string{cmd.Name}, cmd.Args...), " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v", append([]string{cmd.Name}, cmd.Args...))
	}
	if cmd.Shell {
		t.Fatal("dig command must never run through a shell")
	}
	if cmd.Timeout <= 0 || cmd.Timeout > 2*time.Second {
		t.Fatalf("per-call timeout = %v", cmd.Timeout)
	}
	if cmd.MaxStdoutBytes != 64<<10 || cmd.MaxStderrBytes != 8<<10 {
		t.Fatalf("capture limits = %d/%d", cmd.MaxStdoutBytes, cmd.MaxStderrBytes)
	}
}

func TestDigArgvNameserverAndPTRReverse(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A @dns.example": {digResult("", 9)},
		"/usr/bin/dig -r +short -q 8.8.8.8.in-addr.arpa -t PTR":      {digResult("dns.google.\n", 0)},
	})
	if _, err := (aFunc{}).Execute(context.Background(), rt, &AArgs{
		Host:       "www.google.com",
		Nameserver: digString("dns.example"),
	}); err != nil {
		t.Fatal(err)
	}
	if got := argvOf(t, runner, 0); strings.Join(got, " ") != "/usr/bin/dig -r +short -q www.google.com -t A @dns.example" {
		t.Fatalf("nameserver argv = %v", got)
	}
	value, err := ptrFunc{}.Execute(context.Background(), rt, &PTRArgs{Host: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[dns.google.]" {
		t.Fatalf("PTR value = %#v", value)
	}
	if got := argvOf(t, runner, 1); strings.Join(got, " ") != "/usr/bin/dig -r +short -q 8.8.8.8.in-addr.arpa -t PTR" {
		t.Fatalf("PTR argv = %v", got)
	}
}

func TestDigPTRIPv6ReverseForm(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa -t PTR": {digResult("dns.google.\n", 0)},
	})
	value, err := ptrFunc{}.Execute(context.Background(), rt, &PTRArgs{Host: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[dns.google.]" {
		t.Fatalf("PTR value = %#v", value)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

// ---------------------------------------------------------------------------
// A / AAAA

func TestDigAPinnedVectorAndQuirks(t *testing.T) {
	stdout := "74.125.193.104\n74.125.193.105\n74.125.193.99\n74.125.193.106\n74.125.193.103\n74.125.193.147"
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {digResult(stdout+"\n", 0)},
	})
	value, err := aFunc{}.Execute(context.Background(), rt, &AArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"74.125.193.104", "74.125.193.105", "74.125.193.99", "74.125.193.106", "74.125.193.103", "74.125.193.147"}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("A value = %#v", value)
	}
}

func TestDigASharedPredicateKeepsQuirks(t *testing.T) {
	// Cross-family literals, CIDR strings, duplicates, and order are
	// all retained by the single check_ip predicate; junk lines drop.
	stdout := "2607:f8b0:400f:801::1014\n74.125.193.104\n198.60.22.0/24\n74.125.193.104\nnot-an-ip\n\n::ffff:1.2.3.4"
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q mix.example -t AAAA": {digResult(stdout, 0)},
	})
	value, err := aaaaFunc{}.Execute(context.Background(), rt, &AAAAArgs{Host: "mix.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"2607:f8b0:400f:801::1014",
		"74.125.193.104",
		"198.60.22.0/24",
		"74.125.193.104",
		"::ffff:1.2.3.4",
	}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("AAAA value = %#v", value)
	}
}

func TestDigRstripOnceBeforeParsing(t *testing.T) {
	// Salt cmd.run_all rstrips trailing Unicode whitespace once; a
	// CNAME stdout keeps interior content (including the trailing dot)
	// and loses only the trailing whitespace run.
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.eitr.tech -t CNAME": {digResult("bellanotte1986.github.io.\n\n \t\n ", 0)},
	})
	value, err := cnameFunc{}.Execute(context.Background(), rt, &CNAMEArgs{Host: "www.eitr.tech"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "bellanotte1986.github.io." {
		t.Fatalf("CNAME value = %#v", value)
	}
}

func TestDigPythonWhitespaceSemantics(t *testing.T) {
	ctx := context.Background()
	// U+001C..U+001F are Python whitespace but not Go whitespace: the
	// trailing rstrip of the pinned transport drops a trailing run
	// (TXT/NS keep the raw split afterwards), while interior bytes stay.
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t TXT": {digResult("text\x1c", 0)},
	})
	value, err := txtFunc{}.Execute(ctx, rt, &TXTArgs{Host: "ws.example"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[text]" {
		t.Fatalf("TXT trailing U+001C value = %#v", value)
	}

	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t NS": {digResult("a\x1c\x1d.example.\nb.example.\x1e", 0)},
	})
	value, err = nsFunc{}.Execute(ctx, rt2, &NSArgs{Domain: "ws.example", Resolve: digBool(false)})
	if err != nil {
		t.Fatal(err)
	}
	// The trailing run is stripped; the interior separator survives the
	// raw newline split as part of the first label.
	want := []string{"a\x1c\x1d.example.", "b.example."}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("NS raw whitespace value = %#v", value)
	}

	// MX rows split on Python whitespace: U+001C separates the fields,
	// and the trailing U+001E/U+001F-only line was already rstripped by
	// the pinned transport before the newline split.
	rt3, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t MX": {digResult("10\x1cmx.example.\n\x1f\x1e\n", 0)},
	})
	value, err = mxFunc{}.Execute(ctx, rt3, &MXArgs{Domain: "ws.example"})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := value.([][]string)
	if !ok || len(rows) != 1 {
		t.Fatalf("MX whitespace rows = %#v", value)
	}
	if fmt.Sprint(rows[0]) != "[10 mx.example.]" {
		t.Fatalf("MX whitespace fields = %#v", rows)
	}

	// SPF sections split on Python whitespace: U+001C separates tokens.
	rt4, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t TXT": {digResult("v=spf1\x1cip4:192.0.2.1/2_4\x1f~all", 0)},
	})
	value, err = spfFunc{}.Execute(ctx, rt4, &SPFArgs{Domain: "ws.example", Record: digString("TXT")})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[192.0.2.1/2_4]" {
		t.Fatalf("SPF whitespace value = %#v", value)
	}
}

// TestDigPythonFieldsAllocatedEmptyRows pins R102-FINAL-01 at the
// helper level: Salt's line.split() answers a real (non-nil) empty
// list for empty and whitespace-only rows, so every empty-token row
// must be an allocated empty slice — distinguishable from a nil slice
// through reflect — while non-empty tokenization keeps order and
// content.
func TestDigPythonFieldsAllocatedEmptyRows(t *testing.T) {
	vectors := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{" ", []string{}},
		{" \t\n\v\f\r", []string{}},
		{"\x1c\x1d\x1e\x1f", []string{}}, // Python-only whitespace too
		{"10 mx.example.", []string{"10", "mx.example."}},
		{"  10   mx.example.  ", []string{"10", "mx.example."}},
		{"a\x1cb", []string{"a", "b"}},
	}
	for _, v := range vectors {
		got := pythonFields(v.in)
		// The reflect-level nil-vs-empty distinction: an empty row
		// must be an allocated slice, never a nil one.
		if reflect.ValueOf(got).IsNil() {
			t.Fatalf("pythonFields(%q) is nil; want an allocated empty slice", v.in)
		}
		if !reflect.DeepEqual(got, v.want) {
			t.Fatalf("pythonFields(%q) = %#v, want %#v", v.in, got, v.want)
		}
	}
}

func TestDigASharedPredicateAcceptsZonedIPv6(t *testing.T) {
	// The shared check_ip predicate accepts scoped IPv6 literals like
	// Python ip_address, so the A/AAAA filter retains them.
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q zoned.example -t AAAA": {digResult("fe80::1%eth0\njunk\n", 0)},
	})
	value, err := aaaaFunc{}.Execute(context.Background(), rt, &AAAAArgs{Host: "zoned.example"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[fe80::1%eth0]" {
		t.Fatalf("AAAA zoned value = %#v", value)
	}
}

func TestDigPTRZonedLiteralReverseForm(t *testing.T) {
	// A scoped IPv6 literal is a valid PTR argument (Python literal
	// semantics); the fixed reverse name carries only the 16 address
	// bytes, never the zone.
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa -t PTR": {digResult("ptr.example.\n", 0)},
	})
	value, err := ptrFunc{}.Execute(context.Background(), rt, &PTRArgs{Host: "fe80::1%eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[ptr.example.]" {
		t.Fatalf("PTR zoned value = %#v", value)
	}
	if got := argvOf(t, runner, 0); !strings.HasSuffix(strings.Join(got, " "), ".ip6.arpa -t PTR") ||
		strings.Contains(strings.Join(got, " "), "eth0") {
		t.Fatalf("PTR zoned argv = %v", got)
	}
}

// TestDigCheckIPMultiZoneScopeGuard pins R102-BACKEND-FINAL-01: Python
// ip_address rejects IPv6 scope text carrying more than one percent
// delimiter (ip_address('fe80::1%eth0%extra') raises ValueError) while
// Go netip.ParseAddr accepts the same text, so the shared guard in
// pythonIPVersion rejects more than one '%' before parsing. Exactly one
// zone delimiter stays valid with or without a prefix, and the one
// predicate stays shared: A and AAAA response filtering (one digALookup
// over check_ip), the SPF ip6 filter (check_ip), and PTR's literal
// validation (reverseQuery's pythonIPVersion switch) all exclude the
// multi-zone value, while the host/query resolver validators keep
// rejecting every zone independently of this guard.
func TestDigCheckIPMultiZoneScopeGuard(t *testing.T) {
	ctx := context.Background()
	for _, v := range []struct {
		addr string
		want bool
	}{
		{"fe80::1%eth0", true},
		{"fe80::1%eth0/64", true},
		{"fe80::1%25", true}, // numeric zone id
		{"fe80::1%eth0%extra", false},
		{"fe80::1%%eth0", false},
		{"fe80::1%eth0%extra%more", false},
	} {
		if got := checkIP(v.addr); got != v.want {
			t.Errorf("check_ip(%q) = %v, want %v", v.addr, got, v.want)
		}
	}

	// The shared A/AAAA filter keeps the one-zone literal and drops the
	// multi-zone value for both record types (one predicate).
	stdout := "fe80::1%eth0%extra\nfe80::1%eth0\njunk\n"
	for _, tc := range []struct {
		name string
		run  func(*runtime.Runtime) (any, error)
		key  string
	}{
		{"A", func(rt *runtime.Runtime) (any, error) {
			return aFunc{}.Execute(ctx, rt, &AArgs{Host: "zoned.example"})
		}, "/usr/bin/dig -r +short -q zoned.example -t A"},
		{"AAAA", func(rt *runtime.Runtime) (any, error) {
			return aaaaFunc{}.Execute(ctx, rt, &AAAAArgs{Host: "zoned.example"})
		}, "/usr/bin/dig -r +short -q zoned.example -t AAAA"},
	} {
		rt, runner := newDigRuntime(map[string][]process.CommandResult{
			tc.key: {digResult(stdout, 0)},
		})
		value, err := tc.run(rt)
		if err != nil {
			t.Fatalf("%s multi-zone err = %v", tc.name, err)
		}
		if fmt.Sprint(value) != "[fe80::1%eth0]" {
			t.Fatalf("%s multi-zone value = %#v", tc.name, value)
		}
		if len(runner.commands) != 1 {
			t.Fatalf("%s multi-zone dispatches = %d", tc.name, len(runner.commands))
		}
	}

	// The SPF ip6 filter shares the predicate: the multi-zone ip6
	// mechanism drops, the one-zone mechanism survives in order.
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q zoned.example -t TXT": {
			digResult("v=spf1 ip6:fe80::1%eth0%extra ip6:fe80::1%eth0 ~all", 0),
		},
	})
	value, err := spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "zoned.example", Record: digString("TXT")})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[fe80::1%eth0]" {
		t.Fatalf("SPF multi-zone ip6 value = %#v", value)
	}

	// PTR literal validation shares the guard: the multi-zone text is
	// not a Python IP literal, so it rejects value-free with zero
	// dispatch (a lone Go netip.ParseAddr would have accepted it).
	rt2, runner2 := newDigRuntime(nil)
	if _, err := (ptrFunc{}).Execute(ctx, rt2, &PTRArgs{Host: "fe80::1%eth0%extra"}); err != errDigInvalidAddress {
		t.Fatalf("PTR multi-zone err = %v", err)
	}
	if len(runner2.commands) != 0 {
		t.Fatalf("PTR multi-zone dispatches = %d", len(runner2.commands))
	}
}

func TestDigNonzeroExitEmptyFallbacks(t *testing.T) {
	script := map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q fail.example -t A":           {digResult("74.125.193.104\n", 9)},
		"/usr/bin/dig -r +short -q fail.example -t AAAA":        {digResult("::1\n", 9)},
		"/usr/bin/dig -r +short -q fail.example -t CNAME":       {digResult("target.example.\n", 9)},
		"/usr/bin/dig -r +short -q fail.example -t NS":          {digResult("ns.example.\n", 9)},
		"/usr/bin/dig -r +short -q fail.example -t SPF":         {digResult("v=spf1 ~all", 9)},
		"/usr/bin/dig -r +short -q fail.example -t MX":          {digResult("10 mx.example.\n", 9)},
		"/usr/bin/dig -r +short -q fail.example -t TXT":         {digResult("text\n", 9)},
		"/usr/bin/dig -r +short -q 1.2.3.4.in-addr.arpa -t PTR": {digResult("ptr.example.\n", 9)},
	}
	rt, runner := newDigRuntime(script)
	ctx := context.Background()
	checks := []struct {
		name string
		run  func() (any, error)
		want string
	}{
		{"A", func() (any, error) { return aFunc{}.Execute(ctx, rt, &AArgs{Host: "fail.example"}) }, "[]"},
		{"AAAA", func() (any, error) { return aaaaFunc{}.Execute(ctx, rt, &AAAAArgs{Host: "fail.example"}) }, "[]"},
		{"CNAME", func() (any, error) { return cnameFunc{}.Execute(ctx, rt, &CNAMEArgs{Host: "fail.example"}) }, "[]"},
		{"NS", func() (any, error) { return nsFunc{}.Execute(ctx, rt, &NSArgs{Domain: "fail.example"}) }, "[]"},
		{"SPF", func() (any, error) { return spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "fail.example"}) }, "[]"},
		{"MX", func() (any, error) { return mxFunc{}.Execute(ctx, rt, &MXArgs{Domain: "fail.example"}) }, "[]"},
		{"TXT", func() (any, error) { return txtFunc{}.Execute(ctx, rt, &TXTArgs{Host: "fail.example"}) }, "[]"},
		{"PTR", func() (any, error) { return ptrFunc{}.Execute(ctx, rt, &PTRArgs{Host: "1.2.3.4"}) }, "[]"},
	}
	for _, check := range checks {
		value, err := check.run()
		if err != nil {
			t.Fatalf("%s nonzero fallback err = %v", check.name, err)
		}
		if fmt.Sprint(value) != check.want {
			t.Fatalf("%s nonzero fallback = %#v want %s", check.name, value, check.want)
		}
	}
	if len(runner.commands) != len(checks) {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

// ---------------------------------------------------------------------------
// PTR / TXT / CNAME shapes

func TestDigPTRAndTXTRawSplit(t *testing.T) {
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q 8.8.8.8.in-addr.arpa -t PTR": {digResult("dns.google.\nsecond.example.\n", 0)},
		"/usr/bin/dig -r +short -q _dmarc.example -t TXT":       {digResult("\"v=DMARC1\"\"\"\n\nmiddle empty\n", 0)},
	})
	ctx := context.Background()
	value, err := ptrFunc{}.Execute(ctx, rt, &PTRArgs{Host: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[dns.google. second.example.]" {
		t.Fatalf("PTR value = %#v", value)
	}
	value, err = txtFunc{}.Execute(ctx, rt, &TXTArgs{Host: "_dmarc.example"})
	if err != nil {
		t.Fatal(err)
	}
	// Quotes, interior empties, and trailing dots are retained verbatim;
	// only the trailing whitespace run was stripped by cmd.run_all.
	want := []string{`"v=DMARC1"""`, "", "middle empty"}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("TXT value = %#v", value)
	}
}

func TestDigEmptyStdoutSplits(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q empty.example -t PTR":   {digResult("", 0)},
		"/usr/bin/dig -r +short -q empty.example -t TXT":   {digResult("", 0)},
		"/usr/bin/dig -r +short -q empty.example -t CNAME": {digResult("", 0)},
	})
	ctx := context.Background()
	value, err := ptrFunc{}.Execute(ctx, rt, &PTRArgs{Host: "1.2.3.4"})
	if err != nil || fmt.Sprint(value) != "[]" || len(value.([]string)) != 1 {
		t.Fatalf("PTR empty = %#v err = %v", value, err)
	}
	value, err = txtFunc{}.Execute(ctx, rt, &TXTArgs{Host: "empty.example"})
	if err != nil || fmt.Sprint(value) != "[]" || len(value.([]string)) != 1 {
		t.Fatalf("TXT empty = %#v err = %v", value, err)
	}
	value, err = cnameFunc{}.Execute(ctx, rt, &CNAMEArgs{Host: "empty.example"})
	if err != nil || value != "" {
		t.Fatalf("CNAME empty = %#v err = %v", value, err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

func TestDigCNAMENoneFound(t *testing.T) {
	rt, _ := newDigRuntime(nil) // unmatched: successful empty
	value, err := cnameFunc{}.Execute(context.Background(), rt, &CNAMEArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "" {
		t.Fatalf("CNAME none found = %#v", value)
	}
}

// ---------------------------------------------------------------------------
// NS

func TestDigNSResolveDefaultAndRaw(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t NS":     {digResult("ns4.google.com.\n", 0)},
		"/usr/bin/dig -r +short -q ns4.google.com. -t A": {digResult("216.239.32.10\njunk\n", 0)},
	})
	ctx := context.Background()
	// resolve defaults to true: the nameserver line is revalidated and
	// resolved through the shared A lookup.
	value, err := nsFunc{}.Execute(ctx, rt, &NSArgs{Domain: "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[216.239.32.10]" {
		t.Fatalf("NS resolve value = %#v", value)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}

	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t NS": {digResult("ns4.google.com.\nns3.google.com.\n", 0)},
	})
	value, err = nsFunc{}.Execute(ctx, rt2, &NSArgs{Domain: "google.com", Resolve: digBool(false)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ns4.google.com.", "ns3.google.com."}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("NS raw value = %#v", value)
	}
}

func TestDigNSEmptyAndMalformed(t *testing.T) {
	ctx := context.Background()
	// Empty stdout with resolve=true answers [] with no child lookup.
	rt, runner := newDigRuntime(nil)
	value, err := nsFunc{}.Execute(ctx, rt, &NSArgs{Domain: "empty.example"})
	if err != nil || fmt.Sprint(value) != "[]" {
		t.Fatalf("NS empty = %#v err = %v", value, err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("NS empty dispatches = %d", len(runner.commands))
	}

	// A response-derived nameserver that fails revalidation rejects the
	// whole operation without partial results.
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q bad.example -t NS": {digResult("ns1.example.\n-spoof.example\n", 0)},
	})
	if _, err := (nsFunc{}).Execute(ctx, rt2, &NSArgs{Domain: "bad.example"}); !errors.Is(err, errDigInvalidName) {
		t.Fatalf("NS malformed err = %v", err)
	}

	// resolve=false keeps the raw split, including the [""] empty row.
	rt3, _ := newDigRuntime(nil)
	value, err = nsFunc{}.Execute(ctx, rt3, &NSArgs{Domain: "empty.example", Resolve: digBool(false)})
	if err != nil || fmt.Sprint(value) != "[]" || len(value.([]string)) != 1 {
		t.Fatalf("NS raw empty = %#v err = %v", value, err)
	}
}

// ---------------------------------------------------------------------------
// MX

func TestDigMXPinnedRawVector(t *testing.T) {
	stdout := "10 aspmx.l.google.com.\n20 alt1.aspmx.l.google.com.\n40 alt3.aspmx.l.google.com.\n50 alt4.aspmx.l.google.com.\n30 alt2.aspmx.l.google.com."
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t MX": {digResult(stdout, 0)},
	})
	value, err := mxFunc{}.Execute(context.Background(), rt, &MXArgs{Domain: "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"10", "aspmx.l.google.com."},
		{"20", "alt1.aspmx.l.google.com."},
		{"40", "alt3.aspmx.l.google.com."},
		{"50", "alt4.aspmx.l.google.com."},
		{"30", "alt2.aspmx.l.google.com."},
	}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("MX raw value = %#v", value)
	}
}

func TestDigMXResolveFirstAOnly(t *testing.T) {
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q google.com -t MX":         {digResult("10 aspmx.l.google.com.\n", 0)},
		"/usr/bin/dig -r +short -q aspmx.l.google.com. -t A": {digResult("64.233.162.27\n64.233.162.28\n", 0)},
	})
	value, err := mxFunc{}.Execute(context.Background(), rt, &MXArgs{
		Domain:  "google.com",
		Resolve: digBool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"10", "64.233.162.27"}}
	if fmt.Sprint(value) != fmt.Sprint(want) {
		t.Fatalf("MX resolve value = %#v", value)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}
}

func TestDigMXEmptySuccessAndMalformed(t *testing.T) {
	ctx := context.Background()
	// Empty stdout is a successful query: the raw shape answers [[]].
	rt, _ := newDigRuntime(nil)
	value, err := mxFunc{}.Execute(ctx, rt, &MXArgs{Domain: "empty.example"})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := value.([][]string)
	if !ok || len(rows) != 1 || len(rows[0]) != 0 {
		t.Fatalf("MX empty success = %#v", value)
	}
	// R102-FINAL-01: the empty row is an allocated slice, never nil,
	// so the serialized shape is [[]] and not [null].
	if rows[0] == nil || reflect.ValueOf(rows[0]).IsNil() {
		t.Fatalf("MX empty success row is nil; want an allocated empty slice")
	}

	// The pinned IndexError positions under resolve=true map to the
	// fixed malformed-record rejection: a short row, then an exchange
	// whose A lookup answers no address.
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q bad.example -t MX": {digResult("10\n", 0)},
	})
	if _, err := (mxFunc{}).Execute(ctx, rt2, &MXArgs{Domain: "bad.example", Resolve: digBool(true)}); !errors.Is(err, errDigMalformedRecord) {
		t.Fatalf("MX short row err = %v", err)
	}
	rt3, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q noa.example -t MX": {digResult("10 noa.example.\n", 0)},
		"/usr/bin/dig -r +short -q noa.example. -t A": {digResult("not-an-ip\n", 0)},
	})
	if _, err := (mxFunc{}).Execute(ctx, rt3, &MXArgs{Domain: "noa.example", Resolve: digBool(true)}); !errors.Is(err, errDigMalformedRecord) {
		t.Fatalf("MX empty A err = %v", err)
	}
	// A response-derived exchange that fails revalidation rejects
	// before dispatch.
	rt4, runner4 := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q spoof.example -t MX": {digResult("10 -spoof.example\n", 0)},
	})
	if _, err := (mxFunc{}).Execute(ctx, rt4, &MXArgs{Domain: "spoof.example", Resolve: digBool(true)}); !errors.Is(err, errDigInvalidName) {
		t.Fatalf("MX spoof err = %v", err)
	}
	if len(runner4.commands) != 1 {
		t.Fatalf("MX spoof dispatches = %d", len(runner4.commands))
	}
}

// TestDigMXRowsSerializeEmptyNeverNull pins the MX JSON shape
// (R102-FINAL-01): Salt answers line.split() rows and a Python list is
// never null, so an empty successful stdout must serialize [[]] and an
// interior blank/whitespace row must serialize [] — never null — with
// order and non-empty tokenization unchanged.
func TestDigMXRowsSerializeEmptyNeverNull(t *testing.T) {
	ctx := context.Background()
	// Empty raw stdout: exactly one empty row, [[]].
	rt, _ := newDigRuntime(nil)
	value, err := mxFunc{}.Execute(ctx, rt, &MXArgs{Domain: "empty.example"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[[]]" {
		t.Fatalf("MX empty stdout json = %s, want [[]]", encoded)
	}
	var decoded [][]string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0] == nil || len(decoded[0]) != 0 {
		t.Fatalf("MX empty stdout decoded = %#v; want one non-null empty row", decoded)
	}

	// Interior blank/whitespace rows serialize [] (never null); the
	// trailing whitespace run was already rstripped once by the pinned
	// cmd.run_all transport, so the final row is the last content line.
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q blankrows.example -t MX": {digResult("10 a.example.\n \n\t\n20 b.example.\n\n \t", 0)},
	})
	value, err = mxFunc{}.Execute(ctx, rt2, &MXArgs{Domain: "blankrows.example"})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := value.([][]string)
	if !ok || len(rows) != 4 {
		t.Fatalf("MX blank rows value = %#v", value)
	}
	for i, row := range rows {
		if row == nil || reflect.ValueOf(row).IsNil() {
			t.Fatalf("MX blank row %d is nil; want an allocated empty slice", i)
		}
	}
	encoded, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want := `[["10","a.example."],[],[],["20","b.example."]]`
	if string(encoded) != want {
		t.Fatalf("MX blank rows json = %s, want %s", encoded, want)
	}
	decoded = nil
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for i, row := range decoded {
		if row == nil {
			t.Fatalf("decoded MX blank row %d is null", i)
		}
	}
	if fmt.Sprint(decoded[0]) != "[10 a.example.]" || fmt.Sprint(decoded[3]) != "[20 b.example.]" {
		t.Fatalf("MX blank rows decoded = %#v", decoded)
	}
}

// ---------------------------------------------------------------------------
// SPF

func TestDigSPFPinnedVectors(t *testing.T) {
	script := map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q foo.com -t TXT": {
			digResult("v=spf1 ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all", 0),
		},
		"/usr/bin/dig -r +short -q xmission.com -t SPF": {digResult("", 0)},
		"/usr/bin/dig -r +short -q xmission.com -t TXT": {
			digResult(`"v=spf1 a mx include:_spf.xmission.com ?all"`, 0),
		},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t SPF": {digResult("", 0)},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t TXT": {
			digResult(`"v=spf1 a mx ip4:198.60.22.0/24 ip4:166.70.13.0/24 ~all"`, 0),
		},
		"/usr/bin/dig -r +short -q xmission-redirect.com -t SPF": {digResult("", 0)},
		"/usr/bin/dig -r +short -q xmission-redirect.com -t TXT": {
			digResult("v=spf1 redirect=_spf.xmission.com", 0),
		},
	}
	ctx := context.Background()

	rt, runner := newDigRuntime(script)
	value, err := spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "foo.com", Record: digString("TXT")})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[216.73.93.70/31 216.73.93.72/31]" {
		t.Fatalf("SPF foo.com = %#v", value)
	}
	// An explicitly requested TXT record never falls back.
	if got := argvOf(t, runner, 0); !strings.HasSuffix(strings.Join(got, " "), "-t TXT") {
		t.Fatalf("SPF explicit TXT argv = %v", got)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("SPF explicit TXT dispatches = %d", len(runner.commands))
	}

	rt2, _ := newDigRuntime(script)
	value, err = spfFunc{}.Execute(ctx, rt2, &SPFArgs{Domain: "xmission.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[198.60.22.0/24 166.70.13.0/24]" {
		t.Fatalf("SPF include = %#v", value)
	}

	rt3, _ := newDigRuntime(script)
	value, err = spfFunc{}.Execute(ctx, rt3, &SPFArgs{Domain: "xmission-redirect.com"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[198.60.22.0/24 166.70.13.0/24]" {
		t.Fatalf("SPF redirect = %#v", value)
	}
}

func TestDigSPFFallbackCountedAndExactEmptyOnly(t *testing.T) {
	ctx := context.Background()
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q empty.example -t SPF": {digResult("", 0)},
		"/usr/bin/dig -r +short -q empty.example -t TXT": {digResult("", 0)},
	})
	value, err := spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "empty.example"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[]" {
		t.Fatalf("SPF fallback value = %#v", value)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("fallback dispatches = %d", len(runner.commands))
	}
	// An explicitly requested TXT record with an empty answer never
	// falls back.
	rt2, runner2 := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q empty.example -t TXT": {digResult("", 0)},
	})
	value, err = spfFunc{}.Execute(ctx, rt2, &SPFArgs{Domain: "empty.example", Record: digString("TXT")})
	if err != nil || fmt.Sprint(value) != "[]" {
		t.Fatalf("SPF explicit TXT = %#v err = %v", value, err)
	}
	if len(runner2.commands) != 1 {
		t.Fatalf("explicit TXT dispatches = %d", len(runner2.commands))
	}
	// An invalid record argument rejects with zero dispatch.
	rt3, runner3 := newDigRuntime(nil)
	if _, err := (spfFunc{}).Execute(ctx, rt3, &SPFArgs{Domain: "empty.example", Record: digString("MX")}); !errors.Is(err, errDigInvalidRecord) {
		t.Fatalf("SPF bad record err = %v", err)
	}
	if len(runner3.commands) != 0 {
		t.Fatalf("bad record dispatches = %d", len(runner3.commands))
	}
	if _, err := (spfFunc{}).Execute(ctx, rt3, &SPFArgs{Domain: "empty.example", Record: digString("")}); !errors.Is(err, errDigInvalidRecord) {
		t.Fatalf("SPF empty record err = %v", err)
	}
}

func TestDigSPFTokenRules(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"lone v=spf1 answers empty", "v=spf1", "[]"},
		{"first token must be exact", "V=spf1 ip4:1.2.3.4", "[]"},
		{"missing token", "v=spf1mx ip4:1.2.3.4", "[]"},
		{"quotes stripped everywhere", `"v=spf1" "ip4:1.2.3.4"`, "[1.2.3.4]"},
		{"redirect only as second token", "v=spf1 ip4:9.9.9.9 redirect=ignored.example", "[9.9.9.9]"},
		{"plus and tilde prefixes", "v=spf1 +ip4:1.2.3.4 ~ip4:5.6.7.8 -ip4:9.9.9.9", "[1.2.3.4 5.6.7.8]"},
		{"invalid ip arguments dropped", "v=spf1 ip4:999.9.9.9 ip6:zz::1 ip4:1.2.3.4", "[1.2.3.4]"},
		{"duplicates and order kept", "v=spf1 ip4:1.2.3.4 ip4:1.2.3.4 ip6:2001:db8::1/64", "[1.2.3.4 1.2.3.4 2001:db8::1/64]"},
	}
	for _, tc := range cases {
		rt, _ := newDigRuntime(map[string][]process.CommandResult{
			"/usr/bin/dig -r +short -q token.example -t TXT": {digResult(tc.stdout, 0)},
		})
		value, err := spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "token.example", Record: digString("TXT")})
		if err != nil {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if fmt.Sprint(value) != tc.want {
			t.Fatalf("%s: value = %#v want %s", tc.name, value, tc.want)
		}
	}

	// A redirect honored as the second token replaces collection; a
	// third-token redirect= is plain data and never dispatches.
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q token.example -t TXT": {digResult("v=spf1 redirect=ok.example", 0)},
		"/usr/bin/dig -r +short -q ok.example -t SPF":    {digResult("v=spf1 ip4:1.2.3.4 ~all", 0)},
	})
	value, err := spfFunc{}.Execute(ctx, rt, &SPFArgs{Domain: "token.example", Record: digString("TXT")})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[1.2.3.4]" {
		t.Fatalf("redirect honored value = %#v", value)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("redirect dispatches = %d", len(runner.commands))
	}
}

func TestDigSPFCyclesDepthAndFanout(t *testing.T) {
	ctx := context.Background()

	// redirect= to the active domain is a cycle.
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q self.example -t TXT": {digResult("v=spf1 redirect=self.example", 0)},
	})
	if _, err := (spfFunc{}).Execute(ctx, rt, &SPFArgs{Domain: "self.example", Record: digString("TXT")}); !errors.Is(err, errDigCycle) {
		t.Fatalf("redirect self err = %v", err)
	}

	// include: of the active domain is a cycle too.
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q self.example -t TXT": {digResult("v=spf1 include:self.example", 0)},
	})
	if _, err := (spfFunc{}).Execute(ctx, rt2, &SPFArgs{Domain: "self.example", Record: digString("TXT")}); !errors.Is(err, errDigCycle) {
		t.Fatalf("include self err = %v", err)
	}

	// A two-hop redirect loop closes the cycle at the repeat.
	rt3, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q a.example -t TXT": {digResult("v=spf1 redirect=b.example", 0)},
		"/usr/bin/dig -r +short -q b.example -t TXT": {digResult("v=spf1 redirect=a.example", 0)},
	})
	if _, err := (spfFunc{}).Execute(ctx, rt3, &SPFArgs{Domain: "a.example", Record: digString("TXT")}); !errors.Is(err, errDigCycle) {
		t.Fatalf("redirect loop err = %v", err)
	}

	// Siblings are not deduplicated: two includes of one target both
	// dispatch and both contribute.
	rt4, runner4 := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q dup.example -t TXT": {digResult("v=spf1 include:t.example include:t.example", 0)},
		"/usr/bin/dig -r +short -q t.example -t SPF": {
			digResult("v=spf1 ip4:1.2.3.4 ~all", 0),
			digResult("v=spf1 ip4:1.2.3.4 ~all", 0),
		},
	})
	value, err := spfFunc{}.Execute(ctx, rt4, &SPFArgs{Domain: "dup.example", Record: digString("TXT")})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[1.2.3.4 1.2.3.4]" {
		t.Fatalf("sibling value = %#v", value)
	}
	if len(runner4.commands) != 3 {
		t.Fatalf("sibling dispatches = %d", len(runner4.commands))
	}

	// A redirect chain nesting deeper than the active-path limit fails
	// closed before the sixth frame.
	chain := map[string][]process.CommandResult{}
	labels := []string{"a", "b", "c", "d", "e", "f"}
	for i, label := range labels {
		next := "f.example"
		if i < len(labels)-1 {
			next = labels[i+1] + ".example"
		}
		if label == "f" {
			chain["/usr/bin/dig -r +short -q "+label+".example -t SPF"] = []process.CommandResult{digResult("v=spf1 ~all", 0)}
		} else {
			chain["/usr/bin/dig -r +short -q "+label+".example -t SPF"] = []process.CommandResult{digResult("v=spf1 redirect="+next, 0)}
		}
	}
	rt5, _ := newDigRuntime(chain)
	if _, err := (spfFunc{}).Execute(ctx, rt5, &SPFArgs{Domain: "a.example"}); !errors.Is(err, errDigDepthBudget) {
		t.Fatalf("depth err = %v", err)
	}

	// Eleven dispatches (parent + ten includes) exceed the shared call
	// budget; the failure carries no partial results.
	fanout := map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q wide.example -t TXT": {digResult("v=spf1 include:i1.example include:i2.example include:i3.example include:i4.example include:i5.example include:i6.example include:i7.example include:i8.example include:i9.example include:i10.example", 0)},
	}
	for i := 1; i <= 10; i++ {
		fanout[fmt.Sprintf("/usr/bin/dig -r +short -q i%d.example -t SPF", i)] = []process.CommandResult{digResult("v=spf1 ip4:10.0.0.1 ~all", 0)}
	}
	rt6, _ := newDigRuntime(fanout)
	if _, err := (spfFunc{}).Execute(ctx, rt6, &SPFArgs{Domain: "wide.example", Record: digString("TXT")}); !errors.Is(err, errDigCallBudget) {
		t.Fatalf("call budget err = %v", err)
	}
}

func TestDigSPFResponseDerivedRevalidation(t *testing.T) {
	ctx := context.Background()
	// A response-derived include target that fails name validation
	// rejects before dispatch.
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q bad.example -t TXT": {digResult("v=spf1 include:-spoof.example", 0)},
	})
	if _, err := (spfFunc{}).Execute(ctx, rt, &SPFArgs{Domain: "bad.example", Record: digString("TXT")}); !errors.Is(err, errDigInvalidName) {
		t.Fatalf("include spoof err = %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("include spoof dispatches = %d", len(runner.commands))
	}
	// A redirect target is revalidated the same way.
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q bad.example -t TXT": {digResult("v=spf1 redirect=-spoof.example", 0)},
	})
	if _, err := (spfFunc{}).Execute(ctx, rt2, &SPFArgs{Domain: "bad.example", Record: digString("TXT")}); !errors.Is(err, errDigInvalidName) {
		t.Fatalf("redirect spoof err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// validation: zero dispatch on invalid input

func TestDigZeroDispatchOnInvalidInput(t *testing.T) {
	ctx := context.Background()
	badNames := []string{
		"",
		"-flag.example",
		"@server.example",
		"slash/example",
		"back\\slash.example",
		"space example.example",
		"tab\texample",
		"new\nline",
		"nul\x00byte",
		"ctrl\x01byte",
		"dot..double",
		".leading",
		"trailing..",
		"ünïcode.example",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat(strings.Repeat("a", 60)+".", 4) + strings.Repeat("b", 30),
	}
	rt, runner := newDigRuntime(nil)
	for _, name := range badNames {
		if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: name}); !errors.Is(err, errDigInvalidName) {
			t.Fatalf("A(%q) err = %v", name, err)
		}
	}
	// Underscore labels stay supported (SPF/SRV style names).
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "_spf.xmission.com"}); err != nil {
		t.Fatalf("underscore name err = %v", err)
	}
	// A single terminal dot is allowed.
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "example.com."}); err != nil {
		t.Fatalf("terminal dot err = %v", err)
	}
	// Only the invalid calls may dispatch.
	if len(runner.commands) != 2 {
		t.Fatalf("dispatches = %d", len(runner.commands))
	}

	badServers := []string{
		"@ns.example",
		"ns.example:53",
		"dns://ns.example",
		"1.2.3.0/24",
		"[::1]",
		"::1%eth0",
		"ns example",
		"http://ns.example",
	}
	rt2, runner2 := newDigRuntime(nil)
	for _, server := range badServers {
		if _, err := (aFunc{}).Execute(ctx, rt2, &AArgs{Host: "ok.example", Nameserver: digString(server)}); !errors.Is(err, errDigInvalidNameserver) {
			t.Fatalf("nameserver %q err = %v", server, err)
		}
	}
	if len(runner2.commands) != 0 {
		t.Fatalf("nameserver dispatches = %d", len(runner2.commands))
	}
	// Valid nameserver forms dispatch once each.
	for _, server := range []string{"ns.example", "192.0.2.53", "2001:db8::53"} {
		if _, err := (aFunc{}).Execute(ctx, rt2, &AArgs{Host: "ok.example", Nameserver: digString(server)}); err != nil {
			t.Fatalf("valid nameserver %q err = %v", server, err)
		}
	}
	if len(runner2.commands) != 3 {
		t.Fatalf("valid nameserver dispatches = %d", len(runner2.commands))
	}

	// PTR requires a bare IP literal.
	rt3, runner3 := newDigRuntime(nil)
	for _, host := range []string{"example.com", "1.2.3.4/24", "not-an-ip", ""} {
		if _, err := (ptrFunc{}).Execute(ctx, rt3, &PTRArgs{Host: host}); !errors.Is(err, errDigInvalidAddress) {
			t.Fatalf("PTR(%q) err = %v", host, err)
		}
	}
	if len(runner3.commands) != 0 {
		t.Fatalf("PTR dispatches = %d", len(runner3.commands))
	}
}

func TestDigDiagnosticsAreValueFree(t *testing.T) {
	ctx := context.Background()
	secretish := []string{"meta example", "ns example", "1.2.3.4:53", "-flag.example"}
	rt, _ := newDigRuntime(nil)
	errs := []error{}
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "meta example"}); err != nil {
		errs = append(errs, err)
	}
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "ok.example", Nameserver: digString("1.2.3.4:53")}); err != nil {
		errs = append(errs, err)
	}
	if _, err := (ptrFunc{}).Execute(ctx, rt, &PTRArgs{Host: "not-an-ip"}); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 3 {
		t.Fatalf("collected %d errors", len(errs))
	}
	for _, err := range errs {
		msg := err.Error()
		for _, needle := range secretish {
			if strings.Contains(msg, needle) {
				t.Fatalf("error %q leaks %q", msg, needle)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// budgets and limits

func TestDigRunnerFailureClassification(t *testing.T) {
	ctx := context.Background()
	wrapped := map[error]error{
		fmt.Errorf("/usr/bin/dig -r +short -q x -t A timed out: %w", context.DeadlineExceeded): errDigTimeout,
		fmt.Errorf("dig canceled: %w", context.Canceled):                                       errDigCanceled,
		fmt.Errorf("dig: %w", process.ErrOutputLimit):                                          errDigOutputLimit,
		errors.New("fork/exec dig: no such file or directory"):                                 errDigLaunch,
	}
	for input, want := range wrapped {
		rt, _ := newDigRuntime(nil)
		rt.Runner = &digResolverRunner{inner: &digErrorRunner{err: input}, path: fakeDigPath}
		_, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "x.example"})
		if !errors.Is(err, want) {
			t.Fatalf("classified %v as %v, want %v", input, err, want)
		}
		if err.Error() != want.Error() {
			t.Fatalf("error %q is not the fixed sentinel %q", err.Error(), want.Error())
		}
	}
}

type digErrorRunner struct{ err error }

func (r *digErrorRunner) Run(context.Context, process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: -1, Err: r.err}
}

func TestDigOutputTruncationRejections(t *testing.T) {
	ctx := context.Background()
	// Runner-reported truncation.
	rt, _ := newDigRuntime(nil)
	rt.Runner = &digResolverRunner{inner: &digTruncatingRunner{}, path: fakeDigPath}
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "x.example"}); !errors.Is(err, errDigOutputLimit) {
		t.Fatalf("truncation err = %v", err)
	}
	// A custom Runner ignoring the requested caps is still rejected
	// defensively.
	rt2, _ := newDigRuntime(nil)
	rt2.Runner = &digResolverRunner{inner: &digOversizedRunner{stdout: strings.Repeat("1.2.3.4\n", 12*1024)}, path: fakeDigPath} // ~72 KiB
	if _, err := (aFunc{}).Execute(ctx, rt2, &AArgs{Host: "x.example"}); !errors.Is(err, errDigOutputLimit) {
		t.Fatalf("oversized err = %v", err)
	}
}

type digTruncatingRunner struct{}

func (r *digTruncatingRunner) Run(context.Context, process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: 0, StdoutTruncated: true}
}

type digOversizedRunner struct{ stdout string }

func (r *digOversizedRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: 0, Stdout: []byte(r.stdout)}
}

func TestDigAggregateOutputLimit(t *testing.T) {
	ctx := context.Background()
	// NS with five children at 60 KiB each: 300 KiB aggregate crosses
	// the 256 KiB budget without any single call crossing its own cap.
	chunk := strings.Repeat("line-of-output-that-is-not-an-ip-xxxxxxxxxxxx\n", 1334) // ~60 KiB
	script := map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q agg.example -t NS": {digResult("n1.example.\nn2.example.\nn3.example.\nn4.example.\nn5.example.\n", 0)},
	}
	for _, n := range []string{"n1", "n2", "n3", "n4", "n5"} {
		script["/usr/bin/dig -r +short -q "+n+".example. -t A"] = []process.CommandResult{digResult(chunk, 0)}
	}
	rt, runner := newDigRuntime(script)
	if _, err := (nsFunc{}).Execute(ctx, rt, &NSArgs{Domain: "agg.example"}); !errors.Is(err, errDigAggregateLimit) {
		t.Fatalf("aggregate err = %v", err)
	}
	if len(runner.commands) > 6 {
		t.Fatalf("aggregate dispatches = %d", len(runner.commands))
	}
}

func TestDigResultLimit(t *testing.T) {
	ctx := context.Background()
	var b strings.Builder
	for i := 0; i <= maxResults; i++ {
		fmt.Fprintf(&b, "10.0.%d.%d\n", i/256, i%256)
	}
	rt, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q many.example -t A": {digResult(b.String(), 0)},
	})
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "many.example"}); !errors.Is(err, errDigResultLimit) {
		t.Fatalf("result limit err = %v", err)
	}
	// Exactly maxResults is fine.
	exact := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	rt2, _ := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q exact.example -t A": {digResult(strings.Join(exact[:maxResults], "\n"), 0)},
	})
	value, err := aFunc{}.Execute(ctx, rt2, &AArgs{Host: "exact.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(value.([]string)) != maxResults {
		t.Fatalf("exact results = %d", len(value.([]string)))
	}
}

func TestDigOperationDeadlineShared(t *testing.T) {
	// The per-call timeout never exceeds 2s and the shared operation
	// deadline only shrinks it; a canceled operation context rejects
	// before dispatch.
	rt, runner := newDigRuntime(map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ns.example -t NS": {digResult("a.example.\n", 0)},
		"/usr/bin/dig -r +short -q a.example. -t A":  {digResult("1.2.3.4\n", 0)},
	})
	if _, err := (nsFunc{}).Execute(context.Background(), rt, &NSArgs{Domain: "ns.example"}); err != nil {
		t.Fatal(err)
	}
	for i, cmd := range runner.commands {
		if cmd.Timeout <= 0 || cmd.Timeout > 2*time.Second {
			t.Fatalf("call %d timeout = %v", i, cmd.Timeout)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt2, runner2 := newDigRuntime(nil)
	if _, err := (aFunc{}).Execute(ctx, rt2, &AArgs{Host: "x.example"}); !errors.Is(err, errDigCanceled) {
		t.Fatalf("canceled err = %v", err)
	}
	if len(runner2.commands) != 0 {
		t.Fatalf("canceled dispatches = %d", len(runner2.commands))
	}
}

// ---------------------------------------------------------------------------
// availability gate and trusted native boundary

func TestDigAvailabilityGate(t *testing.T) {
	ctx := context.Background()
	runner := &digResolverRunner{inner: &digFakeRunner{}, err: errors.New("trusted resolution failed")}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "x.example"}); !errors.Is(err, errDigUnavailable) {
		t.Fatalf("A unavailable err = %v", err)
	}
	// The pinned __virtual__ gate covers the whole module: check_ip
	// fails closed too, with zero dispatch.
	if _, err := (checkIPFunc{}).Execute(ctx, rt, &CheckIPArgs{Addr: "127.0.0.1"}); !errors.Is(err, errDigUnavailable) {
		t.Fatalf("check_ip unavailable err = %v", err)
	}
	if len(runner.inner.(*digFakeRunner).commands) != 0 {
		t.Fatalf("unavailable dispatches = %d", len(runner.inner.(*digFakeRunner).commands))
	}
	if _, err := (ptrFunc{}).Execute(ctx, rt, &PTRArgs{Host: "1.2.3.4"}); !errors.Is(err, errDigUnavailable) {
		t.Fatalf("PTR unavailable err = %v", err)
	}
	// The gate error is value-free.
	if strings.Contains(errDigUnavailable.Error(), "x.example") {
		t.Fatal("unavailable error leaks input")
	}
}

func TestDigTrustedResolutionDrivesArgvAndEnv(t *testing.T) {
	const synthetic = "/usr/bin/dig"
	inner := &digFakeRunner{script: map[string][]process.CommandResult{
		synthetic + " -r +short -q x.example -t A": {digResult("1.2.3.4\n", 0)},
	}}
	runner := &digResolverRunner{inner: inner, path: synthetic}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	value, err := aFunc{}.Execute(context.Background(), rt, &AArgs{Host: "x.example"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(value) != "[1.2.3.4]" {
		t.Fatalf("resolved value = %#v", value)
	}
	if len(inner.commands) != 1 {
		t.Fatalf("dispatches = %d", len(inner.commands))
	}
	cmd := inner.commands[0]
	if cmd.Name != synthetic {
		t.Fatalf("argv[0] = %q, want the resolved absolute path", cmd.Name)
	}
	if cmd.Shell {
		t.Fatal("dig command must never run through a shell")
	}
	// The environment is exactly the fixed allowlist: nothing is
	// inherited, so RES_OPTIONS, LOCALDOMAIN, HOSTALIASES, LD_*, and
	// caller secrets cannot reach the child.
	if !reflect.DeepEqual(cmd.Env, wantDigEnv) {
		t.Fatalf("env = %q, want %q", cmd.Env, wantDigEnv)
	}
	for _, env := range cmd.Env {
		for _, forbidden := range []string{"RES_OPTIONS", "LOCALDOMAIN", "HOSTALIASES", "LD_"} {
			if strings.HasPrefix(env, forbidden+"=") {
				t.Fatalf("forbidden inherited variable %q", env)
			}
		}
	}
	// The env template itself stays unmutated across dispatches.
	inner2 := &digFakeRunner{script: map[string][]process.CommandResult{
		synthetic + " -r +short -q y.example -t A": {digResult("1.2.3.4\n", 0)},
	}}
	runner2 := &digResolverRunner{inner: inner2, path: synthetic}
	rt2 := &runtime.Runtime{Runner: runner2, FS: runtime.NewMemoryFS()}
	if _, err := (aFunc{}).Execute(context.Background(), rt2, &AArgs{Host: "y.example"}); err != nil {
		t.Fatal(err)
	}
	inner2.commands[0].Env[0] = "HOME=/mutated"
	if !reflect.DeepEqual(digCommandEnv, wantDigEnv) {
		t.Fatalf("shared env template mutated: %q", digCommandEnv)
	}
}

func TestDigTrustedResolutionRejectsUntrustedContracts(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		path string
		err  error
	}{
		{"resolution error", "", errors.New("unavailable")},
		{"relative synthetic path", "dig", nil},
		{"traversal-shaped path", "usr/bin/dig", nil},
		{"empty path with nil error", "", nil},
	}
	for _, tc := range cases {
		runner := &digResolverRunner{inner: &digFakeRunner{}, path: tc.path, err: tc.err}
		rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
		if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "x.example"}); !errors.Is(err, errDigUnavailable) {
			t.Fatalf("%s: err = %v, want the fixed unavailable gate error", tc.name, err)
		}
		if len(runner.inner.(*digFakeRunner).commands) != 0 {
			t.Fatalf("%s: dispatches = %d", tc.name, len(runner.inner.(*digFakeRunner).commands))
		}
	}
	// A resolver contract violation on one name never leaks into a
	// successful resolution on the fixed name.
	runner := &digResolverRunner{inner: &digFakeRunner{}, path: "/usr/bin/dig"}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	if _, err := (checkIPFunc{}).Execute(ctx, rt, &CheckIPArgs{Addr: "127.0.0.1"}); err != nil {
		t.Fatalf("check_ip over resolving runner: %v", err)
	}
}

func TestDigRunnerWithoutCapabilityFailsClosed(t *testing.T) {
	// A Runner without the TrustedCommandResolver capability cannot
	// verify the dig executable: every dig.* function, check_ip
	// included, fails closed with the fixed unverified-executable error
	// and zero dispatch. The module never substitutes a bare-name
	// dispatch or a host LookPath of its own (R102-SEC-01).
	ctx := context.Background()
	runner := &digFakeRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q x.example -t A": {digResult("1.2.3.4\n", 0)},
	}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	if _, err := (aFunc{}).Execute(ctx, rt, &AArgs{Host: "x.example"}); !errors.Is(err, errDigUnverifiedExecutable) {
		t.Fatalf("capability-less A err = %v, want the fixed unverified-executable error", err)
	}
	if _, err := (checkIPFunc{}).Execute(ctx, rt, &CheckIPArgs{Addr: "127.0.0.1"}); !errors.Is(err, errDigUnverifiedExecutable) {
		t.Fatalf("capability-less check_ip err = %v, want the fixed unverified-executable error", err)
	}
	// The scripted answer is never consumed: availability fails closed
	// before any dispatch.
	if len(runner.commands) != 0 {
		t.Fatalf("capability-less dispatches = %d", len(runner.commands))
	}
	// The error is value-free.
	if strings.Contains(errDigUnverifiedExecutable.Error(), "x.example") {
		t.Fatal("unverified-executable error leaks input")
	}
	// A nil Runner fails closed with the runner-unavailable class.
	if _, err := (aFunc{}).Execute(ctx, &runtime.Runtime{}, &AArgs{Host: "x.example"}); !errors.Is(err, errDigRunnerUnavailable) {
		t.Fatalf("nil runner err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// registry surface

func TestDigRegistryRegistration(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"dig.A", "dig.AAAA", "dig.CNAME", "dig.MX", "dig.NS", "dig.PTR", "dig.SPF", "dig.TXT",
		"dig.a", "dig.aaaa", "dig.check_ip", "dig.cname", "dig.mx", "dig.ns", "dig.ptr", "dig.spf",
	}
	names := reg.Names()
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("registered names = %v", names)
	}
	// No txt alias exists, matching the pinned source tail.
	if _, ok := reg.Get("dig.txt"); ok {
		t.Fatal("dig.txt alias must not exist")
	}
	for _, name := range names {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if constrained, ok := fn.(runtime.PlatformConstrained); ok {
			t.Fatalf("%s unexpectedly constrained to %v", name, constrained.Platforms())
		}
	}
}

func TestDigAliasesMatchCanonicalBehavior(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	// Every key serves both the alias and the canonical call (the SPF
	// vector consumes one SPF answer plus its TXT fallback each time).
	single := map[string]string{
		"/usr/bin/dig -r +short -q alias.example -t A":          "1.2.3.4\n",
		"/usr/bin/dig -r +short -q alias.example -t AAAA":       "::1\n",
		"/usr/bin/dig -r +short -q alias.example -t CNAME":      "c.example.\n",
		"/usr/bin/dig -r +short -q alias.example -t NS":         "n.example.\n",
		"/usr/bin/dig -r +short -q n.example. -t A":             "1.2.3.4\n",
		"/usr/bin/dig -r +short -q alias.example -t SPF":        "",
		"/usr/bin/dig -r +short -q alias.example -t TXT":        "v=spf1 ip4:1.2.3.4 -all",
		"/usr/bin/dig -r +short -q alias.example -t MX":         "10 m.example.\n",
		"/usr/bin/dig -r +short -q 4.3.2.1.in-addr.arpa -t PTR": "ptr.example.\n",
	}
	script := make(map[string][]process.CommandResult, len(single))
	for key, stdout := range single {
		script[key] = []process.CommandResult{digResult(stdout, 0), digResult(stdout, 0)}
	}
	rt, _ := newDigRuntime(script)
	rt.Exec = reg
	ctx := context.Background()

	pairs := []struct {
		alias     string
		canonical string
		args      func() any
	}{
		{"dig.a", "dig.A", func() any { return &AArgs{Host: "alias.example"} }},
		{"dig.aaaa", "dig.AAAA", func() any { return &AAAAArgs{Host: "alias.example"} }},
		{"dig.cname", "dig.CNAME", func() any { return &CNAMEArgs{Host: "alias.example"} }},
		{"dig.ns", "dig.NS", func() any { return &NSArgs{Domain: "alias.example"} }},
		{"dig.spf", "dig.SPF", func() any { return &SPFArgs{Domain: "alias.example"} }},
		{"dig.mx", "dig.MX", func() any { return &MXArgs{Domain: "alias.example"} }},
		{"dig.ptr", "dig.PTR", func() any { return &PTRArgs{Host: "1.2.3.4"} }},
	}
	for _, pair := range pairs {
		aliasValue, err := reg.Call(ctx, rt, pair.alias, pair.args())
		if err != nil {
			t.Fatalf("%s: %v", pair.alias, err)
		}
		canonicalValue, err := reg.Call(ctx, rt, pair.canonical, pair.args())
		if err != nil {
			t.Fatalf("%s: %v", pair.canonical, err)
		}
		if fmt.Sprint(aliasValue) != fmt.Sprint(canonicalValue) {
			t.Fatalf("%s = %#v but %s = %#v", pair.alias, aliasValue, pair.canonical, canonicalValue)
		}
	}
}
