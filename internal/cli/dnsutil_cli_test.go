//go:build dns_contract

package cli

// dnsutil CLI contract tests (dns_contract build tag): every dig-backed
// vector runs against the real dig family over a scripted fake Runner
// and a test trusted resolver, and every parse vector runs against
// runtime.MemoryFS — no dig execution, no DNS, no network, and no host
// /etc/hosts or zone file read.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
	execdnsutil "github.com/friz-zy/statekit/modules/exec/dnsutil"
)

// dnsutilCLIRunner scripts CommandResults by joined argv.
type dnsutilCLIRunner struct {
	script   map[string][]process.CommandResult
	commands []process.Command
}

func (r *dnsutilCLIRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
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

// dnsutilCLIResolverRunner adds the test TrustedCommandResolver seam.
type dnsutilCLIResolverRunner struct {
	inner *dnsutilCLIRunner
	path  string
	err   error
}

func (r *dnsutilCLIResolverRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	return r.inner.Run(ctx, cmd)
}

func (r *dnsutilCLIResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

func dnsutilCLIResult(stdout string, exitCode int) process.CommandResult {
	return process.CommandResult{Stdout: []byte(stdout), ExitCode: exitCode}
}

func dnsutilCLIApp(t *testing.T, runner *dnsutilCLIResolverRunner) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
		Runner: runner,
	}
	if err := execdig.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := execdnsutil.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestDNSUtilCLIParseHostsInline drives the parsing surface end to end:
// inline hosts data answers the pinned map as JSON ([] alias lists,
// never null) and the missing default path answers the pinned
// not-found string with a zero exit, without reading the host
// /etc/hosts (the MemoryFS carries none).
func TestDNSUtilCLIParseHostsInline(t *testing.T) {
	app := dnsutilCLIApp(t, &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, path: "/usr/bin/dig"})

	code, out, errS := captureCode(t, app, "exec", "dnsutil.parse_hosts",
		"--hosts", "127.0.0.1\tlocalhost\n9.9.9.9\n1.2.3.4 a b a", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_hosts code=%d out=%q err=%q", code, out, errS)
	}
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse_hosts json: %v (%q)", err, out)
	}
	want := map[string][]string{
		"127.0.0.1": {"localhost"},
		"9.9.9.9":   {},
		"1.2.3.4":   {"a", "b", "a"},
	}
	if !reflect.DeepEqual(parsed, want) {
		t.Fatalf("parse_hosts = %#v", parsed)
	}
	if strings.Contains(out, "null") {
		t.Fatalf("parse_hosts json contains null: %q", out)
	}

	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_hosts", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_hosts default code=%d err=%q", code, errS)
	}
	var message string
	if err := json.Unmarshal([]byte(out), &message); err != nil || message != "Error: hosts data was not found" {
		t.Fatalf("parse_hosts default out = %q (decoded %q, err %v)", out, message, err)
	}
}

// TestDNSUtilCLIParseZoneInline drives parse_zone end to end: the
// oracle-pinned SOA zone answers the full shape as JSON.
func TestDNSUtilCLIParseZoneInline(t *testing.T) {
	app := dnsutilCLIApp(t, &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, path: "/usr/bin/dig"})
	zone := "$ORIGIN example.com.\n@ IN SOA ns root.example.com. ( 1 2 3 4 5 6 7 8 )\nwww IN A 192.0.2.10\n"

	code, out, errS := captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", zone, "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_zone code=%d out=%q err=%q", code, out, errS)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse_zone json: %v (%q)", err, out)
	}
	if parsed["CONTACT"] != "root@example.com." || parsed["ORIGIN"] != "example.com." {
		t.Fatalf("parse_zone = %#v", parsed)
	}
	if a, ok := parsed["A"].(map[string]any); !ok || a["www.example.com."] != "192.0.2.10" {
		t.Fatalf("parse_zone A = %#v", parsed["A"])
	}

	// A crash-position zone answers the fixed value-free error on a
	// nonzero exit without leaking zone bytes.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", "www IN A 1.2.3.4", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone malformed code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: malformed zone data") {
		t.Fatalf("parse_zone malformed err = %q", errS)
	}
}

// TestDNSUtilCLIParseZoneMalformedMultiline pins R103A-FINAL-01 at the
// CLI surface: the whitespace-only '('…')' continuation join of the
// multiline zone "(\n)\n" answers the exact fixed value-free
// malformed-zone error on a nonzero exit with empty stdout and zero
// dig dispatch.
func TestDNSUtilCLIParseZoneMalformedMultiline(t *testing.T) {
	runner := &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, path: "/usr/bin/dig"}
	app := dnsutilCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", "(\n)\n", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone malformed-multiline code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: malformed zone data") {
		t.Fatalf("parse_zone malformed-multiline err = %q", errS)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("malformed-multiline dispatches = %d, want 0", len(runner.inner.commands))
	}

	// A parse_hosts call on the same app still answers normally: the
	// malformed zone did not break the family surface.
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_hosts",
		"--hosts", "1.2.3.4 a", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_hosts after malformed code=%d err=%q", code, errS)
	}
	var hosts map[string][]string
	if err := json.Unmarshal([]byte(out), &hosts); err != nil || !reflect.DeepEqual(hosts["1.2.3.4"], []string{"a"}) {
		t.Fatalf("parse_hosts after malformed out = %q", out)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("post-vector dispatches = %d, want 0", len(runner.inner.commands))
	}
}

// TestDNSUtilCLIDigDelegation drives the dig-backed surface end to end:
// dnsutil.A reaches the exact fixed dig argv through the real dig
// family and the result shape reaches stdout as JSON.
func TestDNSUtilCLIDigDelegation(t *testing.T) {
	runner := &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{
		script: map[string][]process.CommandResult{
			"/usr/bin/dig -r +short -q www.google.com -t A": {
				dnsutilCLIResult("74.125.193.104\n74.125.193.105\n", 0),
			},
			"/usr/bin/dig -r +short -q google.com -t MX": {
				dnsutilCLIResult("10 aspmx.l.google.com.\n", 0),
			},
		},
	}, path: "/usr/bin/dig"}
	app := dnsutilCLIApp(t, runner)

	code, out, errS := captureCode(t, app, "exec", "dnsutil.A", "--host", "www.google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dnsutil.A code=%d out=%q err=%q", code, out, errS)
	}
	var rows []string
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("dnsutil.A json: %v (%q)", err, out)
	}
	if fmt.Sprint(rows) != "[74.125.193.104 74.125.193.105]" {
		t.Fatalf("dnsutil.A rows = %#v", rows)
	}
	joined := strings.Join(append([]string{runner.inner.commands[0].Name}, runner.inner.commands[0].Args...), " ")
	if joined != "/usr/bin/dig -r +short -q www.google.com -t A" {
		t.Fatalf("dnsutil.A argv = %q", joined)
	}
	if runner.inner.commands[0].Shell {
		t.Fatal("dnsutil.A dispatched through a shell")
	}

	code, out, errS = captureCode(t, app, "exec", "dnsutil.MX", "--domain", "google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dnsutil.MX code=%d out=%q err=%q", code, out, errS)
	}
	var mxRows [][]string
	if err := json.Unmarshal([]byte(out), &mxRows); err != nil {
		t.Fatalf("dnsutil.MX json: %v (%q)", err, out)
	}
	if fmt.Sprint(mxRows) != "[[10 aspmx.l.google.com.]]" {
		t.Fatalf("dnsutil.MX rows = %#v", mxRows)
	}
	if len(runner.inner.commands) != 2 {
		t.Fatalf("dispatches = %d", len(runner.inner.commands))
	}
}

// TestDNSUtilCLIGateAnswersPinnedMessage pins the availability gate at
// the CLI surface: a failing resolver answers the pinned unavailable
// string as a successful result (the exact Salt shape) with zero
// dispatch, and the registry-miss class answers a nonzero exit with a
// value-free stderr.
func TestDNSUtilCLIGateAnswersPinnedMessage(t *testing.T) {
	gated := &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, err: fmt.Errorf("untrusted dig")}
	app := dnsutilCLIApp(t, gated)

	code, out, errS := captureCode(t, app, "exec", "dnsutil.A", "--host", "www.google.com", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dnsutil.A gated code=%d out=%q err=%q", code, out, errS)
	}
	var unavailable string
	if err := json.Unmarshal([]byte(out), &unavailable); err != nil ||
		unavailable != "This function requires dig, which is not currently available" {
		t.Fatalf("dnsutil.A gated out = %q (decoded %q, err %v)", out, unavailable, err)
	}
	if len(gated.inner.commands) != 0 {
		t.Fatalf("gated dispatches = %d", len(gated.inner.commands))
	}

	code, out, errS = captureCode(t, app, "exec", "dnsutil.check_ip", "--addr", "127.0.0.1", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("dnsutil.check_ip gated code=%d out=%q err=%q", code, out, errS)
	}
	unavailable = ""
	if err := json.Unmarshal([]byte(out), &unavailable); err != nil ||
		unavailable != "This function requires dig, which is not currently available" {
		t.Fatalf("dnsutil.check_ip gated out = %q (decoded %q, err %v)", out, unavailable, err)
	}

	// Registry miss (dnsutil without dig in the registry): the fixed
	// value-free unavailable error on stderr, no query value leak.
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
		Runner: &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, path: "/usr/bin/dig"},
	}
	if err := execdnsutil.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	missApp := NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
	code, out, errS = captureCode(t, missApp, "exec", "dnsutil.A", "--host", "www.google.com", "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("registry-miss code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: dig function unavailable") {
		t.Fatalf("registry-miss err = %q", errS)
	}
	if strings.Contains(errS, "www.google.com") {
		t.Fatalf("registry-miss err leaks the query value: %q", errS)
	}
}

// TestDNSUtilCLIResultBudgetRejectsOversized pins the R103A-GATE-01/02
// result budgets at the CLI surface: the ~17 KiB gate-probe zone (1024
// records whose expanded generic-bucket keys and values retain ~8.2 MB
// of JSON) answers the fixed value-free byte error on a nonzero exit
// with empty stdout, no zone bytes on stderr, and zero dig dispatch,
// while an under-ceiling escaping-heavy zone answers JSON on stdout.
// The R103A-GATE-02 shape-changing-replacement regression (8195 final
// retained items through two scalar->TARGET/TTL rewrites) and the
// R103A-FINAL-BYTES-01 exact nested-entry byte boundary (one encoded
// byte above an exactly-4,194,304-byte compact A/AAAA encoding
// rejected with empty stdout; the complete-result framing asserted
// byte-exactly on a small same-shape zone) ride the same surface.
func TestDNSUtilCLIResultBudgetRejectsOversized(t *testing.T) {
	runner := &dnsutilCLIResolverRunner{inner: &dnsutilCLIRunner{}, path: "/usr/bin/dig"}
	app := dnsutilCLIApp(t, runner)

	origin := strings.Repeat("a", 3999) + "."
	zone := "$ORIGIN " + origin + "\n"
	for i := 0; i < 1024; i++ {
		zone += fmt.Sprintf("x. IN @%d @\n", i)
	}

	code, out, errS := captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", zone, "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone oversized code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: result byte limit exceeded") {
		t.Fatalf("parse_zone oversized err = %q", errS)
	}
	if strings.Contains(errS, origin) || strings.Contains(errS, "x. IN") {
		t.Fatalf("parse_zone oversized err leaks zone bytes: %q", errS)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("oversized dispatches = %d, want 0", len(runner.inner.commands))
	}

	// The item ceiling rides the same surface value-free: 4095
	// owner-TTL-IN-A rows (12,287 retained nested items) reject with
	// the fixed item error.
	itemZone := "$ORIGIN example.com.\n"
	for i := 0; i < 4095; i++ {
		itemZone += fmt.Sprintf("h%d 60 IN A 127.0.0.1\n", i)
	}
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", itemZone, "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone item-over code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: result item limit exceeded") {
		t.Fatalf("parse_zone item-over err = %q", errS)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("item-over dispatches = %d, want 0", len(runner.inner.commands))
	}

	// R103A-GATE-02 shape-changing-replacement regression at the CLI
	// surface: $ORIGIN + two generic A strings for x0/x1 + the two
	// owner-TTL-IN-A rewrites of those owners + 2729 fresh
	// owner-TTL-IN-A rows retain 8195 items, three over the ceiling —
	// the pre-fix budget missed the two +2 replacements. Nonzero exit,
	// EMPTY stdout (no partial CLI output), the fixed value-free item
	// error on stderr, and zero dig dispatch.
	replacement := "$ORIGIN example.com.\n" +
		"x0 y A v0\n" +
		"x1 y A v1\n" +
		"x0 60 IN A 127.0.0.1\n" +
		"x1 60 IN A 127.0.0.1\n"
	for i := 0; i < 2729; i++ {
		replacement += fmt.Sprintf("h%d 60 IN A 127.0.0.1\n", i)
	}
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", replacement, "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone replacement-over code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: result item limit exceeded") {
		t.Fatalf("parse_zone replacement-over err = %q", errS)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("replacement-over dispatches = %d, want 0", len(runner.inner.commands))
	}

	// R103A-FINAL-BYTES-01 exact nested-entry byte boundary at the CLI
	// surface: the nested TARGET/TTL object contributes exactly 18
	// structural bytes (not 19), so a nested A/AAAA zone whose exact
	// compact encoding/json result is exactly 4,194,304 bytes is
	// accepted by the parser, and exactly one encoded byte above
	// answers the fixed value-free byte error on a nonzero exit with
	// EMPTY stdout (no partial CLI output) and zero dig dispatch. The
	// accepted full-result framing is asserted on a small same-shape
	// zone instead (the undrained capture pipes hold only a page or
	// two): the CLI output is byte-identical to an independently built
	// replica of the CLI's indented non-HTML-escaped encoder over the
	// oracle map, proving the complete result reaches stdout unchanged.
	payload := strings.Repeat("\x01", 2000)
	byteZone := func(records, pad int) string {
		zone := "$ORIGIN example.com.\n"
		for i := 0; i < records; i++ {
			zone += fmt.Sprintf("w%d 60 IN A %s\n", i, payload)
		}
		zone += fmt.Sprintf("z\"<\\%s <6> IN AAAA %s\n", strings.Repeat("a", pad), payload)
		return zone
	}
	oracleMap := func(records, pad int) map[string]any {
		m := map[string]any{"ORIGIN": "example.com.", "A": map[string]any{}, "AAAA": map[string]any{}}
		for i := 0; i < records; i++ {
			m["A"].(map[string]any)[fmt.Sprintf("w%d.example.com.", i)] =
				map[string]string{"TARGET": payload, "TTL": "60"}
		}
		m["AAAA"].(map[string]any)["z\"<\\"+strings.Repeat("a", pad)+".example.com."] =
			map[string]string{"TARGET": payload, "TTL": "<6>"}
		return m
	}
	encodedSize := func(pad int) int {
		enc, err := json.Marshal(oracleMap(347, pad))
		if err != nil {
			t.Fatal(err)
		}
		return len(enc)
	}
	lo, hi := 0, 3900
	if encodedSize(lo) > 4<<20 || encodedSize(hi) <= 4<<20 {
		t.Fatalf("CLI byte boundary not bracketed: %d..%d", encodedSize(lo), encodedSize(hi))
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if encodedSize(mid) <= 4<<20 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	atPad := lo - 1
	if encodedSize(atPad) != 4<<20 || encodedSize(atPad+1) != 4<<20+1 {
		t.Fatalf("CLI byte boundary not exact: %d %d", encodedSize(atPad), encodedSize(atPad+1))
	}

	// Small same-shape framing vector: three A records and one AAAA
	// record over a 64-byte control payload — the byte-exact CLI
	// framing of the complete nested result without stressing the
	// capture pipes.
	smallPayload := strings.Repeat("\x01", 64)
	smallZone := "$ORIGIN example.com.\n"
	for i := 0; i < 3; i++ {
		smallZone += fmt.Sprintf("w%d 60 IN A %s\n", i, smallPayload)
	}
	smallZone += fmt.Sprintf("z\"<\\10 <6> IN AAAA %s\n", smallPayload)
	smallOracle := func() map[string]any {
		m := map[string]any{"ORIGIN": "example.com.", "A": map[string]any{}, "AAAA": map[string]any{}}
		for i := 0; i < 3; i++ {
			m["A"].(map[string]any)[fmt.Sprintf("w%d.example.com.", i)] =
				map[string]string{"TARGET": smallPayload, "TTL": "60"}
		}
		m["AAAA"].(map[string]any)["z\"<\\10.example.com."] =
			map[string]string{"TARGET": smallPayload, "TTL": "<6>"}
		return m
	}
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", smallZone, "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_zone small-framing code=%d err=%q", code, errS)
	}
	var cliFramed bytes.Buffer
	enc := json.NewEncoder(&cliFramed)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(smallOracle()); err != nil {
		t.Fatal(err)
	}
	if out != cliFramed.String() {
		t.Fatalf("parse_zone small-framing out = %d bytes, want the byte-exact oracle framing of %d",
			len(out), cliFramed.Len())
	}
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", byteZone(347, atPad+1), "-o", "json")
	if code == ExitOK || out != "" || errS == "" {
		t.Fatalf("parse_zone one-byte-over code=%d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "dnsutil: result byte limit exceeded") {
		t.Fatalf("parse_zone one-byte-over err = %q", errS)
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("one-byte-over dispatches = %d, want 0", len(runner.inner.commands))
	}

	// An under-ceiling escaping-heavy zone answers JSON on stdout
	// within the cap (the CLI encoder's trailing newline aside).
	escape := "$ORIGIN \"o\\b\x01.\n\"ow\\q\"\x01. 60 IN A 127.0.0.1\n"
	code, out, errS = captureCode(t, app, "exec", "dnsutil.parse_zone", "--zone", escape, "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("parse_zone escaping code=%d err=%q", code, errS)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse_zone escaping json: %v (%q)", err, out)
	}
	if len(out) > 4<<20 {
		t.Fatalf("parse_zone escaping out = %d bytes", len(out))
	}
	aBucket, ok := parsed["A"].(map[string]any)
	if !ok || len(aBucket) != 1 {
		t.Fatalf("parse_zone escaping A = %#v", parsed["A"])
	}
	if len(runner.inner.commands) != 0 {
		t.Fatalf("escaping dispatches = %d, want 0", len(runner.inner.commands))
	}
}
