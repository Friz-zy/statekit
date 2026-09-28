//go:build dns_contract

package differential

// R10.2 dig behavioral differential tests, moved out of r10_test.go
// behind the dns_contract build tag: the default host CI `go test
// ./...` compiles none of this file, while the rootless contract job
// (`go test -tags=dns_contract ./modules/exec/dig ./internal/cli
// ./tests/differential`) executes every test below. Every vector is
// scripted-fake-only over the r10DigRunner/r10DigResolverRunner seams:
// no dig binary is executed, no DNS name is resolved, and no network
// is touched. Test names and expected cases are unchanged by the move.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execdig "github.com/friz-zy/statekit/modules/exec/dig"
)

// r10DigRunner is the scripted fake Runner for the dig differential
// vectors: no dig execution, no DNS, no network.
type r10DigRunner struct {
	script   map[string][]process.CommandResult
	commands []process.Command
}

func (r *r10DigRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
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

// r10DigResolverRunner adds the test TrustedCommandResolver seam: it
// answers a synthetic absolute path for "dig" only (R102-SEC-01), so
// the differential transport vectors pin the trusted native boundary
// without any real binary.
type r10DigResolverRunner struct {
	inner *r10DigRunner
	path  string
	err   error
}

func (r *r10DigResolverRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	return r.inner.Run(ctx, cmd)
}

func (r *r10DigResolverRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != "dig" {
		return "", process.ErrTrustedCommandUnsupported
	}
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

// TestR10DigMockDifferential pins the dig family contract through the
// registered names with the scripted fake Runner behind a test trusted
// resolver: the exact shell-free argv over the resolved absolute path,
// the exact environment allowlist, the pinned SPF include recursion,
// and the alias parity.
func TestR10DigMockDifferential(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := execdig.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &r10DigResolverRunner{inner: &r10DigRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q www.google.com -t A": {
			{Stdout: []byte("74.125.193.104\n74.125.193.105\n74.125.193.99\n74.125.193.106\n74.125.193.103\n74.125.193.147\n"), ExitCode: 0},
			{Stdout: []byte("74.125.193.104\n74.125.193.105\n74.125.193.99\n74.125.193.106\n74.125.193.103\n74.125.193.147\n"), ExitCode: 0},
		},
		"/usr/bin/dig -r +short -q xmission.com -t SPF": {{ExitCode: 0}},
		"/usr/bin/dig -r +short -q xmission.com -t TXT": {
			{Stdout: []byte(`"v=spf1 a mx include:_spf.xmission.com ?all"` + "\n"), ExitCode: 0},
		},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t SPF": {{ExitCode: 0}},
		"/usr/bin/dig -r +short -q _spf.xmission.com -t TXT": {
			{Stdout: []byte(`"v=spf1 a mx ip4:198.60.22.0/24 ip4:166.70.13.0/24 ~all"` + "\n"), ExitCode: 0},
		},
	}}, path: "/usr/bin/dig"}
	rt := &runtime.Runtime{Exec: reg, Runner: runner}

	value, err := reg.Call(context.Background(), rt, "dig.A", &execdig.AArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatalf("r10 dig.A: %v", err)
	}
	want := []string{"74.125.193.104", "74.125.193.105", "74.125.193.99", "74.125.193.106", "74.125.193.103", "74.125.193.147"}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("r10 dig.A value = %#v", value)
	}
	first := runner.inner.commands[0]
	joined := strings.Join(append([]string{first.Name}, first.Args...), " ")
	if joined != "/usr/bin/dig -r +short -q www.google.com -t A" {
		t.Fatalf("r10 dig.A argv = %q", joined)
	}
	if first.Shell {
		t.Fatal("r10 dig.A dispatched through a shell")
	}
	// The child environment is exactly the fixed allowlist; nothing is
	// inherited from the parent environment.
	wantEnv := []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "TZ=UTC"}
	if !reflect.DeepEqual(first.Env, wantEnv) {
		t.Fatalf("r10 dig.A env = %q, want %q", first.Env, wantEnv)
	}

	// The alias answers the identical value through the identical argv.
	aliasValue, err := reg.Call(context.Background(), rt, "dig.a", &execdig.AArgs{Host: "www.google.com"})
	if err != nil {
		t.Fatalf("r10 dig.a: %v", err)
	}
	if !reflect.DeepEqual(aliasValue, want) {
		t.Fatalf("r10 dig.a value = %#v", aliasValue)
	}

	value, err = reg.Call(context.Background(), rt, "dig.SPF", &execdig.SPFArgs{Domain: "xmission.com"})
	if err != nil {
		t.Fatalf("r10 dig.SPF: %v", err)
	}
	if !reflect.DeepEqual(value, []string{"198.60.22.0/24", "166.70.13.0/24"}) {
		t.Fatalf("r10 dig.SPF value = %#v", value)
	}
	// SPF xmission.com dispatches SPF (empty), TXT fallback, then the
	// include target's SPF (empty) and TXT fallback: four processes,
	// all shell-free over the resolved absolute path.
	if len(runner.inner.commands) != 6 {
		t.Fatalf("r10 dispatches = %d", len(runner.inner.commands))
	}
	for i, cmd := range runner.inner.commands {
		if cmd.Shell {
			t.Fatalf("r10 dispatch %d ran through a shell", i)
		}
		if cmd.Name != "/usr/bin/dig" {
			t.Fatalf("r10 dispatch %d executable = %q", i, cmd.Name)
		}
		if !reflect.DeepEqual(cmd.Env, wantEnv) {
			t.Fatalf("r10 dispatch %d env = %q", i, cmd.Env)
		}
	}
	spfSecond := strings.Join(append([]string{runner.inner.commands[3].Name}, runner.inner.commands[3].Args...), " ")
	if spfSecond != "/usr/bin/dig -r +short -q xmission.com -t TXT" {
		t.Fatalf("r10 SPF fallback argv = %q", spfSecond)
	}
}

// TestR10DigTrustedGateAndUnverifiedExecutable pins the availability
// gate over the trusted resolver seam: failed resolution fails every
// function closed with zero dispatch, and a resolver-less fake Runner
// cannot verify the executable — it fails closed with the fixed
// unverified-executable error and zero dispatch (the module never
// LookPaths and never dispatches a bare name).
func TestR10DigTrustedGateAndUnverifiedExecutable(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := execdig.Register(reg); err != nil {
		t.Fatal(err)
	}
	gated := &r10DigResolverRunner{inner: &r10DigRunner{}, err: process.ErrTrustedCommandUnavailable}
	rt := &runtime.Runtime{Exec: reg, Runner: gated}
	if _, err := reg.Call(context.Background(), rt, "dig.A", &execdig.AArgs{Host: "x.example"}); err == nil ||
		!strings.Contains(err.Error(), "dig module cannot be loaded") {
		t.Fatalf("r10 gated dig.A err = %v", err)
	}
	if _, err := reg.Call(context.Background(), rt, "dig.check_ip", &execdig.CheckIPArgs{Addr: "127.0.0.1"}); err == nil ||
		!strings.Contains(err.Error(), "dig module cannot be loaded") {
		t.Fatalf("r10 gated check_ip err = %v", err)
	}
	if len(gated.inner.commands) != 0 {
		t.Fatalf("r10 gated dispatches = %d", len(gated.inner.commands))
	}

	// A resolver answering a relative path violates the trusted
	// contract and fails closed identically.
	relative := &r10DigResolverRunner{inner: &r10DigRunner{}, path: "dig"}
	rtRelative := &runtime.Runtime{Exec: reg, Runner: relative}
	if _, err := reg.Call(context.Background(), rtRelative, "dig.A", &execdig.AArgs{Host: "x.example"}); err == nil {
		t.Fatal("r10 relative-path resolver must fail closed")
	}

	// The capability-less fake Runner never reaches a dispatch: the
	// fixed unverified-executable error answers every dig.* target,
	// including check_ip, with zero processes — no LookPath, no
	// bare-name PATH fallback.
	capless := &r10DigRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q x.example -t A": {{Stdout: []byte("1.2.3.4\n"), ExitCode: 0}},
	}}
	rtCapless := &runtime.Runtime{Exec: reg, Runner: capless}
	if _, err := reg.Call(context.Background(), rtCapless, "dig.A", &execdig.AArgs{Host: "x.example"}); err == nil ||
		!strings.Contains(err.Error(), "dig: unverified executable") {
		t.Fatalf("r10 capability-less dig.A err = %v", err)
	}
	if _, err := reg.Call(context.Background(), rtCapless, "dig.check_ip", &execdig.CheckIPArgs{Addr: "127.0.0.1"}); err == nil ||
		!strings.Contains(err.Error(), "dig: unverified executable") {
		t.Fatalf("r10 capability-less check_ip err = %v", err)
	}
	if len(capless.commands) != 0 {
		t.Fatalf("r10 capability-less dispatches = %d", len(capless.commands))
	}
}

// TestR10DigPythonSemantics pins the runtime-checker-corrected Python
// semantics at the registered surface: check_ip's int()/ip_address
// grammar (R102-F2) and the Python whitespace predicate behind the
// trailing rstrip and MX/SPF field splits (R102-F3).
func TestR10DigPythonSemantics(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := execdig.Register(reg); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Exec: reg, Runner: &r10DigResolverRunner{inner: &r10DigRunner{}, path: "/usr/bin/dig"}}
	ctx := context.Background()

	vectors := []struct {
		addr string
		want bool
	}{
		{"192.0.2.1/2_4", true},   // Python underscores between digits
		{"192.0.2.1/２４", true},    // Unicode Nd decimal digits
		{"192.0.2.1/２_４", true},   // underscore between Nd digits
		{"192.0.2.1/24_", false},  // trailing underscore
		{"192.0.2.1/2__4", false}, // doubled underscore
		{"fe80::1%eth0", true},    // scoped IPv6 literal (Python >= 3.9)
		{"fe80::1%eth0/64", true},
		{"1.2.3.4%eth0", false}, // zoned IPv4 stays invalid
	}
	for _, v := range vectors {
		value, err := reg.Call(ctx, rt, "dig.check_ip", &execdig.CheckIPArgs{Addr: v.addr})
		if err != nil {
			t.Fatalf("r10 check_ip(%q): %v", v.addr, err)
		}
		if value != v.want {
			t.Fatalf("r10 check_ip(%q) = %v, want %v", v.addr, value, v.want)
		}
	}

	// U+001C is Python whitespace: MX rows and SPF sections split on it
	// and the transport's trailing rstrip drops a trailing run.
	runner := &r10DigRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t MX":  {{Stdout: []byte("10\x1cmx.example.\n"), ExitCode: 0}},
		"/usr/bin/dig -r +short -q ws.example -t TXT": {{Stdout: []byte("v=spf1\x1cip4:192.0.2.1/2_4 ~all"), ExitCode: 0}},
	}}
	rt2 := &runtime.Runtime{Exec: reg, Runner: &r10DigResolverRunner{inner: runner, path: "/usr/bin/dig"}}
	value, err := reg.Call(ctx, rt2, "dig.MX", &execdig.MXArgs{Domain: "ws.example"})
	if err != nil {
		t.Fatalf("r10 MX whitespace: %v", err)
	}
	if !reflect.DeepEqual(value, [][]string{{"10", "mx.example."}}) {
		t.Fatalf("r10 MX whitespace value = %#v", value)
	}
	value, err = reg.Call(ctx, rt2, "dig.SPF", &execdig.SPFArgs{Domain: "ws.example", Record: ptrStringR10("TXT")})
	if err != nil {
		t.Fatalf("r10 SPF whitespace: %v", err)
	}
	if !reflect.DeepEqual(value, []string{"192.0.2.1/2_4"}) {
		t.Fatalf("r10 SPF whitespace value = %#v", value)
	}

	// The trailing rstrip drops a trailing U+001C run before the TXT
	// newline split.
	runner2 := &r10DigRunner{script: map[string][]process.CommandResult{
		"/usr/bin/dig -r +short -q ws.example -t TXT": {{Stdout: []byte("row\x1c"), ExitCode: 0}},
	}}
	rt3 := &runtime.Runtime{Exec: reg, Runner: &r10DigResolverRunner{inner: runner2, path: "/usr/bin/dig"}}
	value, err = reg.Call(ctx, rt3, "dig.TXT", &execdig.TXTArgs{Host: "ws.example"})
	if err != nil {
		t.Fatalf("r10 TXT whitespace: %v", err)
	}
	if !reflect.DeepEqual(value, []string{"row"}) {
		t.Fatalf("r10 TXT whitespace value = %#v", value)
	}
}

func ptrStringR10(v string) *string { return &v }
