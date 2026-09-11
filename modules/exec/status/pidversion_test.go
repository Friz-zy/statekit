package status

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// R4-final tests for status.pid and status.version, pinned to
// saltstack/salt/modules/status.py:1607-1682.

func linuxVersionRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := stRT(t, files)
	rt.Facts = facts.ForTesting(facts.Overrides{Kernel: &facts.KernelFacts{Name: "Linux"}})
	return rt
}

func kernelRT(t *testing.T, kernel string, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := stRT(t, files)
	rt.Facts = facts.ForTesting(facts.Overrides{Kernel: &facts.KernelFacts{Name: kernel}})
	return rt
}

// TestFilterPidLinesSaltFixture replays Salt's own unit-test fixture
// (tests/pytests/unit/modules/test_status.py test_status_pid_linux):
// ps rows, own pid 6674 excluded, sig "httpd" -> the five httpd pids.
func TestFilterPidLinesSaltFixture(t *testing.T) {
	ps := []string{
		"UID      PID PPID  C STIME TTY      TIME CMD",
		"root     360    2  0 Jun08 ?        00:00:00   [jbd2/dm-0-8]",
		"root     947    2  0 Jun08 ?        00:00:00  [jbd2/dm-1-8]",
		"root    2701    1  0 Jun08 ?        00:00:28   /usr/sbin/httpd -k start",
		"apache  7539 2701  0 04:40 ?        00:00:04     /usr/sbin/httpd -k start",
		"apache  7540 2701  0 04:40 ?        00:00:02     /usr/sbin/httpd -k start",
		"apache  7542 2701  0 04:40 ?        00:01:46     /usr/sbin/httpd -k start",
		"apache  7623 2701  0 04:40 ?        00:02:41     /usr/sbin/httpd -k start",
		"root    1564    1  0 Jun11 ?        00:07:19   /usr/bin/python3 /usr/bin/salt-minion -d",
		"root    6674 1564  0 19:53 ?        00:00:00    /usr/bin/python3 /usr/bin/salt-call status.pid httpd -l debug",
	}
	sig := regexp.MustCompile("httpd")
	got := filterPidLines(ps, "6674", sig)
	want := []string{"2701", "7539", "7540", "7542", "7623"}
	if !equalSlice(got, want) {
		t.Fatalf("filterPidLines = %#v want %#v", got, want)
	}
	if joined := strings.Join(got, "\n"); joined != "2701\n7539\n7540\n7542\n7623" {
		t.Fatalf("join shape = %q", joined)
	}
}

// TestFilterPidLinesOwnPidSubstringQuirk pins Salt's substring (not
// column) own-pid skip: a foreign process whose command line merely
// mentions the pid string is dropped too, and lines without a PID column
// cannot contribute.
func TestFilterPidLinesOwnPidSubstringQuirk(t *testing.T) {
	sig := regexp.MustCompile("worker")
	lines := []string{
		"root 42 1 /usr/bin/daemon worker",        // matches
		"root 43 1 /usr/bin/daemon --port 6674",   // mentions own pid: skipped
		"root    6674 1 /usr/bin/daemon worker",   // own row: skipped
		"solo",                                    // no PID column: skipped
		"root 44 1 /usr/bin/other worker --pad x", // matches
	}
	got := filterPidLines(lines, "6674", sig)
	if !equalSlice(got, []string{"42", "44"}) {
		t.Fatalf("quirk filter = %#v", got)
	}
}

// TestStatusPidExcludesOwnProcess scans the real /proc (kernel FS, not
// injectable): a regex matching the test binary's own command line must
// not yield the own pid, and the catch-all regex must yield numeric
// pids in /proc directory order with the own pid absent.
func TestStatusPidExcludesOwnProcess(t *testing.T) {
	fn := statusPidFunc{}
	own := strconv.Itoa(os.Getpid())

	selfSig := regexp.QuoteMeta(os.Args[0])
	got, err := fn.Execute(context.Background(), nil, &statusPidArgs{Sig: selfSig})
	if err != nil {
		t.Fatalf("self-match pid: %v", err)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("pid result type %T", got)
	}
	for _, line := range strings.Split(s, "\n") {
		if line == own {
			t.Fatalf("own pid %s leaked into self-match result %q", own, s)
		}
	}

	all, err := fn.Execute(context.Background(), nil, &statusPidArgs{Sig: ".*"})
	if err != nil {
		t.Fatalf("catch-all pid: %v", err)
	}
	lines := strings.Split(all.(string), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		t.Fatalf("catch-all scan found no processes: %q", all)
	}
	seen := map[string]bool{}
	for _, line := range lines {
		if _, convErr := strconv.Atoi(line); convErr != nil {
			t.Fatalf("non-numeric pid %q in %q", line, all)
		}
		if line == own {
			t.Fatalf("own pid %s leaked into catch-all result", own)
		}
		if seen[line] {
			t.Fatalf("duplicate pid %q", line)
		}
		seen[line] = true
	}
	if !sort.StringsAreSorted(lines) {
		t.Fatalf("pids not in /proc directory (sorted) order: %v", lines)
	}
}

func TestStatusPidNoMatchReturnsEmptyString(t *testing.T) {
	got, err := (statusPidFunc{}).Execute(context.Background(), nil,
		&statusPidArgs{Sig: "StateKitNoSuchProcessZZQQ123"})
	if err != nil {
		t.Fatalf("no-match pid: %v", err)
	}
	if got != "" {
		t.Fatalf("no-match result = %#v, want empty string", got)
	}
}

func TestStatusPidInvalidRegexFailsBeforeScan(t *testing.T) {
	got, err := (statusPidFunc{}).Execute(context.Background(), nil,
		&statusPidArgs{Sig: "[unclosed"})
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("invalid regex err = %v", err)
	}
	if got != nil {
		t.Fatalf("invalid regex result = %#v", got)
	}
	// RE2-rejected Python-re constructs (lookaround) fail the same way.
	if _, err = (statusPidFunc{}).Execute(context.Background(), nil,
		&statusPidArgs{Sig: "(?<=x)y"}); err == nil {
		t.Fatal("lookaround signature must fail compilation under RE2")
	}
}

func TestStatusVersionLinux(t *testing.T) {
	content := "Linux version 6.1.0-23-amd64 (debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC\n"
	rt := linuxVersionRT(t, map[string]string{"/proc/version": content})
	got, err := (statusVersionFunc{}).Execute(context.Background(), rt, &statusVersionArgs{})
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if got != strings.TrimSpace(content) {
		t.Fatalf("version = %#v", got)
	}
}

func TestStatusVersionReadErrorYieldsEmptyMap(t *testing.T) {
	rt := linuxVersionRT(t, nil) // no /proc/version in the FS stub
	got, err := (statusVersionFunc{}).Execute(context.Background(), rt, &statusVersionArgs{})
	if err != nil {
		t.Fatalf("version missing file: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok || m == nil || len(m) != 0 {
		t.Fatalf("version missing file = %#v, want empty map", got)
	}
}

func TestStatusVersionBoundEnforced(t *testing.T) {
	rt := linuxVersionRT(t, map[string]string{"/proc/version": strings.Repeat("a", int(maxProcVersionBytes)*2)})
	got, err := (statusVersionFunc{}).Execute(context.Background(), rt, &statusVersionArgs{})
	if err != nil {
		t.Fatalf("version oversized: %v", err)
	}
	if m, ok := got.(map[string]any); !ok || len(m) != 0 {
		t.Fatalf("version oversized = %#v, want empty map from bounded read", got)
	}
}

func TestStatusVersionUnsupportedKernels(t *testing.T) {
	const errmsg = "This method is unsupported on the current operating system!"
	for _, kernel := range []string{"", "windows", "darwin", "freebsd", "FreeBSD", "Junos", "OpenBSD", "AIX"} {
		rt := kernelRT(t, kernel, nil)
		got, err := (statusVersionFunc{}).Execute(context.Background(), rt, &statusVersionArgs{})
		if err != nil {
			t.Fatalf("kernel %q: %v", kernel, err)
		}
		if got != errmsg {
			t.Fatalf("kernel %q version = %#v", kernel, got)
		}
	}
}

func TestStatusPidVersionRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTail(reg); err != nil {
		t.Fatal(err)
	}

	pidFn, ok := reg.Get("status.pid")
	if !ok {
		t.Fatal("status.pid is not registered")
	}
	versionFn, ok := reg.Get("status.version")
	if !ok {
		t.Fatal("status.version is not registered")
	}
	if _, ok := reg.Get("status.pid_list"); !ok {
		t.Fatal("status.pid_list must stay registered as a distinct name")
	}

	if !reflect.DeepEqual(pidFn.Args(), statusPidArgs{Sig: ""}) {
		t.Fatalf("pid Args = %#v", pidFn.Args())
	}
	if !reflect.DeepEqual(versionFn.Args(), statusVersionArgs{}) {
		t.Fatalf("version Args = %#v", versionFn.Args())
	}
	pidNames, err := config.ArgumentNames(pidFn.Args())
	if err != nil || !equalSlice(pidNames, []string{"sig"}) {
		t.Fatalf("pid argument names = %v err=%v", pidNames, err)
	}
	versionNames, err := config.ArgumentNames(versionFn.Args())
	if err != nil || len(versionNames) != 0 {
		t.Fatalf("version argument names = %v err=%v", versionNames, err)
	}

	if constrained, ok := pidFn.(runtime.PlatformConstrained); !ok ||
		!equalSlice(constrained.Platforms(), []string{"linux"}) {
		t.Fatalf("pid must be procOnly linux-only: %v", pidFn)
	}
	if _, ok := versionFn.(runtime.PlatformConstrained); ok {
		t.Fatal("version must dispatch on Facts kernel, not GOOS platforms")
	}
	if caps := reg.ProviderCapabilities("status.pid"); caps != nil {
		t.Fatalf("pid capabilities = %v", caps)
	}
	if caps := reg.ProviderCapabilities("status.version"); caps != nil {
		t.Fatalf("version capabilities = %v", caps)
	}

	rt := linuxVersionRT(t, map[string]string{"/proc/version": "Linux version 1.2.3 test\n"})

	pidProto, err := reg.ResolveArgs(rt, "status.pid")
	if err != nil || reflect.TypeOf(pidProto) != reflect.TypeOf(statusPidArgs{}) {
		t.Fatalf("pid prototype = %T err=%v", pidProto, err)
	}
	listProto, err := reg.ResolveArgs(rt, "status.pid_list")
	if err != nil || reflect.TypeOf(listProto) != reflect.TypeOf(pidListArgs{}) {
		t.Fatalf("pid_list prototype = %T err=%v (cross-registration?)", listProto, err)
	}

	got, err := reg.Call(context.Background(), rt, "status.version", &statusVersionArgs{})
	if err != nil {
		t.Fatalf("registry version call: %v", err)
	}
	if got != "Linux version 1.2.3 test" {
		t.Fatalf("registry version = %#v", got)
	}
	got, err = reg.Call(context.Background(), rt, "status.pid",
		&statusPidArgs{Sig: "StateKitNoSuchProcessZZQQ123"})
	if err != nil {
		t.Fatalf("registry pid call: %v", err)
	}
	if got != "" {
		t.Fatalf("registry pid = %#v", got)
	}
}
