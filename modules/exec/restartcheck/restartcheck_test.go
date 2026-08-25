package restartcheck

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests pinning the family dispatch, kernel detection and formatter
// behaviors read from saltstack/salt/modules/restartcheck.py @ pinned
// revision. The /proc scanner runs against the real /proc tree.

func rcRT(t *testing.T, family string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: strings.ToLower(family), Name: family, Family: family,
		}}),
	}
	return rt
}

type scriptedRunner struct {
	calls  [][]string
	stdout map[string]string
}

func (s *scriptedRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	s.calls = append(s.calls, argv)
	if out, ok := s.stdout[strings.Join(argv, " ")]; ok {
		return process.CommandResult{Stdout: []byte(out)}
	}
	return process.CommandResult{}
}

// Unsupported families return the verbatim dict.
func TestUnsupportedFamily(t *testing.T) {
	rt := rcRT(t, "suse")
	fn := restartCheckFunc{}
	res, err := fn.Execute(context.Background(), rt, &RestartCheckArgs{})
	if err != nil {
		t.Fatal(err)
	}
	dict := res.(map[string]any)
	if dict["result"] != false ||
		dict["comment"] != "Only available on Debian, Red Hat and NI Linux Real-Time based systems." {
		t.Fatalf("unsupported family = %#v", dict)
	}
}

// Debian path: kernel detection via dpkg --get-selections; with no deleted
// files the check reports nothing to restart.
func TestDebianNoPackages(t *testing.T) {
	rt := rcRT(t, "debian")
	runner := &scriptedRunner{stdout: map[string]string{
		"uname -a":                                    "Linux host 6.1.0-16-amd64 #1 SMP Debian 6.1.0-16",
		"dpkg --get-selections linux-image-*":         "linux-image-6.1.0-16-amd64\t\tinstall\nlinux-image-6.1.0-17-amd64\t\tinstall\n",
		"apt-cache policy linux-image-6.1.0-16-amd64": "linux-image-6.1.0-16-amd64:\n  Installed: 6.1.0-16-amd64\n",
	}}
	rt.Runner = runner

	got, err := restartCheckFunc{}.Execute(context.Background(), rt, &RestartCheckArgs{})
	if err != nil {
		t.Fatal(err)
	}
	s := got.(string)
	if !strings.Contains(s, "No packages seem to need to be restarted.") {
		t.Fatalf("reply = %q", s)
	}
	foundDpkg := false
	for _, call := range runner.calls {
		if equalSlice(call[:2], []string{"dpkg", "--get-selections"}) {
			foundDpkg = true
		}
	}
	if !foundDpkg {
		t.Fatalf("dpkg probe missing: %#v", runner.calls)
	}
}

// RedHat path uses rpm -q kernel for version names.
func TestRedhatKernelVersions(t *testing.T) {
	rt := rcRT(t, "redhat")
	runner := &scriptedRunner{stdout: map[string]string{
		"uname -a":      "Linux host 5.14.0-362.el9.x86_64 #1 SMP x86_64",
		"rpm -q kernel": "kernel-5.14.0-100.el9\nkernel-5.14.0-362.el9\n",
	}}
	rt.Runner = runner

	versions := kernelVersionsRedhat(context.Background(), rt)
	want := []string{"vmlinuz-kernel-5.14.0-100.el9", "vmlinuz-kernel-5.14.0-362.el9"}
	if len(versions) != 2 || versions[0] != want[0] || versions[1] != want[1] {
		t.Fatalf("redhat kernels = %#v; want %#v", versions, want)
	}
	_ = runner
}

// Pins validDeletedFile filtering: deleted/inode markers pass, excluded
// directories fail.
func TestValidDeletedFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/x.so (deleted)", true},
		{"/usr/lib/lib.so.#prelink#.1234 (path inode=12345)", true},
		{"/var/log/syslog (deleted)", false},
		{"/tmp/junk (deleted)", false},
		{"/usr/lib/normal.so", false},
	}
	for _, c := range cases {
		if got := validDeletedFile(c.path); got != c.want {
			t.Fatalf("validDeletedFile(%q) = %v; want %v", c.path, got, c.want)
		}
	}
}

// Pins the verbose formatter text shapes.
func TestFormatOutputVerbose(t *testing.T) {
	assertStr := func(v any, substr string) {
		s, ok := v.(string)
		if !ok || !strings.Contains(s, substr) {
			t.Fatalf("output %#v missing %q", v, substr)
		}
	}
	packages := map[string]*pkgInfo{
		"nginx": {
			InitScripts: []string{"nginx"},
			Processes:   []string{"\t123 /usr/sbin/nginx (file: /usr/sbin/nginx)"},
			ProcessName: "nginx",
		},
	}
	ret := FormatOutput(true, packages, true,
		[]string{"nginx"}, nil,
		[]string{"systemctl restart nginx.service"}, nil)
	assertStr(ret, "System restart required.")
	assertStr(ret, "Found 1 processes using old versions")
	assertStr(ret, "These are the systemd services:")
	assertStr(ret, "systemctl restart nginx.service")

	nonrestartable := map[string]*pkgInfo{
		"custom": {Processes: []string{"\t456 /opt/app"}, ProcessName: "custom"},
	}
	ret = FormatOutput(false, nonrestartable, true, nil, []string{"custom"}, nil, nil)
	assertStr(ret, "These processes 1 do not seem to have an associated init script")
}

// Non-verbose output lists package names only.
func TestFormatOutputNonVerbose(t *testing.T) {
	ret := FormatOutput(true, map[string]*pkgInfo{}, false,
		nil, nil, nil, nil)
	list := ret.([]string)
	if len(list) != 1 || list[0] != "System restart required." {
		t.Fatalf("kernel-only list = %#v", list)
	}
}

func ctxBg() context.Context { return context.Background() }

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
