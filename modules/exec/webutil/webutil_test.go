package webutil

// R5.3 tests for the htpasswd surface, mapped onto the source-derived
// contracts of saltstack/salt/modules/webutil.py @ pinned revision.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type wuRunner struct {
	calls []process.Command
	resp  func(process.Command) process.CommandResult
}

func (r *wuRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.calls = append(r.calls, c)
	if r.resp != nil {
		return r.resp(c)
	}
	return process.CommandResult{}
}

func wuRT(t *testing.T) (*runtime.Runtime, *wuRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &wuRunner{}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  runner,
		Options: runtime.RuntimeOptions{},
	}
	orig := whichBin
	whichBin = func(exe string) string { return "/usr/bin/" + exe }
	t.Cleanup(func() { whichBin = orig })
	return rt, runner
}

func mustWU(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func TestWebutilLifecycle(t *testing.T) {
	rt, runner := wuRT(t)

	// useradd on an absent file appends the create flag "c".
	res := mustWU(t, rt, "webutil.useradd", &useraddArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "larry", Password: "badpassword",
	})
	m := res.(map[string]any)
	cmd := runner.calls[len(runner.calls)-1]
	if wuArgv(cmd) != "htpasswd -bc /etc/httpd/htpasswd larry badpassword" {
		t.Fatalf("create argv = %v %v", cmd.Name, cmd.Args)
	}
	if m["retcode"] != 0 {
		t.Fatalf("run_all shape = %#v", m)
	}

	// Existing file keeps plain opts.
	if err := rt.FS.MkdirAll(filepath.Dir("/etc/httpd/htpasswd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/httpd/htpasswd", []byte("larry:$apr1$\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustWU(t, rt, "webutil.useradd", &useraddArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "curly", Password: "pw",
		Opts: strPtrWU("ns"),
	})
	cmd = runner.calls[len(runner.calls)-1]
	if wuArgv(cmd) != "htpasswd -bns /etc/httpd/htpasswd curly pw" {
		t.Fatalf("append argv = %v", cmd.Args)
	}

	// userdel returns stdout lines by default and the error string when the
	// file is absent.
	runner.resp = func(c process.Command) process.CommandResult {
		if c.Args[0] == "-D" {
			return process.CommandResult{Stdout: []byte("Deleted password for user larry\n")}
		}
		return process.CommandResult{}
	}
	res = mustWU(t, rt, "webutil.userdel", &userdelArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "larry",
	})
	list, ok := res.([]any)
	if !ok || len(list) != 1 || !strings.Contains(list[0].(string), "Deleted password") {
		t.Fatalf("userdel lines = %#v", res)
	}
	res = mustWU(t, rt, "webutil.userdel", &userdelArgs{
		Pwfile: "/nonexistent/htpasswd", User: "larry",
	})
	if res != "Error: The specified htpasswd file does not exist" {
		t.Fatalf("absent-file reply = %#v", res)
	}

	// all_results switches to the run_all dict.
	all := true
	res = mustWU(t, rt, "webutil.userdel", &userdelArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "curly", AllResults: &all,
	})
	if _, ok := res.(map[string]any); !ok {
		t.Fatalf("all_results shape = %#v", res)
	}

	// verify maps retcode 0 -> true; missing file -> literal False.
	runner.resp = func(process.Command) process.CommandResult {
		return process.CommandResult{ExitCode: 1}
	}
	res = mustWU(t, rt, "webutil.verify", &verifyArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "larry", Password: "wrong",
	})
	if res != false {
		t.Fatalf("mismatch verify = %#v", res)
	}
	runner.resp = func(process.Command) process.CommandResult {
		return process.CommandResult{ExitCode: 0}
	}
	res = mustWU(t, rt, "webutil.verify", &verifyArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "larry", Password: "ok",
	})
	if res != true {
		t.Fatalf("match verify = %#v", res)
	}
	res = mustWU(t, rt, "webutil.verify", &verifyArgs{
		Pwfile: "/nonexistent", User: "larry", Password: "x",
	})
	if res != false {
		t.Fatalf("absent verify = %#v", res)
	}

	// Missing htpasswd binary -> verbatim __virtual__ message.
	orig := whichBin
	whichBin = func(string) string { return "" }
	t.Cleanup(func() { whichBin = orig })
	_, err := verifyFunc{}.Execute(context.Background(), rt, &verifyArgs{
		Pwfile: "/etc/httpd/htpasswd", User: "larry", Password: "x",
	})
	if err == nil ||
		err.Error() != "The htpasswd execution mdule cannot be loaded: htpasswd binary not in path." {
		t.Fatalf("which-guard = %v", err)
	}
}

func strPtrWU(s string) *string { return &s }

func wuArgv(c process.Command) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}
