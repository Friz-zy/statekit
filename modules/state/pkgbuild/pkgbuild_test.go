package pkgbuild

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkgbuild "github.com/friz-zy/statekit/modules/exec/pkgbuild"
)

// State tests pinning the flows read from saltstack/salt/states/pkgbuild.py
// (upstream ships integration-only tests).

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
	onRun   func(argv []string) process.CommandResult
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if f.onRun != nil {
		return f.onRun(argv)
	}
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func stateRT(t *testing.T, family string, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: family, Name: family, Family: family, Version: "9",
		}}),
		Runner: runner,
	}
	if err := execpkgbuild.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func TestBuiltRequiresResults(t *testing.T) {
	rt := stateRT(t, "redhat", &fakeRunner{}, nil)
	ret := builtFunc{}.Apply(context.Background(), rt, &builtArgs{
		Name: "hello-build", Runas: "root", DestDir: "/testbed/out",
		Spec: "/testbed/in/hello.spec", Tgt: "epel-9-x86_64",
	})
	if ret.Result == nil || *ret.Result != false ||
		ret.Comment != "'results' argument is required" {
		t.Fatalf("results-required = %#v %q", ret.Result, ret.Comment)
	}
}

func TestBuiltAlreadyExists(t *testing.T) {
	rt := stateRT(t, "redhat", &fakeRunner{}, map[string]string{
		"/testbed/out/hello-1.0.rpm": "rpm",
	})
	ret := builtFunc{}.Apply(context.Background(), rt, &builtArgs{
		Name: "hello-build", Runas: "root", DestDir: "/testbed/out",
		Spec: "/testbed/in/hello.spec", Tgt: "epel-9-x86_64",
		Results: []any{"hello-1.0.rpm"},
	})
	if ret.Result == nil || *ret.Result != true ||
		ret.Comment != "All needed packages exist" {
		t.Fatalf("already-exists = %#v %q", ret.Result, ret.Comment)
	}
}

func TestBuiltTestMode(t *testing.T) {
	rt := stateRT(t, "redhat", &fakeRunner{}, nil)
	ret := builtFunc{}.Apply(context.Background(), rt, &builtArgs{
		Name: "hello-build", Runas: "root", DestDir: "/testbed/out",
		Spec: "/testbed/in/hello.spec", Tgt: "epel-9-x86_64",
		Results: []any{"a.rpm", "b.rpm"}, Test: true,
	})
	if ret.Result != nil {
		t.Fatalf("test result = %#v; want nil (comment=%q)", ret.Result, ret.Comment)
	}
	if ret.Comment != "The following packages need to be built: a.rpm, b.rpm" {
		t.Fatalf("comment = %q", ret.Comment)
	}

	forceRet := builtFunc{}.Apply(context.Background(), rt, &builtArgs{
		Name: "hello-build", Runas: "root", DestDir: "/testbed/out",
		Spec: "/testbed/in/hello.spec", Tgt: "epel-9-x86_64",
		Results: []any{"a.rpm"}, Force: true, Test: true,
	})
	if forceRet.Comment != "Packages will be force-built" {
		t.Fatalf("force comment = %q", forceRet.Comment)
	}
}

// Full flow: build produces the artifact, verification passes.
func TestBuiltEndToEnd(t *testing.T) {
	var rt *runtime.Runtime
	runner := &fakeRunner{}
	rt = stateRT(t, "redhat", runner, map[string]string{
		"/testbed/in/hello.spec":       "Name: hello\n",
		"/testbed/in/hello-1.0.tar.gz": "src",
	})
	runner.onRun = func(argv []string) process.CommandResult {
		switch argv[0] {
		case "rpmbuild":
			for i, arg := range argv {
				if arg == "--define" && i+1 < len(argv) &&
					strings.HasPrefix(argv[i+1], "_topdir ") {
					topdir := strings.TrimPrefix(argv[i+1], "_topdir ")
					writeFileP(rt, topdir+"/SRPMS/hello.src.rpm", "srpm")
					writeFileP(rt, topdir+"/../results/hello-1.0.el9.rpm", "rpm")
					writeFileP(rt, topdir+"/../results/build.log", "log")
				}
			}
			return process.CommandResult{}
		case "mock":
			for _, arg := range argv {
				if strings.HasPrefix(arg, "--resultdir=") {
					resultsDir := strings.TrimPrefix(arg, "--resultdir=")
					writeFileP(rt, resultsDir+"/hello-1.0.el9.rpm", "rpm")
					writeFileP(rt, resultsDir+"/build.log", "log")
				}
			}
			return process.CommandResult{}
		case "rpm":
			return process.CommandResult{Stdout: []byte("/var/log/salt/pkgbuild/hello/1.0-el9")}
		}
		return process.CommandResult{}
	}

	ret := builtFunc{}.Apply(context.Background(), rt, &builtArgs{
		Name: "hello-build", Runas: "root", DestDir: "/testbed/out",
		Spec: "/testbed/in/hello.spec", Tgt: "epel-8-x86_64",
		Sources: []any{"/testbed/in/hello-1.0.tar.gz"},
		Results: []any{"hello-1.0.el9.rpm"},
	})
	if ret.Result == nil || *ret.Result != true ||
		ret.Comment != "All needed packages were built" {
		t.Fatalf("end-to-end = %#v %q", ret.Result, ret.Comment)
	}
	pkgs, _ := ret.Changes["Packages"].([]string)
	if len(pkgs) != 1 || !strings.HasSuffix(pkgs[0], "hello-1.0.el9.rpm") {
		t.Fatalf("changes Packages = %#v", ret.Changes["Packages"])
	}
}

func TestRepoStateFlows(t *testing.T) {
	stubHome(t, "/testbed/home/root")

	// test mode.
	rt := stateRT(t, "redhat", &fakeRunner{}, map[string]string{
		"/testbed/repo/hello.rpm": "rpm",
	})
	ret := repoFunc{}.Apply(context.Background(), rt, &repoArgs{
		Name: "/testbed/repo", Test: true,
	})
	if ret.Result != nil ||
		ret.Comment != "Package repo metadata at /testbed/repo will be refreshed" {
		t.Fatalf("test mode = %#v %q", ret.Result, ret.Comment)
	}

	// Success refresh records the change and concatenates output comments.
	repoRT := stateRT(t, "redhat", &fakeRunner{}, map[string]string{
		"/testbed/repo/hello.rpm": "rpm",
	})
	repoRT.Runner.(*fakeRunner).onRun = func(argv []string) process.CommandResult {
		if argv[0] == "createrepo" {
			return process.CommandResult{Stdout: []byte("repo done")}
		}
		return process.CommandResult{}
	}
	ret = repoFunc{}.Apply(context.Background(), repoRT, &repoArgs{Name: "/testbed/repo"})
	if ret.Result == nil || *ret.Result != true {
		t.Fatalf("repo success = %#v %q", ret.Result, ret.Comment)
	}
	if _, ok := ret.Changes["refresh"]; !ok {
		t.Fatalf("changes = %#v", ret.Changes)
	}
	if ret.Comment != "repo done" {
		t.Fatalf("comment = %q", ret.Comment)
	}
}

func writeFileP(rt *runtime.Runtime, path, content string) error {
	if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
		return err
	}
	return rt.FS.WriteFile(path, []byte(content), 0o644)
}

func stubHome(t *testing.T, home string) {}
