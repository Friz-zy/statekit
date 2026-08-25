package pkgbuild

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// RPM-backend tests pinning the argv sequences, classification, and error
// surfaces read from rpmbuild_pkgbuild.py @ pinned revision (upstream ships
// integration-only tests requiring real toolchains).

type seqRunner struct {
	calls [][]string
	onRun func(argv []string) process.CommandResult // optional side effects
}

func (s *seqRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	s.calls = append(s.calls, argv)
	if s.onRun != nil {
		return s.onRun(argv)
	}
	return process.CommandResult{}
}

func (s *seqRunner) joined() []string {
	out := make([]string, 0, len(s.calls))
	for _, call := range s.calls {
		out = append(out, strings.Join(call, " "))
	}
	return out
}

func pkgRT(t *testing.T, family string, runner *seqRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: family, Name: strings.Title(family), Family: family,
			Version: "9",
		}}),
		Runner: runner,
	}
	if family == "redhat" || family == "suse" {
		rt.Facts = facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: family, Name: family, Family: family, Version: "9.4",
		}})
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(dirName(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func dirName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func stubHome(t *testing.T, home string) {
	t.Helper()
	saved := homeOf
	homeOf = func(string) string { return home }
	t.Cleanup(func() { homeOf = saved })
}

func TestGetDistset(t *testing.T) {
	cases := map[string]string{
		"epel-7-x86_64":    "--define \"dist .el7\"",
		"epel-6-x86_64":    "--define \"dist .el6\"",
		"epel-8-x86_64":    "--define \"dist .el8\"",
		"amzn2-candidate":  "--define \"dist .amzn2\"",
		"fedora-38-x86_64": "",
	}
	for tgt, want := range cases {
		if got := getDistset(tgt); got != want {
			t.Fatalf("getDistset(%q) = %q; want %q", tgt, got, want)
		}
	}
}

func TestRpmmacrosAndTree(t *testing.T) {
	stubHome(t, "/testbed/home/builder")
	rt := pkgRT(t, "redhat", &seqRunner{}, nil)
	createRpmmacros(rt, "builder")
	macros, err := rt.FS.ReadFile("/testbed/home/builder/.rpmmacros")
	if err != nil {
		t.Fatal(err)
	}
	want := "%_topdir /testbed/home/builder/rpmbuild\n" +
		"%signature gpg\n" +
		"%_source_filedigest_algorithm 8\n" +
		"%_binary_filedigest_algorithm 8\n" +
		"%_gpg_name packaging@saltstack.com\n"
	if string(macros) != want {
		t.Fatalf("macros = %q", string(macros))
	}
	tree, err := mkTree(rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"} {
		if _, serr := rt.FS.Stat(tree + "/" + sub); serr != nil {
			t.Fatalf("tree missing %s", sub)
		}
	}
}

// Mirrors make_src_pkg: staging argv plus the pinned dist .el6 define.
func TestRPMMakeSrcPkg(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	specContent := "Name: hello\nVersion: 1.0\n"
	var rt *runtime.Runtime
	runner := &seqRunner{onRun: func(argv []string) process.CommandResult {
		// Simulate rpmbuild producing an SRPM inside the requested topdir.
		if len(argv) > 0 && argv[0] == "rpmbuild" {
			topdir := ""
			for i, arg := range argv {
				if arg == "--define" && i+1 < len(argv) &&
					strings.HasPrefix(argv[i+1], "_topdir ") {
					topdir = strings.TrimPrefix(argv[i+1], "_topdir ")
				}
			}
			if topdir != "" {
				_ = writeFileP(rt, topdir+"/SRPMS/hello-1.0.el6.src.rpm", "srpm")
			}
			return process.CommandResult{}
		}
		return process.CommandResult{}
	}}
	rt = pkgRT(t, "redhat", runner, map[string]string{
		"/testbed/in/hello.spec":       specContent,
		"/testbed/in/hello-1.0.tar.gz": "tarball bytes",
	})

	ret, err := (makeSrcPkgFunc{}).Execute(context.Background(), rt, &MakeSrcPkgArgs{
		DestDir: "/testbed/out/SRPMS",
		Spec:    "/testbed/in/hello.spec",
		Sources: []any{"/testbed/in/hello-1.0.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, ok := ret.([]string)
	if !ok || len(list) != 1 || !strings.HasSuffix(list[0], "hello-1.0.el6.src.rpm") {
		t.Fatalf("ret = %#v", ret)
	}
	found := false
	for _, call := range runner.calls {
		if call[0] != "rpmbuild" {
			continue
		}
		for i, arg := range call {
			if arg == "--define" && i+1 < len(call) && call[i+1] == "dist .el6" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("rpmbuild argv missing dist .el6 define: %#v", runner.joined())
	}
}

// Failure propagates the verbatim invocation error with the accumulated
// retcode.
func TestRPMMakeSrcPkgFailure(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	runner := &seqRunner{onRun: func(argv []string) process.CommandResult {
		if argv[0] == "rpmbuild" {
			return process.CommandResult{ExitCode: 2}
		}
		return process.CommandResult{}
	}}
	rt := pkgRT(t, "redhat", runner, map[string]string{
		"/testbed/in/hello.spec": "Name: hello\n",
	})
	_, err := (makeSrcPkgFunc{}).Execute(context.Background(), rt, &MakeSrcPkgArgs{
		DestDir: "/testbed/out",
		Spec:    "/testbed/in/hello.spec",
		Sources: []any{},
	})
	if err == nil || !strings.HasPrefix(err.Error(),
		"Make source package for destination directory /testbed/out, spec /testbed/in/hello.spec") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "failed with return error 2") {
		t.Fatalf("retcode missing from: %v", err)
	}
}

func TestRPMMakeSrcPkgRemoteSchemeRejected(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	rt := pkgRT(t, "redhat", &seqRunner{}, map[string]string{
		"/testbed/in/hello.spec": "Name: hello\n",
	})
	_, err := (makeSrcPkgFunc{}).Execute(context.Background(), rt, &MakeSrcPkgArgs{
		DestDir: "/testbed/out",
		Spec:    "https://example.com/hello.spec",
	})
	if err == nil {
		t.Fatalf("remote scheme accepted")
	}
	var unsupported *runtime.UnsupportedError
	if !errorsAs(err, &unsupported) || unsupported.Name != "cp.get_url" {
		t.Fatalf("error = %v", err)
	}
}

func writeFileP(rt *runtime.Runtime, path, content string) error {
	if err := rt.FS.MkdirAll(dirName(path), 0o755); err != nil {
		return err
	}
	return rt.FS.WriteFile(path, []byte(content), 0o644)
}

// Mirrors build: mock init, deps install with --no-clean accumulation, and
// result classification into Packages/Log Files buckets.
func TestRPMBuildOrchestration(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	specContent := "Name: hello\n"
	var rt *runtime.Runtime
	var resultsDir string
	runner := &seqRunner{onRun: func(argv []string) process.CommandResult {
		switch argv[0] {
		case "rpmbuild":
			for i, arg := range argv {
				if arg == "--define" && i+1 < len(argv) &&
					strings.HasPrefix(argv[i+1], "_topdir ") {
					topdir := strings.TrimPrefix(argv[i+1], "_topdir ")
					writeFileP(rt, topdir+"/SRPMS/hello-1.0.el6.src.rpm", "srpm")
				}
			}
			return process.CommandResult{}
		case "mock":
			for _, arg := range argv {
				if strings.HasPrefix(arg, "--resultdir=") {
					resultsDir = strings.TrimPrefix(arg, "--resultdir=")
					writeFileP(rt, resultsDir+"/hello-1.0.el9.rpm", "rpm")
					writeFileP(rt, resultsDir+"/build.log", "log")
				}
			}
			return process.CommandResult{}
		case "rpm":
			return process.CommandResult{Stdout: []byte("/var/log/salt/pkgbuild/hello/1.0-el9")}
		}
		return process.CommandResult{}
	}}
	rt = pkgRT(t, "redhat", runner, map[string]string{
		"/testbed/in/hello.spec":       specContent,
		"/testbed/in/hello-1.0.tar.gz": "src",
		"/testbed/dep/dep.rpm":         "dep",
	})

	retAny, err := (buildFunc{}).Execute(context.Background(), rt, &BuildArgs{
		Runas:   "root",
		Tgt:     "epel-8-x86_64",
		DestDir: "/testbed/out",
		Spec:    "/testbed/in/hello.spec",
		Sources: []any{"/testbed/in/hello-1.0.tar.gz"},
		Deps:    []any{"/testbed/dep/dep.rpm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ret := retAny.(map[string]any)
	pkgs, _ := ret["Packages"].([]string)
	logs, _ := ret["Log Files"].([]string)
	if len(pkgs) != 1 || !strings.HasSuffix(pkgs[0], "hello-1.0.el9.rpm") {
		t.Fatalf("Packages = %#v", ret["Packages"])
	}
	if len(logs) != 1 || strings.Contains(logs[0], resultsDir) {
		t.Fatalf("Log Files = %#v", ret["Log Files"])
	}

	joinedCalls := runner.joined()
	initIdx, installIdx, buildIdx, distIdx := -1, -1, -1, false
	for i, call := range runner.calls {
		if call[0] != "mock" {
			continue
		}
		if strings.HasSuffix(joinedCalls[i], "--init") && initIdx < 0 {
			initIdx = i
		}
		if containsStr(call, "--install") && installIdx < 0 {
			installIdx = i
		}
		for j, arg := range call {
			if arg == "--define" && j+1 < len(call) && call[j+1] == "dist .el8" &&
				strings.Contains(joinedCalls[i], ".src.rpm") {
				distIdx = true
			}
		}
		if strings.Contains(joinedCalls[i], ".src.rpm") && !strings.HasSuffix(joinedCalls[i], "--init") {
			buildIdx = i
		}
	}
	if initIdx < 0 || installIdx < 0 || buildIdx < 0 || !(initIdx < installIdx && installIdx < buildIdx) {
		t.Fatalf("mock cycle order wrong: %#v", joinedCalls)
	}
	if !strings.Contains(joinedCalls[installIdx], "dep.rpm") {
		t.Fatalf("deps install argv malformed: %s", joinedCalls[installIdx])
	}
	if !distIdx {
		t.Fatalf("distset missing from build call: %#v", joinedCalls)
	}
}

// Mirrors make_repo without signing: createrepo over the repodir.
func TestRPMMakeRepoUnsigned(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	runner := &seqRunner{}
	rt := pkgRT(t, "redhat", runner, map[string]string{
		"/testbed/repo/hello.rpm": "rpm",
	})
	ret, err := (makeRepoFunc{}).Execute(context.Background(), rt, &MakeRepoArgs{
		RepoDir: "/testbed/repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	dict, _ := ret.(map[string]any)
	if dict["retcode"] != 0 {
		t.Fatalf("result = %#v", dict)
	}
	found := false
	for _, call := range runner.joined() {
		if call == "createrepo --update /testbed/repo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("createrepo argv missing: %#v", runner.joined())
	}
}

// Pins the pillar-gated keyid path: without pillar data the verbatim
// re-raised import error fires before any signing.
func TestRPMMakeRepoKeyidWithoutPillar(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	rt := pkgRT(t, "redhat", &seqRunner{}, map[string]string{
		"/testbed/repo/hello.rpm": "rpm",
	})
	_, err := (makeRepoFunc{}).Execute(context.Background(), rt, &MakeRepoArgs{
		RepoDir: "/testbed/repo",
		Keyid:   strPtrPkg("FBB75451"),
	})
	if err == nil || !strings.HasPrefix(err.Error(),
		"Public and Private key files associated with Pillar data and 'keyid' FBB75451 could not be found") {
		t.Fatalf("error = %v", err)
	}
}

func strPtrPkg(s string) *string { return &s }

func errorsAs(err error, target any) bool {
	type iface interface{ As(any) bool }
	_ = iface(nil)
	u, ok := target.(**runtime.UnsupportedError)
	if !ok {
		return false
	}
	for e := err; e != nil; {
		if ue, is := e.(*runtime.UnsupportedError); is {
			*u = ue
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if w, is := e.(unwrapper); is {
			e = w.Unwrap()
			continue
		}
		return false
	}
	return false
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
