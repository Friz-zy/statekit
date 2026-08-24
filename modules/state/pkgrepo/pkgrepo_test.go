package pkgrepo

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkgrepo "github.com/friz-zy/statekit/modules/exec/pkgrepo"
)

// State tests mapped onto the pkgrepo managed/absent flows of
// saltstack/tests/unit/states/test_pkgrepo.py, run hermetically through a
// fully registered exec surface over MemoryFS.

const debianSourceLine = "deb http://us.archive.ubuntu.com/ubuntu noble main"

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func readAll(t *testing.T, rt *runtime.Runtime, path string) string {
	t.Helper()
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// redirectPaths points the apt engine at the /etc layout used by the yum
// state test.
func redirectPaths(t *testing.T) {
	t.Helper()
	savedList, savedParts := execpkgrepo.SourcesPaths()
	execpkgrepo.SetSourcesPaths("/etc/apt/sources.list", "/etc/apt/sources.list.d/")
	t.Cleanup(func() { execpkgrepo.SetSourcesPaths(savedList[0], savedParts[0]) })
}

func mustWrite(rt *runtime.Runtime, path, content string) {
	if err := rt.FS.MkdirAll(dirOf(path), 0o755); err != nil {
		panic(err)
	}
	if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
		panic(err)
	}
}

func stateRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	savedList, savedParts := execpkgrepo.SourcesPaths()
	execpkgrepo.SetSourcesPaths("/testbed/sources.list", "/testbed/sources.list.d/")
	t.Cleanup(func() { execpkgrepo.SetSourcesPaths(savedList[0], savedParts[0]) })
	stubWhichBinState(t)
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "ubuntu", Name: "Ubuntu", Family: facts.FamilyDebian,
			Codename: "noble",
		}}),
	}
	if err := execpkgrepo.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(dirOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func stubWhichBinState(t *testing.T) {
	t.Helper()
	saved := execpkgrepo.ExportWhichBin()
	// A real Ubuntu minion resolves apt-key; the create gate in mod_repo
	// depends on it, so the state suites pin the present-binary branch.
	execpkgrepo.SetWhichBin(func(name string) string {
		if name == "apt-key" {
			return "/usr/bin/apt-key"
		}
		return ""
	})
	t.Cleanup(func() { execpkgrepo.SetWhichBin(saved) })
}

func TestManagedCreatesDebianRepo(t *testing.T) {
	rt := stateRT(t, map[string]string{"/testbed/sources.list": ""})
	fn := managedFunc{}
	ret := fn.Apply(context.Background(), rt, &managedArgs{
		Name: debianSourceLine,
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("managed failed: %#v %s", ret.Result, ret.Comment)
	}
	if ret.Comment != "Configured package repo 'deb http://us.archive.ubuntu.com/ubuntu noble main'" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if _, ok := ret.Changes["repo"]; !ok {
		t.Fatalf("changes = %#v", ret.Changes)
	}
	content := readAll(t, rt, "/testbed/sources.list")
	if content != "deb http://us.archive.ubuntu.com/ubuntu noble main\n" {
		t.Fatalf("sources.list = %q", content)
	}
}

func TestManagedIdempotent(t *testing.T) {
	rt := stateRT(t, map[string]string{
		"/testbed/sources.list": debianSourceLine + "\n",
	})
	fn := managedFunc{}
	ret := fn.Apply(context.Background(), rt, &managedArgs{Name: debianSourceLine})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("managed not idempotent: %s", ret.Comment)
	}
	if ret.Comment != "Package repo 'deb http://us.archive.ubuntu.com/ubuntu noble main' already configured" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if len(ret.Changes) != 0 {
		t.Fatalf("changes = %#v", ret.Changes)
	}
}

func TestManagedDisableFlip(t *testing.T) {
	rt := stateRT(t, map[string]string{
		"/testbed/sources.list": debianSourceLine + "\n",
	})
	fn := managedFunc{}
	disabled := true
	ret := fn.Apply(context.Background(), rt, &managedArgs{
		Name:     debianSourceLine,
		Disabled: &disabled,
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("managed disable failed: %s", ret.Comment)
	}
	content := readAll(t, rt, "/testbed/sources.list")
	if !strings.Contains(content, "# deb http://us.archive.ubuntu.com/ubuntu noble main") {
		t.Fatalf("disable not rendered:\n%s", content)
	}
}

func TestManagedTestMode(t *testing.T) {
	rt := stateRT(t, map[string]string{"/testbed/sources.list": ""})
	fn := managedFunc{}
	ret := fn.Apply(context.Background(), rt, &managedArgs{
		Name: debianSourceLine,
		Test: true,
	})
	if ret.Result != nil {
		t.Fatalf("test-mode result = %#v; want nil", ret.Result)
	}
	if !strings.HasPrefix(ret.Comment, "Package repo '") ||
		!strings.Contains(ret.Comment, "would be configured") {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if _, ok := ret.Changes["repo"]; !ok {
		t.Fatalf("changes = %#v", ret.Changes)
	}
	if _, serr := rt.FS.Stat("/testbed/sources.list"); serr == nil {
		if readAll(t, rt, "/testbed/sources.list") != "" {
			t.Fatalf("test mode wrote to disk")
		}
	}
}

func TestManagedValidationBattery(t *testing.T) {
	rt := stateRT(t, map[string]string{"/testbed/sources.list": ""})
	fn := managedFunc{}

	keyURL := "https://example.com/key.gpg"
	ret := fn.Apply(context.Background(), rt, &managedArgs{
		Name:   debianSourceLine,
		KeyURL: &keyURL,
		Keyid:  "FBB75451",
	})
	if ret.Result == nil || *ret.Result {
		t.Fatalf("key_url+keyid accepted")
	}
	want := `You may not use both "keyid"/"keyserver" and "key_url" argument.`
	if ret.Comment != want {
		t.Fatalf("comment = %q", ret.Comment)
	}

	ret = fn.Apply(context.Background(), rt, &managedArgs{
		Name:      debianSourceLine,
		KeyText:   strPtrState("KEY"),
		Keyserver: strPtrState("keys.example"),
	})
	want = `You may not use both "keyid"/"keyserver" and "key_text" argument.`
	if ret.Comment != want {
		t.Fatalf("comment = %q", ret.Comment)
	}

	en := true
	dis := false
	ret = fn.Apply(context.Background(), rt, &managedArgs{
		Name: debianSourceLine, Enabled: &en, Disabled: &dis,
	})
	if ret.Comment != "Only one of enabled/disabled is allowed" {
		t.Fatalf("comment = %q", ret.Comment)
	}

	insecure := "http://example.com/key.gpg"
	noInsecure := false
	ret = fn.Apply(context.Background(), rt, &managedArgs{
		Name:             debianSourceLine,
		KeyURL:           &insecure,
		AllowInsecureKey: &noInsecure,
	})
	if ret.Comment != "Cannot have 'key_url' using http with 'allow_insecure_key' set to True" {
		t.Fatalf("insecure-key comment = %q", ret.Comment)
	}
}

func TestAbsentRemovesDebianRepo(t *testing.T) {
	rt := stateRT(t, map[string]string{
		"/testbed/sources.list": debianSourceLine + "\n",
	})
	fn := absentFunc{}
	ret := fn.Apply(context.Background(), rt, &absentArgs{Name: debianSourceLine})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("absent failed: %s", ret.Comment)
	}
	if ret.Comment != "Removed repo deb http://us.archive.ubuntu.com/ubuntu noble main" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if _, ok := ret.Changes["repo"]; !ok {
		t.Fatalf("changes = %#v", ret.Changes)
	}

	// Second run reports absence without changes.
	ret = fn.Apply(context.Background(), rt, &absentArgs{Name: debianSourceLine})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("second absent failed: %s", ret.Comment)
	}
	if ret.Comment != "Package repo deb http://us.archive.ubuntu.com/ubuntu noble main is absent" {
		t.Fatalf("absent comment = %q", ret.Comment)
	}
}

func TestAbsentArchitectureMismatchIsAbsent(t *testing.T) {
	rt := stateRT(t, map[string]string{
		"/testbed/sources.list": debianSourceLine + "\n",
	})
	fn := absentFunc{}
	// The requested entry carries arch=i386 which the existing line lacks;
	// upstream invalidates the match and reports absence.
	ret := fn.Apply(context.Background(), rt, &absentArgs{
		Name:   "deb [arch=i386] http://us.archive.ubuntu.com/ubuntu noble main",
		Kwargs: map[string]any{},
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("arch-mismatch absent failed: %s", ret.Comment)
	}
	if !strings.Contains(ret.Comment, "is absent") {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if len(ret.Changes) != 0 {
		t.Fatalf("unexpected changes: %#v", ret.Changes)
	}
}

func TestRedHatManagedCreate(t *testing.T) {
	redirectPaths(t)
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "fedora", Name: "Fedora Linux", Family: facts.FamilyRedHat,
		}}),
	}
	if err := execpkgrepo.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/etc/yum.repos.d", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(rt, "/etc/yum/yum.conf", "[main]\nreposdir=/etc/yum.repos.d\n")

	humanname := "Example Repo"
	ret := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name:      "example",
		Humanname: &humanname,
		Baseurl:   strPtrState("http://rpm.example/repo"),
	})
	if ret.Result == nil || !*ret.Result {
		t.Fatalf("redhat managed failed: %s", ret.Comment)
	}
	data, rerr := rt.FS.ReadFile("/etc/yum.repos.d/example.repo")
	if rerr != nil {
		t.Fatal(rerr)
	}
	content := string(data)
	for _, piece := range []string{"[example]", "name=Example Repo", "baseurl=http://rpm.example/repo"} {
		if !strings.Contains(content, piece) {
			t.Fatalf("missing %q in:\n%s", piece, content)
		}
	}
	// enabled=True renders as enabled=1 through the yum writer.
	if !strings.Contains(content, "enabled=1") {
		t.Fatalf("enabled missing:\n%s", content)
	}
}
