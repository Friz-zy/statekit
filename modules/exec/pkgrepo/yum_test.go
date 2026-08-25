package pkgrepo

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// yum/dnf repository tests mapped onto
// saltstack/tests/pytests/unit/modules/test_yumpkg.py
// (test_del_repo_error, test_del_repo_single_file, test_get_copr_repo,
// test_parse_repo_file_error, test_get_repo_with_{existent,non_existent}_repo)
// plus the configparser behaviors those tests exercise indirectly.

const yumMultiRepo = `# Header comment for repos

[r1]
name=Repo One
baseurl=http://example.com/r1
   extra/path
enabled=1
# keep this note
gpgcheck=1

[r2]
name=Repo Two
baseurl=http://example.com/r2
`

func yumRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	redirectPaths(t)
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  factsForTesting(),
	}
	for path, content := range files {
		mustWrite(rt, path, content)
	}
	return rt
}

func stubYumConfPaths(t *testing.T, paths []string) {
	t.Helper()
	saved := yumConfSearchPaths
	yumConfSearchPaths = paths
	t.Cleanup(func() { yumConfSearchPaths = saved })
}

func stubYumDefaultDirs(t *testing.T, dirs []string) {
	t.Helper()
	saved := yumDefaultReposDirs
	yumDefaultReposDirs = dirs
	t.Cleanup(func() { yumDefaultReposDirs = saved })
}

func TestParseYumRepoFile(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/multi.repo": yumMultiRepo,
	})
	file, err := parseYumRepoFile(rt, "/testbed/repos/multi.repo", true)
	if err != nil {
		t.Fatal(err)
	}
	if file.header != "# Header comment for repos" {
		t.Fatalf("header = %q", file.header)
	}
	if len(file.sections) != 2 || file.sections[0].name != "r1" || file.sections[1].name != "r2" {
		t.Fatalf("sections = %#v", file.sections)
	}
	r1 := file.sections[0]
	if got, _ := r1.get("baseurl"); got != "http://example.com/r1\nextra/path" {
		t.Fatalf("multiline baseurl = %q", got)
	}
	if got, _ := r1.get("enabled"); got != "1" {
		t.Fatalf("enabled = %q", got)
	}
	if len(r1.comments) != 1 || r1.comments[0] != "keep this note" {
		t.Fatalf("comments = %#v", r1.comments)
	}

	// ":" delimiter and lowercase key normalization.
	rt = yumRT(t, map[string]string{
		"/testbed/other.repo": "[other]\nName: Other Repo\nFoo=bar\n",
	})
	file, err = parseYumRepoFile(rt, "/testbed/other.repo", true)
	if err != nil {
		t.Fatal(err)
	}
	other := file.sections[0]
	if got, _ := other.get("name"); got != "Other Repo" {
		t.Fatalf("colon delim name = %q", got)
	}
	if got, _ := other.get("foo"); got != "bar" {
		t.Fatalf("lowercased foo = %q", got)
	}

	// Mirrors test_parse_repo_file_error: missing section header degrades
	// to the ("", {}) pair.
	file, err = parseYumRepoFile(rt, "/testbed/absent.repo", true)
	if err != nil || file.header != "" || len(file.sections) != 0 {
		t.Fatalf("missing-file parse = %#v, %v", file, err)
	}
	rt = yumRT(t, map[string]string{
		"/testbed/bad.repo": "key=value\n",
	})
	file, err = parseYumRepoFile(rt, "/testbed/bad.repo", true)
	if err != nil || file.header != "" || len(file.sections) != 0 {
		t.Fatalf("missing-header parse = %#v, %v", file, err)
	}

	// Strict mode rejects duplicate options; relaxed mode keeps the last.
	rt = yumRT(t, map[string]string{
		"/testbed/dup.repo": "[d]\na=1\na=2\n",
	})
	if _, err := parseYumRepoFile(rt, "/testbed/dup.repo", true); err == nil {
		t.Fatalf("strict duplicate accepted")
	}
	file, err = parseYumRepoFile(rt, "/testbed/dup.repo", false)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := file.sections[0].get("a"); got != "2" {
		t.Fatalf("relaxed duplicate = %q", got)
	}
}

func TestGetYumConfigReposdir(t *testing.T) {
	originalPaths := append([]string{}, yumConfSearchPaths...)

	// Explicit [main] reposdir wins.
	rt := yumRT(t, map[string]string{
		"/testbed/yum.conf": "[main]\nreposdir=/a,/b\n",
	})
	stubYumConfPaths(t, []string{"/testbed/yum.conf"})
	dirs, err := normalizeYumBasedir(rt, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSlices(dirs, []string{"/a", "/b"}) {
		t.Fatalf("reposdir = %v", dirs)
	}

	// Comma-string form splits like the upstream str handling.
	dirs, err = normalizeYumBasedir(rt, " x , y ", true)
	if err != nil || !equalSlices(dirs, []string{"x", "y"}) {
		t.Fatalf("string basedir = %v, %v", dirs, err)
	}

	// Without any config file the lookup fails with the verbatim message.
	stubYumConfPaths(t, originalPaths)
	rt = yumRT(t, nil)
	_, err = normalizeYumBasedir(rt, nil, true)
	want := "No suitable yum config file found in: ['/etc/yum/yum.conf', '/etc/yum.conf', '/etc/dnf/dnf.conf', '/etc/tdnf/tdnf.conf']"
	if err == nil || err.Error() != want {
		t.Fatalf("no-config error = %v", err)
	}

	// Config without [main] falls back to internal defaults.
	rt = yumRT(t, map[string]string{
		"/testbed/yum.conf": "[other]\nfoo=bar\n",
	})
	stubYumConfPaths(t, []string{"/testbed/yum.conf"})
	dirs, err = normalizeYumBasedir(rt, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSlices(dirs, []string{"/etc/yum/repos.d", "/etc/yum.repos.d"}) {
		t.Fatalf("defaults = %v", dirs)
	}
}

// Mirrors test_get_copr_repo.
func TestCoprNameMapping(t *testing.T) {
	if got := getCoprRepo("copr:spongebob/squarepants"); got != "copr:copr.fedorainfracloud.org:spongebob:squarepants" {
		t.Fatalf("copr mapping = %q", got)
	}
}

func TestYumListReposOverrides(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/a.repo":     "[r1]\nname=First\n",
		"/testbed/repos/b.repo":     "[r1]\nname=Second\n",
		"/testbed/repos/readme.txt": "ignored\n",
	})
	repos, err := yumListRepos(rt, "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	r1, ok := repos["r1"].(map[string]any)
	if !ok {
		t.Fatalf("repos = %#v", repos)
	}
	if r1["name"] != "Second" {
		t.Fatalf("override did not apply: %#v", r1)
	}
	if f, _ := r1["file"].(string); f != "/testbed/repos/b.repo" {
		t.Fatalf("file = %q", f)
	}
}

// Mirrors test_get_repo_with_existent_repo / non_existent.
func TestYumGetRepo(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/multi.repo": yumMultiRepo,
	})
	repo, err := yumGetRepo(rt, "r1", "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	if repo["name"] != "Repo One" {
		t.Fatalf("get_repo = %#v", repo)
	}
	comments, ok := repo["comments"].([]string)
	if !ok || len(comments) != 1 || comments[0] != "keep this note" {
		t.Fatalf("comments = %#v", repo["comments"])
	}

	missing, err := yumGetRepo(rt, "ghost", "/testbed/repos", true)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing get_repo = %#v, %v", missing, err)
	}

	copr, err := yumGetRepo(rt, "copr:plankton/karen", "/testbed/repos", true)
	if err != nil || len(copr) != 0 {
		t.Fatalf("copr get_repo = %#v, %v", copr, err)
	}
}

// Mirrors test_del_repo_single_file plus the multi-stanza rewrite shape.
// The comment attached to the deleted stanza dies with it; the surviving
// stanza's comment re-renders normalized as "# text".
func TestYumDelRepoMessages(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/single.repo": "[only]\nname=Only\nbaseurl=http://x/\n",
	})
	ret, err := yumDelRepo(context.Background(), rt, "only", "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "File /testbed/repos/single.repo containing repo only has been removed"
	if ret != want {
		t.Fatalf("single-file reply = %q", ret)
	}
	if _, serr := rt.FS.Stat("/testbed/repos/single.repo"); serr == nil {
		t.Fatalf("file survived")
	}

	rt = yumRT(t, map[string]string{
		"/testbed/repos/multi.repo": "# Header comment for repos\n" +
			"\n[r1]\nname=Repo One\nbaseurl=http://example.com/r1\nenabled=1\n\n" +
			"[r2]\nname=Repo Two\n# survivor note\nbaseurl=http://example.com/r2\n",
	})
	ret, err = yumDelRepo(context.Background(), rt, "r1", "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	want = "Repo r1 has been removed from /testbed/repos/multi.repo"
	if ret != want {
		t.Fatalf("multi reply = %q", ret)
	}
	content := readAll(t, rt, "/testbed/repos/multi.repo")
	for _, piece := range []string{
		"# Header comment for repos",
		"[r2]",
		"name=Repo Two",
		"# survivor note",
	} {
		if !strings.Contains(content, piece) {
			t.Fatalf("rewrite lost %q:\n%s", piece, content)
		}
	}
	if strings.Contains(content, "r1") {
		t.Fatalf("deleted stanza survived:\n%s", content)
	}
}

// Mirrors test_del_repo_error including the copr alias expansion inside the
// not-found message.
func TestYumDelRepoNotFound(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/one.repo": "[spongebob]\nname=Spongebob\n",
	})
	ret, err := yumDelRepo(context.Background(), rt, "plankton", "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "Error: the plankton repo does not exist in ['/testbed/repos']"
	if ret != want {
		t.Fatalf("not-found reply = %q", ret)
	}
	ret, err = yumDelRepo(context.Background(), rt, "copr:plankton/karen", "/testbed/repos", true)
	if err != nil {
		t.Fatal(err)
	}
	want = "Error: the copr:copr.fedorainfracloud.org:plankton:karen repo does not exist in ['/testbed/repos']"
	if ret != want {
		t.Fatalf("copr not-found reply = %q", ret)
	}
}

func TestYumModRepoCreateAndModify(t *testing.T) {
	rt := yumRT(t, map[string]string{
		"/testbed/repos/one.repo": "[r1]\nname=Repo One\nbaseurl=http://example.com/r1\ngpgcheck=1\n",
	})

	// Creation into the first existing basedir.
	reply, err := yumModRepo(context.Background(), rt, "newrepo", "/testbed/repos", true, map[string]any{
		"name":    "New Repo",
		"baseurl": "http://new.example.com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/testbed/repos/newrepo.repo"
	if _, ok := reply[path]; !ok {
		t.Fatalf("reply keys = %#v", reply)
	}
	content := readAll(t, rt, path)
	// The render loop always appends comments + "\n", so a comment-less
	// stanza ends with the same blank line upstream produces.
	want := "[newrepo]\nbaseurl=http://new.example.com/\nname=New Repo\n\n"
	if content != want {
		t.Fatalf("created file = %q; want %q", content, want)
	}

	// Modify: boolean true renders as 1.
	reply, err = yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"enabled": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	content = readAll(t, rt, "/testbed/repos/one.repo")
	if !strings.Contains(content, "enabled=1") {
		t.Fatalf("enabled=1 missing:\n%s", content)
	}
	dict := reply["/testbed/repos/one.repo"].(map[string]any)
	if dict["enabled"] != "1" {
		t.Fatalf("reply enabled = %#v", dict["enabled"])
	}

	// False survives the blank-value deletion and writes as 0.
	_, err = yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"enabled": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readAll(t, rt, "/testbed/repos/one.repo"), "enabled=0") {
		t.Fatalf("False was deleted instead of written")
	}

	// Blank values delete their option.
	_, err = yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"gpgcheck": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readAll(t, rt, "/testbed/repos/one.repo"), "gpgcheck") {
		t.Fatalf("blank gpgcheck not deleted")
	}
}

func TestYumModRepoValidationBattery(t *testing.T) {
	base := func() *runtime.Runtime {
		return yumRT(t, map[string]string{
			"/testbed/repos/one.repo": "[r1]\nname=Repo One\nbaseurl=http://x/\n",
		})
	}

	rt := base()
	if _, err := yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"baseurl":    "http://a/",
		"mirrorlist": "http://b/",
	}); err == nil || !strings.HasPrefix(err.Error(), "One and only one of baseurl, mirrorlist, metalink can be used") {
		t.Fatalf("two-link error = %v", err)
	}

	rt = base()
	if _, err := yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"name": "",
	}); err == nil || err.Error() != "The repo name cannot be deleted" {
		t.Fatalf("name-delete error = %v", err)
	}

	rt = base()
	if _, err := yumModRepo(context.Background(), rt, "brand-new", "/testbed/repos", true, map[string]any{
		"baseurl": "http://new/",
	}); err == nil || !strings.Contains(err.Error(), "but a name was not given") {
		t.Fatalf("create-without-name error = %v", err)
	}

	rt = base()
	if _, err := yumModRepo(context.Background(), rt, "brand-new", "/testbed/repos", true, map[string]any{
		"name": "No Link",
	}); err == nil || !strings.Contains(err.Error(), "but none of baseurl, mirrorlist, metalink was given") {
		t.Fatalf("create-without-link error = %v", err)
	}

	rt = base()
	if _, err := yumModRepo(context.Background(), rt, "brand-new", []string{"/nope"}, true, map[string]any{
		"name":    "X",
		"baseurl": "http://x/",
	}); err == nil || !strings.Contains(err.Error(), "basedir directories exist: ['/nope']") {
		t.Fatalf("no-basedir error = %v", err)
	}

	rt = base()
	if _, err := yumModRepo(context.Background(), rt, "r1", "/testbed/repos", true, map[string]any{
		"baseurl": "",
	}); err == nil || err.Error() != "Cannot delete baseurl without specifying mirrorlist or metalink" {
		t.Fatalf("link-deletion error = %v", err)
	}
}

// Pins the OS-family routing across the shared pkg.* registrations.
func TestBackendDispatch(t *testing.T) {
	redirectPaths(t)

	aptFacts := facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
		ID: "debian", Name: "Debian GNU/Linux", Family: facts.FamilyDebian,
	}})
	yumFacts := facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
		ID: "fedora", Name: "Fedora Linux", Family: facts.FamilyRedHat,
	}})
	unknownFacts := facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
		ID: "plan9", Name: "Plan 9", Family: facts.FamilyUnknown,
	}})

	newRT := func(f *facts.Facts, files map[string]string) *runtime.Runtime {
		rt := &runtime.Runtime{
			Exec:   runtime.NewExecRegistry(),
			States: runtime.NewStateRegistry(),
			FS:     runtime.NewMemoryFS(),
			Facts:  f,
		}
		for path, content := range files {
			mustWrite(rt, path, content)
		}
		return rt
	}

	// Debian family routes to the apt engine.
	rt := newRT(aptFacts, map[string]string{
		"/testbed/sources.list": "deb http://deb.example/ stretch main\n",
	})
	got, err := (listReposFunc{}).Execute(context.Background(), rt, &ListReposArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(map[string][]map[string]any)["http://deb.example/"]; !ok {
		t.Fatalf("apt dispatch result = %#v", got)
	}

	// RedHat family routes to the yum engine.
	rt = newRT(yumFacts, map[string]string{
		"/testbed/repos/x.repo": "[xr]\nname=X\nbaseurl=http://rpm.example/\n",
	})
	got, err = (listReposFunc{}).Execute(context.Background(), rt, &ListReposArgs{Basedir: strPtr("/testbed/repos")})
	if err != nil {
		t.Fatal(err)
	}
	yumResult, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("yum dispatch result type = %T", got)
	}
	if _, ok := yumResult["xr"]; !ok {
		t.Fatalf("yum dispatch result = %#v", got)
	}

	// The key trio exists only in the apt provider module.
	keysFn := getRepoKeysFunc{}
	if _, err := keysFn.Execute(context.Background(), rt, &GetRepoKeysArgs{}); err == nil ||
		!strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("keys on yum backend = %v", err)
	}

	// Unknown families fail like Salt's __virtual__ rejection.
	rt = newRT(unknownFacts, nil)
	listFn := listReposFunc{}
	if _, err := listFn.Execute(context.Background(), rt, &ListReposArgs{}); err == nil ||
		err.Error() != "The pkg module could not be loaded: unsupported OS family" {
		t.Fatalf("unknown-family error = %v", err)
	}
}
