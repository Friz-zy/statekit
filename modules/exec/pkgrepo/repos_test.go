package pkgrepo

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

// Repository-function tests mapped onto
// saltstack/tests/pytests/unit/modules/test_aptpkg.py:
// test_list_repos, test_get_repo_deb822*, test_mod_repo_deb822_*,
// test_del_repo_deb822, test_mod_repo_match, test__expand_repo_def*,
// and the SourcesList consolidation behaviors.

const deb822Content = `# TEST SOURCE Deb822
Types: deb
URIs: http://cz.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

// aptRT builds a runtime with the /testbed sources layout. whichBin is
// stubbed empty so the apt-key flows take their no-binary branches
// deterministically.
func aptRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	redirectPaths(t)
	stubWhichBin(t, func(string) string { return "" })
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  factsForTesting(),
	}
	mustWrite(rt, "/testbed/sources.list", "")
	for path, content := range files {
		mustWrite(rt, path, content)
	}
	return rt
}

func stubWhichBin(t *testing.T, fn func(string) string) {
	t.Helper()
	saved := whichBin
	whichBin = fn
	t.Cleanup(func() { whichBin = saved })
}

// Mirrors test_list_repos.
func TestListReposClassic(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list": "deb http://cdn-aws.deb.debian.org/debian/ stretch main\n",
	})
	repos, err := listRepos(rt)
	if err != nil {
		t.Fatal(err)
	}
	uri := "http://cdn-aws.deb.debian.org/debian/"
	list, ok := repos[uri]
	if !ok || len(list) != 1 {
		t.Fatalf("repos[%q] missing or wrong size: %#v", uri, repos)
	}
	repo := list[0]
	if line, _ := repo["line"].(string); !strings.HasPrefix(line, "deb http://cdn-aws.deb.debian.org/debian/") {
		t.Fatalf("line = %q", line)
	}
	if gotURI, _ := repo["uri"].(string); gotURI != uri || !strings.HasSuffix(gotURI, "/") {
		t.Fatalf("uri = %q", gotURI)
	}
	if enabled, _ := repo["enabled"].(bool); !enabled {
		t.Fatalf("enabled = %v", repo["enabled"])
	}
	if comps, _ := repo["comps"].([]string); !equalSlices(comps, []string{"main"}) {
		t.Fatalf("comps = %v", repo["comps"])
	}
}

// Mirrors test_get_repo_deb822 plus the Enabled true/false batteries.
func TestGetRepoDeb822(t *testing.T) {
	cases := []struct {
		enabledLine string
		wantEnabled bool
	}{
		{"", true},
		{"Enabled: no\n", false},
		{"Enabled: false\n", false},
		{"Enabled: yes\n", true},
		{"Enabled: 1\n", true},
	}
	for _, c := range cases {
		rt := aptRT(t, map[string]string{
			"/testbed/sources.list.d/test.sources": deb822Content + c.enabledLine,
		})
		result, err := getRepo(rt, "deb http://cz.archive.ubuntu.com/ubuntu/ noble main", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) == 0 {
			t.Fatalf("get_repo(%q) empty (enabledLine=%q)", "deb http://cz.archive.ubuntu.com/ubuntu/ noble main", c.enabledLine)
		}
		if gotURI, _ := result["uri"].(string); gotURI != "http://cz.archive.ubuntu.com/ubuntu/" {
			t.Fatalf("uri = %q", gotURI)
		}
		if enabled, ok := result["enabled"].(bool); !ok || enabled != c.wantEnabled {
			t.Fatalf("enabled = %#v; want %v", result["enabled"], c.wantEnabled)
		}
	}
}

// Mirrors test_mod_repo_deb822_modify.
func TestModRepoDeb822Modify(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list.d/test.sources": deb822Content,
	})
	repo := "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://cz.archive.ubuntu.com/ubuntu/ noble main"
	ret, err := modRepo(context.Background(), rt, repo, "base", true, map[string]any{
		"enabled":    false,
		"file":       "/testbed/sources.list.d/test.sources",
		"refresh_db": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, ok := ret[repo].(map[string]any)
	if !ok || len(info) == 0 {
		t.Fatalf("mod_repo reply = %#v", ret)
	}
	content := readAll(t, rt, "/testbed/sources.list.d/test.sources")
	if !strings.Contains(content, "Enabled: no") {
		t.Fatalf("file missing 'Enabled: no':\n%s", content)
	}
	if !strings.Contains(content, "URIs: http://cz.archive.ubuntu.com/ubuntu/") {
		t.Fatalf("file lost URIs:\n%s", content)
	}
}

// Mirrors test_mod_repo_deb822_add.
func TestModRepoDeb822Add(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list.d/test.sources": deb822Content,
	})
	repo := "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://security.ubuntu.com/ubuntu/ noble-security main"
	_, err := modRepo(context.Background(), rt, repo, "base", true, map[string]any{
		"file":       "/testbed/sources.list.d/test.sources",
		"refresh_db": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	content := readAll(t, rt, "/testbed/sources.list.d/test.sources")
	if !strings.Contains(content, "URIs: http://security.ubuntu.com/ubuntu/") {
		t.Fatalf("new stanza missing:\n%s", content)
	}
	if !strings.Contains(content, "Suites: noble-security") {
		t.Fatalf("new suite missing:\n%s", content)
	}
}

// Mirrors test_del_repo_deb822 including the part-file removal on the last
// deletion and the two message shapes.
func TestDelRepoDeb822(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list.d/test.sources": deb822Content,
	})
	filePath := "/testbed/sources.list.d/test.sources"

	ret, err := delRepo(context.Background(), rt, "deb http://cz.archive.ubuntu.com/ubuntu/ noble main", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "Repo 'deb http://cz.archive.ubuntu.com/ubuntu/ noble main' has been removed from " + filePath + ".\n"
	if ret != want {
		t.Fatalf("del#1 reply = %q; want %q", ret, want)
	}
	if _, statErr := rt.FS.Stat(filePath); statErr != nil {
		t.Fatalf("file removed too early: %v", statErr)
	}

	if _, err := delRepo(context.Background(), rt, "deb http://cz.archive.ubuntu.com/ubuntu/ noble-updates main", nil); err != nil {
		t.Fatal(err)
	}
	if _, statErr := rt.FS.Stat(filePath); statErr != nil {
		t.Fatalf("file removed too early: %v", statErr)
	}

	ret, err = delRepo(context.Background(), rt, "deb http://cz.archive.ubuntu.com/ubuntu/ noble-backports main", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantFileGone := "File " + filePath + " containing repo 'deb http://cz.archive.ubuntu.com/ubuntu/ noble-backports main' has been removed."
	if ret != wantFileGone {
		t.Fatalf("del#3 reply = %q; want %q", ret, wantFileGone)
	}
	if _, statErr := rt.FS.Stat(filePath); statErr == nil {
		t.Fatalf("part file still present")
	}
}

// Mirrors test_mod_repo_match: matching ignores a trailing slash on the
// request URI.
func TestModRepoMatch(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list": "deb http://cdn-aws.deb.debian.org/debian/ stretch main\n",
	})
	noSlash := "deb http://cdn-aws.deb.debian.org/debian stretch main"
	ret, err := modRepo(context.Background(), rt, noSlash, "base", true, map[string]any{
		"enabled":    false,
		"refresh_db": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, ok := ret[noSlash].(map[string]any)
	if !ok || len(info) == 0 {
		t.Fatalf("no-slash request did not match existing repo: %#v", ret)
	}
	if dist, _ := info["dist"].(string); dist != "stretch" {
		t.Fatalf("matched wrong repo: %#v", info)
	}
	content := readAll(t, rt, "/testbed/sources.list")
	if !strings.Contains(content, "# deb ") {
		t.Fatalf("disable not rendered:\n%s", content)
	}
}

// Mirrors test__expand_repo_def, test__expand_repo_def_cdrom, and
// test__expand_repo_def_not_repo.
func TestExpandRepoDef(t *testing.T) {
	redirectPaths(t)
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Facts: factsForTesting()}
	mustWrite(rt, "/testbed/sources.list", "")

	sanitized, err := expandRepoDef(rt, "debian", "stretch", map[string]any{
		"repo": "deb http://cdn-aws.deb.debian.org/debian/ stretch main\n",
		"file": "/etc/apt/sources.list",
	})
	if err != nil {
		t.Fatal(err)
	}
	if uri, _ := sanitized["uri"].(string); !strings.HasSuffix(uri, "/") {
		t.Fatalf("uri = %q", uri)
	}

	sanitized, err = expandRepoDef(rt, "debian", "stretch", map[string]any{
		"repo":          "deb http://cdn-aws.deb.debian.org/debian/ stretch main\n",
		"file":          "/etc/apt/sources.list",
		"architectures": "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if line, _ := sanitized["line"].(string); line != "deb [arch=amd64] http://cdn-aws.deb.debian.org/debian/ stretch main" {
		t.Fatalf("arch line = %q", line)
	}

	sanitized, err = expandRepoDef(rt, "debian", "", map[string]any{
		"repo": "# deb cdrom:[Debian GNU/Linux 11.4.0 _Bullseye_ - Official amd64 NETINST 20220709-10:31]/ bullseye main\n",
		"file": "/etc/apt/sources.list",
	})
	if err != nil {
		t.Fatal(err)
	}
	if uri, _ := sanitized["uri"].(string); !strings.HasSuffix(uri, "/") {
		t.Fatalf("cdrom uri = %q", uri)
	}
	if disabled, _ := sanitized["disabled"].(bool); !disabled {
		t.Fatalf("cdrom disabled = %v", sanitized["disabled"])
	}

	_, err = expandRepoDef(rt, "debian", "stretch", map[string]any{"architectures": "amd64"})
	if err == nil || err.Error() != "missing 'repo' argument" {
		t.Fatalf("missing-repo error = %v", err)
	}
}

// Pins consolidateRepoSources: same-key entries merge onto sources.list and
// EVERY non-base part file disappears (upstream adds each processed part
// file to the deletion set, even when its entry survives). Comps keep
// first-seen order (documented divergence from upstream's unordered set
// union).
func TestConsolidateRepoSources(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list":              "deb http://u/ focal main\n",
		"/testbed/sources.list.d/a.list":     "deb http://u/ focal main\n",
		"/testbed/sources.list.d/b.list":     "deb http://u/ focal main universe\n",
		"/testbed/sources.list.d/other.list": "deb http://other/ focal main\n",
	})
	sources := newSourcesList(rt)
	consolidated := consolidateRepoSources(rt, sources)

	var classics []*sourceEntry
	for _, item := range consolidated.list {
		se, ok := item.(*sourceEntry)
		if !ok {
			t.Fatalf("unexpected entry type %T", item)
		}
		classics = append(classics, se)
	}
	if len(classics) != 2 {
		t.Fatalf("expected 2 consolidated entries, got %d", len(classics))
	}
	merged := classics[0]
	if !equalSlices(merged.comps, []string{"main", "universe"}) {
		t.Fatalf("merged comps = %v", merged.comps)
	}
	if merged.file != "/testbed/sources.list" {
		t.Fatalf("merged file = %q", merged.file)
	}
	for _, gone := range []string{
		"/testbed/sources.list.d/a.list",
		"/testbed/sources.list.d/b.list",
		"/testbed/sources.list.d/other.list",
	} {
		if _, err := rt.FS.Stat(gone); err == nil {
			t.Fatalf("%s survived consolidation", gone)
		}
	}
	content := readAll(t, rt, "/testbed/sources.list")
	if !strings.Contains(content, "deb http://other/ focal main") {
		t.Fatalf("unrelated entry lost from sources.list:\n%s", content)
	}
	if !strings.Contains(content, "deb http://u/ focal main universe") {
		t.Fatalf("merged entry not rendered onto sources.list:\n%s", content)
	}
}

// Pins the not-found error surface of del_repo on classic layouts.
func TestDelRepoClassicMissingError(t *testing.T) {
	rt := aptRT(t, map[string]string{
		"/testbed/sources.list": "deb http://real/ stretch main\n",
	})
	_, err := delRepo(context.Background(), rt, "deb http://x/ y z", nil)
	if err == nil || err.Error() != "Repo deb http://x/ y z doesn't exist in the sources.list(s)" {
		t.Fatalf("missing-repo error = %v", err)
	}
}

// Pins the Launchpad format expansion including del_repo's swapped
// argument-order quirk.
func TestExpandPPAFormats(t *testing.T) {
	got, err := expandPPARepo("ppa:foo/bar", "noble", "", false)
	if err != nil || got != "deb http://ppa.launchpad.net/foo/bar/ubuntu noble main" {
		t.Fatalf("public PPA expansion = %q, %v", got, err)
	}
	got, err = expandPPARepo("ppa:foo/bar", "noble", "auth", false)
	if err != nil || got != "deb https://auth@private-ppa.launchpad.net/foo/bar/ubuntu noble main" {
		t.Fatalf("private PPA expansion = %q, %v", got, err)
	}
	got, err = expandPPARepo("ppa:foo/bar", "noble", "auth", true)
	if err != nil || got != "deb https://auth@private-ppa.launchpad.net/noble/foo/ubuntu bar main" {
		t.Fatalf("swapped del_repo expansion = %q, %v", got, err)
	}
	if _, err := expandPPARepo("ppa:noslash", "noble", "", false); err == nil {
		t.Fatalf("malformed ppa accepted")
	}
}

func readAll(t *testing.T, rt *runtime.Runtime, path string) string {
	t.Helper()
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
