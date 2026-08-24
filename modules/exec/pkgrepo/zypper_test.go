package pkgrepo

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// SUSE/zypper repository tests mapped onto
// saltstack/tests/unit/modules/test_zypperpkg.py (test_refresh_db and the
// zypp/*.cfg repo fixtures) plus the _Zypper wrapper behaviors those tests
// exercise.

func zypperRT(t *testing.T, files map[string]string, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := zypperReposDir
	zypperReposDir = "/testbed/etc/zypp/repos.d"
	t.Cleanup(func() { zypperReposDir = saved })
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: "opensuse-leap", Name: "openSUSE Leap", Family: facts.FamilySuse,
		}}),
		Runner: runner,
	}
	for path, content := range files {
		mustWrite(rt, path, content)
	}
	return rt, runner
}

func stubZypperLockWait(t *testing.T) {
	t.Helper()
	saved := zypperLockWait
	zypperLockWait = func() {}
	t.Cleanup(func() { zypperLockWait = saved })
}

const zypperRepoCfg = `[SLE12-SP1-x86_64-Update]
name=Update Repository
enabled=1
autorefresh=1
baseurl=http://somehost.com/SUSE/Updates/SLE-SERVER/12-SP1/x86_64/update/
type=NONE

[SLE12-SP1-x86_64-Update-disabled]
name=Update Repository
enabled=0
autorefresh=0
baseurl=http://somehost.com/SUSE/Updates/SLE-SERVER/12-SP1/x86_64/update/
type=NONE
`

func TestZypperListAndGetRepo(t *testing.T) {
	rt, _ := zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": zypperRepoCfg,
	}, nil)

	repos, err := zypperListRepos(rt, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 {
		t.Fatalf("repos = %#v", repos)
	}
	active := repos["SLE12-SP1-x86_64-Update"].(map[string]any)
	if active["enabled"] != true || active["autorefresh"] != true {
		t.Fatalf("coercion failed: %#v", active)
	}
	if active["type"] != nil {
		t.Fatalf("NONE coercion failed: %#v", active["type"])
	}
	if active["alias"] != "SLE12-SP1-x86_64-Update" {
		t.Fatalf("alias missing: %#v", active)
	}

	disabled := repos["SLE12-SP1-x86_64-Update-disabled"].(map[string]any)
	if disabled["enabled"] != false || disabled["autorefresh"] != false {
		t.Fatalf("disabled coercion failed: %#v", disabled)
	}

	repo, err := zypperGetRepo(rt, "SLE12-SP1-x86_64-Update", "")
	if err != nil {
		t.Fatal(err)
	}
	if repo["baseurl"] != "http://somehost.com/SUSE/Updates/SLE-SERVER/12-SP1/x86_64/update/" {
		t.Fatalf("get_repo baseurl = %#v", repo["baseurl"])
	}

	missing, err := zypperGetRepo(rt, "ghost", "")
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing get_repo = %#v, %v", missing, err)
	}
}

// Mirrors the del_repo flow with XML feedback.
func TestZypperDelRepo(t *testing.T) {
	xmlOut := `<?xml version="1.0"?>
<stream>
<progress id="Repository 'SLE12'">
<message type="info">Repository &apos;SLE12&apos; has been removed.</message>
</progress>
</stream>`
	rt, runner := zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": "[SLE12]\nname=SLE12\nbaseurl=http://x/\n",
	}, map[string]process.CommandResult{
		"zypper --non-interactive --xmlout --no-refresh rr --loose-auth --loose-query SLE12": {
			Stdout: []byte(xmlOut),
		},
	})

	ret, err := zypperDelRepo(context.Background(), rt, "SLE12", "")
	if err != nil {
		t.Fatal(err)
	}
	if ret["SLE12"] != true {
		t.Fatalf("del reply = %#v", ret)
	}
	if msg, _ := ret["message"].(string); !strings.Contains(msg, "has been removed") {
		t.Fatalf("message = %#v", ret["message"])
	}
	found := false
	for _, call := range runner.calls {
		if equalSlices(call, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh",
			"rr", "--loose-auth", "--loose-query", "SLE12"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("rr argv missing: %v", runner.calls)
	}

	// Without progress/message feedback upstream raises not-found even after
	// a successful removal.
	rt, _ = zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": "[SLE12]\nname=SLE12\nbaseurl=http://x/\n",
	}, map[string]process.CommandResult{
		"zypper --non-interactive --xmlout --no-refresh rr --loose-auth --loose-query SLE12": {
			Stdout: []byte(`<?xml version="1.0"?><stream></stream>`),
		},
	})
	if _, err := zypperDelRepo(context.Background(), rt, "SLE12", ""); err == nil ||
		err.Error() != "Repository 'SLE12' not found." {
		t.Fatalf("silent-del error = %v", err)
	}
}

// Mirrors test_refresh_db including the exact argv shapes and output parse.
func TestZypperRefreshDB(t *testing.T) {
	refOut := strings.Join([]string{
		"Repository 'openSUSE-Leap-42.1-LATEST' is up to date.",
		"Repository 'openSUSE-Leap-42.1-Update' is up to date.",
		"Retrieving repository 'openSUSE-Leap-42.1-Update-Non-Oss' metadata",
		"Forcing building of repository cache",
		"Building repository 'openSUSE-Leap-42.1-Update-Non-Oss' cache ..........[done]",
		"Building repository 'salt-dev' cache",
		"All repositories have been refreshed.",
	}, "\n")
	stdoutKey := "zypper --non-interactive refresh --force"
	rt, runner := zypperRT(t, nil, map[string]process.CommandResult{
		stdoutKey: {Stdout: []byte(refOut)},
	})

	ret, err := zypperRefreshDB(context.Background(), rt, nil, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ret["openSUSE-Leap-42.1-LATEST"] != false ||
		ret["openSUSE-Leap-42.1-Update"] != false ||
		ret["openSUSE-Leap-42.1-Update-Non-Oss"] != true {
		t.Fatalf("refresh parse = %#v", ret)
	}
	found := false
	for _, call := range runner.calls {
		if equalSlices(call, []string{"zypper", "--non-interactive", "refresh", "--force"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("refresh argv missing (want no --no-refresh): %v", runner.calls)
	}

	// force=False drops --force; gpgautoimport prepends the key flag.
	rt, runner = zypperRT(t, nil, map[string]process.CommandResult{
		"zypper --non-interactive refresh":                                {Stdout: []byte("")},
		"zypper --non-interactive --gpg-auto-import-keys refresh --force": {Stdout: []byte("")},
		"zypper --non-interactive --gpg-auto-import-keys refresh":         {Stdout: []byte("")},
	})
	noForce := false
	if _, err := zypperRefreshDB(context.Background(), rt, &noForce, "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := zypperRefreshDB(context.Background(), rt, nil, "", true, nil); err != nil {
		t.Fatal(err)
	}
	foundPlain := false
	foundAutoForce := false
	for _, call := range runner.calls {
		if equalSlices(call, []string{"zypper", "--non-interactive", "refresh"}) {
			foundPlain = true
		}
		if equalSlices(call, []string{"zypper", "--non-interactive", "--gpg-auto-import-keys", "refresh", "--force"}) {
			foundAutoForce = true
		}
	}
	if !foundPlain || !foundAutoForce {
		t.Fatalf("argv shapes missing: %v", runner.calls)
	}
}

func TestZypperModRepoFlows(t *testing.T) {
	stubZypperLockWait(t)

	// Creation without URL fails verbatim.
	rt, _ := zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": zypperRepoCfg,
	}, nil)
	if _, err := zypperModRepo(context.Background(), rt, "newrepo", "", nil); err == nil ||
		!strings.HasPrefix(err.Error(), "Repository 'newrepo' not found, and neither 'baseurl' nor 'mirrorlist' was specified") {
		t.Fatalf("create-no-url error = %v", err)
	}

	// Malformed URL fails verbatim.
	if _, err := zypperModRepo(context.Background(), rt, "newrepo", "", map[string]any{
		"baseurl": "not-a-url",
	}); err == nil || !strings.Contains(err.Error(), "URL for baseurl/mirrorlist is malformed") {
		t.Fatalf("malformed-url error = %v", err)
	}

	// Duplicate URL under another alias fails before any call.
	dupURL := "http://somehost.com/SUSE/Updates/SLE-SERVER/12-SP1/x86_64/update/"
	dupRT, dupRunner := zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": zypperRepoCfg,
	}, nil)
	if _, err := zypperModRepo(context.Background(), dupRT, "newrepo", "", map[string]any{
		"baseurl": dupURL,
	}); err == nil || !strings.Contains(err.Error(), "already exists as 'SLE12-SP1-x86_64-Update'.") {
		t.Fatalf("duplicate-url error = %v", err)
	}
	if len(dupRunner.calls) != 0 {
		t.Fatalf("duplicate probe invoked zypper: %v", dupRunner.calls)
	}

	// Modification renders the mr flags in Salt's order.
	mrXML := `<?xml version="1.0"?><stream></stream>`
	modRT, modRunner := zypperRT(t, map[string]string{
		"/testbed/etc/zypp/repos.d/sle.repo": zypperRepoCfg,
	}, map[string]process.CommandResult{
		"zypper --non-interactive --xmlout mr --disable --no-refresh --keep-packages --priority=50 name": {Stdout: []byte(mrXML)},
	})
	if _, err := zypperModRepo(context.Background(), modRT, "SLE12-SP1-x86_64-Update", "", map[string]any{
		"enabled":  false,
		"refresh":  false,
		"cache":    true,
		"priority": 50,
		"name":     "Renamed",
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, call := range modRunner.calls {
		if equalSlices(call, []string{"zypper", "--non-interactive", "--xmlout", "mr",
			"--disable", "--no-refresh", "--keep-packages", "--priority=50", "--name", "Renamed",
			"SLE12-SP1-x86_64-Update"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("mr argv missing: %v", modRunner.calls)
	}

	// No-op modification carries the comment marker.
	reply, err := zypperModRepo(context.Background(), modRT, "SLE12-SP1-x86_64-Update", "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if reply["comment"] != "Specified arguments did not result in modification of repo" {
		t.Fatalf("comment = %#v", reply["comment"])
	}
}

// Pins the root-aware repos path resolution.
func TestZypperRootPath(t *testing.T) {
	saved := zypperReposDir
	zypperReposDir = "/etc/zypp/repos.d"
	t.Cleanup(func() { zypperReposDir = saved })
	if got := zypperReposCfgPath(""); got != "/etc/zypp/repos.d" {
		t.Fatalf("default path = %q", got)
	}
	if got := zypperReposCfgPath("/mnt"); got != "/mnt/etc/zypp/repos.d" {
		t.Fatalf("rooted path = %q", got)
	}
}
