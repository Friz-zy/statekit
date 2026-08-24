package pkgbuild

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Deb-backend tests pinning the pure helpers and the argv sequences read
// from debbuild_pkgbuild.py @ pinned revision.

func TestGetBuildEnv(t *testing.T) {
	if got := getBuildEnv(nil); got != "" {
		t.Fatalf("nil env = %q", got)
	}
	got := getBuildEnv(map[string]any{"DEB_BUILD_OPTIONS": "nocheck"})
	want := "DEB_BUILD_OPTIONS=nocheck\nexport DEB_BUILD_OPTIONS\n"
	if got != want {
		t.Fatalf("env = %q; want %q", got, want)
	}
}

func TestGetRepoOptionsEnv(t *testing.T) {
	got := getRepoOptionsEnv(map[string]any{
		"OPTIONS": "ask-passphrase",
		"OTHER":   "ignored",
	})
	if got != "ask-passphrase\n" {
		t.Fatalf("options = %q", got)
	}
	if got := getRepoOptionsEnv(nil); got != "" {
		t.Fatalf("nil options = %q", got)
	}
}

// Mirrors _get_repo_dists_env including the dead-code quirk: with an env
// dict missing CODENAME no default is injected and codename stays empty.
func TestGetRepoDistsEnv(t *testing.T) {
	codename, dists := getRepoDistsEnv(nil)
	if codename != "stretch" {
		t.Fatalf("nil codename = %q", codename)
	}
	for _, want := range []string{
		"Codename: stretch\n",
		"Architectures: i386 amd64 source\n",
		"Components: main\n",
	} {
		if !strings.Contains(dists, want) {
			t.Fatalf("dists missing %q in %q", want, dists)
		}
	}
	if strings.Contains(dists, "OPTIONS") {
		t.Fatalf("ignored key leaked: %q", dists)
	}

	codename, dists = getRepoDistsEnv(map[string]any{
		"CODENAME":    "jessie",
		"ARCHS":       "amd64 source",
		"CUSTOMFIELD": "custom-value",
	})
	if codename != "jessie" {
		t.Fatalf("codename = %q", codename)
	}
	for _, want := range []string{
		"Codename: jessie\n",
		"Architectures: amd64 source\n",
		"CUSTOMFIELD: custom-value\n",
	} {
		if !strings.Contains(dists, want) {
			t.Fatalf("dists missing %q in %q", want, dists)
		}
	}
	if strings.Contains(dists, "Codename: stretch") {
		t.Fatalf("default codename injected despite dead back-fill: %q", dists)
	}

	codename, _ = getRepoDistsEnv(map[string]any{"ORIGIN": "x"})
	if codename != "" {
		t.Fatalf("missing-CODENAME codename = %q; want empty", codename)
	}
}

// Mirrors the .dsc passthrough branch of make_src_pkg.
func TestDebMakeSrcPkgDSCPassthrough(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	rt := pkgRT(t, "debian", &seqRunner{}, map[string]string{
		"/testbed/home/root/.pbuilderrc": "",
		"/testbed/in/pkg.dsc":            "dsc contents",
		"/testbed/in/pkg.orig.tar.gz":    "orig",
		"/testbed/in/pkg.debian.tar.xz":  "debian",
	})
	ret, err := makeSrcPkgFunc{}.Execute(context.Background(), rt, &MakeSrcPkgArgs{
		DestDir: "/testbed/out",
		Spec:    "/testbed/in/pkg.dsc",
		Sources: []any{
			"/testbed/in/pkg.orig.tar.gz",
			"/testbed/in/pkg.debian.tar.xz",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	list := ret.([]string)
	if len(list) != 3 {
		t.Fatalf("passthrough = %#v", list)
	}
}

// Pins the salt-tarball rename dance argv sequence ending in
// `debuild -S -uc -us -sa`.
func TestDebMakeSrcPkgTarballDance(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	var rt *runtime.Runtime
	runner := &seqRunner{}
	rt = pkgRT(t, "debian", runner, map[string]string{
		"/testbed/home/root/.pbuilderrc": "",
		"/testbed/in/control.tar.xz":     "control",
		"/testbed/in/salt-3008.0.tar.gz": "sdist",
	})

	_, err := makeSrcPkgFunc{}.Execute(context.Background(), rt, &MakeSrcPkgArgs{
		DestDir: "/testbed/out",
		Spec:    "/testbed/in/control.tar.xz",
		Sources: []any{"/testbed/in/salt-3008.0.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joinedCalls := runner.joined()
	wantSequence := []string{"tar -xvzf salt-3008.0.tar.gz"}
	found := -1
	for i, call := range joinedCalls {
		if strings.HasPrefix(call, "tar -xvzf salt-3008.0.tar.gz") {
			found = i
			break
		}
	}
	if found < 0 {
		t.Fatalf("extract argv missing: %#v", joinedCalls)
	}
	wantSteps := []string{
		"mv salt-3008.0 salt_3008.0",
		"tar -cvzf ",
		"rm -f salt-3008.0.tar.gz",
	}
	if !strings.HasPrefix(joinedCalls[found], wantSequence[0]) {
		t.Fatalf("sequence start wrong at %d: %s", found, joinedCalls[found])
	}
	for offset, prefix := range wantSteps {
		idx := found + 1 + offset
		if idx >= len(joinedCalls) || !strings.HasPrefix(joinedCalls[idx], prefix) {
			t.Fatalf("sequence step %q missing at %d: %#v", prefix, idx, joinedCalls)
		}
	}
	debuildIdx := -1
	for i, call := range joinedCalls {
		if call == "debuild -S -uc -us -sa" {
			debuildIdx = i
		}
	}
	if debuildIdx < found+4 {
		t.Fatalf("debuild argv misplaced: %#v", joinedCalls)
	}
}

// Mirrors build: pbuilder create failure surfaces verbatim.
func TestDebBuildPbuilderCreateFailure(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	runner := &seqRunner{onRun: func(argv []string) process.CommandResult {
		if strings.HasSuffix(strings.Join(argv, " "), "--create") {
			return process.CommandResult{ExitCode: 3}
		}
		return process.CommandResult{}
	}}
	rt := pkgRT(t, "debian", runner, map[string]string{
		"/testbed/home/root/.pbuilderrc": "",
		"/testbed/in/pkg.dsc":            "dsc",
	})
	ret, err := buildFunc{}.Execute(context.Background(), rt, &BuildArgs{
		Runas:   "root",
		Tgt:     "deb-12-x86_64",
		DestDir: "/testbed/out",
		Spec:    "/testbed/in/pkg.dsc",
		Sources: []any{},
	})
	if err == nil || !strings.HasPrefix(err.Error(), "pbuilder create failed with return error '3'") {
		t.Fatalf("error = %v (ret=%#v)", err, ret)
	}
}

// Mirrors make_repo unsigned: conf rendering plus includedeb flows.
func TestDebMakeRepoUnsigned(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	env := map[string]any{
		"CODENAME":   "noble",
		"ARCHS":      "amd64 source",
		"COMPONENTS": "main",
	}
	rt := pkgRT(t, "debian", &seqRunner{onRun: func(argv []string) process.CommandResult {
		if argv[0] == "reprepro" {
			return process.CommandResult{Stdout: []byte("included")}
		}
		return process.CommandResult{}
	}}, map[string]string{
		"/testbed/repo/hello.deb": "deb",
	})
	ret, err := makeRepoFunc{}.Execute(context.Background(), rt, &MakeRepoArgs{
		RepoDir: "/testbed/repo",
		Env:     env,
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["retcode"] != 0 {
		t.Fatalf("result = %#v", dict)
	}
	dists := string(mustReadFile(t, rt, "/testbed/repo/conf/distributions"))
	for _, want := range []string{"Codename: noble\n", "Architectures: amd64 source\n"} {
		if !strings.Contains(dists, want) {
			t.Fatalf("distributions missing %q:\n%s", want, dists)
		}
	}
	if strings.Contains(dists, "SignWith:") {
		t.Fatalf("unsigned repo carries SignWith:\n%s", dists)
	}
}

// Pins the SignWith-before-pillar-gate ordering and the gate error.
func TestDebMakeRepoKeyidWithoutPillar(t *testing.T) {
	stubHome(t, "/testbed/home/root")
	rt := pkgRT(t, "debian", &seqRunner{}, map[string]string{
		"/testbed/repo/hello.deb": "deb",
	})
	_, err := makeRepoFunc{}.Execute(context.Background(), rt, &MakeRepoArgs{
		RepoDir: "/testbed/repo",
		Keyid:   strPtrPkg("FBB75451"),
		Env: map[string]any{
			"CODENAME": "noble", "ARCHS": "amd64 source", "COMPONENTS": "main",
		},
	})
	if err == nil || !strings.Contains(err.Error(),
		"Public and Private key files associated with Pillar data and 'keyid' FBB75451") {
		t.Fatalf("error = %v", err)
	}
	dists := string(mustReadFile(t, rt, "/testbed/repo/conf/distributions"))
	if !strings.Contains(dists, "SignWith: FBB75451\n") {
		t.Fatalf("SignWith not persisted before the gate:\n%s", dists)
	}
}

func mustReadFile(t *testing.T, rt *runtime.Runtime, path string) []byte {
	t.Helper()
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Dispatch routes families to their builder backends.
func TestBackendDispatch(t *testing.T) {
	for family, backend := range map[string]string{
		"redhat": "rpm",
		"suse":   "rpm",
		"debian": "deb",
	} {
		rt := pkgRT(t, family, &seqRunner{}, nil)
		got, err := backendOf(rt)
		if err != nil || got != backend {
			t.Fatalf("%s -> %q, %v; want %q", family, got, err, backend)
		}
	}
	rt := pkgRT(t, "alpine", &seqRunner{}, nil)
	if _, err := backendOf(rt); err == nil ||
		err.Error() != "The pkgbuild module could not be loaded: unsupported OS family" {
		t.Fatalf("unknown family error = %v", err)
	}
}
