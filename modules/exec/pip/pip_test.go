package pip

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests pinning the binary resolution, argv contracts, and query surface
// read from saltstack/salt/modules/pip.py @ pinned revision.

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
	hook    func(argv []string)
}

func (f *fakeRunner) joined() []string {
	out := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		out = append(out, strings.Join(call, " "))
	}
	return out
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if f.hook != nil {
		f.hook(argv)
	}
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func pipRT(t *testing.T, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	versionCacheMu.Lock()
	versionCache = map[string]string{}
	versionCacheMu.Unlock()

	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o755)
		if strings.HasSuffix(path, ".txt") || !strings.Contains(path, "bin/") {
			mode = 0o644
		}
		if err := rt.FS.WriteFile(path, []byte(content), mode); err != nil {
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

func TestGetPipBinFromVenv(t *testing.T) {
	rt := pipRT(t, &fakeRunner{}, map[string]string{
		"/venvs/app/bin/python": "#!/bin/sh\n",
	})
	got, err := getPipBin(rt, "/venvs/app")
	if err != nil {
		t.Fatal(err)
	}
	if !equalSlice(got, []string{"/venvs/app/bin/python", "-m", "pip"}) {
		t.Fatalf("venv pip = %#v", got)
	}

	got, err = getPipBin(rt, "")
	want := []string{pythonExecutable(), "-m", "pip"}
	if err != nil || !equalSlice(got, want) {
		t.Fatalf("default pip = %#v, %v", got, err)
	}
}

func TestGetPipBinRanked(t *testing.T) {
	rt := pipRT(t, &fakeRunner{}, map[string]string{
		"/venvs/ranked/bin/python3.12": "#!/bin/sh\n",
		"/venvs/ranked/bin/python3":    "#!/bin/sh\n",
	})
	got, err := getPipBin(rt, "/venvs/ranked")
	if err != nil {
		t.Fatal(err)
	}
	// Rank 0 (python) missing; rank 1 python3 wins over python3.12.
	if !equalSlice(got, []string{"/venvs/ranked/bin/python3", "-m", "pip"}) {
		t.Fatalf("ranked pip = %#v", got)
	}
}

func TestGetPipBinErrors(t *testing.T) {
	// A venv directory that exists but has no python yields the dedicated
	// message (ranked search exhausted).
	rt := pipRT(t, &fakeRunner{results: map[string]process.CommandResult{}}, map[string]string{
		"/venvs/empty/README": "not a python\n",
	})
	if _, err := getPipBin(rt, "/venvs/empty"); err == nil ||
		err.Error() != "Could not find a pip binary in virtualenv /venvs/empty" {
		t.Fatalf("empty venv error = %v", err)
	}
	rt = pipRT(t, &fakeRunner{results: map[string]process.CommandResult{}}, nil)
	if _, err := getPipBin(rt, "/nonexistent/pip"); err == nil ||
		err.Error() != "Access denied to /nonexistent/pip, could not find a pip binary" {
		t.Fatalf("missing binary error = %v", err)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"requests_ntlm":   "requests-ntlm",
		"Django_Thing.x":  "django-thing-x",
		"zope.interface":  "zope-interface",
		"Flask--Admin___": "flask-admin-",
	}
	for input, want := range cases {
		if got := normalize(input); got != want {
			t.Fatalf("normalize(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestVersionParsesAndMemoizes(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		pythonExecutable() + "\x00-m\x00pip\x00--version": {Stdout: []byte("pip 23.2.1 from /usr/lib (python 3.12)\n")},
	}}
	rt := pipRT(t, runner, nil)

	got, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "23.2.1" {
		t.Fatalf("version = %#v", got)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("memoization failed: %d calls", len(runner.calls))
	}

	// Failed lookup raises the verbatim not-found error.
	runner.results[pythonExecutable()+"\x00-m\x00pip\x00--version"] =
		process.CommandResult{ExitCode: 1}
	clearContext("")
	probeFn := versionFunc{}
	_, probeErr := probeFn.Execute(context.Background(), rt, &VersionArgs{})
	if probeErr == nil || probeErr.Error() != "Could not find a `pip` binary" {
		t.Fatalf("not-found error = %v", probeErr)
	}
}

// Mirrors pip 10+ behavior: nothing to install short-circuits without a call.
func TestInstallNothingSpecified(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	rt := pipRT(t, runner, map[string]string{})
	ret, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["retcode"] != 0 || dict["stdout"] != "No packages to install." {
		t.Fatalf("short-circuit = %#v", dict)
	}
	// The version lookup precedes the short-circuit (one --version call).
	if len(runner.calls) != 1 || !strings.HasSuffix(strings.Join(runner.calls[0], " "), "--version") {
		t.Fatalf("unexpected calls: %#v", runner.joined())
	}
}

func TestInstallArgvAssembly(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		strings.Join([]string{pythonExecutable(), "-m", "pip", "--version"}, "\x00"): {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
	}}
	rt := pipRT(t, runner, map[string]string{})

	ret, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Pkgs:                "markdown,django",
		Upgrade:             true,
		NoDeps:              true,
		IndexURL:            strPtr("https://pypi.example/simple"),
		ExistsAction:        strPtr("s"),
		DisableVersionCheck: true,
		TrustedHost:         strPtr("pypi.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["retcode"] != 0 {
		t.Fatalf("install result = %#v", dict)
	}
	call := strings.Join(runner.calls[len(runner.calls)-1], " ")
	for _, piece := range []string{
		"-m pip install",
		"--index-url https://pypi.example/simple",
		"--upgrade",
		"--no-deps",
		"--exists-action s",
		"--disable-pip-version-check",
		"--trusted-host pypi.example",
		"markdown django",
	} {
		if !strings.Contains(call, piece) {
			t.Fatalf("argv missing %q: %s", piece, call)
		}
	}
}

func TestInstallValidations(t *testing.T) {
	base := func() (*runtime.Runtime, *fakeRunner) {
		runner := &fakeRunner{results: map[string]process.CommandResult{
			strings.Join([]string{pythonExecutable(), "-m", "pip", "--version"}, "\x00"): {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		}}
		return pipRT(t, runner, map[string]string{}), runner
	}

	rt, _ := base()
	_, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		NoIndex: true, IndexURL: strPtr("https://pypi.example/simple"),
	})
	if err == nil || err.Error() !=
		"'no_index' and ('index_url' or 'extra_index_url') are mutually exclusive." {
		t.Fatalf("mutual-exclusion = %v", err)
	}

	rt, _ = base()
	badURL := "notaurl"
	_, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		IndexURL: &badURL,
	})
	if err == nil || err.Error() != "'notaurl' is not a valid URL" {
		t.Fatalf("bad index_url = %v", err)
	}

	rt, _ = base()
	badAction := "x"
	_, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		ExistsAction: &badAction, Pkgs: "pkg",
	})
	if err == nil || !strings.Contains(err.Error(),
		"The exists_action pip option only supports the values s, i, w, and b.") {
		t.Fatalf("exists_action = %v", err)
	}

	rt, _ = base()
	floatTimeout := 1.5
	_, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Timeout: floatTimeout, Pkgs: "pkg",
	})
	if err == nil || !strings.Contains(err.Error(),
		"'1.5' is not a valid timeout, must be an integer") {
		t.Fatalf("float timeout = %v", err)
	}

	rt, _ = base()
	_, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Editable: "git+https://github.com/x/y.git", Pkgs: "",
	})
	if err == nil || err.Error() != "You must specify an egg for this editable" {
		t.Fatalf("editable guard = %v", err)
	}

	rt, _ = base()
	_, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Requirements: "salt://reqs.txt",
	})
	var unsupported *runtime.UnsupportedError
	foundUnsupported := false
	for e := err; e != nil && !foundUnsupported; {
		if ue, is := e.(*runtime.UnsupportedError); is {
			unsupported = ue
			foundUnsupported = true
			break
		}
		type unwrapper interface{ Unwrap() error }
		if w, is := e.(unwrapper); is {
			e = w.Unwrap()
			continue
		}
		break
	}
	if !foundUnsupported || unsupported.Name != "cp.cache_file" {
		t.Fatalf("salt requirements boundary = %v", err)
	}
}

// Mirrors freeze: --all plus the version-check suppression (#68214).
func TestFreeze(t *testing.T) {
	freezeKey := pythonExecutable() + "\x00-m\x00pip\x00freeze\x00--all\x00--disable-pip-version-check"
	verKey := pythonExecutable() + "\x00-m\x00pip\x00--version"
	runner := &fakeRunner{results: map[string]process.CommandResult{
		verKey:    {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		freezeKey: {Stdout: []byte("pip==23.2.1\nrequests==2.31.0\n")},
	}}
	rt := pipRT(t, runner, nil)

	got, err := (freezeFunc{}).Execute(context.Background(), rt, &FreezeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	lines := got.([]string)
	if !equalSlice(lines, []string{"pip==23.2.1", "requests==2.31.0"}) {
		t.Fatalf("freeze = %#v", lines)
	}

	runner.results[freezeKey] =
		process.CommandResult{ExitCode: 1, Stderr: []byte("boom")}
	probeFn := freezeFunc{}
	_, probeErr := probeFn.Execute(context.Background(), rt, &FreezeArgs{})
	if probeErr == nil || probeErr.Error() != "boom" {
		t.Fatalf("freeze failure = %v", probeErr)
	}
}

// Mirrors list_freeze_parse line handling including the -e/#egg and ===
// variants and the skipped unparseable line.
func TestListFreezeParse(t *testing.T) {
	verKey := pythonExecutable() + "\x00-m\x00pip\x00--version"
	freezeKey := strings.Join([]string{
		pythonExecutable(), "-m", "pip", "freeze",
		"--all", "--disable-pip-version-check",
	}, "\x00")
	runner := &fakeRunner{results: map[string]process.CommandResult{
		verKey: {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		freezeKey: {Stdout: []byte(strings.Join([]string{
			"pip==23.2.1",
			"-f /find/links/dir",
			"# comment",
			"-e git+https://github.com/x/y.git@v1#egg=edited_pkg",
			"weird===1.0.dev1",
			"requests==2.31.0",
			"unparseable-line",
		}, "\n"))},
	}}
	rt := pipRT(t, runner, nil)

	got, err := (listFreezeParseFunc{}).Execute(context.Background(), rt,
		&ListFreezeParseArgs{})
	if err != nil {
		t.Fatal(err)
	}
	pkgs := got.(map[string]string)
	if pkgs["pip"] != "23.2.1" || pkgs["edited_pkg"] !=
		"git+https://github.com/x/y.git@v1" ||
		pkgs["weird"] != "1.0.dev1" || pkgs["requests"] != "2.31.0" {
		t.Fatalf("packages = %#v", pkgs)
	}
	if _, hasUnparsed := pkgs["unparseable-line"]; hasUnparsed {
		t.Fatalf("unparseable line recorded")
	}
}

// Mirrors list_ on the JSON path with prefix normalization.
func TestListJSONPathWithPrefix(t *testing.T) {
	verKey := pythonExecutable() + "\x00-m\x00pip\x00--version"
	listKey := strings.Join([]string{
		pythonExecutable(), "-m", "pip",
		"list", "--format=json", "--disable-pip-version-check",
	}, "\x00")
	runner := &fakeRunner{results: map[string]process.CommandResult{
		verKey:  {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		listKey: {Stdout: []byte(`[{"name": "Requests", "version": "2.31.0"}, {"name": "flask", "version": "3.0"}]`)},
	}}
	rt := pipRT(t, runner, nil)

	got, err := (listFunc{}).Execute(context.Background(), rt,
		&ListArgs{Prefix: strPtr("REQUEST")})
	if err != nil {
		t.Fatal(err)
	}
	pkgs := got.(map[string]string)
	if len(pkgs) != 1 || pkgs["requests"] != "2.31.0" {
		t.Fatalf("prefix-filtered list = %#v", pkgs)
	}
}

// Mirrors list_upgrades JSON output.
func TestListUpgradesJSON(t *testing.T) {
	verKey := pythonExecutable() + "\x00-m\x00pip\x00--version"
	outdatedKey := strings.Join([]string{
		pythonExecutable(), "-m", "pip",
		"list", "--outdated", "--disable-pip-version-check", "--format=json",
	}, "\x00")
	runner := &fakeRunner{results: map[string]process.CommandResult{
		verKey:      {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		outdatedKey: {Stdout: []byte(`[{"name": "requests", "latest_version": "2.32.0", "latest_filetype": "wheel"}]`)},
	}}
	rt := pipRT(t, runner, nil)

	got, err := (listUpgradesFunc{}).Execute(context.Background(), rt, &ListUpgradesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	pkgs := got.(map[string]string)
	if pkgs["requests"] != "2.32.0 [wheel]" {
		t.Fatalf("upgrades = %#v", pkgs)
	}

	avail, err := (upgradeAvailableFunc{}).Execute(context.Background(), rt,
		&UpgradeAvailableArgs{Pkg: "requests"})
	if err != nil || avail != true {
		t.Fatalf("upgrade_available = %#v, %v", avail, err)
	}
}

// Mirrors upgrade(): per-outdated installs, changes diff, failure marking.
func TestUpgradeFlow(t *testing.T) {
	verKey := pythonExecutable() + "\x00-m\x00pip\x00--version"
	listKey := strings.Join([]string{
		pythonExecutable(), "-m", "pip",
		"list", "--format=json", "--disable-pip-version-check",
	}, "\x00")
	outdatedKey := strings.Join([]string{
		pythonExecutable(), "-m", "pip",
		"list", "--outdated", "--disable-pip-version-check", "--format=json",
	}, "\x00")

	runner := &fakeRunner{results: map[string]process.CommandResult{
		verKey:      {Stdout: []byte("pip 23.2.1 from x (python 3.12)\n")},
		listKey:     {Stdout: []byte(`[{"name": "requests", "version": "2.31.0"}, {"name": "old-pkg", "version": "1.0"}]`)},
		outdatedKey: {Stdout: []byte(`[{"name": "requests", "latest_version": "2.32.0", "latest_filetype": "wheel"}]`)},
	}}
	rt := pipRT(t, runner, nil)

	// The per-package install runs after listing; flip the list output so
	// the post-upgrade rescan reflects the new state.
	runner.hook = func(argv []string) {
		if len(argv) > 2 && argv[len(argv)-3] == "-U" {
			runner.results[listKey] =
				process.CommandResult{Stdout: []byte(`[{"name": "requests", "version": "2.32.0"}]`)}
		}
	}

	ret, err := (upgradeFunc{}).Execute(context.Background(), rt, &UpgradeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["result"] != true {
		t.Fatalf("result = %#v (%q)", dict["result"], dict["comment"])
	}
	changes := dict["changes"].(map[string]any)
	reqChange, ok := changes["requests"].(map[string]any)
	if !ok || reqChange["old"] != "2.31.0" || reqChange["new"] != "2.32.0" {
		t.Fatalf("changes = %#v", changes)
	}
	if _, removed := changes["old-pkg"]; !removed {
		t.Fatalf("removed package missing from changes: %#v", changes)
	}
}

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
