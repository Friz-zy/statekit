//go:build darwin

package pkg

// R6.11 mock tests for the Darwin pkg virtual module covering both
// mac_brew_pkg and mac_portspkg, mapped onto
// saltstack/salt/modules/mac_brew_pkg.py and mac_portspkg.py @ pinned
// revision 8b63e700637e and their pytests: brew/port argv for every
// operation, the pinned brew info --json=v2 fixtures (casks with custom
// taps, aliases, revisions), list_upgrades outdated JSON, hold/unhold
// comment/changes contracts, the trust surface, install/remove change
// diffs and the registry matrix. All Runner output is scripted; this
// file compiles and runs only on Darwin (verified off-platform via
// GOOS=darwin go test -c).

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const (
	mockBrewBin = "/opt/homebrew/bin/brew"

	// Pytest custom_call_brew fixture (test_mac_brew_pkg.py): two casks
	// (custom tap + homebrew/cask) and two formulae (plain + alias).
	mockInstalledJSON = `{"casks":[` +
		`{"full_token":"autofirma","token":"autofirma","tap":"cdalvaro/tap","installed":"1.8.2"},` +
		`{"full_token":"discord","token":"discord","tap":"homebrew/cask","installed":"0.0.293"}` +
		`],"formulae":[` +
		`{"name":"jq","full_name":"jq","aliases":[],"installed":[{"version":"1.7.1"}]},` +
		`{"name":"neovim","full_name":"neovim","aliases":["nvim"],"installed":[{"version":"0.10.0"}]}` +
		`]}`

	// Pytest test_list_pkgs_cask_null_installed_version fixture.
	mockNullInstalledJSON = `{"casks":[` +
		`{"full_token":"discord","token":"discord","tap":"homebrew/cask","installed":null}` +
		`],"formulae":[]}`

	// Pytest test_list_pkgs_cask_null_full_token fixture.
	mockNullFullTokenJSON = `{"casks":[` +
		`{"full_token":null,"token":"discord","tap":"homebrew/cask","installed":"0.0.293"}` +
		`],"formulae":[]}`

	// Pytest test_latest_version_multiple_names fixture: formula
	// revision suffix + cask version token.
	mockInfoJSON = `{"formulae":[` +
		`{"name":"salt","full_name":"cdalvaro/tap/salt","aliases":[],"versions":{"stable":"3007.1","bottle":true},"revision":2},` +
		`{"name":"neovim","full_name":"neovim","aliases":["nvim"],"versions":{"stable":"0.10.0","bottle":true},"revision":0}` +
		`],"casks":[` +
		`{"token":"visual-studio-code","full_token":"visual-studio-code","tap":"homebrew/cask","version":"1.89.1","installed":"1.86.0"}` +
		`]}`

	// Pytest test_latest_version_with_options fixture (cask only).
	mockInfoCaskJSON = `{"formulae":[],"casks":[` +
		`{"token":"salt","full_token":"cdalvaro/tap/salt","tap":"cdalvaro/tap","version":"3007.1","installed":"3007.1"}` +
		`]}`

	// Pytest test_list_upgrades fixture.
	mockOutdatedJSON = `{"formulae":[` +
		`{"name":"cmake","current_version":"3.19.4"},` +
		`{"name":"fzf","current_version":"0.25.1"}` +
		`],"casks":[` +
		`{"name":"ksdiff","current_version":"2.3.6,123-jan-18-2021"}` +
		`]}`

	// Pytest test_info_installed fixture.
	mockInfoInstalledJSON = `{"formulae":[` +
		`{"name":"salt","full_name":"cdalvaro/tap/salt","aliases":[]},` +
		`{"name":"vim","full_name":"vim","aliases":[]}` +
		`],"casks":[` +
		`{"token":"visual-studio-code","full_token":"visual-studio-code","tap":null}` +
		`]}`

	mockFooInstalledJSON = `{"casks":[],"formulae":[` +
		`{"name":"foo","full_name":"foo","aliases":[],"installed":[{"version":"0.1.5"}]}` +
		`]}`

	mockEmptyInstalledJSON = `{"casks":[],"formulae":[]}`

	mockWgetInstalledJSON = `{"casks":[],"formulae":[` +
		`{"name":"wget","full_name":"wget","aliases":[],"installed":[{"version":"1.0"}]}` +
		`]}`

	mockWgetUpgradedJSON = `{"casks":[],"formulae":[` +
		`{"name":"wget","full_name":"wget","aliases":[],"installed":[{"version":"2.0"}]}` +
		`]}`
)

// brewPortMockRunner scripts the brew/port toolchain. The after*
// pointers swap the installed-set view so before/after list diffs
// behave like the real package databases (nil = no mutation).
type brewPortMockRunner struct {
	installed          string
	afterInstall       *string
	afterUninstall     *string
	afterUpgrade       *string
	info               string
	outdated           string
	pinned             string
	taps               string
	trust              string
	brewPrefixOut      string
	portInstalled      string
	portAfterInstall   *string
	portAfterUninstall *string
	portList           string
	failSubstr         string // argv substring forced to retcode 1
	failStderr         string
	calls              []process.Command
}

func (r *brewPortMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if r.failSubstr != "" && strings.Contains(joined, r.failSubstr) {
		return process.CommandResult{ExitCode: 1, Stderr: []byte(r.failStderr)}
	}
	if command.Name == "brew" && len(command.Args) == 1 && command.Args[0] == "--prefix" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.brewPrefixOut)}
	}
	if command.Name == mockBrewBin && len(command.Args) > 0 {
		switch command.Args[0] {
		case "update":
			return process.CommandResult{ExitCode: 0}
		case "info":
			if strings.Contains(joined, "--installed") {
				return process.CommandResult{ExitCode: 0, Stdout: []byte(r.installed)}
			}
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.info)}
		case "outdated":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.outdated)}
		case "list":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.pinned)}
		case "tap":
			if len(command.Args) == 2 {
				if r.taps != "" {
					r.taps += "\n"
				}
				r.taps += command.Args[1]
				return process.CommandResult{ExitCode: 0}
			}
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.taps)}
		case "install":
			if r.afterInstall != nil {
				r.installed = *r.afterInstall
			}
			return process.CommandResult{ExitCode: 0}
		case "uninstall":
			if r.afterUninstall != nil {
				r.installed = *r.afterUninstall
			}
			return process.CommandResult{ExitCode: 0}
		case "upgrade":
			if r.afterUpgrade != nil {
				r.installed = *r.afterUpgrade
			}
			return process.CommandResult{ExitCode: 0}
		case "trust", "untrust":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.trust)}
		}
	}
	if command.Name == "port" && len(command.Args) > 0 {
		switch command.Args[0] {
		case "selfupdate":
			return process.CommandResult{ExitCode: 0}
		case "installed":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.portInstalled)}
		case "list":
			return process.CommandResult{ExitCode: 0, Stdout: []byte(r.portList)}
		case "install":
			if r.portAfterInstall != nil {
				r.portInstalled = *r.portAfterInstall
			}
			return process.CommandResult{ExitCode: 0}
		case "uninstall":
			if r.portAfterUninstall != nil {
				r.portInstalled = *r.portAfterUninstall
			}
			return process.CommandResult{ExitCode: 0}
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func brewPortRT(t *testing.T, manager string) (*runtime.Runtime, *brewPortMockRunner) {
	t.Helper()
	t.Setenv("HOMEBREW_PREFIX", "/opt/homebrew")
	runner := &brewPortMockRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: manager}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	return rt, runner
}

func brewPortArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func brewPortArgvs(runner *brewPortMockRunner) []string {
	out := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		out = append(out, brewPortArgv(call))
	}
	return out
}

func strPtrMac(value string) *string { return &value }

func TestMacPkgHomebrewPrefix(t *testing.T) {
	// HOMEBREW_PREFIX env wins without touching the runner (pytest
	// test_homebrew_prefix_env).
	rt, runner := brewPortRT(t, "brew")
	res, err := macHomebrewPrefixFunc{}.Execute(context.Background(), rt, macHomebrewPrefixArgs{})
	if err != nil || res != "/opt/homebrew" {
		t.Fatalf("env prefix = %v %v", res, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("env prefix must not run brew, got %+v", runner.calls)
	}
	if got := brewPath(rt); got != mockBrewBin {
		t.Fatalf("brew path = %q", got)
	}

	// Without the env var the prefix comes from `brew --prefix` (pytest
	// test_homebrew_prefix_command); _homebrew_bin appends /bin/brew.
	t.Setenv("HOMEBREW_PREFIX", "")
	runner2 := &brewPortMockRunner{brewPrefixOut: "/usr/local"}
	rt2 := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: "brew"}),
		Runner: runner2, FS: runtime.NewMemoryFS(),
	}
	if got := homebrewPrefix(rt2); got != "/usr/local" {
		t.Fatalf("command prefix = %q", got)
	}
	if got := brewPath(rt2); got != "/usr/local/bin/brew" {
		t.Fatalf("command brew path = %q", got)
	}
	if got := brewPortArgv(runner2.calls[0]); got != "brew --prefix" {
		t.Fatalf("prefix argv = %q", got)
	}

	// pytest test_homebrew_prefix_returns_none*: a failing or empty
	// brew --prefix collapses to the bare "brew" name.
	runner3 := &brewPortMockRunner{failSubstr: "brew --prefix"}
	rt3 := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: "brew"}),
		Runner: runner3, FS: runtime.NewMemoryFS(),
	}
	if got := homebrewPrefix(rt3); got != "" {
		t.Fatalf("failed prefix = %q", got)
	}
	if got := brewPath(rt3); got != "brew" {
		t.Fatalf("fallback brew path = %q", got)
	}

	// homebrew_prefix is brew-only: MacPorts reports nil.
	rtPort, _ := brewPortRT(t, "port")
	res, err = macHomebrewPrefixFunc{}.Execute(context.Background(), rtPort, macHomebrewPrefixArgs{})
	if err != nil || res != nil {
		t.Fatalf("port homebrew_prefix = %v %v", res, err)
	}
}

func TestMacPkgListPkgsBrew(t *testing.T) {
	// pytest test_list_pkgs_homebrew_cask_pakages: token, full_token,
	// tap/token and alias keys all map to the installed versions.
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockInstalledJSON
	res, err := macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{VersionsAsList: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"autofirma":              "1.8.2",
		"cdalvaro/tap/autofirma": "1.8.2",
		"discord":                "0.0.293",
		"homebrew/cask/discord":  "0.0.293",
		"jq":                     []string{"1.7.1"},
		"neovim":                 []string{"0.10.0"},
		"nvim":                   []string{"0.10.0"},
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("brew list = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" info --json=v2 --installed" {
		t.Fatalf("argv = %q", got)
	}
	if runner.calls[0].Shell {
		t.Fatal("brew list must stay shell-free")
	}

	// versions_as_list=false stringifies formula versions like Salt's
	// pkg_resource.stringify.
	res, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	listed := res.(map[string]any)
	if listed["jq"] != "1.7.1" || listed["neovim"] != "0.10.0" {
		t.Fatalf("stringified = %#v", listed)
	}

	// pytest test_list_pkgs_cask_null_installed_version: a null
	// installed cask reports the empty string, not a nil version.
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockNullInstalledJSON
	res, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{VersionsAsList: true})
	if err != nil {
		t.Fatal(err)
	}
	wantNull := map[string]any{"discord": "", "homebrew/cask/discord": ""}
	if !reflect.DeepEqual(res, wantNull) {
		t.Fatalf("null installed = %#v", res)
	}

	// pytest test_list_pkgs_cask_null_full_token: a null full_token
	// never becomes an empty-string key.
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockNullFullTokenJSON
	res, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{VersionsAsList: true})
	if err != nil {
		t.Fatal(err)
	}
	listed = res.(map[string]any)
	if _, exists := listed[""]; exists {
		t.Fatalf("empty key leaked: %#v", listed)
	}
	if listed["discord"] != "0.0.293" || listed["homebrew/cask/discord"] != "0.0.293" {
		t.Fatalf("null full_token = %#v", listed)
	}

	// pytest test_list_pkgs_removed: removed/purge_desired return {}.
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockInstalledJSON
	res, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{
		Kwargs: map[string]any{"removed": true},
	})
	if err != nil || !reflect.DeepEqual(res, map[string]any{}) {
		t.Fatalf("removed kwargs = %#v %v", res, err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("removed kwargs must not run brew, got %+v", runner.calls)
	}

	// Salt _call_brew failhard: a failing brew info surfaces as the
	// "Brew command failed" error.
	rt, runner = brewPortRT(t, "brew")
	runner.failSubstr = "info --json=v2 --installed"
	_, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{})
	if err == nil || !strings.Contains(err.Error(), "Brew command failed") {
		t.Fatalf("failhard = %v", err)
	}
}

func TestMacPkgListPkgsPort(t *testing.T) {
	// mac_portspkg list_pkgs: `port installed`, LIST_ACTIVE_ONLY and
	// the @ version prefix strip.
	rt, runner := brewPortRT(t, "port")
	runner.portInstalled = "The following ports are currently installed:\n" +
		"  curl @8.4.0_0 (active)\n" +
		"  zsh @5.9_0\n" +
		"  wget @1.21.4_0 (inactive)\n"
	res, err := macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"curl": "8.4.0_0"}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("port list = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != "port installed" {
		t.Fatalf("argv = %q", got)
	}
	// versions_as_list wraps the version in a single-element list.
	res, err = macListPkgsFunc{}.Execute(context.Background(), rt, &macListPkgsArgs{VersionsAsList: true})
	if err != nil || !reflect.DeepEqual(res, map[string]any{"curl": []string{"8.4.0_0"}}) {
		t.Fatalf("port list as list = %#v %v", res, err)
	}
}

func TestMacPkgVersion(t *testing.T) {
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockInstalledJSON
	// single name -> bare string; unknown -> empty string.
	res, err := macVersionFunc{}.Execute(context.Background(), rt, &macVersionArgs{Names: []string{"jq"}})
	if err != nil || res != "1.7.1" {
		t.Fatalf("version single = %v %v", res, err)
	}
	res, err = macVersionFunc{}.Execute(context.Background(), rt, &macVersionArgs{Names: []string{"missing"}})
	if err != nil || res != "" {
		t.Fatalf("version missing = %v %v", res, err)
	}
	// multiple names -> name/version dict.
	res, err = macVersionFunc{}.Execute(context.Background(), rt, &macVersionArgs{Names: []string{"jq", "nvim"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"jq": "1.7.1", "nvim": "0.10.0"}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("version multi = %#v", res)
	}
}

func TestMacPkgLatestVersionBrew(t *testing.T) {
	// pytest test_latest_version_multiple_names: revision >= 1 appends
	// _N to the stable version; casks use the version token.
	rt, runner := brewPortRT(t, "brew")
	runner.info = mockInfoJSON
	res, err := macLatestVersionFunc{}.Execute(context.Background(), rt, &macLatestVersionArgs{
		Names: []string{"cdalvaro/tap/salt", "nvim", "visual-studio-code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"cdalvaro/tap/salt":  "3007.1_2",
		"nvim":               "0.10.0",
		"visual-studio-code": "1.89.1",
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("latest multi = %#v", res)
	}
	// refresh defaults to true: brew update runs before info.
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" update" {
		t.Fatalf("refresh argv = %q", got)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" info --json=v2 cdalvaro/tap/salt nvim visual-studio-code" {
		t.Fatalf("info argv = %q", got)
	}

	// pytest test_latest_version: single name returns the bare string.
	res, err = macLatestVersionFunc{}.Execute(context.Background(), rt, &macLatestVersionArgs{Names: []string{"neovim"}})
	if err != nil || res != "0.10.0" {
		t.Fatalf("latest single = %v %v", res, err)
	}

	// pytest test_latest_version_with_options: options sit between the
	// json flag and the names; refresh=false skips brew update.
	rt, runner = brewPortRT(t, "brew")
	runner.info = mockInfoCaskJSON
	noRefresh := false
	res, err = macLatestVersionFunc{}.Execute(context.Background(), rt, &macLatestVersionArgs{
		Names: []string{"cdalvaro/tap/salt"}, Options: []string{"--cask"}, Refresh: &noRefresh,
	})
	if err != nil || res != "3007.1" {
		t.Fatalf("latest options = %v %v", res, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("refresh=false calls = %+v", brewPortArgvs(runner))
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" info --json=v2 --cask cdalvaro/tap/salt" {
		t.Fatalf("options argv = %q", got)
	}

	// available_version is the deprecated alias of latest_version.
	res, err = macAvailableVersionFunc{}.Execute(context.Background(), rt, &macLatestVersionArgs{
		Names: []string{"cdalvaro/tap/salt"}, Refresh: &noRefresh,
	})
	if err != nil || res != "3007.1" {
		t.Fatalf("available_version alias = %v %v", res, err)
	}
}

func TestMacPkgLatestVersionPort(t *testing.T) {
	// mac_portspkg latest_version: port selfupdate then port list.
	rt, runner := brewPortRT(t, "port")
	runner.portList = "curl @8.4.0_0 net\nzsh @5.9_0 shells\n"
	res, err := macLatestVersionFunc{}.Execute(context.Background(), rt, &macLatestVersionArgs{
		Names: []string{"curl", "zsh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"curl": "8.4.0_0", "zsh": "5.9_0"}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("port latest = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != "port selfupdate" {
		t.Fatalf("selfupdate argv = %q", got)
	}
	if got := brewPortArgv(runner.calls[1]); got != "port list curl zsh" {
		t.Fatalf("port list argv = %q", got)
	}
}

func TestMacPkgRemoveBrew(t *testing.T) {
	// pytest test_remove: removing an uninstalled package is a no-op.
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockInstalledJSON
	res, err := macRemoveFunc{}.Execute(context.Background(), rt, &macRemoveArgs{Name: strPtrMac("foo")})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, map[string]any{}) {
		t.Fatalf("remove noop = %#v", res)
	}
	for _, call := range runner.calls {
		if strings.Contains(brewPortArgv(call), "uninstall") {
			t.Fatalf("noop remove ran uninstall: %+v", runner.calls)
		}
	}

	// pytest test_remove_with_options: options precede the targets and
	// the change dict reports old -> "".
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockFooInstalledJSON
	empty := mockEmptyInstalledJSON
	runner.afterUninstall = &empty
	name := "foo"
	res, err = macRemoveFunc{}.Execute(context.Background(), rt, &macRemoveArgs{
		Name: &name, Options: []string{"--cask"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantChange := map[string]any{
		"foo": map[string]any{"old": "0.1.5", "new": ""},
	}
	if !reflect.DeepEqual(res, wantChange) {
		t.Fatalf("remove changes = %#v", res)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" uninstall --cask foo" {
		t.Fatalf("uninstall argv = %q", got)
	}

	// a failing uninstall with stderr raises Salt's error text.
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockFooInstalledJSON
	runner.failSubstr = "uninstall"
	runner.failStderr = "brew: no such keg"
	_, err = macRemoveFunc{}.Execute(context.Background(), rt, &macRemoveArgs{Name: &name})
	if err == nil || !strings.Contains(err.Error(), "Problem encountered removing package(s): brew: no such keg") {
		t.Fatalf("remove failure = %v", err)
	}
}

func TestMacPkgRemovePort(t *testing.T) {
	// mac_portspkg remove: `port uninstall <targets>` with an
	// old -> "" change diff.
	rt, runner := brewPortRT(t, "port")
	runner.portInstalled = "  curl @8.4.0_0 (active)\n"
	empty := ""
	runner.portAfterUninstall = &empty
	res, err := macRemoveFunc{}.Execute(context.Background(), rt, &macRemoveArgs{Name: strPtrMac("curl")})
	if err != nil {
		t.Fatal(err)
	}
	wantChange := map[string]any{
		"curl": map[string]any{"old": "8.4.0_0", "new": ""},
	}
	if !reflect.DeepEqual(res, wantChange) {
		t.Fatalf("port remove changes = %#v", res)
	}
	if got := brewPortArgv(runner.calls[1]); got != "port uninstall curl" {
		t.Fatalf("port uninstall argv = %q", got)
	}
}

func TestMacPkgRefreshDB(t *testing.T) {
	rt, runner := brewPortRT(t, "brew")
	res, err := macRefreshDBFunc{}.Execute(context.Background(), rt, macRefreshDBArgs{})
	if err != nil || res != true {
		t.Fatalf("refresh_db = %v %v", res, err)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" update" {
		t.Fatalf("refresh argv = %q", got)
	}
	// a failing update reports False (Salt raises via failhard; the
	// port maps the failure onto the documented False return).
	rt, runner = brewPortRT(t, "brew")
	runner.failSubstr = "update"
	res, err = macRefreshDBFunc{}.Execute(context.Background(), rt, macRefreshDBArgs{})
	if err != nil || res != false {
		t.Fatalf("failed refresh_db = %v %v", res, err)
	}
	// MacPorts refreshes through `port selfupdate`.
	rt, runner = brewPortRT(t, "port")
	if _, err := (macRefreshDBFunc{}).Execute(context.Background(), rt, macRefreshDBArgs{}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[0]); got != "port selfupdate" {
		t.Fatalf("selfupdate argv = %q", got)
	}
}

func TestMacPkgInstallBrew(t *testing.T) {
	// no targets -> {} without any brew call (pytest test_install).
	rt, runner := brewPortRT(t, "brew")
	res, err := macInstallFunc{}.Execute(context.Background(), rt, &macInstallArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, map[string]any{}) {
		t.Fatalf("empty install = %#v", res)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("empty install calls = %+v", runner.calls)
	}

	// Salt install flow: list before, tap missing repos, install, list
	// after; the change dict reports "" -> version.
	rt, runner = brewPortRT(t, "brew")
	runner.taps = "homebrew/core"
	fooInstalled := mockFooInstalledJSON
	runner.afterInstall = &fooInstalled
	name := "foo"
	res, err = macInstallFunc{}.Execute(context.Background(), rt, &macInstallArgs{
		Name: &name, Taps: []string{"homebrew/dupes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantChange := map[string]any{
		"foo": map[string]any{"old": "", "new": "0.1.5"},
	}
	if !reflect.DeepEqual(res, wantChange) {
		t.Fatalf("install changes = %#v", res)
	}
	wantArgv := []string{
		mockBrewBin + " info --json=v2 --installed",
		mockBrewBin + " tap",
		mockBrewBin + " tap homebrew/dupes",
		mockBrewBin + " install foo",
		mockBrewBin + " info --json=v2 --installed",
	}
	if !reflect.DeepEqual(brewPortArgvs(runner), wantArgv) {
		t.Fatalf("install argvs = %#v", brewPortArgvs(runner))
	}

	// an already-present tap is not re-tapped.
	rt, runner = brewPortRT(t, "brew")
	runner.taps = "homebrew/core\nhomebrew/dupes"
	runner.afterInstall = &fooInstalled
	if _, err := (macInstallFunc{}).Execute(context.Background(), rt, &macInstallArgs{
		Name: &name, Taps: []string{"homebrew/dupes"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, argv := range brewPortArgvs(runner) {
		if argv == mockBrewBin+" tap homebrew/dupes" {
			t.Fatal("present tap was re-tapped")
		}
	}

	// options trail the targets (Salt: cmd.extend(targets) then
	// cmd.extend(options)).
	rt, runner = brewPortRT(t, "brew")
	runner.afterInstall = &fooInstalled
	if _, err := (macInstallFunc{}).Execute(context.Background(), rt, &macInstallArgs{
		Name: &name, Options: []string{"--cask"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" install foo --cask" {
		t.Fatalf("options argv = %q", got)
	}

	// a failing install with stderr raises Salt's error text.
	rt, runner = brewPortRT(t, "brew")
	runner.failSubstr = "install"
	runner.failStderr = "brew: no formula"
	_, err = macInstallFunc{}.Execute(context.Background(), rt, &macInstallArgs{Name: &name})
	if err == nil || !strings.Contains(err.Error(), "Problem encountered installing package(s): brew: no formula") {
		t.Fatalf("install failure = %v", err)
	}
}

func TestMacPkgInstallPort(t *testing.T) {
	// mac_portspkg install: version and variant extend the single-name
	// target. Salt appends "@"+version as a separate argv element while
	// the port glues name@version into one token; this pins the port
	// form.
	rt, runner := brewPortRT(t, "port")
	active := "  git-core @1.8.5.5_0 (active)\n"
	runner.portAfterInstall = &active
	name := "git-core"
	version := "1.8.5.5"
	variant := "+credential_osxkeychain+doc+pcre"
	res, err := macInstallFunc{}.Execute(context.Background(), rt, &macInstallArgs{
		Name: &name, Version: &version, Variant: &variant,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantChange := map[string]any{
		"git-core": map[string]any{"old": "", "new": "1.8.5.5_0"},
	}
	if !reflect.DeepEqual(res, wantChange) {
		t.Fatalf("port install changes = %#v", res)
	}
	wantArgv := []string{
		"port installed",
		"port install git-core@1.8.5.5 +credential_osxkeychain+doc+pcre",
		"port installed",
	}
	if !reflect.DeepEqual(brewPortArgvs(runner), wantArgv) {
		t.Fatalf("port install argvs = %#v", brewPortArgvs(runner))
	}

	// a pkgs list bypasses the version/variant kwargs entirely.
	rt, runner = brewPortRT(t, "port")
	activeBoth := "  foo @1.0_0 (active)\n  bar @2.0_0 (active)\n"
	runner.portAfterInstall = &activeBoth
	res, err = macInstallFunc{}.Execute(context.Background(), rt, &macInstallArgs{
		Pkgs: []string{"foo", "bar"}, Version: &version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := res.(map[string]any); !ok || len(got) != 2 {
		t.Fatalf("port pkgs install = %#v", res)
	}
	if got := brewPortArgv(runner.calls[1]); got != "port install foo bar" {
		t.Fatalf("pkgs argv = %q", got)
	}
}

func TestMacPkgListUpgradesBrew(t *testing.T) {
	// pytest test_list_upgrades: formulae only by default, casks with
	// include_casks.
	rt, runner := brewPortRT(t, "brew")
	runner.outdated = mockOutdatedJSON
	noRefresh := false
	res, err := macListUpgradesFunc{}.Execute(context.Background(), rt, &macListUpgradesArgs{
		Refresh: &noRefresh,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"cmake": "3.19.4", "fzf": "0.25.1"}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("upgrades = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" outdated --json=v2" {
		t.Fatalf("outdated argv = %q", got)
	}
	res, err = macListUpgradesFunc{}.Execute(context.Background(), rt, &macListUpgradesArgs{
		Refresh: &noRefresh, IncludeCasks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want["ksdiff"] = "2.3.6,123-jan-18-2021"
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("upgrades with casks = %#v", res)
	}

	// pytest test_list_upgrades_with_options: options trail --json=v2.
	rt, runner = brewPortRT(t, "brew")
	runner.outdated = mockOutdatedJSON
	if _, err := (macListUpgradesFunc{}).Execute(context.Background(), rt, &macListUpgradesArgs{
		Refresh: &noRefresh, IncludeCasks: true, Options: []string{"--greedy", "--fetch-HEAD"},
	}); err != nil {
		t.Fatal(err)
	}
	wantArgv := mockBrewBin + " outdated --json=v2 --greedy --fetch-HEAD"
	if got := brewPortArgv(runner.calls[0]); got != wantArgv {
		t.Fatalf("options argv = %q; want %q", got, wantArgv)
	}

	// unparseable outdated output raises Salt's error text.
	rt, runner = brewPortRT(t, "brew")
	runner.outdated = "not json"
	if _, err := (macListUpgradesFunc{}).Execute(context.Background(), rt, &macListUpgradesArgs{
		Refresh: &noRefresh,
	}); err == nil || !strings.Contains(err.Error(), `unable to interpret output from "brew outdated"`) {
		t.Fatalf("bad outdated = %v", err)
	}

	// refresh defaults to true (brew update first).
	rt, runner = brewPortRT(t, "brew")
	runner.outdated = mockOutdatedJSON
	if _, err := (macListUpgradesFunc{}).Execute(context.Background(), rt, &macListUpgradesArgs{}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" update" {
		t.Fatalf("default refresh argv = %q", got)
	}

	// upgrade_available is a membership check over list_upgrades.
	rt, runner = brewPortRT(t, "brew")
	runner.outdated = mockOutdatedJSON
	res, err = macUpgradeAvailableFunc{}.Execute(context.Background(), rt, &macUpgradeAvailableArgs{
		Pkg: "cmake", Refresh: &noRefresh,
	})
	if err != nil || res != true {
		t.Fatalf("upgrade_available hit = %v %v", res, err)
	}
	res, err = macUpgradeAvailableFunc{}.Execute(context.Background(), rt, &macUpgradeAvailableArgs{
		Pkg: "absent", Refresh: &noRefresh,
	})
	if err != nil || res != false {
		t.Fatalf("upgrade_available miss = %v %v", res, err)
	}
}

func TestMacPkgListUpgradesPort(t *testing.T) {
	// mac_portspkg list_upgrades: `port list outdated`.
	rt, runner := brewPortRT(t, "port")
	runner.portList = "curl @8.4.0_0 net\n"
	noRefresh := false
	res, err := macListUpgradesFunc{}.Execute(context.Background(), rt, &macListUpgradesArgs{Refresh: &noRefresh})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"curl": "8.4.0_0"}; !reflect.DeepEqual(res, want) {
		t.Fatalf("port upgrades = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != "port list outdated" {
		t.Fatalf("outdated argv = %q", got)
	}
}

func TestMacPkgUpgradeBrew(t *testing.T) {
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockWgetInstalledJSON
	upgraded := mockWgetUpgradedJSON
	runner.afterUpgrade = &upgraded
	noRefresh := false
	res, err := macUpgradeFunc{}.Execute(context.Background(), rt, &macUpgradeArgs{Refresh: &noRefresh})
	if err != nil {
		t.Fatal(err)
	}
	wantChange := map[string]any{
		"wget": map[string]any{"old": "1.0", "new": "2.0"},
	}
	if !reflect.DeepEqual(res, wantChange) {
		t.Fatalf("upgrade changes = %#v", res)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" upgrade" {
		t.Fatalf("upgrade argv = %q", got)
	}

	// a failing upgrade raises Salt's error text.
	rt, runner = brewPortRT(t, "brew")
	runner.installed = mockWgetInstalledJSON
	runner.failSubstr = "upgrade"
	_, err = macUpgradeFunc{}.Execute(context.Background(), rt, &macUpgradeArgs{Refresh: &noRefresh})
	if err == nil || err.Error() != "Problem encountered upgrading packages" {
		t.Fatalf("upgrade failure = %v", err)
	}

	// MacPorts upgrades via `port upgrade outdated`.
	rt, runner = brewPortRT(t, "port")
	runner.portInstalled = "  curl @8.4.0_0 (active)\n"
	if _, err := (macUpgradeFunc{}).Execute(context.Background(), rt, &macUpgradeArgs{Refresh: &noRefresh}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[1]); got != "port upgrade outdated" {
		t.Fatalf("port upgrade argv = %q", got)
	}
}

func TestMacPkgInfoInstalled(t *testing.T) {
	// pytest test_info_installed: requested names map onto their info
	// objects keyed by name/full_name/token/full_token.
	rt, runner := brewPortRT(t, "brew")
	runner.info = mockInfoInstalledJSON
	res, err := macInfoInstalledFunc{}.Execute(context.Background(), rt, &macInfoInstalledArgs{
		Names: []string{"cdalvaro/tap/salt", "vim", "visual-studio-code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if len(info) != 4 { // name/full_name for formulae, token/full_token for the cask
		t.Fatalf("info_installed keys = %#v", info)
	}
	salt := info["cdalvaro/tap/salt"].(map[string]any)
	if salt["name"] != "salt" || salt["tap"] != "cdalvaro/tap" {
		t.Fatalf("salt info = %#v", salt)
	}
	vscode := info["visual-studio-code"].(map[string]any)
	if vscode["full_token"] != "visual-studio-code" {
		t.Fatalf("cask info = %#v", vscode)
	}
	// pytest test_info_installed_extra_options: options precede names.
	rt, runner = brewPortRT(t, "brew")
	runner.info = mockEmptyInstalledJSON
	if _, err := (macInfoInstalledFunc{}).Execute(context.Background(), rt, &macInfoInstalledArgs{
		Names: []string{"salt"}, Options: []string{"--cask"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" info --json=v2 --cask salt" {
		t.Fatalf("info options argv = %q", got)
	}
	// info_installed is Homebrew-only.
	rt, _ = brewPortRT(t, "port")
	res, err = macInfoInstalledFunc{}.Execute(context.Background(), rt, &macInfoInstalledArgs{Names: []string{"curl"}})
	if err != nil || !reflect.DeepEqual(res, map[string]any{}) {
		t.Fatalf("port info_installed = %#v %v", res, err)
	}
}

func TestMacPkgHoldUnholdMatrix(t *testing.T) {
	// Salt hold/unhold state-comment contracts from the pytest matrix
	// (test_hold, test_hold_not_installed, test_hold_pinned,
	// test_unhold, test_unhold_not_installed, test_unhold_not_pinned).
	scenes := []struct {
		name        string
		pinned      string // brew list --pinned stdout
		hold        bool   // hold (pin) or unhold (unpin)
		test        bool   // test mode
		failPin     bool
		installed   string
		wantComment string
		wantChanges map[string]any
		wantResult  any
		wantVerb    string // expected brew pin/unpin verb, "" for none
	}{
		{
			name: "hold installed", pinned: "", hold: true, installed: mockFooInstalledJSON,
			wantComment: "Package foo is now being held.",
			wantChanges: map[string]any{"old": "install", "new": "hold"}, wantResult: true, wantVerb: "pin",
		},
		{
			name: "hold not installed", pinned: "", hold: true, installed: mockEmptyInstalledJSON,
			wantComment: "Package foo does not have a state.", wantResult: false,
		},
		{
			name: "hold already pinned", pinned: "foo\n", hold: true, installed: mockFooInstalledJSON,
			wantComment: "Package foo is already set to be held.", wantResult: true,
		},
		{
			name: "hold test mode", pinned: "", hold: true, test: true, installed: mockFooInstalledJSON,
			wantComment: "Package foo is set to be held.", wantResult: nil,
		},
		{
			name: "hold pin failure", pinned: "", hold: true, failPin: true, installed: mockFooInstalledJSON,
			wantComment: "Unable to hold package foo.", wantResult: false, wantVerb: "pin",
		},
		{
			name: "unhold pinned", pinned: "foo\n", hold: false, installed: mockFooInstalledJSON,
			wantComment: "Package foo is no longer being held.",
			wantChanges: map[string]any{"old": "hold", "new": "install"}, wantResult: true, wantVerb: "unpin",
		},
		{
			name: "unhold not pinned", pinned: "", hold: false, installed: mockFooInstalledJSON,
			wantComment: "Package foo is already set not to be held.", wantResult: true,
		},
		{
			name: "unhold test mode", pinned: "foo\n", hold: false, test: true, installed: mockFooInstalledJSON,
			wantComment: "Package foo is set to be unheld.", wantResult: nil,
		},
		{
			name: "unhold not installed", pinned: "foo\n", hold: false, installed: mockEmptyInstalledJSON,
			wantComment: "Package foo does not have a state.", wantResult: false,
		},
	}
	for _, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			rt, runner := brewPortRT(t, "brew")
			runner.installed = sc.installed
			runner.pinned = sc.pinned
			if sc.failPin {
				runner.failSubstr = "pin foo"
			}
			var fn runtime.ExecFunction = macHoldFunc{}
			if !sc.hold {
				fn = macUnholdFunc{}
			}
			name := "foo"
			res, err := fn.Execute(context.Background(), rt, &macHoldArgs{Name: &name, Test: sc.test})
			if err != nil {
				t.Fatal(err)
			}
			entry := res.(map[string]any)["foo"].(map[string]any)
			if entry["comment"] != sc.wantComment {
				t.Fatalf("comment = %q; want %q", entry["comment"], sc.wantComment)
			}
			if sc.wantResult == nil && entry["result"] != nil {
				t.Fatalf("result = %#v; want nil", entry["result"])
			}
			if sc.wantResult != nil && entry["result"] != sc.wantResult {
				t.Fatalf("result = %#v; want %#v", entry["result"], sc.wantResult)
			}
			changes, _ := entry["changes"].(map[string]any)
			if sc.wantChanges != nil {
				if !reflect.DeepEqual(changes, sc.wantChanges) {
					t.Fatalf("changes = %#v; want %#v", changes, sc.wantChanges)
				}
			} else if len(changes) != 0 {
				t.Fatalf("unexpected changes = %#v", changes)
			}
			var verbs []string
			for _, call := range runner.calls {
				if len(call.Args) >= 2 && (call.Args[0] == "pin" || call.Args[0] == "unpin") {
					verbs = append(verbs, call.Args[0])
				}
			}
			if sc.wantVerb == "" {
				if len(verbs) != 0 {
					t.Fatalf("unexpected pin/unpin call: %+v", brewPortArgvs(runner))
				}
			} else if len(verbs) != 1 || verbs[0] != sc.wantVerb {
				t.Fatalf("pin/unpin verbs = %#v; want [%s]", verbs, sc.wantVerb)
			}
		})
	}

	// the pinned listing itself rides on `brew list --pinned`.
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockFooInstalledJSON
	runner.pinned = "foo\n"
	name := "foo"
	if _, err := (macHoldFunc{}).Execute(context.Background(), rt, &macHoldArgs{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" list --pinned" {
		t.Fatalf("pinned argv = %q", got)
	}

	// pin/unpin alias hold/unhold.
	rt, _ = brewPortRT(t, "brew")
	rt.Runner.(*brewPortMockRunner).installed = mockFooInstalledJSON
	if _, err := (macPinFunc{}).Execute(context.Background(), rt, &macHoldArgs{Name: &name}); err != nil {
		t.Fatal(err)
	}
	rt, _ = brewPortRT(t, "brew")
	rt.Runner.(*brewPortMockRunner).installed = mockFooInstalledJSON
	rt.Runner.(*brewPortMockRunner).pinned = "foo\n"
	if _, err := (macUnpinFunc{}).Execute(context.Background(), rt, &macHoldArgs{Name: &name}); err != nil {
		t.Fatal(err)
	}

	// Salt guards: no targets -> invocation error; sources names are
	// used as targets.
	rt, _ = brewPortRT(t, "brew")
	_, err := macHoldFunc{}.Execute(context.Background(), rt, &macHoldArgs{})
	if err == nil || err.Error() != "One of name, pkgs, or sources must be specified." {
		t.Fatalf("no targets = %v", err)
	}
	rt, _ = brewPortRT(t, "brew")
	rt.Runner.(*brewPortMockRunner).installed = mockFooInstalledJSON
	res, err := macHoldFunc{}.Execute(context.Background(), rt, &macHoldArgs{
		Sources: []any{map[string]any{"foo": "1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.(map[string]any)["foo"]; !ok {
		t.Fatalf("sources targets = %#v", res)
	}

	// hold is Homebrew-only (MacPorts has no pin concept).
	rt, _ = brewPortRT(t, "port")
	_, err = macHoldFunc{}.Execute(context.Background(), rt, &macHoldArgs{Name: &name})
	if err == nil || err.Error() != "pkg.hold is only supported by Homebrew" {
		t.Fatalf("port hold = %v", err)
	}
	rt, _ = brewPortRT(t, "port")
	_, err = macUnholdFunc{}.Execute(context.Background(), rt, &macHoldArgs{Name: &name})
	if err == nil || err.Error() != "pkg.unhold is only supported by Homebrew" {
		t.Fatalf("port unhold = %v", err)
	}
}

func TestMacPkgTrustSurface(t *testing.T) {
	// pytest test_list_trusted: grouped dict payload, plain argv.
	rt, runner := brewPortRT(t, "brew")
	runner.trust = `{"taps":["thirdparty/foo"],"formulae":["thirdparty/foo/bar"],"casks":[],"commands":[]}`
	res, err := macListTrustedFunc{}.Execute(context.Background(), rt, &macListTrustedArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"taps":     []any{"thirdparty/foo"},
		"formulae": []any{"thirdparty/foo/bar"},
		"casks":    []any{},
		"commands": []any{},
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("list_trusted = %#v", res)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" trust --json=v1" {
		t.Fatalf("trust argv = %q", got)
	}

	// pytest test_list_trusted_by_type: the --<type> flag is appended.
	kind := "tap"
	runner.trust = `["thirdparty/foo"]`
	res, err = macListTrustedFunc{}.Execute(context.Background(), rt, &macListTrustedArgs{Type: &kind})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, []any{"thirdparty/foo"}) {
		t.Fatalf("typed trust = %#v", res)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" trust --json=v1 --tap" {
		t.Fatalf("typed argv = %q", got)
	}

	// pytest test_list_trusted_invalid_type: exact invocation error.
	bad := "invalid"
	_, err = macListTrustedFunc{}.Execute(context.Background(), rt, &macListTrustedArgs{Type: &bad})
	if err == nil || err.Error() != "Invalid type 'invalid'. Valid values: tap, formula, cask, command" {
		t.Fatalf("invalid type = %v", err)
	}

	// pytest test_is_trusted_found/_not_found: list and grouped shapes.
	rt, _ = brewPortRT(t, "brew")
	rt.Runner.(*brewPortMockRunner).trust = `{"taps":["thirdparty/foo"],"formulae":[],"casks":[],"commands":[]}`
	res, err = macIsTrustedFunc{}.Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo"})
	if err != nil || res != true {
		t.Fatalf("is_trusted grouped hit = %v %v", res, err)
	}
	res, err = macIsTrustedFunc{}.Execute(context.Background(), rt, &macTrustArgs{Name: "other/tap"})
	if err != nil || res != false {
		t.Fatalf("is_trusted grouped miss = %v %v", res, err)
	}
	rt, _ = brewPortRT(t, "brew")
	rt.Runner.(*brewPortMockRunner).trust = `["thirdparty/foo"]`
	res, err = macIsTrustedFunc{}.Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo", Type: &kind})
	if err != nil || res != true {
		t.Fatalf("is_trusted list hit = %v %v", res, err)
	}

	// pytest test_trust/_with_type/_untrust: argv forms.
	rt, runner = brewPortRT(t, "brew")
	if _, err := (macTrustFunc{}).Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo"}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[0]); got != mockBrewBin+" trust thirdparty/foo" {
		t.Fatalf("trust argv = %q", got)
	}
	if _, err := (macTrustFunc{}).Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo", Type: &kind}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[1]); got != mockBrewBin+" trust --tap thirdparty/foo" {
		t.Fatalf("typed trust argv = %q", got)
	}
	if _, err := (macUntrustFunc{}).Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo/bar", Type: strPtrMac("formula")}); err != nil {
		t.Fatal(err)
	}
	if got := brewPortArgv(runner.calls[2]); got != mockBrewBin+" untrust --formula thirdparty/foo/bar" {
		t.Fatalf("untrust argv = %q", got)
	}

	// pytest test_trust_failure: a failing brew call reports False.
	rt, runner = brewPortRT(t, "brew")
	runner.failSubstr = "trust thirdparty"
	res, err = macTrustFunc{}.Execute(context.Background(), rt, &macTrustArgs{Name: "thirdparty/foo"})
	if err != nil || res != false {
		t.Fatalf("trust failure = %v %v", res, err)
	}

	// the trust surface is Homebrew-only.
	rt, _ = brewPortRT(t, "port")
	_, err = macListTrustedFunc{}.Execute(context.Background(), rt, &macListTrustedArgs{})
	if err == nil || err.Error() != "pkg.list_trusted is only supported by Homebrew" {
		t.Fatalf("port list_trusted = %v", err)
	}
	rt, _ = brewPortRT(t, "port")
	_, err = macTrustFunc{}.Execute(context.Background(), rt, &macTrustArgs{Name: "x"})
	if err == nil || err.Error() != "pkg trust operations are only supported by Homebrew" {
		t.Fatalf("port trust = %v", err)
	}
}

func TestMacPkgRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkg.available_version",
		"pkg.homebrew_prefix",
		"pkg.hold",
		"pkg.info_installed",
		"pkg.install",
		"pkg.is_trusted",
		"pkg.latest_version",
		"pkg.list_pkgs",
		"pkg.list_trusted",
		"pkg.list_upgrades",
		"pkg.pin",
		"pkg.refresh_db",
		"pkg.remove",
		"pkg.trust",
		"pkg.unhold",
		"pkg.unpin",
		"pkg.untrust",
		"pkg.upgrade",
		"pkg.upgrade_available",
		"pkg.version",
	}
	// This file is darwin-only, so Register installs the mac surface.
	if !reflect.DeepEqual(reg.Names(), want) {
		t.Fatalf("darwin names = %v", reg.Names())
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, runner := brewPortRT(t, "brew")
	runner.installed = mockInstalledJSON
	rt.Exec = reg
	res, err := rt.Exec.Call(context.Background(), rt, "pkg.version", &macVersionArgs{Names: []string{"jq"}})
	if err != nil || res != "1.7.1" {
		t.Fatalf("dispatch = %v %v", res, err)
	}
}
