package pkg

// R8.1 mock tests for the FreeBSD pkgng virtual pkg surface, mapped onto
// saltstack/salt/modules/pkgng.py @ pinned revision 8b63e700637e and
// tests/pytests/unit/modules/test_pkgng.py: the latest_version search
// argv ladder (name/origin/out-of-date/unavailable/up-to-date), the
// lock/unlock/locked inversion table, the full pkg upgrade --dry-run
// parser fixture across all five sections, upgrade flag combinations,
// install option vectors including the batch env and pkg-add file
// flavor, remove origin handling, refresh_db, stats/check/autoremove/
// audit/which/fetch argv, hold/unhold state contracts, list_locked,
// version lookups, version_cmp, parse_config/update_package_site, error
// and cancellation boundaries, and binary-missing behavior. The runner
// is a recording fake; no real pkg binary runs and the tests are
// untagged so they execute on the Linux CI host.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// pkgngMockRunner scripts the pkg(8) tool surface. infoScript feeds
// sequential `pkg info -ao` views so before/after list diffs behave
// like the real package database (the pytest `pkgs` side_effect).
type pkgngMockRunner struct {
	infoScript    []string
	searchOut     string
	lockOut       string
	lockScript    []string
	lockRetcode   int
	upgradeOut    string
	versionCmpOut string
	fixOut        string
	fetchOut      string
	auditOut      string
	backupOut     string
	statsOut      string
	checkOut      string
	updateRet     int
	failSubstr    string
	failStderr    string
	forceMissing  bool
	calls         []process.Command
}

func (r *pkgngMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	result := func(stdout string) process.CommandResult {
		return process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)}
	}
	missing := process.CommandResult{
		Err:      errors.New("exec: \"pkg\": executable file not found in $PATH"),
		ExitCode: -1,
	}
	if r.forceMissing || command.Name != "pkg" {
		return missing
	}
	if r.failSubstr != "" && strings.Contains(joined, r.failSubstr) {
		return process.CommandResult{ExitCode: 1, Stderr: []byte(r.failStderr)}
	}
	switch {
	case strings.Contains(joined, " info -ao"):
		out := ""
		if len(r.infoScript) > 0 {
			out = r.infoScript[0]
			r.infoScript = r.infoScript[1:]
		}
		return result(out)
	case strings.Contains(joined, " search "):
		return result(r.searchOut)
	case strings.Contains(joined, " lock ") || strings.Contains(joined, " unlock "):
		out := r.lockOut
		if len(r.lockScript) > 0 {
			out = r.lockScript[0]
			r.lockScript = r.lockScript[1:]
		}
		return process.CommandResult{ExitCode: r.lockRetcode, Stdout: []byte(out)}
	case strings.Contains(joined, " upgrade --dry-run"):
		return result(r.upgradeOut)
	case strings.Contains(joined, " version --test-version"):
		return result(r.versionCmpOut)
	case strings.Contains(joined, " which "):
		return result(r.fixOut)
	case strings.Contains(joined, " fetch "):
		return result(r.fetchOut)
	case strings.Contains(joined, " audit "):
		return result(r.auditOut)
	case strings.Contains(joined, " backup -d"):
		return result(r.backupOut)
	case strings.Contains(joined, " stats"):
		return result(r.statsOut)
	case strings.Contains(joined, " check "):
		return result(r.checkOut)
	case strings.Contains(joined, " update"):
		return process.CommandResult{ExitCode: r.updateRet}
	}
	return result("")
}

func pkgngTestRuntime(runner *pkgngMockRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func pkgngArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

// pkgsFixture is the pytest `pkgs` side_effect: one installed package
// before the operation, three after.
var pkgngPkgsFixture = []string{
	"openvpn-2.4.8_2 security/openvpn\n",
	"openvpn-2.4.8_2 security/openvpn\ngettext-runtime-0.20.1 devel/gettext-runtime\np5-Mojolicious-8.40 www/p5-Mojolicious\n",
}

func TestPkgngLatestVersionArgvAndParse(t *testing.T) {
	rows := []struct {
		name     string
		info     string
		search   string
		target   string
		want     any
		wantArgv []string
	}{
		{
			name: "fresh package", info: "openvpn-2.4.8_2 security/openvpn\n", search: "bash-5.1.4",
			target: "bash", want: "5.1.4",
			wantArgv: []string{"pkg", "search", "-eqS", "name", "-U", "bash"},
		},
		{
			name: "origin search", info: "openvpn-2.4.8_2 security/openvpn\n", search: "bash-5.1.4_2",
			target: "shells/bash", want: "5.1.4_2",
			wantArgv: []string{"pkg", "search", "-eqS", "origin", "-U", "shells/bash"},
		},
		{
			name: "out of date", info: "openvpn-2.4.8_2 security/openvpn\n", search: "openvpn-2.4.8_3",
			target: "openvpn", want: "2.4.8_3",
			wantArgv: []string{"pkg", "search", "-eqS", "name", "-U", "openvpn"},
		},
		{
			name: "unavailable", info: "openvpn-2.4.8_2 security/openvpn\n", search: "",
			target: "does_not_exist", want: "",
			wantArgv: []string{"pkg", "search", "-eqS", "name", "-U", "does_not_exist"},
		},
		{
			name: "up to date", info: "openvpn-2.4.8_2 security/openvpn\n", search: "openvpn-2.4.8_2",
			target: "openvpn", want: "",
			wantArgv: []string{"pkg", "search", "-eqS", "name", "-U", "openvpn"},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &pkgngMockRunner{infoScript: []string{row.info}, searchOut: row.search}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngLatestVersionFunc{}.Execute(context.Background(), rt,
				&PkgngLatestVersionArgs{Names: []string{row.target}})
			if err != nil {
				t.Fatal(err)
			}
			if got != row.want {
				t.Fatalf("latest_version = %v, want %v", got, row.want)
			}
			if len(runner.calls) != 2 || !reflect.DeepEqual(pkgngArgv(runner.calls[1]), row.wantArgv) {
				t.Fatalf("argv = %#v, want %v", runner.calls, row.wantArgv)
			}
		})
	}
}

func TestPkgngLatestVersionRefreshSkipsRepoUpdateFlag(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: []string{"openvpn-2.4.8_2 security/openvpn\n"}, searchOut: "bash-5.1.4"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngLatestVersionFunc{}.Execute(context.Background(), rt,
		&PkgngLatestVersionArgs{Names: []string{"bash"}, Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "5.1.4" {
		t.Fatalf("latest_version = %v", got)
	}
	if want := []string{"pkg", "search", "-eqS", "name", "bash"}; !reflect.DeepEqual(pkgngArgv(runner.calls[1]), want) {
		t.Fatalf("argv = %v, want %v", pkgngArgv(runner.calls[1]), want)
	}
}

func TestPkgngLockUnlockLockedInversion(t *testing.T) {
	lockOut := "pkga-1.0\npkgb-2.0\n"

	runner := &pkgngMockRunner{lockOut: lockOut}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngLockFunc{}.Execute(context.Background(), rt, &PkgngLockArgs{Name: "pkga"})
	if err != nil || got != true {
		t.Fatalf("lock(pkga) = %v err=%v", got, err)
	}
	if want := []string{"pkg", "lock", "-y", "--quiet", "--show-locked", "pkga"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("lock argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{lockOut: lockOut}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngLockFunc{}.Execute(context.Background(), rt, &PkgngLockArgs{Name: "dummy"})
	if err != nil || got != false {
		t.Fatalf("lock(dummy) = %v err=%v", got, err)
	}

	// unlock inverts: a package still listed as locked was NOT unlocked.
	runner = &pkgngMockRunner{lockOut: lockOut}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnlockFunc{}.Execute(context.Background(), rt, &PkgngLockArgs{Name: "pkga"})
	if err != nil || got != false {
		t.Fatalf("unlock(pkga) = %v err=%v", got, err)
	}
	if want := []string{"pkg", "unlock", "-y", "--quiet", "--show-locked", "pkga"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("unlock argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{lockOut: lockOut}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnlockFunc{}.Execute(context.Background(), rt, &PkgngLockArgs{Name: "dummy"})
	if err != nil || got != true {
		t.Fatalf("unlock(dummy) = %v err=%v", got, err)
	}

	// locked lists without a package argument.
	runner = &pkgngMockRunner{lockOut: lockOut}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngLockedFunc{}.Execute(context.Background(), rt, &PkgngLockedArgs{Name: "pkga"})
	if err != nil || got != true {
		t.Fatalf("locked(pkga) = %v err=%v", got, err)
	}
	if want := []string{"pkg", "lock", "-y", "--quiet", "--show-locked"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("locked argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{lockOut: lockOut}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngLockedFunc{}.Execute(context.Background(), rt, &PkgngLockedArgs{Name: "dummy"})
	if err != nil || got != false {
		t.Fatalf("locked(dummy) = %v err=%v", got, err)
	}
}

const pkgngUpgradeDryRunFixture = `
The following 6 package(s) will be affected (of 0 checked):

Installed packages to be UPGRADED:
	pkga: 1.0 -> 1.1
	pkgb: 2.0 -> 2.1 [FreeBSD]
	pkgc: 3.0 -> 3.1 [FreeBSD] (dependency changed)
	pkgd: 4.0 -> 4.1 (dependency changed)

New packages to be INSTALLED:
	pkge: 1.0
	pkgf: 2.0 [FreeBSD]
	pkgg: 3.0 [FreeBSD] (dependency changed)
	pkgh: 4.0 (dependency changed)

Installed packages to be REINSTALLED:
	pkgi-1.0
	pkgj-2.0 [FreeBSD]
	pkgk-3.0 [FreeBSD] (direct dependency changed: pkga)
	pkgl-4.0 (direct dependency changed: pkgb)

Installed packages to be DOWNGRADED:
	pkgm: 1.1 -> 1.0
	pkgn: 2.1 -> 2.0 [FreeBSD]
	pkgo: 3.1 -> 3.0 [FreeBSD] (dependency changed)
	pkgp: 4.1 -> 4.0 (dependency changed)

Installed packages to be REMOVED:
	pkgq-1.0
	pkgr-2.0 [FreeBSD]
	pkgs-3.0 [FreeBSD] (direct dependency changed: pkga)
	pkgt-4.0 (direct dependency changed: pkgb)

Number of packages to be upgraded: 2
Number of packages to be reinstalled: 2

The process will require 14 MiB more space.
22 MiB to be downloaded.
`

// pkgngUpEntry builds a version-transition record (upgrade/downgrade).
func pkgngUpEntry(current, newVersion, repo, reason any) map[string]any {
	return map[string]any{
		"version": map[string]any{"current": current, "new": newVersion},
		"repo":    repo,
		"reason":  reason,
	}
}

// pkgngCurEntry builds a current-version-only record (install/reinstall/remove).
func pkgngCurEntry(current, repo, reason any) map[string]any {
	return map[string]any{
		"version": map[string]any{"current": current},
		"repo":    repo,
		"reason":  reason,
	}
}

func TestPkgngParseUpgradeFullFixture(t *testing.T) {
	parsed := pkgngParseUpgrade(pkgngUpgradeDryRunFixture)
	want := map[string]map[string]any{
		"upgrade": {
			"pkga": pkgngUpEntry("1.0", "1.1", nil, nil),
			"pkgb": pkgngUpEntry("2.0", "2.1", "FreeBSD", nil),
			"pkgc": pkgngUpEntry("3.0", "3.1", "FreeBSD", "dependency changed"),
			"pkgd": pkgngUpEntry("4.0", "4.1", nil, "dependency changed"),
		},
		"install": {
			"pkge": pkgngCurEntry("1.0", nil, nil),
			"pkgf": pkgngCurEntry("2.0", "FreeBSD", nil),
			"pkgg": pkgngCurEntry("3.0", "FreeBSD", "dependency changed"),
			"pkgh": pkgngCurEntry("4.0", nil, "dependency changed"),
		},
		"reinstall": {
			"pkgi": pkgngCurEntry("1.0", nil, nil),
			"pkgj": pkgngCurEntry("2.0", "FreeBSD", nil),
			"pkgk": pkgngCurEntry("3.0", "FreeBSD", "direct dependency changed: pkga"),
			"pkgl": pkgngCurEntry("4.0", nil, "direct dependency changed: pkgb"),
		},
		"downgrade": {
			"pkgm": pkgngUpEntry("1.1", "1.0", nil, nil),
			"pkgn": pkgngUpEntry("2.1", "2.0", "FreeBSD", nil),
			"pkgo": pkgngUpEntry("3.1", "3.0", "FreeBSD", "dependency changed"),
			"pkgp": pkgngUpEntry("4.1", "4.0", nil, "dependency changed"),
		},
		"remove": {
			"pkgq": pkgngCurEntry("1.0", nil, nil),
			"pkgr": pkgngCurEntry("2.0", "FreeBSD", nil),
			"pkgs": pkgngCurEntry("3.0", "FreeBSD", "direct dependency changed: pkga"),
			"pkgt": pkgngCurEntry("4.0", nil, "direct dependency changed: pkgb"),
		},
	}
	if !reflect.DeepEqual(parsed, want) {
		t.Fatalf("parse_upgrade mismatch:\n got %#v\nwant %#v", parsed, want)
	}
}

func TestPkgngListUpgrades(t *testing.T) {
	runner := &pkgngMockRunner{upgradeOut: pkgngUpgradeDryRunFixture}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngListUpgradesFunc{}.Execute(context.Background(), rt, &PkgngListUpgradesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"pkga": "1.1", "pkgb": "2.1", "pkgc": "3.1", "pkgd": "4.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_upgrades = %#v, want %#v", got, want)
	}
	// Refresh defaults to True: no --no-repo-update flag.
	wantArgv := []string{"pkg", "upgrade", "--dry-run", "--quiet"}
	if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %v", argv)
	}

	runner = &pkgngMockRunner{upgradeOut: pkgngUpgradeDryRunFixture}
	rt = pkgngTestRuntime(runner)
	refresh := false
	got, err = pkgngListUpgradesFunc{}.Execute(context.Background(), rt, &PkgngListUpgradesArgs{Refresh: &refresh})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_upgrades(refresh=false) = %#v", got)
	}
	wantArgv = []string{"pkg", "upgrade", "--dry-run", "--quiet", "--no-repo-update"}
	if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %v, want %v", argv, wantArgv)
	}

	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngListUpgradesFunc{}.Execute(context.Background(), rt, &PkgngListUpgradesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("absent upgrades = %#v", got)
	}
}

func pkgngUpgradeChangesFixture() map[string]any {
	return map[string]any{
		"gettext-runtime": map[string]any{"new": "0.20.1", "old": ""},
		"p5-Mojolicious":  map[string]any{"new": "8.40", "old": ""},
	}
}

func TestPkgngUpgradeFlagMatrix(t *testing.T) {
	rows := []struct {
		name     string
		args     PkgngUpgradeArgs
		wantArgv []string
	}{
		{name: "plain", wantArgv: []string{"pkg", "upgrade", "-y"}},
		{name: "fromrepo", args: PkgngUpgradeArgs{Fromrepo: "FreeBSD"}, wantArgv: []string{"pkg", "upgrade", "-y", "--repository", "FreeBSD"}},
		{name: "fetchonly", args: PkgngUpgradeArgs{Fetchonly: true}, wantArgv: []string{"pkg", "upgrade", "-Fy"}},
		{name: "local", args: PkgngUpgradeArgs{Local: true}, wantArgv: []string{"pkg", "upgrade", "-Uy"}},
	}
	want := pkgngUpgradeChangesFixture()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...)}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngUpgradeFunc{}.Execute(context.Background(), rt, &row.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("upgrade changes = %#v, want %#v", got, want)
			}
			upgradeCalls := 0
			for _, call := range runner.calls {
				if strings.Contains(strings.Join(call.Args, " "), "upgrade") && !strings.Contains(strings.Join(call.Args, " "), "--dry-run") {
					upgradeCalls++
					if argv := pkgngArgv(call); !reflect.DeepEqual(argv, row.wantArgv) {
						t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
					}
				}
			}
			if upgradeCalls != 1 {
				t.Fatalf("upgrade calls = %d", upgradeCalls)
			}
		})
	}
}

func TestPkgngUpgradeNonzeroRetcodeIsError(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...), failSubstr: "upgrade -y", failStderr: "pkg: cannot upgrade"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngUpgradeFunc{}.Execute(context.Background(), rt, &PkgngUpgradeArgs{})
	if got != nil || err == nil || !strings.Contains(err.Error(), "Problem encountered upgrading packages") {
		t.Fatalf("upgrade failure got=%#v err=%v", got, err)
	}
}

func TestPkgngInstallOptionMatrix(t *testing.T) {
	targets := []any{"gettext-runtime", "p5-Mojolicious"}
	rows := []struct {
		name     string
		args     PkgngInstallArgs
		wantArgv []string
		checkEnv func(*testing.T, process.Command)
	}{
		{name: "plain", wantArgv: []string{"pkg", "install", "-y", "gettext-runtime", "p5-Mojolicious"}},
		{name: "local", args: PkgngInstallArgs{Local: true}, wantArgv: []string{"pkg", "install", "-yU", "gettext-runtime", "p5-Mojolicious"}},
		{name: "fromrepo", args: PkgngInstallArgs{Fromrepo: "FreeBSD"}, wantArgv: []string{"pkg", "install", "-r", "FreeBSD", "-y", "gettext-runtime", "p5-Mojolicious"}},
		{name: "glob", args: PkgngInstallArgs{Glob: true}, wantArgv: []string{"pkg", "install", "-yg", "gettext-runtime", "p5-Mojolicious"}},
		{name: "reinstall_requires", args: PkgngInstallArgs{ReinstallRequires: true, Force: true}, wantArgv: []string{"pkg", "install", "-yfR", "gettext-runtime", "p5-Mojolicious"}},
		{name: "regex", args: PkgngInstallArgs{Regex: true}, wantArgv: []string{"pkg", "install", "-yx", "gettext-runtime", "p5-Mojolicious"}},
		{name: "pcre", args: PkgngInstallArgs{Pcre: true}, wantArgv: []string{"pkg", "install", "-yX", "gettext-runtime", "p5-Mojolicious"}},
		{name: "orphan", args: PkgngInstallArgs{Orphan: true}, wantArgv: []string{"pkg", "install", "-yA", "gettext-runtime", "p5-Mojolicious"}},
		{
			name: "batch", args: PkgngInstallArgs{Batch: true},
			wantArgv: []string{"pkg", "install", "-y", "gettext-runtime", "p5-Mojolicious"},
			checkEnv: func(t *testing.T, command process.Command) {
				env := strings.Join(command.Env, " ")
				if !strings.Contains(env, "BATCH=true") || !strings.Contains(env, "ASSUME_ALWAYS_YES=YES") {
					t.Fatalf("batch env = %v", command.Env)
				}
			},
		},
	}
	want := pkgngUpgradeChangesFixture()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			args := row.args
			args.Pkgs = targets
			runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...)}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngInstallFunc{}.Execute(context.Background(), rt, &args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("install changes = %#v, want %#v", got, want)
			}
			found := false
			for _, call := range runner.calls {
				argv := pkgngArgv(call)
				if strings.Contains(strings.Join(argv, " "), " install ") {
					found = true
					if !reflect.DeepEqual(argv, row.wantArgv) {
						t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
					}
					if row.checkEnv != nil {
						row.checkEnv(t, call)
					}
				}
			}
			if !found {
				t.Fatalf("no install call in %#v", runner.calls)
			}
		})
	}
}

func TestPkgngInstallVersionedNameAndNameOnly(t *testing.T) {
	// kwargs version applies only when a single name was passed.
	runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...)}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngInstallFunc{}.Execute(context.Background(), rt,
		&PkgngInstallArgs{Name: "gettext-runtime", Version: "0.20.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(map[string]any); !ok {
		t.Fatalf("install got=%#v", got)
	}
	wantArgv := []string{"pkg", "install", "-y", "gettext-runtime-0.20.0"}
	found := false
	for _, call := range runner.calls {
		if argv := pkgngArgv(call); reflect.DeepEqual(argv, wantArgv) {
			found = true
		}
	}
	if !found {
		t.Fatalf("argv %v missing in %#v", wantArgv, runner.calls)
	}

	// No targets at all returns the empty change dict without running pkg.
	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngInstallFunc{}.Execute(context.Background(), rt, &PkgngInstallArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
		t.Fatalf("empty install got=%#v calls=%d", got, len(runner.calls))
	}
}

func TestPkgngInstallFileSourcesFlavor(t *testing.T) {
	// Sources select `pkg add`; dry-run echoes the argv instead of running.
	runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...)}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngInstallFunc{}.Execute(context.Background(), rt,
		&PkgngInstallArgs{Sources: []any{"/tmp/mutt-2.0.6.txz"}, Force: true, Dryrun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "pkg add -f /tmp/mutt-2.0.6.txz" {
		t.Fatalf("pkg add dryrun echo = %q", got)
	}
	if len(runner.calls) != 1 { // only the before-list ran
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestPkgngInstallStderrFailureIsError(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: append([]string{}, pkgngPkgsFixture...), failSubstr: "install -y", failStderr: "pkg: No packages available"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngInstallFunc{}.Execute(context.Background(), rt,
		&PkgngInstallArgs{Pkgs: []any{"gettext-runtime"}})
	if got != nil || err == nil || !strings.Contains(err.Error(), "Problem encountered installing package(s)") {
		t.Fatalf("install failure got=%#v err=%v", got, err)
	}
}

func TestPkgngRemoveTargetsAndOriginQuirk(t *testing.T) {
	installed := "openvpn-2.4.8_2 security/openvpn\nbash-5.1.4 shells/bash\n"

	// Plain removal of an installed package deletes it.
	runner := &pkgngMockRunner{infoScript: []string{installed, "openvpn-2.4.8_2 security/openvpn\n"}}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngRemoveFunc{}.Execute(context.Background(), rt, &PkgngRemoveArgs{Name: "bash"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"bash": map[string]any{"new": "", "old": "5.1.4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remove changes = %#v, want %#v", got, want)
	}
	wantArgv := []string{"pkg", "delete", "-y", "bash"}
	if argv := pkgngArgv(runner.calls[1]); !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %v, want %v", argv, wantArgv)
	}

	// A target that is not installed returns {} without running pkg.
	runner = &pkgngMockRunner{infoScript: []string{installed}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngRemoveFunc{}.Execute(context.Background(), rt, &PkgngRemoveArgs{Name: "does_not_exist"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 1 {
		t.Fatalf("absent remove got=%#v calls=%d", got, len(runner.calls))
	}

	// Origin-named removal reproduces the pinned source's first-character
	// membership quirk: the resolved name is checked as its initial
	// character against the installed keys, so nothing is deleted.
	runner = &pkgngMockRunner{infoScript: []string{installed}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngRemoveFunc{}.Execute(context.Background(), rt, &PkgngRemoveArgs{Name: "shells/bash"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 1 {
		t.Fatalf("origin quirk got=%#v calls=%d", got, len(runner.calls))
	}

	// An origin with no installed match is the source's IndexError.
	runner = &pkgngMockRunner{infoScript: []string{installed}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngRemoveFunc{}.Execute(context.Background(), rt, &PkgngRemoveArgs{Name: "www/missing"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "no installed package with origin") {
		t.Fatalf("origin miss got=%#v err=%v", got, err)
	}
}

func TestPkgngRefreshDB(t *testing.T) {
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngRefreshDBFunc{}.Execute(context.Background(), rt, &PkgngRefreshDBArgs{})
	if err != nil || got != true {
		t.Fatalf("refresh_db = %v err=%v", got, err)
	}
	if want := []string{"pkg", "update"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngRefreshDBFunc{}.Execute(context.Background(), rt, &PkgngRefreshDBArgs{Force: true})
	if err != nil || got != true {
		t.Fatalf("refresh_db(force) = %v err=%v", got, err)
	}
	if want := []string{"pkg", "update", "-f"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{updateRet: 1}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngRefreshDBFunc{}.Execute(context.Background(), rt, &PkgngRefreshDBArgs{})
	if err != nil || got != false {
		t.Fatalf("refresh_db failure = %v err=%v", got, err)
	}
}

func TestPkgngStatsArgvAndEmptyOutput(t *testing.T) {
	rows := []struct {
		name     string
		args     PkgngStatsArgs
		wantArgv []string
	}{
		{name: "local", args: PkgngStatsArgs{Local: true}, wantArgv: []string{"pkg", "stats", "-l"}},
		{name: "remote", args: PkgngStatsArgs{Remote: true}, wantArgv: []string{"pkg", "stats", "-r"}},
		{name: "remote bytes", args: PkgngStatsArgs{Remote: true, Bytes: true}, wantArgv: []string{"pkg", "stats", "-rb"}},
		{name: "local bytes", args: PkgngStatsArgs{Local: true, Bytes: true}, wantArgv: []string{"pkg", "stats", "-lb"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &pkgngMockRunner{}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngStatsFunc{}.Execute(context.Background(), rt, &row.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, []string{}) {
				t.Fatalf("stats empty output = %#v", got)
			}
			if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, row.wantArgv) {
				t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
			}
		})
	}
	runner := &pkgngMockRunner{statsOut: "\tPackages in local repository:\t1\n\tDisk space required:\t2 MiB\n"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngStatsFunc{}.Execute(context.Background(), rt, &PkgngStatsArgs{Local: true})
	if err != nil {
		t.Fatal(err)
	}
	// The trailing newline yields a final empty element exactly like
	// iterating split() over the captured output in the pinned source.
	want := []string{"Packages in local repository:\t1", "Disk space required:\t2 MiB", ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stats parse = %#v, want %#v", got, want)
	}
}

func TestPkgngCheckArgvMatrix(t *testing.T) {
	rows := []struct {
		name     string
		args     PkgngCheckArgs
		wantArgv []string
	}{
		{name: "depends", args: PkgngCheckArgs{Depends: true}, wantArgv: []string{"pkg", "check", "-dy"}},
		{name: "checksum", args: PkgngCheckArgs{Checksum: true}, wantArgv: []string{"pkg", "check", "-s"}},
		{name: "recompute", args: PkgngCheckArgs{Recompute: true}, wantArgv: []string{"pkg", "check", "-r"}},
		{name: "checklibs", args: PkgngCheckArgs{Checklibs: true}, wantArgv: []string{"pkg", "check", "-B"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &pkgngMockRunner{checkOut: ""}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngCheckFunc{}.Execute(context.Background(), rt, &row.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != "" {
				t.Fatalf("check output = %#v", got)
			}
			if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, row.wantArgv) {
				t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
			}
		})
	}
	// No flag set returns the literal guidance string without running pkg.
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngCheckFunc{}.Execute(context.Background(), rt, &PkgngCheckArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "One of depends, recompute, checksum or checklibs must be set to True" || len(runner.calls) != 0 {
		t.Fatalf("check no-flag got=%#v calls=%d", got, len(runner.calls))
	}
}

func TestPkgngAutoremoveAndCleanAndAudit(t *testing.T) {
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngAutoremoveFunc{}.Execute(context.Background(), rt, &PkgngAutoremoveArgs{Dryrun: true})
	if err != nil || got != "" {
		t.Fatalf("autoremove dryrun = %v err=%v", got, err)
	}
	if want := []string{"pkg", "autoremove", "-n"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	if _, err := (pkgngAutoremoveFunc{}).Execute(context.Background(), rt, &PkgngAutoremoveArgs{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg", "autoremove", "-y"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}

	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	if _, err := (pkgngCleanFunc{}).Execute(context.Background(), rt, &PkgngCleanArgs{}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg", "clean", "-y"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("clean argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	if _, err := (pkgngCleanFunc{}).Execute(context.Background(), rt, &PkgngCleanArgs{CleanAll: true, Dryrun: true}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg", "clean", "-an"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("clean argv = %v", pkgngArgv(runner.calls[0]))
	}

	runner = &pkgngMockRunner{auditOut: "0 problem(s) in the installed packages found"}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngAuditFunc{}.Execute(context.Background(), rt, &PkgngAuditArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "0 problem(s) in the installed packages found" {
		t.Fatalf("audit = %v", got)
	}
	if want := []string{"pkg", "audit", "-F"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("audit argv = %v", pkgngArgv(runner.calls[0]))
	}
}

func TestPkgngFetchArgvMatrix(t *testing.T) {
	rows := []struct {
		name     string
		args     PkgngFetchArgs
		wantArgv []string
	}{
		{name: "default glob", wantArgv: []string{"pkg", "fetch", "-y", "-g", "mutt"}},
		{name: "depends", args: PkgngFetchArgs{Depends: true}, wantArgv: []string{"pkg", "fetch", "-y", "-gd", "mutt"}},
		{name: "regex", args: PkgngFetchArgs{Regex: true}, wantArgv: []string{"pkg", "fetch", "-y", "-gx", "mutt"}},
		{name: "fromrepo", args: PkgngFetchArgs{Fromrepo: "FreeBSD-poudriere"}, wantArgv: []string{"pkg", "fetch", "-y", "-r", "FreeBSD-poudriere", "-g", "mutt"}},
		{name: "local", args: PkgngFetchArgs{Local: true}, wantArgv: []string{"pkg", "fetch", "-y", "-gL", "mutt"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			args := row.args
			args.Name = "mutt"
			runner := &pkgngMockRunner{fetchOut: "mutt"}
			rt := pkgngTestRuntime(runner)
			got, err := pkgngFetchFunc{}.Execute(context.Background(), rt, &args)
			if err != nil {
				t.Fatal(err)
			}
			if got != "mutt" {
				t.Fatalf("fetch = %v", got)
			}
			if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, row.wantArgv) {
				t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
			}
		})
	}
	// glob=False (a pointer) drops the -g flag from the default.
	glob := false
	runner := &pkgngMockRunner{fetchOut: "mutt"}
	rt := pkgngTestRuntime(runner)
	if _, err := (pkgngFetchFunc{}).Execute(context.Background(), rt, &PkgngFetchArgs{Name: "mutt", Glob: &glob}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg", "fetch", "-y", "mutt"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v, want %v", pkgngArgv(runner.calls[0]), want)
	}
}

func TestPkgngWhichArgv(t *testing.T) {
	runner := &pkgngMockRunner{fixOut: "/usr/local/bin/mutt was installed by package mutt-2.0.6"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngWhichFunc{}.Execute(context.Background(), rt, &PkgngWhichArgs{Path: "/usr/local/bin/mutt"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.(string), "mutt-2.0.6") {
		t.Fatalf("which = %v", got)
	}
	if want := []string{"pkg", "which", "/usr/local/bin/mutt"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
	runner = &pkgngMockRunner{fixOut: "/usr/local/bin/mutt was installed by package mail/mutt"}
	rt = pkgngTestRuntime(runner)
	if _, err := (pkgngWhichFunc{}).Execute(context.Background(), rt, &PkgngWhichArgs{Path: "/usr/local/bin/mutt", Origin: true}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg", "which", "-o", "/usr/local/bin/mutt"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
}

func TestPkgngSearchFlagLadder(t *testing.T) {
	runner := &pkgngMockRunner{searchOut: "mutt-2.0.6"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngSearchFunc{}.Execute(context.Background(), rt,
		&PkgngSearchArgs{Name: "mutt", Exact: true, Comment: true, Desc: true, Full: true, Size: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != "mutt-2.0.6" {
		t.Fatalf("search = %v", got)
	}
	want := []string{"pkg", "search", "-ecDfs", "mutt"}
	if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
}

func TestPkgngUpdatingSingleFlagWord(t *testing.T) {
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	if _, err := (pkgngUpdatingFunc{}).Execute(context.Background(), rt,
		&PkgngUpdatingArgs{Name: "foo", Filedate: "20130101", Filename: "/tmp/UPDATING"}); err != nil {
		t.Fatal(err)
	}
	// "-d 20130101" and "-f /tmp/UPDATING" are single argv elements,
	// exactly as the pinned source builds them.
	want := []string{"pkg", "updating", "-d 20130101f /tmp/UPDATING", "foo"}
	if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
}

func TestPkgngVersionLookup(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: []string{"mutt-2.0.6 mail/mutt\n"}}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngVersionFunc{}.Execute(context.Background(), rt, &PkgngVersionArgs{Names: []string{"mutt"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.0.6" {
		t.Fatalf("version = %v", got)
	}
	// Missing packages report the empty string (single) / empty map
	// entries (multiple), like pkg_resource.version.
	runner = &pkgngMockRunner{infoScript: []string{"mutt-2.0.6 mail/mutt\n"}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngVersionFunc{}.Execute(context.Background(), rt, &PkgngVersionArgs{Names: []string{"missing"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("missing version = %v", got)
	}
	runner = &pkgngMockRunner{infoScript: []string{"mutt-2.0.6 mail/mutt\n"}}
	rt = pkgngTestRuntime(runner)
	gotMap, err := pkgngVersionFunc{}.Execute(context.Background(), rt, &PkgngVersionArgs{Names: []string{"mutt", "missing"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"mutt": "2.0.6", "missing": ""}
	if !reflect.DeepEqual(gotMap, want) {
		t.Fatalf("multi version = %#v, want %#v", gotMap, want)
	}
}

func TestPkgngVersionWithOrigin(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: []string{"mutt-2.0.6 mail/mutt\n"}}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngVersionFunc{}.Execute(context.Background(), rt,
		&PkgngVersionArgs{Names: []string{"mutt"}, WithOrigin: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"mutt": map[string]any{"origin": "mail/mutt", "version": "2.0.6"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("version with_origin = %#v", got)
	}
}

func TestPkgngListPkgsShapes(t *testing.T) {
	runner := &pkgngMockRunner{infoScript: []string{"gettext-runtime-0.20.1 devel/gettext-runtime\np5-Mojolicious-8.40 www/p5-Mojolicious\n"}}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngListPkgsFunc{}.Execute(context.Background(), rt, &PkgngListPkgsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"gettext-runtime": "0.20.1", "p5-Mojolicious": "8.40"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_pkgs = %#v", got)
	}

	runner = &pkgngMockRunner{infoScript: []string{"gettext-runtime-0.20.1 devel/gettext-runtime\n"}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngListPkgsFunc{}.Execute(context.Background(), rt, &PkgngListPkgsArgs{VersionsAsList: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"gettext-runtime": []string{"0.20.1"}}) {
		t.Fatalf("list_pkgs versions_as_list = %#v", got)
	}

	runner = &pkgngMockRunner{infoScript: []string{"gettext-runtime-0.20.1 devel/gettext-runtime\n"}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngListPkgsFunc{}.Execute(context.Background(), rt, &PkgngListPkgsArgs{WithOrigin: true})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"gettext-runtime": map[string]any{"origin": "devel/gettext-runtime", "version": "0.20.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_pkgs with_origin = %#v", got)
	}

	// removed/purge_desired short-circuit to the empty dict.
	runner = &pkgngMockRunner{}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngListPkgsFunc{}.Execute(context.Background(), rt, &PkgngListPkgsArgs{Removed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
		t.Fatalf("removed got=%#v calls=%d", got, len(runner.calls))
	}
}

func TestPkgngListLocked(t *testing.T) {
	runner := &pkgngMockRunner{
		lockOut:    "pkga-1.0\npkgb-2.0\n",
		infoScript: []string{"pkga-1.0 category/pkga\npkgb-2.0 category/pkgb\n"},
	}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngListLockedFunc{}.Execute(context.Background(), rt, &PkgngListLockedArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkga-1.0", "pkgb-2.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_locked = %#v", got)
	}
}

func TestPkgngHoldUnholdContracts(t *testing.T) {
	// Locked already: single listing call, settled comment, no mutation.
	runner := &pkgngMockRunner{lockOut: "pkga-1.0\npkgb-2.0\n"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngHoldFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "pkga"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"pkga": map[string]any{"name": "pkga", "changes": map[string]any{}, "result": true,
			"comment": "Package pkga is already set to be held."},
	}
	if !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("hold settled = %#v calls=%d", got, len(runner.calls))
	}

	// Fresh lock: listing then the lock call, changes new=hold.
	runner = &pkgngMockRunner{lockScript: []string{
		"pkga-1.0\npkgb-2.0\n",
		"pkga-1.0\npkgb-2.0\ndummy-1.0\n",
	}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngHoldFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "dummy"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"dummy": map[string]any{"name": "dummy",
			"changes": map[string]any{"new": "hold", "old": ""},
			"result":  true, "comment": "Package dummy is now being held."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hold fresh = %#v", got)
	}
	if want := []string{"pkg", "lock", "-y", "--quiet", "--show-locked", "dummy"}; !reflect.DeepEqual(pkgngArgv(runner.calls[1]), want) {
		t.Fatalf("hold argv = %v", pkgngArgv(runner.calls[1]))
	}

	// Test mode: no mutation call, result null.
	runner = &pkgngMockRunner{lockOut: ""}
	rt = pkgngTestRuntime(runner)
	rt.Options.Test = true
	got, err = pkgngHoldFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "dummy"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"dummy": map[string]any{"name": "dummy", "changes": map[string]any{}, "result": nil,
			"comment": "Package dummy is set to be held."},
	}
	if !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("hold test-mode = %#v calls=%d", got, len(runner.calls))
	}

	// Unhold of a locked package that stays listed failed to unlock.
	runner = &pkgngMockRunner{lockOut: "pkga-1.0\n"}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnholdFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "pkga"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"pkga": map[string]any{"name": "pkga", "changes": map[string]any{}, "result": false,
			"comment": "Package pkga was unable to be unheld."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unhold stuck = %#v", got)
	}

	// Successful unlock: the post-unlock listing no longer carries the
	// package, so changes new="" old="hold".
	runner = &pkgngMockRunner{lockScript: []string{"pkga-1.0\n", ""}}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnholdFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "pkga"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"pkga": map[string]any{"name": "pkga",
			"changes": map[string]any{"new": "", "old": "hold"},
			"result":  true, "comment": "Package pkga is no longer held."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unhold success = %#v", got)
	}
	if want := []string{"pkg", "unlock", "-y", "--quiet", "--show-locked", "pkga"}; !reflect.DeepEqual(pkgngArgv(runner.calls[1]), want) {
		t.Fatalf("unhold argv = %v", pkgngArgv(runner.calls[1]))
	}

	// Unhold of an unlocked package is settled without a mutation call.
	runner = &pkgngMockRunner{lockOut: ""}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnholdFunc{}.Execute(context.Background(), rt, &PkgngHoldArgs{Name: "dummy"})
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{
		"dummy": map[string]any{"name": "dummy", "changes": map[string]any{}, "result": true,
			"comment": "Package dummy is not being held."},
	}
	if !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("unhold settled = %#v calls=%d", got, len(runner.calls))
	}

	// pkgs list and mapping entries expand to one entry per target.
	runner = &pkgngMockRunner{lockOut: "pkga-1.0\n"}
	rt = pkgngTestRuntime(runner)
	got, err = pkgngUnholdFunc{}.Execute(context.Background(), rt,
		&PkgngHoldArgs{Pkgs: []any{"pkga", map[string]any{"dummy": "1.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.(map[string]any)) != 2 {
		t.Fatalf("unhold multi = %#v", got)
	}
}

func TestPkgngLockCmdFailureIsError(t *testing.T) {
	runner := &pkgngMockRunner{lockRetcode: 1}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngLockFunc{}.Execute(context.Background(), rt, &PkgngLockArgs{Name: "pkga"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "Problem encountered locking packages") {
		t.Fatalf("lock failure got=%#v err=%v", got, err)
	}
}

func TestPkgngVersionCmp(t *testing.T) {
	rows := []struct {
		stdout string
		want   any
	}{
		{"<", -1},
		{">", 1},
		{"=", 0},
		{"garbage", nil},
		{"", nil},
	}
	for _, row := range rows {
		runner := &pkgngMockRunner{versionCmpOut: row.stdout}
		rt := pkgngTestRuntime(runner)
		got, err := pkgngVersionCmpFunc{}.Execute(context.Background(), rt,
			&PkgngVersionCmpArgs{Pkg1: "2.1.11", Pkg2: "2.1.12"})
		if err != nil {
			t.Fatal(err)
		}
		if got != row.want {
			t.Fatalf("version_cmp(%q) = %v, want %v", row.stdout, got, row.want)
		}
		if want := []string{"pkg", "version", "--test-version", "2.1.11", "2.1.12"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
			t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
		}
	}
}

func TestPkgngVersionCompareOrdering(t *testing.T) {
	rows := []struct {
		a, b string
		want int
	}{
		{"2.4.8_2", "2.4.8_3", -1},
		{"2.4.8_2", "2.4.8_2", 0},
		{"2.4.8", "2.4.8_2", -1},
		{"2.4.8_3", "2.4.8_2", 1},
		{"1.0", "1.0.1", -1},
	}
	for _, row := range rows {
		if got := pkgngVersionCompare(row.a, row.b); got != row.want {
			t.Fatalf("compare(%q,%q) = %d, want %d", row.a, row.b, got, row.want)
		}
	}
}

func TestPkgngParseConfig(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/usr/local/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	content := "# comment line\nPACKAGESITE\t : http://old.example/\n\n"
	if err := fs.WriteFile("/usr/local/etc/pkg.conf", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: &pkgngMockRunner{}, FS: fs}
	got, err := pkgngParseConfigFunc{}.Execute(context.Background(), rt, &PkgngParseConfigArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"PACKAGESITE": " : http://old.example/",
		"config_file": "/usr/local/etc/pkg.conf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parse_config = %#v, want %#v", got, want)
	}

	// Missing file returns the literal status string.
	got, err = pkgngParseConfigFunc{}.Execute(context.Background(), rt, &PkgngParseConfigArgs{FileName: "/missing/pkg.conf"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Unable to find /missing/pkg.conf on file system" {
		t.Fatalf("missing file = %#v", got)
	}

	// A non-comment line without a tab reproduces the ValueError crash
	// as an error.
	if err := fs.WriteFile("/usr/local/etc/pkg.conf", []byte("not-a-pair\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := (pkgngParseConfigFunc{}).Execute(context.Background(), rt, &PkgngParseConfigArgs{}); got != nil || err == nil {
		t.Fatalf("malformed got=%#v err=%v", got, err)
	}
}

func TestPkgngUpdatePackageSiteMutatesOnlyConfig(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/usr/local/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/usr/local/etc/pkg.conf", []byte("PACKAGESITE\t : http://old.example/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/usr/local/etc/other", []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{Runner: &pkgngMockRunner{}, FS: fs}
	got, err := pkgngUpdatePackageSiteFunc{}.Execute(context.Background(), rt,
		&PkgngUpdatePackageSiteArgs{NewURL: "http://127.0.0.1/"})
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("update_package_site = %v", got)
	}
	data, _ := fs.ReadFile("/usr/local/etc/pkg.conf")
	if string(data) != "PACKAGESITE\t : http://127.0.0.1/\n" {
		t.Fatalf("pkg.conf = %q", string(data))
	}
	other, _ := fs.ReadFile("/usr/local/etc/other")
	if string(other) != "keep\n" {
		t.Fatalf("unrelated file mutated: %q", string(other))
	}

	// A missing pkg.conf is the pinned source's KeyError path.
	empty := runtime.NewMemoryFS()
	rt = &runtime.Runtime{Runner: &pkgngMockRunner{}, FS: empty}
	if got, err := (pkgngUpdatePackageSiteFunc{}).Execute(context.Background(), rt,
		&PkgngUpdatePackageSiteArgs{NewURL: "http://x/"}); got != nil || err == nil {
		t.Fatalf("missing conf got=%#v err=%v", got, err)
	}
}

func TestPkgngBackupMarkerSplit(t *testing.T) {
	runner := &pkgngMockRunner{backupOut: "Dumping to /tmp/pkg...\nsuccess"}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngBackupFunc{}.Execute(context.Background(), rt, &PkgngBackupArgs{FileName: "/tmp/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "\nsuccess" {
		t.Fatalf("backup = %q", got)
	}
	runner = &pkgngMockRunner{backupOut: "no marker"}
	rt = pkgngTestRuntime(runner)
	if got, err := (pkgngBackupFunc{}).Execute(context.Background(), rt, &PkgngBackupArgs{FileName: "/tmp/pkg"}); got != nil || err == nil {
		t.Fatalf("backup markerless got=%#v err=%v", got, err)
	}
}

func TestPkgngRestore(t *testing.T) {
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	got, err := pkgngRestoreFunc{}.Execute(context.Background(), rt, &PkgngRestoreArgs{FileName: "/tmp/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("restore = %v", got)
	}
	if want := []string{"pkg", "backup", "-r", "/tmp/pkg"}; !reflect.DeepEqual(pkgngArgv(runner.calls[0]), want) {
		t.Fatalf("argv = %v", pkgngArgv(runner.calls[0]))
	}
}

func TestPkgngCancellationAndBinaryMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &pkgngMockRunner{}
	rt := pkgngTestRuntime(runner)
	if got, err := (pkgngAuditFunc{}).Execute(ctx, rt, &PkgngAuditArgs{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	// A missing pkg binary surfaces the Runner error, never a fabricated
	// result; the which-guard mirrors Salt's __virtual__ dependency on
	// the pkg binary existing.
	missing := &pkgngMockRunner{forceMissing: true}
	rt = &runtime.Runtime{Runner: missing, FS: runtime.NewMemoryFS()}
	if got, err := (pkgngAuditFunc{}).Execute(context.Background(), rt, &PkgngAuditArgs{}); got != nil || err == nil || len(missing.calls) != 1 {
		t.Fatalf("binary-missing got=%#v err=%v", got, err)
	}
}

func TestPkgngJailChrootRootScope(t *testing.T) {
	rows := []struct {
		name     string
		args     PkgngAuditArgs
		wantArgv []string
	}{
		{name: "jail", args: PkgngAuditArgs{Jail: "web"}, wantArgv: []string{"pkg", "-j", "web", "audit", "-F"}},
		{name: "chroot", args: PkgngAuditArgs{Chroot: "/chroot"}, wantArgv: []string{"pkg", "-c", "/chroot", "audit", "-F"}},
		{name: "root", args: PkgngAuditArgs{Root: "/root"}, wantArgv: []string{"pkg", "-r", "/root", "audit", "-F"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &pkgngMockRunner{}
			rt := pkgngTestRuntime(runner)
			if _, err := (pkgngAuditFunc{}).Execute(context.Background(), rt, &row.args); err != nil {
				t.Fatal(err)
			}
			if argv := pkgngArgv(runner.calls[0]); !reflect.DeepEqual(argv, row.wantArgv) {
				t.Fatalf("argv = %v, want %v", argv, row.wantArgv)
			}
		})
	}
}
