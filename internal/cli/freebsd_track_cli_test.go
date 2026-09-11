package cli

// R8.1 CLI smoke for the FreeBSD track: the freebsd-only additions to
// the virtual pkg/user/group families (pkg.audit, user.chloginclass,
// group.members, ...) are PlatformConstrained to freebsd, so on a Linux
// host the CLI resolves them as unsupported (exit 3) exactly like the
// registry boundary, while the canonical shared names keep resolving.
// The positive freebsd execution path is covered by the module-level
// provider tests; a native FreeBSD runner is the remaining gate.

import (
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execgroup "github.com/friz-zy/statekit/modules/exec/group"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func freebsdTrackCLIApp(t *testing.T, runner *cliRecordingRunner) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:      runtime.NewExecRegistry(),
			Providers: runtime.NewProviderRegistry(),
			Runner:    runner,
			Facts:     facts.ForTesting(facts.Overrides{Package: "apt", OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
			FS:        runtime.NewMemoryFS(),
		}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			return nil, err
		}
		if err := execpkg.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execuser.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execgroup.Register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

func TestFreeBSDTrackCLIGOOSGating(t *testing.T) {
	if runtime.CurrentGOOS() == "freebsd" {
		t.Skip("freebsd host runs the freebsd surface")
	}
	runner := &cliRecordingRunner{}
	app := freebsdTrackCLIApp(t, runner)

	// FreeBSD-only names across all three families surface as
	// unsupported on this host, with no Runner activity. Names the Linux
	// surface also registers (pkg.autoremove, pkg.search, pkg.which,
	// pkg.version_cmp, pkg.list_upgrades, ...) are deliberately absent
	// from this list: they are shared virtual names.
	freebsdOnly := []string{
		"pkg.audit", "pkg.backup", "pkg.check", "pkg.clean", "pkg.fetch",
		"pkg.lock", "pkg.unlock", "pkg.locked", "pkg.list_locked",
		"pkg.stats", "pkg.restore", "pkg.parse_config", "pkg.update_package_site",
		"pkg.updating",
		"user.chloginclass", "user.get_loginclass", "user.chroomnumber",
		"user.chworkphone", "user.chhomephone",
		"group.members", "group.adduser", "group.deluser", "group.getent",
	}
	for _, name := range freebsdOnly {
		code, _, errS := captureCode(t, app, "exec", name)
		if code != ExitUnsupported {
			t.Fatalf("freebsd-only %s code=%d err=%q, want ExitUnsupported", name, code, errS)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("gated calls spawned processes: %#v", runner.calls)
	}

	// Shared virtual names stay resolvable on the Linux surface: the
	// lookup reaches argument resolution (a missing required argument
	// fails with invalid input, exit 2) rather than unsupported.
	code, _, errS := captureCode(t, app, "exec", "user.info")
	if code != ExitInvalidInput || !strings.Contains(errS, "missing required argument") {
		t.Fatalf("user.info code=%d err=%q, want ExitInvalidInput with required-argument failure", code, errS)
	}
	code, _, _ = captureCode(t, app, "exec", "group.chgid")
	if code != ExitInvalidInput {
		t.Fatalf("group.chgid code=%d, want ExitInvalidInput", code)
	}
	// pkg.autoremove resolves through the apt provider on Linux.
	code, _, _ = captureCode(t, app, "exec", "pkg.autoremove")
	if code == ExitUnsupported {
		t.Fatalf("pkg.autoremove unexpectedly unsupported on linux")
	}
}
