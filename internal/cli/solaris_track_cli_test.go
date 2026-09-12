package cli

// R8.2 CLI smoke for the Solaris track: the solaris-only shadow
// additions (shadow.default_hash, shadow.gen_password,
// shadow.del_password, shadow.set_password, shadow.set_maxdays,
// shadow.set_mindays, shadow.set_warndays) surface as unsupported
// (exit 3) on a Linux host with no Runner activity, while the shared
// virtual names (shadow.info, system.init, user.info, group.chgid)
// keep resolving through the Linux surface. The positive solaris
// execution path is covered by the module-level provider tests; a
// official Go compile targets include solaris/amd64 and illumos/amd64, but no
// native Solaris runner is attached, so the untagged mock tests are the
// remaining runtime-contract gate.

import (
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execgroup "github.com/friz-zy/statekit/modules/exec/group"
	execshadow "github.com/friz-zy/statekit/modules/exec/shadow"
	execsystem "github.com/friz-zy/statekit/modules/exec/system"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

func solarisTrackCLIApp(t *testing.T, runner *cliRecordingRunner) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:      runtime.NewExecRegistry(),
			Providers: runtime.NewProviderRegistry(),
			Runner:    runner,
			Facts:     facts.ForTesting(facts.Overrides{Package: "apt", OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
			FS:        runtime.NewMemoryFS(),
		}
		if err := execuser.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execgroup.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execshadow.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execsystem.Register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

func TestSolarisTrackCLIGOOSGating(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("solaris host runs the solaris surface")
	}
	runner := &cliRecordingRunner{}
	app := solarisTrackCLIApp(t, runner)

	// The solaris shadow surface is the only track that contributes
	// these names; on the Linux host they resolve as unsupported with
	// no Runner activity.
	solarisOnly := []string{
		"shadow.default_hash",
		"shadow.gen_password",
		"shadow.del_password",
		"shadow.set_password",
		"shadow.set_maxdays",
		"shadow.set_mindays",
		"shadow.set_warndays",
	}
	for _, name := range solarisOnly {
		code, _, errS := captureCode(t, app, "exec", name)
		if code != ExitUnsupported {
			t.Fatalf("solaris-only %s code=%d err=%q, want ExitUnsupported", name, code, errS)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("gated calls spawned processes: %#v", runner.calls)
	}

	// Shared virtual names stay resolvable through the Linux surface:
	// argument resolution runs and fails on the required argument
	// (exit 2) rather than unsupported.
	for _, name := range []string{"shadow.info", "system.init", "user.info", "group.chgid"} {
		code, _, _ := captureCode(t, app, "exec", name)
		if code == ExitUnsupported {
			t.Fatalf("shared %s unexpectedly unsupported on linux", name)
		}
	}
	// The solaris user/group family names are carried by the freebsd
	// registration and gate identically on Linux.
	code, _, _ := captureCode(t, app, "exec", "user.getent")
	if code != ExitUnsupported {
		t.Fatalf("user.getent code=%d, want ExitUnsupported on linux", code)
	}
}
