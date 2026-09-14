package cli

import (
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execsolarisips "github.com/friz-zy/statekit/modules/exec/solarisipspkg"
	execsolarispkg "github.com/friz-zy/statekit/modules/exec/solarispkg"
)

func solarisPackageCLIApp(t *testing.T, register func(*runtime.ExecRegistry) error, runner *cliRecordingRunner) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:      runtime.NewExecRegistry(),
			Providers: runtime.NewProviderRegistry(),
			Runner:    runner,
			Facts:     facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilySolaris}}),
			FS:        runtime.NewMemoryFS(),
		}
		if err := register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

func TestSolarisPackageCLIGatesEveryProviderFunctionOnLinux(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux CLI gating assertion does not apply on Solaris")
	}
	for _, tc := range []struct {
		name     string
		register func(*runtime.ExecRegistry) error
	}{
		{"legacy", execsolarispkg.Register},
		{"ips", execsolarisips.Register},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{}
			app := solarisPackageCLIApp(t, tc.register, runner)
			names := []string{
				"pkg.list_pkgs", "pkg.latest_version", "pkg.upgrade_available", "pkg.version",
				"pkg.install", "pkg.remove", "pkg.purge",
			}
			if tc.name == "ips" {
				names = append(names,
					"pkg.refresh_db", "pkg.list_upgrades", "pkg.upgrade", "pkg.get_fmri",
					"pkg.normalize_name", "pkg.is_installed", "pkg.search",
				)
			}
			for _, name := range names {
				code, _, errS := captureCode(t, app, "exec", name)
				if code != ExitUnsupported {
					t.Fatalf("%s code=%d err=%q, want ExitUnsupported", name, code, errS)
				}
			}
			if len(runner.calls) != 0 {
				t.Fatalf("gated calls reached Runner: %#v", runner.calls)
			}
		})
	}
}

// Keep the compile-time dependency on process visible in this CLI-only gate;
// it also documents that the runner used by the app is the central interface.
var _ process.Runner = (*cliRecordingRunner)(nil)
