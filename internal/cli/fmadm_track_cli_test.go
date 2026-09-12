package cli

import (
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execfmadm "github.com/friz-zy/statekit/modules/exec/fmadm"
)

// R8.3a CLI smoke: the Solaris-only fmadm family is registered in the
// cross-platform registry but remains unsupported on a Linux host, so no
// fmadm/fmdump Runner call can occur before platform filtering.
func TestSolarisFmadmCLIGOOSGating(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux gating assertion does not apply on Solaris")
	}
	runner := &cliRecordingRunner{}
	app := NewApp("test-version", func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:   runtime.NewExecRegistry(),
			Runner: runner,
			Facts:  facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
		}
		if err := execfmadm.Register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	})
	for _, name := range []string{
		"fmadm.list", "fmadm.show", "fmadm.config", "fmadm.load", "fmadm.unload",
		"fmadm.reset", "fmadm.flush", "fmadm.repaired", "fmadm.replaced", "fmadm.acquit",
		"fmadm.faulty", "fmadm.healthy", "fmadm.list_records",
	} {
		code, _, errText := captureCode(t, app, "exec", name)
		if code != ExitUnsupported {
			t.Fatalf("%s code=%d err=%q, want ExitUnsupported", name, code, errText)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("platform-gated calls spawned processes: %#v", runner.calls)
	}
}
