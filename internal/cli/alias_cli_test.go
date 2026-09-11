package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execfile "github.com/friz-zy/statekit/modules/exec/file"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
)

func aliasCLIApp(t *testing.T) *App {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
	}
	// MemoryFS.WriteFile requires the parent directory to exist, so seed
	// the default logrotate conf location like a provisioned host.
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/logrotate.conf", []byte("weekly\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, register := range []func(*runtime.ExecRegistry) error{
		execfile.Register,
		execfile.RegisterExt,
		execlogrotate.Register,
		execstatus.RegisterTail,
	} {
		if err := register(rt.Exec); err != nil {
			t.Fatal(err)
		}
	}
	// The CLI rebuilds its runtime per Run; returning one shared instance
	// keeps the in-memory filesystem alive across invocations so the repeat
	// makedirs call observes the first call's directories.
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil })
}

// TestCanonicalAliasCLIExitMatrix is the R5.6 alias CLI smoke: the canonical
// loader names status.time, logrotate.set, and file.makedirs run end to end
// through the CLI (exit 0), while their superseded underscore spellings are
// rejected as unsupported (exit 3).
func TestCanonicalAliasCLIExitMatrix(t *testing.T) {
	// One app instance keeps the runtime (and its in-memory filesystem)
	// alive across invocations so the repeat makedirs call observes the
	// first call's directories.
	app := aliasCLIApp(t)

	code, out, errS := captureCode(t, app, "exec", "status.time", "-o", "json")
	var rendered string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &rendered) != nil || rendered == "" {
		t.Fatalf("status.time code=%d out=%q err=%q", code, out, errS)
	}

	code, out, errS = captureCode(t, app,
		"exec", "file.makedirs", "--path", "/testbed/cli/a/b", "-o", "json")
	if code != ExitOK || errS != "" {
		t.Fatalf("file.makedirs code=%d out=%q err=%q", code, out, errS)
	}
	code, out, errS = captureCode(t, app,
		"exec", "file.makedirs", "--path", "/testbed/cli/a/b", "-o", "json")
	// The POSIX registration replies with the source already-exists message;
	// the Windows registration returns true instead, so only the exit code
	// is asserted there.
	if code != ExitOK || (runtime.CurrentGOOS() != "windows" && !strings.Contains(out, "already exists")) {
		t.Fatalf("file.makedirs repeat code=%d out=%q err=%q, want already-exists message", code, out, errS)
	}

	code, out, errS = captureCode(t, app,
		"exec", "logrotate.set", "--key", "compress", "--value", "1", "-o", "json")
	var set bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &set) != nil || !set {
		t.Fatalf("logrotate.set code=%d out=%q err=%q", code, out, errS)
	}

	for _, superseded := range []string{"status.time_", "logrotate.set_", "file.makedirs_"} {
		code, _, errS := captureCode(t, app, "exec", superseded)
		if code != ExitUnsupported {
			t.Fatalf("superseded alias %q code=%d, want ExitUnsupported (err=%q)", superseded, code, errS)
		}
	}
}
