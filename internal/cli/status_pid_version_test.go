package cli

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execstatus "github.com/friz-zy/statekit/modules/exec/status"
)

func statusCLIApp(t *testing.T, kernel string, files map[string]string) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:   runtime.NewExecRegistry(),
			States: runtime.NewStateRegistry(),
			Facts:  facts.ForTesting(facts.Overrides{Kernel: &facts.KernelFacts{Name: kernel}}),
			FS:     runtime.NewMemoryFS(),
		}
		for path, content := range files {
			if err := rt.FS.MkdirAll("/proc", 0o755); err != nil {
				return nil, err
			}
			if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
				return nil, err
			}
		}
		if err := execstatus.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := execstatus.RegisterTail(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

func TestStatusVersionCLI(t *testing.T) {
	const content = "Linux version 6.1.0-cli (builder) #1 SMP\n"
	code, out, errS := captureCode(t, statusCLIApp(t, "Linux",
		map[string]string{"/proc/version": content}), "exec", "status.version", "-o", "json")
	var got string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("code=%d out=%q err=%q", code, out, errS)
	}
	if got != "Linux version 6.1.0-cli (builder) #1 SMP" {
		t.Fatalf("version = %q", got)
	}

	code, out, errS = captureCode(t, statusCLIApp(t, "darwin", nil), "exec", "status.version", "-o", "json")
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("unsupported code=%d out=%q err=%q", code, out, errS)
	}
	if got != "This method is unsupported on the current operating system!" {
		t.Fatalf("unsupported version = %q", got)
	}
}

func TestStatusPidCLI(t *testing.T) {
	app := statusCLIApp(t, "Linux", nil)
	code, out, errS := captureCode(t, app, "exec", "status.pid", "--sig",
		"StateKitNoSuchProcessZZQQ123", "-o", "json")
	var got string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("no-match code=%d out=%q err=%q", code, out, errS)
	}
	if got != "" {
		t.Fatalf("no-match pid = %q", got)
	}

	code, _, _ = captureCode(t, app, "exec", "status.pid")
	if code != ExitInvalidInput {
		t.Fatalf("missing --sig code=%d, want ExitInvalidInput", code)
	}

	code, _, _ = captureCode(t, app, "exec", "status.version", "--sig", "stray")
	if code != ExitInvalidInput {
		t.Fatalf("stray flag code=%d, want ExitInvalidInput", code)
	}
}

// TestStatusPidCLISelfExcluded asserts through the full CLI surface that
// the scanning process does not report itself.
func TestStatusPidCLISelfExcluded(t *testing.T) {
	own := strconv.Itoa(os.Getpid())
	code, out, errS := captureCode(t, statusCLIApp(t, "Linux", nil),
		"exec", "status.pid", "--sig", ".", "-o", "json")
	var got string
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("catch-all code=%d out=%q err=%q", code, out, errS)
	}
	if got == "" {
		t.Fatal("catch-all scan found no processes")
	}
	for _, line := range strings.Split(got, "\n") {
		if line == own {
			t.Fatalf("own pid %s leaked into CLI result %q", own, got)
		}
	}
}
