package cli

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
)

// udevCLIApp builds an app whose runtime carries the udev registration and
// a fresh command recorder so each CLI case observes its own dispatches.
func udevCLIApp(t *testing.T) (*App, *execudevRecorder) {
	t.Helper()
	rec := &execudevRecorder{result: process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte(udevExportFixtureCLI),
	}}
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:   runtime.NewExecRegistry(),
			States: runtime.NewStateRegistry(),
			Facts:  facts.ForTesting(facts.Overrides{}),
			FS:     runtime.NewMemoryFS(),
			Runner: rec,
		}
		if err := execudev.Register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build), rec
}

type execudevRecorder struct {
	commands []process.Command
	result   process.CommandResult
}

func (r *execudevRecorder) Run(_ context.Context, cmd process.Command) process.CommandResult {
	c := cmd
	c.Args = append([]string(nil), cmd.Args...)
	c.Env = append([]string(nil), cmd.Env...)
	r.commands = append(r.commands, c)
	return r.result
}

// udevExportFixtureCLI mirrors the pinned upstream three-record export-db
// fixture used by the module tests.
const udevExportFixtureCLI = `
P: /devices/LNXSYSTM:00/LNXPWRBN:00
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00
E: DRIVER=button
E: MODALIAS=acpi:LNXPWRBN:
E: SUBSYSTEM=acpi

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
E: EV=3
E: ID_INPUT=1
E: SUBSYSTEM=input

P: /devices/LNXSYSTM:00/LNXPWRBN:00/input/input2/event2
N: input/event2
E: DEVNAME=/dev/input/event2
E: MAJOR=13
E: MINOR=66
E: SUBSYSTEM=input
`

// TestUdevExportdbCLIExitMatrix walks the CLI surface of udev.exportdb:
// the untagged default run, the comma-list filter, the explicit empty
// filter, structured-only input, explicit CLI precedence over structured
// values, and rejection of non-list structured input before any dispatch.
func TestUdevExportdbCLIExitMatrix(t *testing.T) {
	wantCommand := process.Command{
		Name:           "udevadm",
		Args:           []string{"info", "--export-db"},
		Env:            []string{"LC_ALL=C"},
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 16 << 20,
		MaxStderrBytes: 64 << 10,
	}

	t.Run("unfiltered", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		code, out, errS := captureCode(t, app, "exec", "udev.exportdb", "-o", "json")
		var records []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &records) != nil {
			t.Fatalf("code=%d out=%q err=%q", code, out, errS)
		}
		if len(records) != 3 {
			t.Fatalf("records = %d, want 3", len(records))
		}
		if len(rec.commands) != 1 || !reflect.DeepEqual(rec.commands[0], wantCommand) {
			t.Fatalf("commands = %+v", rec.commands)
		}
	})

	t.Run("comma list filter", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		code, out, errS := captureCode(t, app,
			"exec", "udev.exportdb", "--subsystems", "usb,acpi", "-o", "json")
		var records []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &records) != nil {
			t.Fatalf("code=%d out=%q err=%q", code, out, errS)
		}
		if len(records) != 1 || records[0]["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
			t.Fatalf("filtered records = %#v", records)
		}
		if len(rec.commands) != 1 {
			t.Fatalf("dispatches = %d", len(rec.commands))
		}
	})

	t.Run("explicit empty filter", func(t *testing.T) {
		app, _ := udevCLIApp(t)
		code, out, errS := captureCode(t, app, "exec", "udev.exportdb", "--subsystems=", "-o", "json")
		if code != ExitOK || errS != "" {
			t.Fatalf("code=%d err=%q", code, errS)
		}
		if strings.TrimSpace(out) != "[]" {
			t.Fatalf("empty filter output = %q, want []", out)
		}
	})

	t.Run("structured list", func(t *testing.T) {
		app, _ := udevCLIApp(t)
		code, out, errS := captureCode(t, app, "exec", "udev.exportdb",
			"--config", `{"subsystems": ["input"]}`, "-o", "json")
		var records []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &records) != nil {
			t.Fatalf("code=%d out=%q err=%q", code, out, errS)
		}
		if len(records) != 2 {
			t.Fatalf("structured filter records = %d, want 2", len(records))
		}
	})

	t.Run("cli overrides structured", func(t *testing.T) {
		app, _ := udevCLIApp(t)
		code, out, errS := captureCode(t, app, "exec", "udev.exportdb",
			"--config", `{"subsystems": ["input"]}`, "--subsystems", "acpi", "-o", "json")
		var records []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &records) != nil {
			t.Fatalf("code=%d out=%q err=%q", code, out, errS)
		}
		if len(records) != 1 {
			t.Fatalf("precedence records = %d, want 1 (CLI filter wins)", len(records))
		}
	})

	t.Run("structured null stays unfiltered", func(t *testing.T) {
		app, _ := udevCLIApp(t)
		code, out, errS := captureCode(t, app, "exec", "udev.exportdb",
			"--config", `{"subsystems": null}`, "-o", "json")
		var records []map[string]any
		if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &records) != nil {
			t.Fatalf("code=%d out=%q err=%q", code, out, errS)
		}
		if len(records) != 3 {
			t.Fatalf("structured null records = %d, want 3 (unfiltered)", len(records))
		}
	})

	t.Run("structured scalar rejected before dispatch", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		code, _, _ := captureCode(t, app, "exec", "udev.exportdb",
			"--config", `{"subsystems": "usb"}`, "-o", "json")
		if code != ExitInvalidInput {
			t.Fatalf("code=%d, want ExitInvalidInput", code)
		}
		if len(rec.commands) != 0 {
			t.Fatalf("invalid structured input dispatched %d commands", len(rec.commands))
		}
	})

	t.Run("over-ceiling cli filter rejected before dispatch", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		overlong := make([]string, 257)
		for i := range overlong {
			overlong[i] = "subsys"
		}
		code, _, _ := captureCode(t, app, "exec", "udev.exportdb",
			"--subsystems", strings.Join(overlong, ","), "-o", "json")
		if code != ExitInvalidInput {
			t.Fatalf("257-entry filter code=%d, want ExitInvalidInput (input-time rejection)", code)
		}
		if len(rec.commands) != 0 {
			t.Fatalf("over-ceiling filter dispatched %d commands", len(rec.commands))
		}
	})

	t.Run("delimiter-heavy cli filter rejected before dispatch", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		code, _, _ := captureCode(t, app, "exec", "udev.exportdb",
			"--subsystems", strings.Repeat(",", 65793), "-o", "json")
		if code != ExitInvalidInput {
			t.Fatalf("delimiter-heavy filter code=%d, want ExitInvalidInput (input-time rejection)", code)
		}
		if len(rec.commands) != 0 {
			t.Fatalf("delimiter-heavy filter dispatched %d commands", len(rec.commands))
		}
	})

	t.Run("failure exits nonzero with fixed error", func(t *testing.T) {
		app, rec := udevCLIApp(t)
		rec.result = process.CommandResult{ExitCode: 1, Stderr: []byte("boom-details")}
		code, _, errS := captureCode(t, app, "exec", "udev.exportdb", "-o", "json")
		if code != ExitFailed {
			t.Fatalf("nonzero exit code=%d, want ExitFailed (execution-error class)", code)
		}
		if strings.TrimSpace(errS) != "statekit: udev.exportdb: command failed" {
			t.Fatalf("err = %q, want the fixed execution-error text", errS)
		}
		if strings.Contains(errS, "boom-details") {
			t.Fatalf("CLI error leaked udevadm stderr: %q", errS)
		}
	})
}
