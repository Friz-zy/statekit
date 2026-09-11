package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
)

func sleepCLIApp(t *testing.T) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec:   runtime.NewExecRegistry(),
			States: runtime.NewStateRegistry(),
			Facts:  facts.ForTesting(facts.Overrides{}),
			FS:     runtime.NewMemoryFS(),
		}
		if err := exectest.Register(rt.Exec); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

// TestSleepCLIExitMatrix exercises the full CLI surface for test.sleep:
// success is exit 0 with true; a missing required --length, a non-integer
// length, and the pre-move --duration spelling are exit 2.
func TestSleepCLIExitMatrix(t *testing.T) {
	code, out, errS := captureCode(t, sleepCLIApp(t), "exec", "test.sleep", "--length", "1", "-o", "json")
	var got bool
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("success code=%d out=%q err=%q", code, out, errS)
	}
	if !got {
		t.Fatalf("sleep result = %v, want true", got)
	}

	cases := []struct {
		name string
		argv []string
		err  string
	}{
		{"missing required length", []string{"exec", "test.sleep"}, "missing required argument"},
		{"non-integer length", []string{"exec", "test.sleep", "--length", "2.5"}, "invalid integer"},
		{"pre-move duration spelling", []string{"exec", "test.sleep", "--duration", "1"}, ""},
	}
	for _, tc := range cases {
		code, _, errS := captureCode(t, sleepCLIApp(t), tc.argv...)
		if code != ExitInvalidInput {
			t.Fatalf("%s: code=%d, want ExitInvalidInput (err=%q)", tc.name, code, errS)
		}
		if tc.err != "" && !strings.Contains(errS, tc.err) {
			t.Fatalf("%s: err=%q, want substring %q", tc.name, errS, tc.err)
		}
	}
}
