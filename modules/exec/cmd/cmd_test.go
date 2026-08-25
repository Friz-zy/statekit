package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func testRuntime() *runtime.Runtime {
	return &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
}

func TestRunEchoes(t *testing.T) {
	value, err := (runFunc{}).Execute(context.Background(), testRuntime(), &RunArgs{Cmd: "printf hello"})
	if err != nil || value != "hello" {
		t.Fatalf("cmd.run = %v, %v", value, err)
	}
}

func TestRunRejectsEmptyAndRunas(t *testing.T) {
	if _, err := (runFunc{}).Execute(context.Background(), testRuntime(), &RunArgs{Cmd: "  "}); err == nil {
		t.Fatal("empty command must fail")
	}
	if _, err := (runFunc{}).Execute(context.Background(), testRuntime(), &RunArgs{Cmd: "id", Runas: "root"}); err == nil {
		t.Fatal("runas must be rejected (plan section 39)")
	}
}

func TestRetcodeReturnsExitStatus(t *testing.T) {
	value, err := (retcodeFunc{}).Execute(context.Background(), testRuntime(), &retcodeArgs{Cmd: "sh -c 'exit 7'"})
	if err != nil || value.(int) != 7 {
		t.Fatalf("cmd.retcode = %v, %v", value, err)
	}
}

func TestRunAllShape(t *testing.T) {
	ret, err := (runAllFunc{}).Execute(context.Background(), testRuntime(), &RunAllArgs{Cmd: "echo data"})
	if err != nil {
		t.Fatalf("run_all: %v", err)
	}
	m := ret.(map[string]any)
	if m["stdout"] != "data\n" || m["stderr"] != "" || m["retcode"].(int) != 0 {
		t.Fatalf("run_all shape wrong: %+v", m)
	}
	rendered := m["cmd"].(string)
	if !strings.Contains(rendered, "echo") {
		t.Fatalf("cmd field missing command text: %q", rendered)
	}
}

func TestTimeoutPropagates(t *testing.T) {
	_, err := (runFunc{}).Execute(context.Background(), testRuntime(), &RunArgs{
		Cmd: "sleep 5", Timeout: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestWhichFindsBinary(t *testing.T) {
	value, err := (whichFunc{}).Execute(context.Background(), testRuntime(), &whichArgs{Name: "sh"})
	if err != nil || value == "" || strings.Contains(value.(string), "missing") {
		t.Fatalf("cmd.which = %v, %v", value, err)
	}
	value, _ = (whichFunc{}).Execute(context.Background(), testRuntime(), &whichArgs{Name: "definitely-not-here-xyz"})
	if value != "" {
		t.Fatalf("missing binary must return empty string, got %v", value)
	}
}
