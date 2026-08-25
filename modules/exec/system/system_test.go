package system

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	calls [][]string
	code  int
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: f.code}
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	return rt, runner
}

func TestPowerCommandsArgv(t *testing.T) {
	rt, runner := newRT()

	(haltFunc{}).Execute(context.Background(), rt, &haltArgs{})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "halt" {
		t.Fatalf("halt argv = %q (Salt parity)", got)
	}

	(poweroffFunc{}).Execute(context.Background(), rt, &poweroffArgs{})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "poweroff" {
		t.Fatalf("poweroff argv = %q", got)
	}

	(rebootFunc{}).Execute(context.Background(), rt, &rebootArgs{})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "shutdown -r now" {
		t.Fatalf("reboot argv = %q", got)
	}

	(rebootFunc{}).Execute(context.Background(), rt, &rebootArgs{AtTime: "5"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "shutdown -r 5" {
		t.Fatalf("delayed reboot argv = %q", got)
	}

	(shutdownFunc{}).Execute(context.Background(), rt, &shutdownArgs{})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "shutdown -h now" {
		t.Fatalf("shutdown argv = %q", got)
	}

	(initFunc{}).Execute(context.Background(), rt, &initArgs{Runlevel: "3"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "init 3" {
		t.Fatalf("init argv = %q", got)
	}
}

func TestFailureSurfacesError(t *testing.T) {
	rt, runner := newRT()
	runner.code = 1
	if _, err := (haltFunc{}).Execute(context.Background(), rt, &haltArgs{}); err == nil {
		t.Fatal("non-zero exit must surface as error")
	}
}
