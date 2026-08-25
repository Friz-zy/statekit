package keyboard

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func newRT(initial string) (*runtime.Runtime, *scriptRunner) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &scriptRunner{}, FS: runtime.NewMemoryFS()}
	if initial != "" {
		rt.FS.MkdirAll("/etc/default", 0o755)
		rt.FS.WriteFile(keyboardConfig, []byte(initial), 0o644)
	}
	return rt, rt.Runner.(*scriptRunner)
}

type scriptRunner struct {
	script []process.CommandResult
	calls  [][]string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

const kbdFixture = "# config\nXKBLAYOUT=us\nXKBOPTIONS=ctrl:nocaps\n"

func TestGetLayout(t *testing.T) {
	rt, _ := newRT(kbdFixture)
	value, err := (getLayoutFunc{}).Execute(context.Background(), rt, &GetLayoutArgs{})
	if err != nil || value != "us" {
		t.Fatalf("layout = %v, %v", value, err)
	}
}

func TestSetLayoutUpdatesFileAndKeepsOptions(t *testing.T) {
	rt, runner := newRT(kbdFixture)
	(setLayoutFunc{}).Execute(context.Background(), rt, &SetLayoutArgs{Layout: "de"})
	data, _ := rt.FS.ReadFile(keyboardConfig)
	rendered := string(data)
	if !strings.Contains(rendered, `XKBLAYOUT="de"`) || !strings.Contains(rendered, "XKBOPTIONS=ctrl:nocaps") {
		t.Fatalf("rewrite wrong:\n%s", rendered)
	}
	last := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if !strings.Contains(last, "set-x11-keymap de") {
		t.Fatalf("localectl argv = %q", last)
	}
}

func TestSetLayoutIdempotent(t *testing.T) {
	rt, _ := newRT(kbdFixture)
	message, _ := (setLayoutFunc{}).Execute(context.Background(), rt, &SetLayoutArgs{Layout: "us"})
	if !strings.Contains(message.(string), "already set") {
		t.Fatalf("idempotent message = %v", message)
	}
}
