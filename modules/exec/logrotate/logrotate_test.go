package logrotate

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type scriptRunner struct {
	calls [][]string
	code  int
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: s.code}
}

func newRT() (*runtime.Runtime, *scriptRunner) {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: &scriptRunner{},
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc/logrotate.d", 0o755)
	rt.FS.WriteFile(mainConfig, []byte("weekly\ninclude /etc/logrotate.d\n"), 0o644)
	rt.FS.WriteFile("/etc/logrotate.d/nginx", []byte("/var/log/nginx/*.log { daily }"), 0o644)
	return rt, rt.Runner.(*scriptRunner)
}

func TestShowConfigIncludesSnippets(t *testing.T) {
	rt, _ := newRT()
	value, err := (showConfigFunc{}).Execute(context.Background(), rt, &ShowConfigArgs{})
	if err != nil {
		t.Fatal(err)
	}
	conf := value.(map[string]any)
	if !strings.Contains(conf["main"].(string), "include /etc/logrotate.d") {
		t.Fatalf("main missing:\n%v", conf["main"])
	}
	includes := conf["includes"].(map[string]string)
	if includes["nginx"] == "" {
		t.Fatalf("snippets = %v", includes)
	}
}

func TestRotateArgv(t *testing.T) {
	rt, runner := newRT()
	(rotateFunc{}).Execute(context.Background(), rt, &RotateArgs{Force: true})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "logrotate -f /etc/logrotate.conf" {
		t.Fatalf("argv = %q", got)
	}
	runner.code = 1
	if _, err := (rotateFunc{}).Execute(context.Background(), rt, &RotateArgs{}); err == nil {
		t.Fatal("failed rotation must error")
	}
}
