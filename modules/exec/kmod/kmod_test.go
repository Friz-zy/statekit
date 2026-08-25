package kmod

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const modulesFixture = `ext4 286208 1 - Live 0x0000000000000000
bridge 245760 0 - Live 0x0000000000000000
`

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
	rt.FS.MkdirAll("/proc", 0o755)
	rt.FS.WriteFile("/proc/modules", []byte(modulesFixture), 0o644)
	return rt, runner
}

func TestLsmodAndIsLoaded(t *testing.T) {
	rt, _ := newRT()
	modules, err := (lsmodFunc{}).Execute(context.Background(), rt, &lsmodArgs{})
	if err != nil {
		t.Fatalf("lsmod: %v", err)
	}
	if strings.Join(modules.([]string), ",") != "ext4,bridge" {
		t.Fatalf("modules = %v", modules)
	}
	value, _ := (isLoadedFunc{}).Execute(context.Background(), rt, &isLoadedArgs{Mod: "bridge"})
	if value != true {
		t.Fatal("bridge must be loaded")
	}
	value, _ = (isLoadedFunc{}).Execute(context.Background(), rt, &isLoadedArgs{Mod: "nvidia"})
	if value != false {
		t.Fatal("nvidia must not be loaded")
	}
}

func TestLoadRemoveArgv(t *testing.T) {
	rt, runner := newRT()
	(loadFunc{}).Execute(context.Background(), rt, &loadArgs{Mod: "bridge"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "modprobe bridge" {
		t.Fatalf("load argv = %q", got)
	}
	(removeFunc{}).Execute(context.Background(), rt, &removeArgs{Mod: "bridge"})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "modprobe -r bridge" {
		t.Fatalf("remove argv = %q", got)
	}
	runner.code = 1
	if _, err := (loadFunc{}).Execute(context.Background(), rt, &loadArgs{Mod: "broken"}); err == nil {
		t.Fatal("failed modprobe must error")
	}
}
