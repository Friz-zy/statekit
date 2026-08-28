package desktop

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type desktopRunner struct {
	calls []process.Command
	fail  bool
}

func (r *desktopRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if r.fail {
		return process.CommandResult{ExitCode: 1, Stdout: []byte("out"), Stderr: []byte("err")}
	}
	if command.Name == "osascript" && len(command.Args) > 1 && strings.HasPrefix(command.Args[1], "get output") {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("55")}
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte("ok")}
}

func TestDesktopVolumeAndControls(t *testing.T) {
	runner := &desktopRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getOutputVolumeFunc{}.Execute(context.Background(), rt, getOutputVolumeArgs{})
	if err != nil || res != "55" {
		t.Fatalf("get volume = %v %v", res, err)
	}
	res, err = setOutputVolumeFunc{}.Execute(context.Background(), rt, &setOutputVolumeArgs{Volume: "75"})
	if err != nil || res != "55" || len(runner.calls) != 3 {
		t.Fatalf("set volume = %v %v calls=%+v", res, err, runner.calls)
	}
	for _, fn := range []runtime.ExecFunction{screensaverFunc{}, lockFunc{}, sayFunc{}} {
		var args any
		switch fn.(type) {
		case screensaverFunc:
			args = screensaverArgs{}
		case lockFunc:
			args = lockArgs{}
		default:
			args = &sayArgs{Words: []string{"hello", "world"}}
		}
		if value, err := fn.Execute(context.Background(), rt, args); err != nil || value != true {
			t.Fatalf("%s = %v %v", fn.Name(), value, err)
		}
	}
}

func TestDesktopCommandErrorAndPlatform(t *testing.T) {
	runner := &desktopRunner{fail: true}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	_, err := getOutputVolumeFunc{}.Execute(context.Background(), rt, getOutputVolumeArgs{})
	if err == nil || err.Error() != "Error running command: errout" {
		t.Fatalf("command error = %v", err)
	}
	platforms := (sayFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
