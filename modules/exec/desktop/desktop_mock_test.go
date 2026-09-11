package desktop

// R6.10 mock tests for the Darwin desktop surface, mapped onto
// saltstack/salt/modules/mac_desktop.py @ pinned revision 8b63e700637e
// (the pinned source ships no pytest of its own): exact osascript/open/
// CGSession/say argv per Salt command strings, the _check_cmd error
// composition (stderr then stdout), shell-free Runner commands and the
// registry matrix. All Runner output is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type desktopScriptRunner struct {
	script []process.CommandResult
	calls  []process.Command
}

func (r *desktopScriptRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.script) == 0 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("ok")}
	}
	next := r.script[0]
	r.script = r.script[1:]
	return next
}

func desktopRT(script ...process.CommandResult) (*runtime.Runtime, *desktopScriptRunner) {
	runner := &desktopScriptRunner{script: script}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func desktopArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestGetOutputVolumeArgv(t *testing.T) {
	rt, runner := desktopRT(process.CommandResult{ExitCode: 0, Stdout: []byte("55")})
	res, err := (getOutputVolumeFunc{}).Execute(context.Background(), rt, getOutputVolumeArgs{})
	if err != nil || res != "55" {
		t.Fatalf("get volume = %v %v", res, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	want := `osascript -e get output volume of (get volume settings)`
	if got := desktopArgv(runner.calls[0]); got != want {
		t.Fatalf("argv = %q; want %q", got, want)
	}
	if runner.calls[0].Shell {
		t.Fatal("desktop commands must stay shell-free")
	}
}

func TestSetOutputVolumeArgvAndChainedRead(t *testing.T) {
	rt, runner := desktopRT(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("75")},
	)
	res, err := (setOutputVolumeFunc{}).Execute(context.Background(), rt, &setOutputVolumeArgs{Volume: "75"})
	if err != nil || res != "75" {
		t.Fatalf("set volume = %v %v", res, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	want := `osascript -e set volume output volume 75`
	if got := desktopArgv(runner.calls[0]); got != want {
		t.Fatalf("write argv = %q; want %q", got, want)
	}
	if got := desktopArgv(runner.calls[1]); got != `osascript -e get output volume of (get volume settings)` {
		t.Fatalf("read-back argv = %q", got)
	}
	// The returned value is the follow-up read, not a hard-coded echo.
	rt2, _ := desktopRT(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("40")},
	)
	res, err = (setOutputVolumeFunc{}).Execute(context.Background(), rt2, &setOutputVolumeArgs{Volume: "40"})
	if err != nil || res != "40" {
		t.Fatalf("read-back value = %v %v", res, err)
	}
}

func TestScreensaverLockSayArgv(t *testing.T) {
	rt, runner := desktopRT()
	if res, err := (screensaverFunc{}).Execute(context.Background(), rt, screensaverArgs{}); err != nil || res != true {
		t.Fatalf("screensaver = %v %v", res, err)
	}
	want := `open /System/Library/Frameworks/ScreenSaver.framework/Versions/A/Resources/ScreenSaverEngine.app`
	if got := desktopArgv(runner.calls[0]); got != want {
		t.Fatalf("screensaver argv = %q; want %q", got, want)
	}
	if res, err := (lockFunc{}).Execute(context.Background(), rt, lockArgs{}); err != nil || res != true {
		t.Fatalf("lock = %v %v", res, err)
	}
	want = `/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession -suspend`
	if got := desktopArgv(runner.calls[1]); got != want {
		t.Fatalf("lock argv = %q; want %q", got, want)
	}
	if res, err := (sayFunc{}).Execute(context.Background(), rt, &sayArgs{Words: []string{"hello", "world"}}); err != nil || res != true {
		t.Fatalf("say = %v %v", res, err)
	}
	if got := desktopArgv(runner.calls[2]); got != `say hello world` {
		t.Fatalf("say argv = %q", got)
	}
	for _, command := range runner.calls {
		if command.Shell {
			t.Fatal("desktop commands must stay shell-free")
		}
	}
}

func TestCheckCmdErrorComposition(t *testing.T) {
	// Salt _check_cmd joins stderr followed by stdout into the
	// CommandExecutionError comment.
	rt, _ := desktopRT(process.CommandResult{ExitCode: 1, Stderr: []byte("err"), Stdout: []byte("out")})
	_, err := (getOutputVolumeFunc{}).Execute(context.Background(), rt, getOutputVolumeArgs{})
	if err == nil || err.Error() != "Error running command: errout" {
		t.Fatalf("stderr+stdout = %v", err)
	}
	rt, _ = desktopRT(process.CommandResult{ExitCode: 1, Stdout: []byte("only-out")})
	_, err = (sayFunc{}).Execute(context.Background(), rt, &sayArgs{})
	if err == nil || err.Error() != "Error running command: only-out" {
		t.Fatalf("stdout only = %v", err)
	}
	rt, _ = desktopRT(process.CommandResult{ExitCode: 1, Stderr: []byte("only-err")})
	_, err = (lockFunc{}).Execute(context.Background(), rt, lockArgs{})
	if err == nil || err.Error() != "Error running command: only-err" {
		t.Fatalf("stderr only = %v", err)
	}
}

func TestDesktopRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"desktop.get_output_volume",
		"desktop.lock",
		"desktop.screensaver",
		"desktop.say",
		"desktop.set_output_volume",
	}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, _ := desktopRT(process.CommandResult{ExitCode: 0, Stdout: []byte("7")})
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "desktop.get_output_volume", getOutputVolumeArgs{})
		if err != nil || res != "7" {
			t.Fatalf("dispatch = %v %v", res, err)
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "desktop.get_output_volume", getOutputVolumeArgs{}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
