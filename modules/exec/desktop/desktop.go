// Package desktop implements Salt's Darwin desktop execution functions.
// Commands are shell-free argv calls through the central Runner.
package desktop

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
)

func desktopRun(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, error) {
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("Error running command: %s%s", result.Stderr, result.Stdout)
	}
	return string(result.Stdout), nil
}

// ---------------------------------------------------------------------------
// volume

type getOutputVolumeArgs struct{}
type getOutputVolumeFunc struct{}

func (getOutputVolumeFunc) Name() string        { return "desktop.get_output_volume" }
func (getOutputVolumeFunc) Args() any           { return getOutputVolumeArgs{} }
func (getOutputVolumeFunc) Platforms() []string { return []string{"darwin"} }
func (getOutputVolumeFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverDesktop(&res, &err)
	return desktopRun(ctx, rt, "osascript", "-e", "get output volume of (get volume settings)")
}

type setOutputVolumeArgs struct {
	Volume string `statekit:"required,name=volume"`
}
type setOutputVolumeFunc struct{}

func (setOutputVolumeFunc) Name() string        { return "desktop.set_output_volume" }
func (setOutputVolumeFunc) Args() any           { return setOutputVolumeArgs{} }
func (setOutputVolumeFunc) Platforms() []string { return []string{"darwin"} }
func (setOutputVolumeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDesktop(&res, &err)
	a := args.(*setOutputVolumeArgs)
	if _, err := desktopRun(ctx, rt, "osascript", "-e", "set volume output volume "+a.Volume); err != nil {
		return nil, err
	}
	return getOutputVolumeFunc{}.Execute(ctx, rt, getOutputVolumeArgs{})
}

// ---------------------------------------------------------------------------
// session controls

type screensaverArgs struct{}
type screensaverFunc struct{}

func (screensaverFunc) Name() string        { return "desktop.screensaver" }
func (screensaverFunc) Args() any           { return screensaverArgs{} }
func (screensaverFunc) Platforms() []string { return []string{"darwin"} }
func (screensaverFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverDesktop(&res, &err)
	if _, err := desktopRun(ctx, rt, "open", "/System/Library/Frameworks/ScreenSaver.framework/Versions/A/Resources/ScreenSaverEngine.app"); err != nil {
		return nil, err
	}
	return true, nil
}

type lockArgs struct{}
type lockFunc struct{}

func (lockFunc) Name() string        { return "desktop.lock" }
func (lockFunc) Args() any           { return lockArgs{} }
func (lockFunc) Platforms() []string { return []string{"darwin"} }
func (lockFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverDesktop(&res, &err)
	if _, err := desktopRun(ctx, rt, "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"); err != nil {
		return nil, err
	}
	return true, nil
}

type sayArgs struct {
	Words []string `statekit:"name=words"`
}
type sayFunc struct{}

func (sayFunc) Name() string        { return "desktop.say" }
func (sayFunc) Args() any           { return sayArgs{} }
func (sayFunc) Platforms() []string { return []string{"darwin"} }
func (sayFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDesktop(&res, &err)
	a := args.(*sayArgs)
	argv := append([]string{"say"}, a.Words...)
	if _, err := desktopRun(ctx, rt, argv...); err != nil {
		return nil, err
	}
	return true, nil
}

func recoverDesktop(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}

// Register installs Darwin desktop functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getOutputVolumeFunc{}, setOutputVolumeFunc{}, screensaverFunc{}, lockFunc{}, sayFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
