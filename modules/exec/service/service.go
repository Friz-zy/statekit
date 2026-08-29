// Package service implements Salt-compatible service execution functions
// backed by the virtual service provider.
//
// Reference: saltstack/salt/modules/systemd_service.py @ pinned revision.
package service

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
	serviceprovider "github.com/friz-zy/statekit/providers/service"
)

type NameArgs struct {
	Name string `statekit:"required"`
}

func resolve(rt *runtime.Runtime) (serviceprovider.Provider, error) {
	return serviceprovider.Resolve(rt)
}

type startFunc struct{}

func (startFunc) Name() string { return "service.start" }
func (startFunc) Args() any    { return NameArgs{} }
func (startFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Start(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	return true, nil
}

type stopFunc struct{}

func (stopFunc) Name() string { return "service.stop" }
func (stopFunc) Args() any    { return NameArgs{} }
func (stopFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Stop(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	return true, nil
}

type restartFunc struct{}

func (restartFunc) Name() string { return "service.restart" }
func (restartFunc) Args() any    { return NameArgs{} }
func (restartFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Restart(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	return true, nil
}

type StatusArgs struct {
	Name string `statekit:"required"`
	Sig  string `statekit:"name=sig"` // accepted for Salt compatibility; unused
}

type statusFunc struct{}

func (statusFunc) Name() string { return "service.status" }
func (statusFunc) Args() any    { return StatusArgs{} }
func (statusFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*StatusArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	running, err := provider.Status(ctx, rt, a.Name)
	if err != nil {
		return nil, err
	}
	if running {
		return fmt.Sprintf("%s is running", a.Name), nil
	}
	return fmt.Sprintf("%s is not running", a.Name), nil
}

type reloadFunc struct{}

func (reloadFunc) Name() string { return "service.reload" }
func (reloadFunc) Args() any    { return NameArgs{} }
func (reloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	res := rt.Runner.Run(ctx, runtime.Command("systemctl", "reload", a.Name))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("systemctl reload exited with code %d", res.ExitCode)
	}
	return true, nil
}

type enableFunc struct{}

func (enableFunc) Name() string { return "service.enable" }
func (enableFunc) Args() any    { return NameArgs{} }
func (enableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Enable(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	return true, nil
}

type disableFunc struct{}

func (disableFunc) Name() string { return "service.disable" }
func (disableFunc) Args() any    { return NameArgs{} }
func (disableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Disable(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	return true, nil
}

type EnabledArgs struct {
	Name string `statekit:"required"`
}

type enabledFunc struct{}

func (enabledFunc) Name() string { return "service.enabled" }
func (enabledFunc) Args() any    { return EnabledArgs{} }
func (enabledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*EnabledArgs)
	provider, err := resolve(rt)
	if err != nil {
		return nil, err
	}
	return provider.Enabled(ctx, rt, a.Name)
}

// Register installs all service-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "darwin" {
		return registerMac(reg)
	}
	if runtime.CurrentGOOS() == "windows" {
		return registerWindows(reg)
	}
	for _, fn := range []runtime.ExecFunction{
		startFunc{}, stopFunc{}, restartFunc{}, statusFunc{}, reloadFunc{},
		enableFunc{}, disableFunc{}, enabledFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
