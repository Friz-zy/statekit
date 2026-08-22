// Package system implements Salt-compatible power and runlevel functions.
//
// Reference: saltstack/salt/modules/system.py @ pinned revision. Commands
// require root; StateKit never escalates privileges itself (plan section 39).
package system

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
)

func runArgv(ctx context.Context, rt *runtime.Runtime, argv ...string) error {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return res.Err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with code %d: %s", argv[0], res.ExitCode, res.Stderr)
	}
	return nil
}

func done(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return true, nil
}

type haltArgs struct{}

type haltFunc struct{}

func (haltFunc) Name() string { return "system.halt" }
func (haltFunc) Args() any    { return haltArgs{} }
func (haltFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return done(runArgv(ctx, rt, "halt"))
}

type poweroffArgs struct{}

type poweroffFunc struct{}

func (poweroffFunc) Name() string { return "system.poweroff" }
func (poweroffFunc) Args() any    { return poweroffArgs{} }
func (poweroffFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return done(runArgv(ctx, rt, "poweroff"))
}

type rebootArgs struct {
	AtTime string `statekit:"name=at_time"`
}

type rebootFunc struct{}

func (rebootFunc) Name() string { return "system.reboot" }
func (rebootFunc) Args() any    { return rebootArgs{} }
func (rebootFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*rebootArgs)
	at := a.AtTime
	if at == "" {
		at = "now"
	}
	return done(runArgv(ctx, rt, "shutdown", "-r", at))
}

type shutdownArgs struct {
	AtTime string `statekit:"name=at_time"`
}

type shutdownFunc struct{}

func (shutdownFunc) Name() string { return "system.shutdown" }
func (shutdownFunc) Args() any    { return shutdownArgs{} }
func (shutdownFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*shutdownArgs)
	at := a.AtTime
	if at == "" {
		at = "now"
	}
	return done(runArgv(ctx, rt, "shutdown", "-h", at))
}

type initArgs struct {
	Runlevel string `statekit:"required,name=runlevel"`
}

type initFunc struct{}

func (initFunc) Name() string { return "system.init" }
func (initFunc) Args() any    { return initArgs{} }
func (initFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*initArgs)
	return done(runArgv(ctx, rt, "init", a.Runlevel))
}

// Register installs all system-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{haltFunc{}, poweroffFunc{}, rebootFunc{}, shutdownFunc{}, initFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
