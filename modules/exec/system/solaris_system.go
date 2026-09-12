package system

// Solaris virtual system implementation for Salt's solaris_system
// module (saltstack/salt/modules/solaris_system.py @ pinned revision
// 8b63e700637e). Every function routes the solaris-like `shutdown`
// binary (`shutdown -i <initstate> -g <delay> -y [message]`) through
// the central shell-free Runner and returns the command output, the
// cmd.run contract the pinned source uses; halt and poweroff are
// aliases of shutdown. The surface is untagged so the Linux test host
// can exercise every provider function directly with a recording fake
// Runner; Platforms() provides the solaris-only gating (mirroring
// Salt's __virtual__ is_sunos + shutdown-in-PATH check; a missing
// shutdown binary surfaces through the Runner error). system.Register
// selects this surface on a solaris GOOS. Official Go distributions list
// solaris/amd64 and illumos/amd64 compile targets; this host has no native
// Solaris runtime runner, so the branch is exercised through registerSolaris
// directly.

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		sunHaltFunc{}, sunInitFunc{}, sunPoweroffFunc{}, sunRebootFunc{}, sunShutdownFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// sunShutdownRun ports the pinned shutdown/reboot/init body: build the
// shutdown argv, run it through the Runner, and return captured stdout.
// Salt's cmd.run default keeps completed non-zero exits as data; only Runner
// failures and context cancellation are errors.
func sunShutdownRun(ctx context.Context, rt *runtime.Runtime, argv []string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return string(res.Stdout), nil
}

// sunShutdownArgs carry the delay (seconds) and broadcast message the
// reboot/shutdown verbs share.
type sunShutdownArgs struct {
	Delay   string `statekit:"name=delay"`
	Message string `statekit:"name=message"`
}

func (a *sunShutdownArgs) argv(initState string) []string {
	delay := a.Delay
	if delay == "" {
		delay = "0"
	}
	argv := []string{"shutdown", "-i", initState, "-g", delay, "-y"}
	if a.Message != "" {
		argv = append(argv, a.Message)
	}
	return argv
}

type sunHaltArgs struct{}

type sunHaltFunc struct{}

func (sunHaltFunc) Name() string        { return "system.halt" }
func (sunHaltFunc) Args() any           { return sunHaltArgs{} }
func (sunHaltFunc) Platforms() []string { return []string{"solaris"} }
func (sunHaltFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return sunShutdownRun(ctx, rt, (&sunShutdownArgs{}).argv("5"))
}

type sunInitArgs struct {
	State string `statekit:"required"`
}

type sunInitFunc struct{}

func (sunInitFunc) Name() string        { return "system.init" }
func (sunInitFunc) Args() any           { return sunInitArgs{} }
func (sunInitFunc) Platforms() []string { return []string{"solaris"} }
func (sunInitFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunInitArgs)
	return sunShutdownRun(ctx, rt, []string{"shutdown", "-i", a.State, "-g", "0", "-y"})
}

type sunPoweroffArgs struct{}

type sunPoweroffFunc struct{}

func (sunPoweroffFunc) Name() string        { return "system.poweroff" }
func (sunPoweroffFunc) Args() any           { return sunPoweroffArgs{} }
func (sunPoweroffFunc) Platforms() []string { return []string{"solaris"} }
func (sunPoweroffFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return sunShutdownRun(ctx, rt, (&sunShutdownArgs{}).argv("5"))
}

type sunRebootArgs struct {
	Delay   string `statekit:"name=delay"`
	Message string `statekit:"name=message"`
}

type sunRebootFunc struct{}

func (sunRebootFunc) Name() string        { return "system.reboot" }
func (sunRebootFunc) Args() any           { return sunRebootArgs{} }
func (sunRebootFunc) Platforms() []string { return []string{"solaris"} }
func (sunRebootFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunRebootArgs)
	return sunShutdownRun(ctx, rt, (&sunShutdownArgs{Delay: a.Delay, Message: a.Message}).argv("6"))
}

type sunShutdownFunc struct{}

func (sunShutdownFunc) Name() string        { return "system.shutdown" }
func (sunShutdownFunc) Args() any           { return sunShutdownArgs{} }
func (sunShutdownFunc) Platforms() []string { return []string{"solaris"} }
func (sunShutdownFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sunShutdownArgs)
	return sunShutdownRun(ctx, rt, a.argv("5"))
}
