// Package apf implements Salt's APF execution-function family.
package apf

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const commandTimeout = 30 * time.Second
const outputLimit = 1 << 20

var errRunnerUnavailable = errors.New("apf: runner unavailable")

type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

func Register(reg *runtime.ExecRegistry) error {
	for _, f := range []interface {
		Name() string
		Args() any
		Execute(context.Context, *runtime.Runtime, any) (any, error)
		Platforms() []string
	}{allowFunc{}, denyFunc{}, disableFunc{}, enableFunc{}, refreshFunc{}, reloadFunc{}, removeFunc{}, runningFunc{}} {
		if err := reg.Register(f); err != nil {
			return err
		}
	}
	return nil
}

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (process.CommandResult, error) {
	if rt == nil || rt.Runner == nil {
		return process.CommandResult{ExitCode: -1}, errRunnerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return process.CommandResult{ExitCode: -1}, err
	}
	if availability, ok := rt.Runner.(process.CommandAvailability); ok {
		if !availability.CommandAvailable(argv[0]) {
			return process.CommandResult{ExitCode: -1}, errors.New("apf: required command unavailable: " + argv[0])
		}
	}
	command := runtime.Command(argv...)
	command.Shell = false
	command.Timeout = commandTimeout
	command.MaxStdoutBytes = outputLimit
	command.MaxStderrBytes = outputLimit
	result := rt.Runner.Run(ctx, command)
	if result.Err != nil {
		return result, result.Err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.StdoutTruncated || result.StderrTruncated || len(result.Stdout) > outputLimit || len(result.Stderr) > outputLimit {
		return result, process.ErrOutputLimit
	}
	return result, nil
}

func commandResult(ctx context.Context, rt *runtime.Runtime, argv ...string) (any, error) {
	r, err := run(ctx, rt, argv...)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		message := r.Stderr
		if len(message) == 0 {
			message = r.Stdout
		}
		return nil, errors.New("apf failed: " + string(message))
	}
	return string(r.Stdout), nil
}

func status(ctx context.Context, rt *runtime.Runtime) (bool, error) {
	if rt != nil && rt.Runner != nil {
		if available, ok := rt.Runner.(process.CommandAvailability); ok && !available.CommandAvailable("apf") {
			return false, errors.New("apf: required command unavailable: apf")
		}
	}
	r, err := run(ctx, rt, "iptables", "-t", "filter", "-S")
	if err != nil {
		return false, err
	}
	if r.ExitCode != 0 {
		message := r.Stderr
		if len(message) == 0 {
			message = r.Stdout
		}
		return false, errors.New("apf: iptables status failed: " + string(message))
	}
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "-N" && strings.Contains(strings.ToLower(fields[1]), "sanity") {
			return true, nil
		}
	}
	return false, nil
}

type AllowArgs struct {
	IP   string  `statekit:"required,name=ip"`
	Port *string `statekit:"name=port"`
}
type IPArgs struct {
	IP string `statekit:"required,name=ip"`
}
type EmptyArgs struct{}

type allowFunc struct{ linuxOnly }

func (allowFunc) Name() string { return "apf.allow" }
func (allowFunc) Args() any    { return AllowArgs{} }
func (allowFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AllowArgs)
	if a.Port != nil {
		return nil, nil
	}
	return commandResult(ctx, rt, "apf", "-a", a.IP)
}

type denyFunc struct{ linuxOnly }

func (denyFunc) Name() string { return "apf.deny" }
func (denyFunc) Args() any    { return IPArgs{} }
func (denyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return commandResult(ctx, rt, "apf", "-d", args.(*IPArgs).IP)
}

type removeFunc struct{ linuxOnly }

func (removeFunc) Name() string { return "apf.remove" }
func (removeFunc) Args() any    { return IPArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return commandResult(ctx, rt, "apf", "-u", args.(*IPArgs).IP)
}

type disableFunc struct{ linuxOnly }

func (disableFunc) Name() string { return "apf.disable" }
func (disableFunc) Args() any    { return EmptyArgs{} }
func (disableFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	running, err := status(ctx, rt)
	if err != nil {
		return nil, err
	}
	if !running {
		return nil, nil
	}
	return commandResult(ctx, rt, "apf", "-f")
}

type enableFunc struct{ linuxOnly }

func (enableFunc) Name() string { return "apf.enable" }
func (enableFunc) Args() any    { return EmptyArgs{} }
func (enableFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	running, err := status(ctx, rt)
	if err != nil {
		return nil, err
	}
	if running {
		return nil, nil
	}
	return commandResult(ctx, rt, "apf", "-s")
}

type reloadFunc struct{ linuxOnly }

func (reloadFunc) Name() string { return "apf.reload" }
func (reloadFunc) Args() any    { return EmptyArgs{} }
func (reloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	running, err := status(ctx, rt)
	if err != nil {
		return nil, err
	}
	if running {
		return nil, nil
	}
	return commandResult(ctx, rt, "apf", "-r")
}

type refreshFunc struct{ linuxOnly }

func (refreshFunc) Name() string { return "apf.refresh" }
func (refreshFunc) Args() any    { return EmptyArgs{} }
func (refreshFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return commandResult(ctx, rt, "apf", "-e")
}

type runningFunc struct{ linuxOnly }

func (runningFunc) Name() string { return "apf.running" }
func (runningFunc) Args() any    { return EmptyArgs{} }
func (runningFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return status(ctx, rt)
}
