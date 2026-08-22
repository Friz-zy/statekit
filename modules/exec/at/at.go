// Package at implements Salt-compatible at(1) job management.
//
// Reference: saltstack/salt/modules/at.py @ pinned revision. Commands run
// through the central Runner; job listing parses atq output.
package at

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type atArgs struct {
	Command  string `statekit:"required,name=command"`
	TimeSpec string `statekit:"name=timespec"`
}

type atFunc struct{}

func (atFunc) Name() string { return "at.at" }
func (atFunc) Args() any    { return atArgs{} }
func (atFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*atArgs)
	spec := a.TimeSpec
	if spec == "" {
		return nil, fmt.Errorf("timespec is required, e.g. '10:30' or '+1min'")
	}
	res := rt.Runner.Run(ctx, process.Command{
		Name: "at", Args: []string{spec}, Stdin: []byte(a.Command),
	})
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("at exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

type atqArgs struct{}

type atqFunc struct{}

func (atqFunc) Name() string { return "at.atq" }
func (atqFunc) Args() any    { return atqArgs{} }
func (atqFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("atq"))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("atq exited with code %d", res.ExitCode)
	}
	jobs := []any{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			jobs = append(jobs, map[string]any{
				"job":  fields[0],
				"time": strings.Join(fields[1:len(fields)-1], " "),
				"user": fields[len(fields)-1],
			})
		}
	}
	return jobs, nil
}

type atrmArgs struct {
	JobID string `statekit:"required,name=jobid"`
}

type atrmFunc struct{}

func (atrmFunc) Name() string { return "at.atrm" }
func (atrmFunc) Args() any    { return atrmArgs{} }
func (atrmFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*atrmArgs)
	res := rt.Runner.Run(ctx, runtime.Command("atrm", a.JobID))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return false, nil
	}
	return true, nil
}

// Register installs all at-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{atFunc{}, atqFunc{}, atrmFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
