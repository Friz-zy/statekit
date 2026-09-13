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
	Command  string         `statekit:"required,name=command"`
	TimeSpec string         `statekit:"name=timespec"`
	Kwargs   map[string]any `statekit:"name=kwargs"`
}

// rejectAtRunas preserves the pinned Salt at.py boundary: Salt forwards a
// non-empty runas value to cmd.run/cmd.run_all, but StateKit has no
// single-user elevation boundary for this module.  Keep this as a stable,
// value-independent UnsupportedError and reject it before touching Runner.
func rejectAtRunas(kwargs map[string]any) error {
	raw, present := kwargs["runas"]
	if !present || raw == nil {
		return nil
	}
	runas, ok := raw.(string)
	if !ok {
		return fmt.Errorf("at: runas must be a string")
	}
	if runas == "" {
		return nil
	}
	return &runtime.UnsupportedError{Kind: "function", Name: "at.at"}
}

// validateAtTimespecOperand rejects option-like timespecs before they become
// the first operand passed to at(1).  at's option boundary is the ASCII '-';
// do not broaden this check to visually similar Unicode characters.
func validateAtTimespecOperand(spec string) error {
	if len(spec) > 0 && spec[0] == '-' {
		return fmt.Errorf("at: invalid timespec")
	}
	return nil
}

type atFunc struct{}

func (atFunc) Name() string { return "at.at" }
func (atFunc) Args() any    { return atArgs{} }
func (atFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a, ok := args.(*atArgs)
	if !ok || a == nil {
		return nil, fmt.Errorf("at.at: invalid arguments")
	}
	if err := rejectAtRunas(a.Kwargs); err != nil {
		return nil, err
	}
	spec := a.TimeSpec
	if spec == "" {
		return nil, fmt.Errorf("timespec is required, e.g. '10:30' or '+1min'")
	}
	if err := validateAtTimespecOperand(spec); err != nil {
		return nil, err
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

func registerGeneric(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{atFunc{}, atqFunc{}, atrmFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// Register installs the one canonical at-family provider for the compiling
// platform. Solaris uses at_solaris' six catalog names; every other platform
// keeps the historical generic Linux surface unchanged.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "solaris" {
		return registerSolaris(reg)
	}
	return registerGeneric(reg)
}
