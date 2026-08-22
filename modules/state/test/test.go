// Package test implements Salt-compatible test state functions.
//
// Reference: saltstack/salt/states/test.py @ pinned revision:
// nop delegates to succeed_without_changes, producing
// {name, changes: {}, result: true, comment: "Success!"}.
package test

import (
	"context"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
)

type nopArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type nopFunc struct{}

func (nopFunc) Name() string { return "test.nop" }
func (nopFunc) Args() any    { return nopArgs{} }
func (nopFunc) Apply(_ context.Context, _ *runtime.Runtime, args any) result.StateResult {
	a := args.(*nopArgs)
	return result.Success(a.Name, "Success!")
}

// Register installs all test-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{nopFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
