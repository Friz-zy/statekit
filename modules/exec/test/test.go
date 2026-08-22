// Package test implements Salt-compatible test execution functions.
//
// Reference: saltstack/salt/modules/test.py @ pinned revision:
// echo(text) returns text verbatim; ping() returns True.
package test

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
)

type pingArgs struct{}

type pingFunc struct{}

func (pingFunc) Name() string { return "test.ping" }
func (pingFunc) Args() any    { return pingArgs{} }
func (pingFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return true, nil
}

type echoArgs struct {
	Text string `statekit:"required"`
}

type echoFunc struct{}

func (echoFunc) Name() string { return "test.echo" }
func (echoFunc) Args() any    { return echoArgs{} }
func (echoFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*echoArgs)
	return a.Text, nil
}

// Register installs all test-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{pingFunc{}, echoFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
