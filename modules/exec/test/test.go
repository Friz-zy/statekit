// Package test implements Salt-compatible test execution functions.
//
// Reference: saltstack/salt/modules/test.py @ pinned revision:
// echo(text) returns text verbatim; ping() returns True; sleep(length)
// sleeps int(length) seconds (length has no source default) and returns
// True.
package test

import (
	"context"
	"fmt"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// timeAfter is split for hermetic tests.
var timeAfter = time.After

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

type sleepArgs struct {
	Length int `statekit:"required,name=length"`
}

type sleepFunc struct{}

func (sleepFunc) Name() string { return "test.sleep" }
func (sleepFunc) Args() any    { return sleepArgs{} }
func (sleepFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*sleepArgs)
	if a.Length < 0 {
		// time.sleep raises ValueError for negative lengths; keep the
		// exact CPython message instead of firing the timer immediately.
		return nil, fmt.Errorf("sleep length must be non-negative")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeAfter(time.Duration(a.Length) * time.Second):
		return true, nil
	}
}

// Register installs all test-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{pingFunc{}, echoFunc{}, sleepFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
