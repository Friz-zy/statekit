// Package sysctl implements the Salt-compatible sysctl.present state.
//
// Reference: saltstack/salt/states/sysctl.py @ pinned revision.
package sysctl

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execsysctl "github.com/friz-zy/statekit/modules/exec/sysctl"
)

type presentArgs struct {
	Name   string `statekit:"required"`
	Value  string `statekit:"required,name=value"`
	Config string `statekit:"name=config"`
	Test   bool   `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "sysctl.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)
	value, err := rt.Exec.Call(ctx, rt, "sysctl.show", &execsysctl.ShowArgs{Name: a.Name})
	current := ""
	if err == nil {
		current, _ = value.(string)
	}
	if current == a.Value {
		return result.Success(a.Name,
			fmt.Sprintf("Sysctl %s is already set to %s", a.Name, a.Value))
	}
	changes := map[string]any{
		a.Name: map[string]any{"old": current, "new": a.Value},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Sysctl %s would be set to %s", a.Name, a.Value), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "sysctl.assign", &execsysctl.AssignArgs{
		Name: a.Name, Value: a.Value, Config: a.Config, Persist: true,
	}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all sysctl-module state functions.
func Register(reg *runtime.StateRegistry) error {
	return reg.Register(presentFunc{})
}
