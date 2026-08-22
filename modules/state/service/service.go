// Package service implements Salt-compatible service state functions backed
// by the virtual service provider through the execution registry.
//
// Reference: saltstack/salt/states/service.py @ pinned revision. Verified
// Salt comments: "The service {name} is already running",
// "Service {name} is set to start". Change deltas use the plan section 9
// shape: changes: {service: {old, new}}.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execservice "github.com/friz-zy/statekit/modules/exec/service"
)

func callStatus(ctx context.Context, rt *runtime.Runtime, name string) (bool, error) {
	value, err := rt.Exec.Call(ctx, rt, "service.status", &execservice.StatusArgs{Name: name})
	if err != nil {
		return false, err
	}
	text, _ := value.(string)
	return strings.HasSuffix(text, "is running"), nil
}

type runningArgs struct {
	Name   string `statekit:"required"`
	Enable string `statekit:"name=enable"` // true/false accepted like Salt CLI
	Test   bool   `statekit:"name=test"`
}

type runningFunc struct{}

func (runningFunc) Name() string { return "service.running" }
func (runningFunc) Args() any    { return runningArgs{} }
func (runningFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*runningArgs)
	running, err := callStatus(ctx, rt, a.Name)
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if running {
		return result.Success(a.Name, fmt.Sprintf("The service %s is already running", a.Name))
	}

	changes := map[string]any{
		"service": map[string]any{"old": "stopped", "new": "running"},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Service %s is set to start", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "service.start", &execservice.NameArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	confirmed, err := callStatus(ctx, rt, a.Name)
	if err != nil || !confirmed {
		return result.Failure(a.Name, fmt.Sprintf("Service %s failed to start", a.Name))
	}
	res := result.New(a.Name, fmt.Sprintf("Service %s was started", a.Name), result.Bool(true), changes)

	if a.Enable == "true" {
		rt.Exec.Call(ctx, rt, "service.enable", &execservice.NameArgs{Name: a.Name})
	} else if a.Enable == "false" {
		rt.Exec.Call(ctx, rt, "service.disable", &execservice.NameArgs{Name: a.Name})
	}
	return res
}

type deadArgs struct {
	Name    string `statekit:"required"`
	Disable bool   `statekit:"name=disable"`
	Test    bool   `statekit:"name=test"`
}

type deadFunc struct{}

func (deadFunc) Name() string { return "service.dead" }
func (deadFunc) Args() any    { return deadArgs{} }
func (deadFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*deadArgs)
	running, err := callStatus(ctx, rt, a.Name)
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if !running {
		return result.Success(a.Name, fmt.Sprintf("The service %s is already dead", a.Name))
	}
	changes := map[string]any{
		"service": map[string]any{"old": "running", "new": "stopped"},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Service %s is set to be stopped", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "service.stop", &execservice.NameArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if a.Disable {
		rt.Exec.Call(ctx, rt, "service.disable", &execservice.NameArgs{Name: a.Name})
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type enabledArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type enabledFunc struct{}

func (enabledFunc) Name() string { return "service.enabled" }
func (enabledFunc) Args() any    { return enabledArgs{} }
func (enabledFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*enabledArgs)
	value, err := rt.Exec.Call(ctx, rt, "service.enabled", &execservice.EnabledArgs{Name: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	isEnabled, _ := value.(bool)
	if isEnabled {
		return result.Success(a.Name, fmt.Sprintf("The service %s is already enabled", a.Name))
	}
	changes := map[string]any{
		"enabled": map[string]any{"old": false, "new": true},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Service %s would be enabled", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "service.enable", &execservice.NameArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type disabledArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type disabledFunc struct{}

func (disabledFunc) Name() string { return "service.disabled" }
func (disabledFunc) Args() any    { return disabledArgs{} }
func (disabledFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*disabledArgs)
	value, err := rt.Exec.Call(ctx, rt, "service.enabled", &execservice.EnabledArgs{Name: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	isEnabled, _ := value.(bool)
	if !isEnabled {
		return result.Success(a.Name, fmt.Sprintf("The service %s is already disabled", a.Name))
	}
	changes := map[string]any{
		"enabled": map[string]any{"old": true, "new": false},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Service %s would be disabled", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "service.disable", &execservice.NameArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all service-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{runningFunc{}, deadFunc{}, enabledFunc{}, disabledFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
