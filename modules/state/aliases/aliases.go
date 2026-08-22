// Package aliases implements Salt-compatible mail alias state functions.
//
// Reference: saltstack/salt/states/aliases.py @ pinned revision:
// present(name, target) / absent(name).
package aliases

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execaliases "github.com/friz-zy/statekit/modules/exec/aliases"
)

type presentArgs struct {
	Name   string `statekit:"required"`
	Target string `statekit:"required"`
	Test   bool   `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "aliases.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)
	value, err := rt.Exec.Call(ctx, rt, "aliases.get_target", &execaliases.GetTargetArgs{Alias: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	current, _ := value.(string)
	for _, target := range strings.Split(current, ",") {
		if strings.TrimSpace(target) == a.Target {
			return result.Success(a.Name,
				fmt.Sprintf("Alias %s is already set to %s", a.Name, a.Target))
		}
	}
	changes := map[string]any{
		a.Name: map[string]any{"old": current, "new": joinTarget(current, a.Target)},
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Alias %s would be set to %s", a.Name, a.Target), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "aliases.set_target", &execaliases.SetTargetArgs{
		Alias: a.Name, Target: a.Target,
	}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, fmt.Sprintf("Alias %s set to %s", a.Name, a.Target),
		result.Bool(true), changes)
}

type absentArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "aliases.absent" }
func (absentFunc) Args() any    { return absentArgs{} }
func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	value, err := rt.Exec.Call(ctx, rt, "aliases.get_target", &execaliases.GetTargetArgs{Alias: a.Name})
	if err != nil || strings.TrimSpace(value.(string)) == "" {
		return result.Success(a.Name, fmt.Sprintf("Alias %s is already absent", a.Name))
	}
	changes := map[string]any{
		a.Name: map[string]any{"old": value.(string), "new": ""},
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("Alias %s would be removed", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "aliases.rm_alias", &execaliases.RmAliasArgs{Alias: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

func joinTarget(current, addition string) string {
	if strings.TrimSpace(current) == "" {
		return addition
	}
	return current + "," + addition
}

// Register installs all aliases-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{presentFunc{}, absentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
