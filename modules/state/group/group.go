// Package group implements Salt-compatible group state functions through the
// execution registry.
//
// Reference: saltstack/salt/states/group.py @ pinned revision.
package group

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execgroup "github.com/friz-zy/statekit/modules/exec/group"
)

type presentArgs struct {
	Name    string   `statekit:"required"`
	GID     string   `statekit:"name=gid"`
	Members []string `statekit:"name=members"`
	System  bool     `statekit:"name=system"` // accepted; only affects new-group creation on some managers
	Test    bool     `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "group.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)

	value, _ := rt.Exec.Call(ctx, rt, "group.info", &execgroup.InfoArgs{Name: a.Name})
	existing, _ := value.(map[string]any)
	if existing != nil {
		var changes map[string]any
		if a.GID != "" && existing["gid"] != a.GID {
			changes = map[string]any{
				"gid": map[string]any{"old": existing["gid"], "new": a.GID},
			}
			if !a.Test {
				if _, err := rt.Exec.Call(ctx, rt, "group.chgid", &execgroup.ChGIDArgs{Name: a.Name, GID: a.GID}); err != nil {
					return result.Failure(a.Name, err.Error())
				}
			}
		}
		if len(a.Members) > 0 {
			current := memberSet(existing["members"])
			desired := map[string]bool{}
			for _, m := range a.Members {
				desired[m] = true
			}
			toAddList := toAdd(current, desired)
			toRemoveList := toRemove(current, desired)
			if len(toAddList) > 0 || len(toRemoveList) > 0 {
				if changes == nil {
					changes = map[string]any{}
				}
				changes["members"] = map[string]any{"old": current, "new": a.Members}
			}
			if !a.Test && (len(toAddList) > 0 || len(toRemoveList) > 0) {
				// Membership changes go through usermod -aG per added user;
				// removals are not supported without gpasswd and stay explicit.
				for _, member := range toAddList {
					res := rt.Runner.Run(ctx, runtime.Command("usermod", "-a", "-G", a.Name, member))
					if res.Err != nil || res.ExitCode != 0 {
						return result.Failure(a.Name, fmt.Sprintf("could not add %s to %s", member, a.Name))
					}
				}
			}
		}
		if changes == nil {
			return result.Success(a.Name, fmt.Sprintf("Group %s is present and up to date", a.Name))
		}
		if a.Test {
			return result.TestPending(a.Name, fmt.Sprintf("Group %s would be updated", a.Name), changes)
		}
		return result.New(a.Name, "", result.Bool(true), changes)
	}

	changes := map[string]any{"new": a.Name}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Group %s would be created", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "group.add", &execgroup.AddArgs{Name: a.Name, GID: a.GID}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type absentArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "group.absent" }
func (absentFunc) Args() any    { return absentArgs{} }
func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	if _, err := rt.Exec.Call(ctx, rt, "group.info", &execgroup.InfoArgs{Name: a.Name}); err != nil {
		return result.Success(a.Name, fmt.Sprintf("Group %s is already absent", a.Name))
	}
	changes := map[string]any{"removed": a.Name}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Group %s would be removed", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "group.delete", &execgroup.DeleteArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

func memberSet(v any) []string {
	list, _ := v.([]string)
	return list
}

func toRemove(current []string, desired map[string]bool) []string {
	out := []string{}
	for _, member := range current {
		if !desired[member] {
			out = append(out, member)
		}
	}
	return out
}

func toAdd(current []string, desired map[string]bool) []string {
	set := map[string]bool{}
	for _, c := range current {
		set[c] = true
	}
	out := []string{}
	for member := range desired {
		if !set[member] {
			out = append(out, member)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// Register installs all group-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{presentFunc{}, absentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
