// Package user implements Salt-compatible account state functions through
// the execution registry.
//
// Reference: saltstack/salt/states/user.py @ pinned revision. Present/absent
// semantics with plan section 12 test-mode comments.
package user

import (
	"context"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

type presentArgs struct {
	Name  string `statekit:"required"`
	UID   string `statekit:"name=uid"`
	GID   string `statekit:"name=gid"`
	Home  string `statekit:"name=home"`
	Shell string `statekit:"name=shell"`
	Other *any   `statekit:"name=other"`
	Test  bool   `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "user.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)
	if a.Other == nil || *a.Other == nil {
		return applyPresentLegacy(ctx, rt, a)
	}
	return applyPresentForGOOS(ctx, rt, a, runtime.CurrentGOOS())
}

func applyPresentForGOOS(ctx context.Context, rt *runtime.Runtime, a *presentArgs, goos string) result.StateResult {
	if a.Other != nil && *a.Other != nil {
		return applyPresentWithOther(ctx, rt, a, goos)
	}
	return applyPresentLegacy(ctx, rt, a)
}

const otherManagedFailure = "user.present: account update failed"

func applyPresentWithOther(ctx context.Context, rt *runtime.Runtime, a *presentArgs, goos string) result.StateResult {
	if goos != "linux" {
		return result.Failure(a.Name, otherManagedFailure)
	}
	other, err := execuser.NormalizeOther(*a.Other)
	if err != nil || !validPresentID(a.UID) || !validPresentID(a.GID) ||
		!validPresentText(a.Home) || !validPresentText(a.Shell) {
		return result.Failure(a.Name, otherManagedFailure)
	}
	entry, err := execuser.ReadLocalPasswd(rt, a.Name)
	if err != nil {
		return result.Failure(a.Name, otherManagedFailure)
	}
	if err := entry.ValidateOtherBuild(other); err != nil {
		return result.Failure(a.Name, otherManagedFailure)
	}

	type changeAction struct {
		change map[string]any
		apply  func(context.Context, *runtime.Runtime) (any, error)
		verify bool
	}
	var actions []changeAction
	if a.UID != "" && entry.UID != a.UID {
		uid := a.UID
		actions = append(actions, changeAction{
			change: map[string]any{"uid": map[string]any{"old": entry.UID, "new": uid}},
			apply: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return rt.Exec.Call(ctx, rt, "user.chuid", &execuser.ChUIDArgs{Name: a.Name, UID: uid})
			},
		})
	}
	if a.GID != "" && entry.GID != a.GID {
		gid := a.GID
		actions = append(actions, changeAction{
			change: map[string]any{"gid": map[string]any{"old": entry.GID, "new": gid}},
			apply: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return rt.Exec.Call(ctx, rt, "user.chgid", &execuser.ChGIDArgs{Name: a.Name, GID: gid})
			},
		})
	}
	if a.Home != "" && entry.Home != a.Home {
		home := a.Home
		actions = append(actions, changeAction{
			change: map[string]any{"home": map[string]any{"old": entry.Home, "new": home}},
			apply: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return rt.Exec.Call(ctx, rt, "user.chhome", &execuser.ChHomeArgs{Name: a.Name, Home: home})
			},
		})
	}
	if a.Shell != "" && entry.Shell != a.Shell {
		shell := a.Shell
		actions = append(actions, changeAction{
			change: map[string]any{"shell": map[string]any{"old": entry.Shell, "new": shell}},
			apply: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return rt.Exec.Call(ctx, rt, "user.chshell", &execuser.ChShellArgs{Name: a.Name, Shell: shell})
			},
		})
	}
	if !entry.OtherMatches(other) {
		var value any = other
		actions = append(actions, changeAction{
			change: map[string]any{"other": map[string]any{"changed": true}},
			apply: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return rt.Exec.Call(ctx, rt, "user.chother", &execuser.ChOtherArgs{Name: a.Name, Other: &value})
			},
			verify: true,
		})
	}

	if len(actions) == 0 {
		return result.Success(a.Name, fmt.Sprintf("User %s is present and up to date", a.Name))
	}
	if a.Test {
		changes := map[string]any{}
		for _, action := range actions {
			for key, value := range action.change {
				changes[key] = value
			}
		}
		return result.TestPending(a.Name, fmt.Sprintf("User %s would be updated", a.Name), changes)
	}
	changes := map[string]any{}
	for _, action := range actions {
		value, err := action.apply(ctx, rt)
		if err != nil {
			return result.Failure(a.Name, otherManagedFailure)
		}
		if action.verify {
			ok, isBool := value.(bool)
			if !isBool || !ok {
				return result.Failure(a.Name, otherManagedFailure)
			}
		}
		for key, value := range action.change {
			changes[key] = value
		}
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

func validPresentID(value string) bool {
	if value == "" {
		return true
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && n <= 4294967294
}

func validPresentText(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] == 0 || value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func applyPresentLegacy(ctx context.Context, rt *runtime.Runtime, a *presentArgs) result.StateResult {

	value, err := rt.Exec.Call(ctx, rt, "user.info", &execuser.InfoArgs{Name: a.Name})
	existing, _ := value.(map[string]any)
	found := err == nil && existing != nil

	if found {
		type changeAction struct {
			change map[string]any
			apply  func(context.Context, *runtime.Runtime) error
		}
		var actions []changeAction
		if a.UID != "" && existing["uid"] != a.UID {
			uid := a.UID
			actions = append(actions, changeAction{
				change: map[string]any{"uid": map[string]any{"old": existing["uid"], "new": uid}},
				apply: func(ctx context.Context, rt *runtime.Runtime) error {
					_, err := rt.Exec.Call(ctx, rt, "user.chuid", &execuser.ChUIDArgs{Name: a.Name, UID: uid})
					return err
				},
			})
		}
		if a.GID != "" && existing["gid"] != a.GID {
			gid := a.GID
			actions = append(actions, changeAction{
				change: map[string]any{"gid": map[string]any{"old": existing["gid"], "new": gid}},
				apply: func(ctx context.Context, rt *runtime.Runtime) error {
					_, err := rt.Exec.Call(ctx, rt, "user.chgid", &execuser.ChGIDArgs{Name: a.Name, GID: gid})
					return err
				},
			})
		}
		if a.Home != "" && existing["home"] != a.Home {
			home := a.Home
			actions = append(actions, changeAction{
				change: map[string]any{"home": map[string]any{"old": existing["home"], "new": home}},
				apply: func(ctx context.Context, rt *runtime.Runtime) error {
					_, err := rt.Exec.Call(ctx, rt, "user.chhome", &execuser.ChHomeArgs{Name: a.Name, Home: home})
					return err
				},
			})
		}
		if a.Shell != "" && existing["shell"] != a.Shell {
			shell := a.Shell
			actions = append(actions, changeAction{
				change: map[string]any{"shell": map[string]any{"old": existing["shell"], "new": shell}},
				apply: func(ctx context.Context, rt *runtime.Runtime) error {
					_, err := rt.Exec.Call(ctx, rt, "user.chshell", &execuser.ChShellArgs{Name: a.Name, Shell: shell})
					return err
				},
			})
		}

		if len(actions) == 0 {
			return result.Success(a.Name, fmt.Sprintf("User %s is present and up to date", a.Name))
		}
		if a.Test {
			changes := map[string]any{}
			for _, action := range actions {
				for key, value := range action.change {
					changes[key] = value
				}
			}
			return result.TestPending(a.Name, fmt.Sprintf("User %s would be updated", a.Name), changes)
		}
		changes := map[string]any{}
		for _, action := range actions {
			if err := action.apply(ctx, rt); err != nil {
				return result.Failure(a.Name, err.Error())
			}
			for key, value := range action.change {
				changes[key] = value
			}
		}
		return result.New(a.Name, "", result.Bool(true), changes)
	}

	changes := map[string]any{"new": a.Name}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("User %s would be created", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "user.add", &execuser.AddArgs{
		Name: a.Name, UID: a.UID, GID: a.GID, Home: a.Home, Shell: a.Shell, Create: true,
	}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type absentArgs struct {
	Name   string `statekit:"required"`
	Remove bool   `statekit:"name=purge"`
	Test   bool   `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "user.absent" }
func (absentFunc) Args() any    { return absentArgs{} }
func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	if _, err := rt.Exec.Call(ctx, rt, "user.info", &execuser.InfoArgs{Name: a.Name}); err != nil {
		return result.Success(a.Name, fmt.Sprintf("User %s is already absent", a.Name))
	}
	changes := map[string]any{"removed": a.Name}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("User %s would be removed", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "user.delete", &execuser.DeleteArgs{Name: a.Name, Remove: a.Remove}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all user-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{presentFunc{}, absentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
