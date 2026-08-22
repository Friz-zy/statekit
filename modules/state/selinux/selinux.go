// Package selinux implements the Salt-compatible selinux.mode state.
//
// Reference: saltstack/salt/states/selinux.py @ pinned revision: mode(name)
// with name in {enforcing, permissive, disabled}.
package selinux

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execselinux "github.com/friz-zy/statekit/modules/exec/selinux"
)

// normalizeMode mirrors the exec module's mode spelling normalization.
func normalizeMode(mode string) (string, error) {
	return execselinux.NormalizeMode(mode)
}

type modeArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type modeFunc struct{}

func (modeFunc) Name() string { return "selinux.mode" }
func (modeFunc) Args() any    { return modeArgs{} }
func (modeFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*modeArgs)
	desired, err := normalizeMode(a.Name)
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}

	value, err := rt.Exec.Call(ctx, rt, "selinux.getenforce", &execselinux.GetenforceArgs{})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	current, _ := value.(string)

	if strings.EqualFold(current, desired) {
		return result.Success(a.Name,
			fmt.Sprintf("SELinux is already set to %s", modeWord(current)))
	}
	if current == "Disabled" || desired == "Disabled" {
		return result.Failure(a.Name,
			"SELinux cannot switch to or from Disabled at runtime; update the boot configuration and reboot")
	}
	changes := map[string]any{"mode": map[string]any{"old": current, "new": desired}}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("SELinux would be switched to %s", desired), changes)
	}
	applied, err := rt.Exec.Call(ctx, rt, "selinux.setenforce", &execselinux.SetenforceArgs{Mode: desired})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	changes["mode"] = map[string]any{"old": current, "new": applied}
	return result.New(a.Name, "", result.Bool(true), changes)
}

func modeWord(mode string) string {
	switch strings.ToLower(mode) {
	case "1":
		return "Enforcing"
	case "0":
		return "Permissive"
	default:
		return mode
	}
}

// Register installs all selinux-module state functions.
func Register(reg *runtime.StateRegistry) error {
	return reg.Register(modeFunc{})
}
