// Package quota implements the Salt-compatible quota.mode state.
//
// Reference: saltstack/salt/states/quota.py @ pinned revision.
package quota

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execquota "github.com/friz-zy/statekit/modules/exec/quota"
)

// linuxOnly matches the quota execution family contract.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

type modeArgs struct {
	Name      string `statekit:"required"`
	Mode      string `statekit:"name=mode"`
	QuotaType string `statekit:"name=quotatype"`
	Test      bool   `statekit:"name=test"`
}

type modeFunc struct {
	linuxOnly
}

func (modeFunc) Name() string { return "quota.mode" }
func (modeFunc) Args() any    { return modeArgs{} }
func (modeFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*modeArgs)

	// Salt models the requested state as a boolean; "on"/"off" map onto it.
	wantOff := "on"
	switch a.Mode {
	case "on", "true", "True":
		wantOff = "on"
	case "", "off", "false", "False":
		wantOff = "off"
	default:
		return result.Failure(a.Name, fmt.Sprintf("Mode %s is invalid.", a.Mode))
	}
	fun := wantOff

	modesRaw, err := rt.Exec.Call(ctx, rt, "quota.get_mode",
		&execquota.GetModeArgs{Device: a.Name})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	modes := modesRaw.(map[string]any)

	current := ""
	if bucket, ok := modes[a.Name].(map[string]any); ok {
		current, _ = bucket[a.QuotaType].(string)
	} else if plain, ok := modes[a.Name].(string); ok {
		current = plain
	}

	ret := result.New(a.Name, "", nil, nil)
	if current == fun {
		return result.Success(a.Name, fmt.Sprintf("Quota for %s already set to %s", a.Name, fun))
	}
	if a.Test {
		ret.Comment = fmt.Sprintf("Quota for %s needs to be set to %s", a.Name, fun)
		return ret
	}

	funName := "quota." + fun
	var changed any
	if changed, err = rt.Exec.Call(ctx, rt, funName, callArgsFor(fun, a.Name)); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	if succeeded(changed) {
		return result.New(a.Name,
			fmt.Sprintf("Set quota for %s to %s", a.Name, fun),
			result.Bool(true),
			map[string]any{"quota": a.Name})
	}
	return result.Failure(a.Name, fmt.Sprintf("Failed to set quota for %s to %s", a.Name, fun))
}

// callArgsFor builds the on/off execution args for a device.
func callArgsFor(fun, device string) any {
	if fun == "on" {
		return &execquota.OnArgs{Device: device}
	}
	return &execquota.OffArgs{Device: device}
}

// succeeded mirrors Salt's truthiness of the on/off return value.
func succeeded(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

// Register installs all quota-module state functions.
func Register(reg *runtime.StateRegistry) error {
	return reg.Register(modeFunc{})
}
