// Package sysfs implements the Salt-compatible sysfs state family.
//
// Reference: saltstack/salt/states/sysfs.py @ pinned revision.
//
// Contract note (init.md section 28): Salt declares the config parameter
// but never reads it; StateKit accepts and ignores it the same way so
// state definitions keep working.
package sysfs

import (
	"context"
	"regexp"

	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
)

// selectionRe strips "everything through the last '['" and "everything
// from the first ']'" like Salt's re.sub(r"(.*\[|\].*)", "", current),
// extracting the selected option from SysFS choice lists.
var selectionRe = regexp.MustCompile(`(.*\[|\].*)`)

type PresentArgs struct {
	Name   string  `statekit:"required"`
	Value  string  `statekit:"required,name=value"`
	Config *string `statekit:"name=config"`
	Test   bool    `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "sysfs.present" }
func (presentFunc) Args() any    { return PresentArgs{} }

// Apply ensures the named SysFS attribute carries the defined value.
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*PresentArgs)
	ret := result.StateResult{Name: a.Name, Result: boolPtr(true), Changes: map[string]any{}}

	currentRaw, err := rt.Exec.Call(ctx, rt, "sysfs.read", &execsysfs.ReadArgs{Key: []any{a.Name}})
	if err != nil || currentRaw == false {
		ret.Result = boolPtr(false)
		ret.Comment = "SysFS attribute " + a.Name + " doesn't exist."
		return ret
	}

	switch current := currentRaw.(type) {
	case map[string]any:
		// A dict means name resolved to an object, not an attribute.
		ret.Result = boolPtr(false)
		ret.Comment = a.Name + " is not a SysFS attribute."
		return ret
	case string:
		current = selectionRe.ReplaceAllString(current, "")
		if current == a.Value {
			ret.Comment = "SysFS attribute " + a.Name + " is already set."
			return ret
		}
	}

	// Change required.
	ret.Result = nil
	if a.Test {
		ret.Comment = "SysFS attribute " + a.Name + " set to be changed."
		return ret
	}

	update, err := rt.Exec.Call(ctx, rt, "sysfs.write", &execsysfs.WriteArgs{Key: a.Name, Value: a.Value})
	if err != nil || update == false {
		ret.Result = boolPtr(false)
		ret.Comment = "Failed to set " + a.Name + " to " + a.Value
		return ret
	}
	ret.Result = boolPtr(true)
	ret.Changes[a.Name] = a.Value
	ret.Comment = "Updated SysFS attribute " + a.Name + " to " + a.Value
	return ret
}

func boolPtr(b bool) *bool { return &b }

// Register installs the sysfs state functions. The state requires the
// sysfs exec module exactly like Salt's __virtual__ guard.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		presentFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
