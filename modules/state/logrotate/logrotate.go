// Package logrotate implements the logrotate state: set, delegating to
// the registered logrotate.* execution functions.
//
// Reference: saltstack/salt/states/logrotate.py @ pinned revision.
package logrotate

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
)

type setArgs struct {
	Name     string  `statekit:"required"`
	Key      string  `statekit:"required,name=key"`
	Value    string  `statekit:"required,name=value"`
	Setting  *string `statekit:"name=setting"`
	ConfFile *string `statekit:"name=conf_file"`
	Test     bool    `statekit:"name=test"`
}

type setFunc struct{}

func (setFunc) Name() string { return "logrotate.set_" }
func (setFunc) Args() any    { return setArgs{} }

func (setFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*setArgs)
	ret := result.New(a.Name, "", nil, map[string]any{})

	value := convertIfInt(a.Value)

	var currentValue any
	if a.Setting == nil {
		currentValue = callGet(rt, ctx, &execlogrotate.GetArgs{Key: a.Key, ConfFile: a.ConfFile})
	} else {
		vs := a.Value
		currentValue = callGet(rt, ctx, &execlogrotate.GetArgs{Key: a.Key, Value: &vs, ConfFile: a.ConfFile})
	}

	if a.Setting == nil {
		if equalAny(currentValue, value) {
			ret.Result = result.Bool(true)
			ret.Comment = fmt.Sprintf("Command '%s' already has value: %v", a.Key, value)
			return ret
		}
		ret.Changes = map[string]any{"old": currentValue, "new": value}
	}

	if a.Test {
		if a.Setting == nil {
			ret.Comment = fmt.Sprintf("Command '%s' will be set to value: %v", a.Key, value)
		} else {
			ret.Comment = fmt.Sprintf("Command '%s' will be set to value: %s setting: %s",
				a.Key, a.Value, *a.Setting)
			ret.Changes = map[string]any{"old": currentValue, "new": *a.Setting}
		}
		return ret
	}

	okAny, err := execlogrotate.SetFunc{}.Execute(ctx, rt, &execlogrotate.SetArgs{
		Key: a.Key, Value: a.Value, Setting: a.Setting, ConfFile: a.ConfFile,
	})
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}
	ok, _ := okAny.(bool)
	ret.Changes = map[string]any{"old": currentValue, "new": a.Value}
	if ok {
		ret.Result = result.Bool(true)
		if a.Setting == nil {
			ret.Comment = fmt.Sprintf("Set command '%s' value: %v", a.Key, value)
		} else {
			ret.Comment = fmt.Sprintf("Set command '%s' value: %s setting: %s",
				a.Key, a.Value, *a.Setting)
		}
		return ret
	}
	ret.Result = result.Bool(false)
	if a.Setting == nil {
		ret.Comment = fmt.Sprintf("Unable to set command '%s' value: %v", a.Key, value)
	} else {
		ret.Comment = fmt.Sprintf("Unable to set command '%s' value: %s", a.Key, a.Value)
	}
	return ret
}

func callGet(rt *runtime.Runtime, ctx context.Context, args *execlogrotate.GetArgs) any {
	res, err := rt.Exec.Call(ctx, rt, "logrotate.get", args)
	if err != nil {
		return false
	}
	return res
}

func convertIfInt(value string) any {
	if n, err := strconvAtoi(value); err == nil {
		return n
	}
	return value
}

func strconvAtoi(s string) (int, error) {
	n := 0
	neg := false
	for i, c := range s {
		switch {
		case c == '-' && i == 0:
			neg = true
		case c >= '0' && c <= '9':
			n = n*10 + int(c-'0')
		default:
			return 0, fmt.Errorf("not int")
		}
	}
	if neg {
		n = -n
	}
	return n, nil
}

func equalAny(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	ab, abok := a.(bool)
	bb, bbok := b.(bool)
	if abok && bbok {
		return ab == bb
	}
	an, anok := a.(int)
	bn, bnok := b.(int)
	if anok && bnok {
		return an == bn
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func strPtr(s string) *string { return &s }

// Register installs the logrotate state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{setFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
