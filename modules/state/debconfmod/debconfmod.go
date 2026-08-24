// Package debconfmod implements Salt's debconf state functions: set and
// set_file, delegating to the registered debconf.* execution functions.
//
// Reference: saltstack/salt/states/debconfmod.py @ pinned revision.
// Behavioral tests mapped from
// saltstack/tests/pytests/unit/states/test_debconfmod.py.
package debconfmod

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execdebconf "github.com/friz-zy/statekit/modules/exec/debconfmod"
)

type setFileArgs struct {
	Name     string         `statekit:"required"`
	Source   string         `statekit:"required,name=source"`
	Template *string        `statekit:"name=template"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
	Test     bool           `statekit:"name=test"`
}

type setFileFunc struct{}

func (setFileFunc) Name() string { return "debconf.set_file" }
func (setFileFunc) Args() any    { return setFileArgs{} }

func (setFileFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*setFileArgs)
	ret := result.New(a.Name, "", nil, map[string]any{})

	if a.Context == nil {
		a.Context = map[string]any{}
	}
	if a.Defaults == nil {
		a.Defaults = map[string]any{}
	}
	if a.Test {
		ret.Result = nil
		ret.Comment = "Debconf selections would have been set."
		return ret
	}

	if a.Template != nil && *a.Template != "" {
		res, err := rt.Exec.Call(ctx, rt, "debconf.set_template", &execdebconf.SetTemplateArgs{
			Path: a.Source, Template: *a.Template,
			Context: a.Context, Defaults: a.Defaults,
			Saltenv: "base",
		})
		if err != nil {
			ret.Result = result.Bool(false)
			ret.Comment = fmt.Sprintf("Unable to set debconf selections from file: %v", err)
			return ret
		}
		if b, ok := res.(bool); ok && b {
			ret.Result = result.Bool(true)
			ret.Comment = "Debconf selections were set."
			return ret
		}
	}

	res, err := rt.Exec.Call(ctx, rt, "debconf.set_file",
		&execdebconf.SetFileArgs{Path: a.Source, Saltenv: "base"})
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}
	if b, ok := res.(bool); ok && b {
		ret.Result = result.Bool(true)
		ret.Comment = "Debconf selections were set."
		return ret
	}

	ret.Result = result.Bool(false)
	ret.Comment = "Unable to set debconf selections from file."
	return ret
}

type setDataEntry struct {
	typ   string
	value any
}

type setArgs struct {
	Name string         `statekit:"required"`
	Data map[string]any `statekit:"required,name=data"`
	Test bool           `statekit:"name=test"`
}

type setFunc struct{}

func (setFunc) Name() string { return "debconf.set" }
func (setFunc) Args() any    { return setArgs{} }

func (setFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*setArgs)
	ret := result.New(a.Name, "", result.Bool(true), map[string]any{})

	showRes, err := rt.Exec.Call(ctx, rt, "debconf.show", &execdebconf.ShowArgs{Name: a.Name})
	if err != nil {
		ret.Result = result.Bool(false)
		ret.Comment = err.Error()
		return ret
	}
	var current [][]string
	if showRes != nil {
		current, _ = showRes.([][]string)
	}

	data := a.Data
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		entry, ok := data[key].(map[string]any)
		if !ok {
			continue
		}
		qType, _ := entry["type"].(string)
		value := entry["value"]

		// Booleans must serialize lowercase for debconf.
		if qType == "boolean" {
			value = boolLower(value)
		}
		valueStr := scalarString(value)

		unchanged := false
		for _, row := range current {
			if len(row) == 3 && row[0] == key && row[1] == qType && row[2] == valueStr {
				unchanged = true
				break
			}
		}
		if unchanged {
			if ret.Comment == "" {
				ret.Comment = "Unchanged answers: "
			}
			ret.Comment += key + " "
			continue
		}

		if a.Test {
			ret.Result = nil
			ret.Changes[key] = fmt.Sprintf("New value: %s", valueStr)
			continue
		}

		res, serr := rt.Exec.Call(ctx, rt, "debconf.set", &execdebconf.SetArgs{
			Package: a.Name, Question: key, Type: qType, Value: valueStr,
		})
		okSet := false
		if serr == nil {
			okSet, _ = res.(bool)
		}
		switch {
		case okSet && qType == "password":
			ret.Changes[key] = "(password hidden)"
		case okSet:
			ret.Changes[key] = valueStr
		default:
			ret.Result = result.Bool(false)
			ret.Comment = "Some settings failed to be applied."
			ret.Changes[key] = "Failed to set!"
		}
	}

	if len(ret.Changes) == 0 {
		ret.Comment = "All specified answers are already set"
	}
	return ret
}

func boolLower(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		if strings.EqualFold(x, "true") {
			return "true"
		}
		return "false"
	}
	if isTruthy(v) {
		return "true"
	}
	return "false"
}

func isTruthy(v any) bool {
	b, ok := v.(bool)
	if ok {
		return b
	}
	s, ok := v.(string)
	if ok {
		return s != "" && !strings.EqualFold(s, "false")
	}
	return v != nil
}

func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case int:
		return fmt.Sprintf("%d", x)
	}
	return fmt.Sprintf("%v", v)
}

// Register installs all debconf state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		setFileFunc{},
		setFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
