// Package ini implements Salt-compatible INI state functions.
//
// Reference: saltstack/salt/states/ini_manage.py @ pinned revision:
// options_present(name, data) / options_absent(name, sections).
package ini

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execini "github.com/friz-zy/statekit/modules/exec/ini"
)

type optionsPresentArgs struct {
	Name      string         `statekit:"required"`
	Data      map[string]any `statekit:"required,name=data"`
	Separator string         `statekit:"name=separator"`
	Test      bool           `statekit:"name=test"`
}

type optionsPresentFunc struct{}

func (optionsPresentFunc) Name() string { return "ini.options_present" }
func (optionsPresentFunc) Args() any    { return optionsPresentArgs{} }
func (optionsPresentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*optionsPresentArgs)

	if a.Test {
		// Compute the delta without mutating anything (plan section 12).
		changes := map[string]any{}
		for _, section := range sortedSections(a.Data) {
			pairs, _ := a.Data[section].(map[string]any)
			for _, key := range sortedPairKeys(pairs) {
				value, _ := rt.Exec.Call(ctx, rt, "ini.get_option", &execini.GetOptionArgs{
					FileName: a.Name, Section: section, Option: key, Separator: a.Separator,
				})
				current, _ := value.(string)
				desired := formatScalar(pairs[key])
				if current != desired {
					changes[section+"."+key] = map[string]any{"old": current, "new": desired}
				}
			}
		}
		if len(changes) == 0 {
			return result.Success(a.Name,
				fmt.Sprintf("INI %s is already in the correct state", a.Name))
		}
		return result.TestPending(a.Name,
			fmt.Sprintf("INI %s would have %d option(s) changed", a.Name, len(changes)), changes)
	}

	value, err := rt.Exec.Call(ctx, rt, "ini.set_option", &execini.SetOptionArgs{
		FileName: a.Name, Sections: a.Data, Separator: a.Separator,
	})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	changes, _ := value.(map[string]any)
	if len(changes) == 0 {
		return result.Success(a.Name,
			fmt.Sprintf("INI %s is already in the correct state", a.Name))
	}
	return result.New(a.Name, fmt.Sprintf("INI %s updated", a.Name),
		result.Bool(true), changes)
}

// formatScalar renders a structured value the way the INI writer will.
func formatScalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func sortedSections(data map[string]any) []string {
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedPairKeys(pairs map[string]any) []string {
	keys := make([]string, 0, len(pairs))
	for key := range pairs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type optionsAbsentArgs struct {
	Name      string   `statekit:"required"`
	Sections  []string `statekit:"required,name=sections"`
	Separator string   `statekit:"name=separator"`
	Test      bool     `statekit:"name=test"`
}

type optionsAbsentFunc struct{}

func (optionsAbsentFunc) Name() string { return "ini.options_absent" }
func (optionsAbsentFunc) Args() any    { return optionsAbsentArgs{} }
func (optionsAbsentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*optionsAbsentArgs)
	changes := map[string]any{}
	for _, entry := range a.Sections {
		section, option := splitEntry(entry)
		if option == "" {
			continue
		}
		value, err := rt.Exec.Call(ctx, rt, "ini.get_option", &execini.GetOptionArgs{
			FileName: a.Name, Section: section, Option: option, Separator: a.Separator,
		})
		if err != nil || value == nil {
			continue
		}
		if text, _ := value.(string); strings.TrimSpace(text) != "" {
			changes[entry] = map[string]any{"old": text, "new": ""}
		}
	}

	if len(changes) == 0 {
		return result.Success(a.Name, fmt.Sprintf("INI %s is already in the correct state", a.Name))
	}
	if a.Test {
		return result.TestPending(a.Name,
			fmt.Sprintf("INI %s would have %d option(s) removed", a.Name, len(changes)), changes)
	}
	for _, entry := range sortedKeys(changes) {
		section, option := splitEntry(entry)
		if _, err := rt.Exec.Call(ctx, rt, "ini.remove_option", &execini.RemoveOptionArgs{
			FileName: a.Name, Section: section, Options: []string{option}, Separator: a.Separator,
		}); err != nil {
			return result.Failure(a.Name, err.Error())
		}
	}
	return result.New(a.Name, fmt.Sprintf("INI %s updated", a.Name), result.Bool(true), changes)
}

func splitEntry(entry string) (string, string) {
	idx := strings.LastIndexByte(entry, '.')
	if idx <= 0 || idx == len(entry)-1 {
		return entry, ""
	}
	return entry[:idx], entry[idx+1:]
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Register installs all ini-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{optionsPresentFunc{}, optionsAbsentFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
