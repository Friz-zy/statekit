// INI execution functions. Reference: saltstack/salt/modules/ini_manage.py
// @ pinned revision.
package ini

import (
	"context"
	"fmt"
	"sort"

	"github.com/friz-zy/statekit/internal/runtime"
)

type GetOptionArgs struct {
	FileName  string `statekit:"required,name=file_name"`
	Section   string `statekit:"required"`
	Option    string `statekit:"required"`
	Separator string `statekit:"name=separator"`
}

type getOptionFunc struct{}

func (getOptionFunc) Name() string { return "ini.get_option" }
func (getOptionFunc) Args() any    { return GetOptionArgs{} }
func (getOptionFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetOptionArgs)
	doc, err := load(rt, a.FileName, a.Separator)
	if err != nil {
		return "", nil
	}
	if section, ok := doc.sections[a.Section]; ok {
		return section.values[a.Option], nil
	}
	return "", nil
}

type GetIniArgs struct {
	FileName  string `statekit:"required,name=file_name"`
	Separator string `statekit:"name=separator"`
}

type getIniFunc struct{}

func (getIniFunc) Name() string { return "ini.get_ini" }
func (getIniFunc) Args() any    { return GetIniArgs{} }
func (getIniFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetIniArgs)
	doc, err := load(rt, a.FileName, a.Separator)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	names := append([]string{}, doc.order...)
	sort.Strings(names)
	for _, name := range names {
		values := map[string]string{}
		for key, value := range doc.sections[name].values {
			values[key] = value
		}
		out[name] = values
	}
	return out, nil
}

type SetOptionArgs struct {
	FileName  string         `statekit:"required,name=file_name"`
	Sections  map[string]any `statekit:"required,name=sections"`
	Separator string         `statekit:"name=separator"`
}

type setOptionFunc struct{}

func (setOptionFunc) Name() string { return "ini.set_option" }
func (setOptionFunc) Args() any    { return SetOptionArgs{} }
func (setOptionFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetOptionArgs)
	separator := a.Separator
	if separator == "" {
		separator = "="
	}
	doc, err := load(rt, a.FileName, separator)
	if err != nil {
		doc = newDocument()
	}

	changes := map[string]any{}
	names := make([]string, 0, len(a.Sections))
	for name := range a.Sections {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		section := doc.ensure(name)
		pairs, ok := toStringMap(a.Sections[name])
		if !ok {
			return nil, fmt.Errorf("section %q must be an object of option=value pairs", name)
		}
		keys := make([]string, 0, len(pairs))
		for key := range pairs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			desired := pairs[key]
			old, existed := section.values[key]
			if existed && old == desired {
				continue
			}
			if !existed {
				section.order = append(section.order, key)
			}
			section.values[key] = desired
			changes[name+"."+key] = map[string]any{"old": old, "new": desired}
		}
	}

	if len(changes) > 0 {
		if err := writeFile(rt, a.FileName, doc, separator); err != nil {
			return nil, fmt.Errorf("could not write %s: %w", a.FileName, err)
		}
	}
	return changes, nil
}

type RemoveOptionArgs struct {
	FileName  string   `statekit:"required,name=file_name"`
	Section   string   `statekit:"required"`
	Options   []string `statekit:"required,name=options"`
	Separator string   `statekit:"name=separator"`
}

type removeOptionFunc struct{}

func (removeOptionFunc) Name() string { return "ini.remove_option" }
func (removeOptionFunc) Args() any    { return RemoveOptionArgs{} }
func (removeOptionFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RemoveOptionArgs)
	separator := a.Separator
	if separator == "" {
		separator = "="
	}
	doc, err := load(rt, a.FileName, separator)
	if err != nil {
		return map[string]any{}, nil
	}
	section, ok := doc.sections[a.Section]
	if !ok {
		return map[string]any{}, nil
	}
	removed := map[string]any{}
	for _, option := range a.Options {
		if old, present := section.values[option]; present {
			delete(section.values, option)
			for i, key := range section.order {
				if key == option {
					section.order = append(section.order[:i], section.order[i+1:]...)
					break
				}
			}
			removed[option] = old
		}
	}
	if len(removed) > 0 {
		if err := writeFile(rt, a.FileName, doc, separator); err != nil {
			return nil, fmt.Errorf("could not write %s: %w", a.FileName, err)
		}
	}
	return removed, nil
}

// Register installs all ini-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getOptionFunc{}, getIniFunc{}, setOptionFunc{}, removeOptionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
