// Package aliases implements Salt-compatible mail alias management.
//
// Reference: saltstack/salt/modules/aliases.py @ pinned revision. The alias
// database (/etc/aliases) is read and written through the runtime FileSystem.
// Leading comments are preserved on rewrite.
package aliases

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const aliasesPath = "/etc/aliases"

type entry struct {
	targets []string
}

type parsedFile struct {
	order    []string
	byAlias  map[string]entry
	comments []string // leading comments and blank lines
}

func parse(content string) *parsedFile {
	file := &parsedFile{byAlias: map[string]entry{}}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			if len(file.order) == 0 {
				file.comments = append(file.comments, line)
			}
			continue
		}
		name, targets, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		list := []string{}
		for _, target := range strings.Split(targets, ",") {
			if target = strings.TrimSpace(target); target != "" {
				list = append(list, target)
			}
		}
		entry, seen := file.byAlias[name]
		if !seen {
			file.order = append(file.order, name)
		}
		entry.targets = append(entry.targets, list...)
		file.byAlias[name] = entry
	}
	return file
}

func (f *parsedFile) serialize() string {
	lines := append([]string{}, f.comments...)
	for _, name := range f.order {
		targets := f.byAlias[name].targets
		if len(targets) == 0 {
			continue
		}
		lines = append(lines, name+": "+strings.Join(targets, ", "))
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func load(rt *runtime.Runtime) *parsedFile {
	data, err := rt.FS.ReadFile(aliasesPath)
	if err != nil {
		return &parsedFile{byAlias: map[string]entry{}}
	}
	return parse(string(data))
}

func save(rt *runtime.Runtime, file *parsedFile) error {
	mode := fs.FileMode(0o644)
	if info, err := rt.FS.Stat(aliasesPath); err == nil {
		mode = info.Mode().Perm()
	}
	return rt.FS.WriteFile(aliasesPath, []byte(file.serialize()), mode)
}

type ListAliasesArgs struct{}

type listFunc struct{}

func (listFunc) Name() string { return "aliases.list_aliases" }
func (listFunc) Args() any    { return ListAliasesArgs{} }
func (listFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	file := load(rt)
	out := map[string]any{}
	for name, entry := range file.byAlias {
		out[name] = strings.Join(entry.targets, ",")
	}
	return out, nil
}

type GetTargetArgs struct {
	Alias string `statekit:"required"`
}

type getTargetFunc struct{}

func (getTargetFunc) Name() string { return "aliases.get_target" }
func (getTargetFunc) Args() any    { return GetTargetArgs{} }
func (getTargetFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetTargetArgs)
	file := load(rt)
	entry, ok := file.byAlias[a.Alias]
	if !ok || len(entry.targets) == 0 {
		return "", nil
	}
	return strings.Join(entry.targets, ","), nil
}

type HasTargetArgs struct {
	Alias  string `statekit:"required"`
	Target string `statekit:"required"`
}

type hasTargetFunc struct{}

func (hasTargetFunc) Name() string { return "aliases.has_target" }
func (hasTargetFunc) Args() any    { return HasTargetArgs{} }
func (hasTargetFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HasTargetArgs)
	for _, target := range load(rt).byAlias[a.Alias].targets {
		if target == a.Target {
			return true, nil
		}
	}
	return false, nil
}

type SetTargetArgs struct {
	Alias  string `statekit:"required"`
	Target string `statekit:"required"`
}

type setTargetFunc struct{}

func (setTargetFunc) Name() string { return "aliases.set_target" }
func (setTargetFunc) Args() any    { return SetTargetArgs{} }
func (setTargetFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetTargetArgs)
	file := load(rt)
	existing := file.byAlias[a.Alias]
	for _, target := range existing.targets {
		if target == a.Target {
			return false, nil
		}
	}
	if _, known := file.byAlias[a.Alias]; !known {
		file.order = append(file.order, a.Alias)
	}
	existing.targets = append(existing.targets, a.Target)
	file.byAlias[a.Alias] = existing
	if err := save(rt, file); err != nil {
		return nil, fmt.Errorf("could not update %s: %w", aliasesPath, err)
	}
	return true, nil
}

type RmAliasArgs struct {
	Alias string `statekit:"required"`
}

type rmAliasFunc struct{}

func (rmAliasFunc) Name() string { return "aliases.rm_alias" }
func (rmAliasFunc) Args() any    { return RmAliasArgs{} }
func (rmAliasFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmAliasArgs)
	file := load(rt)
	if _, ok := file.byAlias[a.Alias]; !ok {
		return false, nil
	}
	delete(file.byAlias, a.Alias)
	filtered := []string{}
	for _, name := range file.order {
		if name != a.Alias {
			filtered = append(filtered, name)
		}
	}
	file.order = filtered
	if err := save(rt, file); err != nil {
		return nil, fmt.Errorf("could not update %s: %w", aliasesPath, err)
	}
	return true, nil
}

// Register installs all aliases-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{}, getTargetFunc{}, hasTargetFunc{}, setTargetFunc{}, rmAliasFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
