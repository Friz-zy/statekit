// Package file extras: Salt-compatible search/replace and ownership
// functions layered on the runtime FileSystem and central Runner.
//
// Reference: saltstack/salt/modules/file.py @ pinned revision
// (replace, search, contains_regex, chown, chgrp).
package file

import (
	"context"
	"fmt"
	"io/fs"
	"os/user"
	"regexp"
	"strconv"

	"github.com/friz-zy/statekit/internal/runtime"
)

type searchArgs struct {
	Path    string `statekit:"required"`
	Pattern string `statekit:"required,name=pattern"`
}

type searchFunc struct{}

func (searchFunc) Name() string { return "file.search" }
func (searchFunc) Args() any    { return searchArgs{} }
func (searchFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*searchArgs)
	re, err := compileMultiline(a.Pattern)
	if err != nil {
		return nil, err
	}
	data, err := rt.FS.ReadFile(expandUser(a.Path))
	if err != nil {
		return nil, err
	}
	return re.MatchString(string(data)), nil
}

// compileMultiline compiles the pattern with Salt's default MULTILINE
// semantics so ^/$ anchor per line.
func compileMultiline(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile("(?m)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	return re, nil
}

type containsRegexArgs struct {
	Path  string `statekit:"required"`
	Regex string `statekit:"required"`
}

type containsRegexFunc struct{}

func (containsRegexFunc) Name() string { return "file.contains_regex" }
func (containsRegexFunc) Args() any    { return containsRegexArgs{} }
func (containsRegexFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return searchFunc{}.Execute(ctx, rt, &searchArgs{Path: argsPath(args), Pattern: argsPattern(args)})
}

func argsPath(args any) string {
	switch a := args.(type) {
	case *containsRegexArgs:
		return a.Path
	case *searchArgs:
		return a.Path
	}
	return ""
}

func argsPattern(args any) string {
	switch a := args.(type) {
	case *containsRegexArgs:
		return a.Regex
	case *searchArgs:
		return a.Pattern
	}
	return ""
}

type replaceArgs struct {
	Path    string `statekit:"required"`
	Pattern string `statekit:"required,name=pattern"`
	Repl    string `statekit:"required,name=repl"`
	Count   int    `statekit:"name=count"`
	Backup  bool   `statekit:"name=backup"`
}

type replaceFunc struct{}

func (replaceFunc) Name() string { return "file.replace" }
func (replaceFunc) Args() any    { return replaceArgs{} }
func (replaceFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*replaceArgs)
	path := expandUser(a.Path)
	re, err := compileMultiline(a.Pattern)
	if err != nil {
		return nil, err
	}
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	count := a.Count
	matches := re.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return false, nil
	}
	mode := fs.FileMode(0o600)
	if info, statErr := rt.FS.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if a.Backup {
		rt.FS.WriteFile(path+".bak", data, mode.Perm())
	}
	updated := data
	limit := len(matches)
	if count > 0 && count < limit {
		limit = count
	}
	for i := 0; i < limit; i++ {
		loc := re.FindIndex(updated)
		if loc == nil {
			break
		}
		next := append([]byte{}, updated[:loc[0]]...)
		next = append(next, []byte(a.Repl)...)
		updated = append(next, updated[loc[1]:]...)
	}
	if err := rt.FS.WriteFile(path, updated, mode.Perm()); err != nil {
		return nil, err
	}
	return true, nil
}

const fs0600 = 0o600

type chownArgs struct {
	Path  string `statekit:"required"`
	User  string `statekit:"name=user"`
	Group string `statekit:"name=group"`
}

type chownFunc struct{}

func (chownFunc) Name() string { return "file.chown" }
func (chownFunc) Args() any    { return chownArgs{} }
func (chownFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chownArgs)
	uid, gid := -1, -1
	if a.User != "" {
		u, err := user.Lookup(a.User)
		if err != nil {
			return nil, fmt.Errorf("user %q not found: %w", a.User, err)
		}
		parsed, parseErr := strconv.Atoi(u.Uid)
		if parseErr != nil {
			return nil, parseErr
		}
		uid = parsed
	}
	if a.Group != "" {
		g, err := user.LookupGroup(a.Group)
		if err != nil {
			return nil, fmt.Errorf("group %q not found: %w", a.Group, err)
		}
		parsed, parseErr := strconv.Atoi(g.Gid)
		if parseErr != nil {
			return nil, parseErr
		}
		gid = parsed
	}
	if err := rt.FS.Chown(expandUser(a.Path), uid, gid); err != nil {
		return nil, err
	}
	return true, nil
}

type chgrpArgs struct {
	Path  string `statekit:"required"`
	Group string `statekit:"required,name=group"`
}

type chgrpFunc struct{}

func (chgrpFunc) Name() string { return "file.chgrp" }
func (chgrpFunc) Args() any    { return chgrpArgs{} }
func (chgrpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*chgrpArgs)
	return chownFunc{}.Execute(ctx, rt, &chownArgs{Path: a.Path, Group: a.Group})
}
