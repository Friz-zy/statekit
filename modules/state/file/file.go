// Package file implements Salt-compatible file state functions.
//
// Reference: saltstack/salt/states/file.py @ pinned revision. Verified Salt
// strings are preserved (e.g. "The directory {name} is in the correct state",
// "File {name} is set for removal"); test-mode comments follow plan section
// 12 ("{X} would be {action}") and remaining divergences are noted inline.
package file

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
)

func desiredContents(ctx context.Context, rt *runtime.Runtime, source string) ([]byte, error) {
	if source == "" {
		return nil, nil
	}
	return rt.FS.ReadFile(source)
}

func equalContent(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type managedArgs struct {
	Name     string `statekit:"required"`
	Contents string `statekit:"name=contents"`
	Source   string `statekit:"name=source"`
	Mode     string `statekit:"name=mode"`
	Test     bool   `statekit:"name=test"`
}

type managedFunc struct{}

func (managedFunc) Name() string { return "file.managed" }
func (managedFunc) Args() any    { return managedArgs{} }
func (managedFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*managedArgs)

	var want []byte
	if a.Source != "" {
		data, err := desiredContents(ctx, rt, a.Source)
		if err != nil {
			return result.Failure(a.Name, fmt.Sprintf("could not read source %q: %v", a.Source, err))
		}
		want = data
	} else {
		want = []byte(a.Contents)
	}

	mode := fs.FileMode(0o644)
	if a.Mode != "" {
		parsed, err := parseOctal(a.Mode)
		if err != nil {
			return result.Failure(a.Name, err.Error())
		}
		mode = parsed
	}

	existing, statErr := rt.FS.ReadFile(a.Name)
	if statErr == nil && equalContent(existing, want) && (a.Mode == "" || modeMatches(rt, a.Name, mode)) {
		res := result.Success(a.Name, "File "+a.Name+" is in the correct state")
		return res
	}

	changes := map[string]any{}
	comment := ""
	if statErr != nil {
		changes["newfile"] = a.Name
		comment = "File " + a.Name + " would be created"
	} else {
		changes["contents"] = map[string]any{
			"old": string(existing),
			"new": string(want),
		}
		comment = "File " + a.Name + " would be updated"
	}
	if a.Mode != "" && !modeMatches(rt, a.Name, mode) {
		changes["mode"] = map[string]any{"old": currentMode(rt, a.Name), "new": a.Mode}
	}

	if a.Test {
		return result.TestPending(a.Name, comment, changes)
	}

	if dir := dirOf(a.Name); dir != "" && dir != "/" {
		rt.FS.MkdirAll(dir, 0o755)
	}
	if err := rt.FS.WriteFile(a.Name, want, mode); err != nil {
		return result.Failure(a.Name, fmt.Sprintf("could not write %q: %v", a.Name, err))
	}
	applied := "File " + a.Name + " updated"
	if _, ok := changes["newfile"]; ok {
		applied = "File " + a.Name + " created"
	}
	return result.New(a.Name, applied, result.Bool(true), changes)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

func modeMatches(rt *runtime.Runtime, path string, mode fs.FileMode) bool {
	info, err := rt.FS.Stat(path)
	if err != nil {
		return true
	}
	return info.Mode().Perm() == mode.Perm()
}

func currentMode(rt *runtime.Runtime, path string) string {
	info, err := rt.FS.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

func parseOctal(mode string) (fs.FileMode, error) {
	var parsed uint64
	digits := mode
	for len(digits) > 0 && digits[0] == '0' {
		digits = digits[1:]
	}
	if digits == "" {
		digits = "0"
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '7' {
			return 0, fmt.Errorf("invalid octal mode %q", mode)
		}
		parsed = parsed*8 + uint64(c-'0')
	}
	return fs.FileMode(parsed).Perm(), nil
}

type absentArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "file.absent" }
func (absentFunc) Args() any    { return absentArgs{} }
func (absentFunc) Apply(_ context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*absentArgs)
	if _, err := rt.FS.Lstat(a.Name); err != nil {
		// Salt returns an empty-comment success when nothing needs removal.
		return result.Success(a.Name, "")
	}
	if a.Test {
		return result.TestPending(a.Name, "File "+a.Name+" is set for removal", map[string]any{
			"removed": a.Name,
		})
	}
	if err := rt.FS.RemoveAll(a.Name); err != nil {
		return result.Failure(a.Name, fmt.Sprintf("could not remove %q: %v", a.Name, err))
	}
	return result.New(a.Name, "Removed file "+a.Name, result.Bool(true), map[string]any{
		"removed": a.Name,
	})
}

type directoryArgs struct {
	Name string `statekit:"required"`
	Mode string `statekit:"name=mode"`
	Test bool   `statekit:"name=test"`
}

type directoryFunc struct{}

func (directoryFunc) Name() string { return "file.directory" }
func (directoryFunc) Args() any    { return directoryArgs{} }
func (directoryFunc) Apply(_ context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*directoryArgs)
	mode := fs.FileMode(0o755)
	if a.Mode != "" {
		parsed, err := parseOctal(a.Mode)
		if err != nil {
			return result.Failure(a.Name, err.Error())
		}
		mode = parsed
	}
	info, err := rt.FS.Stat(a.Name)
	if err == nil && info.IsDir() {
		if a.Mode != "" && !modeMatches(rt, a.Name, mode) {
			changes := map[string]any{
				"mode": map[string]any{"old": currentMode(rt, a.Name), "new": a.Mode},
			}
			if a.Test {
				return result.TestPending(a.Name, "Directory "+a.Name+" would be updated", changes)
			}
			rt.FS.Chmod(a.Name, mode)
			return result.New(a.Name, "", result.Bool(true), changes)
		}
		return result.Success(a.Name, "The directory "+a.Name+" is in the correct state")
	}
	if err == nil {
		return result.Failure(a.Name, a.Name+" exists and is not a directory")
	}
	changes := map[string]any{"created": a.Name}
	if a.Test {
		return result.TestPending(a.Name, "Directory "+a.Name+" would be created", changes)
	}
	if err := rt.FS.MkdirAll(a.Name, mode); err != nil {
		return result.Failure(a.Name, fmt.Sprintf("could not create %q: %v", a.Name, err))
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type symlinkArgs struct {
	Name   string `statekit:"required"`
	Target string `statekit:"required,name=target"`
	Force  bool   `statekit:"name=force"`
	Test   bool   `statekit:"name=test"`
}

type symlinkFunc struct{}

func (symlinkFunc) Name() string { return "file.symlink" }
func (symlinkFunc) Args() any    { return symlinkArgs{} }
func (symlinkFunc) Apply(_ context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*symlinkArgs)
	current, readErr := rt.FS.Readlink(a.Name)
	if readErr == nil && current == a.Target {
		return result.Success(a.Name, "Symlink "+a.Name+" is in the correct state")
	}

	changes := map[string]any{
		"old": current,
		"new": a.Target,
	}
	switch {
	case readErr == nil:
		if !a.Force {
			return result.Failure(a.Name, a.Name+" exists and is not a symlink; use force=true")
		}
		if a.Test {
			return result.TestPending(a.Name,
				fmt.Sprintf("Link %s target is set to be changed to %s", a.Name, a.Target), changes)
		}
	default: // missing or dangling target path
		if _, statErr := rt.FS.Lstat(a.Name); statErr == nil && !a.Force {
			return result.Failure(a.Name, a.Name+" exists and is not a symlink; use force=true")
		}
		changes["old"] = ""
		if a.Test {
			return result.TestPending(a.Name, "Symlink "+a.Name+" would be created", changes)
		}
	}

	if parent := dirOf(a.Name); parent != "" && parent != "/" {
		rt.FS.MkdirAll(parent, 0o755)
	}
	rt.FS.Remove(a.Name)
	if err := rt.FS.Symlink(a.Target, a.Name); err != nil {
		return result.Failure(a.Name, fmt.Sprintf("could not create symlink %q: %v", a.Name, err))
	}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all file-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		managedFunc{}, absentFunc{}, directoryFunc{}, symlinkFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
