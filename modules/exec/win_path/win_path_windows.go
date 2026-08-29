//go:build windows

// Package win_path implements Salt's Windows SYSTEM PATH module through the
// registry command and the environment-change broadcast helper.
package win_path

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const systemPathKey = `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
const systemPathValue = "PATH"

var (
	localPathGet = func() string { return os.Getenv("PATH") }
	localPathSet = func(value string) error { return os.Setenv("PATH", value) }
)

func normalizePath(value string) string { return filepath.Clean(value) }
func pathRegQuery(ctx context.Context, rt *runtime.Runtime) (string, error) {
	result := rt.Runner.Run(ctx, runtime.Command("reg.exe", "query", systemPathKey, "/v", systemPathValue, "/reg:64"))
	if result.Err != nil && result.ExitCode == -1 {
		return "", result.Err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("Unable to read SYSTEM PATH: %s", strings.TrimSpace(string(result.Stderr)))
	}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(line, "\r")))
		if len(fields) >= 3 && strings.EqualFold(fields[0], systemPathValue) {
			return strings.Join(fields[2:], " "), nil
		}
	}
	return "", fmt.Errorf("SYSTEM PATH value not found")
}
func getSystemPath(ctx context.Context, rt *runtime.Runtime) ([]string, error) {
	value, e := pathRegQuery(ctx, rt)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(value, ";")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, normalizePath(part))
	}
	return out, nil
}
func setSystemPath(ctx context.Context, rt *runtime.Runtime, paths []string) error {
	value := strings.Join(paths, ";")
	result := rt.Runner.Run(ctx, runtime.Command("reg.exe", "add", systemPathKey, "/v", systemPathValue, "/t", "REG_EXPAND_SZ", "/d", value, "/f", "/reg:64"))
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("Unable to write SYSTEM PATH: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}
func broadcastPath(ctx context.Context, rt *runtime.Runtime) bool {
	result := rt.Runner.Run(ctx, runtime.Command("rundll32.exe", "user32.dll,UpdatePerUserSystemParameters"))
	return result.Err == nil && result.ExitCode == 0
}

// ---------------------------------------------------------------------------

type rehashFunc struct{}

func (rehashFunc) Name() string        { return "win_path.rehash" }
func (rehashFunc) Args() any           { return struct{}{} }
func (rehashFunc) Platforms() []string { return []string{"windows"} }
func (rehashFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return broadcastPath(ctx, rt), nil
}

type getPathFunc struct{}

func (getPathFunc) Name() string        { return "win_path.get_path" }
func (getPathFunc) Args() any           { return struct{}{} }
func (getPathFunc) Platforms() []string { return []string{"windows"} }
func (getPathFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPath(&res, &err)
	return getSystemPath(ctx, rt)
}

type existsArgs struct {
	Path string `statekit:"required"`
}
type existsFunc struct{}

func (existsFunc) Name() string        { return "win_path.exists" }
func (existsFunc) Args() any           { return existsArgs{} }
func (existsFunc) Platforms() []string { return []string{"windows"} }
func (existsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPath(&res, &err)
	a := args.(*existsArgs)
	wanted := strings.ToLower(normalizePath(a.Path))
	paths, e := getSystemPath(ctx, rt)
	if e != nil {
		return nil, e
	}
	for _, value := range paths {
		if strings.ToLower(value) == wanted {
			return true, nil
		}
	}
	return false, nil
}

type addArgs struct {
	Path   string `statekit:"required"`
	Index  *int   `statekit:"name=index"`
	Rehash *bool  `statekit:"name=rehash"`
}
type addFunc struct{}

func (addFunc) Name() string        { return "win_path.add" }
func (addFunc) Args() any           { return addArgs{} }
func (addFunc) Platforms() []string { return []string{"windows"} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPath(&res, &err)
	a := args.(*addArgs)
	wanted := normalizePath(a.Path)
	if wanted == "." {
		return false, nil
	}
	system, e := getSystemPath(ctx, rt)
	if e != nil {
		return nil, e
	}
	local := splitLocalPath(localPathGet())
	var changed bool
	local, changed = reorderPath(local, wanted, a.Index)
	if changed {
		if e := localPathSet(strings.Join(local, ";")); e != nil {
			return nil, e
		}
	}
	var systemChanged bool
	system, systemChanged = reorderPath(system, wanted, a.Index)
	if !systemChanged {
		return true, nil
	}
	if e := setSystemPath(ctx, rt, system); e != nil {
		return false, e
	}
	rehash := true
	if a.Rehash != nil {
		rehash = *a.Rehash
	}
	if rehash {
		return broadcastPath(ctx, rt), nil
	}
	return true, nil
}

type removeArgs struct {
	Path   string `statekit:"required"`
	Rehash *bool  `statekit:"name=rehash"`
}
type removeFunc struct{}

func (removeFunc) Name() string        { return "win_path.remove" }
func (removeFunc) Args() any           { return removeArgs{} }
func (removeFunc) Platforms() []string { return []string{"windows"} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPath(&res, &err)
	a := args.(*removeArgs)
	wanted := strings.ToLower(normalizePath(a.Path))
	system, e := getSystemPath(ctx, rt)
	if e != nil {
		return nil, e
	}
	local := splitLocalPath(localPathGet())
	var localChanged bool
	local, localChanged = removePath(local, wanted)
	if localChanged {
		if e := localPathSet(strings.Join(local, ";")); e != nil {
			return nil, e
		}
	}
	var systemChanged bool
	system, systemChanged = removePath(system, wanted)
	if !systemChanged {
		return true, nil
	}
	if e := setSystemPath(ctx, rt, system); e != nil {
		return false, e
	}
	rehash := true
	if a.Rehash != nil {
		rehash = *a.Rehash
	}
	if rehash {
		return broadcastPath(ctx, rt), nil
	}
	return true, nil
}

func splitLocalPath(value string) []string {
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ";")
}
func removePath(paths []string, wanted string) ([]string, bool) {
	out := paths[:0]
	changed := false
	for _, value := range paths {
		if strings.ToLower(normalizePath(value)) == wanted {
			changed = true
			continue
		}
		out = append(out, value)
	}
	return out, changed
}
func reorderPath(paths []string, wanted string, index *int) ([]string, bool) {
	lower := make([]string, len(paths))
	for i, value := range paths {
		lower[i] = strings.ToLower(normalizePath(value))
	}
	cur := -1
	for i, value := range lower {
		if value == strings.ToLower(wanted) {
			cur = i
			break
		}
	}
	num := len(paths)
	if index == nil {
		if cur >= 0 {
			return paths, false
		}
		return append(paths, wanted), true
	}
	idx := *index
	pos := idx
	if idx >= num || idx == -1 {
		pos = -1
	} else if idx <= -num {
		pos = 0
	} else if idx < 0 {
		pos = idx + 1
	}
	if pos == -1 {
		if cur == num-1 {
			return paths, false
		}
		if cur >= 0 {
			paths = append(paths[:cur], paths[cur+1:]...)
		}
		return append(paths, wanted), true
	}
	if cur >= 0 {
		if (idx < 0 && cur == num+idx) || (idx >= 0 && cur == idx) {
			return paths, false
		}
		paths = append(paths[:cur], paths[cur+1:]...)
		if cur < pos {
			pos--
		}
	}
	if pos < 0 {
		pos = 0
	}
	if pos > len(paths) {
		pos = len(paths)
	}
	paths = append(paths, "")
	copy(paths[pos+1:], paths[pos:])
	paths[pos] = wanted
	return paths, true
}

func recoverPath(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{rehashFunc{}, getPathFunc{}, existsFunc{}, addFunc{}, removeFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
