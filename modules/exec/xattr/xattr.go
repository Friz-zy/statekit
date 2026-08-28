// Package xattr implements Salt's Darwin extended-attribute module through
// the native xattr utility and the central Runner.
package xattr

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, int, error) {
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.ExitCode, result.Err
	}
	return strings.ToValidUTF8(string(result.Stdout), "\uFFFD"), result.ExitCode, nil
}

func commandError(path, attribute string, stderr []byte) error {
	errText := string(stderr)
	switch {
	case strings.Contains(errText, "No such file"):
		return fmt.Errorf("File not found: %s", path)
	case attribute != "" && strings.Contains(errText, "No such xattr"):
		return fmt.Errorf("Attribute not found: %s", attribute)
	default:
		return fmt.Errorf("Unknown Error: %s", errText)
	}
}

func listImpl(ctx context.Context, rt *runtime.Runtime, path string, hexValue bool) (map[string]any, error) {
	result := rt.Runner.Run(ctx, runtime.Command("xattr", path))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, commandError(path, "", result.Stderr)
	}
	out := strings.TrimSpace(strings.ToValidUTF8(string(result.Stdout), "\uFFFD"))
	if out == "" {
		return map[string]any{}, nil
	}
	attrs := map[string]any{}
	for _, name := range strings.Split(out, "\n") {
		if name == "" {
			continue
		}
		value, err := readImpl(ctx, rt, path, name, hexValue)
		if err != nil {
			return nil, err
		}
		attrs[name] = value
	}
	return attrs, nil
}

func readImpl(ctx context.Context, rt *runtime.Runtime, path, attribute string, hexValue bool) (string, error) {
	argv := []string{"xattr", "-p"}
	if hexValue {
		argv = append(argv, "-x")
	}
	argv = append(argv, attribute, path)
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return "", result.Err
	}
	if result.ExitCode != 0 {
		return "", commandError(path, attribute, result.Stderr)
	}
	return strings.ToValidUTF8(string(result.Stdout), "\uFFFD"), nil
}

func writeImpl(ctx context.Context, rt *runtime.Runtime, path, attribute, value string, hexValue bool) (bool, error) {
	argv := []string{"xattr", "-w"}
	if hexValue {
		argv = append(argv, "-x")
	}
	argv = append(argv, attribute, value, path)
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return false, result.Err
	}
	if result.ExitCode != 0 {
		return false, commandError(path, "", result.Stderr)
	}
	current, err := readImpl(ctx, rt, path, attribute, hexValue)
	return current == value, err
}

func deleteImpl(ctx context.Context, rt *runtime.Runtime, path, attribute string) (bool, error) {
	result := rt.Runner.Run(ctx, runtime.Command("xattr", "-d", attribute, path))
	if result.Err != nil && result.ExitCode == -1 {
		return false, result.Err
	}
	if result.ExitCode != 0 {
		return false, commandError(path, attribute, result.Stderr)
	}
	attrs, err := listImpl(ctx, rt, path, false)
	if err != nil {
		return false, err
	}
	_, exists := attrs[attribute]
	return !exists, nil
}

func clearImpl(ctx context.Context, rt *runtime.Runtime, path string) (bool, error) {
	result := rt.Runner.Run(ctx, runtime.Command("xattr", "-c", path))
	if result.Err != nil && result.ExitCode == -1 {
		return false, result.Err
	}
	if result.ExitCode != 0 {
		return false, commandError(path, "", result.Stderr)
	}
	attrs, err := listImpl(ctx, rt, path, false)
	if err != nil {
		return false, err
	}
	return len(attrs) == 0, nil
}

// ---------------------------------------------------------------------------
// list/read/write/delete/clear

type listArgs struct {
	Path string `statekit:"required"`
	Hex  bool   `statekit:"name=hex"`
}
type listFunc struct{}

func (listFunc) Name() string        { return "xattr.list" }
func (listFunc) Args() any           { return listArgs{} }
func (listFunc) Platforms() []string { return []string{"darwin"} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverXattr(&res, &err)
	a := args.(*listArgs)
	return listImpl(ctx, rt, a.Path, a.Hex)
}

type readArgs struct {
	Path      string `statekit:"required"`
	Attribute string `statekit:"required,name=attribute"`
	Hex       bool   `statekit:"name=hex"`
}
type readFunc struct{}

func (readFunc) Name() string        { return "xattr.read" }
func (readFunc) Args() any           { return readArgs{} }
func (readFunc) Platforms() []string { return []string{"darwin"} }
func (readFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverXattr(&res, &err)
	a := args.(*readArgs)
	return readImpl(ctx, rt, a.Path, a.Attribute, a.Hex)
}

type writeArgs struct {
	Path      string `statekit:"required"`
	Attribute string `statekit:"required,name=attribute"`
	Value     string `statekit:"required,name=value"`
	Hex       bool   `statekit:"name=hex"`
}
type writeFunc struct{}

func (writeFunc) Name() string        { return "xattr.write" }
func (writeFunc) Args() any           { return writeArgs{} }
func (writeFunc) Platforms() []string { return []string{"darwin"} }
func (writeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverXattr(&res, &err)
	a := args.(*writeArgs)
	return writeImpl(ctx, rt, a.Path, a.Attribute, a.Value, a.Hex)
}

type deleteArgs struct {
	Path      string `statekit:"required"`
	Attribute string `statekit:"required,name=attribute"`
}
type deleteFunc struct{}

func (deleteFunc) Name() string        { return "xattr.delete" }
func (deleteFunc) Args() any           { return deleteArgs{} }
func (deleteFunc) Platforms() []string { return []string{"darwin"} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverXattr(&res, &err)
	a := args.(*deleteArgs)
	return deleteImpl(ctx, rt, a.Path, a.Attribute)
}

type clearArgs struct {
	Path string `statekit:"required"`
}
type clearFunc struct{}

func (clearFunc) Name() string        { return "xattr.clear" }
func (clearFunc) Args() any           { return clearArgs{} }
func (clearFunc) Platforms() []string { return []string{"darwin"} }
func (clearFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverXattr(&res, &err)
	return clearImpl(ctx, rt, args.(*clearArgs).Path)
}

func recoverXattr(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Darwin xattr surface; list_ is exposed as xattr.list
// through Salt's __func_alias__ convention.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{}, readFunc{}, writeFunc{}, deleteFunc{}, clearFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
