// Package pkg implements Salt-compatible package state functions backed by
// the virtual pkg provider through the execution registry.
//
// Reference: saltstack/salt/states/pkg.py @ pinned revision. Verified Salt
// comments: "Package {name} is already installed"; test mode follows plan
// section 12 ("{X} would be {action}").
package pkg

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
)

func callVersion(ctx context.Context, rt *runtime.Runtime, name string) string {
	value, err := rt.Exec.Call(ctx, rt, "pkg.version", &execpkg.VersionArgs{Name: name})
	if err != nil {
		return ""
	}
	text, _ := value.(string)
	return text
}

type installedArgs struct {
	Name    string `statekit:"required"`
	Version string `statekit:"name=version"`
	Refresh bool   `statekit:"name=refresh"`
	Test    bool   `statekit:"name=test"`
}

type installedFunc struct{}

func (installedFunc) Name() string { return "pkg.installed" }
func (installedFunc) Args() any    { return installedArgs{} }
func (installedFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*installedArgs)
	current := callVersion(ctx, rt, a.Name)

	satisfied := false
	switch {
	case current == "":
		satisfied = false
	case a.Version == "" || a.Version == "latest":
		satisfied = true
	default:
		satisfied = current == a.Version
	}
	if satisfied {
		comment := fmt.Sprintf("Package %s is already installed", a.Name)
		if a.Version != "" && a.Version != "latest" {
			comment = fmt.Sprintf("Version %s of package '%s' is already installed", a.Version, a.Name)
		}
		return result.Success(a.Name, comment)
	}

	desired := a.Version
	if desired == "" {
		desired = "latest"
	}
	changes := map[string]any{
		a.Name: map[string]any{"old": current, "new": desired},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Package %s would be installed", a.Name), changes)
	}

	_, err := rt.Exec.Call(ctx, rt, "pkg.install", &execpkg.InstallArgs{
		Name: a.Name, Version: a.Version, Refresh: a.Refresh,
	})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	updated := callVersion(ctx, rt, a.Name)
	changes[a.Name] = map[string]any{"old": current, "new": updated}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type removedArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type removedFunc struct{}

func (removedFunc) Name() string { return "pkg.removed" }
func (removedFunc) Args() any    { return removedArgs{} }
func (removedFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*removedArgs)
	current := callVersion(ctx, rt, a.Name)
	if current == "" {
		return result.Success(a.Name, fmt.Sprintf("Package %s is already absent", a.Name))
	}
	changes := map[string]any{
		a.Name: map[string]any{"old": current, "new": ""},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Package %s would be removed", a.Name), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "pkg.remove", &execpkg.RemoveArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	after := callVersion(ctx, rt, a.Name)
	changes[a.Name] = map[string]any{"old": current, "new": after}
	return result.New(a.Name, "", result.Bool(true), changes)
}

type latestArgs struct {
	Name    string `statekit:"required"`
	Refresh bool   `statekit:"name=refresh"`
	Test    bool   `statekit:"name=test"`
}

type latestFunc struct{}

func (latestFunc) Name() string { return "pkg.latest" }
func (latestFunc) Args() any    { return latestArgs{} }
func (latestFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*latestArgs)
	current := callVersion(ctx, rt, a.Name)

	available, err := rt.Exec.Call(ctx, rt, "pkg.latest_version", &execpkg.LatestVersionArgs{
		Name: a.Name, Refresh: a.Refresh,
	})
	if err != nil {
		return result.Failure(a.Name, err.Error())
	}
	latest, _ := available.(string)

	if current != "" && (latest == "" || current == latest) {
		return result.Success(a.Name, fmt.Sprintf("Package %s is already up-to-date", a.Name))
	}

	changes := map[string]any{
		a.Name: map[string]any{"old": current, "new": latest},
	}
	if a.Test {
		return result.TestPending(a.Name, fmt.Sprintf("Package %s would be upgraded to %s", a.Name, latest), changes)
	}
	if _, err := rt.Exec.Call(ctx, rt, "pkg.install", &execpkg.InstallArgs{Name: a.Name}); err != nil {
		return result.Failure(a.Name, err.Error())
	}
	updated := callVersion(ctx, rt, a.Name)
	changes[a.Name] = map[string]any{"old": current, "new": updated}
	return result.New(a.Name, "", result.Bool(true), changes)
}

// Register installs all pkg-module state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{installedFunc{}, removedFunc{}, latestFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
