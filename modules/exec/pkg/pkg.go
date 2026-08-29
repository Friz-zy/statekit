// Package pkg implements Salt-compatible package execution functions backed
// by the virtual pkg provider.
//
// Reference: saltstack/salt/modules/aptpkg.py and siblings @ pinned revision.
package pkg

import (
	"context"
	"fmt"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type RefreshDbArgs struct {
	CacheValidTime int `statekit:"name=cache_valid_time"`
}

type refreshDBFunc struct{}

func (refreshDBFunc) Name() string { return "pkg.refresh_db" }
func (refreshDBFunc) Args() any    { return RefreshDbArgs{} }
func (refreshDBFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	if err := provider.Refresh(ctx, rt); err != nil {
		return nil, err
	}
	return true, nil
}

type VersionArgs struct {
	Name string `statekit:"required"`
}

type versionFunc struct{}

func (versionFunc) Name() string { return "pkg.version" }
func (versionFunc) Args() any    { return VersionArgs{} }
func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*VersionArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	return provider.Version(ctx, rt, a.Name)
}

// ListPkgsArgs mirrors Salt's pkg.list_pkgs signature; versions_as_list
// reports each package's versions as a list instead of a joined string
// (pkg_resource.version consumes the list form).
type ListPkgsArgs struct {
	VersionsAsList bool `statekit:"name=versions_as_list"`
}

type listFunc struct{}

func (listFunc) Name() string { return "pkg.list_pkgs" }
func (listFunc) Args() any    { return ListPkgsArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListPkgsArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	listed, err := provider.List(ctx, rt)
	if err != nil {
		return nil, err
	}
	if !a.VersionsAsList {
		return listed, nil
	}
	ret := make(map[string]any, len(listed))
	for name, version := range listed {
		ret[name] = []string{version}
	}
	return ret, nil
}

type InstallArgs struct {
	Name    string `statekit:"required"`
	Version string `statekit:"name=version"`
	Refresh bool   `statekit:"name=refresh"`
}

type installFunc struct{}

func (installFunc) Name() string { return "pkg.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	if a.Refresh {
		if err := provider.Refresh(ctx, rt); err != nil {
			return nil, fmt.Errorf("could not refresh package database: %w", err)
		}
	}
	oldVersion, _ := provider.Version(ctx, rt, a.Name)
	if err := provider.Install(ctx, rt, a.Name, a.Version); err != nil {
		return nil, err
	}
	newVersion, _ := provider.Version(ctx, rt, a.Name)
	changes := map[string]any{}
	if oldVersion != newVersion {
		changes[a.Name] = map[string]any{"old": oldVersion, "new": newVersion}
	}
	return changes, nil
}

type RemoveArgs struct {
	Name    string `statekit:"required"`
	Refresh bool   `statekit:"name=refresh"`
}

type removeFunc struct{}

func (removeFunc) Name() string { return "pkg.remove" }
func (removeFunc) Args() any    { return RemoveArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RemoveArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	oldVersion, _ := provider.Version(ctx, rt, a.Name)
	if err := provider.Remove(ctx, rt, a.Name); err != nil {
		return nil, err
	}
	newVersion, _ := provider.Version(ctx, rt, a.Name)
	changes := map[string]any{}
	if oldVersion != newVersion {
		changes[a.Name] = map[string]any{"old": oldVersion, "new": newVersion}
	}
	return changes, nil
}

type LatestVersionArgs struct {
	Name    string `statekit:"required"`
	Refresh bool   `statekit:"name=refresh"`
}

type latestVersionFunc struct{}

func (latestVersionFunc) Name() string { return "pkg.latest_version" }
func (latestVersionFunc) Args() any    { return LatestVersionArgs{} }
func (latestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*LatestVersionArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	if a.Refresh {
		provider.Refresh(ctx, rt)
	}
	return provider.LatestVersion(ctx, rt, a.Name)
}

// Register installs all pkg-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "darwin" {
		return registerMac(reg)
	}
	if runtime.CurrentGOOS() == "windows" {
		return registerWindows(reg)
	}
	for _, fn := range []runtime.ExecFunction{
		refreshDBFunc{}, versionFunc{}, listFunc{}, installFunc{}, removeFunc{}, latestVersionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
