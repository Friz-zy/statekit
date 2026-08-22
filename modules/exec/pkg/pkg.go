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

type refreshDbArgs struct {
	CacheValidTime int `statekit:"name=cache_valid_time"`
}

type refreshDBFunc struct{}

func (refreshDBFunc) Name() string { return "pkg.refresh_db" }
func (refreshDBFunc) Args() any    { return refreshDbArgs{} }
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

type versionArgs struct {
	Name string `statekit:"required"`
}

type versionFunc struct{}

func (versionFunc) Name() string { return "pkg.version" }
func (versionFunc) Args() any    { return versionArgs{} }
func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*versionArgs)
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	return provider.Version(ctx, rt, a.Name)
}

type listPkgsArgs struct{}

type listFunc struct{}

func (listFunc) Name() string { return "pkg.list_pkgs" }
func (listFunc) Args() any    { return listPkgsArgs{} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	return provider.List(ctx, rt)
}

type installArgs struct {
	Name      string `statekit:"required"`
	Version   string `statekit:"name=version"`
	Refresh   bool   `statekit:"name=refresh"`
	LatestVer bool
}

type installFunc struct{}

func (installFunc) Name() string { return "pkg.install" }
func (installFunc) Args() any    { return installArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*installArgs)
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

type removeArgs struct {
	Name    string `statekit:"required"`
	Refresh bool   `statekit:"name=refresh"`
}

type removeFunc struct{}

func (removeFunc) Name() string { return "pkg.remove" }
func (removeFunc) Args() any    { return removeArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*removeArgs)
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

type latestVersionArgs struct {
	Name    string `statekit:"required"`
	Refresh bool   `statekit:"name=refresh"`
}

type latestVersionFunc struct{}

func (latestVersionFunc) Name() string { return "pkg.latest_version" }
func (latestVersionFunc) Args() any    { return latestVersionArgs{} }
func (latestVersionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*latestVersionArgs)
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
	for _, fn := range []runtime.ExecFunction{
		refreshDBFunc{}, versionFunc{}, listFunc{}, installFunc{}, removeFunc{}, latestVersionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
