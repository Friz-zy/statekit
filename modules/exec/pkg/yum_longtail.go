package pkg

import (
	"context"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// Signatures mirror salt/modules/yumpkg.py at pinned revision 8b63e700637e40d76f80a00d95c60471797c73b9.
// These functions delegate to salt/modules/rpm_lowpkg.py.
type YumFilesArgs struct {
	Packages []string `statekit:"name=packages"`
	Root     *string  `statekit:"name=root"`
}
type YumInfoInstalledArgs struct {
	Names       []string `statekit:"name=names"`
	AllVersions *bool    `statekit:"name=all_versions"`
	Root        *string  `statekit:"name=root"`
	Attr        *string  `statekit:"name=attr"`
}
type YumOwnerArgs struct {
	Paths []string `statekit:"name=paths"`
	Root  *string  `statekit:"name=root"`
}

type YumCleanMetadataArgs struct {
	Repo            *string `statekit:"name=repo"`
	Fromrepo        *string `statekit:"name=fromrepo"`
	Enablerepo      any     `statekit:"name=enablerepo"`
	Disablerepo     any     `statekit:"name=disablerepo"`
	Branch          *string `statekit:"name=branch"`
	Disableexcludes *string `statekit:"name=disableexcludes"`
	Setopt          any     `statekit:"name=setopt"`
	CheckUpdate     *bool   `statekit:"name=check_update"`
}

// YumListHoldsArgs mirrors yumpkg.list_holds. Pointers preserve whether the
// caller supplied an optional value; the provider applies Salt's defaults.
type YumListHoldsArgs struct {
	Pattern *string `statekit:"name=pattern"`
	Full    *bool   `statekit:"name=full"`
}

// YumListPatchesArgs mirrors list_patches' optional refresh argument.
type YumListPatchesArgs struct {
	Refresh *bool `statekit:"name=refresh"`
}

// YumListInstalledPatchesArgs mirrors yumpkg.list_installed_patches, which
// takes no public arguments and always calls _get_patches(installed_only=True).
type YumListInstalledPatchesArgs struct{}

// YumPrototype returns the exact provider-specific argument shape for a
// shared longtail function. Registration and dispatch remain canonical in
// apt_longtail.go.
func YumPrototype(name string) (any, bool) {
	switch name {
	case "file_list", "file_dict":
		return YumFilesArgs{}, true
	case "info_installed":
		return YumInfoInstalledArgs{}, true
	case "owner":
		return YumOwnerArgs{}, true
	case "clean_metadata":
		return YumCleanMetadataArgs{}, true
	case "list_holds":
		return YumListHoldsArgs{}, true
	case "list_patches":
		return YumListPatchesArgs{}, true
	case "list_installed_patches":
		return YumListInstalledPatchesArgs{}, true
	default:
		return nil, false
	}
}

type yumPatchesFunc struct{ installedOnly bool }

func (f yumPatchesFunc) Name() string {
	if f.installedOnly {
		return "pkg.list_installed_patches"
	}
	return "pkg.list_patches"
}
func (f yumPatchesFunc) Args() any {
	if f.installedOnly {
		return YumListInstalledPatchesArgs{}
	}
	return YumListPatchesArgs{}
}
func (f yumPatchesFunc) ProviderKind() string { return "pkg" }
func (f yumPatchesFunc) ArgsForProvider(providerName string) (any, error) {
	if providerName != "yum" && providerName != "dnf" {
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
	return f.Args(), nil
}
func (f yumPatchesFunc) ProviderArgsStrict() bool       { return true }
func (f yumPatchesFunc) ProviderCapabilities() []string { return []string{"yumpkg"} }
func (f yumPatchesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := f.ArgsForProvider(p.Name())
	if err != nil {
		return nil, err
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs(f.Name(), args, prototype)
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, strings.TrimPrefix(f.Name(), "pkg."), argMap)
}
