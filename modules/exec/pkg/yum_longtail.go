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

// YumListUpgradesArgs mirrors yumpkg.list_upgrades. Repository selectors use
// Salt's scalar-or-list shape; refresh is a pointer so omission keeps the
// source default (true) distinct from an explicit false.
type YumListUpgradesArgs struct {
	Refresh         *bool   `statekit:"name=refresh"`
	Repo            *string `statekit:"name=repo"`
	Fromrepo        *string `statekit:"name=fromrepo"`
	Enablerepo      any     `statekit:"name=enablerepo"`
	Disablerepo     any     `statekit:"name=disablerepo"`
	Disableexcludes *string `statekit:"name=disableexcludes"`
	Branch          *string `statekit:"name=branch"`
	Setopt          any     `statekit:"name=setopt"`
}

type YumUpgradeAvailableArgs struct {
	Name            string  `statekit:"required"`
	Refresh         *bool   `statekit:"name=refresh"`
	Repo            *string `statekit:"name=repo"`
	Fromrepo        *string `statekit:"name=fromrepo"`
	Enablerepo      any     `statekit:"name=enablerepo"`
	Disablerepo     any     `statekit:"name=disablerepo"`
	Disableexcludes *string `statekit:"name=disableexcludes"`
	Branch          *string `statekit:"name=branch"`
	Setopt          any     `statekit:"name=setopt"`
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

// YumGroupInfoArgs mirrors yumpkg.group_info. Optional pointers preserve
// omission semantics at the provider boundary; repository selectors retain
// Salt's string-or-string-list input shape.
type YumGroupInfoArgs struct {
	Name         string   `statekit:"required"`
	Expand       *bool    `statekit:"name=expand"`
	IgnoreGroups []string `statekit:"name=ignore_groups"`
	Fromrepo     *string  `statekit:"name=fromrepo"`
	Enablerepo   any      `statekit:"name=enablerepo"`
	Disablerepo  any      `statekit:"name=disablerepo"`
}

// YumGroupDiffArgs mirrors yumpkg.group_diff. Unlike group_info, Salt's
// source signature exposes no expand or ignore_groups arguments.
type YumGroupDiffArgs struct {
	Name        string  `statekit:"required"`
	Fromrepo    *string `statekit:"name=fromrepo"`
	Enablerepo  any     `statekit:"name=enablerepo"`
	Disablerepo any     `statekit:"name=disablerepo"`
}

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
	case "list_upgrades":
		return YumListUpgradesArgs{}, true
	case "upgrade_available":
		return YumUpgradeAvailableArgs{}, true
	case "list_holds":
		return YumListHoldsArgs{}, true
	case "list_patches":
		return YumListPatchesArgs{}, true
	case "list_installed_patches":
		return YumListInstalledPatchesArgs{}, true
	case "group_info":
		return YumGroupInfoArgs{}, true
	case "group_diff":
		return YumGroupDiffArgs{}, true
	case "services_need_restart":
		return struct{}{}, true
	case "group_list":
		return struct{}{}, true
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
	if providerName != "yum" && providerName != "dnf" && providerName != "dnf5" {
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

type yumGroupListFunc struct{}

func (yumGroupListFunc) Name() string         { return "pkg.group_list" }
func (yumGroupListFunc) Args() any            { return struct{}{} }
func (yumGroupListFunc) ProviderKind() string { return "pkg" }
func (yumGroupListFunc) ArgsForProvider(providerName string) (any, error) {
	if providerName != "yum" && providerName != "dnf" && providerName != "dnf5" {
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
	return struct{}{}, nil
}
func (yumGroupListFunc) ProviderArgsStrict() bool       { return true }
func (yumGroupListFunc) ProviderCapabilities() []string { return []string{"yumpkg"} }
func (yumGroupListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := (yumGroupListFunc{}).ArgsForProvider(p.Name())
	if err != nil {
		return nil, err
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.group_list", args, prototype)
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "group_list", argMap)
}

type yumGroupInfoFunc struct{}

func (yumGroupInfoFunc) Name() string         { return "pkg.group_info" }
func (yumGroupInfoFunc) Args() any            { return YumGroupInfoArgs{} }
func (yumGroupInfoFunc) ProviderKind() string { return "pkg" }
func (yumGroupInfoFunc) ArgsForProvider(providerName string) (any, error) {
	if providerName != "yum" && providerName != "dnf" && providerName != "dnf5" {
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
	return YumGroupInfoArgs{}, nil
}
func (yumGroupInfoFunc) ProviderArgsStrict() bool       { return true }
func (yumGroupInfoFunc) ProviderCapabilities() []string { return []string{"yumpkg"} }
func (yumGroupInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := (yumGroupInfoFunc{}).ArgsForProvider(p.Name())
	if err != nil {
		return nil, err
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.group_info", args, prototype)
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "group_info", argMap)
}
