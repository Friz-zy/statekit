package pkg

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// ModifiedArgs mirrors yumpkg.modified(*packages, **flags). Pointer booleans
// retain the distinction between an omitted filter and an explicit false.
type ModifiedArgs struct {
	Names        []string `statekit:"name=names"`
	Root         *string  `statekit:"name=root"`
	Size         *bool    `statekit:"name=size"`
	Mode         *bool    `statekit:"name=mode"`
	Checksum     *bool    `statekit:"name=checksum"`
	Device       *bool    `statekit:"name=device"`
	Symlink      *bool    `statekit:"name=symlink"`
	Owner        *bool    `statekit:"name=owner"`
	Group        *bool    `statekit:"name=group"`
	Time         *bool    `statekit:"name=time"`
	Capabilities *bool    `statekit:"name=capabilities"`
}

type modifiedFunc struct{}

func (modifiedFunc) Name() string                   { return "pkg.modified" }
func (modifiedFunc) Args() any                      { return ModifiedArgs{} }
func (modifiedFunc) ProviderKind() string           { return "pkg" }
func (modifiedFunc) ProviderArgsStrict() bool       { return true }
func (modifiedFunc) ProviderCapabilities() []string { return []string{"yumpkg", "zypperpkg"} }
func (modifiedFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "yum", "dnf", "dnf5":
		return ModifiedArgs{}, nil
	case "zypper":
		return ZypperModifiedArgs{}, nil
	default:
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
}

func (modifiedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := (modifiedFunc{}).ArgsForProvider(p.Name())
	if err != nil {
		return nil, err
	}
	if p.Name() == "zypper" {
		zp, ok := p.(pkgprovider.ZypperProvider)
		if !ok {
			return nil, pkgprovider.ErrUnsupportedZypper
		}
		argMap, err := mapArgs("pkg.modified", args, prototype)
		if err != nil {
			return nil, err
		}
		return zp.Zypper(ctx, rt, "modified", argMap)
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.modified", args, prototype)
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "modified", argMap)
}
