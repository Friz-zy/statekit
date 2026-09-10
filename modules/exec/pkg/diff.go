package pkg

import (
	"context"
	"errors"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// DiffArgs mirrors yumpkg.diff(*paths). Paths is the decoder-compatible
// varargs representation; the provider preserves source order when it queries
// ownership and processes each package group.
type DiffArgs struct {
	Paths []string `statekit:"name=paths"`
}

type diffFunc struct{}

func (diffFunc) Name() string                   { return "pkg.diff" }
func (diffFunc) Args() any                      { return DiffArgs{} }
func (diffFunc) ProviderKind() string           { return "pkg" }
func (diffFunc) ProviderArgsStrict() bool       { return true }
func (diffFunc) ProviderCapabilities() []string { return []string{"yumpkg", "zypperpkg"} }
func (diffFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "yum", "dnf", "dnf5":
		return DiffArgs{}, nil
	case "zypper":
		return ZypperDiffArgs{}, nil
	default:
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
}

func (diffFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if rt == nil || rt.Facts == nil || rt.Providers == nil {
		return nil, errors.New("pkg.diff requires a complete runtime")
	}
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := (diffFunc{}).ArgsForProvider(provider.Name())
	if err != nil {
		return nil, err
	}
	if zp, ok := provider.(pkgprovider.ZypperProvider); ok && provider.Name() == "zypper" {
		argMap, err := mapArgs("pkg.diff", args, prototype)
		if err != nil {
			return nil, err
		}
		return zp.Zypper(ctx, rt, "diff", argMap)
	}
	yum, ok := provider.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.diff", args, prototype)
	if err != nil {
		return nil, err
	}
	return yum.Yum(ctx, rt, "diff", argMap)
}
