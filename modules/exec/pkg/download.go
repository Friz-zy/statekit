package pkg

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// DownloadArgs mirrors yumpkg.download(*packages). Packages retains Salt's
// variadic call shape as the decoder-compatible list form.
type DownloadArgs struct {
	Packages []string `statekit:"name=packages"`
}

type downloadFunc struct{}

func (downloadFunc) Name() string                   { return "pkg.download" }
func (downloadFunc) Args() any                      { return DownloadArgs{} }
func (downloadFunc) ProviderKind() string           { return "pkg" }
func (downloadFunc) ProviderArgsStrict() bool       { return true }
func (downloadFunc) ProviderCapabilities() []string { return []string{"yumpkg", "zypperpkg"} }
func (downloadFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "yum", "dnf", "dnf5":
		return DownloadArgs{}, nil
	case "zypper":
		return ZypperDownloadArgs{}, nil
	default:
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
}

func (downloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	prototype, err := (downloadFunc{}).ArgsForProvider(p.Name())
	if err != nil {
		return nil, err
	}
	if zp, ok := p.(pkgprovider.ZypperProvider); ok && p.Name() == "zypper" {
		argMap, err := mapArgs("pkg.download", args, prototype)
		if err != nil {
			return nil, err
		}
		return zp.Zypper(ctx, rt, "download", argMap)
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.download", args, prototype)
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "download", argMap)
}
