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
func (downloadFunc) ProviderCapabilities() []string { return []string{"yumpkg"} }
func (downloadFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "yum", "dnf", "dnf5":
		return DownloadArgs{}, nil
	default:
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
}

func (downloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	if _, err := (downloadFunc{}).ArgsForProvider(p.Name()); err != nil {
		return nil, err
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.download", args, DownloadArgs{})
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "download", argMap)
}
