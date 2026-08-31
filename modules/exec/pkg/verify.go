package pkg

import (
	"context"

	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

// VerifyArgs mirrors yumpkg.verify(*names, **kwargs). The interface-valued
// options retain Salt's scalar-or-list input shape; the provider validates the
// actual values before constructing argv.
type VerifyArgs struct {
	Names         []string `statekit:"name=names"`
	Root          *string  `statekit:"name=root"`
	VerifyOptions any      `statekit:"name=verify_options"`
	IgnoreTypes   any      `statekit:"name=ignore_types"`
}

type verifyFunc struct{}

func (verifyFunc) Name() string                   { return "pkg.verify" }
func (verifyFunc) Args() any                      { return VerifyArgs{} }
func (verifyFunc) ProviderKind() string           { return "pkg" }
func (verifyFunc) ProviderArgsStrict() bool       { return true }
func (verifyFunc) ProviderCapabilities() []string { return []string{"yumpkg"} }
func (verifyFunc) ArgsForProvider(providerName string) (any, error) {
	switch providerName {
	case "yum", "dnf", "dnf5":
		return VerifyArgs{}, nil
	default:
		return nil, &runtime.UnsupportedError{Kind: "provider", Name: providerName}
	}
}

func (verifyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	if _, err := (verifyFunc{}).ArgsForProvider(p.Name()); err != nil {
		return nil, err
	}
	yp, ok := p.(pkgprovider.YumProvider)
	if !ok {
		return nil, pkgprovider.ErrUnsupportedYUM
	}
	argMap, err := mapArgs("pkg.verify", args, VerifyArgs{})
	if err != nil {
		return nil, err
	}
	return yp.Yum(ctx, rt, "verify", argMap)
}
