// Cloud machine-metadata surface for `statekit facts --cloud --provider`
// (ADR 0005 amendment 2026-10-14). This file is the ONLY internal/cli
// import site of internal/cloudmeta: the default facts path, the runtime,
// and the bootstrap stay network-free, and the cloud branch is entered
// only when the flags explicitly request it.
package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/friz-zy/statekit/internal/cloudmeta"
	"github.com/friz-zy/statekit/internal/output"
)

// cloudCollectFunc is the collector seam: App.CloudCollect lets tests
// inject an offline fake; nil uses cloudmeta.Collect.
type cloudCollectFunc func(context.Context, string) (*cloudmeta.Result, error)

// runFactsCloud executes the opt-in cloud branch. Exit mapping (plan
// section 40 and ADR 0005): unknown provider exits 2 before any request;
// a recognized deferred or build-disabled provider exits 3 before any
// request; any collection failure exits 1 with no partial payload;
// success exits 0 printing only the {"cloud": ...} envelope — no local
// facts. stderr carries ONLY mapped sentinel codes: each errors.Is match
// prints that sentinel's own text, and a non-sentinel error prints the
// fixed cloud_meta_internal fallback — never err.Error(). The envelope
// is JSON per the approved contract; the -o format flag still applies to
// the local-facts path only.
func (a *App) runFactsCloud(provider string) int {
	collect := cloudmeta.Collect
	if a.CloudCollect != nil {
		collect = a.CloudCollect
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := collect(ctx, provider)
	if err != nil {
		switch {
		case errors.Is(err, cloudmeta.ErrInvalidProvider):
			return failf(ExitInvalidInput, "%s", cloudmeta.ErrInvalidProvider)
		case errors.Is(err, cloudmeta.ErrDeferredProvider):
			return failf(ExitUnsupported, "%s", cloudmeta.ErrDeferredProvider)
		case errors.Is(err, cloudmeta.ErrBuildDisabled):
			return failf(ExitUnsupported, "%s", cloudmeta.ErrBuildDisabled)
		case errors.Is(err, cloudmeta.ErrUnreachable):
			return failf(ExitFailed, "%s", cloudmeta.ErrUnreachable)
		case errors.Is(err, cloudmeta.ErrDeadline):
			return failf(ExitFailed, "%s", cloudmeta.ErrDeadline)
		case errors.Is(err, cloudmeta.ErrProtocol):
			return failf(ExitFailed, "%s", cloudmeta.ErrProtocol)
		case errors.Is(err, cloudmeta.ErrRedirect):
			return failf(ExitFailed, "%s", cloudmeta.ErrRedirect)
		case errors.Is(err, cloudmeta.ErrEncoding):
			return failf(ExitFailed, "%s", cloudmeta.ErrEncoding)
		case errors.Is(err, cloudmeta.ErrOversize):
			return failf(ExitFailed, "%s", cloudmeta.ErrOversize)
		case errors.Is(err, cloudmeta.ErrMalformed):
			return failf(ExitFailed, "%s", cloudmeta.ErrMalformed)
		case errors.Is(err, cloudmeta.ErrForbiddenPath):
			return failf(ExitFailed, "%s", cloudmeta.ErrForbiddenPath)
		default:
			return failf(ExitFailed, "%s", cloudmeta.ErrInternal)
		}
	}
	envelope := struct {
		Cloud *cloudmeta.Result `json:"cloud"`
	}{Cloud: result}
	return encodeOr(os.Stdout, output.FormatJSON, envelope)
}
