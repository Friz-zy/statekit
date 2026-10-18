//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd

package cli

import (
	"os"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

// preflightOutputStream fails closed where this implementation has no
// verified non-mutating descriptor access-mode query.
func preflightOutputStream(file *os.File) error {
	if file == nil {
		return cloudsecret.ErrSink
	}
	if _, err := file.Stat(); err != nil {
		return cloudsecret.ErrSink
	}
	return cloudsecret.ErrUnsupported
}
