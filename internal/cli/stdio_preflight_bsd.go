//go:build dragonfly || freebsd || netbsd

package cli

import (
	"os"

	"github.com/friz-zy/statekit/internal/cloudsecret"
	"golang.org/x/sys/unix"
)

// preflightOutputStream checks only current descriptor state and access mode;
// it does not prove recipient identity or future write success.
func preflightOutputStream(file *os.File) error {
	if file == nil {
		return cloudsecret.ErrSink
	}
	if _, err := file.Stat(); err != nil {
		return cloudsecret.ErrSink
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return cloudsecret.ErrSink
	}
	mode := flags & unix.O_ACCMODE
	if mode != unix.O_WRONLY && mode != unix.O_RDWR {
		return cloudsecret.ErrSink
	}
	return nil
}
