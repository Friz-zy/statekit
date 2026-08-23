//go:build !windows

package partition

import (
	"os"
	"syscall"
)

// fileIsBlock reports whether the file is a block device on unix systems.
func fileIsBlock(fi os.FileInfo) bool {
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		return sys.Mode&syscall.S_IFMT == syscall.S_IFBLK
	}
	return false
}
