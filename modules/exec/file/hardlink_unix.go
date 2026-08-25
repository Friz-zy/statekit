//go:build linux || darwin || freebsd || netbsd || openbsd || solaris

package file

import (
	"io/fs"
	"syscall"
)

// hardlinked reports st_nlink > 1 through the syscall stat structure when
// the filesystem exposes it; the memory filesystem does not track link
// counts, so its nodes always report single-linked (documented).
func hardlinked(info fs.FileInfo) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Nlink > 1
	}
	return false
}
