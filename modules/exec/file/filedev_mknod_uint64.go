//go:build freebsd || netbsd || openbsd || solaris

package file

import "syscall"

// mknodCall adapts the BSD mknod signature (dev is uint64).
func mknodCall(name string, mode uint32, dev uint64) error {
	return syscall.Mknod(name, mode, dev)
}
