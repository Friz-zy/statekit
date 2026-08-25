//go:build linux || darwin

package file

import "syscall"

// mknodCall adapts the Linux/Darwin mknod signature (dev is int).
func mknodCall(name string, mode uint32, dev uint64) error {
	return syscall.Mknod(name, mode, int(dev))
}
