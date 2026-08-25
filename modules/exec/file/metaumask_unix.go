//go:build unix

package file

import "syscall"

func currentUmask() int {
	old := syscall.Umask(0)
	syscall.Umask(old)
	return old
}
