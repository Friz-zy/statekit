//go:build unix

package ssh

import "syscall"

func procEuid() int { return syscall.Geteuid() }
