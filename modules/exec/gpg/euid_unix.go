//go:build unix

package gpg

import "syscall"

func procEuidG() int { return syscall.Geteuid() }
