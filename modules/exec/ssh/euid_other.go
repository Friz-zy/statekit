//go:build !unix

package ssh

func procEuid() int { return -1 }
