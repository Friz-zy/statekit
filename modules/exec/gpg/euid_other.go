//go:build !unix

package gpg

func procEuidG() int { return -1 }
