//go:build !unix

package file

func currentUmask() int { return 0o022 }
