//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !solaris

package file

import "fmt"

// Device-node creation is unsupported on non-Unix platforms.

func isChrdev(string) bool    { return false }
func isBlkdev(string) bool    { return false }
func isFifoDev(string) bool   { return false }
func devmm(string) (int, int) { return 0, 0 }

func mknodUnix(name, ntype string, major, minor int, mode string) (map[string]any, error) {
	return nil, fmt.Errorf("device nodes are unsupported on this platform")
}

func parseMknodMode(mode string) string { return mode }
