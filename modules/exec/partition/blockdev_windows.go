//go:build windows

package partition

import "os"

// fileIsBlock always reports false on windows builds; the partition module
// never loads there anyway.
func fileIsBlock(_ os.FileInfo) bool { return false }
