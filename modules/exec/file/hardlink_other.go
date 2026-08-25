//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !solaris

package file

import "io/fs"

func hardlinked(fs.FileInfo) bool { return false }
