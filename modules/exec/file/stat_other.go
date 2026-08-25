//go:build !unix

package file

import "io/fs"

func uidOf(info fs.FileInfo) int { return -1 }

func gidOf(info fs.FileInfo) int { return -1 }

func nlinkOf(info fs.FileInfo) uint64 { return 1 }
