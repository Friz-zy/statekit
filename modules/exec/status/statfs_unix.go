//go:build !windows

package status

import (
	"fmt"
	"syscall"
)

func readDiskUsage(path string) (map[string]any, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, fmt.Errorf("could not stat filesystem for %q: %w", path, err)
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - free
	usage := map[string]any{
		"filesystem": path,
		"1K-blocks":  total / 1024,
		"used":       used / 1024,
		"available":  available / 1024,
	}
	if total > 0 {
		usage["capacity"] = fmt.Sprintf("%.0f%%", float64(used)/float64(total)*100)
	}
	return usage, nil
}
