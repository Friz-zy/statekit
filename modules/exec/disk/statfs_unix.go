//go:build !windows

package disk

import (
	"fmt"
	"syscall"
)

// filesystemUsage reports df-style numbers through statfs.
func filesystemUsage(path string) (map[string]any, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, fmt.Errorf("could not read filesystem usage for %q: %w", path, err)
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bfree) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - free
	entry := map[string]any{
		"filesystem": path,
		"1K-blocks":  fmt.Sprintf("%d", total/1024),
		"used":       fmt.Sprintf("%d", used/1024),
		"available":  fmt.Sprintf("%d", available/1024),
	}
	if total > 0 {
		entry["use%"] = fmt.Sprintf("%.0f%%", float64(used)/float64(total)*100)
	}
	return entry, nil
}

// filesystemPercent returns used-space percentage for a path.
func filesystemPercent(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	if total == 0 {
		return 0, nil
	}
	used := float64(stat.Blocks-stat.Bfree) * float64(stat.Bsize)
	return used / total * 100, nil
}
