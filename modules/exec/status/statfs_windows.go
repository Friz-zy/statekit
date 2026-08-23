//go:build windows

package status

import "errors"

func readDiskUsage(string) (map[string]any, error) {
	return nil, errors.New("status.diskusage requires a POSIX filesystem")
}
