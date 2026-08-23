//go:build windows

package disk

import "errors"

var errPOSIXOnly = errors.New(
	"disk usage via statfs requires a POSIX filesystem; use dedicated windows tooling")

func filesystemUsage(string) (map[string]any, error) { return nil, errPOSIXOnly }

func filesystemPercent(string) (float64, error) { return 0, errPOSIXOnly }
