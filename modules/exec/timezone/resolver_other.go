//go:build !windows

package timezone

import "errors"

// errWinSystemTreeUnavailable is the fail-closed answer of the
// off-windows resolver stub. It never reaches callers as text: the
// windows variant maps every resolver failure to the fixed
// ErrCannotDetermineZone.
var errWinSystemTreeUnavailable = errors.New("timezone: windows system-tree resolver unavailable off windows")

// defaultWinSystemTree exists only so the package builds off windows;
// the windows variant is registered for GOOS windows alone, and any
// accidental off-host execution fails closed instead of probing the
// host filesystem or environment.
func defaultWinSystemTree() (string, string, error) {
	return "", "", errWinSystemTreeUnavailable
}
