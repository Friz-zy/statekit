//go:build windows

package timezone

import "golang.org/x/sys/windows"

// defaultWinSystemTree resolves the admin-controlled machine system
// tree through the two existing golang.org/x/sys v0.47.0 APIs:
// GetSystemDirectory for the system directory and the machine-wide
// GetSystemWindowsDirectory for the windows directory. The per-user
// GetWindowsDirectory is never used, so a terminal-server private
// windows directory can never supply the tree. Structural validation
// happens in validateWindowsSystemTree; any API error or malformed
// answer fails closed at the caller with ErrCannotDetermineZone.
func defaultWinSystemTree() (string, string, error) {
	sysdir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", "", err
	}
	windir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", "", err
	}
	return sysdir, windir, nil
}
