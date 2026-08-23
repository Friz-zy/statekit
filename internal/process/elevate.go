// Privilege elevation model (plans/porting.md enabler E2).
//
// StateKit never escalates silently (init.md section 39): elevation happens
// only when the caller requests it through Elevate, and the helper binary
// (sudo/doas) must already exist on PATH. On Windows, programmatic elevation
// is not performed — the process must be started elevated; Elevate reports
// that contract as an error rather than pretending.
package process

import (
	"errors"
	"fmt"
	"os/exec"
)

var (
	// ErrNoElevationHelper reports a unix host without sudo/doas.
	ErrNoElevationHelper = errors.New(
		"no privilege escalation helper found (install sudo or doas)")
	// ErrWindowsElevation reports the windows UAC contract.
	ErrWindowsElevation = errors.New(
		"windows elevation is process-level: start statekit from an elevated console")
)

// elevatorLookup is split out for hermetic tests.
var elevatorLookup = exec.LookPath

// DetectUnixElevator returns the first available privilege helper
// ("sudo" or "doas"), or "" when none exists.
func DetectUnixElevator() string {
	for _, candidate := range []string{"sudo", "doas"} {
		if _, err := elevatorLookup(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// Elevate marks a command for execution through the detected unix helper.
//
//	goos="windows": returns ErrWindowsElevation.
//	no helper found: returns ErrNoElevationHelper; callers surface it as a
//	standard operation failure, never silently downgrade.
func Elevate(c Command, goos string) (Command, error) {
	if goos == "windows" {
		return c, fmt.Errorf("%w", ErrWindowsElevation)
	}
	helper := DetectUnixElevator()
	if helper == "" {
		return c, fmt.Errorf("%w", ErrNoElevationHelper)
	}
	elevated := c
	if c.Shell {
		// The whole shell invocation elevates: sh -c 'script' -> sudo sh -c 'script'.
		elevated.Name = helper
		elevated.Args = shellArgsFor(goos, c.Name)
		elevated.Shell = false
		return elevated, nil
	}
	elevated.Name = helper
	elevated.Args = append([]string{c.Name}, c.Args...)
	return elevated, nil
}

// shellArgsFor mirrors ShellModel.WrapShell argv without the program name,
// keeping Elevate independent of the runner instance.
func shellArgsFor(goos, script string) []string {
	model := ShellModelFor(goos)
	args := append([]string{}, model.PrefixArgs...)
	return append(args, script)
}
