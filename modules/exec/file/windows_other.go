//go:build !windows

package file

import "github.com/friz-zy/statekit/internal/runtime"

// registerWindowsFile is a no-op outside Windows.
func registerWindowsFile(_ *runtime.ExecRegistry) error { return nil }
