//go:build !windows

package group

import "github.com/friz-zy/statekit/internal/runtime"

// registerWindows is a no-op on non-Windows builds.
func registerWindows(_ *runtime.ExecRegistry) error { return nil }
