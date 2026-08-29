//go:build !windows

package pkg

import "github.com/friz-zy/statekit/internal/runtime"

// registerWindows is a no-op outside Windows.
func registerWindows(_ *runtime.ExecRegistry) error { return nil }
