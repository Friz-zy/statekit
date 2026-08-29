//go:build !windows

package service

import "github.com/friz-zy/statekit/internal/runtime"

// registerWindows is a no-op outside Windows.
func registerWindows(_ *runtime.ExecRegistry) error { return nil }
