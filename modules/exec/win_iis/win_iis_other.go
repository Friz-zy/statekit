//go:build !windows

package win_iis

import "github.com/friz-zy/statekit/internal/runtime"

// Register is empty outside Windows.
func Register(_ *runtime.ExecRegistry) error { return nil }
