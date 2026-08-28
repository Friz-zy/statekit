//go:build !darwin

package group

import "github.com/friz-zy/statekit/internal/runtime"

// registerMac is a no-op outside Darwin; the Linux group provider remains
// selected there.
func registerMac(_ *runtime.ExecRegistry) error { return nil }
