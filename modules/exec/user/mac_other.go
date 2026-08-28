//go:build !darwin

package user

import "github.com/friz-zy/statekit/internal/runtime"

// registerMac is a no-op outside Darwin; the Linux implementation remains
// the selected virtual user provider on those platforms.
func registerMac(_ *runtime.ExecRegistry) error { return nil }
