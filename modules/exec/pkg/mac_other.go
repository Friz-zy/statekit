//go:build !darwin

package pkg

import "github.com/friz-zy/statekit/internal/runtime"

// registerMac is a no-op outside Darwin; Linux and other existing providers
// retain the generic pkg execution surface there.
func registerMac(_ *runtime.ExecRegistry) error { return nil }
