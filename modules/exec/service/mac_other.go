//go:build !darwin

package service

import "github.com/friz-zy/statekit/internal/runtime"

// registerMac is a no-op outside Darwin; systemd/openrc remain selected.
func registerMac(_ *runtime.ExecRegistry) error { return nil }
