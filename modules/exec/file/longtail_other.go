//go:build !linux

package file

import "github.com/friz-zy/statekit/internal/runtime"

// Linux-only file long-tail functions are not registered on other targets.
func registerLongtail(_ *runtime.ExecRegistry) error { return nil }
