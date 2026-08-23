package runtime

import "runtime"

// PlatformConstrained lets a function declare the GOOS values it supports.
// Functions without the interface are platform-unconstrained.
type PlatformConstrained interface {
	Platforms() []string
}

// SupportsPlatform reports whether fn (optionally constrained) runs on goos.
func SupportsPlatform(fn any, goos string) bool {
	constrained, ok := fn.(PlatformConstrained)
	if !ok {
		return true
	}
	list := constrained.Platforms()
	if len(list) == 0 {
		return true
	}
	for _, p := range list {
		if p == goos {
			return true
		}
	}
	return false
}

// CurrentGOOS exposes the compile-time platform for filtering.
func CurrentGOOS() string { return runtime.GOOS }
