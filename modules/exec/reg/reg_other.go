//go:build !windows

package reg

import "github.com/friz-zy/statekit/internal/runtime"

// Register is intentionally empty outside Windows; reg.exe has no portable
// equivalent and the registry family is platform-scoped.
func Register(_ *runtime.ExecRegistry) error { return nil }
