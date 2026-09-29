//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package runtime

import (
	"context"
)

// Unsupported platforms fail closed because their path-open semantics
// have not been proven to provide the no-follow descriptor boundary
// the bounded update requires.
func (OSFileSystem) UpdateFileBounded(_ context.Context, _ string, limits UpdateLimits, _ bool, _ UpdateTransform) error {
	if err := ValidateUpdateLimits(limits); err != nil {
		return err
	}
	return ErrUnsafePathUpdate
}
