//go:build windows

package runtime

import (
	"context"
)

// Windows path opens do not have a portable standard-library no-follow
// mode with the descriptor guarantees the bounded update requires, so
// the capability fails closed deterministically rather than falling
// back to a non-atomic ReadFile/WriteFile path.
func (OSFileSystem) UpdateFileBounded(_ context.Context, _ string, limits UpdateLimits, _ bool, _ UpdateTransform) error {
	if err := ValidateUpdateLimits(limits); err != nil {
		return err
	}
	return ErrUnsafePathUpdate
}
