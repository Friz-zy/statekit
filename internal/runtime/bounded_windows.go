//go:build windows

package runtime

// Windows path opens do not have a portable standard-library no-follow mode
// with the descriptor guarantees required by bounded consumers. Refuse this
// unsafe path mode deterministically rather than falling back to ReadFile.
func readFileBoundedOS(_ string, limit int64) ([]byte, error) {
	if err := validateBoundedReadLimit(limit); err != nil {
		return nil, err
	}
	return nil, ErrUnsafePathRead
}
