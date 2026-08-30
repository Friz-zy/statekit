//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package runtime

// Unsupported platforms fail closed because their path-open semantics have
// not been proven to provide the no-follow descriptor boundary.
func readFileBoundedOS(_ string, limit int64) ([]byte, error) {
	if err := validateBoundedReadLimit(limit); err != nil {
		return nil, err
	}
	return nil, ErrUnsafePathRead
}
