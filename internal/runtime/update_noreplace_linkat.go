//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package runtime

import (
	"golang.org/x/sys/unix"
)

// updateNoReplaceSupported reports whether this platform can publish
// an initially-absent target atomically: unix.Linkat with empty flags
// is one atomic namespace operation and answers EEXIST when the name
// is occupied, so the complete staged content becomes visible with no
// partial-visibility window.
const updateNoReplaceSupported = true

// publishStagedNoReplace links the staged file under base without
// replacing anything. EEXIST means a racing creator occupied the name;
// the caller maps that to ErrUpdateConflict and aborts (the staging
// unlink on this path is the caller's — its failure is
// post-publication residue, never a rollback).
func publishStagedNoReplace(dirfd int, staging, base string) error {
	return unix.Linkat(dirfd, staging, dirfd, base, 0)
}
