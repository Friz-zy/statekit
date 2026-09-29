//go:build solaris

package runtime

// updateNoReplaceSupported is false on solaris (R103B-GATE-01/
// R103B-SEC-01): the pinned x/sys surface has no linkat, and the only
// remaining creation strategy — an O_EXCL open of the FINAL name
// streamed into place — publishes the name before its contents
// complete, a partial-visibility window the atomic-publication
// contract forbids. Absent-target publication therefore fails closed
// with the fixed ErrUpdateCreateUnsupported BEFORE anything is staged.
// The existing-target path remains fully available: renameat over an
// identity-revalidated inode is genuinely atomic.
const updateNoReplaceSupported = false

// publishStagedNoReplace never runs on solaris (the transaction fails
// closed before staging when the target is initially absent); it
// answers the fixed unsupported error defensively.
func publishStagedNoReplace(int, string, string) error {
	return ErrUpdateCreateUnsupported
}
