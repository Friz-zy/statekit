package runtime

import (
	"context"
	"errors"
	"strings"
)

// Bounded atomic update capability (R10.3b): an optional
// read-modify-publish transaction over Runtime.FS, symmetric with the
// bounded-read and bounded-directory capabilities. It exists so
// file-mutating ports of pinned Salt modules (dnsutil.hosts_append,
// dnsutil.hosts_remove) never truncate or append a destination in
// place: the replacement is rendered and validated in full BEFORE any
// staging or publication happens, and publication is a single atomic
// namespace operation. Errors of this capability are value-free — no
// path or content bytes travel in them.
//
// Trust boundary: this is a trusted same-principal local mutation
// API. The caller-selected path is a PRIVILEGED input — the
// capability performs no confinement or authorization beyond the
// no-follow descriptor walk and the documented bounds; callers
// transporting untrusted input must validate destinations themselves.

var (
	// ErrUpdateUnsupported identifies a filesystem without the optional
	// bounded atomic-update capability. Callers must not fall back to
	// ReadFile/WriteFile: silently doing so would discard the atomicity
	// and bound guarantees the capability exists to provide.
	ErrUpdateUnsupported = errors.New("runtime: bounded file updates unsupported")

	// ErrUnsafePathUpdate reports that the current platform cannot
	// provide the descriptor/no-follow guarantees the bounded update
	// requires; those platforms fail closed exactly like
	// ErrUnsafePathRead does for bounded reads.
	ErrUnsafePathUpdate = errors.New("runtime: bounded path update unsupported")

	// ErrInvalidUpdateLimit reports a non-positive or unreasonably large
	// bounded-update limit. The finite ceiling must be established
	// before the filesystem is touched so no unbounded allocation can
	// be triggered.
	ErrInvalidUpdateLimit = errors.New("runtime: invalid bounded update limit")

	// ErrInvalidUpdateTransform reports a missing transform function.
	ErrInvalidUpdateTransform = errors.New("runtime: bounded update requires a transform")

	// ErrWriteLimit reports that a transform's complete replacement
	// exceeds the write ceiling; the target is left unchanged.
	ErrWriteLimit = errors.New("runtime: file exceeds write limit")

	// ErrUpdateConflict reports that the target changed identity between
	// the bounded read and the atomic publication (or that a racing
	// creator occupied an initially-absent target); the update aborted
	// without publishing. This is a narrowed-race detector, not a CAS:
	// a modification landing between the final identity revalidation
	// and the publication syscall can still be superseded.
	ErrUpdateConflict = errors.New("runtime: file changed during update")

	// ErrUpdateCommittedUncertain reports that the new content IS
	// published but the post-publication parent-directory fsync failed,
	// so durability across a power failure is uncertain. This outcome
	// is deliberately distinct from every pre-publication failure:
	// those leave the target unchanged, this one does not roll back.
	ErrUpdateCommittedUncertain = errors.New("runtime: update committed but durability uncertain")

	// ErrInvalidUpdatePath reports a caller path that was rejected on
	// its ORIGINAL bytes before any filesystem or map access: an empty
	// path, a NUL byte, a path over MaxUpdatePathBytes, any ".."
	// component (rejected outright — there is no lexical cancellation),
	// or trailing-slash / terminal "/." directory syntax for a file
	// target (R103B-SEC-01).
	ErrInvalidUpdatePath = errors.New("runtime: invalid update path")

	// ErrUpdateCreateUnsupported reports that the current platform has
	// no atomic no-replace publication primitive and therefore fails
	// closed for an initially-absent target BEFORE anything is staged:
	// solaris has no linkat in the pinned x/sys surface, and the only
	// alternative (streaming the O_EXCL final form into place)
	// publishes the name before its contents complete — a
	// partial-visibility window the atomic-publication contract
	// forbids. The existing-target rename path (genuinely atomic)
	// remains available on such platforms (R103B-GATE-01/SEC-01).
	ErrUpdateCreateUnsupported = errors.New("runtime: atomic no-replace publication unsupported")

	// ErrUpdateCleanupFailed reports a PRE-publication failure whose
	// staging-file cleanup also failed. The target is still unchanged
	// (nothing was published); the distinct sentinel exists because a
	// leftover staging file is an operational outcome callers must be
	// able to distinguish from a clean abort (R103B-GATE-03/SEC-07).
	// The original failure class is deliberately not reported.
	ErrUpdateCleanupFailed = errors.New("runtime: update failed and staging cleanup failed")

	// ErrUpdateStagingResidue reports a successful no-replace
	// publication whose staging-name unlink then failed. The new
	// content IS live under the target name; only a stray staging file
	// remains. This is NOT a rollback and is never described as one —
	// the publication cannot be undone (R103B-GATE-03/SEC-07).
	ErrUpdateStagingResidue = errors.New("runtime: update committed with staging residue")

	// ErrUpdateTransform is the fixed CAUSE-FREE answer for EVERY error
	// returned by an UpdateTransform callback (R103B-SEC-06). The
	// capability boundary does not inspect the callback error at all —
	// no Error, Is, As, or Unwrap call on it, not even for
	// classification — so a callback error can carry arbitrary text,
	// arbitrary identity chains, attached values, or hostile
	// method implementations (including panicking or
	// sentinel-fabricating Is/Unwrap/As) without any of it being
	// reachable. The sentinel's Error() is constant, there is no
	// Unwrap, and there is NO custom Is: errors.Is matches ONLY this
	// fixed identity — a callback error can never make the boundary
	// classify context.Canceled, a module sentinel, or any other
	// arbitrary target — and errors.As has no chain to walk, so no
	// callback payload can be extracted. Real context
	// cancellation/deadline is detected exclusively by the runtime's
	// independent ctx checks before and after the transform, never by a
	// callback-supplied error. Transform callbacks must not embed
	// secrets in returned errors; the boundary guarantees no callback
	// text reaches a caller-facing error string.
	ErrUpdateTransform = errors.New("runtime: update transform failed")

	// ErrUpdateStageHook is the fixed CAUSE-FREE answer for every
	// non-nil fault-seam (stage-hook) error — the OS staging,
	// revalidate, and publish seams and the MemoryFS start/commit
	// seams. Fault-seam errors are callback-shaped and can carry
	// arbitrary strings, values, or hostile method implementations, so
	// the boundary does not wrap their cause and never invokes a single
	// method of the fault error (no Error, Is, As, Unwrap, or
	// formatting): the fault is DROPPED and this fixed sentinel answers
	// in its place (R103B-REGATE-01). No Unwrap, no errors.As path, no
	// formatting, and no errors.Is identity of the fault survives —
	// only the fixed sentinel identity does. A hook fault on the
	// revalidate/publish stages flows through the checked-cleanup
	// contract: a failing staging cleanup answers ErrUpdateCleanupFailed
	// instead (the target is unchanged either way), and the fault is
	// never misclassified as the post-publication residue or
	// committed-uncertain classes.
	ErrUpdateStageHook = errors.New("runtime: update stage hook failed")
)

// MaxBoundedWriteLimit is the largest finite replacement size accepted
// by UpdateFileBounded, symmetric with MaxBoundedReadLimit.
const MaxBoundedWriteLimit int64 = 64 << 20

// UpdateLimits bounds one read-modify-publish transaction. Both fields
// are mandatory and validated before the filesystem is touched.
type UpdateLimits struct {
	// MaxReadBytes bounds the existing-content read: at most this many
	// bytes plus one sentinel byte, so oversize input is detected
	// without being allocated.
	MaxReadBytes int64
	// MaxWriteBytes bounds the complete replacement content the
	// transform produces; a larger result rejects before any staging.
	MaxWriteBytes int64
}

// UpdateTransform computes the complete replacement content from the
// existing bytes (nil when the target does not exist). It must be pure
// — no filesystem access, no process dispatch, no network use —
// because it runs inside the update transaction. Returning an error
// aborts the transaction with the target unchanged; the error is
// never inspected by the capability boundary — its TEXT, identity
// chain, and any attached value are all DROPPED and the fixed
// cause-free ErrUpdateTransform sentinel (constant message, no
// Unwrap, no custom Is) answers in its place — so callbacks must not
// embed secrets or caller values in returned errors: neither can
// escape.
type UpdateTransform func(existing []byte, exists bool) ([]byte, error)

// BoundedUpdateFileSystem is the optional bounded atomic
// read-modify-publish capability. Implementations must guarantee:
// the ORIGINAL caller path is validated (ErrInvalidUpdatePath) before
// any filesystem or map access; before publication the target is
// unchanged on every failure path; publication is one atomic namespace
// operation, or the platform fails closed for the absent-target case
// with ErrUpdateCreateUnsupported; the pre-publication cleanup contract
// is checked (a staging-unlink failure answers the distinct
// ErrUpdateCleanupFailed sentinel with the target still unchanged, and
// a post-publication staging-unlink failure answers the distinct
// ErrUpdateStagingResidue sentinel with the content live — never a
// rollback); the post-publication parent-directory fsync failure
// answers ErrUpdateCommittedUncertain; every transform callback error
// is answered by the fixed cause-free ErrUpdateTransform sentinel
// (constant text, no Unwrap, no custom Is — the callback error is
// never inspected) and every stage-hook/fault-seam
// error is DROPPED and answered by the fixed ErrUpdateStageHook
// sentinel without invoking any of the fault's methods; and the
// caller's
// context cancellation is checked immediately before publication (or
// node replacement) with the target left unchanged.
//
// Publication REPLACES the target inode: the ordinary permission bits
// are preserved but owner and group are NOT (the staged file is
// created by the calling process), and ACLs, extended attributes,
// security labels, and hard links do not carry over.
//
// Concurrency ceiling: this is NOT a compare-and-swap. Identity
// revalidation (where present) detects inode REPLACEMENT only — a
// same-inode in-place write by another actor is invisible — so lost
// updates are possible throughout read-transform-stage-publish; the
// serialized implementations merely fix the order (their next
// transform sees the committed state). The upgrade path is
// cooperative: consumers needing real serialization hold their own
// lock across the call.
type BoundedUpdateFileSystem interface {
	UpdateFileBounded(ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error
}

// MaxUpdatePathBytes bounds the caller-supplied update path, enforced
// on the original bytes before any filesystem or map access.
const MaxUpdatePathBytes = 4096

// validateUpdatePath validates the ORIGINAL path string before any
// filesystem or map access: empty and over-cap paths, NUL bytes, any
// ".." component (rejected outright — there is no lexical
// cancellation, so symlink-then-.., missing-then-.., and
// non-dir-then-.. never reach resolution), and trailing-slash or
// terminal "/." directory syntax for a file target. It never rewrites
// the path; implementations may normalize only after these checks
// pass.
func validateUpdatePath(name string) error {
	if len(name) == 0 || len(name) > MaxUpdatePathBytes || strings.IndexByte(name, 0) >= 0 {
		return ErrInvalidUpdatePath
	}
	if strings.HasSuffix(name, "/") || strings.HasSuffix(name, "/.") || name == "." {
		return ErrInvalidUpdatePath
	}
	start := 0
	for index := 0; index <= len(name); index++ {
		if index < len(name) && name[index] != '/' {
			continue
		}
		if name[start:index] == ".." {
			return ErrInvalidUpdatePath
		}
		start = index + 1
	}
	return nil
}

// ValidateUpdateLimits enforces positive finite ceilings for both
// bounds before any filesystem access or allocation.
func ValidateUpdateLimits(limits UpdateLimits) error {
	if limits.MaxReadBytes <= 0 || limits.MaxReadBytes > MaxBoundedReadLimit {
		return ErrInvalidUpdateLimit
	}
	if limits.MaxWriteBytes <= 0 || limits.MaxWriteBytes > MaxBoundedWriteLimit {
		return ErrInvalidUpdateLimit
	}
	return nil
}

// UpdateFileBounded dispatches only to filesystems that implement the
// bounded atomic-update capability. Falling back to ReadFile/WriteFile
// would defeat both the allocation bound and the atomic publication, so
// a capability-less filesystem answers ErrUpdateUnsupported instead.
// The ORIGINAL path is validated here — before the capability probe
// and therefore before any filesystem or map access — and both
// implementations re-validate it as their first path-sensitive step.
func UpdateFileBounded(fsys FileSystem, ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error {
	if err := ValidateUpdateLimits(limits); err != nil {
		return err
	}
	if transform == nil {
		return ErrInvalidUpdateTransform
	}
	if err := validateUpdatePath(name); err != nil {
		return err
	}
	updater, ok := fsys.(BoundedUpdateFileSystem)
	if !ok {
		return ErrUpdateUnsupported
	}
	return updater.UpdateFileBounded(ctx, name, limits, allowCreate, transform)
}
