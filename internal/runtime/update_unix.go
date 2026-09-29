//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package runtime

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// osUpdateSeams carries test-only seams for the OS bounded-update path.
// Every callable defaults to the real syscall; tests in this package
// replace individual fields and restore them with t.Cleanup. The seams
// are never part of the capability contract.
var osUpdateSeams = struct {
	write    func(fd int, p []byte) (int, error)
	fsync    func(fd int) error
	close    func(fd int) error
	renameat func(olddirfd int, oldpath string, newdirfd int, newpath string) error
	unlinkat func(dirfd int, path string, flags int) error
	dirfsync func(fd int) error
	staging  func() string
	stage    func(stage string) error
}{
	write:    unix.Write,
	fsync:    unix.Fsync,
	close:    unix.Close,
	renameat: unix.Renameat,
	unlinkat: unix.Unlinkat,
	dirfsync: unix.Fsync,
}

const (
	updateOpenFlags    = unix.O_RDONLY | unix.O_CLOEXEC
	updateStageFlags   = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW
	stagingMode        = 0o600
	newUpdateFileMode  = 0o644
	updateStagingTries = 3
)

// UpdateFileBounded implements the bounded atomic read-modify-publish
// capability for OSFileSystem with the descriptor-relative, no-follow
// discipline of bounded_unix.go: the ORIGINAL caller path is validated
// first (NUL bytes, the 4096-byte cap, any ".." component rejected
// outright, trailing-slash and "/." directory syntax — before any
// filesystem access), then every parent is opened
// O_DIRECTORY|O_NOFOLLOW and the final component
// O_NOFOLLOW|O_NONBLOCK, so symlink-redirected paths, directories, and
// special files are rejected before any content is read (a bounded
// read of at most MaxReadBytes plus one sentinel). The transform runs
// pure — its error is never inspected and is answered at this boundary
// by the fixed cause-free ErrUpdateTransform sentinel (fixed text, no
// Unwrap, no custom Is — only errors.Is(ErrUpdateTransform) classifies)
// — and so is EVERY non-nil stage-hook fault
// (staging, revalidate, publish): fault-seam errors are
// callback-shaped, so the boundary DROPS them without invoking a
// single fault method and answers the
// fixed value-free ErrUpdateStageHook sentinel (no fault text, no
// fault identity, no Unwrap — R103B-REGATE-01). The replacement's
// complete output is
// validated against MaxWriteBytes BEFORE any staging. The replacement
// is staged in the target directory (O_CREATE|O_EXCL, mode 0600,
// never a truncation of the target), fully written with short-write
// handling, chmoded to the existing target's ordinary permission bits
// (0644 for a new file — owner/group are NOT preserved and ACLs,
// xattrs, labels, and hard links do not carry over), and fsynced
// (contents and metadata). Publication is one atomic namespace
// operation: rename over an identity-revalidated existing target, or
// a no-replace link publication for an initially-absent target on the
// platforms with the atomic primitive (solaris fails closed with
// ErrUpdateCreateUnsupported before anything is staged). The target's
// identity is revalidated immediately before publishing and a detected
// change aborts with ErrUpdateConflict.
//
// Cleanup contract: every pre-publication failure removes the staging
// file and leaves the target unchanged; when that cleanup itself
// fails, the distinct ErrUpdateCleanupFailed sentinel REPLACES the
// original error (the target is still unchanged). After a no-replace
// publication, a staging-unlink failure cannot un-publish the content
// and answers the distinct ErrUpdateStagingResidue sentinel — the
// content is live and this is never a rollback. The post-publication
// parent-directory fsync failure answers ErrUpdateCommittedUncertain
// because the new content IS published. Context cancellation is
// checked before staging and again before publication.
//
// Concurrency ceiling: this is NOT a compare-and-swap. Identity
// revalidation detects inode REPLACEMENT only — a same-inode in-place
// write by another actor (write(2) through another descriptor to the
// same inode) is invisible to it — so lost updates are possible
// throughout read→transform→stage→publish; a writer landing inside
// the revalidate→publish gap is superseded (last writer wins). The
// upgrade path is cooperative: consumers needing real serialization
// hold their own lock across the call.
func (OSFileSystem) UpdateFileBounded(ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error {
	if err := ValidateUpdateLimits(limits); err != nil {
		return err
	}
	if transform == nil {
		return ErrInvalidUpdateTransform
	}
	if err := validateUpdatePath(name); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	dirfd, base, err := openParentNoFollow(name)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dirfd) }()

	// Open the existing target without following a final symlink;
	// O_NONBLOCK keeps a planted special file from blocking the open.
	exists := true
	var mode fs.FileMode = newUpdateFileMode
	var identity unix.Stat_t
	var existing []byte
	fd, openErr := unix.Openat(dirfd, base, updateOpenFlags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	switch {
	case openErr == nil:
		if err := unix.Fstat(fd, &identity); err != nil {
			_ = unix.Close(fd)
			return err
		}
		mode = fs.FileMode(identity.Mode & 0o777)
		f := os.NewFile(uintptr(fd), "")
		if f == nil {
			_ = unix.Close(fd)
			return errors.New("runtime: unable to create file descriptor")
		}
		// readBoundedDescriptor enforces the regular-file requirement
		// (directories answer EISDIR, devices/FIFOs ErrNonRegularFile)
		// and the sentinel-bounded read, and closes the descriptor.
		existing, err = readBoundedDescriptor(f, limits.MaxReadBytes)
		if err != nil {
			return err
		}
	case errors.Is(openErr, syscall.ENOENT) && allowCreate:
		exists = false
	default:
		return openErr
	}

	// Platforms without an atomic no-replace primitive (solaris: no
	// linkat in the pinned x/sys surface) fail closed for an
	// initially-absent target HERE, before anything is staged — the
	// streaming O_EXCL final form was removed because it published
	// the name before its contents completed.
	if !exists && !updateNoReplaceSupported {
		return ErrUpdateCreateUnsupported
	}

	replacement, terr := transform(existing, exists)
	if terr != nil {
		// The capability boundary is CAUSE-FREE: the callback error is
		// never inspected (no Error, Is, As, or Unwrap call — not even
		// for classification), so no callback string, value, identity,
		// or hostile method can escape — the fixed sentinel answers
		// alone.
		return ErrUpdateTransform
	}
	if int64(len(replacement)) > limits.MaxWriteBytes {
		return ErrWriteLimit
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Stage the complete, already-validated replacement beside the
	// target. The name is unpredictable and O_EXCL-discovered, so a
	// collision retries with a fresh name and never follows a planted
	// symlink.
	staging := ""
	sfd := -1
	for attempt := 0; attempt < updateStagingTries; attempt++ {
		if err := osUpdateStageHook("staging"); err != nil {
			// A fault-seam error is callback-shaped: it is DROPPED at
			// this boundary and the fixed value-free sentinel answers
			// in its place (nothing is staged yet, so there is nothing
			// to clean up — R103B-REGATE-01).
			return ErrUpdateStageHook
		}
		candidate := updateStagingName()
		fd, err := unix.Openat(dirfd, candidate, updateStageFlags, stagingMode)
		if err == nil {
			staging, sfd = candidate, fd
			break
		}
		if !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	if sfd < 0 {
		return syscall.EEXIST
	}
	// abortUpdate answers a PRE-publication failure: the staging file
	// is removed and the target stays byte-identical. A cleanup
	// failure REPLACES the original error with the distinct value-free
	// ErrUpdateCleanupFailed sentinel (the target is still unchanged).
	abortUpdate := func(err error) error {
		if cleanupErr := osUpdateSeams.unlinkat(dirfd, staging, 0); cleanupErr != nil && !errors.Is(cleanupErr, syscall.ENOENT) {
			return ErrUpdateCleanupFailed
		}
		return err
	}

	if err := writeStagedContents(sfd, replacement, mode); err != nil {
		_ = osUpdateSeams.close(sfd)
		return abortUpdate(err)
	}
	if err := osUpdateSeams.close(sfd); err != nil {
		return abortUpdate(err)
	}

	if err := osUpdateStageHook("revalidate"); err != nil {
		// The fault is DROPPED and the fixed ErrUpdateStageHook
		// sentinel crosses the boundary even on the abort path:
		// abortUpdate preserves it as the returned class when cleanup
		// succeeds, or replaces it with ErrUpdateCleanupFailed when
		// cleanup fails (the target is unchanged either way).
		return abortUpdate(ErrUpdateStageHook)
	}
	var current unix.Stat_t
	if exists {
		if err := unix.Fstatat(dirfd, base, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return abortUpdate(err)
		}
		if current.Mode&unix.S_IFMT != unix.S_IFREG ||
			current.Dev != identity.Dev || current.Ino != identity.Ino {
			return abortUpdate(ErrUpdateConflict)
		}
	} else {
		err := unix.Fstatat(dirfd, base, &current, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return abortUpdate(ErrUpdateConflict)
		}
		if !errors.Is(err, syscall.ENOENT) {
			return abortUpdate(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return abortUpdate(err)
	}
	if err := osUpdateStageHook("publish"); err != nil {
		// Same boundary as revalidate — and the fault is DROPPED in
		// favor of the fixed ErrUpdateStageHook sentinel: this hook
		// fires BEFORE the publication syscall, so it is a
		// pre-publication abort — the checked-cleanup contract
		// applies, never the post-publication residue or
		// committed-uncertain classes.
		return abortUpdate(ErrUpdateStageHook)
	}

	// Publish atomically. The rename path replaces the revalidated
	// inode in one operation; the no-replace path (initially-absent
	// target) refuses to clobber anything that appeared meanwhile.
	if exists {
		if err := osUpdateSeams.renameat(dirfd, staging, dirfd, base); err != nil {
			return abortUpdate(err)
		}
	} else {
		if err := publishStagedNoReplace(dirfd, staging, base); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				return abortUpdate(ErrUpdateConflict)
			}
			return abortUpdate(err)
		}
		// Published. A staging-unlink failure cannot un-publish the
		// new content and is never described as a rollback: it only
		// leaves residue, reported through the distinct sentinel.
		if err := osUpdateSeams.unlinkat(dirfd, staging, 0); err != nil && !errors.Is(err, syscall.ENOENT) {
			return ErrUpdateStagingResidue
		}
	}
	if err := osUpdateSeams.dirfsync(dirfd); err != nil {
		// The publication already happened; only durability is
		// uncertain. This is the one failure that changes no verdict
		// about the content being live.
		return ErrUpdateCommittedUncertain
	}
	return nil
}

// writeStagedContents writes the complete replacement into the staging
// descriptor, handling short writes, then applies the final permission
// bits and fsyncs contents and metadata. Any failure leaves the caller
// to discard the staging file; the target itself is untouched.
func writeStagedContents(fd int, contents []byte, mode fs.FileMode) error {
	buf := contents
	for len(buf) > 0 {
		n, err := osUpdateSeams.write(fd, buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return err
	}
	return osUpdateSeams.fsync(fd)
}

// publishStagedNoReplace makes the staged content visible under base
// without replacing anything (EEXIST when base is already occupied).
// It is defined per platform in update_noreplace_linkat.go (the
// linkat-based atomic primitive) and update_solaris.go (fail-closed:
// solaris has no linkat in the pinned x/sys surface). The staging
// unlink afterwards is the caller's — its failure is post-publication
// residue, not an abort.

// osUpdateStageHook consults the optional stage fault-injection seam
// (stages "staging", "revalidate", "publish"); tests in this package
// install it, the default is a no-op. Every non-nil error it answers
// is DROPPED at its call sites and replaced by the fixed value-free
// ErrUpdateStageHook sentinel: the fault error's methods are never
// invoked at all, so the fault text, identity, and any
// attached value never cross the capability boundary (no Error text,
// no Unwrap, no errors.As, no formatting, no errors.Is identity —
// R103B-REGATE-01). On the revalidate/publish stages the sentinel then
// flows through abortUpdate's checked-cleanup contract: a failing
// staging cleanup answers ErrUpdateCleanupFailed instead (target
// unchanged), and the fault is never misclassified as the
// post-publication residue or committed-uncertain classes.
func osUpdateStageHook(stage string) error {
	if osUpdateSeams.stage == nil {
		return nil
	}
	return osUpdateSeams.stage(stage)
}

// openParentNoFollow walks every component of name's parent through
// directory descriptors opened O_DIRECTORY|O_NOFOLLOW — the
// readFileBoundedOS discipline — and returns the final parent
// directory descriptor plus the last component. An intermediate
// symlink can therefore never redirect the update outside the path the
// caller selected. The ORIGINAL components were already validated by
// validateUpdatePath (no "..", no NUL, no trailing directory syntax)
// before this walk; the filepath.Clean below runs only AFTER that
// original-component validation and cannot erase a rejected shape.
func openParentNoFollow(name string) (int, string, error) {
	cleaned := filepath.Clean(name)
	base := "."
	if filepath.IsAbs(cleaned) {
		base = string(filepath.Separator)
	}
	parts := strings.Split(cleaned, string(filepath.Separator))
	if filepath.IsAbs(cleaned) && len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	parts = compactPathComponents(parts)
	if len(parts) == 0 {
		return -1, "", syscall.EINVAL
	}
	dirfd, err := unix.Open(base, boundedOpenFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(dirfd, part, boundedOpenFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Close(dirfd)
			return -1, "", err
		}
		_ = unix.Close(dirfd)
		dirfd = next
	}
	return dirfd, parts[len(parts)-1], nil
}

// updateStagingName mints an unpredictable same-directory staging
// name. Tests may replace the generator through osUpdateSeams.staging
// for deterministic collision vectors.
func updateStagingName() string {
	if osUpdateSeams.staging != nil {
		return osUpdateSeams.staging()
	}
	var raw [8]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return fmt.Sprintf(".statekit-update-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return ".statekit-update-" + hex.EncodeToString(raw[:])
}
