package runtime

import (
	"context"
	"io/fs"
	"path"
	"strings"
	"syscall"
)

// UpdateFileBounded implements the bounded atomic read-modify-publish
// capability for MemoryFS as one transaction under a single mutex
// hold: the whole sequence — ORIGINAL-path validation, parent walk,
// type and limit validation, bounded read, pure transform,
// complete-replacement validation, and the node replacement — is
// atomic with respect to every other MemoryFS operation. Unlike the
// compatibility ReadFile/WriteFile methods this path never calls
// another public method (no recursive locking) and answers value-free
// errors only (no fs.PathError wrapping), matching the OS
// implementation's contract. Every transform callback error is
// answered at this boundary by the fixed cause-free ErrUpdateTransform
// sentinel (fixed text, no Unwrap, no custom Is — the callback error
// is never inspected), every injected
// start/commit hook fault is DROPPED without invoking a fault method
// and answered by the fixed ErrUpdateStageHook sentinel, and the
// caller's context is rechecked
// AFTER the transform and commit hook, immediately
// before the node replacement — a cancellation there leaves contents
// AND metadata untouched.
//
// Concurrency ceiling: mutex-serialized transactions are atomic but
// are NOT a compare-and-swap — racing updates on one path apply in
// some serialized order and the second supersedes the first. Unlike
// the OS implementation (where identity revalidation detects inode
// replacement only and a same-inode in-place writer is invisible, so
// lost updates are possible throughout read-transform-stage-publish),
// the mutex means the NEXT transaction's transform always sees the
// committed state of the previous one — a serialized-order guarantee,
// not a conflict detector. The upgrade path is cooperative: consumers
// needing real serialization against external actors hold their own
// lock across the call.
func (m *MemoryFS) UpdateFileBounded(ctx context.Context, name string, limits UpdateLimits, allowCreate bool, transform UpdateTransform) error {
	if err := ValidateUpdateLimits(limits); err != nil {
		return err
	}
	if transform == nil {
		return ErrInvalidUpdateTransform
	}
	// The ORIGINAL path is validated before any map access: NUL bytes,
	// the 4096-byte cap, any ".." component (no lexical cancellation),
	// and trailing-slash or "/." directory syntax. m.norm below may
	// Clean only AFTER these original-component checks pass.
	if err := validateUpdatePath(name); err != nil {
		return err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.updateStage("start"); err != nil {
		// A fault-seam error is callback-shaped: it is DROPPED and the
		// fixed value-free ErrUpdateStageHook sentinel answers in its
		// place (R103B-REGATE-01).
		return ErrUpdateStageHook
	}

	// Parent walk over RAW nodes (no symlink resolution), mirroring
	// ReadFileBounded: a symlinked or non-directory parent must never
	// redirect the update, and a missing parent fails closed (the
	// capability never creates directories).
	parts := strings.Split(strings.Trim(m.norm(name), "/"), "/")
	parent := "/"
	for index := 0; index < len(parts)-1; index++ {
		parent = path.Join(parent, parts[index])
		node, ok := m.nodes[parent]
		if !ok {
			return fs.ErrNotExist
		}
		if node.link != "" || !node.dir || node.mode.Type() != 0 {
			return ErrNonRegularFile
		}
	}
	target := path.Join(parent, parts[len(parts)-1])

	node, exists := m.nodes[target]
	if exists {
		if node.link != "" || node.mode.Type() != 0 {
			return ErrNonRegularFile
		}
		if node.dir {
			return syscall.EISDIR
		}
		if int64(len(node.data)) > limits.MaxReadBytes {
			return ErrReadLimit
		}
	}
	if !exists && !allowCreate {
		return fs.ErrNotExist
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	var existing []byte
	if exists {
		existing = make([]byte, len(node.data))
		copy(existing, node.data)
	}
	replacement, err := transform(existing, exists)
	if err != nil {
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

	// The complete validated replacement is the only thing that can be
	// committed; a commit-stage fault leaves the tree untouched (the
	// fault is DROPPED and the fixed ErrUpdateStageHook sentinel
	// answers — R103B-REGATE-01).
	if err := m.updateStage("commit"); err != nil {
		return ErrUpdateStageHook
	}
	// Recheck the context AFTER the transform and the commit hook,
	// immediately before the node replacement: a cancellation here
	// leaves the target — contents AND metadata — unchanged.
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	committed := make([]byte, len(replacement))
	copy(committed, replacement)
	now := m.now()
	if exists {
		node.data = committed
		node.modTime = now
		node.ctime = now
	} else {
		m.nodes[target] = &memNode{mode: 0o644, data: committed, modTime: now, ctime: now}
	}
	// Post-commit fault: the new content IS committed; only its
	// durability story is uncertain (the OS analogue is the
	// post-publication parent-directory fsync failure).
	if err := m.updateStage("durability"); err != nil {
		return ErrUpdateCommittedUncertain
	}
	return nil
}

// updateStage consults the optional fault-injection seam of
// UpdateFileBounded. Stage names: "start" (transaction start, before
// any validation side effects), "commit" (after transform validation,
// before the node replacement), and "durability" (after the commit).
// A non-nil start/commit fault is dropped at its call site — no fault
// method is ever invoked — and
// answered by the fixed ErrUpdateStageHook sentinel; a durability
// fault answers ErrUpdateCommittedUncertain (the content IS committed).
func (m *MemoryFS) updateStage(stage string) error {
	if m.updateHook == nil {
		return nil
	}
	return m.updateHook(stage)
}

// SetUpdateHook installs the fault-injection seam of UpdateFileBounded
// for hermetic tests (stages "start", "commit", "durability"). It is a
// test seam only and never part of the capability contract.
func (m *MemoryFS) SetUpdateHook(hook func(stage string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateHook = hook
}
