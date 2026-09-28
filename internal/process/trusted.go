// Trusted command resolution (plans/porting.md R10.2 R102-SEC-01).
//
// Production modules must not resolve fixed native helpers through the
// parent process PATH at launch time: a PATH-injected or untrusted
// writable binary would then be executed verbatim. TrustedCommandResolver
// is the narrow opt-in capability that resolves a fixed helper name to a
// trusted absolute executable path before any launch, so callers dispatch
// the resolved path instead of a PATH lookup. The DefaultRunner
// implementation is deliberately scoped to the single `dig` helper and the
// canonical system locations; every other name, and every platform without
// the required filesystem metadata, fails closed.

package process

import "errors"

var (
	// ErrTrustedCommandUnsupported reports a helper name outside the fixed
	// trusted-resolution allowlist or a platform without a supported
	// trust check. Resolution never falls back to PATH.
	ErrTrustedCommandUnsupported = errors.New("process: trusted command unsupported")
	// ErrTrustedCommandUnavailable reports that no canonical candidate
	// resolved to a trusted binary (missing, untrusted ownership, or
	// group/world-writable somewhere on the candidate, a symlink, or a
	// symlink target chain).
	ErrTrustedCommandUnavailable = errors.New("process: trusted command unavailable")
)

// TrustedCommandResolver is the optional, shell-free capability for
// resolving a fixed system helper to a trusted absolute path before a
// command that relies on it is launched. Resolution consults only
// canonical system candidate paths — never the parent PATH, the working
// directory, or caller-controlled environment.
type TrustedCommandResolver interface {
	// ResolveTrustedCommand returns the resolved absolute path of the
	// trusted system helper named name, or a fail-closed error.
	ResolveTrustedCommand(name string) (string, error)
}

// trustedDigName is the single helper name this implementation resolves.
const trustedDigName = "dig"

// ResolveTrustedCommand implements TrustedCommandResolver for the default
// Runner. Only the fixed `dig` helper is resolvable: candidates come from
// the canonical system dig locations, and each one is resolved with full
// symlink-chain verification — every component is Lstat'd, every
// directory and symlink on the chain (including each symlink target's
// chain) is root-owned with no group/world write on directories and the
// final binary, every symlink target stays inside the approved system
// roots, symlink hops are bounded against loops, and the final target is
// an absolute regular executable that is root-owned and non-writable. An
// unsupported name or platform fails closed with
// ErrTrustedCommandUnsupported; a missing or untrusted binary fails
// closed with ErrTrustedCommandUnavailable. A user-installed binary
// outside the canonical candidates and approved roots is unsupported:
// resolution never falls back to PATH, the working directory, or any
// caller-controlled location, and no process is started.
func (DefaultRunner) ResolveTrustedCommand(name string) (string, error) {
	if name != trustedDigName {
		return "", ErrTrustedCommandUnsupported
	}
	return resolveTrustedDig()
}
