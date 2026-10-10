// Trusted command resolution (plans/porting.md R10.2 R102-SEC-01).
//
// Production modules must not resolve fixed native helpers through the
// parent process PATH at launch time: a PATH-injected or untrusted
// writable binary would then be executed verbatim. TrustedCommandResolver
// is the narrow opt-in capability that resolves a fixed helper name to a
// trusted absolute executable path before any launch, so callers dispatch
// the resolved path instead of a PATH lookup. DefaultRunner resolves the
// canonical dig candidates and, on Linux only, the fixed /usr/sbin/usermod
// candidate. Every other name and unsupported platform fails closed.

package process

import (
	"errors"
	goruntime "runtime"
)

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

// These helper names are the complete fixed resolver allowlist.
const trustedDigName = "dig"

const trustedUsermodName = "usermod"

// ResolveTrustedCommand implements TrustedCommandResolver for the default
// Runner. It supports dig's canonical candidate set and, on Linux only, the
// single /usr/sbin/usermod candidate. Unix candidates use full symlink-chain
// verification; unsupported names/platforms and missing or untrusted helpers
// fail closed. Resolution never falls back to PATH, the working directory,
// or a caller-controlled location, and no process is started.
func (DefaultRunner) ResolveTrustedCommand(name string) (string, error) {
	if name == trustedDigName {
		return resolveTrustedDig()
	}
	if name == trustedUsermodName {
		if goruntime.GOOS != "linux" {
			return "", ErrTrustedCommandUnsupported
		}
		return resolveTrustedUsermod()
	}
	return "", ErrTrustedCommandUnsupported
}
