//go:build unix

package process

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// trustedDigCandidates lists the canonical system dig locations in
// deterministic resolution order: the fixed Linux/macOS system paths
// /usr/bin/dig and /bin/dig, plus /usr/local/bin/dig, which is accepted
// only when its whole path chain passes the root-owned/no-group-world-
// write checks below (R102-SEC-01: "only if root-owned secure
// directories permit"). The list deliberately excludes every
// caller-controlled location: no PATH element, no working directory, no
// TMPDIR, no configuration-derived path, and no additional sbin, pkg,
// or homebrew locations.
var trustedDigCandidates = []string{
	"/usr/bin/dig",
	"/bin/dig",
	"/usr/local/bin/dig",
}

// trustedDigRoots are the approved system roots for trusted dig
// resolution: the candidate itself, every symlink target reached during
// resolution, and the final executable must all stay inside one of them
// (R102-SEC-01 full-chain closure). This is the exact remaining native
// runtime requirement: a dig binary installed anywhere else — a user or
// homebrew prefix such as /opt/homebrew or $HOME/bin, or any custom
// PATH directory — is unsupported and resolution fails closed with
// ErrTrustedCommandUnavailable; the dig module then answers its fixed
// value-free unavailable error and dispatches nothing. An operator who
// needs dig must install it under a canonical candidate path owned by
// root in non-group/world-writable directories.
var trustedDigRoots = []string{
	"/bin",
	"/usr",
	"/usr/local",
}

// trustedMaxSymlinkHops bounds the total number of symlink resolutions
// performed while walking one candidate. Anything at or beyond the
// bound is treated as a loop (or an unreasonably deep chain) and fails
// closed instead of hanging.
const trustedMaxSymlinkHops = 32

// trustedFS is the filesystem seam of the resolver. Lstat reports each
// component without following it, so symlinks are inspected as
// themselves rather than transparently trusted, and Readlink reads a
// symlink's target. Production uses the real OS calls; tests inject
// synthetic metadata or temp trees so no test ever depends on — let
// alone executes — a native dig binary.
type trustedFS interface {
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
}

type osTrustedFS struct{}

func (osTrustedFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (osTrustedFS) Readlink(name string) (string, error)   { return os.Readlink(name) }

// trustedOwner reports the owning UID of path; ok is false when the
// platform metadata is unavailable, which fails closed.
type trustedOwner func(path string, info fs.FileInfo) (int64, bool)

func unixOwner(_ string, info fs.FileInfo) (int64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int64(stat.Uid), true
}

// errTrustedChain is the internal fail-closed rejection for a single
// candidate; it never escapes this file — the caller skips to the next
// candidate and ultimately fails closed with
// ErrTrustedCommandUnavailable.
var errTrustedChain = errors.New("process: untrusted command path")

func resolveTrustedDig() (string, error) {
	return resolveTrustedDigOn(osTrustedFS{}, unixOwner)
}

// resolveTrustedDigOn walks the canonical candidates in order and
// returns the first whose full resolution passes trustedChainPath. A
// candidate that is missing, dangling, relative, or untrusted — at the
// binary, any ancestor directory, or any symlink hop — is skipped;
// exhausting the list fails closed.
func resolveTrustedDigOn(fsys trustedFS, owner trustedOwner) (string, error) {
	for _, candidate := range trustedDigCandidates {
		resolved, err := trustedChainPath(fsys, owner, candidate, trustedDigRoots)
		if err == nil {
			return resolved, nil
		}
	}
	return "", ErrTrustedCommandUnavailable
}

// resolveTrustedUsermod resolves exactly the Linux usermod candidate. It
// reuses the existing full-chain ownership, mode, symlink, and containment
// checks without expanding the candidate list or trusted roots.
func resolveTrustedUsermod() (string, error) {
	return resolveTrustedUsermodOn(osTrustedFS{}, unixOwner)
}

func resolveTrustedUsermodOn(fsys trustedFS, owner trustedOwner) (string, error) {
	resolved, err := trustedChainPath(fsys, owner, "/usr/sbin/usermod", trustedDigRoots)
	if err != nil {
		return "", ErrTrustedCommandUnavailable
	}
	return resolved, nil
}

// trustedChainPath resolves one absolute candidate path component by
// component with Lstat (R102-SEC-01 full symlink-chain verification):
//
//   - every directory component — of the candidate and of every symlink
//     target — must be a root-owned directory with no group or world
//     write, and the filesystem root itself is verified once;
//   - every symlink on the chain must be root-owned (its permission
//     bits are not consulted: Linux symlinks are always lrwxrwxrwx, so
//     the enforceable controls are the link's owner and the
//     non-group/world-writable, root-owned containing directory), its
//     target must be readable, and the resolved absolute path —
//     relative targets joined to the link's directory, absolute
//     targets cleaned — must stay inside an approved root. Containment
//     is decided on the normalized target (R102-FINAL-02): an
//     absolute target such as /usr/../opt/vendor/dig lexically starts
//     /usr/ but normalizes to /opt/vendor/dig, so it is rejected
//     unless the cleaned final target remains inside a canonical
//     approved root;
//   - the total number of symlink hops is bounded, so loops and deep
//     chains fail closed instead of hanging;
//   - the final component must be a root-owned regular executable with
//     no group or world write.
//
// It returns the fully resolved absolute executable path. Nothing is
// executed and no PATH lookup happens.
func trustedChainPath(fsys trustedFS, owner trustedOwner, path string, roots []string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !underTrustedRoot(path, roots) {
		return "", errTrustedChain
	}
	root := "/"
	if err := trustedDir(fsys, owner, root); err != nil {
		return "", err
	}
	remaining := trustedPathComponents(path)
	dir := root
	hops := 0
	for len(remaining) > 0 {
		child := filepath.Join(dir, remaining[0])
		info, err := fsys.Lstat(child)
		if err != nil {
			return "", err
		}
		mode := info.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			hops++
			if hops > trustedMaxSymlinkHops {
				return "", errTrustedChain
			}
			// Permission bits are skipped for symlinks (always 0777);
			// ownership and the (already verified) containing
			// directory carry the control.
			if !rootOwned(owner, child, info) {
				return "", errTrustedChain
			}
			target, err := fsys.Readlink(child)
			if err != nil {
				return "", err
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				// Join cleans the relative branch.
				resolved = filepath.Join(dir, resolved)
			} else {
				// Every absolute target is cleaned before the
				// prefix/root acceptance (R102-FINAL-02): the
				// raw lexical prefix must not decide containment,
				// only the normalized target may.
				resolved = filepath.Clean(resolved)
			}
			if !underTrustedRoot(resolved, roots) {
				return "", errTrustedChain
			}
			// Continue with the target's components followed by the
			// rest of the original path, restarting from the verified
			// filesystem root.
			remaining = append(trustedPathComponents(resolved), remaining[1:]...)
			dir = root
		case mode.IsDir():
			if len(remaining) == 1 {
				// The final component must be the executable itself,
				// not a directory.
				return "", errTrustedChain
			}
			if !rootOwnedNoGroupWorldWrite(owner, child, info) {
				return "", errTrustedChain
			}
			dir = child
			remaining = remaining[1:]
		case mode.IsRegular():
			if len(remaining) != 1 || mode.Perm()&0o111 == 0 ||
				!rootOwnedNoGroupWorldWrite(owner, child, info) {
				return "", errTrustedChain
			}
			return child, nil
		default:
			// Devices, sockets, and FIFOs are never trusted executables.
			return "", errTrustedChain
		}
	}
	return "", errTrustedChain
}

// trustedDir verifies one directory component.
func trustedDir(fsys trustedFS, owner trustedOwner, dir string) error {
	info, err := fsys.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.Mode().IsDir() || !rootOwnedNoGroupWorldWrite(owner, dir, info) {
		return errTrustedChain
	}
	return nil
}

// trustedPathComponents splits an absolute path into components; the
// filesystem root answers no components.
func trustedPathComponents(path string) []string {
	if path == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

// underTrustedRoot reports whether the absolute, clean path is one of
// the approved roots or lies inside one of them.
func underTrustedRoot(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func rootOwnedNoGroupWorldWrite(owner trustedOwner, path string, info fs.FileInfo) bool {
	if info.Mode().Perm()&0o022 != 0 {
		return false
	}
	return rootOwned(owner, path, info)
}

func rootOwned(owner trustedOwner, path string, info fs.FileInfo) bool {
	uid, ok := owner(path, info)
	return ok && uid == 0
}
