//go:build unix

package process

// Synthetic temp-tree tests for the full symlink-chain verification
// (R102-SEC-01): real directories, regular files, and symlinks are
// created under t.TempDir() and resolved through the production walker
// over real Lstat/Readlink calls. Ownership is synthesized (the
// unprivileged test cannot chown(2) entries to root) keyed by absolute
// path, and the ancestor directories above the test root — whose modes
// belong to the test environment, not to the code under test — are
// presented as fixed root-owned 0755 directories. Nothing is ever
// executed; the assertions only observe metadata resolution.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempTreeOwner synthesizes ownership over real Lstat metadata: paths
// in uids report their mapped uid, everything else reads as root-owned.
func tempTreeOwner(uids map[string]int64) trustedOwner {
	return func(path string, _ fs.FileInfo) (int64, bool) {
		if uid, ok := uids[path]; ok {
			return uid, true
		}
		return 0, true
	}
}

// tempTreeFS delegates metadata for paths inside root to the real OS
// and presents fixed root-owned 0755 directory metadata for the
// environment-controlled ancestors above the test root. Their real
// modes (a sticky, world-writable TMPDIR parent chain, for example) are
// properties of where the test happens to run, not of the symlink-chain
// verification under test. No symlink ever lives above root in these
// vectors, so Readlink above root always fails closed.
type tempTreeFS struct{ root string }

func (f tempTreeFS) aboveRoot(path string) bool {
	return path != f.root && !strings.HasPrefix(path, f.root+"/")
}

func (f tempTreeFS) Lstat(name string) (fs.FileInfo, error) {
	if f.aboveRoot(name) {
		return fakeFileInfo{name: filepath.Base(name), mode: fs.ModeDir | 0o755, uid: 0}, nil
	}
	return os.Lstat(name)
}

func (f tempTreeFS) Readlink(name string) (string, error) {
	if f.aboveRoot(name) {
		return "", os.ErrNotExist
	}
	return os.Readlink(name)
}

// newTempTree creates root/bin and root/lib/bind9 as 0755 directories
// plus a 0755 regular executable at root/lib/bind9/dig-real, and
// returns bin, the real executable path, and the tree root.
func newTempTree(t *testing.T) (bin, real, root string) {
	t.Helper()
	root = t.TempDir()
	bin = filepath.Join(root, "bin")
	lib := filepath.Join(root, "lib", "bind9")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	real = filepath.Join(lib, "dig-real")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n# synthetic; never executed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, real, root
}

// TestTrustedChainTempTreeSafeRootChainAndLink verifies the accepting
// path over a real filesystem: a relative symlink inside the approved
// root whose every component is a root-owned, non-group/world-writable
// directory ending in a root-owned regular executable.
func TestTrustedChainTempTreeSafeRootChainAndLink(t *testing.T) {
	bin, real, root := newTempTree(t)
	link := filepath.Join(bin, "dig")
	if err := os.Symlink("../lib/bind9/dig-real", link); err != nil {
		t.Fatal(err)
	}
	resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), link, []string{root})
	if err != nil {
		t.Fatalf("safe chain resolve: %v", err)
	}
	if resolved != real {
		t.Fatalf("resolve = %q, want %q", resolved, real)
	}
}

// newUsrTempTree creates the R102-FINAL-02 boundary tree: an approved
// root shaped like the production /usr (root/usr/bin and
// root/usr/lib/bind9 as 0755 directories with a 0755 regular executable
// at root/usr/lib/bind9/dig-real), plus a perfectly trusted escape
// destination outside the approved root (root/opt/vendor/dig, 0755
// directories and executable). Only the approved root is passed to the
// walker; everything under the tree root keeps real metadata.
func newUsrTempTree(t *testing.T) (approved, real, escape, root string) {
	t.Helper()
	root = t.TempDir()
	approved = filepath.Join(root, "usr")
	usrBin := filepath.Join(approved, "bin")
	lib := filepath.Join(approved, "lib", "bind9")
	for _, dir := range []string{usrBin, lib, filepath.Join(root, "opt", "vendor")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	real = filepath.Join(lib, "dig-real")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n# synthetic; never executed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	escape = filepath.Join(root, "opt", "vendor", "dig")
	if err := os.WriteFile(escape, []byte("#!/bin/sh\n# synthetic; never executed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return approved, real, escape, root
}

// TestTrustedChainTempTreeAbsoluteDotDotTargetRejected pins the
// R102-FINAL-02 boundary over a real filesystem: an absolute symlink
// target that lexically starts inside the approved root (the production
// analogue is /usr/../opt/vendor/dig, which begins with /usr/) but
// cleans outside it must be rejected — containment is decided on the
// normalized target, not the raw prefix. The escape tree carries
// perfectly trusted metadata (root-owned 0755 directories and a
// root-owned 0755 executable; only the boundary can reject it), and
// the same is enforced for a mid-chain directory symlink, not just the
// final component.
func TestTrustedChainTempTreeAbsoluteDotDotTargetRejected(t *testing.T) {
	approved, _, escape, root := newUsrTempTree(t)
	fsys := tempTreeFS{root: root}
	owner := tempTreeOwner(nil)

	// Final-component symlink: lexically <approved>/…, cleans to the
	// escape executable outside the approved root.
	link := filepath.Join(approved, "bin", "dig")
	target := approved + "/bin/../../opt/vendor/dig"
	if cleaned := filepath.Clean(target); cleaned != escape {
		t.Fatalf("test vector misshaped: %q cleans to %q, want %q", target, cleaned, escape)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if resolved, err := trustedChainPath(fsys, owner, link, []string{approved}); err == nil || resolved != "" {
		t.Fatalf("absolute dot-dot target resolve = %q, %v; want rejection", resolved, err)
	}

	// Mid-chain directory symlink: the absolute dot-dot target cleans
	// outside the approved root before any final component is reached.
	dirlink := filepath.Join(approved, "bindir")
	if err := os.Symlink(approved+"/bin/../../opt", dirlink); err != nil {
		t.Fatal(err)
	}
	if resolved, err := trustedChainPath(fsys, owner, filepath.Join(dirlink, "dig"), []string{approved}); err == nil || resolved != "" {
		t.Fatalf("directory symlink dot-dot target resolve = %q, %v; want rejection", resolved, err)
	}
}

// TestTrustedChainTempTreeAbsoluteTargetCleanedInsideRootAccepted keeps
// the safe pass: an absolute symlink target that lexically starts
// inside the approved root and still cleans inside it resolves through
// the production walker to the real executable (R102-FINAL-02 must
// reject only targets whose normalized form leaves the root).
func TestTrustedChainTempTreeAbsoluteTargetCleanedInsideRootAccepted(t *testing.T) {
	approved, real, _, root := newUsrTempTree(t)
	link := filepath.Join(approved, "bin", "dig")
	target := approved + "/bin/../lib/bind9/dig-real"
	if cleaned := filepath.Clean(target); cleaned != real {
		t.Fatalf("test vector misshaped: %q cleans to %q, want %q", target, cleaned, real)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), link, []string{approved})
	if err != nil {
		t.Fatalf("safe absolute target resolve: %v", err)
	}
	if resolved != real {
		t.Fatalf("safe absolute resolve = %q, want %q", resolved, real)
	}
}

// TestTrustedChainTempTreeRejections verifies the fail-closed paths
// over a real filesystem. Each case rebuilds the safe tree, applies one
// hostile mutation, and expects an empty resolution with an error.
func TestTrustedChainTempTreeRejections(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, bin, real, root string)
	}{
		{"user-owned symlink", func(t *testing.T, bin, real, root string) {
			link := filepath.Join(bin, "dig")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			owner := tempTreeOwner(map[string]int64{link: 1000})
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, owner, link, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"writable parent directory", func(t *testing.T, bin, real, root string) {
			link := filepath.Join(bin, "dig")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(bin, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), link, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"symlink loop", func(t *testing.T, bin, real, root string) {
			link := filepath.Join(bin, "dig")
			if err := os.Symlink("dig", link); err != nil {
				t.Fatal(err)
			}
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), link, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"traversal target outside roots", func(t *testing.T, bin, real, root string) {
			outside := t.TempDir()
			foreign := filepath.Join(outside, "dig")
			if err := os.WriteFile(foreign, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(bin, foreign)
			if err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(bin, "dig")
			if err := os.Symlink(rel, link); err != nil {
				t.Fatal(err)
			}
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), link, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"candidate outside allowed roots", func(t *testing.T, bin, real, root string) {
			outside := t.TempDir()
			foreign := filepath.Join(outside, "dig")
			if err := os.WriteFile(foreign, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			// Perfect metadata, wrong root: rejected by containment.
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), foreign, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"user-owned final executable", func(t *testing.T, bin, real, root string) {
			owner := tempTreeOwner(map[string]int64{real: 1000})
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, owner, real, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"world-writable final executable", func(t *testing.T, bin, real, root string) {
			if err := os.Chmod(real, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(real, 0o755) })
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), real, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
		{"non-executable final executable", func(t *testing.T, bin, real, root string) {
			if err := os.Chmod(real, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(real, 0o755) })
			if resolved, err := trustedChainPath(tempTreeFS{root: root}, tempTreeOwner(nil), real, []string{root}); err == nil || resolved != "" {
				t.Fatalf("resolve = %q, %v; want rejection", resolved, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, real, root := newTempTree(t)
			tc.run(t, bin, real, root)
		})
	}
}
