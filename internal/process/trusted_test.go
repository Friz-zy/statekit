//go:build unix

package process

// Trusted command resolution tests (unix). Every vector runs against a
// synthetic filesystem seam: no test resolves through the real host
// filesystem in a way that depends on a dig binary being installed, and
// no test ever executes one. The one real-filesystem smoke vector only
// stats. This file is unix-constrained because it exercises the
// unix-only resolver internals (R102-FINAL-02); the non-unix fail-closed
// contract has its own file.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFileInfo is a minimal fs.FileInfo for the synthetic seam.
type fakeFileInfo struct {
	name string
	mode fs.FileMode
	uid  int64
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 1 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// fakeTrustedFS serves Lstat and Readlink from synthetic metadata.
// files maps real files and directories; links maps symlinks to their
// targets. lstats and readlinks record every query so tests can assert
// exactly which components the walker inspected.
type fakeTrustedFS struct {
	files    map[string]fakeFileInfo
	links    map[string]string
	lstats   []string
	readlink []string
}

func (f *fakeTrustedFS) Lstat(name string) (fs.FileInfo, error) {
	f.lstats = append(f.lstats, name)
	if _, ok := f.links[name]; ok {
		// Symlinks always present as lrwxrwxrwx; ownership is the
		// only link attribute the walker can meaningfully check.
		return fakeFileInfo{name: filepath.Base(name), mode: fs.ModeSymlink | 0o777, uid: 0}, nil
	}
	info, ok := f.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func (f *fakeTrustedFS) Readlink(name string) (string, error) {
	f.readlink = append(f.readlink, name)
	target, ok := f.links[name]
	if !ok {
		return "", os.ErrNotExist
	}
	return target, nil
}

// fakeOwner reads the synthetic uid; production reads Stat_t.
func fakeOwner(_ string, info fs.FileInfo) (int64, bool) {
	fake, ok := info.(fakeFileInfo)
	if !ok {
		return 0, false
	}
	return fake.uid, true
}

// fakeOwnerWithUid overrides the synthetic uid for exact paths, so a
// single tree entry (for example one symlink) can be user-owned.
func fakeOwnerWithUid(overrides map[string]int64) trustedOwner {
	return func(path string, info fs.FileInfo) (int64, bool) {
		if uid, ok := overrides[path]; ok {
			return uid, true
		}
		return fakeOwner(path, info)
	}
}

func newTrustedDigTree() *fakeTrustedFS {
	return &fakeTrustedFS{
		files: map[string]fakeFileInfo{
			"/":            {name: "/", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr":         {name: "usr", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr/bin":     {name: "bin", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr/bin/dig": {name: "dig", mode: 0o755, uid: 0},
		},
	}
}

func newTrustedUsermodTree() *fakeTrustedFS {
	return &fakeTrustedFS{
		files: map[string]fakeFileInfo{
			"/":                 {name: "/", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr":              {name: "usr", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr/sbin":         {name: "sbin", mode: fs.ModeDir | 0o755, uid: 0},
			"/usr/sbin/usermod": {name: "usermod", mode: 0o755, uid: 0},
		},
	}
}

func TestTrustedUsermodResolvesOnlyUsrSbinCandidate(t *testing.T) {
	fsys := newTrustedUsermodTree()
	path, err := resolveTrustedUsermodOn(fsys, fakeOwner)
	if err != nil || path != "/usr/sbin/usermod" {
		t.Fatalf("usermod resolve = %q, %v; want /usr/sbin/usermod", path, err)
	}
	for _, path := range fsys.lstats {
		if path != "/" && path != "/usr" && path != "/usr/sbin" && path != "/usr/sbin/usermod" {
			t.Fatalf("usermod resolver inspected unexpected path %q", path)
		}
	}
}

func TestTrustedUsermodResolverRejectsHostileAndAlternateTrees(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeTrustedFS)
	}{
		{"missing usermod; sbin-only bait", func(f *fakeTrustedFS) {
			delete(f.files, "/usr/sbin/usermod")
			f.files["/sbin"] = fakeFileInfo{name: "sbin", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/sbin/usermod"] = fakeFileInfo{name: "usermod", mode: 0o755, uid: 0}
		}},
		{"writable usr ancestor", func(f *fakeTrustedFS) {
			f.files["/usr"] = fakeFileInfo{name: "usr", mode: fs.ModeDir | 0o777, uid: 0}
		}},
		{"user-owned sbin ancestor", func(f *fakeTrustedFS) {
			f.files["/usr/sbin"] = fakeFileInfo{name: "sbin", mode: fs.ModeDir | 0o755, uid: 1000}
		}},
		{"user-owned final helper", func(f *fakeTrustedFS) {
			f.files["/usr/sbin/usermod"] = fakeFileInfo{name: "usermod", mode: 0o755, uid: 1000}
		}},
		{"writable final helper", func(f *fakeTrustedFS) {
			f.files["/usr/sbin/usermod"] = fakeFileInfo{name: "usermod", mode: 0o777, uid: 0}
		}},
		{"non-executable final helper", func(f *fakeTrustedFS) {
			f.files["/usr/sbin/usermod"] = fakeFileInfo{name: "usermod", mode: 0o644, uid: 0}
		}},
		{"untrusted escape symlink", func(f *fakeTrustedFS) {
			delete(f.files, "/usr/sbin/usermod")
			f.links = map[string]string{"/usr/sbin/usermod": "/opt/usermod"}
		}},
		{"normalized escape symlink", func(f *fakeTrustedFS) {
			delete(f.files, "/usr/sbin/usermod")
			f.links = map[string]string{"/usr/sbin/usermod": "/usr/../opt/usermod"}
		}},
		{"symlink loop", func(f *fakeTrustedFS) {
			delete(f.files, "/usr/sbin/usermod")
			f.links = map[string]string{"/usr/sbin/usermod": "/usr/sbin/usermod"}
		}},
		{"nonregular final helper", func(f *fakeTrustedFS) {
			f.files["/usr/sbin/usermod"] = fakeFileInfo{name: "usermod", mode: fs.ModeSocket, uid: 0}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := newTrustedUsermodTree()
			tc.mutate(fsys)
			if path, err := resolveTrustedUsermodOn(fsys, fakeOwner); !errors.Is(err, ErrTrustedCommandUnavailable) || path != "" {
				t.Fatalf("resolve = %q, %v; want fail-closed unavailable", path, err)
			}
		})
	}
}

func TestTrustedDigResolvesCanonicalCandidate(t *testing.T) {
	fsys := newTrustedDigTree()
	path, err := resolveTrustedDigOn(fsys, fakeOwner)
	if err != nil || path != "/usr/bin/dig" {
		t.Fatalf("resolve = %q, %v; want /usr/bin/dig", path, err)
	}
	// The walk stays on the first candidate's component chain (the
	// later candidates are never consulted).
	sawCandidate := false
	for _, stat := range fsys.lstats {
		if stat == "/usr/bin/dig" {
			sawCandidate = true
		}
		if stat != "/usr/bin/dig" && stat != "/usr/bin" && stat != "/usr" && stat != "/" {
			t.Fatalf("unexpected lstat path: %q", stat)
		}
	}
	if !sawCandidate {
		t.Fatalf("first candidate never walked: %v", fsys.lstats)
	}
}

func TestTrustedDigFallsThroughCandidatesInOrder(t *testing.T) {
	fsys := newTrustedDigTree()
	delete(fsys.files, "/usr/bin/dig")
	fsys.files["/usr/local/bin/dig"] = fakeFileInfo{name: "dig", mode: 0o755, uid: 0}
	fsys.files["/usr/local"] = fakeFileInfo{name: "local", mode: fs.ModeDir | 0o755, uid: 0}
	fsys.files["/usr/local/bin"] = fakeFileInfo{name: "bin", mode: fs.ModeDir | 0o755, uid: 0}
	path, err := resolveTrustedDigOn(fsys, fakeOwner)
	if err != nil || path != "/usr/local/bin/dig" {
		t.Fatalf("resolve = %q, %v; want /usr/local/bin/dig", path, err)
	}
}

// newChainedDigTree builds a tree where the /bin candidate passes a
// directory symlink (/bin -> usr/bin, relative, like merged-usr), the
// /usr/bin/dig candidate is an absolute symlink into /usr/lib/bind9,
// and the real executable lives there. Every hop is inside the
// approved system roots and every component is root-owned 0755.
func newChainedDigTree() *fakeTrustedFS {
	fsys := newTrustedDigTree()
	delete(fsys.files, "/usr/bin/dig")
	fsys.links = map[string]string{
		"/bin":         "usr/bin",
		"/usr/bin/dig": "/usr/lib/bind9/dig",
	}
	fsys.files["/usr/lib"] = fakeFileInfo{name: "lib", mode: fs.ModeDir | 0o755, uid: 0}
	fsys.files["/usr/lib/bind9"] = fakeFileInfo{name: "bind9", mode: fs.ModeDir | 0o755, uid: 0}
	fsys.files["/usr/lib/bind9/dig"] = fakeFileInfo{name: "dig", mode: 0o755, uid: 0}
	return fsys
}

func TestTrustedDigSymlinkChainStaysInApprovedRoots(t *testing.T) {
	fsys := newChainedDigTree()
	// The first candidate resolves through the /usr/bin/dig symlink.
	path, err := resolveTrustedDigOn(fsys, fakeOwner)
	if err != nil || path != "/usr/lib/bind9/dig" {
		t.Fatalf("resolve = %q, %v; want /usr/lib/bind9/dig", path, err)
	}
	if len(fsys.readlink) == 0 || fsys.readlink[0] != "/usr/bin/dig" {
		t.Fatalf("readlinks = %v, want /usr/bin/dig first", fsys.readlink)
	}
	// The /bin/dig candidate crosses a directory symlink too; exercise
	// it directly against the production roots.
	bin, err := trustedChainPath(fsys, fakeOwner, "/bin/dig", trustedDigRoots)
	if err != nil || bin != "/usr/lib/bind9/dig" {
		t.Fatalf("/bin/dig resolve = %q, %v; want /usr/lib/bind9/dig", bin, err)
	}
}

func TestTrustedDigRejections(t *testing.T) {
	cases := []struct {
		name  string
		mutio func(*fakeTrustedFS)
	}{
		{"missing binary", func(f *fakeTrustedFS) { delete(f.files, "/usr/bin/dig") }},
		{"dangling symlink", func(f *fakeTrustedFS) {
			delete(f.files, "/usr/bin/dig")
			f.links = map[string]string{"/usr/bin/dig": "/gone/dig"}
		}},
		{"symlink loop", func(f *fakeTrustedFS) {
			f.links = map[string]string{"/usr/bin/dig": "/usr/bin/dig"}
		}},
		{"mutual symlink loop", func(f *fakeTrustedFS) {
			f.links = map[string]string{"/usr/bin/dig": "/usr/bin/dig2", "/usr/bin/dig2": "/usr/bin/dig"}
		}},
		{"non-root owner", func(f *fakeTrustedFS) {
			bin := f.files["/usr/bin/dig"]
			bin.uid = 1000
			f.files["/usr/bin/dig"] = bin
		}},
		{"group-writable binary", func(f *fakeTrustedFS) {
			bin := f.files["/usr/bin/dig"]
			bin.mode = 0o775
			f.files["/usr/bin/dig"] = bin
		}},
		{"world-writable binary", func(f *fakeTrustedFS) {
			bin := f.files["/usr/bin/dig"]
			bin.mode = 0o757
			f.files["/usr/bin/dig"] = bin
		}},
		{"non-executable binary", func(f *fakeTrustedFS) {
			bin := f.files["/usr/bin/dig"]
			bin.mode = 0o644
			f.files["/usr/bin/dig"] = bin
		}},
		{"directory instead of regular file", func(f *fakeTrustedFS) {
			f.files["/usr/bin/dig"] = fakeFileInfo{name: "dig", mode: fs.ModeDir | 0o755, uid: 0}
		}},
		{"group-writable parent directory", func(f *fakeTrustedFS) {
			f.files["/usr/bin"] = fakeFileInfo{name: "bin", mode: fs.ModeDir | 0o775, uid: 0}
		}},
		{"world-writable ancestor", func(f *fakeTrustedFS) {
			f.files["/usr"] = fakeFileInfo{name: "usr", mode: fs.ModeDir | 0o757, uid: 0}
		}},
		{"non-root ancestor owner", func(f *fakeTrustedFS) {
			f.files["/usr"] = fakeFileInfo{name: "usr", mode: fs.ModeDir | 0o755, uid: 1234}
		}},
		{"world-writable filesystem root", func(f *fakeTrustedFS) {
			f.files["/"] = fakeFileInfo{name: "/", mode: fs.ModeDir | 0o777, uid: 0}
		}},
		{"missing ancestor metadata", func(f *fakeTrustedFS) { delete(f.files, "/usr") }},
		{"group-writable symlink target directory", func(f *fakeTrustedFS) {
			f.links = map[string]string{"/usr/bin/dig": "/usr/lib/bind9/dig"}
			f.files["/usr/lib"] = fakeFileInfo{name: "lib", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/usr/lib/bind9"] = fakeFileInfo{name: "bind9", mode: fs.ModeDir | 0o775, uid: 0}
			f.files["/usr/lib/bind9/dig"] = fakeFileInfo{name: "dig", mode: 0o755, uid: 0}
		}},
		{"symlink target outside approved roots", func(f *fakeTrustedFS) {
			// Even a perfectly root-owned regular executable outside
			// the approved system roots is rejected.
			f.links = map[string]string{"/usr/bin/dig": "/opt/vendor/dig"}
			f.files["/opt"] = fakeFileInfo{name: "opt", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/opt/vendor"] = fakeFileInfo{name: "vendor", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/opt/vendor/dig"] = fakeFileInfo{name: "dig", mode: 0o755, uid: 0}
		}},
		{"relative traversal target escapes roots", func(f *fakeTrustedFS) {
			f.links = map[string]string{"/usr/bin/dig": "../../tmp/dig"}
			f.files["/tmp"] = fakeFileInfo{name: "tmp", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/tmp/dig"] = fakeFileInfo{name: "dig", mode: 0o755, uid: 0}
		}},
		{"non-regular final target", func(f *fakeTrustedFS) {
			f.links = map[string]string{"/usr/bin/dig": "/usr/lib/bind9/dig"}
			f.files["/usr/lib"] = fakeFileInfo{name: "lib", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/usr/lib/bind9"] = fakeFileInfo{name: "bind9", mode: fs.ModeDir | 0o755, uid: 0}
			f.files["/usr/lib/bind9/dig"] = fakeFileInfo{name: "dig", mode: fs.ModeSocket, uid: 0}
		}},
	}
	for _, tc := range cases {
		fsys := newTrustedDigTree()
		tc.mutio(fsys)
		// Rejections must apply through the last candidate too.
		if _, err := resolveTrustedDigOn(fsys, fakeOwner); !errors.Is(err, ErrTrustedCommandUnavailable) {
			t.Fatalf("%s: err = %v, want ErrTrustedCommandUnavailable", tc.name, err)
		}
	}
}

// TestTrustedDigUserOwnedSymlinkRejected isolates the owner-seam
// rejection for a user-owned symlink whose target tree is otherwise
// perfectly trusted.
func TestTrustedDigUserOwnedSymlinkRejected(t *testing.T) {
	fsys := newChainedDigTree()
	owner := fakeOwnerWithUid(map[string]int64{"/usr/bin/dig": 1000})
	if _, err := resolveTrustedDigOn(fsys, owner); !errors.Is(err, ErrTrustedCommandUnavailable) {
		t.Fatalf("user-owned symlink err = %v, want ErrTrustedCommandUnavailable", err)
	}
	// The same tree with a root-owned symlink resolves.
	if path, err := resolveTrustedDigOn(fsys, fakeOwner); err != nil || path != "/usr/lib/bind9/dig" {
		t.Fatalf("root-owned symlink resolve = %q, %v", path, err)
	}
}

func TestTrustedCommandRejectsNamesOutsideFixedAllowlist(t *testing.T) {
	runner := DefaultRunner{}
	for _, name := range []string{"ps", "mysql", "dig.sh", "", "./dig", "/usr/bin/dig"} {
		if _, err := runner.ResolveTrustedCommand(name); !errors.Is(err, ErrTrustedCommandUnsupported) {
			t.Fatalf("ResolveTrustedCommand(%q) err = %v, want ErrTrustedCommandUnsupported", name, err)
		}
	}
}

// TestTrustedDigRealHostResolutionIsMetadataOnly is the wiring smoke
// vector: on the real filesystem the resolver either yields a trusted
// absolute regular executable or fails closed. It only stats and reads
// symlinks — it never executes anything — and it tolerates hosts that
// ship dig and hosts that do not.
func TestTrustedDigRealHostResolutionIsMetadataOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("real-filesystem metadata walk skipped in short mode")
	}
	path, err := (DefaultRunner{}).ResolveTrustedCommand("dig")
	if err != nil {
		if !errors.Is(err, ErrTrustedCommandUnavailable) {
			t.Fatalf("resolve err = %v, want ErrTrustedCommandUnavailable", err)
		}
		return
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("resolved path %q is not absolute", path)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("resolved path %q is not a regular executable: %v", path, err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("resolved path %q is group/world writable", path)
	}
}
