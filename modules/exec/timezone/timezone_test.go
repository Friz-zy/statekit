package timezone

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type scriptRunner struct {
	script []process.CommandResult
	calls  [][]string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func TestGetZoneFromFile(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/timezone", []byte("Europe/Berlin\n"), 0o644)
	value, err := (getZoneFunc{}).Execute(context.Background(), rt, &getZoneArgs{})
	if err != nil || value != "Europe/Berlin" {
		t.Fatalf("zone = %v, %v", value, err)
	}
}

func TestGetZoneFromLocaltimeSymlink(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.MkdirAll("/usr/share/zoneinfo", 0o755)
	rt.FS.Symlink("/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
	value, err := (getZoneFunc{}).Execute(context.Background(), rt, &getZoneArgs{})
	if err != nil || value != "Asia/Tokyo" {
		t.Fatalf("zone from symlink = %v, %v", value, err)
	}
}

func TestSetZone(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.MkdirAll("/usr/share/zoneinfo/Europe", 0o755)
	rt.FS.WriteFile("/usr/share/zoneinfo/Europe/Paris", []byte{0x1}, 0o644)

	if _, err := (setZoneFunc{}).Execute(context.Background(), rt, &setZoneArgs{TimeZone: "Europe/Paris"}); err != nil {
		t.Fatalf("set_zone: %v", err)
	}
	target, err := rt.FS.Readlink("/etc/localtime")
	if err != nil || target != "/usr/share/zoneinfo/Europe/Paris" {
		t.Fatalf("localtime link = %q, %v", target, err)
	}
	data, _ := rt.FS.ReadFile("/etc/timezone")
	if strings.TrimSpace(string(data)) != "Europe/Paris" {
		t.Fatalf("/etc/timezone = %q", data)
	}
	if _, err := (setZoneFunc{}).Execute(context.Background(), rt, &setZoneArgs{TimeZone: "Nowhere/Never"}); err == nil {
		t.Fatal("unknown zone must fail")
	}
}

func TestHwclockViaTimedatectlAndAdjtime(t *testing.T) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	runner.script = []process.CommandResult{{Stdout: []byte("Clock=UTC\n"), ExitCode: 0}}
	value, err := (getHwclockFunc{}).Execute(context.Background(), rt, &getHwclockArgs{})
	if err != nil || value != "UTC" {
		t.Fatalf("hwclock = %v, %v", value, err)
	}

	runner.script = nil
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/adjtime", []byte("0.0\n0\nLOCAL\n"), 0o644)
	value, err = (getHwclockFunc{}).Execute(context.Background(), rt, &getHwclockArgs{})
	if err != nil || value != "LOCAL" {
		t.Fatalf("adjtime hwclock = %v, %v", value, err)
	}
}

// zoneFakeInfo synthesizes Lstat answers for special-file fixtures the
// in-memory tree cannot represent (FIFOs, sockets, devices).
type zoneFakeInfo struct {
	name string
	mode fs.FileMode
}

func (i zoneFakeInfo) Name() string       { return i.name }
func (i zoneFakeInfo) Size() int64        { return 0 }
func (i zoneFakeInfo) Mode() fs.FileMode  { return i.mode }
func (i zoneFakeInfo) ModTime() time.Time { return time.Time{} }
func (i zoneFakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i zoneFakeInfo) Sys() any           { return nil }

// errZoneUnexpectedOp marks operations zone_compare must never issue.
var errZoneUnexpectedOp = errors.New("timezone test: unexpected filesystem operation")

// zoneRecordingFS wraps a fixture MemoryFS after every fixture has been
// created: mutations and raw unbounded reads are refused and logged,
// and each permitted read is recorded so tests can prove exactly which
// paths were touched, that resolution is no-follow (Lstat/Readlink
// only), and that nothing mutated.
type zoneRecordingFS struct {
	runtime.FileSystem
	calls     []string
	lstatMode map[string]fs.FileMode
}

func (z *zoneRecordingFS) log(call string) { z.calls = append(z.calls, call) }

func (z *zoneRecordingFS) Lstat(name string) (fs.FileInfo, error) {
	z.log("lstat:" + name)
	if mode, ok := z.lstatMode[name]; ok {
		return zoneFakeInfo{name: path.Base(name), mode: mode}, nil
	}
	return z.FileSystem.Lstat(name)
}

func (z *zoneRecordingFS) Readlink(name string) (string, error) {
	z.log("readlink:" + name)
	return z.FileSystem.Readlink(name)
}

func (z *zoneRecordingFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	z.log("bounded:" + name)
	bounded, ok := z.FileSystem.(runtime.BoundedFileSystem)
	if !ok {
		return nil, errors.New("bounded reads unsupported")
	}
	return bounded.ReadFileBounded(name, limit)
}

func (z *zoneRecordingFS) Stat(name string) (fs.FileInfo, error) {
	z.log("stat:" + name)
	return z.FileSystem.Stat(name)
}

func (z *zoneRecordingFS) ReadFile(name string) ([]byte, error) {
	z.log("rawread:" + name)
	return nil, errZoneUnexpectedOp
}

func (z *zoneRecordingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	z.log("readdir:" + name)
	return nil, errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Glob(pattern string) ([]string, error) {
	z.log("glob:" + pattern)
	return nil, errZoneUnexpectedOp
}

func (z *zoneRecordingFS) WriteFile(name string, _ []byte, _ fs.FileMode) error {
	z.log("write:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) MkdirAll(name string, _ fs.FileMode) error {
	z.log("mkdir:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) MkdirTemp(dir string, _ string) (string, error) {
	z.log("mkdirtemp:" + dir)
	return "", errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Remove(name string) error {
	z.log("remove:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) RemoveAll(name string) error {
	z.log("removeall:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Rename(oldpath string, _ string) error {
	z.log("rename:" + oldpath)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Symlink(target string, _ string) error {
	z.log("symlink:" + target)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Link(target string, _ string) error {
	z.log("link:" + target)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Chmod(name string, _ fs.FileMode) error {
	z.log("chmod:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Chown(name string, _ int, _ int) error {
	z.log("chown:" + name)
	return errZoneUnexpectedOp
}

func (z *zoneRecordingFS) Lchown(name string, _ int, _ int) error {
	z.log("lchown:" + name)
	return errZoneUnexpectedOp
}

// zoneUnboundedFS hides the bounded-read capability entirely: bounded
// consumers must fail closed instead of falling back to raw reads.
type zoneUnboundedFS struct {
	runtime.FileSystem
	calls []string
}

func (z *zoneUnboundedFS) Lstat(name string) (fs.FileInfo, error) {
	z.calls = append(z.calls, "lstat:"+name)
	return z.FileSystem.Lstat(name)
}

func (z *zoneUnboundedFS) Readlink(name string) (string, error) {
	z.calls = append(z.calls, "readlink:"+name)
	return z.FileSystem.Readlink(name)
}

func (z *zoneUnboundedFS) ReadFile(name string) ([]byte, error) {
	z.calls = append(z.calls, "rawread:"+name)
	return nil, errZoneUnexpectedOp
}

func zoneMustMkdir(fsys runtime.FileSystem, dir string) {
	if err := fsys.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
}

func zoneMustWrite(fsys runtime.FileSystem, name string, data []byte) {
	if err := fsys.WriteFile(name, data, 0o644); err != nil {
		panic(err)
	}
}

func zoneMustSymlink(fsys runtime.FileSystem, target, link string) {
	if err := fsys.Symlink(target, link); err != nil {
		panic(err)
	}
}

// seedZone writes a regular zone file (and its parent directories)
// under the fixed zoneinfo root of the in-memory fixture tree.
func seedZone(fsys runtime.FileSystem, zone, content string) {
	full := "/usr/share/zoneinfo/" + zone
	zoneMustMkdir(fsys, path.Dir(full))
	zoneMustWrite(fsys, full, []byte(content))
}

// newZoneCompareRuntime seeds the in-memory fixture tree first and only
// then wraps it in the write-rejecting recorder. Fixture paths live in
// the hermetic tree; the host /etc and /usr/share/zoneinfo are never
// touched.
func newZoneCompareRuntime(t *testing.T, seed func(fsys runtime.FileSystem)) (*zoneRecordingFS, *runtime.Runtime, *scriptRunner) {
	t.Helper()
	mem := runtime.NewMemoryFS()
	seed(mem)
	fsys := &zoneRecordingFS{FileSystem: mem}
	runner := &scriptRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	return fsys, rt, runner
}

func zoneCompareExec(t *testing.T, rt *runtime.Runtime, zone string) (any, error) {
	t.Helper()
	return (zoneCompareFunc{}).Execute(context.Background(), rt, &zoneCompareArgs{TimeZone: zone})
}

var zoneForbiddenCallPrefixes = []string{
	"write", "mkdir", "remove", "rename", "symlink", "link:", "chmod", "chown",
	"rawread:", "readdir:", "glob:", "stat:",
}

func requireZoneCalls(t *testing.T, fsys *zoneRecordingFS, want []string) {
	t.Helper()
	if !reflect.DeepEqual(fsys.calls, want) {
		t.Fatalf("filesystem calls = %v\nwant             %v", fsys.calls, want)
	}
}

func forbidZoneCalls(t *testing.T, fsys *zoneRecordingFS, prefixes ...string) {
	t.Helper()
	for _, call := range fsys.calls {
		for _, prefix := range prefixes {
			if strings.HasPrefix(call, prefix) {
				t.Fatalf("forbidden filesystem call %q (all calls: %v)", call, fsys.calls)
			}
		}
	}
}

// forbidZonePaths rejects any recorded operation whose target path has
// one of the given prefixes. Recorded calls are "op:path" strings
// (lstat:, bounded:, readlink:, ...), so the path is cut at the first
// colon before prefix matching; a call without that shape fails the
// test as unparseable. Use this — not raw full-string prefixes — when
// asserting that a path was never touched by ANY operation.
func forbidZonePaths(t *testing.T, fsys *zoneRecordingFS, pathPrefixes ...string) {
	t.Helper()
	for _, call := range fsys.calls {
		_, path, ok := strings.Cut(call, ":")
		if !ok {
			t.Fatalf("unparseable recorded call %q (all calls: %v)", call, fsys.calls)
		}
		for _, prefix := range pathPrefixes {
			if strings.HasPrefix(path, prefix) {
				t.Fatalf("forbidden filesystem access %q under %q (all calls: %v)", call, prefix, fsys.calls)
			}
		}
	}
}

func requireZoneReadOnly(t *testing.T, fsys *zoneRecordingFS) {
	t.Helper()
	forbidZoneCalls(t, fsys, zoneForbiddenCallPrefixes...)
}

// TZC-01: successful detection compares exact names only.
func TestZoneCompareEqualByDetectionWithoutFallback(t *testing.T) {
	fsys, rt, runner := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/timezone", []byte("Europe/Berlin\n"))
	})
	value, err := zoneCompareExec(t, rt, "Europe/Berlin")
	if err != nil || value != true {
		t.Fatalf("zone_compare equal = %v, %v; want true, nil", value, err)
	}
	requireZoneCalls(t, fsys, []string{"lstat:/etc/timezone", "bounded:/etc/timezone"})
	if len(runner.calls) != 0 {
		t.Fatalf("runner dispatched %v", runner.calls)
	}
	requireZoneReadOnly(t, fsys)
}

// TZC-02: unequal names return false without any byte fallback; the
// comparison is exact and case-sensitive, and no read or metadata
// operation may touch /etc/localtime or the zoneinfo tree afterwards
// (the seeded byte-identical zone is bait for a fallback).
func TestZoneCompareUnequalByDetectionSkipsByteFallback(t *testing.T) {
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/timezone", []byte("Europe/Berlin\n"))
		seedZone(f, "europe/berlin", "SAME-TZDATA")
	})
	value, err := zoneCompareExec(t, rt, "europe/berlin")
	if err != nil || value != false {
		t.Fatalf("zone_compare case-sensitive = %v, %v; want false, nil", value, err)
	}
	forbidZonePaths(t, fsys, "/etc/localtime", "/usr/share/zoneinfo")
	requireZoneReadOnly(t, fsys)
}

// TZC-03: detection failure (regular /etc/localtime, no /etc/timezone)
// falls back to a bounded byte comparison; equal bytes return true.
func TestZoneCompareFallbackBytesEqual(t *testing.T) {
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA-A\n"))
		seedZone(f, "Region/City", "TZDATA-A\n")
	})
	value, err := zoneCompareExec(t, rt, "Region/City")
	if err != nil || value != true {
		t.Fatalf("zone_compare byte-equal = %v, %v; want true, nil", value, err)
	}
	requireZoneCalls(t, fsys, []string{
		"lstat:/etc/timezone",
		"lstat:/etc/localtime",
		"lstat:/etc/localtime",
		"bounded:/etc/localtime",
		"lstat:/usr",
		"lstat:/usr/share",
		"lstat:/usr/share/zoneinfo",
		"lstat:/usr/share/zoneinfo/Region",
		"lstat:/usr/share/zoneinfo/Region/City",
		"bounded:/usr/share/zoneinfo/Region/City",
	})
	requireZoneReadOnly(t, fsys)
}

// TZC-04a: differing bytes return false (deep compare, shallow= False).
func TestZoneCompareFallbackBytesDiffer(t *testing.T) {
	_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA-A\n"))
		seedZone(f, "Region/City", "TZDATA-B\n")
	})
	value, err := zoneCompareExec(t, rt, "Region/City")
	if err != nil || value != false {
		t.Fatalf("zone_compare byte-differ = %v, %v; want false, nil", value, err)
	}
}

// TZC-04b: missing-file precedence and the two fixed error categories.
func TestZoneCompareFallbackErrorPrecedence(t *testing.T) {
	// Both sides missing: the current localtime is read first, so the
	// execution-category error wins even though the requested zone is
	// equally absent, and the requested zone is never accessed at all.
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {})
	_, err := zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("both-missing err = %v, want ErrCannotDetermineZone", err)
	}
	if err.Error() != "cannot determine current zone" {
		t.Fatalf("both-missing err text = %q", err.Error())
	}
	forbidZonePaths(t, fsys, "/usr/share/zoneinfo")

	// Only the requested zone missing (current localtime present):
	// invocation-category error, the SaltInvocationError analog of the
	// pinned test_zone_compare_nonexistent.
	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	_, err = zoneCompareExec(t, rt, "No/Such/Secret")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("requested-only-missing err = %v, want ErrUnknownUnsafeZone", err)
	}
	if err.Error() != "unknown/unsafe zone" || strings.Contains(err.Error(), "Secret") {
		t.Fatalf("requested-only-missing err text = %q", err.Error())
	}
}

// TZC-05: /etc/timezone participates only as a regular bounded file;
// symlinks and special files are skipped before any read, and an
// oversize regular file is skipped after its bounded read fails.
func TestZoneCompareEtcTimezoneOnlyRegularBoundedFile(t *testing.T) {
	scenarios := []struct {
		name          string
		lstat         map[string]fs.FileMode
		forbidBounded bool
		seedFn        func(f runtime.FileSystem)
	}{
		{"symlink", nil, true, func(f runtime.FileSystem) {
			seedZone(f, "Asia/Tokyo", "TZ-J\n")
			zoneMustMkdir(f, "/etc")
			zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/timezone")
			zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
		}},
		{"oversize", nil, false, func(f runtime.FileSystem) {
			seedZone(f, "Asia/Tokyo", "TZ-J\n")
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", make([]byte, (1<<20)+1))
			zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
		}},
		{"special", map[string]fs.FileMode{"/etc/timezone": fs.ModeNamedPipe}, true, func(f runtime.FileSystem) {
			seedZone(f, "Asia/Tokyo", "TZ-J\n")
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", []byte("Asia/Tokyo\n"))
			zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
		}},
	}
	for _, scenario := range scenarios {
		fsys, rt, _ := newZoneCompareRuntime(t, scenario.seedFn)
		fsys.lstatMode = scenario.lstat
		value, err := zoneCompareExec(t, rt, "Asia/Tokyo")
		if err != nil || value != true {
			t.Fatalf("%s: zone_compare = %v, %v; want true, nil", scenario.name, value, err)
		}
		if scenario.forbidBounded {
			for _, call := range fsys.calls {
				if call == "bounded:/etc/timezone" {
					t.Fatalf("%s: /etc/timezone read through the bounded API: %v", scenario.name, fsys.calls)
				}
			}
		}
		requireZoneReadOnly(t, fsys)
	}
}

// TZC-06: a contained absolute /etc/localtime symlink yields the exact
// zone name; unequal names answer false without touching zoneinfo.
func TestZoneCompareDetectsZoneFromAbsoluteLocaltimeSymlink(t *testing.T) {
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Asia/Tokyo", "TZ-J\n")
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
	})
	value, err := zoneCompareExec(t, rt, "Asia/Tokyo")
	if err != nil || value != true {
		t.Fatalf("absolute symlink equal = %v, %v", value, err)
	}
	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Asia/Tokyo", "TZ-J\n")
		seedZone(f, "UTC", "TZ-J\n")
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
	})
	value, err = zoneCompareExec(t, rt, "UTC")
	if err != nil || value != false {
		t.Fatalf("absolute symlink unequal = %v, %v; want false without fallback", value, err)
	}
	forbidZoneCalls(t, fsys, "bounded:")
}

// TZC-07: a relative /etc/localtime target resolves within the root to
// the same contained zone name.
func TestZoneCompareDetectsZoneFromRelativeLocaltimeSymlink(t *testing.T) {
	_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Europe/Berlin", "TZ-B\n")
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "../usr/share/zoneinfo/Europe/Berlin", "/etc/localtime")
	})
	value, err := zoneCompareExec(t, rt, "Europe/Berlin")
	if err != nil || value != true {
		t.Fatalf("relative symlink equal = %v, %v", value, err)
	}
}

// TZC-08: the detected name is the INITIAL symlink target suffix, so an
// alias compares equal to itself and unequal to its canonical file —
// with no byte fallback re-ranking the alias to true.
func TestZoneComparePreservesAliasNameFromInitialTarget(t *testing.T) {
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "America/New_York", "TZ-NY\n")
		zoneMustMkdir(f, "/usr/share/zoneinfo/US")
		zoneMustSymlink(f, "../America/New_York", "/usr/share/zoneinfo/US/Eastern")
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "/usr/share/zoneinfo/US/Eastern", "/etc/localtime")
	})
	value, err := zoneCompareExec(t, rt, "US/Eastern")
	if err != nil || value != true {
		t.Fatalf("alias self-compare = %v, %v; want true", value, err)
	}
	value, err = zoneCompareExec(t, rt, "America/New_York")
	if err != nil || value != false {
		t.Fatalf("alias canonical-name compare = %v, %v; want false without fallback", value, err)
	}
	forbidZoneCalls(t, fsys, "bounded:/usr/share/zoneinfo")
}

// TZC-09: symlink chains that escape the fixed zoneinfo root are
// rejected; their content is never read.
func TestZoneCompareRejectsSymlinkEscape(t *testing.T) {
	// /etc/localtime pointing outside zoneinfo: detection fails, and the
	// fallback content resolution rejects the same escape.
	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Region/City", "TZDATA\n")
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/passwd", []byte("root:x:0:0:SECRET"))
		zoneMustSymlink(f, "/etc/passwd", "/etc/localtime")
	})
	_, err := zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrCannotDetermineZone) || strings.Contains(err.Error(), "passwd") {
		t.Fatalf("escape via /etc/localtime err = %v", err)
	}
	forbidZoneCalls(t, fsys, "bounded:/etc/passwd")

	// Relative-parent escape through a zoneinfo-internal symlink.
	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
		zoneMustMkdir(f, "/usr/share/zoneinfo")
		zoneMustSymlink(f, "../../../etc/passwd", "/usr/share/zoneinfo/Evil")
		zoneMustWrite(f, "/etc/passwd", []byte("root:x:0:0:SECRET"))
	})
	_, err = zoneCompareExec(t, rt, "Evil")
	if !errors.Is(err, ErrUnknownUnsafeZone) || strings.Contains(err.Error(), "passwd") {
		t.Fatalf("escape via zoneinfo symlink err = %v", err)
	}
	forbidZoneCalls(t, fsys, "bounded:/etc/passwd")

	// ../.. past the root still lands on a regular file but outside
	// zoneinfo: rejected by the final containment check.
	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
		zoneMustWrite(f, "/etc/passwd", []byte("root:x:0:0:SECRET"))
		zoneMustMkdir(f, "/usr/share/zoneinfo")
		zoneMustSymlink(f, "../../../../../etc/passwd", "/usr/share/zoneinfo/Deep")
	})
	_, err = zoneCompareExec(t, rt, "Deep")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("deep escape err = %v", err)
	}
	forbidZoneCalls(t, fsys, "bounded:/etc/passwd")
}

// TZC-10: loops exhaust the hop budget and fail closed.
func TestZoneCompareRejectsSymlinkLoops(t *testing.T) {
	_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
		zoneMustMkdir(f, "/usr/share/zoneinfo")
		zoneMustSymlink(f, "B", "/usr/share/zoneinfo/A")
		zoneMustSymlink(f, "A", "/usr/share/zoneinfo/B")
	})
	_, err := zoneCompareExec(t, rt, "A")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("zoneinfo loop err = %v", err)
	}

	_, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/usr/share/zoneinfo")
		zoneMustSymlink(f, "B", "/usr/share/zoneinfo/A")
		zoneMustSymlink(f, "A", "/usr/share/zoneinfo/B")
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "/usr/share/zoneinfo/A", "/etc/localtime")
	})
	_, err = zoneCompareExec(t, rt, "Some/Zone")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("localtime loop err = %v", err)
	}
}

// TZC-11: dangling targets, special files, and directories are rejected
// without reading content.
func TestZoneCompareRejectsDanglingSpecialAndDirectoryTargets(t *testing.T) {
	_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustSymlink(f, "/usr/share/zoneinfo/No/Such", "/etc/localtime")
	})
	_, err := zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("dangling localtime err = %v", err)
	}

	_, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	_, err = zoneCompareExec(t, rt, "No/Such")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("dangling zone err = %v", err)
	}

	_, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Europe/Berlin", "TZ-B\n")
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	_, err = zoneCompareExec(t, rt, "Europe")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("directory-as-zone err = %v", err)
	}

	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Region/City", "TZDATA\n")
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	fsys.lstatMode = map[string]fs.FileMode{"/etc/localtime": fs.ModeNamedPipe}
	_, err = zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("special localtime err = %v", err)
	}

	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Region/City", "TZDATA\n")
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	fsys.lstatMode = map[string]fs.FileMode{"/usr/share/zoneinfo/Region/City": fs.ModeSocket}
	_, err = zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("special zone file err = %v", err)
	}
}

// TZC-12: content reads are bounded at exactly 1 MiB.
func TestZoneCompareBoundsContentReadsAt1MiB(t *testing.T) {
	exact := make([]byte, 1<<20)
	exact[0] = 'T'
	over := make([]byte, (1<<20)+1)
	over[0] = 'T'

	fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", exact)
		seedZone(f, "Region/City", string(exact))
	})
	value, err := zoneCompareExec(t, rt, "Region/City")
	if err != nil || value != true {
		t.Fatalf("1MiB-exact compare = %v, %v; want true", value, err)
	}
	requireZoneReadOnly(t, fsys)

	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", over)
		seedZone(f, "Region/City", string(exact))
	})
	_, err = zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("oversize localtime err = %v", err)
	}
	forbidZoneCalls(t, fsys, "bounded:/usr/share/zoneinfo")

	fsys, rt, _ = newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", exact)
		seedZone(f, "Region/City", string(over))
	})
	_, err = zoneCompareExec(t, rt, "Region/City")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("oversize zone err = %v", err)
	}
}

// TZC-13: boundary-valid names pass validation and compare by name.
func TestZoneCompareAcceptsBoundaryZoneNames(t *testing.T) {
	five := strings.Join([]string{
		strings.Repeat("a", 204), strings.Repeat("b", 204), strings.Repeat("c", 204),
		strings.Repeat("d", 204), strings.Repeat("e", 204),
	}, "/") // 5*204 + 4 = 1024 bytes
	deep := strings.Repeat("z/", 63) + "z" // 64 single-byte components
	for _, name := range []string{five, strings.Repeat("s", 255), deep} {
		if len(name) > 1024 {
			t.Fatalf("fixture name %d bytes exceeds the input ceiling", len(name))
		}
		_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", []byte(name+"\n"))
		})
		value, err := zoneCompareExec(t, rt, name)
		if err != nil || value != true {
			t.Fatalf("boundary name (len %d, segs %d) = %v, %v; want true", len(name), strings.Count(name, "/")+1, value, err)
		}
	}
}

// TZC-13 (reject side): boundary-invalid names are refused before any
// filesystem access.
func TestZoneCompareRejectsBoundaryZoneNamesBeforeAnyFilesystemAccess(t *testing.T) {
	overTotal := strings.Join([]string{
		strings.Repeat("a", 204), strings.Repeat("b", 204), strings.Repeat("c", 204),
		strings.Repeat("d", 204), strings.Repeat("e", 204), "x",
	}, "/") // 1026 bytes
	overSegment := strings.Repeat("s", 256)
	overComponents := strings.TrimSuffix(strings.Repeat("z/", 65), "/") // 65 components
	for _, name := range []string{overTotal, overSegment, overComponents} {
		fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", []byte("UTC\n"))
		})
		_, err := zoneCompareExec(t, rt, name)
		if !errors.Is(err, ErrUnknownUnsafeZone) {
			t.Fatalf("boundary-invalid name (len %d) err = %v", len(name), err)
		}
		if len(fsys.calls) != 0 {
			t.Fatalf("boundary-invalid name touched the filesystem: %v", fsys.calls)
		}
	}
}

// TZC-14: unsafe names are rejected with the fixed invocation-category
// error and zero filesystem operations; input is never trimmed or
// normalized into validity.
func TestZoneCompareRejectsUnsafeInputWithoutFilesystemAccess(t *testing.T) {
	for _, name := range []string{
		"", "/UTC", "UTC/", "a//b", ".", "..", "a/./b", "a/../b", "../etc/passwd",
		`a\b`, "UTC\n", "ut\x00c", "café", "UTC x", " UTC", "UTC ", "Etc/GMT+5;rm",
		strings.Repeat("n", 1025),
	} {
		fsys, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", []byte("UTC\n"))
		})
		_, err := zoneCompareExec(t, rt, name)
		if !errors.Is(err, ErrUnknownUnsafeZone) {
			t.Fatalf("unsafe name %q err = %v", name, err)
		}
		if err.Error() != "unknown/unsafe zone" {
			t.Fatalf("unsafe name %q err text = %q", name, err.Error())
		}
		if len(fsys.calls) != 0 {
			t.Fatalf("unsafe name %q touched the filesystem: %v", name, fsys.calls)
		}
	}
}

// TZC-14 (accept side): canonical zone spellings survive validation.
func TestZoneComparePreservesCanonicalZoneNameSpellings(t *testing.T) {
	for _, name := range []string{
		"UTC", "Etc/GMT+5", "Etc/GMT-14", "US/Eastern", "America/Argentina/Buenos_Aires", "EST5EDT",
	} {
		_, rt, _ := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/timezone", []byte(name+"\n"))
		})
		value, err := zoneCompareExec(t, rt, name)
		if err != nil || value != true {
			t.Fatalf("canonical spelling %q = %v, %v; want true", name, value, err)
		}
	}
}

// TZC-15: every outcome is read-only and no command is dispatched.
func TestZoneCompareNeverMutatesOrDispatches(t *testing.T) {
	fsys, rt, runner := newZoneCompareRuntime(t, func(f runtime.FileSystem) {
		seedZone(f, "Region/City", "TZDATA\n")
		seedZone(f, "Other/Zone", "TZDATA-B\n")
		zoneMustMkdir(f, "/etc")
		zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
	})
	outcomes := []struct {
		zone    string
		want    any
		wantErr error
	}{
		{zone: "Region/City", want: true},
		{zone: "Other/Zone", want: false},
		{zone: "No/Such/Zone", wantErr: ErrUnknownUnsafeZone},
		{zone: "UTC", wantErr: ErrUnknownUnsafeZone},
	}
	for _, outcome := range outcomes {
		value, err := zoneCompareExec(t, rt, outcome.zone)
		switch {
		case outcome.wantErr != nil:
			if !errors.Is(err, outcome.wantErr) {
				t.Fatalf("zone %q err = %v, want %v", outcome.zone, err, outcome.wantErr)
			}
		case err != nil || value != outcome.want:
			t.Fatalf("zone %q = %v, %v; want %v, nil", outcome.zone, value, err, outcome.want)
		}
		requireZoneReadOnly(t, fsys)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner dispatched %v", runner.calls)
	}
}

// TZC-18: fail-closed — a filesystem without the bounded-read
// capability never falls back to a raw read.
func TestZoneCompareFailsClosedWithoutBoundedReadSupport(t *testing.T) {
	mem := runtime.NewMemoryFS()
	zoneMustMkdir(mem, "/etc")
	zoneMustWrite(mem, "/etc/timezone", []byte("UTC\n"))
	zoneMustWrite(mem, "/etc/localtime", []byte("TZDATA\n"))
	fsys := &zoneUnboundedFS{FileSystem: mem}
	runner := &scriptRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	_, err := zoneCompareExec(t, rt, "UTC")
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("unbounded-FS err = %v, want ErrCannotDetermineZone", err)
	}
	for _, call := range fsys.calls {
		if strings.HasPrefix(call, "rawread:") {
			t.Fatalf("raw read attempted: %s", call)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner dispatched %v", runner.calls)
	}
}

// TZC-16: the function is registered Linux-only across every registry
// layer: the raw entry exists on every platform (Register and Get never
// filter), while Names visibility and the ResolveArgs/Call dispatch
// gate follow SupportsPlatform and therefore include the name on linux
// and omit/reject it everywhere else.
func TestZoneCompareIsLinuxOnlyRegistration(t *testing.T) {
	var fn runtime.ExecFunction = zoneCompareFunc{}
	constrained, ok := fn.(runtime.PlatformConstrained)
	if !ok {
		t.Fatal("zoneCompareFunc must be platform-constrained")
	}
	if !reflect.DeepEqual(constrained.Platforms(), []string{"linux"}) {
		t.Fatalf("platforms = %v, want [linux]", constrained.Platforms())
	}
	if !runtime.SupportsPlatform(fn, "linux") {
		t.Fatal("zone_compare must support linux")
	}
	for _, goos := range []string{"darwin", "windows", "freebsd", "solaris", "aix"} {
		if runtime.SupportsPlatform(fn, goos) {
			t.Fatalf("zone_compare must not support %s", goos)
		}
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	// Raw layer: registration is unconditional, so the entry (with its
	// platform constraint intact) is present regardless of GOOS.
	raw, ok := reg.Get("timezone.zone_compare")
	if !ok {
		t.Fatal("raw registry entry timezone.zone_compare missing")
	}
	if _, constrained := raw.(runtime.PlatformConstrained); !constrained {
		t.Fatal("raw registry entry lost the platform constraint")
	}

	// Visible layer: Names filters through SupportsPlatform.
	wantTotal := 6
	if runtime.CurrentGOOS() != "linux" {
		wantTotal = 5
	}
	if got := len(reg.Names()); got != wantTotal {
		t.Fatalf("module registration exposes %d names, want %d", got, wantTotal)
	}
	visible := 0
	for _, name := range reg.Names() {
		if name == "timezone.zone_compare" {
			visible++
		}
	}
	if runtime.CurrentGOOS() == "linux" {
		if visible != 1 {
			t.Fatalf("Names listed timezone.zone_compare %d times on linux, want exactly 1", visible)
		}
	} else if visible != 0 {
		t.Fatalf("Names listed timezone.zone_compare %d times on %s, want 0", visible, runtime.CurrentGOOS())
	}

	// Dispatch layer: ResolveArgs and Call apply the same filter,
	// surfacing the function as unsupported off linux. On linux both
	// traverse the gate into the contract itself.
	var unsupported *runtime.UnsupportedError
	_, err := reg.ResolveArgs(nil, "timezone.zone_compare")
	if runtime.CurrentGOOS() == "linux" {
		if err != nil {
			t.Fatalf("ResolveArgs on linux = %v, want nil", err)
		}
	} else if !errors.As(err, &unsupported) || unsupported.Kind != "function" {
		t.Fatalf("ResolveArgs off linux = %v, want unsupported function", err)
	}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &scriptRunner{}}
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/timezone", []byte("UTC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	value, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &zoneCompareArgs{TimeZone: "UTC"})
	if runtime.CurrentGOOS() == "linux" {
		if err != nil || value != true {
			t.Fatalf("Call on linux = %v, %v; want true, nil", value, err)
		}
	} else if !errors.As(err, &unsupported) || unsupported.Kind != "function" {
		t.Fatalf("Call off linux = %v, want unsupported function", err)
	}
}

// TZC-17 hop/component boundaries: 8 symlink hops and 64 cumulative
// components resolve; one more of either fails closed.
func TestZoneCompareSymlinkBudgetBoundaries(t *testing.T) {
	// buildChain(hops) seeds L0→L1→…→L{hops-1}→Chain/File: resolving
	// "L0" crosses exactly hops symlinks.
	buildChain := func(hops int) func(runtime.FileSystem) {
		return func(f runtime.FileSystem) {
			seedZone(f, "Chain/File", "TZDATA\n")
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
			for i := 0; i < hops; i++ {
				target := fmt.Sprintf("L%d", i+1)
				if i == hops-1 {
					target = "Chain/File"
				}
				zoneMustSymlink(f, target, fmt.Sprintf("/usr/share/zoneinfo/L%d", i))
			}
		}
	}
	fsys, rt, _ := newZoneCompareRuntime(t, buildChain(8))
	value, err := zoneCompareExec(t, rt, "L0")
	if err != nil || value != true {
		t.Fatalf("8-hop chain = %v, %v; want true", value, err)
	}
	requireZoneReadOnly(t, fsys)

	_, rt, _ = newZoneCompareRuntime(t, buildChain(9))
	_, err = zoneCompareExec(t, rt, "L0")
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("9-hop chain err = %v", err)
	}

	deepSeed := func(components int) (string, func(runtime.FileSystem)) {
		parts := make([]string, components)
		for i := range parts {
			parts[i] = "a"
		}
		name := strings.Join(parts, "/")
		return name, func(f runtime.FileSystem) {
			seedZone(f, name, "TZDATA\n")
			zoneMustMkdir(f, "/etc")
			zoneMustWrite(f, "/etc/localtime", []byte("TZDATA\n"))
		}
	}
	name, seed := deepSeed(61) // 3 prefix + 61 = 64 cumulative components
	_, rt, _ = newZoneCompareRuntime(t, seed)
	value, err = zoneCompareExec(t, rt, name)
	if err != nil || value != true {
		t.Fatalf("64-component zone = %v, %v; want true", value, err)
	}

	name, seed = deepSeed(62) // 3 prefix + 62 = 65 cumulative components
	_, rt, _ = newZoneCompareRuntime(t, seed)
	_, err = zoneCompareExec(t, rt, name)
	if !errors.Is(err, ErrUnknownUnsafeZone) {
		t.Fatalf("65-component zone err = %v", err)
	}
}
