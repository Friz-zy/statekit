package timezone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
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

// TZC-16: zone_compare registration is selected per GOOS at Register
// time through registerZoneCompareForGOOS(runtime.CurrentGOOS()): the
// Linux generic filesystem contract on linux, the mac systemsetup
// contract on darwin, and no entry anywhere else. On supported GOOS
// the raw entry exists after Register (Get never filters) with its
// platform constraint intact, while Names visibility and the
// ResolveArgs/Call dispatch gate follow SupportsPlatform on every
// platform.
func TestZoneCompareRegistrationSelectsPerGOOS(t *testing.T) {
	var linuxFn runtime.ExecFunction = zoneCompareFunc{}
	constrained, ok := linuxFn.(runtime.PlatformConstrained)
	if !ok {
		t.Fatal("zoneCompareFunc must be platform-constrained")
	}
	if !reflect.DeepEqual(constrained.Platforms(), []string{"linux"}) {
		t.Fatalf("linux platforms = %v, want [linux]", constrained.Platforms())
	}
	if !runtime.SupportsPlatform(linuxFn, "linux") {
		t.Fatal("linux zone_compare must support linux")
	}
	for _, goos := range []string{"darwin", "windows", "freebsd", "solaris", "aix"} {
		if runtime.SupportsPlatform(linuxFn, goos) {
			t.Fatalf("linux zone_compare must not support %s", goos)
		}
	}

	var macFn runtime.ExecFunction = macZoneCompareFunc{}
	macConstrained, ok := macFn.(runtime.PlatformConstrained)
	if !ok {
		t.Fatal("macZoneCompareFunc must be platform-constrained")
	}
	if !reflect.DeepEqual(macConstrained.Platforms(), []string{"darwin"}) {
		t.Fatalf("mac platforms = %v, want [darwin]", macConstrained.Platforms())
	}
	if !runtime.SupportsPlatform(macFn, "darwin") {
		t.Fatal("mac zone_compare must support darwin")
	}
	for _, goos := range []string{"linux", "windows", "freebsd", "solaris", "aix"} {
		if runtime.SupportsPlatform(macFn, goos) {
			t.Fatalf("mac zone_compare must not support %s", goos)
		}
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	goos := runtime.CurrentGOOS()
	supported := goos == "linux" || goos == "darwin"

	// Raw layer: registration happens only on the supported GOOS, so
	// the entry (with its platform constraint intact) exists there and
	// nowhere else.
	raw, ok := reg.Get("timezone.zone_compare")
	if supported {
		if !ok {
			t.Fatalf("raw registry entry timezone.zone_compare missing on %s", goos)
		}
		if _, constrained := raw.(runtime.PlatformConstrained); !constrained {
			t.Fatal("raw registry entry lost the platform constraint")
		}
	} else if ok {
		t.Fatalf("timezone.zone_compare registered on unsupported GOOS %s", goos)
	}

	// Visible layer: Names filters through SupportsPlatform.
	wantTotal := 5
	if supported {
		wantTotal = 6
	}
	if got := len(reg.Names()); got != wantTotal {
		t.Fatalf("module registration exposes %d names on %s, want %d", got, goos, wantTotal)
	}
	visible := 0
	for _, name := range reg.Names() {
		if name == "timezone.zone_compare" {
			visible++
		}
	}
	if supported {
		if visible != 1 {
			t.Fatalf("Names listed timezone.zone_compare %d times on %s, want exactly 1", visible, goos)
		}
	} else if visible != 0 {
		t.Fatalf("Names listed timezone.zone_compare %d times on %s, want 0", visible, goos)
	}

	// Dispatch layer: ResolveArgs and Call apply the same filter,
	// surfacing the function as unsupported off its variant platform.
	// On supported GOOS both traverse the gate into the variant
	// contract itself.
	var unsupported *runtime.UnsupportedError
	_, err := reg.ResolveArgs(nil, "timezone.zone_compare")
	if supported {
		if err != nil {
			t.Fatalf("ResolveArgs on %s = %v, want nil", goos, err)
		}
	} else if !errors.As(err, &unsupported) || unsupported.Kind != "function" {
		t.Fatalf("ResolveArgs on %s = %v, want unsupported function", goos, err)
	}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &scriptRunner{}}
	switch goos {
	case "linux":
		if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile("/etc/timezone", []byte("UTC\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		value, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &zoneCompareArgs{TimeZone: "UTC"})
		if err != nil || value != true {
			t.Fatalf("Call on linux = %v, %v, want true, nil", value, err)
		}
	case "darwin":
		rt.Runner = &scriptRunner{script: []process.CommandResult{{Stdout: []byte("Time Zone: America/Denver\n"), ExitCode: 0}}}
		zone := "America/Denver"
		value, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &macZoneCompareArgs{TimeZone: &zone})
		if err != nil || value != true {
			t.Fatalf("Call on darwin = %v, %v, want true, nil", value, err)
		}
	default:
		if _, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &zoneCompareArgs{TimeZone: "UTC"}); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
			t.Fatalf("Call on %s = %v, want unsupported function", goos, err)
		}
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

// ---------------------------------------------------------------------------
// macOS zone_compare (PTD-EXEC-1638 Mac partial): MZC-01..18 pin the
// pinned mac_timezone.py contract hermetically. Every test uses the
// fake macZoneRunner only — never process.NewRunner, never
// /usr/sbin/systemsetup, never a host filesystem — and the suite makes
// no native Darwin claim.

// macZoneRunner is the fake Runner for the mac zone_compare contract:
// it records the exact process.Command (and context error) of every
// dispatch and replies with one scripted CommandResult.
type macZoneRunner struct {
	cmds   []process.Command
	ctxErr []error
	reply  process.CommandResult
}

func (m *macZoneRunner) Run(ctx context.Context, cmd process.Command) process.CommandResult {
	m.cmds = append(m.cmds, cmd)
	if ctx != nil {
		m.ctxErr = append(m.ctxErr, ctx.Err())
	} else {
		m.ctxErr = append(m.ctxErr, errNoContext)
	}
	return m.reply
}

var errNoContext = errors.New("timezone test: nil context")

// wantMacZoneCommand is the fixed, complete systemsetup invocation:
// absolute admin-controlled path, exactly one argv flag, no shell,
// locale-only child environment, 30s wall clock, equal 64 KiB capture
// ceilings per stream, and nothing else.
func wantMacZoneCommand() process.Command {
	return process.Command{
		Name:           "/usr/sbin/systemsetup",
		Args:           []string{"-gettimezone"},
		Env:            []string{"LC_ALL=C"},
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 64 << 10,
		MaxStderrBytes: 64 << 10,
	}
}

func newMacZoneRuntime(reply process.CommandResult) (*runtime.Runtime, *macZoneRunner) {
	runner := &macZoneRunner{reply: reply}
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		FS:     runtime.NewMemoryFS(),
		Runner: runner,
	}, runner
}

func macZoneCompareExec(t *testing.T, rt *runtime.Runtime, zone string) (any, error) {
	t.Helper()
	return (macZoneCompareFunc{}).Execute(context.Background(), rt, &macZoneCompareArgs{TimeZone: &zone})
}

// requireMacZoneError pins the single fixed execution-category error:
// the errors.Is sentinel, the exact value-free text, and no markers of
// any underlying cause, output, stream, or exit status.
func requireMacZoneError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("err = %v, want ErrCannotDetermineZone", err)
	}
	if err == nil || err.Error() != "cannot determine current zone" {
		t.Fatalf("err text = %v, want cannot determine current zone", err)
	}
	for _, marker := range []string{
		"systemsetup", "Denver", "Wake", "failing", "warning", "13", "exit",
		"stdout", "stderr", "timed out", "canceled", "not supported", "no such file",
	} {
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatalf("err text %q leaks marker %q", err.Error(), marker)
		}
	}
}

// MZC-01: Execute dispatches exactly one shell-free systemsetup
// -gettimezone with the fixed argv, environment, timeout, and capture
// ceilings — deep-equal over the whole process.Command, with the live
// context forwarded to the Runner.
func TestMacZoneCompareDispatchesFixedCommand(t *testing.T) {
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n")})
	if _, err := macZoneCompareExec(t, rt, "America/Denver"); err != nil {
		t.Fatal(err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if !reflect.DeepEqual(runner.cmds[0], wantMacZoneCommand()) {
		t.Fatalf("command = %#v, want %#v", runner.cmds[0], wantMacZoneCommand())
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}
}

// MZC-02: the mac contract never touches the filesystem on success or
// failure — every path stays inside the hermetic MemoryFS with zero
// recorded operations.
func TestMacZoneCompareNeverTouchesFilesystem(t *testing.T) {
	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	if _, err := macZoneCompareExec(t, rt, "America/Denver"); err != nil {
		t.Fatal(err)
	}
	runner.reply = process.CommandResult{ExitCode: 1}
	if _, err := macZoneCompareExec(t, rt, "America/Denver"); !errors.Is(err, ErrCannotDetermineZone) {
		t.Fatalf("nonzero err = %v", err)
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("filesystem touched: %v", fsys.calls)
	}
}

// MZC-03: stdout is trailing-rstripped with Python str.rstrip
// semantics — unicode.IsSpace plus U+001C..U+001F (Python isspace
// includes the file/group/record/unit separators; Go's IsSpace alone
// does not) — with no leading trim, before any parsing.
func TestMacZoneComparePythonTrailingRStrip(t *testing.T) {
	for _, tail := range []string{
		"\n", "\r\n", "\t", " \t\r\n", "\v\f",
		"\u00a0", "\u0085", "\u2028", "\u3000",
		"\u001c", "\u001d", "\u001e", "\u001f",
		" \u001c\u001d\u001e\u001f\u00a0\u2028\t\r\n",
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver" + tail)})
		value, err := macZoneCompareExec(t, rt, "America/Denver")
		if err != nil || value != true {
			t.Fatalf("trailing %q: zone_compare = %v, %v; want true, nil", tail, value, err)
		}
	}

	// Leading whitespace is never stripped: the raw value keeps it and
	// the exact comparison answers false.
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(" America/Denver\n")})
	value, err := macZoneCompareExec(t, rt, "America/Denver")
	if err != nil || value != false {
		t.Fatalf("leading-space zone_compare = %v, %v; want false, nil", value, err)
	}

	// Interior whitespace survives untouched.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Bad/ Zone\n")})
	value, err = macZoneCompareExec(t, rt, "Bad/ Zone")
	if err != nil || value != true {
		t.Fatalf("interior-space zone_compare = %v, %v; want true, nil", value, err)
	}
}

// MZC-04: the parse_return port: the first ": " delimiter wins and
// yields the segment after its first occurrence (later segments are
// discarded), then ":\n", else the whole raw string with no further
// trimming.
func TestMacZoneCompareParseReturnDelimiterPriority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		zone   string
		want   bool
	}{
		{"colon-space", "Time Zone: America/Denver\n", "America/Denver", true},
		{"colon-space repeats discard later segments", "Time Zone: America/Denver: Extra: More\n", "America/Denver", true},
		{"colon-newline fallback", "Time Zone:\nAmerica/Denver\n", "America/Denver", true},
		{"colon-space wins over colon-newline", "Head:\nTime Zone: America/Denver\n", "America/Denver", true},
		{"colon-newline would answer differently", "Head:\nTime Zone: America/Denver\n", "Time Zone: America/Denver", false},
		{"raw passthrough", "America/Denver", "America/Denver", true},
		{"raw value never trimmed", "America/Denver", "America/Denver ", false},
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := macZoneCompareExec(t, rt, tc.zone)
		if err != nil || value != tc.want {
			t.Fatalf("%s: zone_compare(%q) = %v, %v; want %v, nil", tc.name, tc.zone, value, err, tc.want)
		}
	}
}

// MZC-05: mapped Salt mac result shapes — America/Denver compares
// true, another zone false, and the comparison stays exact and
// case-sensitive in both bare and "Time Zone: " output forms.
func TestMacZoneCompareSaltResultShapes(t *testing.T) {
	for _, tc := range []struct {
		stdout string
		zone   string
		want   bool
	}{
		{"Time Zone: America/Denver\n", "America/Denver", true},
		{"Time Zone: America/Denver\n", "Pacific/Wake", false},
		{"Time Zone: America/Denver\n", "america/denver", false},
		{"America/Denver\n", "America/Denver", true},
		{"America/Denver\n", "Pacific/Wake", false},
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := macZoneCompareExec(t, rt, tc.zone)
		if err != nil || value != tc.want {
			t.Fatalf("stdout %q zone %q = %v, %v; want %v, nil", tc.stdout, tc.zone, value, err, tc.want)
		}
	}
}

// MZC-06: exit-0 stdout containing case-insensitive "not supported"
// fails with the fixed execution error before parsing (Salt's
// execute_return_result contract).
func TestMacZoneCompareNotSupportedTextFails(t *testing.T) {
	for _, stdout := range []string{
		"Time Zone: not supported\n",
		"NOT SUPPORTED\n",
		"Not Supported\n",
		"Error: this operation is not supported on this system\n",
	} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})
		_, err := macZoneCompareExec(t, rt, "America/Denver")
		requireMacZoneError(t, err)
		if len(runner.cmds) != 1 {
			t.Fatalf("stdout %q dispatched %d commands, want 1", stdout, len(runner.cmds))
		}
	}
}

// MZC-07: "not supported" in stderr alone does not fail — only the
// rstripped stdout participates in the not-supported gate.
func TestMacZoneCompareStderrNotSupportedAloneDoesNotFail(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Time Zone: America/Denver\n"),
		Stderr:   []byte("warning: something not supported \n"),
	})
	value, err := macZoneCompareExec(t, rt, "America/Denver")
	if err != nil || value != true {
		t.Fatalf("stderr-only not supported = %v, %v; want true, nil", value, err)
	}
}

// MZC-08: a nonzero exit maps to the single fixed error with no
// exit-code, stdout, or stderr markers.
func TestMacZoneCompareNonzeroExitMapsToFixedError(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{
		ExitCode: 13,
		Stdout:   []byte("Time Zone: America/Denver\n"),
		Stderr:   []byte("systemsetup: failing\n"),
	})
	_, err := macZoneCompareExec(t, rt, "America/Denver")
	requireMacZoneError(t, err)
}

// MZC-09: a Runner error (start failure: Started false, Err set) maps
// to the same fixed error with no wrapped cause.
func TestMacZoneCompareRunnerErrorMapsToFixedError(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{
		ExitCode: -1,
		Err:      fmt.Errorf(`exec: "/usr/sbin/systemsetup": stat /usr/sbin/systemsetup: no such file or directory`),
	})
	_, err := macZoneCompareExec(t, rt, "America/Denver")
	requireMacZoneError(t, err)
	if errors.Is(err, fs.ErrNotExist) || errors.Unwrap(err) != nil {
		t.Fatalf("runner error leaked its cause: %v", err)
	}
}

// MZC-10: context cancellation and command timeout both surface as
// Runner errors and map to the same fixed error with no markers, and
// Execute forwards the live context to the Runner.
func TestMacZoneCompareContextAndTimeoutMapToFixedError(t *testing.T) {
	for _, runnerErr := range []error{
		fmt.Errorf("/usr/sbin/systemsetup -gettimezone canceled: %w", context.Canceled),
		fmt.Errorf("/usr/sbin/systemsetup -gettimezone timed out after 30s: %w", context.DeadlineExceeded),
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: -1, Err: runnerErr})
		_, err := macZoneCompareExec(t, rt, "America/Denver")
		requireMacZoneError(t, err)
	}

	// The caller's context reaches the Runner unchanged.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	zone := "America/Denver"
	if _, err := (macZoneCompareFunc{}).Execute(ctx, rt, &macZoneCompareArgs{TimeZone: &zone}); err != nil {
		t.Fatal(err)
	}
	if len(runner.ctxErr) != 1 || !errors.Is(runner.ctxErr[0], context.Canceled) {
		t.Fatalf("runner context errors = %v, want one context.Canceled", runner.ctxErr)
	}
}

// MZC-11: per-stream truncation flags map to the fixed error even
// with a zero exit.
func TestMacZoneCompareTruncationFlagsMapToFixedError(t *testing.T) {
	for _, reply := range []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("Time Zone: America/Denver\n"), StdoutTruncated: true},
		{ExitCode: 0, Stdout: []byte("Time Zone: America/Denver\n"), Stderr: []byte("x"), StderrTruncated: true},
	} {
		rt, _ := newMacZoneRuntime(reply)
		_, err := macZoneCompareExec(t, rt, "America/Denver")
		requireMacZoneError(t, err)
	}
}

// MZC-12: streams longer than the 64 KiB cap fail closed even without
// truncation flags (a fake Runner can be inconsistent); exactly-at-cap
// streams still parse.
func TestMacZoneCompareStreamCapsFailClosed(t *testing.T) {
	atCap := bytes.Repeat([]byte("x"), 64<<10)
	over := bytes.Repeat([]byte("x"), (64<<10)+1)

	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: over})
	_, err := macZoneCompareExec(t, rt, "no-match")
	requireMacZoneError(t, err)

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n"), Stderr: over})
	_, err = macZoneCompareExec(t, rt, "America/Denver")
	requireMacZoneError(t, err)

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: atCap, Stderr: atCap})
	value, err := macZoneCompareExec(t, rt, "no-match")
	if err != nil || value != false {
		t.Fatalf("at-cap streams = %v, %v; want false, nil", value, err)
	}

	padded := append([]byte("America/Denver"), bytes.Repeat([]byte(" "), (64<<10)-len("America/Denver"))...)
	if len(padded) != 64<<10 {
		t.Fatalf("padded fixture is %d bytes, want exactly the cap", len(padded))
	}
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: padded})
	value, err = macZoneCompareExec(t, rt, "America/Denver")
	if err != nil || value != true {
		t.Fatalf("at-cap padded stdout = %v, %v; want true, nil", value, err)
	}
}

// MZC-13: the required-args gate tested directly on both Args
// prototypes — Linux demands the value string `timezone`, Mac demands
// the pointer `time_zone` — so an omitted (nil) mac argument fails
// the gate before any dispatch while the gate itself never dispatches.
func TestMacZoneCompareRequiredArgsGate(t *testing.T) {
	var linuxProto any = (zoneCompareFunc{}).Args()
	if _, ok := linuxProto.(zoneCompareArgs); !ok {
		t.Fatalf("linux Args prototype = %T, want zoneCompareArgs", linuxProto)
	}
	linuxType := reflect.TypeOf(linuxProto)
	linuxField := linuxType.Field(0)
	if linuxField.Name != "TimeZone" || linuxField.Type.Kind() != reflect.String || linuxField.Tag.Get("statekit") != "required,name=timezone" {
		t.Fatalf("linux schema = %s %s tag %q", linuxField.Name, linuxField.Type, linuxField.Tag.Get("statekit"))
	}
	if err := config.ValidateRequired(&zoneCompareArgs{}); err == nil || err.Error() != `missing required argument "timezone"` {
		t.Fatalf("linux missing timezone err = %v", err)
	}

	var macProto any = (macZoneCompareFunc{}).Args()
	if _, ok := macProto.(macZoneCompareArgs); !ok {
		t.Fatalf("mac Args prototype = %T, want macZoneCompareArgs", macProto)
	}
	missing := config.ValidateRequired(&macZoneCompareArgs{})
	if missing == nil || missing.Error() != `missing required argument "time_zone"` {
		t.Fatalf("mac missing time_zone err = %v", missing)
	}
	empty := ""
	if err := config.ValidateRequired(&macZoneCompareArgs{TimeZone: &empty}); err != nil {
		t.Fatalf("mac explicit empty time_zone err = %v, want nil", err)
	}

	// The gate precedes dispatch: a rejected argument never reaches the
	// Runner.
	runner := &macZoneRunner{}
	if missing == nil {
		t.Fatal("nil time_zone passed the required gate")
	}
	if len(runner.cmds) != 0 {
		t.Fatalf("required gate dispatched %d commands, want 0", len(runner.cmds))
	}
}

// MZC-14: an explicit empty time_zone is valid and compares exactly —
// empty successful output yields true, nonempty output false.
func TestMacZoneCompareExplicitEmptyTimeZone(t *testing.T) {
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0})
	value, err := macZoneCompareExec(t, rt, "")
	if err != nil || value != true {
		t.Fatalf("empty output, empty zone = %v, %v; want true, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("explicit-empty zone dispatched %d commands, want 1", len(runner.cmds))
	}

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n")})
	value, err = macZoneCompareExec(t, rt, "")
	if err != nil || value != false {
		t.Fatalf("nonempty output, empty zone = %v, %v; want false, nil", value, err)
	}

	// Whitespace-only successful output rstrips to empty and compares
	// equal to the explicit empty zone.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(" \r\n\u001f")})
	value, err = macZoneCompareExec(t, rt, "")
	if err != nil || value != true {
		t.Fatalf("whitespace-only output, empty zone = %v, %v; want true, nil", value, err)
	}
}

// MZC-15: registerZoneCompareForGOOS selects exactly one variant per
// supported GOOS — the Linux filesystem contract on linux, the mac
// systemsetup contract on darwin, nothing anywhere else — with the
// matching platform constraints and args schema.
func TestMacZoneCompareRegistrationHelperSelectsPerGOOS(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerZoneCompareForGOOS(reg, "linux"); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("timezone.zone_compare")
	if !ok {
		t.Fatal("linux helper registered nothing")
	}
	if _, isLinux := fn.(zoneCompareFunc); !isLinux {
		t.Fatalf("linux helper registered %T, want zoneCompareFunc", fn)
	}
	linuxConstrained, isConstrained := fn.(runtime.PlatformConstrained)
	if !isConstrained || !reflect.DeepEqual(linuxConstrained.Platforms(), []string{"linux"}) {
		t.Fatalf("linux helper platforms = %v", linuxConstrained.Platforms())
	}
	if !runtime.SupportsPlatform(fn, "linux") || runtime.SupportsPlatform(fn, "darwin") {
		t.Fatal("linux helper must support linux only")
	}
	linuxProto := fn.Args()
	if _, ok := linuxProto.(zoneCompareArgs); !ok {
		t.Fatalf("linux helper prototype = %T", linuxProto)
	}

	reg = runtime.NewExecRegistry()
	if err := registerZoneCompareForGOOS(reg, "darwin"); err != nil {
		t.Fatal(err)
	}
	fn, ok = reg.Get("timezone.zone_compare")
	if !ok {
		t.Fatal("darwin helper registered nothing")
	}
	if _, isMac := fn.(macZoneCompareFunc); !isMac {
		t.Fatalf("darwin helper registered %T, want macZoneCompareFunc", fn)
	}
	macConstrained, isConstrained := fn.(runtime.PlatformConstrained)
	if !isConstrained || !reflect.DeepEqual(macConstrained.Platforms(), []string{"darwin"}) {
		t.Fatalf("darwin helper platforms = %v", macConstrained.Platforms())
	}
	if !runtime.SupportsPlatform(fn, "darwin") || runtime.SupportsPlatform(fn, "linux") {
		t.Fatal("darwin helper must support darwin only")
	}
	macType := reflect.TypeOf(fn.Args())
	if macType.Kind() != reflect.Struct || macType.NumField() != 1 {
		t.Fatalf("darwin schema = %s with %d fields", macType, macType.NumField())
	}
	macField := macType.Field(0)
	if macField.Name != "TimeZone" || macField.Type.Kind() != reflect.Pointer || macField.Type.Elem().Kind() != reflect.String {
		t.Fatalf("darwin schema field = %s %s", macField.Name, macField.Type)
	}
	if macField.Tag.Get("statekit") != "required,name=time_zone" {
		t.Fatalf("darwin schema tag = %q", macField.Tag.Get("statekit"))
	}

	for _, goos := range []string{"windows", "freebsd", "openbsd", "netbsd", "solaris", "illumos", "aix", "plan9"} {
		unsupported := runtime.NewExecRegistry()
		if err := registerZoneCompareForGOOS(unsupported, goos); err != nil {
			t.Fatal(err)
		}
		if _, ok := unsupported.Get("timezone.zone_compare"); ok {
			t.Fatalf("helper registered zone_compare for unsupported GOOS %s", goos)
		}
		if unsupported.Len() != 0 {
			t.Fatalf("helper registered %d functions for unsupported GOOS %s", unsupported.Len(), goos)
		}
	}
}

// MZC-16: off its variant platform the registration is invisible and
// dispatch fails as an unsupported function (ResolveArgs and Call),
// whichever variant is off-host.
func TestMacZoneCompareUnsupportedCallRejected(t *testing.T) {
	host := runtime.CurrentGOOS()
	for _, goos := range []string{"linux", "darwin"} {
		if goos == host {
			continue // on-platform dispatch is covered by TZC-16 and MZC-17
		}
		reg := runtime.NewExecRegistry()
		if err := registerZoneCompareForGOOS(reg, goos); err != nil {
			t.Fatal(err)
		}
		if _, ok := reg.Get("timezone.zone_compare"); !ok {
			t.Fatalf("%s helper registered nothing", goos)
		}
		for _, name := range reg.Names() {
			if name == "timezone.zone_compare" {
				t.Fatalf("Names exposed timezone.zone_compare for %s registration on host %s", goos, host)
			}
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &macZoneRunner{}}
		var unsupported *runtime.UnsupportedError
		if _, err := reg.ResolveArgs(rt, "timezone.zone_compare"); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
			t.Fatalf("ResolveArgs for %s registration on %s = %v, want unsupported function", goos, host, err)
		}
		zone := "America/Denver"
		if _, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &macZoneCompareArgs{TimeZone: &zone}); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
			t.Fatalf("Call for %s registration on %s = %v, want unsupported function", goos, host, err)
		}
	}
}

// MZC-17: no duplicate zone_compare entry can exist on any registry:
// the registry keys by name so a second variant fails, the helper
// registers at most one variant, and production Register exposes the
// name exactly once on supported GOOS and not at all elsewhere.
func TestMacZoneCompareNoDuplicateRegistration(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerZoneCompareForGOOS(reg, "linux"); err != nil {
		t.Fatal(err)
	}
	if err := registerZoneCompareForGOOS(reg, "darwin"); err == nil {
		t.Fatal("registering the darwin variant over the linux entry must fail as a duplicate")
	}
	if err := reg.Register(macZoneCompareFunc{}); err == nil {
		t.Fatal("registering the mac variant directly over the linux entry must fail as a duplicate")
	}

	prod := runtime.NewExecRegistry()
	if err := Register(prod); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range prod.Names() {
		if name == "timezone.zone_compare" {
			count++
		}
	}
	goos := runtime.CurrentGOOS()
	if goos == "linux" || goos == "darwin" {
		if count != 1 {
			t.Fatalf("zone_compare visible %d times on %s, want exactly 1", count, goos)
		}
		if prod.Len() != 6 {
			t.Fatalf("production registration holds %d functions on %s, want 6", prod.Len(), goos)
		}
	} else {
		if count != 0 {
			t.Fatalf("zone_compare visible %d times on %s, want 0", count, goos)
		}
		if prod.Len() != 5 {
			t.Fatalf("production registration holds %d functions on %s, want 5", prod.Len(), goos)
		}
	}
}

// MZC-18: the Execute boundary fails safe for direct callers that
// bypass the registry's required-args gate (architecture-gate fix):
// wrong argument types, typed-nil pointers, a nonnil struct with a nil
// required TimeZone, a nil Runtime, and a nil Runner all return fixed
// value-free errors before any Runner dispatch or filesystem access —
// never a panic and never raw args or an underlying cause formatted
// into the error — while an explicit pointer-to-empty time_zone stays
// valid, dispatches exactly once, and compares exactly.
func TestMacZoneCompareExecuteFailsSafeOnMalformedInvocation(t *testing.T) {
	check := func(label string, rt *runtime.Runtime, args any, verify func(t *testing.T, err error)) {
		t.Helper()
		var (
			value    any
			err      error
			panicked bool
		)
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			value, err = (macZoneCompareFunc{}).Execute(context.Background(), rt, args)
		}()
		if panicked {
			t.Fatalf("%s: Execute panicked, want a fixed safe error", label)
		}
		if err == nil {
			t.Fatalf("%s: Execute err = nil, want a fixed safe error", label)
		}
		if value != nil {
			t.Fatalf("%s: Execute value = %#v, want nil on error", label, value)
		}
		verify(t, err)
	}

	fixedValueFree := func(marker ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			if err.Error() == "" {
				t.Fatal("fixed error text is empty")
			}
			for _, secret := range marker {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error text %q leaks raw argument material %q", err.Error(), secret)
				}
			}
		}
	}

	// Malformed args scenarios share one recording runtime whose Runner
	// and filesystem must stay untouched.
	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("America/Denver\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}

	var malformedErrs []error
	for _, tc := range []struct {
		label string
		args  any
	}{
		{"wrong-type string", "Secret/Zone-Marker"},
		{"wrong-type linux args", &zoneCompareArgs{TimeZone: "Secret/Linux-Args"}},
		{"typed-nil mac args", (*macZoneCompareArgs)(nil)},
	} {
		args := tc.args
		check(tc.label, rt, args, func(t *testing.T, err error) {
			fixedValueFree("Secret", "Marker", "Linux", "Denver")(t, err)
			malformedErrs = append(malformedErrs, err)
		})
	}
	for i := 1; i < len(malformedErrs); i++ {
		if malformedErrs[i].Error() != malformedErrs[0].Error() {
			t.Fatalf("malformed-args error %q differs from %q, want one fixed error", malformedErrs[i].Error(), malformedErrs[0].Error())
		}
	}

	// A nonnil struct with a nil required TimeZone reuses the
	// decoder's fixed missing-required error — the same failure the
	// registry gate produces.
	check("nil TimeZone", rt, &macZoneCompareArgs{}, func(t *testing.T, err error) {
		fixedValueFree("Secret", "Denver")(t, err)
		var missing *config.MissingRequiredError
		if !errors.As(err, &missing) || missing.Name != "time_zone" {
			t.Fatalf("nil TimeZone err = %v, want config.MissingRequiredError time_zone", err)
		}
	})

	// No malformed invocation may dispatch or touch the filesystem.
	if len(runner.cmds) != 0 {
		t.Fatalf("malformed invocations dispatched %d commands, want 0", len(runner.cmds))
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("malformed invocations touched the filesystem: %v", fsys.calls)
	}

	// Unavailable runtime: nil Runtime and nil Runner map to the fixed
	// execution-category error before any dispatch.
	zone := "America/Denver"
	check("nil Runtime", nil, &macZoneCompareArgs{TimeZone: &zone}, func(t *testing.T, err error) {
		fixedValueFree("Denver")(t, err)
		if !errors.Is(err, ErrCannotDetermineZone) || err.Error() != "cannot determine current zone" {
			t.Fatalf("nil Runtime err = %v, want fixed ErrCannotDetermineZone", err)
		}
	})
	nilRunnerFS := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	nilRunnerRT := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: nilRunnerFS, Runner: nil}
	check("nil Runner", nilRunnerRT, &macZoneCompareArgs{TimeZone: &zone}, func(t *testing.T, err error) {
		fixedValueFree("Denver")(t, err)
		if !errors.Is(err, ErrCannotDetermineZone) || err.Error() != "cannot determine current zone" {
			t.Fatalf("nil Runner err = %v, want fixed ErrCannotDetermineZone", err)
		}
	})
	if len(nilRunnerFS.calls) != 0 {
		t.Fatalf("nil Runner touched the filesystem: %v", nilRunnerFS.calls)
	}

	// Preservation: the explicit pointer-to-empty time_zone stays valid
	// — it passes the boundary guards, dispatches exactly once, and
	// compares exactly against empty output.
	emptyRT, emptyRunner := newMacZoneRuntime(process.CommandResult{ExitCode: 0})
	empty := ""
	value, err := (macZoneCompareFunc{}).Execute(context.Background(), emptyRT, &macZoneCompareArgs{TimeZone: &empty})
	if err != nil || value != true {
		t.Fatalf("explicit empty time_zone = %v, %v; want true, nil", value, err)
	}
	if len(emptyRunner.cmds) != 1 {
		t.Fatalf("explicit empty time_zone dispatched %d commands, want 1", len(emptyRunner.cmds))
	}
}
