package timezone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
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

	var winFn runtime.ExecFunction = winZoneCompareFunc{}
	winConstrained, ok := winFn.(runtime.PlatformConstrained)
	if !ok {
		t.Fatal("winZoneCompareFunc must be platform-constrained")
	}
	if !reflect.DeepEqual(winConstrained.Platforms(), []string{"windows"}) {
		t.Fatalf("windows platforms = %v, want [windows]", winConstrained.Platforms())
	}
	if !runtime.SupportsPlatform(winFn, "windows") {
		t.Fatal("windows zone_compare must support windows")
	}
	for _, goos := range []string{"linux", "darwin", "freebsd", "solaris", "aix"} {
		if runtime.SupportsPlatform(winFn, goos) {
			t.Fatalf("windows zone_compare must not support %s", goos)
		}
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	goos := runtime.CurrentGOOS()
	supported := goos == "linux" || goos == "darwin" || goos == "windows"

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

	// Visible layer: Names filters through SupportsPlatform. The
	// surface is 10 names on darwin (base 5 + zone_compare + the four
	// Mac systemsetup getters get_date, get_time, get_time_server,
	// get_using_network_time), 7 on linux (base 5 + zone_compare +
	// get_zonecode), 7 on windows (base 5 + zone_compare + the Windows
	// timezone.list of PTD-EXEC-1632), and 5 everywhere else (no
	// getters, no zone_compare).
	wantTotal := 5
	switch goos {
	case "darwin":
		wantTotal = 10
	case "linux":
		wantTotal = 7
	case "windows":
		wantTotal = 7
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
	case "windows":
		overrideWinSystemTree(t, `C:\Windows\System32`, `C:\Windows`, nil)
		if err := rt.FS.WriteFile(`C:\Windows\System32\tzutil.exe`, []byte("MZ fake tzutil"), 0o755); err != nil {
			t.Fatal(err)
		}
		rt.Runner = &scriptRunner{script: []process.CommandResult{{Stdout: []byte("Mountain Standard Time_dstoff\r\n"), ExitCode: 0}}}
		denver := "America/Denver"
		value, err := reg.Call(context.Background(), rt, "timezone.zone_compare", &winZoneCompareArgs{TimeZone: &denver})
		if err != nil || value != true {
			t.Fatalf("Call on windows = %v, %v, want true, nil", value, err)
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
// systemsetup contract on darwin, the windows tzutil contract on
// windows (WZC-15/GAP-08 lockstep), nothing anywhere else — with the
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

	// WZC-15/GAP-08 lockstep: the windows variant registers through the
	// same helper with its own platform constraint and schema.
	reg = runtime.NewExecRegistry()
	if err := registerZoneCompareForGOOS(reg, "windows"); err != nil {
		t.Fatal(err)
	}
	fn, ok = reg.Get("timezone.zone_compare")
	if !ok {
		t.Fatal("windows helper registered nothing")
	}
	if _, isWin := fn.(winZoneCompareFunc); !isWin {
		t.Fatalf("windows helper registered %T, want winZoneCompareFunc", fn)
	}
	winConstrained, isConstrained := fn.(runtime.PlatformConstrained)
	if !isConstrained || !reflect.DeepEqual(winConstrained.Platforms(), []string{"windows"}) {
		t.Fatalf("windows helper platforms = %v", winConstrained.Platforms())
	}
	if !runtime.SupportsPlatform(fn, "windows") || runtime.SupportsPlatform(fn, "linux") || runtime.SupportsPlatform(fn, "darwin") {
		t.Fatal("windows helper must support windows only")
	}
	winType := reflect.TypeOf(fn.Args())
	if winType.Kind() != reflect.Struct || winType.NumField() != 1 {
		t.Fatalf("windows schema = %s with %d fields", winType, winType.NumField())
	}
	winField := winType.Field(0)
	if winField.Name != "TimeZone" || winField.Type.Kind() != reflect.Pointer || winField.Type.Elem().Kind() != reflect.String || winField.Tag.Get("statekit") != "required,name=timezone" {
		t.Fatalf("windows schema field = %s %s tag %q, want *string TimeZone tagged required,name=timezone", winField.Name, winField.Type, winField.Tag.Get("statekit"))
	}

	for _, goos := range []string{"freebsd", "openbsd", "netbsd", "solaris", "illumos", "aix", "plan9"} {
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
	if err := registerZoneCompareForGOOS(reg, "windows"); err == nil {
		t.Fatal("registering the windows variant over the linux entry must fail as a duplicate")
	}
	if err := reg.Register(macZoneCompareFunc{}); err == nil {
		t.Fatal("registering the mac variant directly over the linux entry must fail as a duplicate")
	}
	if err := reg.Register(winZoneCompareFunc{}); err == nil {
		t.Fatal("registering the windows variant directly over the linux entry must fail as a duplicate")
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
	// The production surface is 10 functions on darwin (base 5 +
	// zone_compare + the four Mac systemsetup getters get_date,
	// get_time, get_time_server, get_using_network_time), 7 on linux
	// (base 5 + zone_compare + get_zonecode), 7 on windows (base 5 +
	// zone_compare + the Windows timezone.list), 5 elsewhere.
	wantLen := 5
	switch goos {
	case "darwin":
		wantLen = 10
	case "linux":
		wantLen = 7
	case "windows":
		wantLen = 7
	}
	if goos == "linux" || goos == "darwin" || goos == "windows" {
		if count != 1 {
			t.Fatalf("zone_compare visible %d times on %s, want exactly 1", count, goos)
		}
	} else if count != 0 {
		t.Fatalf("zone_compare visible %d times on %s, want 0", count, goos)
	}
	if prod.Len() != wantLen {
		t.Fatalf("production registration holds %d functions on %s, want %d", prod.Len(), goos, wantLen)
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

// ---------------------------------------------------------------------------
// macOS get_date / get_time (PTD-EXEC-1627/1628): MGT-01..12 pin the
// pinned mac_timezone.py getter contracts hermetically. Every test uses
// the fake macZoneRunner only — never process.NewRunner, never
// /usr/sbin/systemsetup, never a host filesystem — and the suite makes
// no native Darwin claim. The mapped Salt tests are the functional
// test_get_set_date / test_get_time fixtures (root/destructive/
// Darwin-gated in Salt): they were inspected as source only, never
// executed, and the shapes below are source-derived synthetic
// fixtures.

// wantMacGetterCommand is the fixed, complete systemsetup invocation
// for either Mac getter: absolute admin-controlled path, exactly one
// argv flag, no shell, locale-only child environment, 30s wall clock,
// equal 64 KiB capture ceilings per stream, and nothing else.
func wantMacGetterCommand(flag string) process.Command {
	return process.Command{
		Name:           "/usr/sbin/systemsetup",
		Args:           []string{flag},
		Env:            []string{"LC_ALL=C"},
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 64 << 10,
		MaxStderrBytes: 64 << 10,
	}
}

// requireMacGetterError pins the single fixed execution-category error
// for both getters: the errors.Is sentinel, the exact value-free text,
// and no markers of any underlying cause, output, stream, flag, or
// exit status. (The fixed text itself contains the word "systemsetup",
// so the raw-path marker is the full "/usr/sbin" prefix instead.)
func requireMacGetterError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrMacSystemsetupQuery) {
		t.Fatalf("err = %v, want ErrMacSystemsetupQuery", err)
	}
	if err == nil || err.Error() != "macOS systemsetup query failed" {
		t.Fatalf("err text = %v, want macOS systemsetup query failed", err)
	}
	for _, marker := range []string{
		"/usr/sbin", "-getdate", "-gettime", "2/20/2011", "9:48:16",
		"failing", "warning", "13", "exit", "stdout", "stderr",
		"timed out", "canceled", "not supported", "no such file",
	} {
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatalf("err text %q leaks marker %q", err.Error(), marker)
		}
	}
}

// MGT-01: each getter Execute dispatches exactly one shell-free
// systemsetup query with its single fixed argv flag, the fixed
// environment, timeout, and capture ceilings — deep-equal over the
// whole process.Command, with the live context forwarded to the
// Runner — and returns the parsed date/time string.
func TestMacGettersDispatchFixedCommand(t *testing.T) {
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")})
	value, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	if err != nil || value != "2/20/2011" {
		t.Fatalf("get_date = %v, %v; want 2/20/2011, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("get_date dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if !reflect.DeepEqual(runner.cmds[0], wantMacGetterCommand("-getdate")) {
		t.Fatalf("get_date command = %#v, want %#v", runner.cmds[0], wantMacGetterCommand("-getdate"))
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("get_date runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}

	rt, runner = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time: 9:48:16\n")})
	value, err = (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
	if err != nil || value != "9:48:16" {
		t.Fatalf("get_time = %v, %v; want 9:48:16, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("get_time dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if !reflect.DeepEqual(runner.cmds[0], wantMacGetterCommand("-gettime")) {
		t.Fatalf("get_time command = %#v, want %#v", runner.cmds[0], wantMacGetterCommand("-gettime"))
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("get_time runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}
}

// MGT-02: the getter contract never touches the filesystem on success
// or failure — every path stays inside the hermetic MemoryFS with zero
// recorded operations.
func TestMacGettersNeverTouchesFilesystem(t *testing.T) {
	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	if _, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{}); err != nil {
		t.Fatal(err)
	}
	runner.reply = process.CommandResult{ExitCode: 1}
	if _, err := (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{}); !errors.Is(err, ErrMacSystemsetupQuery) {
		t.Fatalf("nonzero err = %v, want ErrMacSystemsetupQuery", err)
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("filesystem touched: %v", fsys.calls)
	}
}

// MGT-03: stdout is trailing-rstripped with Python str.rstrip
// semantics — unicode.IsSpace plus U+001C..U+001F — with no leading
// trim, before any parsing; interior whitespace survives.
func TestMacGettersPythonTrailingRStrip(t *testing.T) {
	for _, tail := range []string{
		"\n", "\r\n", "\t", " \t\r\n", "\v\f",
		"\u00a0", "\u0085", "\u2028", "\u3000",
		"\u001c", "\u001d", "\u001e", "\u001f",
		" \u001c\u001d\u001e\u001f\u00a0\u2028\t\r\n",
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 6/15/2024" + tail)})
		value, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
		if err != nil || value != "6/15/2024" {
			t.Fatalf("trailing %q: get_date = %v, %v; want 6/15/2024, nil", tail, value, err)
		}
	}

	// Leading whitespace after the delimiter is never stripped; the
	// raw value keeps it.
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date:  6/15/2024\n")})
	value, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	if err != nil || value != " 6/15/2024" {
		t.Fatalf("leading-space get_date = %v, %v; want \" 6/15/2024\", nil", value, err)
	}

	// Interior whitespace survives untouched (a value-internal ": "
	// would itself be the parse delimiter — pinned by MZC-04 — so the
	// interior-space fixture carries no ": " inside the value).
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 6/ 15/2024\n")})
	value, err = (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	if err != nil || value != "6/ 15/2024" {
		t.Fatalf("interior-space get_date = %v, %v; want \"6/ 15/2024\", nil", value, err)
	}
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time: 9 48\n")})
	value, err = (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
	if err != nil || value != "9 48" {
		t.Fatalf("interior-space get_time = %v, %v; want \"9 48\", nil", value, err)
	}
}

// MGT-04: the shared parse_return port through the getters: the first
// ": " delimiter wins and yields the segment after its first
// occurrence (later segments are discarded), then ":\n", else the
// whole raw string with no further trimming.
func TestMacGettersParseReturnDelimiterPriority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		want   string
	}{
		{"colon-space", "Date: 2/20/2011\n", "2/20/2011"},
		{"colon-space repeats discard later segments", "Date: 2/20/2011: Extra: More\n", "2/20/2011"},
		{"colon-newline fallback", "Date:\n2/20/2011\n", "2/20/2011"},
		{"colon-space wins over colon-newline", "Head:\nDate: 2/20/2011\n", "2/20/2011"},
		{"raw passthrough", "2/20/2011", "2/20/2011"},
		{"raw value keeps leading whitespace", " 2/20/2011", " 2/20/2011"},
		{"time colon-space", "Time: 9:48:16\n", "9:48:16"},
		{"time raw passthrough", "9:48:16", "9:48:16"},
	} {
		for _, exec := range []struct {
			label string
			run   func(rt *runtime.Runtime) (any, error)
		}{
			{"date", func(rt *runtime.Runtime) (any, error) {
				return (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
			}},
			{"time", func(rt *runtime.Runtime) (any, error) {
				return (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
			}},
		} {
			rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
			value, err := exec.run(rt)
			if err != nil || value != tc.want {
				t.Fatalf("%s/%s: stdout %q = %v, %v; want %q, nil", exec.label, tc.name, tc.stdout, value, err, tc.want)
			}
		}
	}
}

// MGT-05: source-derived shapes of the mapped functional fixtures —
// inspected, never executed (the Salt suite is root/destructive/
// Darwin-gated). test_get_set_date asserts get_date() == "2/20/2011"
// after set_date; test_get_time parses get_time() with "%H:%M:%S".
func TestMacGettersSaltFunctionalShapes(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")})
	value, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	if err != nil || value != "2/20/2011" {
		t.Fatalf("functional date shape = %v, %v; want 2/20/2011, nil", value, err)
	}

	for _, clock := range []string{"9:48:16", "14:03:59", "23:59:59"} {
		rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time: " + clock + "\n")})
		value, err = (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
		if err != nil || value != clock {
			t.Fatalf("functional time shape = %v, %v; want %q, nil", value, err, clock)
		}
		if _, perr := time.Parse("15:04:05", value.(string)); perr != nil {
			t.Fatalf("get_time %q does not parse with %%H:%%M:%%S: %v", value, perr)
		}
	}
}

// MGT-06: a successful empty or whitespace-rstripped stdout returns
// the empty string (the source getters return parse_return of
// whatever came back), and at-cap streams still parse.
func TestMacGettersEmptyOutputReturnsEmptyString(t *testing.T) {
	for _, reply := range []process.CommandResult{
		{ExitCode: 0},
		{ExitCode: 0, Stdout: []byte(" \r\n\t\u001f")},
	} {
		rt, runner := newMacZoneRuntime(reply)
		value, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
		if err != nil || value != "" {
			t.Fatalf("empty-output get_date = %v, %v; want \"\", nil", value, err)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("empty-output get_date dispatched %d commands, want 1", len(runner.cmds))
		}
	}

	atCap := bytes.Repeat([]byte("x"), 64<<10)
	padded := append([]byte("Time: 9:48:16"), bytes.Repeat([]byte(" "), (64<<10)-len("Time: 9:48:16"))...)
	if len(padded) != 64<<10 {
		t.Fatalf("padded fixture is %d bytes, want exactly the cap", len(padded))
	}
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: padded, Stderr: atCap})
	value, err := (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
	if err != nil || value != "9:48:16" {
		t.Fatalf("at-cap get_time = %v, %v; want 9:48:16, nil", value, err)
	}
}

// MGT-07: exit-0 stdout containing case-insensitive "not supported"
// fails with the fixed getter error before parsing (Salt's
// execute_return_result contract); the phrase in stderr alone does
// not fail.
func TestMacGettersNotSupportedTextFails(t *testing.T) {
	for _, stdout := range []string{
		"Date: not supported\n",
		"NOT SUPPORTED\n",
		"Not Supported\n",
		"Error: this operation is not supported on this system\n",
	} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})
		_, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
		requireMacGetterError(t, err)
		if len(runner.cmds) != 1 {
			t.Fatalf("stdout %q dispatched %d commands, want 1", stdout, len(runner.cmds))
		}
	}

	rt, _ := newMacZoneRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Time: 9:48:16\n"),
		Stderr:   []byte("warning: something not supported \n"),
	})
	value, err := (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
	if err != nil || value != "9:48:16" {
		t.Fatalf("stderr-only not supported = %v, %v; want 9:48:16, nil", value, err)
	}
}

// MGT-08: nonzero exit, Runner start errors, context cancellation and
// timeout, truncation flags, and over-cap streams all map to the one
// fixed getter error with no wrapped cause.
func TestMacGettersFailureCategoriesMapToFixedError(t *testing.T) {
	for _, reply := range []process.CommandResult{
		{ExitCode: 13, Stdout: []byte("Date: 2/20/2011\n"), Stderr: []byte("systemsetup: failing\n")},
		{ExitCode: -1, Err: fmt.Errorf(`exec: "/usr/sbin/systemsetup": stat /usr/sbin/systemsetup: no such file or directory`)},
		{ExitCode: -1, Err: fmt.Errorf("/usr/sbin/systemsetup -getdate canceled: %w", context.Canceled)},
		{ExitCode: -1, Err: fmt.Errorf("/usr/sbin/systemsetup -getdate timed out after 30s: %w", context.DeadlineExceeded)},
		{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n"), StdoutTruncated: true},
		{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n"), Stderr: []byte("x"), StderrTruncated: true},
		{ExitCode: 0, Stdout: bytes.Repeat([]byte("x"), (64<<10)+1)},
		{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n"), Stderr: bytes.Repeat([]byte("x"), (64<<10)+1)},
	} {
		rt, _ := newMacZoneRuntime(reply)
		_, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
		requireMacGetterError(t, err)
		if errors.Is(err, fs.ErrNotExist) || errors.Unwrap(err) != nil {
			t.Fatalf("getter error leaked its cause: %v", err)
		}

		rt, _ = newMacZoneRuntime(reply)
		_, err = (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetTimeArgs{})
		requireMacGetterError(t, err)
	}

	// The caller's context reaches the Runner unchanged.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	if _, err := (macGetDateFunc{}).Execute(ctx, rt, &macGetDateArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.ctxErr) != 1 || !errors.Is(runner.ctxErr[0], context.Canceled) {
		t.Fatalf("runner context errors = %v, want one context.Canceled", runner.ctxErr)
	}
}

// MGT-09: the getter sentinel is its own fixed category — errors.Is
// matches only ErrMacSystemsetupQuery, never the zone_compare or
// Windows sentinels, with no Unwrap chain.
func TestMacGettersErrorSentinelIsDistinct(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 1})
	_, err := (macGetDateFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	requireMacGetterError(t, err)
	for _, other := range []error{ErrCannotDetermineZone, ErrUnknownUnsafeZone, ErrInvalidWindowsZone, errMacZoneInvalidArgs, errMacGetterInvalidArgs} {
		if errors.Is(err, other) {
			t.Fatalf("getter err %v matches foreign sentinel %v", err, other)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("getter err unwraps to %v, want no cause", errors.Unwrap(err))
	}
	if errors.Is(ErrCannotDetermineZone, ErrMacSystemsetupQuery) || errors.Is(ErrMacSystemsetupQuery, ErrCannotDetermineZone) {
		t.Fatal("ErrMacSystemsetupQuery and ErrCannotDetermineZone must not cross-match")
	}
	if errors.Is(ErrInvalidWindowsZone, ErrMacSystemsetupQuery) || errors.Is(ErrMacSystemsetupQuery, ErrInvalidWindowsZone) {
		t.Fatal("ErrMacSystemsetupQuery and ErrInvalidWindowsZone must not cross-match")
	}
	if ErrMacSystemsetupQuery.Error() != "macOS systemsetup query failed" {
		t.Fatalf("sentinel text = %q", ErrMacSystemsetupQuery.Error())
	}
}

// MGT-10: the Execute boundary fails safe for direct callers that
// bypass the registry gate: wrong argument types (including the other
// getter's args), typed-nil pointers, a nil Runtime, and a nil Runner
// all return fixed value-free errors before any Runner dispatch or
// filesystem access — never a panic — while valid zero-field args
// dispatch exactly once.
func TestMacGettersExecuteFailsSafeOnMalformedInvocation(t *testing.T) {
	exec := func(label string, rt *runtime.Runtime, args any, verify func(t *testing.T, err error)) {
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
			value, err = (macGetDateFunc{}).Execute(context.Background(), rt, args)
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

	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}

	var malformedErrs []error
	secretZone := "Secret/Zone-Args"
	for _, tc := range []struct {
		label string
		args  any
	}{
		{"wrong-type string", "Secret/Getter-Marker"},
		{"wrong-type zone_compare args", &macZoneCompareArgs{TimeZone: &secretZone}},
		{"wrong-type time args on date func", &macGetTimeArgs{}},
		{"typed-nil date args", (*macGetDateArgs)(nil)},
		{"nil args", nil},
	} {
		args := tc.args
		exec(tc.label, rt, args, func(t *testing.T, err error) {
			fixedValueFree("Secret", "Marker", "Zone", "2/20/2011")(t, err)
			malformedErrs = append(malformedErrs, err)
		})
	}
	for i := 1; i < len(malformedErrs); i++ {
		if malformedErrs[i].Error() != malformedErrs[0].Error() {
			t.Fatalf("malformed-args error %q differs from %q, want one fixed error", malformedErrs[i].Error(), malformedErrs[0].Error())
		}
	}
	if malformedErrs[0].Error() != "invalid timezone getter arguments" {
		t.Fatalf("malformed-args error = %q, want invalid timezone getter arguments", malformedErrs[0].Error())
	}

	// The time getter enforces the same boundary on its own args type.
	_, err := (macGetTimeFunc{}).Execute(context.Background(), rt, &macGetDateArgs{})
	if err == nil || err.Error() != "invalid timezone getter arguments" {
		t.Fatalf("cross-getter args err = %v, want invalid timezone getter arguments", err)
	}

	// No malformed invocation may dispatch or touch the filesystem.
	if len(runner.cmds) != 0 {
		t.Fatalf("malformed invocations dispatched %d commands, want 0", len(runner.cmds))
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("malformed invocations touched the filesystem: %v", fsys.calls)
	}

	// Unavailable runtime: nil Runtime and nil Runner map to the fixed
	// execution-category error before any dispatch.
	exec("nil Runtime", nil, &macGetDateArgs{}, func(t *testing.T, err error) {
		fixedValueFree("2/20/2011")(t, err)
		requireMacGetterError(t, err)
	})
	nilRunnerFS := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	nilRunnerRT := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: nilRunnerFS, Runner: nil}
	exec("nil Runner", nilRunnerRT, &macGetDateArgs{}, func(t *testing.T, err error) {
		fixedValueFree("2/20/2011")(t, err)
		requireMacGetterError(t, err)
	})
	if len(nilRunnerFS.calls) != 0 {
		t.Fatalf("nil Runner touched the filesystem: %v", nilRunnerFS.calls)
	}

	// Preservation: valid zero-field args dispatch exactly once.
	validRT, validRunner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time: 9:48:16\n")})
	value, err := (macGetTimeFunc{}).Execute(context.Background(), validRT, &macGetTimeArgs{})
	if err != nil || value != "9:48:16" {
		t.Fatalf("valid get_time = %v, %v; want 9:48:16, nil", value, err)
	}
	if len(validRunner.cmds) != 1 {
		t.Fatalf("valid get_time dispatched %d commands, want 1", len(validRunner.cmds))
	}
}

// MGT-11: the closed macSystemsetupGetter enum maps the date/time half
// of the read-only getters to -getdate and -gettime; any other value
// is rejected with a fixed error before the Runner is touched —
// arbitrary argv, zone flags, and setter flags cannot be expressed
// through the enum at all (MNT-11 pins the full four-flag closure).
func TestMacGettersUnknownEnumRejectedBeforeRunner(t *testing.T) {
	for _, unknown := range []macSystemsetupGetter{macSystemsetupGetter(4), macSystemsetupGetter(-1)} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Date: 2/20/2011\n")})
		_, err := macSystemsetupQuery(context.Background(), rt, unknown)
		if err == nil || err.Error() != "unknown systemsetup getter" {
			t.Fatalf("unknown enum %d err = %v, want unknown systemsetup getter", unknown, err)
		}
		if errors.Is(err, ErrMacSystemsetupQuery) {
			t.Fatalf("unknown enum %d err = %v, want the distinct unknown-getter error", unknown, err)
		}
		if len(runner.cmds) != 0 {
			t.Fatalf("unknown enum %d dispatched %d commands, want 0", unknown, len(runner.cmds))
		}
	}

	// The two closed values map to their single fixed flags.
	for _, tc := range []struct {
		getter macSystemsetupGetter
		flag   string
	}{
		{macSystemsetupGetDate, "-getdate"},
		{macSystemsetupGetTime, "-gettime"},
	} {
		flag, err := tc.getter.flag()
		if err != nil || flag != tc.flag {
			t.Fatalf("enum %d flag = %q, %v; want %q, nil", tc.getter, flag, err, tc.flag)
		}
	}
}

// MGT-12: registration selects the Mac getters per GOOS through the
// unexported registerMacGettersForGOOS helper (the Darwin selector
// seam, exercised from any host): the getters on darwin only, with
// zero-field args prototypes, no superseded aliases, off-host dispatch
// rejected as unsupported, and the production Register surface at 10
// names on darwin / 7 on linux (with the Linux get_zonecode) / 6 on
// windows / 5 elsewhere (the count includes the network-time getters
// pinned by MNT-12).
func TestMacGettersRegistrationSelectsPerGOOS(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerMacGettersForGOOS(reg, "darwin"); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 4 {
		t.Fatalf("darwin helper registered %d functions, want 4", reg.Len())
	}
	for _, tc := range []struct {
		name string
		fn   runtime.ExecFunction
	}{
		{"timezone.get_date", macGetDateFunc{}},
		{"timezone.get_time", macGetTimeFunc{}},
	} {
		fn, ok := reg.Get(tc.name)
		if !ok {
			t.Fatalf("darwin helper did not register %s", tc.name)
		}
		if _, isDate := fn.(macGetDateFunc); tc.name == "timezone.get_date" && !isDate {
			t.Fatalf("%s registered %T", tc.name, fn)
		}
		if _, isTime := fn.(macGetTimeFunc); tc.name == "timezone.get_time" && !isTime {
			t.Fatalf("%s registered %T", tc.name, fn)
		}
		constrained, isConstrained := fn.(runtime.PlatformConstrained)
		if !isConstrained || !reflect.DeepEqual(constrained.Platforms(), []string{"darwin"}) {
			t.Fatalf("%s platforms = %v, want [darwin]", tc.name, constrained.Platforms())
		}
		if !runtime.SupportsPlatform(fn, "darwin") {
			t.Fatalf("%s must support darwin", tc.name)
		}
		for _, goos := range []string{"linux", "windows", "freebsd", "solaris", "aix"} {
			if runtime.SupportsPlatform(fn, goos) {
				t.Fatalf("%s must not support %s", tc.name, goos)
			}
		}
		// Zero-field args contract (catalog declares no parameters) and
		// no required gate to trip.
		argsType := reflect.TypeOf(tc.fn.Args())
		if argsType.Kind() != reflect.Struct || argsType.NumField() != 0 {
			t.Fatalf("%s args prototype = %s with %d fields, want a zero-field struct", tc.name, argsType, argsType.NumField())
		}
		if err := config.ValidateRequired(reflect.New(argsType).Interface()); err != nil {
			t.Fatalf("%s zero-field args failed the required gate: %v", tc.name, err)
		}
		// The two prototypes are distinct concrete types.
		if reflect.TypeOf((macGetDateFunc{}).Args()) == reflect.TypeOf((macGetTimeFunc{}).Args()) {
			t.Fatal("get_date and get_time must declare distinct args types")
		}
	}
	// No duplicate getter entry can exist.
	if err := reg.Register(macGetDateFunc{}); err == nil {
		t.Fatal("registering get_date twice must fail as a duplicate")
	}
	if err := reg.Register(macGetTimeFunc{}); err == nil {
		t.Fatal("registering get_time twice must fail as a duplicate")
	}

	// Every non-darwin GOOS registers no getter at all.
	for _, goos := range []string{"linux", "windows", "freebsd", "openbsd", "netbsd", "solaris", "illumos", "aix", "plan9"} {
		other := runtime.NewExecRegistry()
		if err := registerMacGettersForGOOS(other, goos); err != nil {
			t.Fatal(err)
		}
		if other.Len() != 0 {
			t.Fatalf("helper registered %d functions for %s, want 0", other.Len(), goos)
		}
		if _, ok := other.Get("timezone.get_date"); ok {
			t.Fatalf("helper registered get_date for %s", goos)
		}
		if _, ok := other.Get("timezone.get_time"); ok {
			t.Fatalf("helper registered get_time for %s", goos)
		}
	}

	// Production Register: the surface is 10 names on darwin, 7 on
	// linux (base 5 + zone_compare + get_zonecode), 7 on windows (base
	// 5 + zone_compare + the Windows timezone.list), 5 elsewhere; the
	// getters are visible exactly on darwin; no superseded alias is
	// ever registered; the raw alias lookup fails on every host.
	prod := runtime.NewExecRegistry()
	if err := Register(prod); err != nil {
		t.Fatal(err)
	}
	goos := runtime.CurrentGOOS()
	wantLen := 5
	switch goos {
	case "darwin":
		wantLen = 10
	case "linux":
		wantLen = 7
	case "windows":
		wantLen = 7
	}
	if prod.Len() != wantLen {
		t.Fatalf("production registration holds %d functions on %s, want %d", prod.Len(), goos, wantLen)
	}
	visible := 0
	for _, name := range prod.Names() {
		if name == "timezone.get_date" || name == "timezone.get_time" {
			visible++
		}
		if strings.HasPrefix(name, "timezone.get_date_") || strings.HasPrefix(name, "timezone.get_time_") {
			t.Fatalf("superseded alias %q registered on %s", name, goos)
		}
	}
	if goos == "darwin" && visible != 2 {
		t.Fatalf("getters visible %d times on darwin, want 2", visible)
	}
	if goos != "darwin" && visible != 0 {
		t.Fatalf("getters visible %d times on %s, want 0", visible, goos)
	}
	for _, alias := range []string{"timezone.get_date_", "timezone.get_time_"} {
		if _, ok := prod.Get(alias); ok {
			t.Fatalf("raw alias %q registered on %s", alias, goos)
		}
	}

	// Off-host dispatch: the darwin registration surfaced through a
	// non-darwin host is invisible and rejected as unsupported
	// (ResolveArgs and Call); on darwin itself the raw entry exists.
	if goos != "darwin" {
		darwinReg := runtime.NewExecRegistry()
		if err := registerMacGettersForGOOS(darwinReg, "darwin"); err != nil {
			t.Fatal(err)
		}
		for _, name := range darwinReg.Names() {
			if name == "timezone.get_date" || name == "timezone.get_time" {
				t.Fatalf("Names exposed %s for darwin registration on host %s", name, goos)
			}
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &macZoneRunner{}}
		var unsupported *runtime.UnsupportedError
		for _, name := range []string{"timezone.get_date", "timezone.get_time"} {
			if _, err := darwinReg.ResolveArgs(rt, name); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
				t.Fatalf("ResolveArgs %s on %s = %v, want unsupported function", name, goos, err)
			}
			if _, err := darwinReg.Call(context.Background(), rt, name, &macGetDateArgs{}); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
				t.Fatalf("Call %s on %s = %v, want unsupported function", name, goos, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// macOS get_using_network_time / get_time_server (PTD-EXEC-1629/1630):
// MNT-01..12 pin the pinned mac_timezone.py network-time getter
// contracts hermetically. Every test uses the fake macZoneRunner only
// — never process.NewRunner, never /usr/sbin/systemsetup, never a host
// filesystem — and the suite makes no native Darwin claim. The mapped
// Salt tests are the functional test_get_set_using_network_time and
// test_get_set_time_server fixtures (they mutate global host settings
// through the setters under root/destructive/Darwin gates in Salt):
// they were inspected as source only, never executed, every shape
// below is a source-derived synthetic fixture, and the only server
// literal used is the synthetic time.example.invalid (the Salt
// fixture's own server literal is deliberately not reproduced).

// requireMacNetworkTimeStateError pins the fixed value-free
// invocation-category error for the network-time state: the errors.Is
// sentinel, the exact text, and no markers of the raw parsed value or
// of any query-failure cause.
func requireMacNetworkTimeStateError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrMacNetworkTimeStateInvalid) {
		t.Fatalf("err = %v, want ErrMacNetworkTimeStateInvalid", err)
	}
	if err == nil || err.Error() != "macOS network time state invalid" {
		t.Fatalf("err text = %v, want macOS network time state invalid", err)
	}
	for _, marker := range []string{
		"/usr/sbin", "-getusingnetworktime", "-getnetworktimeserver",
		"maybe", "flurgendorf", "on off", "true", "False", "enable",
		"exit", "stdout", "stderr",
	} {
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatalf("err text %q leaks marker %q", err.Error(), marker)
		}
	}
}

// MNT-01: each network-time getter Execute dispatches exactly one
// shell-free systemsetup query with its single fixed argv flag, the
// fixed environment, timeout, and capture ceilings — deep-equal over
// the whole process.Command, with the live context forwarded to the
// Runner — and returns the source-shaped answer.
func TestMacNetworkTimeGettersDispatchFixedCommand(t *testing.T) {
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: On\n")})
	value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != true {
		t.Fatalf("get_using_network_time = %v, %v; want true, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("get_using_network_time dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if !reflect.DeepEqual(runner.cmds[0], wantMacGetterCommand("-getusingnetworktime")) {
		t.Fatalf("get_using_network_time command = %#v, want %#v", runner.cmds[0], wantMacGetterCommand("-getusingnetworktime"))
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("get_using_network_time runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}

	rt, runner = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid\n")})
	value, err = (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
	if err != nil || value != "time.example.invalid" {
		t.Fatalf("get_time_server = %v, %v; want time.example.invalid, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("get_time_server dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if !reflect.DeepEqual(runner.cmds[0], wantMacGetterCommand("-getnetworktimeserver")) {
		t.Fatalf("get_time_server command = %#v, want %#v", runner.cmds[0], wantMacGetterCommand("-getnetworktimeserver"))
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("get_time_server runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}
}

// MNT-02: the network-time getter contract never touches the
// filesystem on success, query failure, or invalid state — every path
// stays inside the hermetic MemoryFS with zero recorded operations, so
// no mutation is possible at all.
func TestMacNetworkTimeGettersNeverTouchesFilesystem(t *testing.T) {
	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: On\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	if _, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{}); err != nil {
		t.Fatal(err)
	}
	runner.reply = process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid\n")}
	if _, err := (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{}); err != nil {
		t.Fatal(err)
	}
	runner.reply = process.CommandResult{ExitCode: 1}
	if _, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{}); !errors.Is(err, ErrMacSystemsetupQuery) {
		t.Fatalf("nonzero err = %v, want ErrMacSystemsetupQuery", err)
	}
	runner.reply = process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: maybe\n")}
	if _, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{}); !errors.Is(err, ErrMacNetworkTimeStateInvalid) {
		t.Fatalf("invalid-state err = %v, want ErrMacNetworkTimeStateInvalid", err)
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("filesystem touched: %v", fsys.calls)
	}
}

// MNT-03: stdout is trailing-rstripped with Python str.rstrip
// semantics — unicode.IsSpace plus U+001C..U+001F — with no leading
// trim, before any parsing; interior whitespace survives.
func TestMacNetworkTimeGettersPythonTrailingRStrip(t *testing.T) {
	for _, tail := range []string{
		"\n", "\r\n", "\t", " \t\r\n", "\v\f",
		"\u00a0", "\u0085", "\u2028", "\u3000",
		"\u001c", "\u001d", "\u001e", "\u001f",
		" \u001c\u001d\u001e\u001f\u00a0\u2028\t\r\n",
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: on" + tail)})
		value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
		if err != nil || value != true {
			t.Fatalf("trailing %q: get_using_network_time = %v, %v; want true, nil", tail, value, err)
		}
		rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid" + tail)})
		value, err = (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
		if err != nil || value != "time.example.invalid" {
			t.Fatalf("trailing %q: get_time_server = %v, %v; want time.example.invalid, nil", tail, value, err)
		}
	}

	// Leading whitespace after the delimiter is never stripped: the
	// server value keeps it, and the state value stays invalid — the
	// source validate_enabled applies no trim of its own.
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server:  time.example.invalid\n")})
	value, err := (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
	if err != nil || value != " time.example.invalid" {
		t.Fatalf("leading-space get_time_server = %v, %v; want \" time.example.invalid\", nil", value, err)
	}
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time:  on\n")})
	_, err = (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	requireMacNetworkTimeStateError(t, err)

	// Interior whitespace survives untouched (the fixture carries no
	// ": " inside the value, which would itself be the delimiter).
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid extra\n")})
	value, err = (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
	if err != nil || value != "time.example.invalid extra" {
		t.Fatalf("interior-space get_time_server = %v, %v; want \"time.example.invalid extra\", nil", value, err)
	}
}

// MNT-04: the shared parse_return port through the network-time
// getters: the first ": " delimiter wins and yields the segment after
// its first occurrence (later segments are discarded), then ":\n",
// else the whole raw string with no further trimming. A successful
// empty or whitespace-only stdout — empty after the Python rstrip —
// is a success shape: it parses to the empty string with a nil error,
// never a failure category (QA MNT-04 evidence gap).
func TestMacNetworkTimeGettersParseReturnDelimiterPriority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		want   any
	}{
		{"state colon-space", "Network Time: on\n", true},
		{"state colon-space repeats discard later segments", "Network Time: on: Extra: More\n", true},
		{"state colon-newline fallback", "Network Time:\noff\n", false},
		{"state colon-space wins over colon-newline", "Head:\nNetwork Time: no\n", false},
		{"state raw passthrough", "yes", true},
		{"state raw off", "off", false},
		{"server colon-space", "Time Server: time.example.invalid\n", "time.example.invalid"},
		{"server repeats discard later segments", "Time Server: time.example.invalid: Pool: 2\n", "time.example.invalid"},
		{"server colon-newline fallback", "Time Server:\ntime.example.invalid\n", "time.example.invalid"},
		{"server raw passthrough", "time.example.invalid", "time.example.invalid"},
		{"server empty stdout", "", ""},
		{"server whitespace-only stdout", " \t\r\n", ""},
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		if want, ok := tc.want.(bool); ok {
			value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
			if err != nil || value != want {
				t.Fatalf("%s: stdout %q = %v, %v; want %v, nil", tc.name, tc.stdout, value, err, want)
			}
			continue
		}
		value, err := (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
		if err != nil || value != tc.want.(string) {
			t.Fatalf("%s: stdout %q = %v, %v; want %q, nil", tc.name, tc.stdout, value, err, tc.want)
		}
	}

	// Empty-after-rstrip success evidence for the two rows above: the
	// getter answers "" with a nil error — neither the query-failure
	// sentinel nor the state sentinel — with exactly one fixed
	// -getnetworktimeserver dispatch, the full fixed command, the live
	// context forwarded to the Runner, and zero filesystem operations.
	for _, stdout := range []string{"", " \t\r\n"} {
		fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
		runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
		value, err := (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
		if errors.Is(err, ErrMacSystemsetupQuery) {
			t.Fatalf("empty-after-rstrip stdout %q mislabeled as ErrMacSystemsetupQuery", stdout)
		}
		if errors.Is(err, ErrMacNetworkTimeStateInvalid) {
			t.Fatalf("empty-after-rstrip stdout %q mislabeled as ErrMacNetworkTimeStateInvalid", stdout)
		}
		if err != nil || value != "" {
			t.Fatalf("empty-after-rstrip stdout %q: get_time_server = %v, %v; want \"\", nil", stdout, value, err)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("empty-after-rstrip stdout %q dispatched %d commands, want exactly 1", stdout, len(runner.cmds))
		}
		if !reflect.DeepEqual(runner.cmds[0], wantMacGetterCommand("-getnetworktimeserver")) {
			t.Fatalf("empty-after-rstrip stdout %q command = %#v, want %#v", stdout, runner.cmds[0], wantMacGetterCommand("-getnetworktimeserver"))
		}
		if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
			t.Fatalf("empty-after-rstrip stdout %q runner context errors = %v, want one nil (live context forwarded)", stdout, runner.ctxErr)
		}
		if len(fsys.calls) != 0 {
			t.Fatalf("empty-after-rstrip stdout %q touched the filesystem: %v", stdout, fsys.calls)
		}
	}
}

// MNT-05: source-derived shapes of the mapped functional fixtures —
// inspected, never executed (the Salt suite mutates global host state
// through the setters under root/destructive/Darwin gates).
// test_get_set_using_network_time asserts get_using_network_time()
// truthy after set_using_network_time(True) and falsy after False;
// test_get_set_time_server asserts get_time_server() equals the server
// it set. The synthetic server below is time.example.invalid only: the
// Salt fixture's own server literal is deliberately not reproduced.
func TestMacNetworkTimeGettersSaltFunctionalShapes(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: On\n")})
	value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != true {
		t.Fatalf("functional enabled shape = %v, %v; want true, nil", value, err)
	}

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: Off\n")})
	value, err = (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != false {
		t.Fatalf("functional disabled shape = %v, %v; want false, nil", value, err)
	}

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid\n")})
	value, err = (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
	if err != nil || value != "time.example.invalid" {
		t.Fatalf("functional server shape = %v, %v; want time.example.invalid, nil", value, err)
	}
}

// MNT-06: the validate_enabled string branch accepts exactly the
// case-insensitive on/yes/off/no aliases over the parsed answer —
// nothing more — with exactly one dispatch per call.
func TestMacGetUsingNetworkTimeEnabledAliases(t *testing.T) {
	for _, tc := range []struct {
		answer string
		want   bool
	}{
		{"on", true}, {"ON", true}, {"On", true}, {"oN", true},
		{"yes", true}, {"YES", true}, {"Yes", true}, {"yEs", true},
		{"off", false}, {"OFF", false}, {"Off", false}, {"oFf", false},
		{"no", false}, {"NO", false}, {"No", false}, {"nO", false},
	} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: " + tc.answer + "\n")})
		value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
		if err != nil || value != tc.want {
			t.Fatalf("answer %q = %v, %v; want %v, nil", tc.answer, value, err, tc.want)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("answer %q dispatched %d commands, want 1", tc.answer, len(runner.cmds))
		}
	}

	// A raw (delimiter-free) alias parses to itself.
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("YES\n")})
	value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != true {
		t.Fatalf("raw YES = %v, %v; want true, nil", value, err)
	}
}

// MNT-07: malformed parsed answers are invocation failures, never
// false: the empty string (including whitespace-only stdout), unknown
// words, multi-line leftovers, numeric strings, and Go-style boolean
// words all fail with the fixed value-free state sentinel — mirroring
// the SaltInvocationError of mac_utils.validate_enabled — with a nil
// result value and exactly one dispatch.
func TestMacGetUsingNetworkTimeMalformedOutputErrorsNotFalse(t *testing.T) {
	for _, stdout := range []string{
		"",
		" \r\n\t\u001f",
		"Network Time: \n",
		"Network Time: maybe\n",
		"Network Time: on\nextra line\n",
		"Network Time: 1\n",
		"Network Time: 0\n",
		"Network Time: true\n",
		"Network Time: False\n",
		"Network Time: enable\n",
		"flurgendorf",
	} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)})
		value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
		if err == nil || value != nil {
			t.Fatalf("stdout %q = %v, %v; want nil value and the fixed error", stdout, value, err)
		}
		requireMacNetworkTimeStateError(t, err)
		if errors.Is(err, ErrMacSystemsetupQuery) {
			t.Fatalf("stdout %q mislabeled as a query failure: %v", stdout, err)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("stdout %q dispatched %d commands, want 1", stdout, len(runner.cmds))
		}
	}
}

// MNT-08: nonzero exit, Runner start errors, context cancellation and
// timeout, a not-supported stdout, truncation flags, and over-cap
// streams all map to the one fixed query error for both network-time
// getters — the query-failure category, never the state sentinel —
// with no wrapped cause; at-cap streams still parse; the phrase in
// stderr alone does not fail; the caller's context reaches the Runner.
func TestMacNetworkTimeGettersFailureCategoriesMapToFixedError(t *testing.T) {
	for _, reply := range []process.CommandResult{
		{ExitCode: 13, Stdout: []byte("Network Time: on\n"), Stderr: []byte("systemsetup: failing\n")},
		{ExitCode: -1, Err: fmt.Errorf(`exec: "/usr/sbin/systemsetup": stat /usr/sbin/systemsetup: no such file or directory`)},
		{ExitCode: -1, Err: fmt.Errorf("/usr/sbin/systemsetup -getusingnetworktime canceled: %w", context.Canceled)},
		{ExitCode: -1, Err: fmt.Errorf("/usr/sbin/systemsetup -getnetworktimeserver timed out after 30s: %w", context.DeadlineExceeded)},
		{ExitCode: 0, Stdout: []byte("Network Time: not supported on this machine\n")},
		{ExitCode: 0, Stdout: []byte("Network Time: on\n"), StdoutTruncated: true},
		{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid\n"), Stderr: []byte("x"), StderrTruncated: true},
		{ExitCode: 0, Stdout: bytes.Repeat([]byte("x"), (64<<10)+1)},
		{ExitCode: 0, Stdout: []byte("Network Time: on\n"), Stderr: bytes.Repeat([]byte("x"), (64<<10)+1)},
	} {
		rt, _ := newMacZoneRuntime(reply)
		_, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
		requireMacGetterError(t, err)
		if errors.Is(err, ErrMacNetworkTimeStateInvalid) {
			t.Fatalf("query failure mislabeled as invalid state: %v", err)
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Unwrap(err) != nil {
			t.Fatalf("getter error leaked its cause: %v", err)
		}

		rt, _ = newMacZoneRuntime(reply)
		_, err = (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
		requireMacGetterError(t, err)
	}

	// At-cap streams still parse (the limits fail closed only above
	// the cap).
	padded := append([]byte("Time Server: time.example.invalid"), bytes.Repeat([]byte(" "), (64<<10)-len("Time Server: time.example.invalid"))...)
	if len(padded) != 64<<10 {
		t.Fatalf("padded fixture is %d bytes, want exactly the cap", len(padded))
	}
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: padded, Stderr: bytes.Repeat([]byte("x"), 64<<10)})
	value, err := (macGetTimeServerFunc{}).Execute(context.Background(), rt, &macGetTimeServerArgs{})
	if err != nil || value != "time.example.invalid" {
		t.Fatalf("at-cap get_time_server = %v, %v; want time.example.invalid, nil", value, err)
	}

	// The not-supported phrase in stderr alone does not fail.
	rt, _ = newMacZoneRuntime(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("Network Time: off\n"),
		Stderr:   []byte("warning: something not supported \n"),
	})
	value, err = (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != false {
		t.Fatalf("stderr-only not supported = %v, %v; want false, nil", value, err)
	}

	// The caller's context reaches the Runner unchanged.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: on\n")}}
	rt = &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	if _, err := (macGetUsingNetworkTimeFunc{}).Execute(ctx, rt, &macGetUsingNetworkTimeArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.ctxErr) != 1 || !errors.Is(runner.ctxErr[0], context.Canceled) {
		t.Fatalf("runner context errors = %v, want one context.Canceled", runner.ctxErr)
	}
}

// MNT-09: the two network-time error categories are distinct fixed
// sentinels: errors.Is matches only its own sentinel, never the
// zone_compare, Windows, getter-args, unknown-getter, or sibling
// query/state sentinels, with no Unwrap chain.
func TestMacNetworkTimeErrorSentinelsAreDistinct(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: maybe\n")})
	_, stateErr := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	requireMacNetworkTimeStateError(t, stateErr)

	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 1})
	_, queryErr := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), rt, &macGetUsingNetworkTimeArgs{})
	requireMacGetterError(t, queryErr)

	if errors.Is(stateErr, ErrMacSystemsetupQuery) || errors.Is(queryErr, ErrMacNetworkTimeStateInvalid) {
		t.Fatal("state and query categories must not cross-match")
	}
	for _, other := range []error{ErrCannotDetermineZone, ErrUnknownUnsafeZone, ErrInvalidWindowsZone, errMacZoneInvalidArgs, errMacGetterInvalidArgs, errMacSystemsetupUnknownGetter} {
		if errors.Is(stateErr, other) {
			t.Fatalf("state err %v matches foreign sentinel %v", stateErr, other)
		}
		if errors.Is(queryErr, other) {
			t.Fatalf("query err %v matches foreign sentinel %v", queryErr, other)
		}
	}
	if errors.Unwrap(stateErr) != nil || errors.Unwrap(queryErr) != nil {
		t.Fatalf("errors unwrap: state=%v query=%v, want no causes", errors.Unwrap(stateErr), errors.Unwrap(queryErr))
	}
	for _, pair := range [][2]error{
		{ErrMacNetworkTimeStateInvalid, ErrCannotDetermineZone},
		{ErrMacNetworkTimeStateInvalid, ErrInvalidWindowsZone},
		{ErrMacNetworkTimeStateInvalid, ErrUnknownUnsafeZone},
		{ErrMacNetworkTimeStateInvalid, ErrMacSystemsetupQuery},
	} {
		if errors.Is(pair[0], pair[1]) || errors.Is(pair[1], pair[0]) {
			t.Fatalf("sentinels %v and %v must not cross-match", pair[0], pair[1])
		}
	}
	if ErrMacNetworkTimeStateInvalid.Error() != "macOS network time state invalid" {
		t.Fatalf("sentinel text = %q", ErrMacNetworkTimeStateInvalid.Error())
	}
}

// MNT-10: the Execute boundary fails safe for direct callers that
// bypass the registry gate: wrong argument types (including the other
// getters' args), typed-nil pointers, nil args, a nil Runtime, and a
// nil Runner all return fixed value-free errors before any Runner
// dispatch or filesystem access — never a panic — while valid
// zero-field args dispatch exactly once.
func TestMacNetworkTimeGettersExecuteFailsSafeOnMalformedInvocation(t *testing.T) {
	exec := func(label string, fn runtime.ExecFunction, rt *runtime.Runtime, args any, verify func(t *testing.T, err error)) {
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
			value, err = fn.Execute(context.Background(), rt, args)
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

	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: On\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}

	secretZone := "Secret/Zone-Args"
	var malformedErrs []error
	for _, tc := range []struct {
		label string
		fn    runtime.ExecFunction
		args  any
	}{
		{"wrong-type string on state", macGetUsingNetworkTimeFunc{}, "Secret/Network-Marker"},
		{"wrong-type string on server", macGetTimeServerFunc{}, "Secret/Network-Marker"},
		{"wrong-type zone_compare args", macGetUsingNetworkTimeFunc{}, &macZoneCompareArgs{TimeZone: &secretZone}},
		{"wrong-type date args", macGetUsingNetworkTimeFunc{}, &macGetDateArgs{}},
		{"cross-getter server args on state", macGetUsingNetworkTimeFunc{}, &macGetTimeServerArgs{}},
		{"cross-getter state args on server", macGetTimeServerFunc{}, &macGetUsingNetworkTimeArgs{}},
		{"typed-nil state args", macGetUsingNetworkTimeFunc{}, (*macGetUsingNetworkTimeArgs)(nil)},
		{"typed-nil server args", macGetTimeServerFunc{}, (*macGetTimeServerArgs)(nil)},
		{"nil args", macGetUsingNetworkTimeFunc{}, nil},
	} {
		exec(tc.label, tc.fn, rt, tc.args, func(t *testing.T, err error) {
			fixedValueFree("Secret", "Marker", "Zone", "Network")(t, err)
			malformedErrs = append(malformedErrs, err)
		})
	}
	for i := 1; i < len(malformedErrs); i++ {
		if malformedErrs[i].Error() != malformedErrs[0].Error() {
			t.Fatalf("malformed-args error %q differs from %q, want one fixed error", malformedErrs[i].Error(), malformedErrs[0].Error())
		}
	}
	if malformedErrs[0].Error() != "invalid timezone getter arguments" {
		t.Fatalf("malformed-args error = %q, want invalid timezone getter arguments", malformedErrs[0].Error())
	}

	// No malformed invocation may dispatch or touch the filesystem.
	if len(runner.cmds) != 0 {
		t.Fatalf("malformed invocations dispatched %d commands, want 0", len(runner.cmds))
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("malformed invocations touched the filesystem: %v", fsys.calls)
	}

	// Unavailable runtime: nil Runtime and nil Runner map to the fixed
	// execution-category error before any dispatch.
	exec("nil Runtime", macGetUsingNetworkTimeFunc{}, nil, &macGetUsingNetworkTimeArgs{}, func(t *testing.T, err error) {
		fixedValueFree("On")(t, err)
		requireMacGetterError(t, err)
	})
	nilRunnerFS := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	nilRunnerRT := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: nilRunnerFS, Runner: nil}
	exec("nil Runner", macGetTimeServerFunc{}, nilRunnerRT, &macGetTimeServerArgs{}, func(t *testing.T, err error) {
		fixedValueFree("On")(t, err)
		requireMacGetterError(t, err)
	})
	if len(nilRunnerFS.calls) != 0 {
		t.Fatalf("nil Runner touched the filesystem: %v", nilRunnerFS.calls)
	}

	// Preservation: valid zero-field args dispatch exactly once on
	// both getters.
	validRT, validRunner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: On\n")})
	value, err := (macGetUsingNetworkTimeFunc{}).Execute(context.Background(), validRT, &macGetUsingNetworkTimeArgs{})
	if err != nil || value != true {
		t.Fatalf("valid get_using_network_time = %v, %v; want true, nil", value, err)
	}
	if len(validRunner.cmds) != 1 {
		t.Fatalf("valid get_using_network_time dispatched %d commands, want 1", len(validRunner.cmds))
	}
	validRT, validRunner = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Time Server: time.example.invalid\n")})
	value, err = (macGetTimeServerFunc{}).Execute(context.Background(), validRT, &macGetTimeServerArgs{})
	if err != nil || value != "time.example.invalid" {
		t.Fatalf("valid get_time_server = %v, %v; want time.example.invalid, nil", value, err)
	}
	if len(validRunner.cmds) != 1 {
		t.Fatalf("valid get_time_server dispatched %d commands, want 1", len(validRunner.cmds))
	}
}

// MNT-11: the closed macSystemsetupGetter enum maps only to the four
// read-only flags; the two network-time values map to
// -getusingnetworktime and -getnetworktimeserver, and any other value
// is rejected with the fixed unknown-getter error before the Runner is
// touched — no setter flag (or zone flag) can be expressed through the
// enum at all.
func TestMacNetworkTimeGettersClosedEnumRejectsSettersBeforeRunner(t *testing.T) {
	for _, unknown := range []macSystemsetupGetter{macSystemsetupGetter(4), macSystemsetupGetter(99), macSystemsetupGetter(-1)} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("Network Time: on\n")})
		_, err := macSystemsetupQuery(context.Background(), rt, unknown)
		if err == nil || err.Error() != "unknown systemsetup getter" {
			t.Fatalf("unknown enum %d err = %v, want unknown systemsetup getter", unknown, err)
		}
		if errors.Is(err, ErrMacSystemsetupQuery) || errors.Is(err, ErrMacNetworkTimeStateInvalid) {
			t.Fatalf("unknown enum %d err = %v, want the distinct unknown-getter error", unknown, err)
		}
		if len(runner.cmds) != 0 {
			t.Fatalf("unknown enum %d dispatched %d commands, want 0", unknown, len(runner.cmds))
		}
	}

	// The four closed values map to exactly their single fixed flags.
	flags := map[macSystemsetupGetter]string{}
	for _, tc := range []struct {
		getter macSystemsetupGetter
		flag   string
	}{
		{macSystemsetupGetDate, "-getdate"},
		{macSystemsetupGetTime, "-gettime"},
		{macSystemsetupGetUsingNetworkTime, "-getusingnetworktime"},
		{macSystemsetupGetTimeServer, "-getnetworktimeserver"},
	} {
		flag, err := tc.getter.flag()
		if err != nil || flag != tc.flag {
			t.Fatalf("enum %d flag = %q, %v; want %q, nil", tc.getter, flag, err, tc.flag)
		}
		flags[tc.getter] = flag
	}

	// No closed value can express a setter or zone flag: the closed
	// answer set is exactly the four read-only getters.
	for _, forbidden := range []string{
		"-setdate", "-settime", "-settimezone",
		"-setusingnetworktime", "-setnetworktimeserver",
		"-gettimezone", "setusingnetworktime", "",
	} {
		for g, flag := range flags {
			if flag == forbidden {
				t.Fatalf("closed enum value %d maps to forbidden flag %q", g, flag)
			}
		}
	}
}

// MNT-12: registration selects the two network-time getters per GOOS
// through the unexported registerMacGettersForGOOS helper (the Darwin
// selector seam, exercised from any host): all four Mac getters on
// darwin only, with zero-field args prototypes matching the catalog's
// zero parameters, no superseded aliases, off-host dispatch rejected
// as unsupported, and the production Register surface at 10 names on
// darwin / 7 on linux (with the Linux get_zonecode) / 7 on windows
// (with the Windows timezone.list) / 5 elsewhere.
func TestMacNetworkTimeGettersRegistrationSelectsPerGOOS(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerMacGettersForGOOS(reg, "darwin"); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 4 {
		t.Fatalf("darwin helper registered %d functions, want 4", reg.Len())
	}
	for _, tc := range []struct {
		name string
		fn   runtime.ExecFunction
	}{
		{"timezone.get_using_network_time", macGetUsingNetworkTimeFunc{}},
		{"timezone.get_time_server", macGetTimeServerFunc{}},
	} {
		fn, ok := reg.Get(tc.name)
		if !ok {
			t.Fatalf("darwin helper did not register %s", tc.name)
		}
		if _, isState := fn.(macGetUsingNetworkTimeFunc); tc.name == "timezone.get_using_network_time" && !isState {
			t.Fatalf("%s registered %T", tc.name, fn)
		}
		if _, isServer := fn.(macGetTimeServerFunc); tc.name == "timezone.get_time_server" && !isServer {
			t.Fatalf("%s registered %T", tc.name, fn)
		}
		constrained, isConstrained := fn.(runtime.PlatformConstrained)
		if !isConstrained || !reflect.DeepEqual(constrained.Platforms(), []string{"darwin"}) {
			t.Fatalf("%s platforms = %v, want [darwin]", tc.name, constrained.Platforms())
		}
		if !runtime.SupportsPlatform(fn, "darwin") {
			t.Fatalf("%s must support darwin", tc.name)
		}
		for _, goos := range []string{"linux", "windows", "freebsd", "solaris", "aix"} {
			if runtime.SupportsPlatform(fn, goos) {
				t.Fatalf("%s must not support %s", tc.name, goos)
			}
		}
		// Zero-field args contract (catalog declares no parameters)
		// and no required gate to trip.
		argsType := reflect.TypeOf(tc.fn.Args())
		if argsType.Kind() != reflect.Struct || argsType.NumField() != 0 {
			t.Fatalf("%s args prototype = %s with %d fields, want a zero-field struct", tc.name, argsType, argsType.NumField())
		}
		if err := config.ValidateRequired(reflect.New(argsType).Interface()); err != nil {
			t.Fatalf("%s zero-field args failed the required gate: %v", tc.name, err)
		}
	}

	// The four getter prototypes are pairwise distinct concrete types.
	argTypes := []reflect.Type{
		reflect.TypeOf((macGetDateFunc{}).Args()),
		reflect.TypeOf((macGetTimeFunc{}).Args()),
		reflect.TypeOf((macGetUsingNetworkTimeFunc{}).Args()),
		reflect.TypeOf((macGetTimeServerFunc{}).Args()),
	}
	for i := range argTypes {
		for j := i + 1; j < len(argTypes); j++ {
			if argTypes[i] == argTypes[j] {
				t.Fatalf("args types %d and %d must be distinct", i, j)
			}
		}
	}

	// No duplicate getter entry can exist.
	if err := reg.Register(macGetUsingNetworkTimeFunc{}); err == nil {
		t.Fatal("registering get_using_network_time twice must fail as a duplicate")
	}
	if err := reg.Register(macGetTimeServerFunc{}); err == nil {
		t.Fatal("registering get_time_server twice must fail as a duplicate")
	}

	// Every non-darwin GOOS registers no getter at all.
	for _, goos := range []string{"linux", "windows", "freebsd", "openbsd", "netbsd", "solaris", "illumos", "aix", "plan9"} {
		other := runtime.NewExecRegistry()
		if err := registerMacGettersForGOOS(other, goos); err != nil {
			t.Fatal(err)
		}
		if other.Len() != 0 {
			t.Fatalf("helper registered %d functions for %s, want 0", other.Len(), goos)
		}
		if _, ok := other.Get("timezone.get_using_network_time"); ok {
			t.Fatalf("helper registered get_using_network_time for %s", goos)
		}
		if _, ok := other.Get("timezone.get_time_server"); ok {
			t.Fatalf("helper registered get_time_server for %s", goos)
		}
	}

	// Production Register: the surface is 10 names on darwin, 7 on
	// linux (base 5 + zone_compare + get_zonecode), 7 on windows (base
	// 5 + zone_compare + the Windows timezone.list), 5 elsewhere; the
	// network-time getters are visible exactly on darwin; no
	// superseded alias is ever registered; the raw alias lookup fails
	// on every host.
	prod := runtime.NewExecRegistry()
	if err := Register(prod); err != nil {
		t.Fatal(err)
	}
	goos := runtime.CurrentGOOS()
	wantLen := 5
	switch goos {
	case "darwin":
		wantLen = 10
	case "linux":
		wantLen = 7
	case "windows":
		wantLen = 7
	}
	if prod.Len() != wantLen {
		t.Fatalf("production registration holds %d functions on %s, want %d", prod.Len(), goos, wantLen)
	}
	visible := 0
	for _, name := range prod.Names() {
		if name == "timezone.get_using_network_time" || name == "timezone.get_time_server" {
			visible++
		}
		if strings.HasPrefix(name, "timezone.get_using_network_time_") || strings.HasPrefix(name, "timezone.get_time_server_") {
			t.Fatalf("superseded alias %q registered on %s", name, goos)
		}
	}
	if goos == "darwin" && visible != 2 {
		t.Fatalf("network-time getters visible %d times on darwin, want 2", visible)
	}
	if goos != "darwin" && visible != 0 {
		t.Fatalf("network-time getters visible %d times on %s, want 0", visible, goos)
	}
	for _, alias := range []string{"timezone.get_using_network_time_", "timezone.get_time_server_"} {
		if _, ok := prod.Get(alias); ok {
			t.Fatalf("raw alias %q registered on %s", alias, goos)
		}
	}

	// Off-host dispatch: the darwin registration surfaced through a
	// non-darwin host is invisible and rejected as unsupported
	// (ResolveArgs and Call); on darwin itself the raw entry exists.
	if goos != "darwin" {
		darwinReg := runtime.NewExecRegistry()
		if err := registerMacGettersForGOOS(darwinReg, "darwin"); err != nil {
			t.Fatal(err)
		}
		for _, name := range darwinReg.Names() {
			if name == "timezone.get_using_network_time" || name == "timezone.get_time_server" {
				t.Fatalf("Names exposed %s for darwin registration on host %s", name, goos)
			}
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &macZoneRunner{}}
		var unsupported *runtime.UnsupportedError
		for _, name := range []string{"timezone.get_using_network_time", "timezone.get_time_server"} {
			if _, err := darwinReg.ResolveArgs(rt, name); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
				t.Fatalf("ResolveArgs %s on %s = %v, want unsupported function", name, goos, err)
			}
			if _, err := darwinReg.Call(context.Background(), rt, name, &macGetUsingNetworkTimeArgs{}); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
				t.Fatalf("Call %s on %s = %v, want unsupported function", name, goos, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Linux get_zonecode (PTD-EXEC-1631): LGZ-01..09 pin the pinned
// timezone.py get_zonecode contract hermetically. Every test uses the
// fake macZoneRunner only — never process.NewRunner, never the real
// date binary, never a host filesystem or host timezone — and the
// suite makes no live-cli claim. Upstream ships no get_zonecode unit
// test (GZC-05): the shapes below are transcribed from the pinned
// source get_zonecode → cmd.run(["date", "+%Z"], python_shell=False),
// whose stdout-only Python str.rstrip the port reuses; they are
// source-derived synthetic fixtures, not ported Salt tests.

// wantZonecodeCommand is the fixed, complete date invocation for the
// Linux generic get_zonecode: the executable name "date" resolved by
// the Runner through the parent PATH (user-authorized, caller-owned
// trust), exactly one argv flag, no shell, working directory "/", a
// locale-plus-optional-TZ child environment, 30s wall clock, and
// equal 64 KiB capture ceilings per stream, and nothing else.
func wantZonecodeCommand(env []string) process.Command {
	return process.Command{
		Name:           "date",
		Args:           []string{"+%Z"},
		Dir:            "/",
		Env:            env,
		Timeout:        30 * time.Second,
		MaxStdoutBytes: 64 << 10,
		MaxStderrBytes: 64 << 10,
	}
}

// requireZonecodeError pins the single fixed execution-category error
// for get_zonecode: the errors.Is sentinel, the exact value-free text,
// and no markers of the command, environment, output, streams, or exit
// status. (The fixed text itself contains the word "zonecode", so the
// raw-command marker is the executable/flag text instead.)
func requireZonecodeError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrZonecodeQuery) {
		t.Fatalf("err = %v, want ErrZonecodeQuery", err)
	}
	if err == nil || err.Error() != "timezone zonecode query failed" {
		t.Fatalf("err text = %v, want timezone zonecode query failed", err)
	}
	for _, marker := range []string{
		"date", "+%Z", "Zonecode", "Sentinel", "PST", "CEST", "+03",
		"failing", "warning", "13", "exit", "stdout", "stderr",
		"timed out", "canceled", "no such file", "TZ",
	} {
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Fatalf("err text %q leaks marker %q", err.Error(), marker)
		}
	}
}

// zonecodeUnsetTZ removes TZ for the current test and restores the
// prior value afterwards; the unset-versus-empty distinction of
// os.LookupEnv is exactly what LGZ-01 pins, so t.Setenv alone (which
// cannot unset) is not enough. Never call from parallel tests.
func zonecodeUnsetTZ(t *testing.T) {
	t.Helper()
	old, had := os.LookupEnv("TZ")
	if err := os.Unsetenv("TZ"); err != nil {
		t.Fatal(err)
	}
	if had {
		t.Cleanup(func() {
			if err := os.Setenv("TZ", old); err != nil {
				t.Fatal(err)
			}
		})
	} else {
		t.Cleanup(func() {
			if err := os.Unsetenv("TZ"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// LGZ-01: Execute dispatches exactly one shell-free `date +%Z` with
// the fixed argv, working directory, timeout, and capture ceilings —
// deep-equal over the whole process.Command, with the live context
// forwarded to the Runner — and the child environment is exactly
// LC_ALL=C plus the caller's TZ only when it is set: unset TZ yields
// LC_ALL=C alone, a set-but-empty TZ forwards the empty `TZ=` value,
// and a set TZ forwards it verbatim.
func TestZonecodeDispatchesFixedCommand(t *testing.T) {
	t.Setenv("TZ", "Zonecode/Sentinel")
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")})
	value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != "PST" {
		t.Fatalf("set TZ get_zonecode = %v, %v; want PST, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("set TZ dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	want := wantZonecodeCommand([]string{"LC_ALL=C", "TZ=Zonecode/Sentinel"})
	if !reflect.DeepEqual(runner.cmds[0], want) {
		t.Fatalf("set TZ command = %#v, want %#v", runner.cmds[0], want)
	}
	if len(runner.ctxErr) != 1 || runner.ctxErr[0] != nil {
		t.Fatalf("set TZ runner context errors = %v, want one nil (live context forwarded)", runner.ctxErr)
	}

	zonecodeUnsetTZ(t)
	rt, runner = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != "PST" {
		t.Fatalf("unset TZ get_zonecode = %v, %v; want PST, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("unset TZ dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if want := wantZonecodeCommand([]string{"LC_ALL=C"}); !reflect.DeepEqual(runner.cmds[0], want) {
		t.Fatalf("unset TZ command = %#v, want %#v", runner.cmds[0], want)
	}

	t.Setenv("TZ", "")
	rt, runner = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != "PST" {
		t.Fatalf("set-empty TZ get_zonecode = %v, %v; want PST, nil", value, err)
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("set-empty TZ dispatched %d commands, want exactly 1", len(runner.cmds))
	}
	if want := wantZonecodeCommand([]string{"LC_ALL=C", "TZ="}); !reflect.DeepEqual(runner.cmds[0], want) {
		t.Fatalf("set-empty TZ command = %#v, want %#v", runner.cmds[0], want)
	}
}

// LGZ-02: the get_zonecode contract never touches the filesystem on
// success or failure — every path stays inside the hermetic MemoryFS
// with zero recorded operations.
func TestZonecodeNeverTouchesFilesystem(t *testing.T) {
	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("UTC\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}
	if _, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{}); err != nil {
		t.Fatal(err)
	}
	runner.reply = process.CommandResult{ExitCode: 1}
	if _, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{}); !errors.Is(err, ErrZonecodeQuery) {
		t.Fatalf("nonzero err = %v, want ErrZonecodeQuery", err)
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("filesystem touched: %v", fsys.calls)
	}
}

// LGZ-03: stdout is trailing-rstripped with Python str.rstrip
// semantics — unicode.IsSpace plus U+001C..U+001F — with no leading
// trim, exactly like Salt's cmd.run output handling; interior
// whitespace survives.
func TestZonecodePythonTrailingRStrip(t *testing.T) {
	for _, tail := range []string{
		"\n", "\r\n", "\t", " \t\r\n", "\v\f",
		"\u00a0", "\u0085", "\u2028", "\u3000",
		"\u001c", "\u001d", "\u001e", "\u001f",
		" \u001c\u001d\u001e\u001f\u00a0\u2028\t\r\n",
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("PST" + tail)})
		value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
		if err != nil || value != "PST" {
			t.Fatalf("trailing %q: get_zonecode = %v, %v; want PST, nil", tail, value, err)
		}
	}

	// Leading whitespace is never stripped.
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(" PST\n")})
	value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != " PST" {
		t.Fatalf("leading-space get_zonecode = %v, %v; want \" PST\", nil", value, err)
	}

	// Interior whitespace survives untouched.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("P ST\n")})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != "P ST" {
		t.Fatalf("interior-space get_zonecode = %v, %v; want \"P ST\", nil", value, err)
	}
}

// LGZ-04: successful answers pass through with no normalization or
// validation of the abbreviation (GZC-04): alphabetic, numeric offset
// forms, exotic abbreviation text, the empty value, and at-cap output
// all return exactly their rstripped stdout.
func TestZonecodeValueShapesNeverNormalized(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
		want   string
	}{
		{"alphabetic", "UTC\n", "UTC"},
		{"no trailing newline", "PST", "PST"},
		{"numeric positive offset", "+03\n", "+03"},
		{"numeric negative offset", "-05\n", "-05"},
		{"exotic abbreviation text", "<+0330>-3\n", "<+0330>-3"},
		{"no content gate", "not supported\n", "not supported"},
		{"empty output", "", ""},
		{"whitespace-only output", " \r\n\t\u001f", ""},
	} {
		rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(tc.stdout)})
		value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
		if err != nil || value != tc.want {
			t.Fatalf("%s: get_zonecode = %v, %v; want %q, nil", tc.name, value, err, tc.want)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("%s dispatched %d commands, want 1", tc.name, len(runner.cmds))
		}
	}

	// At exactly the 64 KiB cap without a truncation flag, the value
	// still parses (only the trailing newline rstrips).
	atCap := append(bytes.Repeat([]byte("x"), (64<<10)-1), '\n')
	if len(atCap) != 64<<10 {
		t.Fatalf("at-cap fixture is %d bytes, want exactly the cap", len(atCap))
	}
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: atCap})
	value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != string(bytes.Repeat([]byte("x"), (64<<10)-1)) {
		t.Fatalf("at-cap get_zonecode = %d bytes, %v; want %d bytes, nil", len(value.(string)), err, (64<<10)-1)
	}
}

// LGZ-05: nonzero exit, Runner start errors, context cancellation and
// timeout, either stream's truncation flag, and over-cap streams all
// map to the one fixed ErrZonecodeQuery with a nil value and no
// wrapped cause — the documented fail-closed divergence from Salt's
// cmd.run, which returns stdout even on nonzero and merges stderr.
func TestZonecodeFailureCategoriesMapToFixedError(t *testing.T) {
	for _, reply := range []process.CommandResult{
		{ExitCode: 13, Stdout: []byte("PST\n"), Stderr: []byte("date: failing\n")},
		{ExitCode: -1, Err: fmt.Errorf(`exec: "date": executable file not found in $PATH`)},
		{ExitCode: -1, Err: fmt.Errorf("date query canceled: %w", context.Canceled)},
		{ExitCode: -1, Err: fmt.Errorf("date query timed out after 30s: %w", context.DeadlineExceeded)},
		{ExitCode: 0, Stdout: []byte("PST\n"), StdoutTruncated: true},
		{ExitCode: 0, Stdout: []byte("PST\n"), Stderr: []byte("x"), StderrTruncated: true},
		{ExitCode: 0, Stdout: bytes.Repeat([]byte("x"), (64<<10)+1)},
		{ExitCode: 0, Stdout: []byte("PST\n"), Stderr: bytes.Repeat([]byte("x"), (64<<10)+1)},
	} {
		rt, runner := newMacZoneRuntime(reply)
		value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
		requireZonecodeError(t, err)
		if value != nil {
			t.Fatalf("failure value = %#v, want nil", value)
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Unwrap(err) != nil {
			t.Fatalf("zonecode error leaked its cause: %v", err)
		}
		if len(runner.cmds) != 1 {
			t.Fatalf("failure dispatched %d commands, want exactly 1 (never retried)", len(runner.cmds))
		}
	}

	// The caller's context reaches the Runner unchanged.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	if _, err := (getZonecodeFunc{}).Execute(ctx, rt, &getZonecodeArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.ctxErr) != 1 || !errors.Is(runner.ctxErr[0], context.Canceled) {
		t.Fatalf("runner context errors = %v, want one context.Canceled", runner.ctxErr)
	}
}

// GZC-10: exact per-stream 64 KiB cap boundaries independent of the
// truncation flags — a fake Runner can report over-cap lengths without
// ever setting StdoutTruncated/StderrTruncated, so the length checks
// alone must fail closed. stdout exactly 64 KiB with exit 0 and no
// flags returns the full string; stdout 64 KiB + 1 returns a nil value
// and exactly the fixed sentinel; stderr exactly 64 KiB with good
// stdout leaves the answer untouched; stderr 64 KiB + 1 fails the same
// way. No partial output, raw fixture material, or wrapped cause may
// travel in any error; the fixtures are pure in-memory 64 KiB strings
// with zero host I/O.
func TestZonecodeStreamCapsExactBoundaries(t *testing.T) {
	atCap := strings.Repeat("x", 64<<10)
	overCap := strings.Repeat("x", (64<<10)+1)
	if len(atCap) != 64<<10 || len(overCap) != (64<<10)+1 {
		t.Fatalf("cap fixtures are %d/%d bytes, want 65536/65537", len(atCap), len(overCap))
	}

	// stdout exactly 64 KiB, exit 0, no truncation flags: the full
	// string returns unchanged (no trailing whitespace to rstrip).
	rt, runner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(atCap)})
	value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	got, ok := value.(string)
	if err != nil || !ok || got != atCap || len(got) != 64<<10 {
		t.Fatalf("at-cap stdout = (%T) %#v, %v; want the full %d-byte string, nil", value, value, err, len(atCap))
	}
	if len(runner.cmds) != 1 {
		t.Fatalf("at-cap stdout dispatched %d commands, want 1", len(runner.cmds))
	}

	// stdout 64 KiB + 1: nil value and exactly the fixed sentinel.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(overCap)})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	requireZonecodeQueryOnly(t, err, "xxxxx")
	if value != nil {
		t.Fatalf("over-cap stdout value = %#v, want nil", value)
	}

	// stderr exactly 64 KiB with good stdout: stderr stays dropped and
	// the stdout answer returns.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("CEST\n"), Stderr: []byte(atCap)})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	if err != nil || value != "CEST" {
		t.Fatalf("at-cap stderr = %#v, %v; want CEST, nil", value, err)
	}

	// stderr 64 KiB + 1 with good stdout: nil value and exactly the
	// fixed sentinel; neither the dropped stderr nor the stdout answer
	// may leak into the error.
	rt, _ = newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("CEST\n"), Stderr: []byte(overCap)})
	value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	requireZonecodeQueryOnly(t, err, "xxxxx", "CEST")
	if value != nil {
		t.Fatalf("over-cap stderr value = %#v, want nil", value)
	}
}

// requireZonecodeQueryOnly pins an over-cap failure to exactly the
// fixed sentinel: errors.Is on ErrZonecodeQuery only (never a foreign
// sentinel), the byte-exact value-free text containing no partial
// output or raw fixture material, and no wrapped cause.
func requireZonecodeQueryOnly(t *testing.T, err error, markers ...string) {
	t.Helper()
	requireZonecodeError(t, err)
	for _, other := range []error{ErrCannotDetermineZone, ErrUnknownUnsafeZone, ErrInvalidWindowsZone, ErrMacSystemsetupQuery, ErrMacNetworkTimeStateInvalid} {
		if errors.Is(err, other) {
			t.Fatalf("over-cap err %v matches foreign sentinel %v", err, other)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("over-cap err unwraps to %v, want no cause", errors.Unwrap(err))
	}
	for _, marker := range markers {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("err text %q leaks raw output or fixture material %q", err.Error(), marker)
		}
	}
}

// LGZ-06: the zonecode sentinel is its own fixed category — errors.Is
// matches only ErrZonecodeQuery, never any other module sentinel,
// with no Unwrap chain.
func TestZonecodeErrorSentinelIsDistinct(t *testing.T) {
	rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 1})
	_, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
	requireZonecodeError(t, err)
	for _, other := range []error{
		ErrCannotDetermineZone, ErrUnknownUnsafeZone, ErrInvalidWindowsZone,
		ErrMacSystemsetupQuery, ErrMacNetworkTimeStateInvalid,
		errMacZoneInvalidArgs, errMacGetterInvalidArgs, errZonecodeInvalidArgs,
	} {
		if errors.Is(err, other) {
			t.Fatalf("zonecode err %v matches foreign sentinel %v", err, other)
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("zonecode err unwraps to %v, want no cause", errors.Unwrap(err))
	}
	for _, other := range []error{ErrCannotDetermineZone, ErrInvalidWindowsZone, ErrMacSystemsetupQuery} {
		if errors.Is(other, ErrZonecodeQuery) || errors.Is(ErrZonecodeQuery, other) {
			t.Fatalf("ErrZonecodeQuery cross-matches %v", other)
		}
	}
	if ErrZonecodeQuery.Error() != "timezone zonecode query failed" {
		t.Fatalf("sentinel text = %q", ErrZonecodeQuery.Error())
	}
}

// LGZ-07: stderr is dropped on success (documented divergence from
// Salt's cmd.run, which merges stderr into the returned stream): the
// value comes from stdout alone and no stderr content — warning text,
// the mac-only "not supported" phrase, or arbitrary bytes — fails the
// call or leaks into the answer.
func TestZonecodeStderrDroppedOnSuccess(t *testing.T) {
	for _, stderr := range []string{
		"",
		"warning: clock skew\n",
		"this operation is not supported\n",
		"secret-zonecode-stderr",
	} {
		rt, _ := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("CEST\n"), Stderr: []byte(stderr)})
		value, err := (getZonecodeFunc{}).Execute(context.Background(), rt, &getZonecodeArgs{})
		if err != nil || value != "CEST" {
			t.Fatalf("stderr %q: get_zonecode = %v, %v; want CEST, nil", stderr, value, err)
		}
	}
}

// LGZ-08: the Execute boundary fails safe for direct callers that
// bypass the registry gate: wrong argument types (including other
// functions' args), typed-nil pointers, nil args, a nil Runtime, and a
// nil Runner all return fixed value-free errors before any Runner
// dispatch or filesystem access — never a panic — while valid
// zero-field args dispatch exactly once.
func TestZonecodeExecuteFailsSafeOnMalformedInvocation(t *testing.T) {
	exec := func(label string, rt *runtime.Runtime, args any, verify func(t *testing.T, err error)) {
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
			value, err = (getZonecodeFunc{}).Execute(context.Background(), rt, args)
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

	fsys := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	runner := &macZoneRunner{reply: process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: fsys, Runner: runner}

	var malformedErrs []error
	secretZone := "Secret/Zonecode-Marker"
	for _, tc := range []struct {
		label string
		args  any
	}{
		{"wrong-type string", "Secret/Zonecode-Marker"},
		{"wrong-type linux zone_compare args", &zoneCompareArgs{TimeZone: secretZone}},
		{"wrong-type mac getter args", &macGetDateArgs{}},
		{"typed-nil zonecode args", (*getZonecodeArgs)(nil)},
		{"nil args", nil},
	} {
		args := tc.args
		exec(tc.label, rt, args, func(t *testing.T, err error) {
			fixedValueFree("Secret", "Marker", "Zone", "PST")(t, err)
			malformedErrs = append(malformedErrs, err)
		})
	}
	for i := 1; i < len(malformedErrs); i++ {
		if malformedErrs[i].Error() != malformedErrs[0].Error() {
			t.Fatalf("malformed-args error %q differs from %q, want one fixed error", malformedErrs[i].Error(), malformedErrs[0].Error())
		}
	}
	if malformedErrs[0].Error() != "invalid timezone zonecode arguments" {
		t.Fatalf("malformed-args error = %q, want invalid timezone zonecode arguments", malformedErrs[0].Error())
	}

	// No malformed invocation may dispatch or touch the filesystem.
	if len(runner.cmds) != 0 {
		t.Fatalf("malformed invocations dispatched %d commands, want 0", len(runner.cmds))
	}
	if len(fsys.calls) != 0 {
		t.Fatalf("malformed invocations touched the filesystem: %v", fsys.calls)
	}

	// Unavailable runtime: nil Runtime and nil Runner map to the fixed
	// execution-category error before any dispatch.
	exec("nil Runtime", nil, &getZonecodeArgs{}, func(t *testing.T, err error) {
		fixedValueFree("PST")(t, err)
		requireZonecodeError(t, err)
	})
	nilRunnerFS := &zoneRecordingFS{FileSystem: runtime.NewMemoryFS()}
	nilRunnerRT := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: nilRunnerFS, Runner: nil}
	exec("nil Runner", nilRunnerRT, &getZonecodeArgs{}, func(t *testing.T, err error) {
		fixedValueFree("PST")(t, err)
		requireZonecodeError(t, err)
	})
	if len(nilRunnerFS.calls) != 0 {
		t.Fatalf("nil Runner touched the filesystem: %v", nilRunnerFS.calls)
	}

	// Preservation: valid zero-field args dispatch exactly once.
	validRT, validRunner := newMacZoneRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("PST\n")})
	value, err := (getZonecodeFunc{}).Execute(context.Background(), validRT, &getZonecodeArgs{})
	if err != nil || value != "PST" {
		t.Fatalf("valid get_zonecode = %v, %v; want PST, nil", value, err)
	}
	if len(validRunner.cmds) != 1 {
		t.Fatalf("valid get_zonecode dispatched %d commands, want 1", len(validRunner.cmds))
	}
}

// LGZ-09: registration selects the Linux getter per GOOS through the
// unexported registerLinuxGettersForGOOS helper (the Linux selector
// seam, exercised from any host): timezone.get_zonecode on linux only,
// with a zero-field args prototype matching the catalog's zero
// parameters, no superseded alias, off-host dispatch rejected as
// unsupported, and the production Register surface at 7 names on
// linux / 10 on darwin / 7 on windows (with the Windows
// timezone.list) / 5 elsewhere.
func TestZonecodeRegistrationSelectsPerGOOS(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerLinuxGettersForGOOS(reg, "linux"); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("linux helper registered %d functions, want 1", reg.Len())
	}
	fn, ok := reg.Get("timezone.get_zonecode")
	if !ok {
		t.Fatal("linux helper did not register timezone.get_zonecode")
	}
	if _, isZonecode := fn.(getZonecodeFunc); !isZonecode {
		t.Fatalf("timezone.get_zonecode registered %T", fn)
	}
	constrained, isConstrained := fn.(runtime.PlatformConstrained)
	if !isConstrained || !reflect.DeepEqual(constrained.Platforms(), []string{"linux"}) {
		t.Fatalf("timezone.get_zonecode platforms = %v, want [linux]", constrained.Platforms())
	}
	if !runtime.SupportsPlatform(fn, "linux") {
		t.Fatal("timezone.get_zonecode must support linux")
	}
	for _, goos := range []string{"darwin", "windows", "freebsd", "solaris", "aix"} {
		if runtime.SupportsPlatform(fn, goos) {
			t.Fatalf("timezone.get_zonecode must not support %s", goos)
		}
	}
	// Zero-field args contract (catalog declares no parameters) and no
	// required gate to trip; the prototype stays distinct from the
	// legacy zero-field get_zone prototype.
	argsType := reflect.TypeOf((getZonecodeFunc{}).Args())
	if argsType.Kind() != reflect.Struct || argsType.NumField() != 0 {
		t.Fatalf("timezone.get_zonecode args prototype = %s with %d fields, want a zero-field struct", argsType, argsType.NumField())
	}
	if err := config.ValidateRequired(reflect.New(argsType).Interface()); err != nil {
		t.Fatalf("timezone.get_zonecode zero-field args failed the required gate: %v", err)
	}
	if argsType == reflect.TypeOf((getZoneFunc{}).Args()) {
		t.Fatal("get_zonecode and get_zone must declare distinct args types")
	}
	// No duplicate entry can exist.
	if err := reg.Register(getZonecodeFunc{}); err == nil {
		t.Fatal("registering get_zonecode twice must fail as a duplicate")
	}

	// Every non-linux GOOS registers nothing at all.
	for _, goos := range []string{"darwin", "windows", "freebsd", "openbsd", "netbsd", "solaris", "illumos", "aix", "plan9"} {
		other := runtime.NewExecRegistry()
		if err := registerLinuxGettersForGOOS(other, goos); err != nil {
			t.Fatal(err)
		}
		if other.Len() != 0 {
			t.Fatalf("helper registered %d functions for %s, want 0", other.Len(), goos)
		}
		if _, ok := other.Get("timezone.get_zonecode"); ok {
			t.Fatalf("helper registered get_zonecode for %s", goos)
		}
	}

	// Production Register: the surface is 7 names on linux, 10 on
	// darwin, 7 on windows (base 5 + zone_compare + the Windows
	// timezone.list), 5 elsewhere; get_zonecode is visible exactly on
	// linux; no superseded alias is ever registered; the raw alias
	// lookup fails on every host.
	prod := runtime.NewExecRegistry()
	if err := Register(prod); err != nil {
		t.Fatal(err)
	}
	goos := runtime.CurrentGOOS()
	wantLen := 5
	switch goos {
	case "linux":
		wantLen = 7
	case "darwin":
		wantLen = 10
	case "windows":
		wantLen = 7
	}
	if prod.Len() != wantLen {
		t.Fatalf("production registration holds %d functions on %s, want %d", prod.Len(), goos, wantLen)
	}
	visible := 0
	for _, name := range prod.Names() {
		if name == "timezone.get_zonecode" {
			visible++
		}
		if strings.HasPrefix(name, "timezone.get_zonecode_") {
			t.Fatalf("superseded alias %q registered on %s", name, goos)
		}
	}
	if goos == "linux" && visible != 1 {
		t.Fatalf("get_zonecode visible %d times on linux, want 1", visible)
	}
	if goos != "linux" && visible != 0 {
		t.Fatalf("get_zonecode visible %d times on %s, want 0", visible, goos)
	}
	if _, ok := prod.Get("timezone.get_zonecode_"); ok {
		t.Fatalf("raw alias timezone.get_zonecode_ registered on %s", goos)
	}

	// Off-host dispatch: the linux registration surfaced through a
	// non-linux host is invisible and rejected as unsupported
	// (ResolveArgs and Call); on linux itself the raw entry exists.
	if goos != "linux" {
		linuxReg := runtime.NewExecRegistry()
		if err := registerLinuxGettersForGOOS(linuxReg, "linux"); err != nil {
			t.Fatal(err)
		}
		for _, name := range linuxReg.Names() {
			if name == "timezone.get_zonecode" {
				t.Fatalf("Names exposed %s for linux registration on host %s", name, goos)
			}
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: &macZoneRunner{}}
		var unsupported *runtime.UnsupportedError
		if _, err := linuxReg.ResolveArgs(rt, "timezone.get_zonecode"); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
			t.Fatalf("ResolveArgs timezone.get_zonecode on %s = %v, want unsupported function", goos, err)
		}
		if _, err := linuxReg.Call(context.Background(), rt, "timezone.get_zonecode", &getZonecodeArgs{}); !errors.As(err, &unsupported) || unsupported.Kind != "function" {
			t.Fatalf("Call timezone.get_zonecode on %s = %v, want unsupported function", goos, err)
		}
	}
}
