package pkg

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperNoCallRunner struct{ calls int }

func (r *zypperNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	panic("zypper pure function invoked Runner")
}

type zypperNoCallFS struct{ calls int }

func (f *zypperNoCallFS) fail()                                       { f.calls++; panic("zypper pure function invoked FS") }
func (f *zypperNoCallFS) Stat(string) (fs.FileInfo, error)            { f.fail(); return nil, nil }
func (f *zypperNoCallFS) Lstat(string) (fs.FileInfo, error)           { f.fail(); return nil, nil }
func (f *zypperNoCallFS) ReadFile(string) ([]byte, error)             { f.fail(); return nil, nil }
func (f *zypperNoCallFS) WriteFile(string, []byte, fs.FileMode) error { f.fail(); return nil }
func (f *zypperNoCallFS) MkdirAll(string, fs.FileMode) error          { f.fail(); return nil }
func (f *zypperNoCallFS) MkdirTemp(string, string) (string, error)    { f.fail(); return "", nil }
func (f *zypperNoCallFS) Remove(string) error                         { f.fail(); return nil }
func (f *zypperNoCallFS) RemoveAll(string) error                      { f.fail(); return nil }
func (f *zypperNoCallFS) Rename(string, string) error                 { f.fail(); return nil }
func (f *zypperNoCallFS) Symlink(string, string) error                { f.fail(); return nil }
func (f *zypperNoCallFS) Link(string, string) error                   { f.fail(); return nil }
func (f *zypperNoCallFS) Glob(string) ([]string, error)               { f.fail(); return nil, nil }
func (f *zypperNoCallFS) Readlink(string) (string, error)             { f.fail(); return "", nil }
func (f *zypperNoCallFS) ReadDir(string) ([]fs.DirEntry, error)       { f.fail(); return nil, nil }
func (f *zypperNoCallFS) Chmod(string, fs.FileMode) error             { f.fail(); return nil }
func (f *zypperNoCallFS) Chown(string, int, int) error                { f.fail(); return nil }
func (f *zypperNoCallFS) Lchown(string, int, int) error               { f.fail(); return nil }

func zypperPureRuntime(osarch string) *runtime.Runtime {
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{CPU: &facts.CPUFacts{Arch: osarch}}),
		Runner: &zypperNoCallRunner{},
		FS:     &zypperNoCallFS{},
	}
}

func assertZypperPureNoSideEffects(t *testing.T, rt *runtime.Runtime) {
	t.Helper()
	if got := rt.Runner.(*zypperNoCallRunner).calls; got != 0 {
		t.Fatalf("Runner calls=%d", got)
	}
	if got := rt.FS.(*zypperNoCallFS).calls; got != 0 {
		t.Fatalf("FS calls=%d", got)
	}
}

func TestZypperNormalizeAndParseArchSourceVectors(t *testing.T) {
	provider := &commandProvider{spec: zypperSpec}
	for _, tc := range []struct {
		name, osarch, want string
	}{
		{"pkg.x86_64", "amd64", "pkg"},
		{"pkg.x86_64", "x86_64", "pkg"},
		{"pkg.x86_64_v2", "x86_64", "pkg.x86_64_v2"},
		{"pkg.x86_64", "x86_64_v2", "pkg.x86_64"},
		{"pkg.i686", "x86_64", "pkg.i686"},
		{"pkg.i686", "386", "pkg"},
		{"pkg.i386", "386", "pkg"},
		{"pkg.i686", "i686", "pkg"},
		{"pkg.armv7l", "armv7hl", "pkg"},
		{"pkg.armv7l", "arm", "pkg"},
		{"pkg.armv7hl", "arm", "pkg"},
		{"pkg.noarch", "x86_64", "pkg"},
		{"pkg.ppc64", "x86_64", "pkg.ppc64"},
		{"pkg.ppc64", "ppc64", "pkg"},
		{"pkg.mips64", "mips64", "pkg.mips64"},
		{"pkg.sparcv9", "sparcv9", "pkg.sparcv9"},
		{"pkg.part.x86_64", "x86_64", "pkg.part"},
		{"x86_64", "x86_64", ""},
	} {
		t.Run(tc.name+"/"+tc.osarch, func(t *testing.T) {
			rt := zypperPureRuntime(tc.osarch)
			got, err := provider.Zypper(context.Background(), rt, "normalize_name", map[string]any{"name": tc.name})
			if err != nil || got != tc.want {
				t.Fatalf("got=%#v err=%v want=%q", got, err, tc.want)
			}
			assertZypperPureNoSideEffects(t, rt)
		})
	}

	for _, tc := range []struct {
		name string
		want map[string]any
	}{
		{"pkg.x86_64", map[string]any{"name": "pkg", "arch": "x86_64"}},
		{"pkg.i686", map[string]any{"name": "pkg", "arch": "i686"}},
		{"pkg.noarch", map[string]any{"name": "pkg", "arch": "noarch"}},
		{"pkg.ppc64", map[string]any{"name": "pkg", "arch": "ppc64"}},
		{"pkg.mips64", map[string]any{"name": "pkg.mips64", "arch": nil}},
		{"pkg.part.x86_64", map[string]any{"name": "pkg.part", "arch": "x86_64"}},
		{"pkg", map[string]any{"name": "pkg", "arch": nil}},
	} {
		rt := zypperPureRuntime("x86_64")
		got, err := provider.Zypper(context.Background(), rt, "parse_arch", map[string]any{"name": tc.name})
		if err != nil || !equalZypperMaps(got, tc.want) {
			t.Fatalf("%q: got=%#v err=%v want=%#v", tc.name, got, err, tc.want)
		}
		assertZypperPureNoSideEffects(t, rt)
	}
}

func TestZypperRejectsUnsafeTokensWithoutSideEffects(t *testing.T) {
	provider := &commandProvider{spec: zypperSpec}
	for _, tc := range []struct {
		name, function, key, value, want string
	}{
		{"nul-name", "normalize_name", "name", "pkg.\x00secret", errInvalidZypperPackageName.Error()},
		{"control-name", "parse_arch", "name", "pkg.\nsecret", errInvalidZypperPackageName.Error()},
		{"unicode-control-name", "normalize_name", "name", "pkg.\u0085secret", errInvalidZypperPackageName.Error()},
		{"format-name", "parse_arch", "name", "pkg.\u200bsecret", errInvalidZypperPackageName.Error()},
		{"empty-name", "normalize_name", "name", "", errInvalidZypperPackageName.Error()},
		{"whitespace-version", "version_cmp", "ver1", "1.0\nsecret", errInvalidZypperPackageVersion.Error()},
		{"oversized-version", "version_cmp", "ver1", strings.Repeat("v", maxZypperTokenRunes+1), errInvalidZypperPackageVersion.Error()},
		{"oversized-epoch", "version_cmp", "ver1", strings.Repeat("9", maxZypperEpochRunes+1) + ":1", errInvalidZypperPackageVersion.Error()},
		{"oversized-unicode-epoch", "version_cmp", "ver1", strings.Repeat("١", maxZypperEpochRunes+1) + ":1", errInvalidZypperPackageVersion.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := zypperPureRuntime("x86_64")
			args := map[string]any{"name": "pkg"}
			if tc.function == "version_cmp" {
				args = map[string]any{"ver1": "1", "ver2": "1"}
			}
			args[tc.key] = tc.value
			got, err := provider.Zypper(context.Background(), rt, tc.function, args)
			if got != nil || err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "secret") {
				t.Fatalf("got=%#v err=%v want=%q", got, err, tc.want)
			}
			assertZypperPureNoSideEffects(t, rt)
		})
	}
}

func TestZypperAcceptsTokenAndEpochLimits(t *testing.T) {
	provider := &commandProvider{spec: zypperSpec}
	name := strings.Repeat("n", maxZypperTokenRunes)
	rt := zypperPureRuntime("x86_64")
	got, err := provider.Zypper(context.Background(), rt, "normalize_name", map[string]any{"name": name})
	if err != nil || got != name {
		t.Fatalf("name at limit got=%#v err=%v", got, err)
	}
	assertZypperPureNoSideEffects(t, rt)

	version := strings.Repeat("v", maxZypperTokenRunes)
	rt = zypperPureRuntime("x86_64")
	got, err = provider.Zypper(context.Background(), rt, "version_cmp", map[string]any{"ver1": version, "ver2": version})
	if err != nil || got != 0 {
		t.Fatalf("version at limit got=%#v err=%v", got, err)
	}
	assertZypperPureNoSideEffects(t, rt)

	epoch := strings.Repeat("9", maxZypperEpochRunes) + ":1"
	rt = zypperPureRuntime("x86_64")
	got, err = provider.Zypper(context.Background(), rt, "version_cmp", map[string]any{"ver1": epoch, "ver2": "0:1"})
	if err != nil || got != 1 {
		t.Fatalf("epoch at limit got=%#v err=%v", got, err)
	}
	assertZypperPureNoSideEffects(t, rt)
}

func equalZypperMaps(got any, want map[string]any) bool {
	actual, ok := got.(map[string]any)
	if !ok || len(actual) != len(want) {
		return false
	}
	for key, value := range want {
		if actual[key] != value {
			if actual[key] == nil && value == nil {
				continue
			}
			return false
		}
	}
	return true
}

func TestZypperVersionCmpSourceVectors(t *testing.T) {
	provider := &commandProvider{spec: zypperSpec}
	for _, tc := range []struct {
		name, left, right string
		ignore            bool
		want              int
	}{
		{"equal", "1.2-3", "1.2-3", false, 0},
		{"epoch", "1:1.0-1", "0:9.9-9", false, 1},
		{"valid underscore epoch", "1_0:1", "2:1", false, 1},
		{"valid underscore epoch equal", "1_0:1", "10:1", false, 0},
		{"signed underscore epoch", "+1_0:1", "10:1", false, 0},
		{"unicode underscore epoch", "١_٠:1", "10:1", false, 0},
		{"invalid repeated underscore epoch", "1__0:1", "1:1", false, -1},
		{"invalid leading underscore epoch", "_10:1", "1:1", false, -1},
		{"invalid trailing underscore epoch", "10_:1", "1:1", false, -1},
		{"ignore underscore epoch", "1_0:1", "2:1", true, 0},
		{"signed epoch", "-1:1.0", "0:1.0", false, -1},
		{"ignore epoch", "1:1.0-1", "0:1.0-1", true, 0},
		{"version", "1.10", "1.9", false, 1},
		{"release", "1.0-2", "1.0-1", false, 1},
		{"leading zeros", "1.01", "1.1", false, 0},
		{"numeric alpha", "1.0", "1.a", false, 1},
		{"punctuation", "1.0.1", "1_0_1", false, 0},
		{"tilde", "1.0~rc1", "1.0", false, -1},
		{"caret", "1.0", "1.0^git1", false, -1},
		{"missing release lower", "1.0", "1.0-99", false, 0},
		{"missing release upper", "1.0-99", "1.0", false, 0},
		{"both release present", "1.0-99", "1.0-100", false, -1},
		{"empty", "", "1.0", false, -1},
		{"invalid epoch", "wat:1.0", "1.0", false, 0},
		{"unicode alpha", "1.0α", "1.0β", false, -1},
		{"unicode digit", "1.٠", "1.2", false, 1},
		{"unicode punctuation", "1.0+α", "1.0_β", false, -1},
		{"unicode fraction", "1.½", "1.1", false, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := zypperPureRuntime("x86_64")
			got, err := provider.Zypper(context.Background(), rt, "version_cmp", map[string]any{
				"ver1": tc.left, "ver2": tc.right, "ignore_epoch": tc.ignore,
			})
			if err != nil || got != tc.want {
				t.Fatalf("got=%#v err=%v want=%d", got, err, tc.want)
			}
			assertZypperPureNoSideEffects(t, rt)
		})
	}
}

func TestZypperPureDispatchRejectsUnsupportedAndMalformedWithoutSideEffects(t *testing.T) {
	provider := &commandProvider{spec: zypperSpec}
	rt := zypperPureRuntime("x86_64")
	for _, args := range []map[string]any{
		{"name": 1}, {"name": "pkg", "extra": true},
		{"ver1": 1, "ver2": "1"}, {"ver1": "1", "ver2": nil}, {"ver1": "1", "ver2": "1", "ignore_epoch": "no"},
	} {
		if got, err := provider.Zypper(context.Background(), rt, "version_cmp", args); got != nil || err == nil {
			t.Fatalf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if got, err := provider.Zypper(context.Background(), rt, "install", nil); got != nil || err == nil {
		t.Fatalf("unsupported got=%#v err=%v", got, err)
	}
	if _, err := (&commandProvider{spec: yumSpec}).Zypper(context.Background(), rt, "version_cmp", map[string]any{"ver1": "1", "ver2": "2"}); !errors.Is(err, ErrUnsupportedZypper) {
		t.Fatalf("wrong provider error=%v", err)
	}
}
