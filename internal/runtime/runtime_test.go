package runtime

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/result"
)

type fakeExec struct {
	name string
}

type capableFakeExec struct{}

type providerAwareFakeExec struct{}

type matrixProviderAwareExec struct {
	prototype any
	err       error
	executed  *int
}

type resolveNoCallRunner struct{ calls int }

func (r *resolveNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{}
}

func (f matrixProviderAwareExec) Name() string         { return "pkg.matrix" }
func (f matrixProviderAwareExec) Args() any            { return struct{}{} }
func (f matrixProviderAwareExec) ProviderKind() string { return "pkg" }
func (f matrixProviderAwareExec) ArgsForProvider(provider string) (any, error) {
	if provider == "zypper" {
		return nil, &UnsupportedError{Kind: "provider", Name: provider}
	}
	return f.prototype, f.err
}
func (f matrixProviderAwareExec) Execute(context.Context, *Runtime, any) (any, error) {
	if f.executed != nil {
		*f.executed++
	}
	return nil, nil
}

func (providerAwareFakeExec) Name() string         { return "pkg.provider_aware" }
func (providerAwareFakeExec) Args() any            { return struct{ Legacy string }{} }
func (providerAwareFakeExec) ProviderKind() string { return "pkg" }
func (providerAwareFakeExec) ArgsForProvider(name string) (any, error) {
	if name == "yum" {
		return struct{ YumOnly string }{}, nil
	}
	return nil, &UnsupportedError{Kind: "provider", Name: name}
}
func (providerAwareFakeExec) Execute(context.Context, *Runtime, any) (any, error) { return nil, nil }

func TestExecRegistryResolveArgsProviderAware(t *testing.T) {
	reg := NewExecRegistry()
	if err := reg.Register(providerAwareFakeExec{}); err != nil {
		t.Fatal(err)
	}
	providers := NewProviderRegistry()
	if err := providers.Register("pkg", "yum", struct{}{}); err != nil {
		t.Fatal(err)
	}
	providers.SetSelector("pkg", func(*facts.Facts) (string, error) { return "yum", nil })
	rt := &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: providers}
	got, err := reg.ResolveArgs(rt, "pkg.provider_aware")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(struct{ YumOnly string }); !ok {
		t.Fatalf("prototype=%T", got)
	}
}

func TestExecRegistryResolveArgsProviderFailuresHaveNoSideEffects(t *testing.T) {
	type setup func() *Runtime
	selectorError := errors.New("selector failed")
	cases := []struct {
		name  string
		setup setup
		want  string
	}{
		{"nil runtime", func() *Runtime { return nil }, `unsupported provider "pkg"`},
		{"nil providers", func() *Runtime { return &Runtime{Facts: facts.ForTesting(facts.Overrides{})} }, `unsupported provider "pkg"`},
		{"nil facts", func() *Runtime { return &Runtime{Providers: NewProviderRegistry()} }, `unsupported provider "pkg"`},
		{"selector missing", func() *Runtime {
			p := NewProviderRegistry()
			_ = p.Register("pkg", "apt", struct{}{})
			_ = p.Register("pkg", "yum", struct{}{})
			return &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: p}
		}, `unsupported provider "pkg"`},
		{"selector error", func() *Runtime {
			p := NewProviderRegistry()
			_ = p.Register("pkg", "apt", struct{}{})
			p.SetSelector("pkg", func(*facts.Facts) (string, error) { return "", selectorError })
			return &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: p}
		}, `unsupported provider "pkg"`},
		{"unknown provider", func() *Runtime {
			p := NewProviderRegistry()
			p.SetSelector("pkg", func(*facts.Facts) (string, error) { return "missing", nil })
			_ = p.Register("pkg", "apt", struct{}{})
			return &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: p}
		}, `unsupported provider "pkg"`},
		{"inapplicable zypper provider", func() *Runtime {
			p := NewProviderRegistry()
			_ = p.Register("pkg", "zypper", struct{}{})
			p.SetSelector("pkg", func(*facts.Facts) (string, error) { return "zypper", nil })
			return &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: p}
		}, `unsupported provider "zypper"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			reg := NewExecRegistry()
			if err := reg.Register(matrixProviderAwareExec{prototype: struct{ Valid string }{}, executed: &calls}); err != nil {
				t.Fatal(err)
			}
			rt := tc.setup()
			runner := &resolveNoCallRunner{}
			var fsBefore int
			if rt != nil {
				rt.Runner = runner
				memory := NewMemoryFS()
				rt.FS = memory
				fsBefore = len(memory.nodes)
			}
			got, err := reg.ResolveArgs(rt, "pkg.matrix")
			if got != nil || err == nil || err.Error() != tc.want {
				t.Fatalf("prototype=%#v err=%v want=%q", got, err, tc.want)
			}
			if calls != 0 {
				t.Fatalf("execute calls=%d", calls)
			}
			if runner.calls != 0 {
				t.Fatalf("runner calls=%d", runner.calls)
			}
			if rt != nil {
				if memory, ok := rt.FS.(*MemoryFS); ok && len(memory.nodes) != fsBefore {
					t.Fatalf("filesystem changed: before=%d after=%d", fsBefore, len(memory.nodes))
				}
			}
		})
	}

	for _, tc := range []struct {
		name      string
		prototype any
		err       error
	}{
		{"unsupported prototype", "not a struct", nil},
		{"malformed provider-aware function", nil, errors.New("bad prototype")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			reg := NewExecRegistry()
			if err := reg.Register(matrixProviderAwareExec{prototype: tc.prototype, err: tc.err, executed: &calls}); err != nil {
				t.Fatal(err)
			}
			p := NewProviderRegistry()
			_ = p.Register("pkg", "yum", struct{}{})
			p.SetSelector("pkg", func(*facts.Facts) (string, error) { return "yum", nil })
			runner := &resolveNoCallRunner{}
			memory := NewMemoryFS()
			rt := &Runtime{Facts: facts.ForTesting(facts.Overrides{}), Providers: p, Runner: runner, FS: memory}
			fsBefore := len(memory.nodes)
			got, err := reg.ResolveArgs(rt, "pkg.matrix")
			if got != nil || err == nil {
				t.Fatalf("prototype=%#v err=%v", got, err)
			}
			var unsupported *UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Name != "yum" {
				t.Fatalf("error=%v", err)
			}
			if calls != 0 {
				t.Fatalf("execute calls=%d", calls)
			}
			if runner.calls != 0 || len(memory.nodes) != fsBefore {
				t.Fatalf("side effects: runner=%d fs=%d/%d", runner.calls, len(memory.nodes), fsBefore)
			}
		})
	}
}

func (capableFakeExec) Name() string                                        { return "pkg.apt_only" }
func (capableFakeExec) Args() any                                           { return struct{}{} }
func (capableFakeExec) Execute(context.Context, *Runtime, any) (any, error) { return nil, nil }
func (capableFakeExec) ProviderCapabilities() []string                      { return []string{"aptpkg"} }

func TestExecRegistryProviderCapabilities(t *testing.T) {
	reg := NewExecRegistry()
	if err := reg.Register(capableFakeExec{}); err != nil {
		t.Fatal(err)
	}
	if got := reg.ProviderCapabilities("pkg.apt_only"); len(got) != 1 || got[0] != "aptpkg" {
		t.Fatalf("capabilities = %#v", got)
	}
	got := reg.ProviderCapabilities("missing")
	if got != nil {
		t.Fatalf("missing capabilities = %#v", got)
	}
}

func TestReadFileBoundedValidationAndOSLimits(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys := NewOSFileSystem()
	data, err := ReadFileBounded(fsys, file, 4)
	if err != nil || string(data) != "1234" {
		t.Fatalf("exact read = %q, %v", data, err)
	}
	if _, err := ReadFileBounded(fsys, file, 3); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("over-limit error = %v", err)
	}
	if _, err := ReadFileBounded(fsys, dir, 4); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("directory error = %v", err)
	}
	for _, limit := range []int64{-1, MaxBoundedReadLimit + 1, int64(^uint64(0) >> 1)} {
		if _, err := ReadFileBounded(fsys, file, limit); !errors.Is(err, ErrInvalidReadLimit) {
			t.Fatalf("invalid limit %d: %v", limit, err)
		}
	}
}

func TestCommandWithInputBounded(t *testing.T) {
	argv := []string{"dpkg", "--set-selections"}
	for _, tc := range []struct {
		name, input string
		wantErr     bool
	}{
		{"under", "abc", false},
		{"exact", strings.Repeat("x", MaxCommandInputBytes), false},
		{"over", strings.Repeat("x", MaxCommandInputBytes+1), true},
		{"negative is not an input", "", false},
	} {
		cmd, err := CommandWithInputBounded(argv, tc.input)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
		if err == nil && string(cmd.Stdin) != tc.input {
			t.Fatalf("%s: stdin changed", tc.name)
		}
	}
	if _, err := CommandWithInputBounded(nil, strings.Repeat("x", MaxCommandInputBytes+1)); !errors.Is(err, ErrCommandInputLimit) {
		t.Fatalf("invalid command input: %v", err)
	}
}

func TestReadFileBoundedRejectsUnsupportedFSAndMemoryLimits(t *testing.T) {
	if _, err := ReadFileBounded(struct{ FileSystem }{}, "x", 1); err == nil || !strings.Contains(err.Error(), "does not support bounded reads") {
		t.Fatalf("unsupported filesystem error = %v", err)
	}
	m := NewMemoryFS()
	if err := m.WriteFile("/bounded", []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadFileBounded("/bounded", 2); !errors.Is(err, ErrReadLimit) {
		t.Fatalf("memory over-limit error = %v", err)
	}
	if _, err := m.ReadFileBounded("/bounded", -1); !errors.Is(err, ErrInvalidReadLimit) {
		t.Fatalf("memory invalid-limit error = %v", err)
	}
}

func TestMemoryFSBoundedWalkRejectsUnsafeParentsAndFinalNodes(t *testing.T) {
	m := NewMemoryFS()
	if err := m.MkdirAll("/safe/nested", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFile("/safe/nested/value", []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll("/outside", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFile("/outside/value", []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"/safe/nested/value", "safe/nested/value"} {
		data, err := m.ReadFileBounded(name, 16)
		if err != nil || string(data) != "safe" {
			t.Fatalf("bounded %q = %q, %v", name, data, err)
		}
	}

	if err := m.Symlink("/outside", "/safe/link"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadFileBounded("/safe/link/value", 16); err != ErrNonRegularFile {
		t.Fatalf("parent symlink error = %v, want %v", err, ErrNonRegularFile)
	}

	// Install a raw non-directory node to ensure bounded traversal does not
	// resolve or otherwise bypass an unsafe parent representation.
	m.nodes["/safe/not-a-directory"] = &memNode{mode: fs.ModeNamedPipe}
	if _, err := m.ReadFileBounded("/safe/not-a-directory/value", 16); err != ErrNonRegularFile {
		t.Fatalf("non-directory parent error = %v, want %v", err, ErrNonRegularFile)
	}

	if err := m.Symlink("/outside/value", "/safe/final-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadFileBounded("/safe/final-link", 16); err != ErrNonRegularFile {
		t.Fatalf("final symlink error = %v, want %v", err, ErrNonRegularFile)
	}
	m.nodes["/safe/device"] = &memNode{mode: fs.ModeDevice}
	if _, err := m.ReadFileBounded("/safe/device", 16); err != ErrNonRegularFile {
		t.Fatalf("final non-regular error = %v, want %v", err, ErrNonRegularFile)
	}
}

func (f fakeExec) Name() string { return f.name }
func (fakeExec) Args() any      { return struct{}{} }
func (f fakeExec) Execute(_ context.Context, _ *Runtime, _ any) (any, error) {
	return f.name, nil
}

type fakeState struct {
	name string
}

func (s fakeState) Name() string { return s.name }
func (fakeState) Args() any      { return struct{}{} }
func (s fakeState) Apply(_ context.Context, _ *Runtime, _ any) result.StateResult {
	return result.Success(s.name, "done")
}

func TestExecRegistryCall(t *testing.T) {
	reg := NewExecRegistry()
	if err := reg.Register(fakeExec{name: "test.echo"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	rt := &Runtime{}
	value, err := reg.Call(context.Background(), rt, "test.echo", nil)
	if err != nil || value != "test.echo" {
		t.Fatalf("call = %v, %v", value, err)
	}
	_, err = reg.Call(context.Background(), rt, "missing.fn", nil)
	var unsupported *UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Kind != "function" {
		t.Fatalf("expected UnsupportedError, got %v", err)
	}
}

func TestStateRegistryApply(t *testing.T) {
	reg := NewStateRegistry()
	if err := reg.Register(fakeState{name: "test.nop"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := reg.Apply(context.Background(), &Runtime{}, "test.nop", nil)
	if err != nil || !res.Succeeded() || res.Comment != "done" {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	_, err = reg.Apply(context.Background(), &Runtime{}, "missing.state", nil)
	if err == nil {
		t.Fatal("unknown state must fail")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error text = %v", err)
	}
}

func TestProviderRegistryResolution(t *testing.T) {
	reg := NewProviderRegistry()
	f := facts.ForTesting(facts.Overrides{
		OS: &facts.OSFacts{ID: "debian", Family: facts.FamilyDebian},
	})

	if _, _, err := reg.Resolve(f, "pkg"); err == nil {
		t.Fatal("empty kind must not resolve")
	}

	if err := reg.Register("pkg", "apt", "APT"); err != nil {
		t.Fatalf("register: %v", err)
	}
	provider, name, err := reg.Resolve(f, "pkg")
	if err != nil || provider != "APT" || name != "apt" {
		t.Fatalf("single-provider resolve = %v, %q, %v", provider, name, err)
	}

	if err := reg.Register("pkg", "dnf", "DNF"); err != nil {
		t.Fatalf("register second: %v", err)
	}
	if _, _, err := reg.Resolve(f, "pkg"); err == nil || !strings.Contains(err.Error(), "no selector") {
		t.Fatalf("multi-provider without selector must fail, got %v", err)
	}

	reg.SetSelector("pkg", func(f *facts.Facts) (string, error) {
		switch f.OS().Family {
		case facts.FamilyDebian:
			return "apt", nil
		default:
			return "", errors.New("no provider for family")
		}
	})
	provider, name, err = reg.Resolve(f, "pkg")
	if err != nil || name != "apt" {
		t.Fatalf("selector resolve = %v, %q, %v", provider, name, err)
	}

	reg.SetSelector("pkg", func(*facts.Facts) (string, error) { return "unknownpkg", nil })
	_, _, err = reg.Resolve(f, "pkg")
	if !errors.As(err, new(*UnsupportedError)) {
		t.Fatalf("unknown selected name must be UnsupportedError, got %v", err)
	}
}

func TestMemoryFSSubset(t *testing.T) {
	m := NewMemoryFS()

	if err := m.MkdirAll("/etc/app", 0o755); err != nil {
		t.Fatalf("mkdirall: %v", err)
	}
	if err := m.WriteFile("/etc/app/conf", []byte("data"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := m.ReadFile("/etc/app/conf")
	if err != nil || string(data) != "data" {
		t.Fatalf("read = %q, %v", data, err)
	}

	info, err := m.Stat("/etc/app/conf")
	if err != nil || info.Name() != "conf" || info.IsDir() || info.Mode().Perm() != 0o640 {
		t.Fatalf("stat = %+v, %v", info, err)
	}

	if _, err := m.ReadFile("/etc/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing read err = %v", err)
	}

	if err := m.WriteFile("/no-parent/file", []byte("x"), 0o600); err == nil {
		t.Fatal("write into missing parent must fail like os.WriteFile")
	}

	if err := m.Rename("/etc/app/conf", "/etc/app/moved"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := m.Stat("/etc/app/conf"); err == nil {
		t.Fatal("renamed source must vanish")
	}

	if err := m.Remove("/etc/app"); err == nil {
		t.Fatal("non-empty dir remove must fail")
	}

	if err := m.Symlink("/etc/app/moved", "/etc/link"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	target, err := m.Readlink("/etc/link")
	if err != nil || target != "/etc/app/moved" {
		t.Fatalf("readlink = %q, %v", target, err)
	}
	viaLink, err := m.ReadFile("/etc/link")
	if err != nil || string(viaLink) != "data" {
		t.Fatalf("read through symlink = %q, %v", viaLink, err)
	}
	linfo, err := m.Lstat("/etc/link")
	if err != nil || linfo.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("lstat symlink mode = %v, %v", linfo, err)
	}

	if err := m.RemoveAll("/etc/app"); err != nil {
		t.Fatalf("removeall: %v", err)
	}
	if _, err := m.Stat("/etc/app"); err == nil {
		t.Fatal("subtree must be gone")
	}

	tmp, err := m.MkdirTemp("", "statekit-*")
	if err != nil || tmp == "" {
		t.Fatalf("mkdirtemp = %q, %v", tmp, err)
	}
	if !strings.HasPrefix(tmp, "/tmp/statekit-") {
		t.Fatalf("tmp dir path = %q", tmp)
	}

	dirEntries, err := m.ReadDir("/")
	if err != nil {
		t.Fatalf("readdir root: %v", err)
	}
	for _, e := range dirEntries {
		if e.Name() == "tmp" && !e.IsDir() {
			t.Fatal("/tmp must stay a directory")
		}
	}
}

func TestMemoryFSChmodChown(t *testing.T) {
	m := NewMemoryFS()
	m.MkdirAll("/d", 0o755)
	m.WriteFile("/d/f", []byte("x"), 0o600)
	if err := m.Chmod("/d/f", 0o444); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	info, _ := m.Stat("/d/f")
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("mode after chmod = %v", info.Mode())
	}
	if err := m.Chown("/d/f", 100, 200); err != nil {
		t.Fatalf("chown: %v", err)
	}
}
