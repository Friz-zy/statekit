package runtime

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/result"
)

type fakeExec struct {
	name string
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
