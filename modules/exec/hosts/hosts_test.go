package hosts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"golang.org/x/sys/unix"
)

const hostsFixture = `127.0.0.1 localhost
# comment
10.0.0.5 web web.local
`

func testRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/hosts", []byte(hostsFixture), 0o644)
	return rt
}

func TestListHosts(t *testing.T) {
	value, err := (listFunc{}).Execute(context.Background(), testRT(), &ListArgs{})
	if err != nil {
		t.Fatalf("list_hosts: %v", err)
	}
	m := value.(map[string]any)
	if strings.Join(m["10.0.0.5"].([]string), ",") != "web,web.local" {
		t.Fatalf("hosts map wrong: %+v", m)
	}
}

func TestAddAndHasPair(t *testing.T) {
	rt := testRT()
	if _, err := (addFunc{}).Execute(context.Background(), rt, &AddArgs{
		IP: "10.0.0.9", Aliases: []string{"db", "db.local"},
	}); err != nil {
		t.Fatalf("add_host: %v", err)
	}
	value, _ := (hasPairFunc{}).Execute(context.Background(), rt, &HasPairArgs{IP: "10.0.0.9", Alias: "db"})
	if value != true {
		t.Fatal("has_pair must find new entry")
	}
	data, _ := rt.FS.ReadFile("/etc/hosts")
	rendered := string(data)
	if !strings.Contains(rendered, "10.0.0.9\tdb\tdb.local") {
		t.Fatalf("rendered hosts missing entry:\n%s", rendered)
	}
	if !strings.Contains(rendered, "# comment") {
		t.Fatal("comments must survive rewriting")
	}
}

func TestRmHost(t *testing.T) {
	rt := testRT()
	(rmFunc{}).Execute(context.Background(), rt, &RmArgs{IP: "10.0.0.5"})
	data, _ := rt.FS.ReadFile("/etc/hosts")
	if strings.Contains(string(data), "10.0.0.5") {
		t.Fatalf("entry not removed:\n%s", data)
	}
	found, _ := (rmFunc{}).Execute(context.Background(), rt, &RmArgs{IP: "10.9.9.9"})
	if found != false {
		t.Fatal("removing absent ip must report false")
	}
}

func TestConfiguredHostsPath(t *testing.T) {
	dir := fixtureTempDir(t)
	configured := filepath.Join(dir, "hosts")
	if err := os.WriteFile(configured, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(HostsPathEnv, configured)

	rt := testRT()
	rt.FS = runtime.NewOSFileSystem()
	if err := ConfigureRuntime(rt); err != nil {
		t.Fatalf("configure hosts path: %v", err)
	}
	value, err := (hasPairFunc{}).Execute(context.Background(), rt, &HasPairArgs{
		IP: "127.0.0.1", Alias: "localhost",
	})
	if err != nil || value != true {
		t.Fatalf("configured hosts path: value=%v err=%v", value, err)
	}
}

func TestConfigureRuntimeIsSyntaxOnly(t *testing.T) {
	dir := fixtureTempDir(t)
	configured := filepath.Join(dir, "missing-hosts")
	t.Setenv(HostsPathEnv, configured)
	rt, audit, _ := customAuditRT(t)
	rt.Options.HostsPath = ""
	if err := ConfigureRuntime(rt); err != nil {
		t.Fatalf("configure syntax-only path: %v", err)
	}
	if rt.Options.HostsPath != configured {
		t.Fatalf("configured path = %q", rt.Options.HostsPath)
	}
	assertNoFSOperations(t, audit)
}

func TestConfigureRuntimeRejectsOutsideTempAndRedacts(t *testing.T) {
	dir, err := os.MkdirTemp(".", "fixture-path-secret-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	configured, err := filepath.Abs(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configured, []byte("fixture-source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(HostsPathEnv, configured)

	err = ConfigureRuntime(&runtime.Runtime{})
	if !errors.Is(err, errInvalidHostsPath) {
		t.Fatalf("outside-temp error = %v", err)
	}
	assertNoConfiguredLeak(t, err, configured)
}

func TestGetIP(t *testing.T) {
	rt := testRT()
	value, _ := (getIPFunc{}).Execute(context.Background(), rt, &GetIPArgs{Name: "web"})
	if value != "10.0.0.5" {
		t.Fatalf("get_ip = %v", value)
	}
	value, _ = (getIPFunc{}).Execute(context.Background(), rt, &GetIPArgs{Name: "missing"})
	if value != "" {
		t.Fatalf("unknown name must be empty, got %v", value)
	}
}

type auditingFS struct {
	*runtime.MemoryFS
	rawReads     int
	boundedReads int
	stats        int
	lstats       int
	writes       int
	renames      int
	removes      int
	boundedErr   error
}

func (a *auditingFS) ReadFile(name string) ([]byte, error) {
	a.rawReads++
	return a.MemoryFS.ReadFile(name)
}

func (a *auditingFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	a.boundedReads++
	if a.boundedErr != nil {
		return nil, a.boundedErr
	}
	return a.MemoryFS.ReadFileBounded(name, limit)
}

func (a *auditingFS) Stat(name string) (fs.FileInfo, error) {
	a.stats++
	return a.MemoryFS.Stat(name)
}

func (a *auditingFS) Lstat(name string) (fs.FileInfo, error) {
	a.lstats++
	return a.MemoryFS.Lstat(name)
}

func (a *auditingFS) WriteFile(name string, data []byte, mode fs.FileMode) error {
	a.writes++
	return a.MemoryFS.WriteFile(name, data, mode)
}

func (a *auditingFS) Rename(oldpath, newpath string) error {
	a.renames++
	return a.MemoryFS.Rename(oldpath, newpath)
}

func (a *auditingFS) Remove(name string) error {
	a.removes++
	return a.MemoryFS.Remove(name)
}

func customAuditRT(t *testing.T) (*runtime.Runtime, *auditingFS, string) {
	t.Helper()
	memory := runtime.NewMemoryFS()
	if err := memory.MkdirAll(FixtureHostsRoot+"/fixture-owned", 0o700); err != nil {
		t.Fatal(err)
	}
	path := FixtureHostsRoot + "/fixture-owned/hosts-fixture-path-secret"
	if err := memory.WriteFile(path, []byte(hostsFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := &auditingFS{MemoryFS: memory}
	return &runtime.Runtime{FS: audit, Options: runtime.RuntimeOptions{HostsPath: path}}, audit, path
}

func TestCustomReadFunctionsUseBoundedNoFollow(t *testing.T) {
	calls := []struct {
		name string
		call func(*runtime.Runtime) (any, error)
	}{
		{"list", func(rt *runtime.Runtime) (any, error) {
			return (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
		}},
		{"getIP", func(rt *runtime.Runtime) (any, error) {
			return (getIPFunc{}).Execute(context.Background(), rt, &GetIPArgs{Name: "web"})
		}},
		{"hasPair", func(rt *runtime.Runtime) (any, error) {
			return (hasPairFunc{}).Execute(context.Background(), rt, &HasPairArgs{IP: "10.0.0.5", Alias: "web"})
		}},
		{"getAlias", func(rt *runtime.Runtime) (any, error) {
			return (getAliasFunc{}).Execute(context.Background(), rt, &GetAliasArgs{IP: "10.0.0.5"})
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			rt, audit, _ := customAuditRT(t)
			if _, err := tc.call(rt); err != nil {
				t.Fatalf("custom read: %v", err)
			}
			if audit.boundedReads != 1 || audit.rawReads != 0 {
				t.Fatalf("reads: bounded=%d raw=%d", audit.boundedReads, audit.rawReads)
			}
		})
	}
}

func TestCustomReadErrorsAreStableAndRedacted(t *testing.T) {
	calls := []struct {
		name string
		call func(*runtime.Runtime) (any, error)
	}{
		{"list", func(rt *runtime.Runtime) (any, error) {
			return (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
		}},
		{"getIP", func(rt *runtime.Runtime) (any, error) {
			return (getIPFunc{}).Execute(context.Background(), rt, &GetIPArgs{Name: "web"})
		}},
		{"hasPair", func(rt *runtime.Runtime) (any, error) {
			return (hasPairFunc{}).Execute(context.Background(), rt, &HasPairArgs{IP: "10.0.0.5", Alias: "web"})
		}},
		{"getAlias", func(rt *runtime.Runtime) (any, error) {
			return (getAliasFunc{}).Execute(context.Background(), rt, &GetAliasArgs{IP: "10.0.0.5"})
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			rt, audit, configured := customAuditRT(t)
			audit.boundedErr = fmt.Errorf("underlying fixture-source-secret at %s", configured)
			_, err := tc.call(rt)
			if !errors.Is(err, errConfiguredHostsRead) || err.Error() != errConfiguredHostsRead.Error() {
				t.Fatalf("custom error = %v", err)
			}
			assertNoConfiguredLeak(t, err, configured)
		})
	}
}

func TestCustomMutationsFailBeforeFilesystemOperation(t *testing.T) {
	calls := []struct {
		name string
		call func(*runtime.Runtime) (any, error)
	}{
		{"add", func(rt *runtime.Runtime) (any, error) {
			return (addFunc{}).Execute(context.Background(), rt, &AddArgs{IP: "10.0.0.9", Aliases: []string{"db"}})
		}},
		{"rm", func(rt *runtime.Runtime) (any, error) {
			return (rmFunc{}).Execute(context.Background(), rt, &RmArgs{IP: "10.0.0.5"})
		}},
		{"setHost", func(rt *runtime.Runtime) (any, error) {
			return (setHostFunc{}).Execute(context.Background(), rt, &SetHostArgs{IP: "10.0.0.5", Aliases: "changed"})
		}},
		{"writeFile", func(rt *runtime.Runtime) (any, error) {
			return nil, writeFile(rt, "127.0.0.1 localhost\n", 0o600)
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			rt, audit, configured := customAuditRT(t)
			_, err := tc.call(rt)
			if !errors.Is(err, errConfiguredHostsChange) || err.Error() != errConfiguredHostsChange.Error() {
				t.Fatalf("custom mutation error = %v", err)
			}
			assertNoConfiguredLeak(t, err, configured)
			assertNoFSOperations(t, audit)
		})
	}
}

func TestRuntimeOptionsHostsPathRejectsOutsideTempBeforeRead(t *testing.T) {
	rt, audit, _ := customAuditRT(t)
	configured := "/etc/hosts"
	rt.Options.HostsPath = configured
	_, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if !errors.Is(err, errConfiguredHostsRead) || err.Error() != errConfiguredHostsRead.Error() {
		t.Fatalf("explicit runtime option error = %v", err)
	}
	assertNoConfiguredLeak(t, err, configured)
	assertNoFSOperations(t, audit)
}

func TestConfigureRuntimeRejectsUnsafeScopeIndependentOfTMPDIR(t *testing.T) {
	t.Setenv("TMPDIR", "/etc")
	for name, configured := range map[string]string{
		"ambient tmpdir attack": "/etc/hosts",
		"relative":              "relative-fixture-path-secret",
		"unclean":               FixtureHostsRoot + "/./hosts",
		"root itself":           FixtureHostsRoot,
		"sibling prefix":        FixtureHostsRoot + "-other/hosts",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(HostsPathEnv, configured)
			err := ConfigureRuntime(&runtime.Runtime{})
			if !errors.Is(err, errInvalidHostsPath) || err.Error() != HostsPathEnv+": "+errInvalidHostsPath.Error() {
				t.Fatalf("unsafe path error = %v", err)
			}
			assertNoConfiguredLeak(t, err, configured)
		})
	}
}

func TestExplicitRuntimeOptionsUseSameValidation(t *testing.T) {
	rt := &runtime.Runtime{Options: runtime.RuntimeOptions{HostsPath: "/etc/hosts"}}
	err := ConfigureRuntime(rt)
	if !errors.Is(err, errInvalidHostsPath) {
		t.Fatalf("explicit option error = %v", err)
	}
	assertNoConfiguredLeak(t, err, rt.Options.HostsPath)
}

func TestConfiguredReadsFailClosedAfterReplacement(t *testing.T) {
	t.Run("final symlink", func(t *testing.T) {
		dir, configured, rt := configuredOSRuntime(t)
		outside := filepath.Join(dir, "fixture-source-secret")
		if err := os.WriteFile(outside, []byte("fixture-source-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(configured); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, configured); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		_, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
		assertConfiguredReadFailure(t, err, configured)
	})

	t.Run("parent symlink", func(t *testing.T) {
		root := fixtureTempDir(t)
		parent := filepath.Join(root, "fixture-path-secret-parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		configured := filepath.Join(parent, "hosts")
		if err := os.WriteFile(configured, []byte(hostsFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		rt := configureOSRuntime(t, configured)
		moved := filepath.Join(root, "moved")
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, parent); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		_, err := (hasPairFunc{}).Execute(context.Background(), rt, &HasPairArgs{IP: "127.0.0.1", Alias: "localhost"})
		assertConfiguredReadFailure(t, err, configured)
	})

	t.Run("oversized", func(t *testing.T) {
		_, configured, rt := configuredOSRuntime(t)
		if err := os.Truncate(configured, maxConfiguredHostsFileSize+1); err != nil {
			t.Fatal(err)
		}
		_, err := (getIPFunc{}).Execute(context.Background(), rt, &GetIPArgs{Name: "web"})
		assertConfiguredReadFailure(t, err, configured)
	})

	t.Run("fifo does not block", func(t *testing.T) {
		_, configured, rt := configuredOSRuntime(t)
		if err := os.Remove(configured); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(configured, 0o600); err != nil {
			t.Skipf("fifo unavailable: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := (getAliasFunc{}).Execute(context.Background(), rt, &GetAliasArgs{IP: "10.0.0.5"})
			done <- err
		}()
		select {
		case err := <-done:
			assertConfiguredReadFailure(t, err, configured)
		case <-time.After(2 * time.Second):
			t.Fatal("configured FIFO read blocked")
		}
	})

	t.Run("portable nonregular capability", func(t *testing.T) {
		rt, audit, configured := customAuditRT(t)
		audit.boundedErr = runtime.ErrNonRegularFile
		done := make(chan error, 1)
		go func() {
			_, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
			done <- err
		}()
		select {
		case err := <-done:
			assertConfiguredReadFailure(t, err, configured)
		case <-time.After(2 * time.Second):
			t.Fatal("configured nonregular read blocked")
		}
	})
}

func TestConfiguredReadReplacementRaceDoesNotLeak(t *testing.T) {
	dir, configured, rt := configuredOSRuntime(t)
	secret := filepath.Join(dir, "fixture-source-secret")
	if err := os.WriteFile(secret, []byte("203.0.113.9 fixture-source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	swapErr := make(chan error, 1)
	go func() {
		<-start
		for i := 0; i < 300; i++ {
			link := filepath.Join(dir, fmt.Sprintf("link-%d", i))
			if err := os.Symlink(secret, link); err != nil {
				swapErr <- err
				return
			}
			if err := os.Rename(link, configured); err != nil {
				swapErr <- err
				return
			}
			replacement := filepath.Join(dir, fmt.Sprintf("safe-%d", i))
			if err := os.WriteFile(replacement, []byte(hostsFixture), 0o600); err != nil {
				swapErr <- err
				return
			}
			if err := os.Rename(replacement, configured); err != nil {
				swapErr <- err
				return
			}
		}
		swapErr <- nil
	}()
	close(start)

	for i := 0; i < 1000; i++ {
		value, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
		if err != nil {
			if !errors.Is(err, errConfiguredHostsRead) || err.Error() != errConfiguredHostsRead.Error() {
				t.Fatalf("replacement race error = %v", err)
			}
			assertNoConfiguredLeak(t, err, configured)
			continue
		}
		if _, leaked := value.(map[string]any)["203.0.113.9"]; leaked {
			t.Fatal("replacement race crossed the configured-file descriptor boundary")
		}
	}
	if err := <-swapErr; err != nil {
		t.Fatalf("replacement race setup: %v", err)
	}
}

func configuredOSRuntime(t *testing.T) (string, string, *runtime.Runtime) {
	t.Helper()
	dir := fixtureTempDir(t)
	configured := filepath.Join(dir, "hosts-fixture-path-secret")
	if err := os.WriteFile(configured, []byte(hostsFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, configured, configureOSRuntime(t, configured)
}

func configureOSRuntime(t *testing.T, configured string) *runtime.Runtime {
	t.Helper()
	t.Setenv(HostsPathEnv, configured)
	rt := &runtime.Runtime{FS: runtime.NewOSFileSystem()}
	if err := ConfigureRuntime(rt); err != nil {
		t.Fatalf("configure custom hosts: %v", err)
	}
	return rt
}

func fixtureTempDir(t *testing.T) string {
	t.Helper()
	if err := os.Mkdir(FixtureHostsRoot, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("create fixture root: %v", err)
	}
	info, err := os.Lstat(FixtureHostsRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("unsafe fixture root")
	}
	dir, err := os.MkdirTemp(FixtureHostsRoot, "hosts-test-")
	if err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func assertNoFSOperations(t *testing.T, audit *auditingFS) {
	t.Helper()
	if audit.rawReads != 0 || audit.boundedReads != 0 || audit.stats != 0 || audit.lstats != 0 ||
		audit.writes != 0 || audit.renames != 0 || audit.removes != 0 {
		t.Fatalf("filesystem touched: %+v", audit)
	}
}

func assertConfiguredReadFailure(t *testing.T, err error, configured string) {
	t.Helper()
	if !errors.Is(err, errConfiguredHostsRead) || err.Error() != errConfiguredHostsRead.Error() {
		t.Fatalf("configured read error = %v", err)
	}
	assertNoConfiguredLeak(t, err, configured)
}

func assertNoConfiguredLeak(t *testing.T, err error, configured string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected configured hosts error")
	}
	for _, forbidden := range []string{configured, "fixture-path-secret", "fixture-source-secret"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("configured hosts error leaked protected input: %q", err)
		}
	}
}
