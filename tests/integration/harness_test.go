// Package integration runs the compiled statekit binary against
// language-independent YAML fixtures (plan section 25).
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	"github.com/friz-zy/statekit/internal/runtime"
	exechosts "github.com/friz-zy/statekit/modules/exec/hosts"
	"gopkg.in/yaml.v3"
)

const repoRoot = "../.."

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "statekit-bin-")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "statekit")
		var stderr bytes.Buffer
		cmd := exec.Command("go", "build", "-o", out, "./cmd/statekit")
		cmd.Dir = repoRoot
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("build statekit: %v", buildErr)
	}
	return binPath
}

type fixture struct {
	ID             string         `yaml:"id"`
	RequiresRoot   bool           `yaml:"requires-root"`
	Command        []string       `yaml:"command"`
	Stdin          string         `yaml:"stdin"`
	Exit           int            `yaml:"exit"`
	Stdout         string         `yaml:"stdout"`
	Contains       []string       `yaml:"contains"`
	StderrContains []string       `yaml:"stderr-contains"`
	JSON           map[string]any `yaml:"json"`
	Tmpdir         bool           `yaml:"tmpdir"`
	HostsFile      string         `yaml:"hosts-file"`
}

func loadFixtures(t *testing.T) []string {
	t.Helper()
	var matches []string
	root := filepath.Join(repoRoot, "tests", "fixtures")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no fixtures found under tests/fixtures")
	}
	sort.Strings(matches)
	return matches
}

func TestFixtures(t *testing.T) {
	bin := buildBinary(t)
	for _, path := range loadFixtures(t) {
		path := path
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var f fixture
			if err := yaml.Unmarshal(data, &f); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			// Tier 2 suites need a real init system; they execute through
			// tests/run-fixtures.sh inside systemd containers instead.
			if suiteOf(path) == "service" {
				t.Skip("tier 2: requires a systemd container (tests/run-fixtures.sh)")
			}
			if f.RequiresRoot && os.Geteuid() != 0 {
				t.Skip("requires root; executed in privileged containers")
			}
			runFixture(t, bin, f)
		})
	}
}

// fixtureProcessEnv constructs a deterministic child environment. Fixture
// subprocesses receive only execution essentials; ambient override duplicates
// and credential-bearing variables are never forwarded.
func fixtureProcessEnv(ambient []string, hostsPath string) []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "TZ": true,
	}
	values := make(map[string]string, len(allowed))
	for _, entry := range ambient {
		key, value, ok := strings.Cut(entry, "=")
		if ok && allowed[key] {
			values[key] = value
		}
	}
	keys := []string{"PATH", "HOME", "LANG", "LC_ALL", "TZ"}
	env := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		if value, ok := values[key]; ok {
			env = append(env, key+"="+value)
		}
	}
	if hostsPath != "" {
		env = append(env, exechosts.HostsPathEnv+"="+hostsPath)
	}
	return env
}

func TestFixtureProcessEnvFiltersAmbientAndDuplicates(t *testing.T) {
	ambient := []string{
		"HOME=/fixture-home",
		"PATH=/first",
		exechosts.HostsPathEnv + "=/ambient/not-owned",
		"LANG=C",
		"PATH=/last",
		"CREDENTIAL_SHOULD_NOT_PASS=synthetic",
	}
	owned := filepath.Join(exechosts.FixtureHostsRoot, "fixture-owned", "hosts")
	got := fixtureProcessEnv(ambient, owned)
	want := []string{"PATH=/last", "HOME=/fixture-home", "LANG=C", exechosts.HostsPathEnv + "=" + owned}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture environment = %#v, want %#v", got, want)
	}

	withoutOverride := fixtureProcessEnv(ambient, "")
	for _, entry := range withoutOverride {
		if strings.HasPrefix(entry, exechosts.HostsPathEnv+"=") {
			t.Fatal("ambient hosts override survived filtering")
		}
	}
}

func fixtureHostsDir(t *testing.T) string {
	t.Helper()
	if err := os.Mkdir(exechosts.FixtureHostsRoot, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("create fixture root: %v", err)
	}
	info, err := os.Lstat(exechosts.FixtureHostsRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("unsafe fixture root")
	}
	dir, err := os.MkdirTemp(exechosts.FixtureHostsRoot, "integration-")
	if err != nil {
		t.Fatalf("create hosts fixture directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type buildRuntimeAuditFS struct {
	*runtime.MemoryFS
	rawReads     int
	boundedReads int
	stats        int
	lstats       int
	writes       int
	renames      int
	removes      int
}

func (a *buildRuntimeAuditFS) Stat(name string) (fs.FileInfo, error) {
	a.stats++
	return a.MemoryFS.Stat(name)
}
func (a *buildRuntimeAuditFS) Lstat(name string) (fs.FileInfo, error) {
	a.lstats++
	return a.MemoryFS.Lstat(name)
}
func (a *buildRuntimeAuditFS) ReadFile(name string) ([]byte, error) {
	a.rawReads++
	return a.MemoryFS.ReadFile(name)
}
func (a *buildRuntimeAuditFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	a.boundedReads++
	return a.MemoryFS.ReadFileBounded(name, limit)
}
func (a *buildRuntimeAuditFS) WriteFile(name string, data []byte, mode fs.FileMode) error {
	a.writes++
	return a.MemoryFS.WriteFile(name, data, mode)
}
func (a *buildRuntimeAuditFS) Rename(oldpath, newpath string) error {
	a.renames++
	return a.MemoryFS.Rename(oldpath, newpath)
}
func (a *buildRuntimeAuditFS) Remove(name string) error {
	a.removes++
	return a.MemoryFS.Remove(name)
}

func TestBuildRuntimeCustomHostsMutationsTouchNoFilesystem(t *testing.T) {
	configured := filepath.Join(exechosts.FixtureHostsRoot, "nonexistent", "hosts-fixture-path-secret")
	t.Setenv("TMPDIR", "/etc")
	t.Setenv(exechosts.HostsPathEnv, configured)
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatalf("BuildRuntime syntax-only configuration: %v", err)
	}

	calls := []struct {
		name     string
		function string
		args     any
	}{
		{"add", "hosts.add_host", &exechosts.AddArgs{IP: "127.0.0.2", Aliases: []string{"fixture"}}},
		{"rm", "hosts.rm_host", &exechosts.RmArgs{IP: "127.0.0.1"}},
		{"setHost", "hosts.set_host", &exechosts.SetHostArgs{IP: "127.0.0.1", Aliases: "fixture"}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			audit := &buildRuntimeAuditFS{MemoryFS: runtime.NewMemoryFS()}
			rt.FS = audit
			_, err := rt.Exec.Call(context.Background(), rt, tc.function, tc.args)
			if err == nil || err.Error() != "hosts: configured hosts file is read-only" {
				t.Fatalf("custom mutation error = %v", err)
			}
			if strings.Contains(err.Error(), configured) || strings.Contains(err.Error(), "fixture-path-secret") {
				t.Fatalf("custom mutation error leaked configured path: %q", err)
			}
			if audit.rawReads != 0 || audit.boundedReads != 0 || audit.stats != 0 || audit.lstats != 0 ||
				audit.writes != 0 || audit.renames != 0 || audit.removes != 0 {
				t.Fatalf("custom mutation touched filesystem: %+v", audit)
			}
		})
	}
}

func runFixture(t *testing.T, bin string, f fixture) {
	t.Helper()
	command := f.Command
	if f.Tmpdir {
		dir := t.TempDir()
		for i, arg := range command {
			command[i] = strings.ReplaceAll(arg, "__TMPDIR__", dir)
		}
		if len(f.JSON) > 0 {
			raw, err := json.Marshal(f.JSON)
			if err != nil {
				t.Fatalf("marshal expectations: %v", err)
			}
			var substituted map[string]any
			if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), "__TMPDIR__", dir)), &substituted); err != nil {
				t.Fatalf("unmarshal expectations: %v", err)
			}
			f.JSON = substituted
		}
	}
	var hostsPath string
	if f.HostsFile != "" {
		dir := fixtureHostsDir(t)
		hostsPath = filepath.Join(dir, "hosts")
		if err := os.WriteFile(hostsPath, []byte(f.HostsFile), 0o600); err != nil {
			t.Fatalf("write hosts fixture: %v", err)
		}
	}
	cmd := exec.Command(bin, command...)
	cmd.Env = fixtureProcessEnv(os.Environ(), hostsPath)
	cmd.Stdin = strings.NewReader(f.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run binary: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}

	if exitCode != f.Exit {
		t.Fatalf("exit = %d want %d\nstdout:\n%s\nstderr:\n%s",
			exitCode, f.Exit, stdout.String(), stderr.String())
	}
	for _, want := range f.Contains {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q\ngot:\n%s", want, stdout.String())
		}
	}
	for _, want := range f.StderrContains {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q\ngot:\n%s", want, stderr.String())
		}
	}
	if f.Stdout != "" && stdout.String() != f.Stdout {
		t.Fatalf("stdout mismatch\ngot:  %q\nwant: %q", stdout.String(), f.Stdout)
	}
	if len(f.JSON) > 0 {
		var actual map[string]any
		if jerr := json.Unmarshal(stdout.Bytes(), &actual); jerr != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", jerr, stdout.String())
		}
		if problems := subsetMatch(f.JSON, actual); len(problems) > 0 {
			t.Fatalf("json mismatch (%s)\ngot:\n%s", strings.Join(problems, "; "), stdout.String())
		}
	}
}

// TestFileManagedLifecycle drives create -> idempotent re-run ->
// test-mode no-mutation -> absent against the real binary in one temp dir.
func TestFileManagedLifecycle(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	path := dir + "/app.conf"

	run := func(args ...string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run: %v", err)
			}
			code = exitErr.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}

	out, _, code := run("state", "file.managed", "--name", path,
		"--contents", "v1", "-o", "json")
	if code != 0 || !strings.Contains(out, `"newfile"`) {
		t.Fatalf("create step wrong: rc=%d out=%s", code, out)
	}

	out, _, _ = run("state", "file.managed", "--name", path,
		"--contents", "v1", "-o", "json")
	if !strings.Contains(out, `"result": true`) || strings.Contains(out, "changes") && strings.Contains(out, "newfile") {
		t.Fatalf("idempotent rerun wrong: %s", out)
	}

	out, _, _ = run("state", "file.managed", "--name", path,
		"--contents", "v2", "--test", "-o", "json")
	if !strings.Contains(out, `"result": null`) {
		t.Fatalf("test mode must be pending: %s", out)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "v1" {
		t.Fatalf("test mode mutated file: %q", data)
	}

	out, _, _ = run("state", "file.absent", "--name", path, "-o", "json")
	if !strings.Contains(out, `"removed"`) {
		t.Fatalf("absent step wrong: %s", out)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("file must be gone after absent")
	}
}

// subsetMatch verifies every expected key exists in actual with an equal or
// recursively matching value.
func subsetMatch(expected, actual map[string]any) []string {
	var problems []string
	for key, wantValue := range expected {
		gotValue, present := actual[key]
		if !present {
			problems = append(problems, "missing key "+key)
			continue
		}
		wantMap, wantIsMap := wantValue.(map[string]any)
		gotMap, gotIsMap := gotValue.(map[string]any)
		if wantIsMap && gotIsMap {
			problems = append(problems, subsetMatch(wantMap, gotMap)...)
			continue
		}
		if !valuesEqual(wantValue, gotValue) {
			problems = append(problems, fmt.Sprintf("%s: got %#v want %#v", key, gotValue, wantValue))
		}
	}
	sortStrings(problems)
	return problems
}

func valuesEqual(want, got any) bool {
	return reflect.DeepEqual(normalizeNumbers(want), normalizeNumbers(got))
}

func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case float32:
		return float64(t)
	default:
		return v
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestApplyEndToEnd runs the real binary against a generated operations
// document covering success, global dry-run, and failure-stop semantics.
func TestApplyEndToEnd(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	opsPath := dir + "/ops.yaml"

	writeOps := func(content string) {
		if err := os.WriteFile(opsPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		var stdout bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Stdout = &stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run: %v", err)
			}
			code = exitErr.ExitCode()
		}
		return stdout.String(), code
	}

	writeOps("operations:\n" +
		"  - state: file.managed\n" +
		"    args: {name: " + dir + "/a.conf, contents: A}\n" +
		"  - state: test.nop\n" +
		"    args: {name: mid}\n")
	out, code := run("apply", opsPath)
	if code != 0 || strings.Count(out, "result: true") != 2 {
		t.Fatalf("success apply wrong: rc=%d out=%s", code, out)
	}
	data, _ := os.ReadFile(dir + "/a.conf")
	if string(data) != "A" {
		t.Fatalf("applied content = %q", data)
	}

	// Global --test leaves no mutations and reports null results.
	os.Remove(dir + "/a.conf")
	out, code = run("apply", opsPath, "--test", "-o", "json")
	if code != 0 || !strings.Contains(out, `"result": null`) {
		t.Fatalf("global dry-run wrong: rc=%d out=%s", code, out)
	}
	if _, statErr := os.Stat(dir + "/a.conf"); !os.IsNotExist(statErr) {
		t.Fatal("global dry-run mutated the filesystem")
	}

	// Failure stops by default.
	writeOps("operations:\n" +
		"  - state: file.managed\n" +
		"    args: {name: " + dir + "/broken.conf, source: /definitely/missing/src}\n" +
		"  - state: test.nop\n" +
		"    args: {name: never}\n")
	_, code = run("apply", opsPath)
	if code == 0 {
		t.Fatal("failing apply must exit non-zero")
	}
}

// suiteOf returns the fixtures family directory ("" for root-level files).
func suiteOf(path string) string {
	rel, err := filepath.Rel(filepath.Join(repoRoot, "tests", "fixtures"), path)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(filepath.ToSlash(rel), "/", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[0]
}
