package pkg

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type yumDownloadRunner struct {
	available         bool
	availabilityCalls int
	commands          []process.Command
	results           []process.CommandResult
	onRun             func(process.Command)
	cancel            context.CancelFunc
}

func (r *yumDownloadRunner) CommandAvailable(name string) bool {
	r.availabilityCalls++
	return r.available && name == "yumdownloader"
}

func (r *yumDownloadRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.onRun != nil {
		r.onRun(command)
	}
	if r.cancel != nil {
		r.cancel()
	}
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

type yumDownloadFS struct {
	*runtime.MemoryFS
	root       string
	mkdirErr   error
	readErr    error
	removeErr  error
	entries    []fs.DirEntry
	info       map[string]fs.FileInfo
	mkdirs     []string
	readLimits []int
	removed    []string
	lstats     []string
}

func newYumDownloadFS(manager string) *yumDownloadFS {
	return &yumDownloadFS{
		MemoryFS: runtime.NewMemoryFS(),
		root:     "/var/cache/" + manager + "/packages",
		info:     map[string]fs.FileInfo{},
	}
}

func (f *yumDownloadFS) MkdirAll(name string, perm fs.FileMode) error {
	f.mkdirs = append(f.mkdirs, name)
	if f.mkdirErr != nil {
		return f.mkdirErr
	}
	return f.MemoryFS.MkdirAll(name, perm)
}

func (f *yumDownloadFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	f.readLimits = append(f.readLimits, max)
	if f.readErr != nil {
		return nil, f.readErr
	}
	entries, err := f.MemoryFS.ReadDirBounded(name, max)
	if err != nil || name != f.root || len(f.entries) == 0 {
		return entries, err
	}
	all := append([]fs.DirEntry{}, entries...)
	all = append(all, f.entries...)
	if len(all) > max {
		return nil, runtime.ErrDirReadLimit
	}
	return all, nil
}

func (f *yumDownloadFS) Lstat(name string) (fs.FileInfo, error) {
	f.lstats = append(f.lstats, name)
	if info, ok := f.info[name]; ok {
		return info, nil
	}
	return f.MemoryFS.Lstat(name)
}

func (f *yumDownloadFS) Remove(name string) error {
	f.removed = append(f.removed, name)
	if f.removeErr != nil {
		return f.removeErr
	}
	return f.MemoryFS.Remove(name)
}

type yumDownloadEntry struct {
	name string
	mode fs.FileMode
}

func (e yumDownloadEntry) Name() string      { return e.name }
func (e yumDownloadEntry) IsDir() bool       { return e.mode.IsDir() }
func (e yumDownloadEntry) Type() fs.FileMode { return e.mode }
func (e yumDownloadEntry) Info() (fs.FileInfo, error) {
	return yumDownloadInfo{name: e.name, mode: e.mode}, nil
}

type yumDownloadInfo struct {
	name string
	mode fs.FileMode
}

func (i yumDownloadInfo) Name() string       { return i.name }
func (i yumDownloadInfo) Size() int64        { return 0 }
func (i yumDownloadInfo) Mode() fs.FileMode  { return i.mode }
func (i yumDownloadInfo) ModTime() time.Time { return time.Time{} }
func (i yumDownloadInfo) IsDir() bool        { return i.mode.IsDir() }
func (i yumDownloadInfo) Sys() any           { return nil }

type yumDownloadUnboundedFS struct{ runtime.FileSystem }

func newYumDownloadRuntime(manager string) (*runtime.Runtime, *yumDownloadFS, *yumDownloadRunner) {
	fsys := newYumDownloadFS(manager)
	runner := &yumDownloadRunner{available: true}
	return &runtime.Runtime{FS: fsys, Runner: runner}, fsys, runner
}

func callYumDownload(ctx context.Context, manager string, rt *runtime.Runtime, args map[string]any) (any, error) {
	return (&commandProvider{spec: rpmSpec(manager)}).Yum(ctx, rt, "download", args)
}

func writeYumDownloadFile(t *testing.T, fsys *yumDownloadFS, name string) {
	t.Helper()
	if err := fsys.MemoryFS.WriteFile(name, []byte("rpm"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertYumDownloadCommand(t *testing.T, command process.Command, cache string, packages []string) {
	t.Helper()
	want := append([]string{"-q", "--destdir=" + cache}, packages...)
	if command.Name != "yumdownloader" || !reflect.DeepEqual(command.Args, want) || command.Shell ||
		command.MaxStdoutBytes != yumDownloadOutputLimit || command.MaxStderrBytes != yumDownloadOutputLimit {
		t.Fatalf("command=%#v want args=%#v", command, want)
	}
}

func TestYumDownloadManagerMatrixAndSourceResult(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			rt, fsys, runner := newYumDownloadRuntime(manager)
			cache := fsys.root
			packages := []string{"alpha", "beta"}
			before := append([]string(nil), packages...)
			args := map[string]any{"packages": packages}
			runner.onRun = func(process.Command) {
				writeYumDownloadFile(t, fsys, cache+"/alpha-2.rpm")
				writeYumDownloadFile(t, fsys, cache+"/beta-3.rpm")
			}

			got, err := callYumDownload(context.Background(), manager, rt, args)
			want := map[string]any{"alpha": cache + "/alpha-2.rpm", "beta": cache + "/beta-3.rpm"}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			if len(runner.commands) != 1 || len(fsys.mkdirs) != 1 || fsys.mkdirs[0] != cache {
				t.Fatalf("commands=%#v mkdirs=%#v", runner.commands, fsys.mkdirs)
			}
			assertYumDownloadCommand(t, runner.commands[0], cache, packages)
			if !reflect.DeepEqual(fsys.readLimits, []int{yumDownloadMaxEntries, yumDownloadMaxEntries}) {
				t.Fatalf("bounded reads=%v", fsys.readLimits)
			}
			if !reflect.DeepEqual(packages, before) || !reflect.DeepEqual(args, map[string]any{"packages": before}) {
				t.Fatalf("input mutated: packages=%#v args=%#v", packages, args)
			}
		})
	}
}

func TestYumDownloadRemovesOnlySafeStaleRPMFiles(t *testing.T) {
	rt, fsys, runner := newYumDownloadRuntime("yum")
	cache := fsys.root
	if err := fsys.MemoryFS.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	writeYumDownloadFile(t, fsys, cache+"/alpha-old.rpm")
	writeYumDownloadFile(t, fsys, cache+"/alpha-not-rpm.txt")
	writeYumDownloadFile(t, fsys, cache+"/other-old.rpm")
	if err := fsys.MemoryFS.Symlink("alpha-old.rpm", cache+"/alpha-link.rpm"); err != nil {
		t.Fatal(err)
	}
	runner.onRun = func(process.Command) {
		writeYumDownloadFile(t, fsys, cache+"/alpha-new.rpm")
	}

	got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
	want := map[string]any{"alpha": cache + "/alpha-new.rpm"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	if !reflect.DeepEqual(fsys.removed, []string{cache + "/alpha-old.rpm"}) {
		t.Fatalf("removed=%#v", fsys.removed)
	}
	for _, name := range []string{cache + "/alpha-not-rpm.txt", cache + "/other-old.rpm", cache + "/alpha-link.rpm"} {
		if _, err := fsys.MemoryFS.Lstat(name); err != nil {
			t.Fatalf("unsafe stale candidate removed %q: %v", name, err)
		}
	}
}

func TestYumDownloadFinalScanHonorsSafetyPrefixAndOrder(t *testing.T) {
	rt, fsys, runner := newYumDownloadRuntime("dnf")
	cache := fsys.root
	fsys.entries = []fs.DirEntry{
		yumDownloadEntry{name: "alpha-pipe.rpm", mode: fs.ModeNamedPipe},
		yumDownloadEntry{name: "alpha-unknown.rpm", mode: 0},
		yumDownloadEntry{name: "alpha-/unsafe.rpm", mode: 0},
	}
	fsys.info[cache+"/alpha-unknown.rpm"] = yumDownloadInfo{name: "alpha-unknown.rpm", mode: fs.ModeSymlink}
	runner.onRun = func(process.Command) {
		writeYumDownloadFile(t, fsys, cache+"/alpha-beta-1.rpm")
		writeYumDownloadFile(t, fsys, cache+"/alpha-ignore.txt")
		if err := fsys.MemoryFS.Symlink("alpha-beta-1.rpm", cache+"/alpha-link.rpm"); err != nil {
			t.Fatal(err)
		}
	}

	packages := []string{"alpha", "alpha-beta", "alpha"}
	got, err := callYumDownload(context.Background(), "dnf", rt, map[string]any{"packages": packages})
	want := map[string]any{
		"alpha":  cache + "/alpha-beta-1.rpm",
		"_error": "The following package(s) failed to download: alpha-beta",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
	}
	if len(fsys.removed) != 0 {
		t.Fatalf("unsafe entries removed: %v", fsys.removed)
	}
	for _, name := range fsys.lstats {
		if strings.Contains(name, "/unsafe.rpm") {
			t.Fatalf("unsafe name reached lstat: %q", name)
		}
	}
}

func TestYumDownloadRejectsUnsafeInputBeforeWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   any
		wantErr string
	}{
		{"missing", nil, "No packages were specified"},
		{"empty", []string{}, "No packages were specified"},
		{"empty token", []string{""}, "invalid package token"},
		{"path traversal", []string{"../alpha"}, "invalid package token"},
		{"absolute path", []string{"/tmp/alpha"}, "invalid package token"},
		{"separator", []string{"alpha/beta"}, "invalid package token"},
		{"backslash", []string{"alpha\\beta"}, "invalid package token"},
		{"option", []string{"--destdir=/tmp"}, "invalid package token"},
		{"control", []string{"alpha\nbeta"}, "invalid package token"},
		{"nul", []string{"alpha\x00beta"}, "invalid package token"},
		{"wrong list", []any{"alpha"}, `argument "packages" must be a string list`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDownloadRuntime("yum")
			got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": tc.value})
			if got != nil || err == nil || err.Error() != tc.wantErr {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(fsys.mkdirs) != 0 || len(fsys.readLimits) != 0 || len(fsys.removed) != 0 || len(runner.commands) != 0 || runner.availabilityCalls != 0 {
				t.Fatalf("work occurred: mkdirs=%v reads=%v removes=%v commands=%v availability=%d", fsys.mkdirs, fsys.readLimits, fsys.removed, runner.commands, runner.availabilityCalls)
			}
		})
	}

	rt, fsys, runner := newYumDownloadRuntime("yum")
	got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}, "root": "/wrong"})
	if got != nil || err == nil || len(fsys.mkdirs) != 0 || len(runner.commands) != 0 {
		t.Fatalf("root remapping accepted: got=%#v err=%v mkdirs=%v commands=%v", got, err, fsys.mkdirs, runner.commands)
	}
}

func TestYumDownloadTestModeAndHelperAvailabilityDoNotMutate(t *testing.T) {
	rt, fsys, runner := newYumDownloadRuntime("dnf5")
	rt.Options.Test = true
	got, err := callYumDownload(context.Background(), "dnf5", rt, map[string]any{"packages": []string{"alpha"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("test mode got=%#v err=%v", got, err)
	}
	if len(fsys.mkdirs) != 0 || len(fsys.readLimits) != 0 || len(fsys.removed) != 0 || len(runner.commands) != 0 || runner.availabilityCalls != 0 {
		t.Fatalf("test mode mutated: mkdirs=%v reads=%v removes=%v commands=%v availability=%d", fsys.mkdirs, fsys.readLimits, fsys.removed, runner.commands, runner.availabilityCalls)
	}

	rt, fsys, runner = newYumDownloadRuntime("dnf5")
	runner.available = false
	got, err = callYumDownload(context.Background(), "dnf5", rt, map[string]any{"packages": []string{"alpha"}})
	if got != nil || err == nil || err.Error() != "'yumdownloader' command not available" {
		t.Fatalf("helper result=%#v err=%v", got, err)
	}
	if len(fsys.mkdirs) != 0 || len(fsys.readLimits) != 0 || len(runner.commands) != 0 || runner.availabilityCalls != 1 {
		t.Fatalf("helper check worked unexpectedly: mkdirs=%v reads=%v commands=%v availability=%d", fsys.mkdirs, fsys.readLimits, runner.commands, runner.availabilityCalls)
	}
}

func TestYumDownloadCacheFailuresAndBoundedFS(t *testing.T) {
	sentinel := errors.New("mkdir failed")
	rt, fsys, runner := newYumDownloadRuntime("yum")
	fsys.mkdirErr = sentinel
	got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
	if got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 0 || len(fsys.readLimits) != 0 {
		t.Fatalf("mkdir error got=%#v err=%v commands=%v reads=%v", got, err, runner.commands, fsys.readLimits)
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"missing cache", fs.ErrNotExist},
		{"bounded overflow", runtime.ErrDirReadLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDownloadRuntime("yum")
			fsys.readErr = tc.err
			got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
			if got != nil || !errors.Is(err, tc.err) || len(runner.commands) != 0 || !reflect.DeepEqual(fsys.readLimits, []int{yumDownloadMaxEntries}) {
				t.Fatalf("got=%#v err=%v commands=%v reads=%v", got, err, runner.commands, fsys.readLimits)
			}
		})
	}

	base := runtime.NewMemoryFS()
	runner = &yumDownloadRunner{available: true}
	rt = &runtime.Runtime{FS: yumDownloadUnboundedFS{FileSystem: base}, Runner: runner}
	got, err = callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
	if got != nil || !errors.Is(err, runtime.ErrBoundedDirUnsupported) || len(runner.commands) != 0 {
		t.Fatalf("unbounded fs got=%#v err=%v commands=%v", got, err, runner.commands)
	}
}

func TestYumDownloadRunnerFailuresCancellationAndNonzeroScan(t *testing.T) {
	sentinel := errors.New("runner failed")
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		want   error
	}{
		{"runner error", process.CommandResult{Err: sentinel}, sentinel},
		{"output limit", process.CommandResult{Err: process.ErrOutputLimit}, process.ErrOutputLimit},
		{"truncated output", process.CommandResult{StdoutTruncated: true}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDownloadRuntime("yum")
			runner.results = []process.CommandResult{tc.result}
			got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
			if got != nil || !errors.Is(err, tc.want) || len(runner.commands) != 1 || len(fsys.readLimits) != 1 {
				t.Fatalf("got=%#v err=%v commands=%v reads=%v", got, err, runner.commands, fsys.readLimits)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt, fsys, runner := newYumDownloadRuntime("yum")
	runner.cancel = cancel
	got, err := callYumDownload(ctx, "yum", rt, map[string]any{"packages": []string{"alpha"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 1 || len(fsys.readLimits) != 1 {
		t.Fatalf("canceled got=%#v err=%v commands=%v reads=%v", got, err, runner.commands, fsys.readLimits)
	}

	rt, fsys, runner = newYumDownloadRuntime("dnf")
	cache := fsys.root
	runner.results = []process.CommandResult{{ExitCode: 7, Stdout: []byte("completed with warnings\n")}}
	runner.onRun = func(process.Command) { writeYumDownloadFile(t, fsys, cache+"/alpha-1.rpm") }
	got, err = callYumDownload(context.Background(), "dnf", rt, map[string]any{"packages": []string{"alpha"}})
	want := map[string]any{"alpha": cache + "/alpha-1.rpm"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("nonzero got=%#v err=%v want=%#v", got, err, want)
	}
}

func TestYumDownloadNoResultAndPartialResultStrings(t *testing.T) {
	rt, _, runner := newYumDownloadRuntime("yum")
	got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha", "beta"}})
	if got != nil || err == nil || err.Error() != "Unable to download any of the following packages: alpha, beta" || len(runner.commands) != 1 {
		t.Fatalf("no-result got=%#v err=%v commands=%v", got, err, runner.commands)
	}

	rt, fsys, runner := newYumDownloadRuntime("yum")
	cache := fsys.root
	runner.onRun = func(process.Command) { writeYumDownloadFile(t, fsys, cache+"/alpha-1.rpm") }
	got, err = callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha", "beta"}})
	want := map[string]any{
		"alpha":  cache + "/alpha-1.rpm",
		"_error": "The following package(s) failed to download: beta",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("partial got=%#v err=%v want=%#v", got, err, want)
	}
}

func TestYumDownloadIgnoresStaleRemoveFailures(t *testing.T) {
	rt, fsys, runner := newYumDownloadRuntime("yum")
	cache := fsys.root
	if err := fsys.MemoryFS.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	writeYumDownloadFile(t, fsys, cache+"/alpha-old.rpm")
	fsys.removeErr = errors.New("remove denied")
	runner.onRun = func(process.Command) { writeYumDownloadFile(t, fsys, cache+"/alpha-new.rpm") }
	got, err := callYumDownload(context.Background(), "yum", rt, map[string]any{"packages": []string{"alpha"}})
	want := map[string]any{"alpha": cache + "/alpha-new.rpm"}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(fsys.removed, []string{cache + "/alpha-old.rpm"}) {
		t.Fatalf("got=%#v err=%v removed=%v", got, err, fsys.removed)
	}
}
