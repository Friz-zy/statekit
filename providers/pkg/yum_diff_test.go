package pkg

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type yumDiffRunner struct {
	available         map[string]bool
	availabilityCalls []string
	commands          []process.Command
	run               func(context.Context, process.Command) process.CommandResult
}

func (r *yumDiffRunner) CommandAvailable(name string) bool {
	r.availabilityCalls = append(r.availabilityCalls, name)
	return r.available[name]
}

func (r *yumDiffRunner) Run(ctx context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.run == nil {
		return process.CommandResult{}
	}
	return r.run(ctx, command)
}

type yumDiffNoAvailabilityRunner struct {
	commands []process.Command
}

func (r *yumDiffNoAvailabilityRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if command.Name == "rpm" {
		return process.CommandResult{Stdout: []byte("alpha")}
	}
	return process.CommandResult{}
}

type yumDiffFS struct {
	*runtime.MemoryFS
	stats      []string
	lstats     []string
	mkdirs     []string
	readDirs   []string
	readLimits []int
}

func newYumDiffFS() *yumDiffFS { return &yumDiffFS{MemoryFS: runtime.NewMemoryFS()} }

func (f *yumDiffFS) Stat(name string) (fs.FileInfo, error) {
	f.stats = append(f.stats, name)
	return f.MemoryFS.Stat(name)
}

func (f *yumDiffFS) Lstat(name string) (fs.FileInfo, error) {
	f.lstats = append(f.lstats, name)
	return f.MemoryFS.Lstat(name)
}

func (f *yumDiffFS) MkdirAll(name string, perm fs.FileMode) error {
	f.mkdirs = append(f.mkdirs, name)
	return f.MemoryFS.MkdirAll(name, perm)
}

func (f *yumDiffFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	f.readDirs = append(f.readDirs, name)
	f.readLimits = append(f.readLimits, max)
	return f.MemoryFS.ReadDirBounded(name, max)
}

func (f *yumDiffFS) ReadFile(string) ([]byte, error) {
	panic("pkg.diff must not directly read a host path")
}

func newYumDiffRuntime() (*runtime.Runtime, *yumDiffFS, *yumDiffRunner) {
	fsys := newYumDiffFS()
	runner := &yumDiffRunner{available: map[string]bool{
		"yumdownloader": true, "rpm2cpio": true, "cpio": true, "diff": true,
	}}
	return &runtime.Runtime{FS: fsys, Runner: runner}, fsys, runner
}

func writeYumDiffFile(t *testing.T, fsys *yumDiffFS, name string, data []byte) {
	t.Helper()
	if err := fsys.MemoryFS.MkdirAll(path.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.MemoryFS.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func callYumDiff(ctx context.Context, manager string, rt *runtime.Runtime, args map[string]any) (any, error) {
	return (&commandProvider{spec: rpmSpec(manager)}).Yum(ctx, rt, "diff", args)
}

func yumDiffArgv(commands []process.Command) [][]string {
	out := make([][]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, append([]string{command.Name}, command.Args...))
	}
	return out
}

func TestYumDiffProviderPipelineOrderAndBounds(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			rt, fsys, runner := newYumDiffRuntime()
			writeYumDiffFile(t, fsys, "/etc/one", []byte("current one"))
			writeYumDiffFile(t, fsys, "/etc/two", []byte("current two"))
			writeYumDiffFile(t, fsys, "/usr/unmanaged", []byte("outside package"))
			cache := "/var/cache/" + manager + "/packages"
			runner.run = func(_ context.Context, command process.Command) process.CommandResult {
				switch command.Name {
				case "rpm":
					switch command.Args[len(command.Args)-1] {
					case "/etc/one", "/etc/two":
						return process.CommandResult{Stdout: []byte("alpha")}
					case "/usr/unmanaged", "/missing":
						return process.CommandResult{ExitCode: 1}
					}
				case "yumdownloader":
					writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
					return process.CommandResult{}
				case "rpm2cpio":
					return process.CommandResult{Stdout: []byte("archive")}
				case "cpio":
					if !bytes.Equal(command.Stdin, []byte("archive")) {
						t.Fatalf("cpio stdin=%q", command.Stdin)
					}
					return process.CommandResult{Stdout: []byte("original")}
				case "diff":
					if !bytes.Equal(command.Stdin, []byte("original")) {
						t.Fatalf("diff stdin=%q", command.Stdin)
					}
					if command.Args[len(command.Args)-1] == "/etc/one" {
						return process.CommandResult{ExitCode: 1, Stdout: []byte("--- A /etc/one\n+++ B /etc/one\n")}
					}
					return process.CommandResult{}
				}
				t.Fatalf("unexpected command=%#v", command)
				return process.CommandResult{}
			}
			paths := []string{"/etc/one", "/etc/two", "/usr/unmanaged", "/missing", "/etc/one"}
			before := append([]string(nil), paths...)
			got, err := callYumDiff(context.Background(), manager, rt, map[string]any{"paths": paths})
			want := map[string]any{
				"/etc/one":       "--- A /etc/one\n+++ B /etc/one\n",
				"/etc/two":       "Unchanged",
				"/usr/unmanaged": "Not managed",
				"/missing":       "N/A",
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			if !reflect.DeepEqual(paths, before) {
				t.Fatalf("paths mutated: %v", paths)
			}
			wantArgv := [][]string{
				{"rpm", "-qf", "--queryformat", "%{name}", "/etc/one"},
				{"rpm", "-qf", "--queryformat", "%{name}", "/etc/two"},
				{"rpm", "-qf", "--queryformat", "%{name}", "/usr/unmanaged"},
				{"rpm", "-qf", "--queryformat", "%{name}", "/missing"},
				{"rpm", "-qf", "--queryformat", "%{name}", "/etc/one"},
				{"yumdownloader", "-q", "--destdir=" + cache, "alpha"},
				{"rpm2cpio", cache + "/alpha-1.rpm"},
				{"cpio", "-i", "--quiet", "--to-stdout", "./etc/one"},
				{"diff", "-u", "--label", "A /etc/one", "--from-file=-", "--label", "B /etc/one", "/etc/one"},
				{"rpm2cpio", cache + "/alpha-1.rpm"},
				{"cpio", "-i", "--quiet", "--to-stdout", "./etc/two"},
				{"diff", "-u", "--label", "A /etc/two", "--from-file=-", "--label", "B /etc/two", "/etc/two"},
				{"rpm2cpio", cache + "/alpha-1.rpm"},
				{"cpio", "-i", "--quiet", "--to-stdout", "./etc/one"},
				{"diff", "-u", "--label", "A /etc/one", "--from-file=-", "--label", "B /etc/one", "/etc/one"},
			}
			if gotArgv := yumDiffArgv(runner.commands); !reflect.DeepEqual(gotArgv, wantArgv) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, wantArgv)
			}
			for _, command := range runner.commands {
				if command.Shell {
					t.Fatalf("shell command=%#v", command)
				}
				if command.Name == "rpm2cpio" || command.Name == "cpio" || command.Name == "diff" {
					if command.MaxStdoutBytes != yumDiffOutputLimit || command.MaxStderrBytes != yumDiffOutputLimit {
						t.Fatalf("unbounded helper=%#v", command)
					}
				}
			}
			if !reflect.DeepEqual(runner.availabilityCalls, []string{"rpm2cpio", "cpio", "diff", "yumdownloader"}) {
				t.Fatalf("availability=%v", runner.availabilityCalls)
			}
		})
	}
}

func TestYumDiffUnownedUsesStatAndLstatSourceResults(t *testing.T) {
	rt, fsys, runner := newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/present", []byte("x"))
	if err := fsys.MemoryFS.Symlink("/present", "/linked"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.MemoryFS.Symlink("/missing-target", "/broken"); err != nil {
		t.Fatal(err)
	}
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name != "rpm" {
			t.Fatalf("unexpected command=%#v", command)
		}
		return process.CommandResult{ExitCode: 1}
	}
	paths := []string{"/present", "/linked", "/broken", "/missing"}
	got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": paths})
	want := map[string]any{"/present": "Not managed", "/linked": "Not managed", "/broken": "N/A", "/missing": "N/A"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(runner.commands) != len(paths) || len(fsys.lstats) == 0 || len(fsys.stats) == 0 || len(runner.availabilityCalls) != 0 || len(fsys.mkdirs) != 0 {
		t.Fatalf("commands=%d lstat=%v stat=%v availability=%v mkdirs=%v", len(runner.commands), fsys.lstats, fsys.stats, runner.availabilityCalls, fsys.mkdirs)
	}
}

func TestYumDiffRejectsUnsafeInputsBeforeDownload(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"relative", []string{"relative"}},
		{"traversal", []string{"/etc/../passwd"}},
		{"control", []string{"/etc/a\nb"}},
		{"backslash", []string{"/etc/a\\b"}},
		{"oversize", []string{"/" + strings.Repeat("a", yumDiffPathLimit)}},
		{"too many", make([]string, yumDiffMaxPaths+1)},
		{"wrong list", []any{"/etc/file"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDiffRuntime()
			got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": tc.value})
			if got != nil || err == nil || len(runner.commands) != 0 || len(fsys.mkdirs) != 0 || len(runner.availabilityCalls) != 0 {
				t.Fatalf("got=%#v err=%v commands=%d mkdirs=%v availability=%v", got, err, len(runner.commands), fsys.mkdirs, runner.availabilityCalls)
			}
		})
	}

	rt, fsys, runner := newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("x"))
	runner.run = func(_ context.Context, _ process.Command) process.CommandResult {
		return process.CommandResult{Stdout: []byte("alpha\nbeta")}
	}
	got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || err == nil || len(runner.commands) != 1 || len(runner.availabilityCalls) != 0 || len(fsys.mkdirs) != 0 {
		t.Fatalf("multiple owner got=%#v err=%v commands=%d availability=%v mkdirs=%v", got, err, len(runner.commands), runner.availabilityCalls, fsys.mkdirs)
	}

	rt, fsys, runner = newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/target", []byte("x"))
	if err := fsys.MemoryFS.Symlink("/target", "/etc-link"); err != nil {
		t.Fatal(err)
	}
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name == "rpm" {
			return process.CommandResult{Stdout: []byte("alpha")}
		}
		t.Fatalf("unsafe symlink reached helper=%#v", command)
		return process.CommandResult{}
	}
	got, err = callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc-link"}})
	if got != nil || err == nil || len(runner.commands) != 1 || len(runner.availabilityCalls) != 0 || len(fsys.mkdirs) != 0 {
		t.Fatalf("symlink got=%#v err=%v commands=%d availability=%v mkdirs=%v", got, err, len(runner.commands), runner.availabilityCalls, fsys.mkdirs)
	}
}

func TestYumDiffHelperAvailabilityAndTestModeAvoidMutations(t *testing.T) {
	rt, fsys, runner := newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("x"))
	runner.available["rpm2cpio"] = false
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name != "rpm" {
			t.Fatalf("missing helper reached %q", command.Name)
		}
		return process.CommandResult{Stdout: []byte("alpha")}
	}
	got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || err == nil || err.Error() != "'rpm2cpio' command not available" || len(runner.commands) != 1 || len(fsys.mkdirs) != 0 {
		t.Fatalf("missing helper got=%#v err=%v commands=%d mkdirs=%v", got, err, len(runner.commands), fsys.mkdirs)
	}

	fsys = newYumDiffFS()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("x"))
	noAvailability := &yumDiffNoAvailabilityRunner{}
	got, err = callYumDiff(context.Background(), "yum", &runtime.Runtime{FS: fsys, Runner: noAvailability}, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || err == nil || err.Error() != "'rpm2cpio' command not available" || len(noAvailability.commands) != 1 || len(fsys.mkdirs) != 0 {
		t.Fatalf("missing capability got=%#v err=%v commands=%d mkdirs=%v", got, err, len(noAvailability.commands), fsys.mkdirs)
	}

	rt, fsys, runner = newYumDiffRuntime()
	rt.Options.Test = true
	got, err = callYumDiff(context.Background(), "dnf5", rt, map[string]any{"paths": []string{"/etc/file"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 || len(runner.availabilityCalls) != 0 || len(fsys.lstats) != 0 || len(fsys.mkdirs) != 0 {
		t.Fatalf("test mode got=%#v err=%v commands=%d availability=%v fs=%v/%v", got, err, len(runner.commands), runner.availabilityCalls, fsys.lstats, fsys.mkdirs)
	}
}

func TestYumDiffDownloadFailuresAndPipelineFailures(t *testing.T) {
	downloadSentinel := errors.New("download failed")
	for _, tc := range []struct {
		name           string
		writeRPM       bool
		downloadResult process.CommandResult
		wantErr        error
	}{
		{"download runner", false, process.CommandResult{Err: downloadSentinel}, downloadSentinel},
		{"download output", false, process.CommandResult{StdoutTruncated: true}, process.ErrOutputLimit},
		{"no download result", false, process.CommandResult{}, nil},
		{"partial download", true, process.CommandResult{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDiffRuntime()
			writeYumDiffFile(t, fsys, "/etc/a", []byte("a"))
			writeYumDiffFile(t, fsys, "/etc/b", []byte("b"))
			cache := "/var/cache/yum/packages"
			runner.run = func(_ context.Context, command process.Command) process.CommandResult {
				switch command.Name {
				case "rpm":
					if command.Args[len(command.Args)-1] == "/etc/a" {
						return process.CommandResult{Stdout: []byte("alpha")}
					}
					return process.CommandResult{Stdout: []byte("beta")}
				case "yumdownloader":
					if tc.writeRPM {
						writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
					}
					return tc.downloadResult
				default:
					t.Fatalf("download failure reached %q", command.Name)
					return process.CommandResult{}
				}
			}
			got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/a", "/etc/b"}})
			if got != nil || err == nil || len(runner.commands) != 3 {
				t.Fatalf("got=%#v err=%v commands=%#v", got, err, yumDiffArgv(runner.commands))
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v does not wrap %v", err, tc.wantErr)
			}
		})
	}

	rt, fsys, runner := newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("current"))
	cache := "/var/cache/yum/packages"
	sentinel := errors.New("rpm2cpio failed")
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		switch command.Name {
		case "rpm":
			return process.CommandResult{Stdout: []byte("alpha")}
		case "yumdownloader":
			writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
			return process.CommandResult{}
		case "rpm2cpio":
			return process.CommandResult{Err: sentinel}
		default:
			t.Fatalf("runner failure reached %q", command.Name)
			return process.CommandResult{}
		}
	}
	got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 3 {
		t.Fatalf("runner failure got=%#v err=%v commands=%#v", got, err, yumDiffArgv(runner.commands))
	}

	rt, fsys, runner = newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("current"))
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		switch command.Name {
		case "rpm":
			return process.CommandResult{Stdout: []byte("alpha")}
		case "yumdownloader":
			writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
			return process.CommandResult{}
		case "rpm2cpio":
			return process.CommandResult{StdoutTruncated: true}
		default:
			t.Fatalf("output limit reached %q", command.Name)
			return process.CommandResult{}
		}
	}
	got, err = callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.commands) != 3 {
		t.Fatalf("output limit got=%#v err=%v commands=%#v", got, err, yumDiffArgv(runner.commands))
	}

	rt, fsys, runner = newYumDiffRuntime()
	writeYumDiffFile(t, fsys, "/etc/file", []byte("current"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner.run = func(_ context.Context, command process.Command) process.CommandResult {
		switch command.Name {
		case "rpm":
			return process.CommandResult{Stdout: []byte("alpha")}
		case "yumdownloader":
			writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
			return process.CommandResult{}
		case "rpm2cpio":
			cancel()
			return process.CommandResult{Stdout: []byte("archive")}
		default:
			t.Fatalf("cancellation reached %q", command.Name)
			return process.CommandResult{}
		}
	}
	got, err = callYumDiff(ctx, "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 3 {
		t.Fatalf("canceled got=%#v err=%v commands=%#v", got, err, yumDiffArgv(runner.commands))
	}
}

func TestYumDiffDiffResultSemanticsAndUnsupportedProviders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  process.CommandResult
		want    string
		wantErr bool
	}{
		{"changed", process.CommandResult{ExitCode: 1, Stdout: []byte("--- A\n+++ B\n")}, "--- A\n+++ B\n", false},
		{"unchanged", process.CommandResult{}, "Unchanged", false},
		{"binary", process.CommandResult{ExitCode: 1, Stdout: []byte("Binary file A and B differ\n")}, "File '/etc/file' is binary and its content has been modified.", false},
		{"nonzero", process.CommandResult{ExitCode: 2}, "", true},
		{"empty changed", process.CommandResult{ExitCode: 1}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newYumDiffRuntime()
			writeYumDiffFile(t, fsys, "/etc/file", []byte("current"))
			cache := "/var/cache/yum/packages"
			runner.run = func(_ context.Context, command process.Command) process.CommandResult {
				switch command.Name {
				case "rpm":
					return process.CommandResult{Stdout: []byte("alpha")}
				case "yumdownloader":
					writeYumDiffFile(t, fsys, cache+"/alpha-1.rpm", []byte("rpm"))
					return process.CommandResult{}
				case "rpm2cpio":
					return process.CommandResult{Stdout: []byte("archive")}
				case "cpio":
					return process.CommandResult{Stdout: []byte("original")}
				case "diff":
					return tc.result
				}
				t.Fatalf("unexpected command=%#v", command)
				return process.CommandResult{}
			}
			got, err := callYumDiff(context.Background(), "yum", rt, map[string]any{"paths": []string{"/etc/file"}})
			if tc.wantErr {
				if got != nil || err == nil {
					t.Fatalf("got=%#v err=%v", got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/file": tc.want}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		spec spec
	}{
		{"apt", aptSpec}, {"zypper", zypperSpec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumDiffRunner{}
			got, err := (&commandProvider{spec: tc.spec}).Yum(context.Background(), &runtime.Runtime{Runner: runner, FS: newYumDiffFS()}, "diff", map[string]any{"paths": []string{"/etc/file"}})
			var unsupported *runtime.UnsupportedError
			if got != nil || !errors.As(err, &unsupported) || unsupported.Kind != "provider" || unsupported.Name != tc.name || len(runner.commands) != 0 {
				t.Fatalf("got=%#v err=%T %v calls=%d", got, err, err, len(runner.commands))
			}
		})
	}
}
