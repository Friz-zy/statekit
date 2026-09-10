package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperDownloadedRuntime(results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner, *runtime.MemoryFS) {
	runner := &yumRecordingRunner{results: results}
	fsys := runtime.NewMemoryFS()
	return &runtime.Runtime{Runner: runner, FS: fsys}, runner, fsys
}

func writeZypperRPM(t *testing.T, fsys *runtime.MemoryFS, name string, data []byte) {
	t.Helper()
	if err := fsys.MkdirAll(dirOf(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dirOf(name string) string {
	if index := strings.LastIndexByte(name, '/'); index > 0 {
		return name[:index]
	}
	return "/"
}

func TestZypperListDownloadedWalksCacheAndDescribesRPMs(t *testing.T) {
	root := "/target"
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}
	rt, runner, fsys := zypperDownloadedRuntime(
		process.CommandResult{Stdout: []byte("bash_|-0_|-4.3_|-83.3.1_|-x86_64_|-none_|-0\n")},
		process.CommandResult{Stdout: []byte("vim_|-2_|-7.4_|-326_|-x86_64_|-none_|-0\n")},
	)
	writeZypperRPM(t, fsys, "/target/var/cache/zypp/packages/OSS/bash-4.3.rpm", []byte("rpm1"))
	writeZypperRPM(t, fsys, "/target/var/cache/zypp/packages/nested/vim-7.4.x86_64.rpm", []byte("rpm22"))
	writeZypperRPM(t, fsys, "/target/var/cache/zypp/packages/OSS/README.txt", []byte("skip"))

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", args)
	if err != nil {
		t.Fatal(err)
	}
	ret := got.(map[string]any)
	if len(ret) != 2 || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v args=%#v", ret, args)
	}
	bashVersions := ret["bash"].(map[string]any)
	if len(bashVersions) != 1 {
		t.Fatalf("bash=%#v", bashVersions)
	}
	bashMeta := bashVersions["4.3-83.3.1"].(map[string]any)
	if bashMeta["path"] != "/target/var/cache/zypp/packages/OSS/bash-4.3.rpm" || bashMeta["size"] != int64(4) {
		t.Fatalf("bash meta=%#v", bashMeta)
	}
	if ts, ok := bashMeta["creation_date_time_t"].(int64); !ok || ts == 0 {
		t.Fatalf("bash ctime=%#v", bashMeta["creation_date_time_t"])
	}
	stamp, ok := bashMeta["creation_date_time"].(string)
	if !ok {
		t.Fatalf("bash stamp=%#v", bashMeta["creation_date_time"])
	}
	// utcfromtimestamp(...).isoformat() without microseconds.
	if _, parseErr := time.Parse("2006-01-02T15:04:05", stamp); parseErr != nil {
		t.Fatalf("stamp=%q err=%v", stamp, parseErr)
	}
	vimMeta := ret["vim"].(map[string]any)["2:7.4-326"].(map[string]any)
	if vimMeta["path"] != "/target/var/cache/zypp/packages/nested/vim-7.4.x86_64.rpm" || vimMeta["size"] != int64(5) {
		t.Fatalf("vim meta=%#v", vimMeta)
	}
	wantArgv := [][]string{
		{"rpm", "-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}", "/target/var/cache/zypp/packages/OSS/bash-4.3.rpm"},
		{"rpm", "-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}", "/target/var/cache/zypp/packages/nested/vim-7.4.x86_64.rpm"},
	}
	if len(runner.commands) != len(wantArgv) {
		t.Fatalf("commands=%d want=%d", len(runner.commands), len(wantArgv))
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), wantArgv[i])
		}
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command[%d]=%#v", i, command)
		}
	}
}

func TestZypperListDownloadedDefaultCacheAndEmptyCache(t *testing.T) {
	rt, _, _ := zypperDownloadedRuntime()
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("missing cache got=%#v err=%v", got, err)
	}

	rt, runner, fsys := zypperDownloadedRuntime(process.CommandResult{Stdout: []byte("a_|-0_|-1_|-1_|-noarch_|-none_|-0\n")})
	writeZypperRPM(t, fsys, "/var/cache/zypp/packages/a-1.noarch.rpm", []byte("rpm"))
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if err != nil || len(got.(map[string]any)) != 1 {
		t.Fatalf("default cache got=%#v err=%v", got, err)
	}
	if argv := zypperCommandArgs(runner.commands[0]); argv[len(argv)-1] != "/var/cache/zypp/packages/a-1.noarch.rpm" {
		t.Fatalf("default argv=%v", argv)
	}
}

func TestZypperListDownloadedSkipsNonRegularAndSymlinks(t *testing.T) {
	rt, runner, fsys := zypperDownloadedRuntime(process.CommandResult{Stdout: []byte("real_|-0_|-1_|-1_|-noarch_|-none_|-0\n")})
	writeZypperRPM(t, fsys, "/var/cache/zypp/packages/real.rpm", []byte("rpm"))
	if err := fsys.Symlink("/var/cache/zypp/packages/real.rpm", "/var/cache/zypp/packages/link.rpm"); err != nil {
		t.Fatal(err)
	}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	versions := got.(map[string]any)["real"].(map[string]any)
	if len(versions) != 1 || len(runner.commands) != 1 {
		t.Fatalf("got=%#v calls=%d", got, len(runner.commands))
	}
	if _, exists := versions["1-1"]; !exists {
		t.Fatalf("versions=%#v", versions)
	}
}

func TestZypperListDownloadedDuplicateVersionsKeepWalkOrderWinner(t *testing.T) {
	rt, _, fsys := zypperDownloadedRuntime(
		process.CommandResult{Stdout: []byte("bash_|-0_|-4.3_|-83.3.1_|-x86_64_|-none_|-0\n")},
		process.CommandResult{Stdout: []byte("bash_|-0_|-4.3_|-83.3.1_|-x86_64_|-none_|-0\n")},
	)
	writeZypperRPM(t, fsys, "/var/cache/zypp/packages/a/bash.rpm", []byte("one"))
	writeZypperRPM(t, fsys, "/var/cache/zypp/packages/b/bash.rpm", []byte("three"))
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	meta := got.(map[string]any)["bash"].(map[string]any)["4.3-83.3.1"].(map[string]any)
	// BFS walk order visits a/ before b/, so the later record replaces the
	// earlier one exactly like the source's nested-dict assignment.
	if meta["path"] != "/var/cache/zypp/packages/b/bash.rpm" || meta["size"] != int64(5) {
		t.Fatalf("meta=%#v", meta)
	}
}

func TestZypperListDownloadedRejectsMalformedMetadataAndBadArgs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout string
	}{
		{"empty output", ""},
		{"missing fields", "garbage\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner, fsys := zypperDownloadedRuntime(process.CommandResult{Stdout: []byte(tc.stdout)})
			writeZypperRPM(t, fsys, "/var/cache/zypp/packages/x.rpm", []byte("rpm"))
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
			if got != nil || err == nil || len(runner.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}

	rt, runner, _ := zypperDownloadedRuntime()
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{"root": 7}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("bad root err=%v calls=%d", err, len(runner.commands))
	}
	rt, runner, _ = zypperDownloadedRuntime()
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{"other": true}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("unknown kwarg err=%v calls=%d", err, len(runner.commands))
	}
}

func TestZypperListDownloadedRequiresFilesystemAndRunner(t *testing.T) {
	rt, _ := zypperLowpkgRuntime()
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if got != nil || err == nil {
		t.Fatalf("nil fs got=%#v err=%v", got, err)
	}
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("err=%v", err)
	}

	rt = &runtime.Runtime{FS: runtime.NewMemoryFS()}
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_downloaded", map[string]any{})
	if got != nil || err == nil {
		t.Fatalf("nil runner got=%#v err=%v", got, err)
	}
}

func TestZypperListDownloadedCancelPropagates(t *testing.T) {
	cancelRunner := &zypperCancelRunner{}
	rt := &runtime.Runtime{Runner: cancelRunner, FS: runtime.NewMemoryFS()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_downloaded", map[string]any{})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}
}
