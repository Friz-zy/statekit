package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperDiffDownloadXML = `<stream><download-result>` +
	`<repository name="OSS" alias="repo-oss"/>` +
	`<localfile path="/var/cache/zypp/packages/alpha-1.0.x86_64.rpm"/>` +
	`<name>alpha</name>` +
	`</download-result></stream>`

func zypperDiffRuntime(run func(context.Context, process.Command) process.CommandResult) (*runtime.Runtime, *yumDiffRunner, *runtime.MemoryFS) {
	runner := &yumDiffRunner{
		available: map[string]bool{"rpm2cpio": true, "cpio": true, "diff": true},
		run:       run,
	}
	fsys := runtime.NewMemoryFS()
	return &runtime.Runtime{Runner: runner, FS: fsys}, runner, fsys
}

// zypperDiffStage answers each pipeline stage deterministically: ownership,
// the zypper download XML, the checksum probe, and the rpm2cpio/cpio/diff
// stages of the shared rpm_lowpkg.diff port.
func zypperDiffStage(_ context.Context, command process.Command) process.CommandResult {
	if zypperDiffIsOwnerQuery(command) {
		return process.CommandResult{Stdout: []byte("alpha")}
	}
	switch command.Name {
	case "rpm":
		return process.CommandResult{ExitCode: 0}
	case "zypper":
		return process.CommandResult{Stdout: []byte(zypperDiffDownloadXML)}
	case "rpm2cpio":
		return process.CommandResult{Stdout: []byte("ARCHIVE")}
	case "cpio":
		return process.CommandResult{Stdout: []byte("original one")}
	case "diff":
		return process.CommandResult{ExitCode: 1, Stdout: []byte("--- a\n+++ b\n")}
	}
	return process.CommandResult{}
}

// zypperDiffIsOwnerQuery recognizes rpm -qf regardless of a --root prefix.
func zypperDiffIsOwnerQuery(command process.Command) bool {
	if command.Name != "rpm" {
		return false
	}
	for _, arg := range command.Args {
		if arg == "-qf" {
			return true
		}
	}
	return false
}

func zypperDiffStageWithOwner(owner string) func(context.Context, process.Command) process.CommandResult {
	return func(ctx context.Context, command process.Command) process.CommandResult {
		if zypperDiffIsOwnerQuery(command) {
			return process.CommandResult{Stdout: []byte(owner)}
		}
		return zypperDiffStage(ctx, command)
	}
}

func writeZypperDiffFile(t *testing.T, fsys *runtime.MemoryFS, name string, data []byte) {
	t.Helper()
	dir := "/"
	if index := strings.LastIndexByte(name, '/'); index > 0 {
		dir = name[:index]
	}
	if err := fsys.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestZypperDiffOwnerlessPathsReportNotManagedAndNA(t *testing.T) {
	rt, runner, fsys := zypperDiffRuntime(func(_ context.Context, command process.Command) process.CommandResult {
		return process.CommandResult{Stdout: []byte("file is not owned by any package")}
	})
	writeZypperDiffFile(t, fsys, "/etc/present", []byte("data"))

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/present", "/etc/gone"}})
	want := map[string]any{"/etc/present": "Not managed", "/etc/gone": "N/A"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands=%d", len(runner.commands))
	}
	for _, command := range runner.commands {
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unsafe command=%#v", command)
		}
	}
}

func TestZypperDiffOwnedPathRunsSharedRPMDiffPipeline(t *testing.T) {
	rt, runner, fsys := zypperDiffRuntime(zypperDiffStage)
	writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
	writeZypperDiffFile(t, fsys, "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm", []byte("rpm"))

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"/etc/one": "--- a\n+++ b\n"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v", got)
	}
	wantArgv := [][]string{
		{"rpm", "-qf", "--queryformat", "%{name}", "/etc/one"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "download", "alpha"},
		{"rpm", "-K", "--quiet", "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm"},
		{"rpm2cpio", "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm"},
		{"cpio", "-i", "--quiet", "--to-stdout", "./etc/one"},
		{"diff", "-u", "--label", "A /etc/one", "--from-file=-", "--label", "B /etc/one", "/etc/one"},
	}
	if len(runner.commands) != len(wantArgv) {
		t.Fatalf("commands=%#v", runner.commands)
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), wantArgv[i])
		}
	}
}

func TestZypperDiffUnchangedAndBinarySentinels(t *testing.T) {
	fsysSetup := func(t *testing.T, fsys *runtime.MemoryFS) {
		writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
		writeZypperDiffFile(t, fsys, "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm", []byte("rpm"))
	}

	rt, _, fsys := zypperDiffRuntime(func(ctx context.Context, command process.Command) process.CommandResult {
		if command.Name == "diff" {
			return process.CommandResult{ExitCode: 0}
		}
		return zypperDiffStage(ctx, command)
	})
	fsysSetup(t, fsys)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/one": "Unchanged"}) {
		t.Fatalf("unchanged got=%#v err=%v", got, err)
	}

	rt, _, fsys = zypperDiffRuntime(func(ctx context.Context, command process.Command) process.CommandResult {
		if command.Name == "diff" {
			return process.CommandResult{ExitCode: 1, Stdout: []byte("Binary file /etc/one differs\n")}
		}
		return zypperDiffStage(ctx, command)
	})
	fsysSetup(t, fsys)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/one": "File '/etc/one' is binary and its content has been modified."}) {
		t.Fatalf("binary got=%#v err=%v", got, err)
	}
}

func TestZypperDiffGroupsPathsByPackageAndKeepsOrder(t *testing.T) {
	rt, runner, fsys := zypperDiffRuntime(zypperDiffStageWithOwner("alpha"))
	writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
	writeZypperDiffFile(t, fsys, "/etc/two", []byte("current two"))
	writeZypperDiffFile(t, fsys, "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm", []byte("rpm"))

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one", "/etc/two"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.(map[string]any)) != 2 {
		t.Fatalf("got=%#v", got)
	}
	// One download for the single owning package; the diff stages run in
	// path order: /etc/one before /etc/two.
	diffs := 0
	for _, command := range runner.commands {
		if command.Name == "diff" {
			diffs++
			want := "/etc/one"
			if diffs == 2 {
				want = "/etc/two"
			}
			if command.Args[len(command.Args)-1] != want {
				t.Fatalf("diff order %d got %q", diffs, command.Args[len(command.Args)-1])
			}
		}
	}
	if diffs != 2 {
		t.Fatalf("diff stages=%d", diffs)
	}
	downloads := 0
	for _, command := range runner.commands {
		if command.Name == "zypper" {
			downloads++
		}
	}
	if downloads != 1 {
		t.Fatalf("downloads=%d", downloads)
	}
}

func TestZypperDiffRootFlowsToOwnerAndDownload(t *testing.T) {
	root := "/target"
	rt, runner, fsys := zypperDiffRuntime(zypperDiffStage)
	writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
	writeZypperDiffFile(t, fsys, "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm", []byte("rpm"))

	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}, "root": &root}); err != nil {
		t.Fatal(err)
	}
	wantArgv := [][]string{
		{"rpm", "--root", root, "-qf", "--queryformat", "%{name}", "/etc/one"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "download", "alpha"},
		{"rpm", "--root", root, "-K", "--quiet", "/var/cache/zypp/packages/alpha-1.0.x86_64.rpm"},
	}
	if len(runner.commands) < len(wantArgv) {
		t.Fatalf("commands=%#v", runner.commands)
	}
	for i, want := range wantArgv {
		if !reflect.DeepEqual(zypperCommandArgs(runner.commands[i]), want) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(runner.commands[i]), want)
		}
	}
}

func TestZypperDiffDownloadFailuresSurfaceAsErrors(t *testing.T) {
	writeFiles := func(t *testing.T, fsys *runtime.MemoryFS) {
		writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
	}

	rt, _, fsys := zypperDiffRuntime(zypperDiffStageWithOwner("alpha"))
	rt.Runner.(*yumDiffRunner).run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name == "zypper" {
			return process.CommandResult{Stdout: []byte(`<stream/>`)}
		}
		return zypperDiffStage(context.Background(), command)
	}
	writeFiles(t, fsys)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	var downloadFailure *yumDiffFailure
	if got != nil || err == nil || !errors.As(err, &downloadFailure) || downloadFailure.stage != "package download" {
		t.Fatalf("no results got=%#v err=%v", got, err)
	}

	const partialXML = `<stream><download-result><repository name="r" alias="a"/><localfile path="/var/cache/zypp/packages/beta.rpm"/><name>beta</name></download-result></stream>`
	rt, _, fsys = zypperDiffRuntime(zypperDiffStageWithOwner("alpha"))
	rt.Runner.(*yumDiffRunner).run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name == "zypper" {
			return process.CommandResult{Stdout: []byte(partialXML)}
		}
		return zypperDiffStage(context.Background(), command)
	}
	writeFiles(t, fsys)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if got != nil || err == nil || err.Error() != "pkg.diff package download was incomplete" {
		t.Fatalf("partial got=%#v err=%v", got, err)
	}

	// A relative localfile cannot be validated for the rpm2cpio stage.
	const relativeXML = `<stream><download-result><repository name="r" alias="a"/><localfile path="var/cache/zypp/packages/alpha.rpm"/><name>alpha</name></download-result></stream>`
	rt, _, fsys = zypperDiffRuntime(zypperDiffStageWithOwner("alpha"))
	rt.Runner.(*yumDiffRunner).run = func(_ context.Context, command process.Command) process.CommandResult {
		if command.Name == "zypper" {
			return process.CommandResult{Stdout: []byte(relativeXML)}
		}
		return zypperDiffStage(context.Background(), command)
	}
	writeFiles(t, fsys)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if got != nil || err == nil || err.Error() != "pkg.diff downloaded package is unsafe" {
		t.Fatalf("relative got=%#v err=%v", got, err)
	}
}

func TestZypperDiffRejectsInvalidOwnerResult(t *testing.T) {
	rt, runner, fsys := zypperDiffRuntime(zypperDiffStageWithOwner("two tokens"))
	writeZypperDiffFile(t, fsys, "/etc/one", []byte("current one"))
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if got != nil || err == nil || err.Error() != "pkg.diff owner result is invalid" || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperDiffBoundariesAndBadArguments(t *testing.T) {
	// Empty path list is the source's empty result.
	rt, runner, _ := zypperDiffRuntime(zypperDiffStage)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 {
		t.Fatalf("empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// Missing helpers stop after the owner lookup, before any download.
	rt, _, fsys := zypperDiffRuntime(zypperDiffStageWithOwner("alpha"))
	noHelpers := &yumDiffRunner{run: zypperDiffStageWithOwner("alpha")}
	rt.Runner = noHelpers
	writeZypperDiffFile(t, fsys, "/etc/one", []byte("x"))
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if got != nil || err == nil || len(noHelpers.commands) != 1 {
		t.Fatalf("helpers got=%#v err=%v calls=%d", got, err, len(noHelpers.commands))
	}

	// Test mode returns before owner lookup.
	rt, runner, _ = zypperDiffRuntime(zypperDiffStage)
	rt.Options.Test = true
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 {
		t.Fatalf("test got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	// A canceled context never reaches the runner.
	rt, runner, _ = zypperDiffRuntime(zypperDiffStage)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = zypperLowpkgProvider().Zypper(ctx, rt, "diff", map[string]any{"paths": []string{"/etc/one"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	for _, args := range []map[string]any{
		{"paths": "not-a-list"},
		{"paths": []string{"/etc/one"}, "other": true},
		{"paths": []string{"bad\npath"}},
		{"paths": []string{"/etc/one"}, "root": 7},
	} {
		rt, runner, _ := zypperDiffRuntime(zypperDiffStage)
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "diff", args)
		if got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.commands))
		}
	}
}
