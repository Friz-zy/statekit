//go:build linux

package file

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type longtailRunner struct{ calls []process.Command }

func (r *longtailRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	return process.CommandResult{ExitCode: 0, Stdout: []byte("grep output\n")}
}

func longtailRuntime(t *testing.T) (*runtime.Runtime, *longtailRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/tmp/r4/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/tmp/r4/a.txt", []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/tmp/r4/sub/b.log", []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &longtailRunner{}
	return &runtime.Runtime{Exec: runtime.NewExecRegistry(), FS: fs, Runner: runner}, runner
}

func TestLongtailFindGrepAndUsage(t *testing.T) {
	rt, runner := longtailRuntime(t)
	res, err := findFunc{}.Execute(context.Background(), rt, &findArgs{Path: "/tmp/r4", Kwargs: map[string]any{"name": "*.txt"}})
	if err != nil || len(res.([]string)) != 1 || res.([]string)[0] != "/tmp/r4/a.txt" {
		t.Fatalf("find = %v %v", res, err)
	}
	res, err = containsGlobFunc{}.Execute(context.Background(), rt, &containsGlobArgs{Path: "/tmp/r4/a.txt", GlobExpr: "a*"})
	if err != nil || res != true {
		t.Fatalf("contains glob = %v %v", res, err)
	}
	res, err = grepFunc{}.Execute(context.Background(), rt, &grepArgs{Path: "/tmp/r4/*.txt", Pattern: "alpha", Opts: []any{"-n"}})
	if err != nil || res.(map[string]any)["retcode"] != 0 || len(runner.calls) != 1 {
		t.Fatalf("grep = %v %v calls=%v", res, err, runner.calls)
	}
	res, err = diskusageFunc{}.Execute(context.Background(), rt, &diskusageArgs{Path: "/tmp/r4"})
	if err != nil || res.(int64) != int64(len("alpha\nbeta\n")+len("beta\n")) {
		t.Fatalf("diskusage = %v %v", res, err)
	}
}

func TestLongtailLinePsedMove(t *testing.T) {
	rt, _ := longtailRuntime(t)
	res, err := lineFunc{}.Execute(context.Background(), rt, &lineArgs{Path: "/tmp/r4/a.txt", Content: stringPtrLong("gamma"), Mode: stringPtrLong("ensure"), ShowChanges: boolPtrLong(false)})
	if err != nil || res != true {
		t.Fatalf("line = %v %v", res, err)
	}
	res, err = psedFunc{}.Execute(context.Background(), rt, &psedArgs{Path: "/tmp/r4/a.txt", Before: "gamma", After: "delta", Flags: stringPtrLong("g"), Backup: stringPtrLong("")})
	if err != nil || res != true {
		t.Fatalf("psed = %v %v", res, err)
	}
	data, _ := rt.FS.ReadFile("/tmp/r4/a.txt")
	if !strings.Contains(string(data), "delta") {
		t.Fatalf("psed data = %q", data)
	}
	res, err = moveFunc{}.Execute(context.Background(), rt, &moveArgs{Src: "/tmp/r4/a.txt", Dst: "/tmp/r4/moved.txt"})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("move = %v %v", res, err)
	}
	if _, err := rt.FS.Stat("/tmp/r4/moved.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestLongtailBackupsAndBoundaries(t *testing.T) {
	rt, _ := longtailRuntime(t)
	stamp := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	name := fmt.Sprintf("a.txt_%s_%06d_%04d", stamp.Format("Mon_Jan_02_15:04:05"), stamp.Nanosecond()/1000, stamp.Year())
	backup := ".statekit/file_backup/tmp/r4/" + name
	if err := rt.FS.MkdirAll(".statekit/file_backup/tmp/r4", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(backup, []byte("backup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := listBackupsFunc{}.Execute(context.Background(), rt, &backupListArgs{Path: "/tmp/r4/a.txt"})
	if err != nil || len(res.(map[int]map[string]any)) != 1 {
		t.Fatalf("backups = %v %v", res, err)
	}
	res, err = restoreBackupFunc{}.Execute(context.Background(), rt, &backupIDArgs{Path: "/tmp/r4/a.txt", BackupID: 0})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("restore = %v %v", res, err)
	}
	data, _ := rt.FS.ReadFile("/tmp/r4/a.txt")
	if string(data) != "backup\n" {
		t.Fatalf("restored = %q", data)
	}
	res, err = deleteBackupFunc{}.Execute(context.Background(), rt, &backupIDArgs{Path: "/tmp/r4/a.txt", BackupID: 0})
	if err != nil || res.(map[string]any)["result"] != true {
		t.Fatalf("delete backup = %v %v", res, err)
	}
	res, err = applyTemplateOnContents("x", "")
	if err != nil || res != "x" {
		t.Fatalf("empty template = %v %v", res, err)
	}
	_, err = applyTemplateOnContents("x", "jinja")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("template boundary = %v", err)
	}
}

func TestLongtailStatvfsAndMissingOpenFiles(t *testing.T) {
	rt, _ := longtailRuntime(t)
	res, err := statvfsFunc{}.Execute(context.Background(), rt, &statvfsArgs{Path: "/tmp"})
	if err != nil || res.(map[string]any)["f_bsize"] == nil {
		t.Fatalf("statvfs = %v %v", res, err)
	}
	res, err = openFilesFunc{}.Execute(context.Background(), rt, &openFilesArgs{})
	if err != nil || res == nil {
		t.Fatalf("open files = %v %v", res, err)
	}
}

func stringPtrLong(value string) *string { return &value }
func boolPtrLong(value bool) *bool       { return &value }
