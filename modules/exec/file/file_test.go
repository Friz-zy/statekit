package file

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func testRT() *runtime.Runtime {
	return &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
}

func TestExistsChecks(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/passwd", []byte("data"), 0o644)

	value, err := (fileExistsFunc{}).Execute(context.Background(), rt, &fileExistsArgs{Path: "/etc/passwd"})
	if err != nil || value != true {
		t.Fatalf("file_exists = %v, %v", value, err)
	}
	value, _ = (directoryExistsFunc{}).Execute(context.Background(), rt, &directoryExistsArgs{Path: "/etc"})
	if value != true {
		t.Fatalf("directory_exists = %v", value)
	}
	value, _ = (fileExistsFunc{}).Execute(context.Background(), rt, &fileExistsArgs{Path: "/etc"})
	if value != false {
		t.Fatal("directories are not files")
	}
}

func TestRemoveRequiresAbsolutePath(t *testing.T) {
	if _, err := (removeFunc{}).Execute(context.Background(), testRT(), &removeArgs{Path: "relative/path"}); err == nil {
		t.Fatal("relative paths must be rejected like Salt")
	}
}

func TestRemoveRemovesAndReportsMissing(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/tmp/x/deep", 0o755)
	rt.FS.WriteFile("/tmp/x/deep/f", []byte("d"), 0o644)

	value, err := (removeFunc{}).Execute(context.Background(), rt, &removeArgs{Path: "/tmp/x"})
	if err != nil || value != true {
		t.Fatalf("remove = %v, %v", value, err)
	}
	if _, statErr := rt.FS.Stat("/tmp/x"); statErr == nil {
		t.Fatal("subtree must be gone")
	}
	value, _ = (removeFunc{}).Execute(context.Background(), rt, &removeArgs{Path: "/tmp/missing"})
	if value != false {
		t.Fatalf("removing missing path must report false, got %v", value)
	}
}

func TestWriteReadAppendContains(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/srv", 0o755)
	(writeFunc{}).Execute(context.Background(), rt, &writeArgs{
		Path: "/srv/conf.txt", Content: "alpha\n", Mode: "0644",
	})
	value, err := (readFunc{}).Execute(context.Background(), rt, &readArgs{Path: "/srv/conf.txt"})
	if err != nil || value != "alpha\n" {
		t.Fatalf("read = %v, %v", value, err)
	}
	(appendFunc{}).Execute(context.Background(), rt, &appendArgs{Path: "/srv/conf.txt", Lines: []string{"beta"}})
	value, _ = (readFunc{}).Execute(context.Background(), rt, &readArgs{Path: "/srv/conf.txt"})
	if value != "alpha\nbeta\n" {
		t.Fatalf("append result = %q", value)
	}
	value, _ = (containsFunc{}).Execute(context.Background(), rt, &containsArgs{Path: "/srv/conf.txt", Text: "beta"})
	if value != true {
		t.Fatal("contains must find beta")
	}
	info, err := rt.FS.Stat("/srv/conf.txt")
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode not preserved: %v %v", info, err)
	}
}

func TestMkdirIdempotent(t *testing.T) {
	rt := testRT()
	for range [2]int{} {
		value, err := (mkdirFunc{}).Execute(context.Background(), rt, &mkdirArgs{DirPath: "/a/b/c", Mode: "0755"})
		if err != nil || value != true {
			t.Fatalf("mkdir = %v, %v", value, err)
		}
	}
	rt.FS.WriteFile("/taken", []byte("x"), 0o644)
	if _, err := (mkdirFunc{}).Execute(context.Background(), rt, &mkdirArgs{DirPath: "/taken"}); err == nil {
		t.Fatal("mkdir onto an existing file must fail")
	}
}

func TestTouchCreates(t *testing.T) {
	rt := testRT()
	if _, err := (touchFunc{}).Execute(context.Background(), rt, &touchNameArgs{Name: "/deep/dir/newfile"}); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if _, err := rt.FS.Stat("/deep/dir/newfile"); err != nil {
		t.Fatalf("touched file missing: %v", err)
	}
}

func TestCopyRecursive(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/src/sub", 0o755)
	rt.FS.WriteFile("/src/a", []byte("A"), 0o600)
	rt.FS.WriteFile("/src/sub/b", []byte("B"), 0o640)

	value, err := (copyFunc{}).Execute(context.Background(), rt, &copyArgs{Src: "/src", Dst: "/dst", Recurse: true})
	if err != nil || value != true {
		t.Fatalf("copy = %v, %v", value, err)
	}
	aData, _ := rt.FS.ReadFile("/dst/a")
	bData, _ := rt.FS.ReadFile("/dst/sub/b")
	if string(aData) != "A" || string(bData) != "B" {
		t.Fatalf("recursive copy lost data: %q %q", aData, bData)
	}
	info, _ := rt.FS.Stat("/dst/a")
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("copy did not preserve mode: %v", info.Mode())
	}
}

func TestStatsShape(t *testing.T) {
	rt := testRT()
	rt.FS.WriteFile("/f", []byte("12345"), 0o640)
	ret, err := (statsFunc{}).Execute(context.Background(), rt, &statsArgs{Path: "/f"})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	m := ret.(map[string]any)
	if m["size"].(int64) != 5 || m["mode"] != "0640" || m["type"] != "file" || m["isdir"] != false {
		t.Fatalf("stats shape wrong: %+v", m)
	}
}

func TestReadlinkCanonicalize(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/real", 0o755)
	rt.FS.WriteFile("/real/data", []byte("x"), 0o644)
	rt.FS.Symlink("/real/data", "/link1")
	rt.FS.Symlink("/link1", "/link2")

	value, err := (readlinkFunc{}).Execute(context.Background(), rt, &readlinkArgs{Path: "/link2"})
	if err != nil || value != "/link1" {
		t.Fatalf("readlink = %v, %v", value, err)
	}
	value, _ = (readlinkFunc{}).Execute(context.Background(), rt, &readlinkArgs{Path: "/link2", Canonicalize: true})
	if value != "/real/data" {
		t.Fatalf("canonicalized readlink = %v", value)
	}
}

func TestRename(t *testing.T) {
	rt := testRT()
	rt.FS.WriteFile("/old", []byte("x"), 0o644)
	value, err := (renameFunc{}).Execute(context.Background(), rt, &renameArgs{Src: "/old", Dst: "/new"})
	if err != nil || value != true {
		t.Fatalf("rename = %v, %v", value, err)
	}
	if _, err := rt.FS.Stat("/old"); err == nil {
		t.Fatal("source must be gone after rename")
	}
}
