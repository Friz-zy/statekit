package archive

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func testRT() *runtime.Runtime {
	return &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
}

func TestTarCreateExtractRoundtrip(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/work/src/sub", 0o755)
	rt.FS.WriteFile("/work/src/a.txt", []byte("alpha"), 0o644)
	rt.FS.WriteFile("/work/src/sub/b.txt", []byte("beta"), 0o600)

	value, err := tarFunc{}.Execute(context.Background(), rt, &tarArgs{
		Tarfile: "/work/out.tar", Sources: []string{"src"}, Cwd: "/work",
	})
	if err != nil {
		t.Fatalf("tar create: %v", err)
	}
	names := value.([]string)
	if len(names) != 2 || names[0] != "src/a.txt" {
		t.Fatalf("added = %v", names)
	}

	rt2 := testRT()
	tarData, _ := rt.FS.ReadFile("/work/out.tar")
	rt2.FS.MkdirAll("/work", 0o755)
	rt2.FS.WriteFile("/work/out.tar", tarData, 0o644)
	extracted, err := tarFunc{}.Execute(context.Background(), rt2, &tarArgs{
		Options: "x", Tarfile: "/work/out.tar", Dest: "/restore", Cwd: "/work",
	})
	if err != nil {
		t.Fatalf("untar: %v", err)
	}
	if !strings.Contains(strings.Join(extracted.([]string), ","), "sub/b.txt") {
		t.Fatalf("extracted list = %v", extracted)
	}
	aData, err := rt2.FS.ReadFile("/restore/src/a.txt")
	if err != nil || string(aData) != "alpha" {
		t.Fatalf("restored a.txt = %q, %v", aData, err)
	}
	bInfo, _ := rt2.FS.Stat("/restore/src/sub/b.txt")
	if bInfo.Mode().Perm() != 0o600 {
		t.Fatalf("mode not restored: %v", bInfo.Mode())
	}
}

func TestTarListAndGzip(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/work", 0o755)
	rt.FS.WriteFile("/work/f", []byte("data"), 0o644)
	tarFunc{}.Execute(context.Background(), rt, &tarArgs{
		Tarfile: "/work/t.tar.gz", Sources: []string{"f"}, Cwd: "/work", Options: "czf",
	})
	listing, err := tarFunc{}.Execute(context.Background(), rt, &tarArgs{
		Options: "t", Tarfile: "/work/t.tar.gz", Cwd: "/work",
	})
	if err != nil {
		t.Fatalf("list gzipped tar: %v", err)
	}
	if strings.Join(listing.([]string), ",") != "f" {
		t.Fatalf("listing = %v", listing)
	}
}

func TestGzipGunzip(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/d", 0o755)
	rt.FS.WriteFile("/d/file", []byte("payload"), 0o644)

	if _, err := (gzipFunc{}).Execute(context.Background(), rt, &gzipArgs{Sourcefile: "/d/file"}); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if _, err := rt.FS.Stat("/d/file.gz"); err != nil {
		t.Fatal(".gz file missing")
	}
	value, err := gunzipFunc{}.Execute(context.Background(), rt, &gunzipArgs{Gzipfile: "/d/file.gz"})
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if value.([]string)[0] != "/d/file" {
		t.Fatalf("gunzip target = %v", value)
	}
	back, _ := rt.FS.ReadFile("/d/file")
	if string(back) != "payload" {
		t.Fatalf("roundtrip content = %q", back)
	}
}

func TestZipUnzip(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/z/in", 0o755)
	rt.FS.WriteFile("/z/in/x", []byte("ex"), 0o644)
	rt.FS.WriteFile("/z/y", []byte("why"), 0o644)

	if _, err := (zipFunc{}).Execute(context.Background(), rt, &zipArgs{
		ZipFile: "/z/a.zip", Sources: []string{"in/x", "y"}, Cwd: "/z",
	}); err != nil {
		t.Fatalf("zip: %v", err)
	}

	rt2 := testRT()
	zipData, _ := rt.FS.ReadFile("/z/a.zip")
	rt2.FS.MkdirAll("/z", 0o755)
	rt2.FS.WriteFile("/z/a.zip", zipData, 0o644)
	value, err := unzipFunc{}.Execute(context.Background(), rt2, &unzipArgs{ZipFile: "/z/a.zip", Dest: "/out"})
	if err != nil {
		t.Fatalf("unzip: %v", err)
	}
	got := strings.Join(value.([]string), ",")
	if got != "in/x,y" {
		t.Fatalf("unzip entries = %q", got)
	}
	x, _ := rt2.FS.ReadFile("/out/in/x")
	y, _ := rt2.FS.ReadFile("/out/y")
	if string(x) != "ex" || string(y) != "why" {
		t.Fatalf("zip roundtrip data wrong: %q %q", x, y)
	}
}
