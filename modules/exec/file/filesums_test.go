package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// R4.2 tests mapped onto the file-module behaviors read from
// saltstack/salt/modules/file.py @ pinned revision.

func TestGetSumAndGetHash(t *testing.T) {
	content := "hello world\n"
	rt := xtRT(t, map[string]string{"/f": content})

	sumFn := getSumFunc{}
	got, _ := sumFn.Execute(context.Background(), rt, &getSumArgs{Path: "/f"})
	// sha256("hello world\n")
	want := "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
	if got != want {
		t.Fatalf("sha256 = %#v; want %s", got, want)
	}

	// Missing file returns the literal string, not an error.
	got, _ = sumFn.Execute(context.Background(), rt, &getSumArgs{Path: "/missing"})
	if got != "File not found" {
		t.Fatalf("missing get_sum = %#v", got)
	}

	// md5 form.
	md5 := "md5"
	got, _ = sumFn.Execute(context.Background(), rt, &getSumArgs{Path: "/f", Form: &md5})
	if got != "6f5902ac237024bdd0c176cb93063dc4" {
		t.Fatalf("md5 = %#v", got)
	}

	hashFn := getHashFunc{}
	got, err := hashFn.Execute(context.Background(), rt,
		&getHashArgs{Path: "/f", Form: &md5, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	if got != "6f5902ac237024bdd0c176cb93063dc4" {
		t.Fatalf("chunked hash = %#v", got)
	}

	badForm := "xyz"
	if _, err := hashFn.Execute(context.Background(), rt,
		&getHashArgs{Path: "/f", Form: &badForm}); err == nil ||
		err.Error() != "Invalid hash type: xyz" {
		t.Fatalf("invalid form error = %v", err)
	}
}

func TestCheckHash(t *testing.T) {
	rt := xtRT(t, map[string]string{"/f": "hello world\n"})
	fn := checkHashFunc{}

	// Bare sha256.
	got, err := fn.Execute(context.Background(), rt, &checkHashArgs{
		Path:     "/f",
		FileHash: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
	})
	if err != nil || got != true {
		t.Fatalf("bare check_hash = %#v, %v", got, err)
	}

	// Prefixed md5.
	got, err = fn.Execute(context.Background(), rt, &checkHashArgs{
		Path:     "/f",
		FileHash: "md5=6f5902ac237024bdd0c176cb93063dc4",
	})
	if err != nil || got != true {
		t.Fatalf("md5 check_hash = %#v, %v", got, err)
	}

	// Colon separator.
	got, err = fn.Execute(context.Background(), rt, &checkHashArgs{
		Path:     "/f",
		FileHash: "sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
	})
	if err != nil || got != true {
		t.Fatalf("colon check_hash = %#v, %v", got, err)
	}

	// Unsupported length raises the enumeration error rather than
	// returning a boolean (upstream raises SaltInvocationError).
	_, err = fn.Execute(context.Background(), rt, &checkHashArgs{
		Path: "/f", FileHash: "deadbeef",
	})
	if err == nil || !strings.Contains(err.Error(),
		"Hash deadbeef (length: 8) could not be matched") {
		t.Fatalf("deadbeef error = %v", err)
	}

	// Genuine mismatch with a valid length returns false.
	got, err = fn.Execute(context.Background(), rt, &checkHashArgs{
		Path:     "/f",
		FileHash: "md5=00000000000000000000000000000000",
	})
	if err != nil || got != false {
		t.Fatalf("mismatch = %#v, %v", got, err)
	}

	// Unsupported length raises the verbatim enumeration error.
	_, err = fn.Execute(context.Background(), rt, &checkHashArgs{
		Path: "/f", FileHash: "abc",
	})
	if err == nil || !strings.Contains(err.Error(),
		"could not be matched to a supported hash type") ||
		!strings.Contains(err.Error(), "md5 (32)") || !strings.Contains(err.Error(), "sha512 (128)") {
		t.Fatalf("unsupported-length error = %v", err)
	}
}

// Mirrors extract_hash over a sha256sums-style file with priority order.
func TestExtractHash(t *testing.T) {
	hashFile := strings.Join([]string{
		"# comment line",
		"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  hello.tar.gz",
		"6f5902ac237024bdd0c176cb93063dc4  other.tar.gz",
		"",
	}, "\n")
	rt := xtRT(t, map[string]string{"/hashes.txt": hashFile})

	fn := extractHashFunc{}

	// file_name match wins over source when no source_hash_name given.
	ret, err := fn.Execute(context.Background(), rt, &extractHashArgs{
		HashFn:   "/hashes.txt",
		FileName: strPtr("/tmp/hello.tar.gz"),
		Source:   strPtr("https://example.com/other.tar.gz"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dict := ret.(map[string]any)
	if dict["hsum"] != "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447" ||
		dict["hash_type"] != "sha256" {
		t.Fatalf("file_name match = %#v", dict)
	}

	// source_hash_name takes precedence over everything.
	ret, err = fn.Execute(context.Background(), rt, &extractHashArgs{
		HashFn:         "/hashes.txt",
		FileName:       strPtr("/tmp/hello.tar.gz"),
		Source:         strPtr("https://example.com/other.tar.gz"),
		SourceHashName: strPtr("other.tar.gz"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dict = ret.(map[string]any)
	if dict["hsum"] != "6f5902ac237024bdd0c176cb93063dc4" {
		t.Fatalf("source_hash_name match = %#v", dict)
	}

	// No matching filename → partial fallback (first hash in file).
	ret, err = fn.Execute(context.Background(), rt, &extractHashArgs{
		HashFn: "/hashes.txt", FileName: strPtr("unrelated.bin"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dict = ret.(map[string]any)
	if dict["hsum"] != "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447" {
		t.Fatalf("partial fallback = %#v", dict)
	}

	// No hashes at all → nil.
	emptyRt := xtRT(t, map[string]string{"/empty.txt": "# only comments\n"})
	ret, err = fn.Execute(context.Background(), emptyRt, &extractHashArgs{
		HashFn: "/empty.txt",
	})
	if err != nil || ret != nil {
		t.Fatalf("no-hash result = %#v, %v", ret, err)
	}

	// md5-typed extraction restricts to that length.
	ret, err = fn.Execute(context.Background(), rt, &extractHashArgs{
		HashFn: "/hashes.txt", HashType: strPtr("md5"),
		FileName: strPtr("other.tar.gz"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dict = ret.(map[string]any)
	if dict["hash_type"] != "md5" {
		t.Fatalf("md5 typed = %#v", dict)
	}
}

func TestUserGroupResolution(t *testing.T) {
	rt := xtRT(t, nil)

	// root is universally present; uid 0 maps back and forth.
	got, _ := userToUidFunc{}.Execute(context.Background(), rt, &userArgs{User: "root"})
	if got != 0 {
		t.Fatalf("user_to_uid(root) = %#v", got)
	}
	got, _ = uidToUserFunc{}.Execute(context.Background(), rt, &uidArgs{Uid: 0})
	if got != "root" {
		t.Fatalf("uid_to_user(0) = %#v", got)
	}

	// Nonexistent names fall back to "".
	got, _ = userToUidFunc{}.Execute(context.Background(), rt, &userArgs{User: "no-such-user-xyz"})
	if got != "" {
		t.Fatalf("missing user = %#v", got)
	}
	got, _ = groupToGidFunc{}.Execute(context.Background(), rt, &groupArgs{Group: "no-such-group-xyz"})
	if got != "" {
		t.Fatalf("missing group = %#v", got)
	}
}

func TestOwnershipProbes(t *testing.T) {
	rt := xtRT(t, map[string]string{"/owned/file.txt": "x"})

	// The memory FS does not carry ownership: uid/gid degrade to -1 and
	// user/group degrade to False exactly like upstream's stats defaults.
	got, _ := getUidFunc{}.Execute(context.Background(), rt,
		&statOwnerArgs{Path: "/owned/file.txt"})
	if got != -1 {
		t.Fatalf("get_uid = %#v", got)
	}
	got, _ = getGidFunc{}.Execute(context.Background(), rt,
		&statOwnerArgs{Path: "/owned/file.txt"})
	if got != -1 {
		t.Fatalf("get_gid = %#v", got)
	}
	got, _ = getUserFunc{}.Execute(context.Background(), rt,
		&statOwnerArgs{Path: "/owned/file.txt"})
	if got != false {
		t.Fatalf("get_user = %#v", got)
	}
}

// Real-filesystem probes for access/lstat (the OS backend carries real
// permission bits).
func TestAccessAndLstatOnOS(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{
		Exec:  runtime.NewExecRegistry(),
		FS:    runtime.OSFileSystem{},
		Facts: factsForTestingOS(),
	}

	accessFn := accessFunc{}
	got, err := accessFn.Execute(context.Background(), rt, &accessArgs{Path: path, Mode: "x"})
	if err != nil || got != true {
		t.Fatalf("access x = %#v, %v", got, err)
	}
	got, err = accessFn.Execute(context.Background(), rt, &accessArgs{Path: path, Mode: "f"})
	if err != nil || got != true {
		t.Fatalf("access f = %#v, %v", got, err)
	}

	if _, err := accessFn.Execute(context.Background(), rt,
		&accessArgs{Path: path, Mode: "z"}); err == nil ||
		err.Error() != "Invalid mode specified." {
		t.Fatalf("invalid mode = %v", err)
	}
	if _, err := accessFn.Execute(context.Background(), rt,
		&accessArgs{Path: "relative/path", Mode: "f"}); err == nil ||
		err.Error() != "Path to link must be absolute." {
		t.Fatalf("relative guard = %v", err)
	}

	lstatFn := lstatFunc{}
	res, err := lstatFn.Execute(context.Background(), rt, &lstatArgs{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	dict := res.(map[string]any)
	if dict["st_size"] != int64(10) {
		t.Fatalf("lstat size = %#v", dict["st_size"])
	}
	if nlink, ok := dict["st_nlink"].(uint64); !ok || nlink < 1 {
		t.Fatalf("lstat nlink = %#v", dict["st_nlink"])
	}

	// Error path yields an empty dict.
	res, err = lstatFn.Execute(context.Background(), rt,
		&lstatArgs{Path: filepath.Join(tmpDir, "missing")})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("missing lstat = %#v, %v", res, err)
	}
}

func TestDeviceProbes(t *testing.T) {
	// Character device /dev/null exists on every Linux container.
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
	}

	chrFn := isChrdevFunc{}
	got, _ := chrFn.Execute(context.Background(), rt, &isChrdevArgs{Name: "/dev/null"})
	if got != true {
		t.Fatalf("is_chrdev(/dev/null) = %#v", got)
	}
	blkFn := isBlkdevFunc{}
	got, _ = blkFn.Execute(context.Background(), rt, &isBlkdevArgs{Name: "/dev/null"})
	if got != false {
		t.Fatalf("is_blkdev(/dev/null) = %#v", got)
	}

	devmmFn := getDevmmFunc{}
	got, _ = devmmFn.Execute(context.Background(), rt, &getDevmmArgs{Name: "/dev/null"})
	mm := got.([]int)
	if mm[0] == 0 && mm[1] == 0 {
		t.Fatalf("get_devmm returned zeros for a char device: %#v", mm)
	}

	// Regular files are neither.
	rt2 := xtRT(t, map[string]string{"/plain": "x"})
	got, _ = chrFn.Execute(context.Background(), rt2, &isChrdevArgs{Name: "/plain"})
	if got != false {
		t.Fatalf("is_chrdev(regular) = %#v", got)
	}
}

func TestMknodFifo(t *testing.T) {
	tmpDir := t.TempDir()
	fifoPath := filepath.Join(tmpDir, "pipe")
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.OSFileSystem{},
	}

	fifoFn := mknodFifoFunc{}
	ret, err := fifoFn.Execute(context.Background(), rt, &mknodFifoArgs{
		Name: fifoPath, Mode: strPtr("0644"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ret != true {
		t.Fatalf("fifo creation = %#v (%v)", ret, err)
	}
	info, serr := os.Stat(fifoPath)
	if serr != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("fifo not created: %v", serr)
	}

	// EEXIST path returns the upstream comment instead of an error.
	ret2, err := fifoFn.Execute(context.Background(), rt, &mknodFifoArgs{
		Name: fifoPath, Mode: strPtr("0644"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = ret2
}

func factsForTestingOS() *facts.Facts { return facts.ForTesting(facts.Overrides{}) }
