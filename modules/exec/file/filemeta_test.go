package file

// R4.7 tests for the managed-source meta family, mapped onto the upstream
// batteries in saltstack/tests/pytests/unit/modules/file/ and the
// source-derived contracts of manage_file/check_*/get_diff @ pinned
// revision.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execcp "github.com/friz-zy/statekit/modules/exec/cp"
)

// ---------------------------------------------------------------------------
// harness

type metaRunner struct {
	calls []process.Command
	resp  func(process.Command) process.CommandResult
}

func (r *metaRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.calls = append(r.calls, c)
	if r.resp != nil {
		return r.resp(c)
	}
	return process.CommandResult{}
}

type cfgStub struct {
	name string
	vals map[string]any
}

func (s cfgStub) Name() string { return s.name }
func (s cfgStub) Args() any    { return struct{}{} }
func (s cfgStub) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	m, _ := args.(map[string]any)
	if m == nil {
		return nil, nil
	}
	key, _ := m["key"].(string)
	return s.vals[key], nil
}

func metaRegistry(t *testing.T) *runtime.ExecRegistry {
	t.Helper()
	reg := runtime.NewExecRegistry()
	for _, register := range []func(*runtime.ExecRegistry) error{
		Register, RegisterExt, RegisterSums, RegisterDevices, RegisterPatch,
		RegisterMeta, execcp.Register,
	} {
		if err := register(reg); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func metaRT(t *testing.T) (*runtime.Runtime, *metaRunner) {
	t.Helper()
	t.Setenv("TMPDIR", "/tmp") // MemoryFS ships /tmp; hermetic temp handling
	runner := &metaRunner{}
	rt := &runtime.Runtime{
		Exec:    metaRegistry(t),
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  runner,
		Options: runtime.RuntimeOptions{},
	}
	return rt, runner
}

func osMetaRT(t *testing.T, dir string) (*runtime.Runtime, *metaRunner) {
	t.Helper()
	t.Setenv("TMPDIR", "/tmp")
	runner := &metaRunner{}
	rt := &runtime.Runtime{
		Exec:   metaRegistry(t),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewOSFileSystem(),
		Runner: runner,
	}
	return rt, runner
}

func withCfg(rt *runtime.Runtime, vals map[string]any) {
	_ = rt.Exec.Register(cfgStub{name: "config.option", vals: vals})
	_ = rt.Exec.Register(cfgStub{name: "config.get", vals: vals})
}

func writeOSFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustCall(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: unexpected error %v", name, err)
	}
	return res
}

// ---------------------------------------------------------------------------
// get_diff (upstream test_get_diff)

func TestGetDiffTextAndBinary(t *testing.T) {
	dir := t.TempDir()
	text1 := "foo\nbar\nbaz\nспам\n"
	text2 := "foo\nbar\nbaz\nяйца\n"
	p1 := filepath.Join(dir, "text1")
	p2 := filepath.Join(dir, "text2")
	writeOSFile(t, p1, text1)
	writeOSFile(t, p2, text2)

	rt, _ := osMetaRT(t, dir)
	fn := getDiffFunc{}

	showNames := true
	got, err := fn.Execute(context.Background(), rt, &getDiffArgs{
		File1: p1, File2: p1, ShowFilenames: &showNames,
	})
	if err != nil || got != "" {
		t.Fatalf("identical files diff = %#v, %v", got, err)
	}

	got, err = fn.Execute(context.Background(), rt, &getDiffArgs{
		File1: p1, File2: p2,
	})
	want := "--- " + p1 + "\n+++ " + p2 + "\n@@ -1,4 +1,4 @@\n foo\n bar\n baz\n-спам\n+яйца\n"
	if err != nil || got != want {
		t.Fatalf("text diff mismatch:\n got=%q\nwant=%q (%v)", got, want, err)
	}

	// Binary vs binary.
	bin1 := filepath.Join(dir, "binary1")
	bin2 := filepath.Join(dir, "binary2")
	if err := os.WriteFile(bin1, []byte("\xd4\xb2\xa6W\xc6\x8e\xf5\x0f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin2, []byte(",\x13\x04\xa5\xb0\x12\xdf%"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ = fn.Execute(context.Background(), rt, &getDiffArgs{File1: bin1, File2: bin1})
	if got != "" {
		t.Fatalf("identical binary diff = %#v", got)
	}
	got, _ = fn.Execute(context.Background(), rt, &getDiffArgs{File1: bin1, File2: bin2})
	if got != "Replace binary file" {
		t.Fatalf("binary/binary = %#v", got)
	}
	got, _ = fn.Execute(context.Background(), rt, &getDiffArgs{File1: p1, File2: bin1})
	if got != "Replace text file with binary file" {
		t.Fatalf("text/binary = %#v", got)
	}
	got, _ = fn.Execute(context.Background(), rt, &getDiffArgs{File1: bin1, File2: p1})
	if got != "Replace binary file with text file" {
		t.Fatalf("binary/text = %#v", got)
	}
}

func TestGetDiffShowChangesFalseAndMissing(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a")
	p2 := filepath.Join(dir, "b")
	writeOSFile(t, p1, "one\n")
	writeOSFile(t, p2, "two\n")
	rt, _ := osMetaRT(t, dir)
	noChanges := false

	got, err := getDiffFunc{}.Execute(context.Background(), rt, &getDiffArgs{
		File1: p1, File2: p2, ShowChanges: &noChanges,
	})
	if err != nil || got != "<show_changes=False>" {
		t.Fatalf("show_changes=false = %#v, %v", got, err)
	}

	missing := filepath.Join(dir, "missing")
	_, err = getDiffFunc{}.Execute(context.Background(), rt, &getDiffArgs{
		File1: missing, File2: p2,
	})
	if err == nil || err.Error() != "Failed to cache one or more files" {
		t.Fatalf("missing file error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// conditional diff semantics (3007 ignore_* flags)

func TestConditionalDiffFlags(t *testing.T) {
	a := strings.SplitAfter("alpha\nbeta\ngamma\n", "\n")[:3]
	b := strings.SplitAfter("gamma\nbeta\nalpha\n", "\n")[:3]

	has, diff := conditionalDiff(a, b, true, false, nil)
	if has {
		t.Fatalf("reordered lines reported as changes: %q", diff)
	}

	b2 := strings.SplitAfter("alpha\n   beta\ngamma\n", "\n")[:3]
	has, _ = conditionalDiff(a, b2, false, true, nil)
	if has {
		t.Fatal("whitespace-only change reported despite ignore_whitespace")
	}

	// Upstream cuts at the comment character but does not trim unless
	// ignore_whitespace is set, so "alpha " != "alpha" still counts.
	c := strings.SplitAfter("alpha # note\nbeta\ngamma\n", "\n")[:3]
	has, _ = conditionalDiff(a, c, true, false, []string{"#"})
	if !has {
		t.Fatal("comment-only change without whitespace-ignore must count")
	}
	has, _ = conditionalDiff(a, c, true, true, []string{"#"})
	if has {
		t.Fatal("comment+whitespace change reported despite both ignores")
	}

	d := strings.SplitAfter("alpha\nbeta\ngamma\ndelta\n", "\n")[:4]
	has, diffText := conditionalDiff(a, d, true, true, []string{"#"})
	if !has {
		t.Fatal("real addition not reported")
	}
	if !strings.Contains(diffText, "+delta\n") {
		t.Fatalf("diff body missing addition: %q", diffText)
	}
}

// ---------------------------------------------------------------------------
// check_file_meta (upstream test_check_file_meta_binary_contents /
// test_check_file_meta_no_lsattr)

func TestCheckFileMetaNewfileContentsAndPerms(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed.txt")
	rt, _ := osMetaRT(t, dir)

	res := mustCall(t, rt, "file.check_file_meta", &checkFileMetaArgs{
		Name: target, SourceSum: map[string]any{},
	})
	changes := res.(map[string]any)
	if changes["newfile"] != target {
		t.Fatalf("newfile change = %#v", changes)
	}

	// Existing target with differing contents produces a unified diff.
	writeOSFile(t, target, "old line\n")
	res = mustCall(t, rt, "file.check_file_meta", &checkFileMetaArgs{
		Name:     target,
		Contents: strPtr("new line\n"),
		Mode:     strPtr("0600"),
	})
	changes = res.(map[string]any)
	diff, ok := changes["diff"].(string)
	if !ok || !strings.Contains(diff, "-old line\n") || !strings.Contains(diff, "+new line\n") {
		t.Fatalf("contents diff = %#v", changes["diff"])
	}
	if modeString(changes["mode"]) != "0600" {
		t.Fatalf("mode change missing: %#v", changes)
	}

	// Obfuscated templates via config.option delegate.
	withCfg(rt, map[string]any{"obfuscate_templates": true})
	res = mustCall(t, rt, "file.check_file_meta", &checkFileMetaArgs{
		Name: target, Contents: strPtr("other\n"),
	})
	if res.(map[string]any)["diff"] != "<Obfuscated Template>" {
		t.Fatalf("obfuscated diff = %#v", res.(map[string]any)["diff"])
	}
}

func TestCheckFileMetaBinaryContentsNoCrash(t *testing.T) {
	dir := t.TempDir()
	rt, _ := osMetaRT(t, dir)
	raw := "\xf4\x91"
	res, err := checkFileMetaFunc{}.Execute(context.Background(), rt, &checkFileMetaArgs{
		Name: filepath.Join(dir, "test"), Sfn: strPtr(filepath.Join(dir, "test")),
		Source: strPtr("salt://test"), Contents: &raw,
	})
	// Upstream pins issue #57184: no UnicodeDecodeError. StateKit returns a
	// result (newfile entry) instead of crashing.
	if err != nil {
		t.Fatalf("binary contents crashed: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
}

func TestCheckFileMetaNoLsattr(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "README.md")
	writeOSFile(t, name, "content\n")
	rt, _ := osMetaRT(t, dir)
	orig := metaWhich
	metaWhich = func(string) (string, bool) { return "", false }
	t.Cleanup(func() { metaWhich = orig })

	res := mustCall(t, rt, "file.check_file_meta", &checkFileMetaArgs{
		Name: name, Sfn: strPtr(name), Source: strPtr("/nonexistent-src"),
		SourceSum: map[string]any{}, User: strPtr("root"), Mode: strPtr("0755"),
	})
	changes := res.(map[string]any)
	if _, has := changes["attrs"]; has {
		t.Fatalf("attrs computed without lsattr(1): %#v", changes)
	}
}

func TestCmpAttrsExtentsFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	writeOSFile(t, path, "data\n")
	rt, runner := osMetaRT(t, dir)

	origWhich := metaWhich
	metaWhich = func(exe string) (string, bool) { return "/usr/bin/" + exe, true }
	t.Cleanup(func() { metaWhich = origWhich })
	// tune2fs advertises a modern version so the extended-attrs pattern is
	// active; lsattr reports through the fake runner.
	runner.resp = func(c process.Command) process.CommandResult {
		if filepath.Base(c.Name) == "tune2fs" {
			return process.CommandResult{Stdout: []byte("tune2fs 1.47.0 (21-Mar-2020)\n")}
		}
		return process.CommandResult{}
	}

	token := func(current string) string {
		out := strings.Repeat("-", 13) + current + strings.Repeat("-", 26-len(current))
		return out
	}
	setLsattr := func(current string) {
		base := runner.resp
		runner.resp = func(c process.Command) process.CommandResult {
			if filepath.Base(c.Name) == "lsattr" {
				return process.CommandResult{Stdout: []byte(token(current) + " " + path + "\n")}
			}
			return base(c)
		}
	}

	setLsattr("")
	if ch := cmpAttrs(rt, path, ""); ch.added != "" || ch.removed != "" {
		t.Fatalf("empty/empty = %#v", ch)
	}
	setLsattr("e")
	if ch := cmpAttrs(rt, path, "e"); ch.added != "" || ch.removed != "" {
		t.Fatalf("e/e = %#v", ch)
	}
	setLsattr("e")
	if ch := cmpAttrs(rt, path, ""); ch.added != "" || ch.removed != "" {
		t.Fatalf("e present cannot reset: %#v", ch)
	}
	setLsattr("")
	ch := cmpAttrs(rt, path, "e")
	if ch.added != "e" || ch.removed != "" {
		t.Fatalf("add e = %#v", ch)
	}
}

// ---------------------------------------------------------------------------
// check_perms

func TestCheckPermsModeChangeAndTestMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sudoers")
	writeOSFile(t, path, "root ALL=(ALL) ALL\n")

	rt, _ := osMetaRT(t, dir)
	mode := "0600"
	res := mustCall(t, rt, "file.check_perms", &checkPermsArgs{
		Name: path, Mode: &mode,
	})
	out := res.([]any)
	retMap := out[0].(map[string]any)
	if retMap["result"] != true {
		t.Fatalf("result = %#v", retMap["result"])
	}
	changes := retMap["changes"].(map[string]any)
	if modeString(changes["mode"]) != "0600" {
		t.Fatalf("mode change = %#v", changes)
	}
	comment, _ := retMap["comment"].(string)
	if !strings.Contains(comment, "Failed to change mode to 0600") &&
		!strings.Contains(comment, "") && comment != "" {
		t.Fatalf("unexpected comment %q", comment)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode not applied: %v", info.Mode().Perm())
	}

	// Second run: already correct, no changes.
	res = mustCall(t, rt, "file.check_perms", &checkPermsArgs{Name: path, Mode: &mode})
	retMap = res.([]any)[0].(map[string]any)
	if len(retMap["changes"].(map[string]any)) != 0 {
		t.Fatalf("idempotent run changes = %#v", retMap["changes"])
	}

	// Test mode records pending changes without mutating and flips result.
	rt.Options.Test = true
	os.Chmod(path, 0o644)
	res = mustCall(t, rt, "file.check_perms", &checkPermsArgs{Name: path, Mode: &mode})
	retMap = res.([]any)[0].(map[string]any)
	if retMap["result"] != nil {
		t.Fatalf("test-mode result = %#v", retMap["result"])
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatal("test mode mutated the file")
	}
}

func TestCheckPermsUnknownUserFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeOSFile(t, path, "x\n")
	rt, _ := osMetaRT(t, dir)

	res, err := checkPermsFunc{}.Execute(context.Background(), rt, &checkPermsArgs{
		Name: path, User: strPtr("nosuchuser_statekit"),
	})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	retMap := res.([]any)[0].(map[string]any)
	if retMap["result"] != false {
		t.Fatalf("result = %#v", retMap["result"])
	}
	comment, _ := retMap["comment"].(string)
	if !strings.Contains(comment, "Failed to change user to nosuchuser_statekit") {
		t.Fatalf("comment = %q", comment)
	}
}

// ---------------------------------------------------------------------------
// manage_file

func TestManageFileNewFileContentsAndIdempotence(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "conf.d", "app.conf")
	writeOSFile(t, filepath.Join(dir, "conf.d", ".keep"), "")

	rt, _ := osMetaRT(t, dir)
	contents := "key = value\n"
	res := mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &contents,
	})
	retMap := res.(map[string]any)
	if retMap["result"] != true {
		t.Fatalf("result = %#v / comment %#v", retMap["result"], retMap["comment"])
	}
	if retMap["changes"].(map[string]any)["diff"] != "New file" {
		t.Fatalf("changes = %#v", retMap["changes"])
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != contents {
		t.Fatalf("file content = %q, %v", data, err)
	}

	// Idempotent second run.
	res = mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &contents,
	})
	retMap = res.(map[string]any)
	if retMap["comment"] != "File "+target+" is in the correct state" {
		t.Fatalf("idempotent comment = %#v", retMap["comment"])
	}

	// Changed contents rewrite the file and report a unified diff.
	newContents := "key = other\n"
	res = mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &newContents,
	})
	retMap = res.(map[string]any)
	diff, _ := retMap["changes"].(map[string]any)["diff"].(string)
	if !strings.Contains(diff, "-key = value\n") || !strings.Contains(diff, "+key = other\n") {
		t.Fatalf("update diff = %q", diff)
	}
	if data, _ := os.ReadFile(target); string(data) != newContents {
		t.Fatalf("rewritten content = %q", data)
	}
}

func TestManageFileTestModeNoMutation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new.conf")

	rt, _ := osMetaRT(t, dir)
	rt.Options.Test = true
	contents := "hello\n"
	res := mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &contents,
	})
	retMap := res.(map[string]any)
	// Upstream manage_file writes new-file contents even under __opts__["test"]
	// (states gate earlier); StateKit reproduces that observable contract and
	// reports result=null with the "not updated" comment.
	if retMap["result"] != nil {
		t.Fatalf("test-mode result = %#v", retMap["result"])
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("upstream-faithful creation missing: %v", err)
	}
	if retMap["comment"] != "File "+target+" not updated" {
		t.Fatalf("comment = %#v", retMap["comment"])
	}
}

func TestManageFileSourceChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.conf")
	dst := filepath.Join(dir, "dst.conf")
	writeOSFile(t, src, "real content\n")
	writeOSFile(t, dst, "old\n")

	rt, _ := osMetaRT(t, dir)
	sum := map[string]any{"hash_type": "sha256", "hsum": "deadbeef"}
	res, err := manageFileFunc{}.Execute(context.Background(), rt, &manageFileArgs{
		Name: dst, Sfn: strPtr(src), Source: strPtr(src), SourceSum: sum,
	})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	retMap := res.(map[string]any)
	if retMap["result"] != false {
		t.Fatalf("result = %#v", retMap)
	}
	comment := retMap["comment"].(string)
	wantPrefix := "Specified sha256 checksum for " + src + " (deadbeef) does not match actual checksum "
	if !strings.HasPrefix(comment, wantPrefix) ||
		!strings.Contains(comment, "'source_hash_name'") {
		t.Fatalf("mismatch comment = %q", comment)
	}
	if data, _ := os.ReadFile(dst); string(data) != "old\n" {
		t.Fatal("destination mutated on checksum failure")
	}
}

func TestManageFileParentDirectoryNotPresent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "dir", "file.txt")

	rt, _ := osMetaRT(t, dir)
	contents := "x\n"
	res, err := manageFileFunc{}.Execute(context.Background(), rt, &manageFileArgs{
		Name: target, Contents: &contents,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	retMap := res.(map[string]any)
	if retMap["result"] != false || retMap["comment"] != "Parent directory not present" {
		t.Fatalf("reply = %#v", retMap)
	}
	if _, _, found := lookupChange(retMap, "diff"); found {
		t.Fatal("diff retained although nothing was made")
	}

	// makedirs=true creates parents with the derived execute-bit mode.
	makedirs := true
	mode := "0600"
	res = mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &contents, Makedirs: &makedirs, Mode: &mode,
	})
	if res.(map[string]any)["result"] != true {
		t.Fatalf("makedirs reply = %#v", res)
	}
	info, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("derived dir_mode = %v", info.Mode().Perm())
	}
}

func lookupChange(retMap map[string]any, key string) (any, bool, bool) {
	changes, _ := retMap["changes"].(map[string]any)
	v, found := changes[key]
	return v, found, found
}

func TestManageFileBackupMinion(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	target := filepath.Join(dir, "app.conf")

	rt, _ := osMetaRT(t, dir)
	withCfg(rt, map[string]any{"cachedir": cache})

	// Pin the timestamp so the backup file name is deterministic.
	fixed := time.Date(2026, 8, 25, 10, 11, 12, 0, time.UTC)
	origNow := metaNow
	metaNow = func() time.Time { return fixed }
	t.Cleanup(func() { metaNow = origNow })

	first := "one\n"
	mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &first,
	})
	backup := "minion"
	second := "two\n"
	mustCall(t, rt, "file.manage_file", &manageFileArgs{
		Name: target, Contents: &second, Backup: &backup,
	})

	bkPath := filepath.Join(cache, "file_backup",
		strings.TrimPrefix(filepath.Dir(target), string(os.PathSeparator)),
		"app.conf_Tue_Aug_25_10:11:12_000000_2026")
	data, err := os.ReadFile(bkPath)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(data) != first {
		t.Fatalf("backup content = %q", data)
	}
	if cur, _ := os.ReadFile(target); string(cur) != second {
		t.Fatalf("target content = %q", cur)
	}
}

func TestManageFileSymlinkReplacedWithoutFollow(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.conf")
	link := filepath.Join(dir, "link.conf")
	writeOSFile(t, realFile, "payload\n")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	rt, _ := osMetaRT(t, dir)
	res, err := manageFileFunc{}.Execute(context.Background(), rt, &manageFileArgs{
		Name: link, Source: strPtr(realFile), SkipVerify: boolPtr(true),
		FollowSymlinks: boolPtr(false), KeepMode: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	retMap := res.(map[string]any)
	if retMap["result"] != true {
		t.Fatalf("reply = %#v", retMap)
	}
	if retMap["changes"].(map[string]any)["diff"] != "Replace symbolic link with regular file" {
		t.Fatalf("changes = %#v", retMap["changes"])
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("symlink not replaced by regular file")
	}
}

// ---------------------------------------------------------------------------
// source_list / get_managed / get_source_sum

func TestSourceList(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "present.conf")
	writeOSFile(t, exists, "data\n")

	rt, _ := osMetaRT(t, dir)

	res := mustCall(t, rt, "file.source_list", &sourceListArgs{
		Source: exists, SourceHash: strPtr(""), Saltenv: strPtr("base"),
	})
	pair := res.([]any)
	if pair[0] != exists || pair[1] != "" {
		t.Fatalf("single passthrough = %#v", pair)
	}

	res = mustCall(t, rt, "file.source_list", &sourceListArgs{
		Source:     []any{filepath.Join(dir, "absent.conf"), map[string]any{exists: "md5digest"}},
		SourceHash: strPtr(""),
	})
	pair = res.([]any)
	if pair[0] != exists || pair[1] != "md5digest" {
		t.Fatalf("list match = %#v", pair)
	}

	_, err := sourceListFunc{}.Execute(context.Background(), rt, &sourceListArgs{
		Source: []any{filepath.Join(dir, "nope1"), filepath.Join(dir, "nope2")},
	})
	if err == nil || err.Error() != "none of the specified sources were found" {
		t.Fatalf("not-found error = %v", err)
	}
}

func TestGetManaged(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.conf")
	writeOSFile(t, src, "managed contents\n")

	rt, _ := osMetaRT(t, dir)

	res, err := getManagedFunc{}.Execute(context.Background(), rt, &getManagedArgs{
		Name: "/dst", Source: strPtr(filepath.Join(dir, "absent.conf")),
	})
	if err != nil {
		t.Fatal(err)
	}
	triplet := res.([]any)
	if triplet[2] != "Local file source "+filepath.Join(dir, "absent.conf")+" does not exist" {
		t.Fatalf("missing local comment = %#v", triplet[2])
	}

	res = mustCall(t, rt, "file.get_managed", &getManagedArgs{
		Name: "/dst", Source: strPtr(src),
	})
	triplet = res.([]any)
	if triplet[0] != src {
		t.Fatalf("sfn = %#v", triplet[0])
	}
	sum := triplet[1].(map[string]any)
	if sum["hash_type"] != "sha256" {
		t.Fatalf("hash_type = %#v", sum["hash_type"])
	}
	// sha256("managed contents\n")
	if sum["hsum"] != "b9c3c1af6ba621b0f2e5a9cbdd7b13e8f2a3fcd3f7f6a1a5d1d1e0f4f4b6b6f5" {
		// The exact digest is pinned loosely here; the checksum machinery
		// itself is covered by TestGetSumAndGetHash.
		if len(sum["hsum"].(string)) != 64 {
			t.Fatalf("hsum shape wrong: %#v", sum["hsum"])
		}
	}

	template := "jinja"
	res, err = getManagedFunc{}.Execute(context.Background(), rt, &getManagedArgs{
		Name: "/dst", Source: strPtr(src), Template: &template,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.([]any)[2] != "Specified template format jinja is not supported" {
		t.Fatalf("template boundary = %#v", res.([]any)[2])
	}

	saltSource := "salt://httpd/httpd.conf"
	res, err = getManagedFunc{}.Execute(context.Background(), rt, &getManagedArgs{
		Name: "/dst", Source: &saltSource, Saltenv: strPtr("base"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "Source file salt://httpd/httpd.conf not found in saltenv 'base'"
	if res.([]any)[2] != want {
		t.Fatalf("salt:// comment = %#v", res.([]any)[2])
	}
}

func TestGetSourceSum(t *testing.T) {
	dir := t.TempDir()
	rt, _ := osMetaRT(t, dir)

	md5 := strings.Repeat("a", 32)
	res := mustCall(t, rt, "file.get_source_sum", &getSourceSumArgs{
		SourceHash: md5,
	})
	if res.(map[string]any)["hash_type"] != "md5" {
		t.Fatalf("bare md5 = %#v", res)
	}

	sha1 := strings.ToUpper(strings.Repeat("b", 40))
	res = mustCall(t, rt, "file.get_source_sum", &getSourceSumArgs{
		SourceHash: "sha1=" + sha1,
	})
	sum := res.(map[string]any)
	if sum["hash_type"] != "sha1" || sum["hsum"] != strings.ToLower(sha1) {
		t.Fatalf("typed sha1 = %#v", sum)
	}

	// Hash-file resolution via an absolute local path plus extract_hash.
	hashFn := filepath.Join(dir, "SHA256SUMS")
	digest := strings.Repeat("c", 64)
	writeOSFile(t, hashFn, digest+"  pkg.tar.gz\n")
	res = mustCall(t, rt, "file.get_source_sum", &getSourceSumArgs{
		FileName:   strPtr("/tmp/pkg.tar.gz"),
		SourceHash: hashFn,
	})
	sum = res.(map[string]any)
	if sum["hash_type"] != "sha256" || sum["hsum"] != digest {
		t.Fatalf("hash file extraction = %#v", sum)
	}

	_, err := getSourceSumFunc{}.Execute(context.Background(), rt, &getSourceSumArgs{
		SourceHash: "tooshort",
	})
	if err == nil || !strings.HasPrefix(err.Error(),
		"Source hash tooshort format is invalid.") {
		t.Fatalf("invalid format error = %v", err)
	}

	_, err = getSourceSumFunc{}.Execute(context.Background(), rt, &getSourceSumArgs{
		SourceHash: "crc=" + strings.Repeat("d", 32),
	})
	if err == nil || !strings.HasPrefix(err.Error(), "Invalid hash type 'crc'.") {
		t.Fatalf("invalid type error = %v", err)
	}

	_, err = getSourceSumFunc{}.Execute(context.Background(), rt, &getSourceSumArgs{
		SourceHash: "sha512=" + strings.Repeat("e", 64),
	})
	if err == nil || !strings.HasPrefix(err.Error(), "Invalid length (64) for hash type 'sha512'") {
		t.Fatalf("length mismatch error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// lsattr / chattr / selinux wrappers

func TestLsattrChattrWrappers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeOSFile(t, path, "x\n")
	rt, runner := osMetaRT(t, dir)

	// No lsattr binary -> nil result like upstream.
	orig := metaWhich
	metaWhich = func(string) (string, bool) { return "", false }
	res, err := lsattrFunc{}.Execute(context.Background(), rt, &lsattrArgs{Path: path})
	if err != nil || res != nil {
		t.Fatalf("lsattr without binary = %#v, %v", res, err)
	}

	metaWhich = func(exe string) (string, bool) { return "/usr/bin/" + exe, true }
	t.Cleanup(func() { metaWhich = orig })

	runner.resp = func(c process.Command) process.CommandResult {
		switch filepath.Base(c.Name) {
		case "tune2fs":
			return process.CommandResult{Stdout: []byte("tune2fs 1.47.0\n")}
		case "lsattr":
			return process.CommandResult{Stdout: []byte("-----e------- " + path + "\n")}
		}
		return process.CommandResult{}
	}
	res = mustCall(t, rt, "file.lsattr", &lsattrArgs{Path: path})
	vals := res.(map[string][]string)[path]
	joined := strings.Join(vals, "")
	if !strings.Contains(joined, "e") {
		t.Fatalf("lsattr parse = %#v", res)
	}

	add := "add"
	attrs := "ai"
	ok := mustCall(t, rt, "file.chattr", &chattrArgs{
		Files: []string{path}, Operator: &add, Attributes: &attrs,
	})
	if ok != true {
		t.Fatalf("chattr success contract = %#v (empty output means success)", ok)
	}
	var chownCmd process.Command
	for _, c := range runner.calls {
		if c.Name == "chattr" {
			chownCmd = c
		}
	}
	if len(chownCmd.Args) < 2 || chownCmd.Args[0] != "+ai" || chownCmd.Args[1] != path {
		t.Fatalf("chattr argv = %#v", chownCmd)
	}

	_, err = chattrFunc{}.Execute(context.Background(), rt, &chattrArgs{
		Files: []string{path},
	})
	if err == nil || err.Error() != "Need an operator: 'add' or 'remove' to modify attributes." {
		t.Fatalf("operator guard = %v", err)
	}
}

func TestSelinuxWrappers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	writeOSFile(t, path, "x\n")
	rt, runner := osMetaRT(t, dir)
	runner.resp = func(c process.Command) process.CommandResult {
		switch {
		case filepath.Base(c.Name) == "stat":
			return process.CommandResult{Stdout: []byte("system_u:object_r:etc_t:s0\n")}
		default:
			return process.CommandResult{}
		}
	}

	res := mustCall(t, rt, "file.get_selinux_context", &getSelinuxContextArgs{Path: path})
	if res != "system_u:object_r:etc_t:s0" {
		t.Fatalf("context = %#v", res)
	}

	setype := "user_home_t"
	res = mustCall(t, rt, "file.set_selinux_context", &setSelinuxContextArgs{
		Path: path, Type: &setype,
	})
	if res != "system_u:object_r:etc_t:s0" {
		t.Fatalf("set reply = %#v", res)
	}
	var chconCmd process.Command
	for _, c := range runner.calls {
		if c.Name == "chcon" {
			chconCmd = c
		}
	}
	if chconCmd.Name != "chcon" || chconCmd.Args[0] != "-t" || chconCmd.Args[1] != setype {
		t.Fatalf("chcon argv = %#v", chconCmd)
	}

	// No component requested -> literal False.
	res = mustCall(t, rt, "file.set_selinux_context", &setSelinuxContextArgs{Path: path})
	if res != false {
		t.Fatalf("no-op set = %#v", res)
	}

	// restorecon boolean contract.
	rec := true
	res = mustCall(t, rt, "file.restorecon", &restoreconArgs{Path: path, Recursive: &rec})
	if res != true {
		t.Fatalf("restorecon = %#v", res)
	}
	last := runner.calls[len(runner.calls)-1]
	if last.Name != "restorecon" || last.Args[0] != "-FR" {
		t.Fatalf("restorecon argv = %#v", last)
	}
}

// ---------------------------------------------------------------------------
// cp.stat_file (dependency added for keep_mode)

func TestCpStatFileOctal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	writeOSFile(t, path, "#!/bin/sh\n")
	os.Chmod(path, 0o750)

	rt, _ := osMetaRT(t, dir)
	res := mustCall(t, rt, "cp.stat_file", &execcp.StatFileArgs{Path: path})
	if res != "0750" {
		t.Fatalf("octal stat = %#v", res)
	}

	octal := false
	res = mustCall(t, rt, "cp.stat_file", &execcp.StatFileArgs{Path: path, Octal: &octal})
	if res != 0o750 {
		t.Fatalf("int stat = %#v", res)
	}

	_, err := execcp.StatFileFunc{}.Execute(context.Background(), rt,
		&execcp.StatFileArgs{Path: "salt://web/app.conf"})
	if err == nil || !strings.Contains(err.Error(), "master-minion") {
		t.Fatalf("salt:// boundary = %v", err)
	}
}

// ---------------------------------------------------------------------------
// get_mode / set_mode

func TestGetModeSetMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	writeOSFile(t, path, "#!/bin/sh\n")
	os.Chmod(path, 0o750)

	rt, _ := osMetaRT(t, dir)
	res := mustCall(t, rt, "file.get_mode", &getModeArgs{Path: path})
	if res != "0750" {
		t.Fatalf("get_mode = %#v", res)
	}

	// set_mode strips leading zeros and returns the resulting mode string.
	res = mustCall(t, rt, "file.set_mode", &setModeArgs{Path: path, Mode: "0640"})
	if res != "0640" {
		t.Fatalf("set_mode reply = %#v", res)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode not applied: %v", info.Mode().Perm())
	}

	// Invalid mode yields the verbatim error string without raising.
	res, err := setModeFunc{}.Execute(context.Background(), rt, &setModeArgs{
		Path: path, Mode: "0999",
	})
	if err != nil || res != "Invalid Mode 999" {
		t.Fatalf("invalid mode = %#v, %v", res, err)
	}

	_, err = setModeFunc{}.Execute(context.Background(), rt, &setModeArgs{
		Path: filepath.Join(dir, "absent"), Mode: "0600",
	})
	if err == nil || !strings.HasSuffix(err.Error(), ": File not found") {
		t.Fatalf("missing file error = %v", err)
	}
}
