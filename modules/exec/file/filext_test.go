package file

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// R4.1 tests mapped onto the file-module behaviors read from
// saltstack/salt/modules/file.py @ pinned revision.

func xtRT(t *testing.T, files map[string]string) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

func TestPathUtilities(t *testing.T) {
	rt := xtRT(t, nil)

	got, _ := (basenameFunc{}).Execute(context.Background(), rt, &pathArgs{Path: "test/test.config"})
	if got != "test.config" {
		t.Fatalf("basename = %#v", got)
	}
	got, _ = (dirnameFunc{}).Execute(context.Background(), rt, &pathArgs{Path: "test/path/filename.config"})
	if got != "test/path" {
		t.Fatalf("dirname = %#v", got)
	}
	got, _ = (normpathFunc{}).Execute(context.Background(), rt, &pathArgs{Path: "a/b/c/.."})
	if got != "a/b" {
		t.Fatalf("normpath = %#v", got)
	}
	got, _ = (pardirFunc{}).Execute(context.Background(), rt, struct{}{})
	if got != ".." {
		t.Fatalf("pardir = %#v", got)
	}
	got, _ = (joinFunc{}).Execute(context.Background(), rt,
		&joinArgs{Args: []string{"subdir", "..", "confdir", "file.conf"}})
	if got != "confdir/file.conf" {
		t.Fatalf("join = %#v", got)
	}

	rt = xtRT(t, map[string]string{"/etc/pam.d/pass": ""})
	existsFn := pathExistsGlobFunc{}
	got, _ = existsFn.Execute(context.Background(), rt,
		&pathExistsGlobArgs{Path: "/etc/pam*/pass*"})
	if got != true {
		t.Fatalf("glob exists = %#v", got)
	}
	got, _ = existsFn.Execute(context.Background(), rt,
		&pathExistsGlobArgs{Path: "/etc/missing*/x"})
	if got != false {
		t.Fatalf("glob missing = %#v", got)
	}
}

func TestPrepend(t *testing.T) {
	rt := xtRT(t, map[string]string{"/etc/motd": "existing line\n"})
	ret, err := (prependFunc{}).Execute(context.Background(), rt, &prependArgs{
		Path: "/etc/motd",
		Args: []string{"first", "second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ret != `Prepended 2 lines to "/etc/motd"` {
		t.Fatalf("reply = %#v", ret)
	}
	data, _ := rt.FS.ReadFile("/etc/motd")
	want := "first\nsecond\nexisting line\n"
	if string(data) != want {
		t.Fatalf("content = %q; want %q", string(data), want)
	}

	prepRet, prepErr := (prependFunc{}).Execute(context.Background(), rt, &prependArgs{
		Path: "/etc/newfile",
		Args: []string{"only"},
	})
	if prepErr != nil {
		t.Fatal(prepErr)
	}
	_ = prepRet
	data, _ = rt.FS.ReadFile("/etc/newfile")
	if string(data) != "only\n" {
		t.Fatalf("created content = %q", string(data))
	}
}

func TestSeekAndTruncate(t *testing.T) {
	rt := xtRT(t, map[string]string{"/data/blob": "0123456789abcdef"})

	got, err := (seekReadFunc{}).Execute(context.Background(), rt,
		&seekReadArgs{Path: "/data/blob", Size: 4, Offset: 2})
	if err != nil || got != "2345" {
		t.Fatalf("seek_read = %#v, %v", got, err)
	}

	if _, err := (seekWriteFunc{}).Execute(context.Background(), rt,
		&seekWriteArgs{Path: "/data/blob", Data: "ABCD", Offset: 4}); err != nil {
		t.Fatal(err)
	}
	data, _ := rt.FS.ReadFile("/data/blob")
	// os.write overwrites in place: bytes 4..7 become ABCD.
	if string(data) != "0123ABCD89abcdef" {
		t.Fatalf("after seek_write = %q", string(data))
	}

	truncFn := truncateFunc{}
	if _, err := truncFn.Execute(context.Background(), rt,
		&truncateArgs{Path: "/data/blob", Length: 6}); err != nil {
		t.Fatal(err)
	}
	data, _ = rt.FS.ReadFile("/data/blob")
	if string(data) != "0123AB" {
		t.Fatalf("after truncate = %q", string(data))
	}
}

// Mirrors comment_line comment/uncomment round trip with .bak backup.
func TestCommentLineRoundTrip(t *testing.T) {
	content := "# pcspkr\nother line\n"
	rt := xtRT(t, map[string]string{"/etc/modules": content})

	commentFn := commentLineFunc{}
	got, err := commentFn.Execute(context.Background(), rt, &commentLineArgs{
		Path: "/etc/modules", Regex: "^pcspkr$",
	})
	if err != nil || got != false {
		t.Fatalf("comment on commented line = %#v, %v", got, err)
	}

	uncommentFn := commentLineFunc{}
	got, err = uncommentFn.Execute(context.Background(), rt, &commentLineArgs{
		Path: "/etc/modules", Regex: "^pcspkr$", Cmnt: boolPtr(false),
	})
	if err != nil || got != true {
		t.Fatalf("uncomment = %#v, %v", got, err)
	}
	data, _ := rt.FS.ReadFile("/etc/modules")
	// Upstream strips only the comment characters: "# pcspkr".lstrip("#")
	// keeps the space.
	if !strings.HasPrefix(string(data), " pcspkr") {
		t.Fatalf("after uncomment = %q", string(data))
	}
	if _, serr := rt.FS.Stat("/etc/modules.bak"); serr != nil {
		t.Fatalf("backup missing")
	}

	// Comment it back on a fresh copy: upstream's lstrip leaves the space,
	// so the plain ^pcspkr$ anchor no longer matches the edited line.
	rt2 := xtRT(t, map[string]string{"/etc/modules": "pcspkr\nother line\n"})
	got, err = commentFn.Execute(context.Background(), rt2, &commentLineArgs{
		Path: "/etc/modules", Regex: "^pcspkr$",
	})
	if err != nil || got != true {
		t.Fatalf("comment = %#v, %v", got, err)
	}
	data2, _ := rt2.FS.ReadFile("/etc/modules")
	if !strings.HasPrefix(string(data2), "#pcspkr") {
		t.Fatalf("after comment = %q", string(data2))
	}
}

func TestCommentUncommentWrappers(t *testing.T) {
	rt := xtRT(t, map[string]string{"/etc/conf": "option active\n"})
	commentWrap := commentFunc{}
	if _, err := commentWrap.Execute(context.Background(), rt, &commentArgs{
		Path: "/etc/conf", Regex: "^option active",
	}); err != nil {
		t.Fatal(err)
	}
	data, _ := rt.FS.ReadFile("/etc/conf")
	if !strings.HasPrefix(string(data), "#option active") {
		t.Fatalf("commented = %q", string(data))
	}
	uncommentWrap := uncommentFunc{}
	if _, err := uncommentWrap.Execute(context.Background(), rt, &commentArgs{
		Path: "/etc/conf", Regex: "^option active",
	}); err != nil {
		t.Fatal(err)
	}
	data, _ = rt.FS.ReadFile("/etc/conf")
	if strings.Contains(string(data), "#option") {
		t.Fatalf("uncommented = %q", string(data))
	}
}

func TestBlockreplaceModifyExisting(t *testing.T) {
	content := "before\n" +
		"#-- start managed zone --\n" +
		"old line\n" +
		"#-- end managed zone --\n" +
		"after\n"
	rt := xtRT(t, map[string]string{"/etc/app.conf": content})

	ret, err := (blockreplaceFunc{}).Execute(context.Background(), rt, &blockreplaceArgs{
		Path:    "/etc/app.conf",
		Content: strPtr("new line\nanother new line\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	diff := ret.(string)
	for _, piece := range []string{"-old line", "+new line", "+another new line"} {
		if !strings.Contains(diff, piece) {
			t.Fatalf("diff missing %q:\n%s", piece, diff)
		}
	}
	data, _ := rt.FS.ReadFile("/etc/app.conf")
	want := "before\n#-- start managed zone --\nnew line\nanother new line\n#-- end managed zone --\nafter\n"
	if string(data) != want {
		t.Fatalf("file = %q; want %q", string(data), want)
	}
	if _, serr := rt.FS.Stat("/etc/app.conf.bak"); serr != nil {
		t.Fatalf("backup missing")
	}
}

// Mirrors the not-found branches: append/prepend/insert and the error when
// none are requested.
func TestBlockreplaceNotFoundBranches(t *testing.T) {
	brFn := blockreplaceFunc{}

	noFlagsRt := xtRT(t, map[string]string{"/f": "line one\n"})
	_, err := brFn.Execute(context.Background(), noFlagsRt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"),
	})
	if err == nil || err.Error() !=
		"Cannot edit marked block. Markers were not found in file." {
		t.Fatalf("no-flags error = %v", err)
	}

	appendRt := xtRT(t, map[string]string{"/f": "line one\n"})
	if _, aerr := brFn.Execute(context.Background(), appendRt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"), AppendIfNotFound: true,
	}); aerr != nil {
		t.Fatal(aerr)
	}
	data, _ := appendRt.FS.ReadFile("/f")
	want := "line one\n#-- start managed zone --\nblock\n#-- end managed zone --\n"
	if string(data) != want {
		t.Fatalf("append result = %q; want %q", string(data), want)
	}

	prependRt := xtRT(t, map[string]string{"/f": "line one\n"})
	if _, perr := brFn.Execute(context.Background(), prependRt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"), PrependIfNotFound: true,
	}); perr != nil {
		t.Fatal(perr)
	}
	data, _ = prependRt.FS.ReadFile("/f")
	if !strings.HasPrefix(string(data), "#-- start managed zone --\n") {
		t.Fatalf("prepend result = %q", string(data))
	}

	afterRt := xtRT(t, map[string]string{"/f": "target here\n"})
	if _, ierr := brFn.Execute(context.Background(), afterRt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"), InsertAfterMatch: strPtr("target"),
	}); ierr != nil {
		t.Fatal(ierr)
	}
	data, _ = afterRt.FS.ReadFile("/f")
	if !strings.Contains(string(data), "target here\n#-- start managed zone --") {
		t.Fatalf("insert-after result = %q", string(data))
	}

	beforeRt := xtRT(t, map[string]string{"/f": "target here\n"})
	if _, ierr := brFn.Execute(context.Background(), beforeRt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"), InsertBeforeMatch: strPtr("target"),
	}); ierr != nil {
		t.Fatal(ierr)
	}
	data, _ = beforeRt.FS.ReadFile("/f")
	if !strings.HasPrefix(string(data), "#-- start managed zone --\nblock\n") {
		t.Fatalf("insert-before result = %q", string(data))
	}
}

func TestBlockreplaceUnterminatedAndDryRun(t *testing.T) {
	rt := xtRT(t, map[string]string{"/f": "#-- start managed zone --\nnever ends\n"})
	brFn := blockreplaceFunc{}
	_, uerr := brFn.Execute(context.Background(), rt, &blockreplaceArgs{
		Path: "/f", Content: strPtr("block\n"),
	})
	if uerr == nil || uerr.Error() !=
		"Unterminated marked block. End of file reached before marker_end." {
		t.Fatalf("unterminated error = %v", uerr)
	}

	rt2 := xtRT(t, map[string]string{"/f": "#-- start --\nold\n#-- end --\n"})
	ret, derr := brFn.Execute(context.Background(), rt2, &blockreplaceArgs{
		Path: "/f", Content: strPtr("new\n"), DryRun: true,
		MarkerStart: strPtr("#-- start --"), MarkerEnd: strPtr("#-- end --"),
	})
	if derr != nil {
		t.Fatal(derr)
	}
	diff := ret.(string)
	if !strings.Contains(diff, "+new") {
		t.Fatalf("dry-run diff = %q", diff)
	}
	data, _ := rt2.FS.ReadFile("/f")
	if !strings.Contains(string(data), "old\n") {
		t.Fatalf("dry run modified the file: %q", string(data))
	}
}

func TestMakedirs(t *testing.T) {
	rt := xtRT(t, nil)

	_, err := (makedirsFunc{}).Execute(context.Background(), rt,
		&makedirsArgs{Path: "/testbed/a/b/c/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/testbed", "/testbed/a", "/testbed/a/b"} {
		if info, serr := rt.FS.Stat(dir); serr != nil || !info.IsDir() {
			t.Fatalf("makedirs_ did not create %s", dir)
		}
	}

	if _, err := (makedirsPermsFunc{}).Execute(context.Background(), rt,
		&makedirsPermsArgs{Name: "/testbed/x/y/z"}); err != nil {
		t.Fatal(err)
	}
	if info, serr := rt.FS.Stat("/testbed/x/y/z"); serr != nil || !info.IsDir() {
		t.Fatalf("makedirs_perms did not create target")
	}
}

func TestReaddirAndRmdir(t *testing.T) {
	rt := xtRT(t, map[string]string{
		"/dir/sub/nested.txt": "n",
		"/dir/top.txt":        "t",
	})

	got, err := (readdirFunc{}).Execute(context.Background(), rt, &readdirArgs{Path: "/dir"})
	if err != nil {
		t.Fatal(err)
	}
	names := got.([]string)
	if len(names) != 4 || names[0] != "." || names[1] != ".." ||
		names[2] != "sub" || names[3] != "top.txt" {
		t.Fatalf("readdir = %#v", names)
	}

	rdFn := readdirFunc{}
	_, rerr := rdFn.Execute(context.Background(), rt, &readdirArgs{Path: "relative/dir"})
	if rerr == nil || rerr.Error() != "Dir path must be absolute." {
		t.Fatalf("relative readdir = %v", rerr)
	}

	rmFn := rmdirFunc{}
	got, rmErr := rmFn.Execute(context.Background(), rt, &rmdirArgs{Path: "/dir/sub"})
	if rmErr != nil {
		t.Fatal(rmErr)
	}
	if got != false {
		t.Fatalf("rmdir non-empty = %#v", got)
	}

	rt2 := xtRT(t, map[string]string{"/tree/in/file": "x"})
	rmF := removeFunc{}
	if _, err := rmF.Execute(context.Background(), rt2, &removeArgs{Path: "/tree/in/file"}); err != nil {
		t.Fatal(err)
	}
	got, err = rmFn.Execute(context.Background(), rt2, &rmdirArgs{Path: "/tree", Recurse: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Fatalf("recursive rmdir = %#v", got)
	}
	if _, serr := rt2.FS.Stat("/tree"); serr == nil {
		t.Fatalf("tree survived recursive rmdir")
	}
}

func TestSymlinkIdempotenceAndForce(t *testing.T) {
	rt := xtRT(t, map[string]string{"/real/target": "t"})
	if err := rt.FS.Symlink("/real/target", "/link"); err != nil {
		t.Fatal(err)
	}

	symFn := symlinkFunc{}
	got, err := symFn.Execute(context.Background(), rt, &SymlinkArgs{
		Src: "/real/target", Path: "/link",
	})
	if err != nil || got != true {
		t.Fatalf("idempotent symlink = %#v, %v", got, err)
	}

	if _, err := symFn.Execute(context.Background(), rt, &SymlinkArgs{
		Src: "/real/other", Path: "/link",
	}); err == nil {
		t.Fatalf("conflicting symlink succeeded without force")
	}

	got, err = symFn.Execute(context.Background(), rt, &SymlinkArgs{
		Src: "/real/other", Path: "/link", Force: true,
	})
	if err != nil || got != true {
		t.Fatalf("forced symlink = %#v, %v", got, err)
	}
	target, _ := rt.FS.Readlink("/link")
	if target != "/real/other" {
		t.Fatalf("readlink = %q", target)
	}

	linkCheck := isLinkFunc{}
	got, _ = linkCheck.Execute(context.Background(), rt, &IsLinkArgs{Path: "/link"})
	if got != true {
		t.Fatalf("is_link = %#v", got)
	}
	got, _ = linkCheck.Execute(context.Background(), rt, &IsLinkArgs{Path: "/real/target"})
	if got != false {
		t.Fatalf("is_link regular file = %#v", got)
	}
}

func TestRelativeSymlinkGuard(t *testing.T) {
	rt := xtRT(t, nil)
	symFn := symlinkFunc{}
	_, err := symFn.Execute(context.Background(), rt, &SymlinkArgs{
		Src: "/real/target", Path: "relative/link",
	})
	if err == nil || err.Error() != "Link path must be absolute: relative/link" {
		t.Fatalf("relative guard = %v", err)
	}
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }
