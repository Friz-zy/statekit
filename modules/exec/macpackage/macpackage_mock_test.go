package macpackage

// R6.11 mock tests for the macpackage surface, mapped onto
// saltstack/salt/modules/macpackage.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_macpackage.py: exact
// installer/rsync/hdiutil/pkgutil argv, the wildcard shell branch,
// xar PackageInfo extraction with identifier regex parsing, the
// PlistBuddy directory fallback, mount/unmount error mapping and the
// registry matrix. All Runner output is scripted.

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// macPackageMockRunner scripts the installer/rsync/hdiutil/pkgutil/xar
// toolchain. The `xar -x` step materializes PackageInfo payloads into the
// Runtime filesystem the way a real extraction would so get_pkg_id can
// read them back through Runtime.FS.
type macPackageMockRunner struct {
	fs            runtime.FileSystem
	xarList       string            // stdout for `xar -t ... | grep PackageInfo`
	pkgInfo       map[string]string // extracted file -> PackageInfo body
	plistBuddyOut string
	findOut       string
	hdiutilErr    bool
	rsyncErr      bool
	calls         []process.Command
}

func (r *macPackageMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	argv := append([]string{command.Name}, command.Args...)
	switch {
	case argv[0] == "installer":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("installed")}
	case argv[0] == "rsync":
		if r.rsyncErr {
			return process.CommandResult{ExitCode: -1, Err: errors.New("rsync: failed")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("copied")}
	case argv[0] == "hdiutil":
		if r.hdiutilErr {
			return process.CommandResult{ExitCode: -1, Err: errors.New("hdiutil: attach failed")}
		}
		if len(argv) > 1 && argv[1] == "attach" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte("attached")}
		}
		return process.CommandResult{ExitCode: 0}
	case argv[0] == "pkgutil":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("com.apple.this\ncom.salt.that")}
	case command.Shell && strings.HasPrefix(command.Name, "xar -t"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.xarList)}
	case command.Shell && strings.HasPrefix(command.Name, "xar -x"):
		// a real extraction lands inside the command's working dir;
		// get_pkg_id reads the payloads back via filepath.Join.
		for name, body := range r.pkgInfo {
			target := filepath.Join(command.Dir, name)
			if err := r.fs.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return process.CommandResult{ExitCode: 1, Stderr: []byte(err.Error())}
			}
			if err := r.fs.WriteFile(target, []byte(body), 0o644); err != nil {
				return process.CommandResult{ExitCode: 1, Stderr: []byte(err.Error())}
			}
		}
		return process.CommandResult{ExitCode: 0}
	case command.Shell && strings.Contains(command.Name, "PlistBuddy"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.plistBuddyOut)}
	case command.Shell && strings.HasPrefix(command.Name, "find "):
		return process.CommandResult{ExitCode: 0, Stdout: []byte(r.findOut)}
	}
	return process.CommandResult{ExitCode: 0}
}

func macPackageMockRuntime(t *testing.T) (*runtime.Runtime, *macPackageMockRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	runner := &macPackageMockRunner{fs: fs, pkgInfo: map[string]string{}}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func macPackageArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestMacPackageInstallArgvMatrix(t *testing.T) {
	// pytest test_install: argv form, default target LocalSystem.
	rt, runner := macPackageMockRuntime(t)
	res, err := installFunc{}.Execute(context.Background(), rt, &installArgs{Pkg: "/path/to/file.pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any); got["retcode"] != 0 || got["stdout"] != "installed" {
		t.Fatalf("install result = %#v", got)
	}
	if got := macPackageArgv(runner.calls[0]); got != "installer -pkg /path/to/file.pkg -target LocalSystem" {
		t.Fatalf("install argv = %q", got)
	}
	if runner.calls[0].Shell {
		t.Fatal("plain install must stay shell-free")
	}

	// pytest test_install_with_extras: flag order -store -allowUntrusted.
	rt, runner = macPackageMockRuntime(t)
	if _, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Pkg: "/path/to/file.pkg", Store: true, AllowUntrusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	want := "installer -pkg /path/to/file.pkg -target LocalSystem -store -allowUntrusted"
	if got := macPackageArgv(runner.calls[0]); got != want {
		t.Fatalf("extras argv = %q; want %q", got, want)
	}

	// pytest test_install_wildcard: the shell branch keeps the glob
	// unquoted; the port additionally shell-quotes the target.
	rt, runner = macPackageMockRuntime(t)
	res, err = installFunc{}.Execute(context.Background(), rt, &installArgs{Pkg: "/path/to/*.pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]any); got["retcode"] != 0 {
		t.Fatalf("wildcard retcode = %v", got["retcode"])
	}
	if got := runner.calls[0].Name; got != "installer -pkg /path/to/*.pkg -target 'LocalSystem'" {
		t.Fatalf("wildcard command = %q", got)
	}
	if !runner.calls[0].Shell {
		t.Fatal("wildcard install must opt into the shell")
	}

	// an explicit custom target flows through in both branches.
	rt, runner = macPackageMockRuntime(t)
	if _, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Pkg: "/path/to/file.pkg", Target: "/Volumes/Macintosh HD",
	}); err != nil {
		t.Fatal(err)
	}
	if got := macPackageArgv(runner.calls[0]); got != "installer -pkg /path/to/file.pkg -target /Volumes/Macintosh HD" {
		t.Fatalf("custom target argv = %q", got)
	}
}

func TestMacPackageInstallAppTargets(t *testing.T) {
	// pytest test_install_app: default target derives the .app name.
	rt, runner := macPackageMockRuntime(t)
	res, err := installAppFunc{}.Execute(context.Background(), rt, &installAppArgs{App: "/path/to/file.app"})
	if err != nil || res != "copied" {
		t.Fatalf("install_app = %v %v", res, err)
	}
	want := "rsync -a --delete /path/to/file.app/ /Applications/file.app"
	if got := macPackageArgv(runner.calls[0]); got != want {
		t.Fatalf("install_app argv = %q; want %q", got, want)
	}
	if runner.calls[0].Shell {
		t.Fatal("rsync must stay shell-free")
	}

	// pytest test_install_app_specify_target: a .app target is kept.
	rt, runner = macPackageMockRuntime(t)
	if _, err := (installAppFunc{}).Execute(context.Background(), rt, &installAppArgs{
		App: "/path/to/file.app", Target: "/Applications/new.app",
	}); err != nil {
		t.Fatal(err)
	}
	if got := macPackageArgv(runner.calls[0]); got != "rsync -a --delete /path/to/file.app/ /Applications/new.app" {
		t.Fatalf("target argv = %q", got)
	}

	// pytest test_install_app_with_slash: a trailing slash on the source
	// is normalized instead of doubled.
	rt, runner = macPackageMockRuntime(t)
	if _, err := (installAppFunc{}).Execute(context.Background(), rt, &installAppArgs{
		App: "/path/to/file.app/",
	}); err != nil {
		t.Fatal(err)
	}
	if got := macPackageArgv(runner.calls[0]); got != "rsync -a --delete /path/to/file.app/ /Applications/file.app" {
		t.Fatalf("slash argv = %q", got)
	}

	// a runner failure (Err + ExitCode -1) surfaces as an error.
	rt, runner = macPackageMockRuntime(t)
	runner.rsyncErr = true
	if _, err := (installAppFunc{}).Execute(context.Background(), rt, &installAppArgs{App: "/x/a.app"}); err == nil {
		t.Fatal("failed rsync must return an error")
	}
}

func TestMacPackageMountUnmount(t *testing.T) {
	// pytest test_mount: hdiutil attach argv order and dmg- temp prefix.
	rt, runner := macPackageMockRuntime(t)
	res, err := mountFunc{}.Execute(context.Background(), rt, &mountArgs{DMG: "/path/to/file.dmg"})
	if err != nil {
		t.Fatal(err)
	}
	pair := res.([]any)
	if pair[0] != "attached" {
		t.Fatalf("mount stdout = %v", pair[0])
	}
	mountpoint, ok := pair[1].(string)
	if !ok || !strings.Contains(mountpoint, "dmg-") {
		t.Fatalf("mountpoint = %#v", pair[1])
	}
	want := "hdiutil attach -readonly -nobrowse -mountpoint " + mountpoint + " /path/to/file.dmg"
	if got := macPackageArgv(runner.calls[0]); got != want {
		t.Fatalf("mount argv = %q; want %q", got, want)
	}

	// pytest test_unmount: detach targets the given mountpoint.
	rt, runner = macPackageMockRuntime(t)
	res, err = unmountFunc{}.Execute(context.Background(), rt, &unmountArgs{Mountpoint: "/tmp/dmg-ABCDEF"})
	if err != nil || res != "" {
		t.Fatalf("unmount = %q %v", res, err)
	}
	if got := macPackageArgv(runner.calls[0]); got != "hdiutil detach /tmp/dmg-ABCDEF" {
		t.Fatalf("unmount argv = %q", got)
	}

	// attach failure (Err + ExitCode -1) maps onto an error return.
	rt, runner = macPackageMockRuntime(t)
	runner.hdiutilErr = true
	if _, err := (mountFunc{}).Execute(context.Background(), rt, &mountArgs{DMG: "/x.dmg"}); err == nil {
		t.Fatal("failed attach must return an error")
	}
}

func TestMacPackageInstalledPkgsSplit(t *testing.T) {
	// pytest test_installed_pkgs: pkgutil --pkgs output splits as-is.
	rt, runner := macPackageMockRuntime(t)
	res, err := installedPkgsFunc{}.Execute(context.Background(), rt, installedPkgsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// pytest test_installed_pkgs: splitlines of the fixture without a
	// trailing newline yields exactly the two receipt ids.
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.this", "com.salt.that"}) {
		t.Fatalf("installed_pkgs = %#v", got)
	}
	if got := macPackageArgv(runner.calls[0]); got != "pkgutil --pkgs" {
		t.Fatalf("argv = %q", got)
	}
}

func TestMacPackageGetPkgIDFromXarFiles(t *testing.T) {
	// pytest test_get_pkg_id_with_files: `xar -t` lists PackageInfo
	// files, `xar -x` extracts them, and identifiers are parsed in order.
	rt, runner := macPackageMockRuntime(t)
	runner.xarList = "/path/to/PackageInfo\n/path/to/some/other/fake/PackageInfo\n"
	runner.pkgInfo = map[string]string{
		"/path/to/PackageInfo":                 `<pkg-info identifier="com.apple.this" version="1.0"/>`,
		"/path/to/some/other/fake/PackageInfo": `<pkg-info identifier="com.salt.that"/>`,
	}
	res, err := getPkgIDFunc{}.Execute(context.Background(), rt, &getPkgIDArgs{Pkg: "/path/to/file.pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.this", "com.salt.that"}) {
		t.Fatalf("pkg ids = %#v", got)
	}
	if !runner.calls[0].Shell || runner.calls[0].Name != "xar -t -f '/path/to/file.pkg' | grep PackageInfo" {
		t.Fatalf("xar -t command = %q shell=%v", runner.calls[0].Name, runner.calls[0].Shell)
	}
	extract := runner.calls[1]
	if !extract.Shell {
		t.Fatal("xar -x must opt into the shell")
	}
	want := "xar -x -f '/path/to/file.pkg' '/path/to/PackageInfo' '/path/to/some/other/fake/PackageInfo'"
	if extract.Name != want {
		t.Fatalf("xar -x command = %q; want %q", extract.Name, want)
	}
	if extract.Dir == "" {
		t.Fatal("xar -x must run inside the temp dir")
	}
	// identifier charset per Salt: letters, digits, dots and dashes.
	if !packageIdentifier.MatchString(`identifier="es.gob.afirma-1"`) {
		t.Fatal("identifier regex must accept dotted dashed ids")
	}
	if packageIdentifier.MatchString(`identifier="under_score"`) {
		t.Fatal("identifier regex must reject underscores like Salt's [a-zA-Z.0-9-]")
	}
}

func TestMacPackageGetPkgIDEmptyXarList(t *testing.T) {
	// An archive listing without PackageInfo files yields no ids and no
	// extraction.
	rt, runner := macPackageMockRuntime(t)
	runner.xarList = "\n"
	res, err := getPkgIDFunc{}.Execute(context.Background(), rt, &getPkgIDArgs{Pkg: "/x.pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); len(got) != 0 {
		t.Fatalf("ids = %#v", got)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
}

func TestMacPackageGetPkgIDDirectoryFallback(t *testing.T) {
	// pytest test_get_pkg_id_with_dir: "Error opening" output routes to
	// the PlistBuddy directory branch.
	rt, runner := macPackageMockRuntime(t)
	runner.xarList = "Error opening /path/to/file.pkg"
	runner.plistBuddyOut = "com.apple.this\n"
	res, err := getPkgIDFunc{}.Execute(context.Background(), rt, &getPkgIDArgs{Pkg: "/path/to/file.pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.this"}) {
		t.Fatalf("dir ids = %#v", got)
	}
	command := runner.calls[1]
	if !command.Shell {
		t.Fatal("PlistBuddy runs through the shell")
	}
	want := `/usr/libexec/PlistBuddy -c "print :CFBundleIdentifier" '/path/to/file.pkg/Contents/Info.plist'`
	if command.Name != want {
		t.Fatalf("PlistBuddy command = %q; want %q", command.Name, want)
	}

	// "Does Not Exist" and empty output both yield an empty list.
	for _, out := range []string{"Does Not Exist: No such key", "\n"} {
		rt, runner := macPackageMockRuntime(t)
		runner.xarList = "Error opening /x"
		runner.plistBuddyOut = out
		res, err := getPkgIDFunc{}.Execute(context.Background(), rt, &getPkgIDArgs{Pkg: "/x"})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.([]string); len(got) != 0 {
			t.Fatalf("plist buddy out %q ids = %#v", out, got)
		}
	}
}

func TestMacPackageGetMpkgIDs(t *testing.T) {
	// pytest test_get_mpkg_ids: find -name '*.pkg' then per-pkg ids.
	rt, runner := macPackageMockRuntime(t)
	runner.findOut = "/tmp/dmg-X/file.pkg\n/tmp/dmg-X/other.pkg\n"
	runner.xarList = "Error opening archive"
	runner.plistBuddyOut = "com.apple.this\n"
	res, err := getMpkgIDsFunc{}.Execute(context.Background(), rt, &getMpkgIDsArgs{MPKG: "/path/to/file.mpkg"})
	if err != nil {
		t.Fatal(err)
	}
	// both found pkgs resolve through the directory fallback; duplicate
	// identifier output collapses into repeated entries like Salt's.
	if got := res.([]string); !reflect.DeepEqual(got, []string{"com.apple.this", "com.apple.this"}) {
		t.Fatalf("mpkg ids = %#v", got)
	}
	if got := runner.calls[0].Name; got != "find '/path/to' -name '*.pkg'" {
		t.Fatalf("find command = %q", got)
	}
	if !runner.calls[0].Shell {
		t.Fatal("find must opt into the shell")
	}
}

func TestMacPackageUninstallAppRemovesTree(t *testing.T) {
	// pytest test_uninstall: file.remove semantics on the app path.
	rt, _ := macPackageMockRuntime(t)
	if err := rt.FS.MkdirAll("/path/to/Demo.app/Contents", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := uninstallAppFunc{}.Execute(context.Background(), rt, &uninstallAppArgs{App: "/path/to/Demo.app"})
	if err != nil || res != true {
		t.Fatalf("uninstall_app = %v %v", res, err)
	}
	if _, err := rt.FS.Stat("/path/to/Demo.app"); err == nil {
		t.Fatal("app tree remains after uninstall")
	}
}

func TestMacPackageRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"macpackage.get_mpkg_ids",
		"macpackage.get_pkg_id",
		"macpackage.install",
		"macpackage.install_app",
		"macpackage.installed_pkgs",
		"macpackage.mount",
		"macpackage.uninstall_app",
		"macpackage.unmount",
	}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, runner := macPackageMockRuntime(t)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "macpackage.installed_pkgs", installedPkgsArgs{})
		if err != nil || len(res.([]string)) != 2 {
			t.Fatalf("dispatch = %v %v", res, err)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("dispatch calls = %d", len(runner.calls))
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "macpackage.installed_pkgs", installedPkgsArgs{}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
