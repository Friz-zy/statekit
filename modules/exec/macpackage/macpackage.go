// Package macpackage implements Salt's Darwin macpackage execution surface.
// Native installer, pkgutil, hdiutil, xar, PlistBuddy and rsync commands are
// routed through Runtime.Runner; filesystem cleanup uses Runtime.FS.
package macpackage

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, command process.Command) process.CommandResult {
	return rt.Runner.Run(ctx, command)
}

func runArgv(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return run(ctx, rt, runtime.Command(argv...))
}

func resultMap(result process.CommandResult) map[string]any {
	code := result.ExitCode
	if result.Err != nil && code == 0 {
		code = -1
	}
	return map[string]any{
		"retcode": code,
		"stdout":  string(result.Stdout),
		"stderr":  string(result.Stderr),
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func wildcardPackage(value string) bool { return strings.Contains(value, "*.") }

// ---------------------------------------------------------------------------
// install

type installArgs struct {
	Pkg            string `statekit:"required,name=pkg"`
	Target         string `statekit:"name=target"`
	Store          bool   `statekit:"name=store"`
	AllowUntrusted bool   `statekit:"name=allow_untrusted"`
}
type installFunc struct{}

func (installFunc) Name() string        { return "macpackage.install" }
func (installFunc) Args() any           { return installArgs{} }
func (installFunc) Platforms() []string { return []string{"darwin"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*installArgs)
	target := a.Target
	if target == "" {
		target = "LocalSystem"
	}
	if wildcardPackage(a.Pkg) {
		command := "installer -pkg " + a.Pkg + " -target " + shellQuote(target)
		if a.Store {
			command += " -store"
		}
		if a.AllowUntrusted {
			command += " -allowUntrusted"
		}
		return resultMap(run(ctx, rt, process.Command{Name: command, Shell: true})), nil
	}
	argv := []string{"installer", "-pkg", a.Pkg, "-target", target}
	if a.Store {
		argv = append(argv, "-store")
	}
	if a.AllowUntrusted {
		argv = append(argv, "-allowUntrusted")
	}
	return resultMap(runArgv(ctx, rt, argv...)), nil
}

// ---------------------------------------------------------------------------
// app installation and mount

type installAppArgs struct {
	App    string `statekit:"required,name=app"`
	Target string `statekit:"name=target"`
}
type installAppFunc struct{}

func (installAppFunc) Name() string        { return "macpackage.install_app" }
func (installAppFunc) Args() any           { return installAppArgs{} }
func (installAppFunc) Platforms() []string { return []string{"darwin"} }
func (installAppFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*installAppArgs)
	target := a.Target
	if target == "" {
		target = "/Applications/"
	}
	if !strings.HasSuffix(target, ".app") {
		base := filepath.Base(strings.TrimSuffix(a.App, "/"))
		target = filepath.Join(target, base)
	}
	app := a.App
	if !strings.HasSuffix(app, "/") {
		app += "/"
	}
	result := runArgv(ctx, rt, "rsync", "-a", "--delete", app, target)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	return string(result.Stdout), nil
}

type uninstallAppArgs struct {
	App string `statekit:"required,name=app"`
}
type uninstallAppFunc struct{}

func (uninstallAppFunc) Name() string        { return "macpackage.uninstall_app" }
func (uninstallAppFunc) Args() any           { return uninstallAppArgs{} }
func (uninstallAppFunc) Platforms() []string { return []string{"darwin"} }
func (uninstallAppFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*uninstallAppArgs)
	return true, rt.FS.RemoveAll(a.App)
}

type mountArgs struct {
	DMG string `statekit:"required,name=dmg"`
}
type mountFunc struct{}

func (mountFunc) Name() string        { return "macpackage.mount" }
func (mountFunc) Args() any           { return mountArgs{} }
func (mountFunc) Platforms() []string { return []string{"darwin"} }
func (mountFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*mountArgs)
	mountpoint, err := rt.FS.MkdirTemp("", "dmg-")
	if err != nil {
		return nil, err
	}
	result := runArgv(ctx, rt, "hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mountpoint, a.DMG)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	return []any{string(result.Stdout), mountpoint}, nil
}

type unmountArgs struct {
	Mountpoint string `statekit:"required,name=mountpoint"`
}
type unmountFunc struct{}

func (unmountFunc) Name() string        { return "macpackage.unmount" }
func (unmountFunc) Args() any           { return unmountArgs{} }
func (unmountFunc) Platforms() []string { return []string{"darwin"} }
func (unmountFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*unmountArgs)
	result := runArgv(ctx, rt, "hdiutil", "detach", a.Mountpoint)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	return string(result.Stdout), nil
}

// ---------------------------------------------------------------------------
// package listing and identifiers

type installedPkgsArgs struct{}
type installedPkgsFunc struct{}

func (installedPkgsFunc) Name() string        { return "macpackage.installed_pkgs" }
func (installedPkgsFunc) Args() any           { return installedPkgsArgs{} }
func (installedPkgsFunc) Platforms() []string { return []string{"darwin"} }
func (installedPkgsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	result := runArgv(ctx, rt, "pkgutil", "--pkgs")
	return strings.Split(string(result.Stdout), "\n"), nil
}

type getPkgIDArgs struct {
	Pkg string `statekit:"required,name=pkg"`
}
type getPkgIDFunc struct{}

func (getPkgIDFunc) Name() string        { return "macpackage.get_pkg_id" }
func (getPkgIDFunc) Args() any           { return getPkgIDArgs{} }
func (getPkgIDFunc) Platforms() []string { return []string{"darwin"} }
func (getPkgIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*getPkgIDArgs)
	return getPkgIDs(ctx, rt, a.Pkg), nil
}

var packageIdentifier = regexp.MustCompile(`identifier="([a-zA-Z.0-9-]+)"`)

func getPkgIDs(ctx context.Context, rt *runtime.Runtime, pkg string) []string {
	tempDir, err := rt.FS.MkdirTemp("", "pkg-")
	if err != nil {
		return []string{}
	}
	defer rt.FS.RemoveAll(tempDir)

	listCommand := "xar -t -f " + shellQuote(pkg) + " | grep PackageInfo"
	result := run(ctx, rt, process.Command{Name: listCommand, Shell: true})
	out := string(result.Stdout)
	if !strings.Contains(out, "Error opening") {
		var files []string
		for _, item := range strings.Split(out, "\n") {
			if strings.TrimSpace(item) != "" {
				files = append(files, item)
			}
		}
		if len(files) == 0 {
			return []string{}
		}
		extract := "xar -x -f " + shellQuote(pkg)
		for _, file := range files {
			extract += " " + shellQuote(file)
		}
		run(ctx, rt, process.Command{Name: extract, Dir: tempDir, Shell: true})
		var ids []string
		for _, file := range files {
			data, rerr := rt.FS.ReadFile(filepath.Join(tempDir, file))
			if rerr != nil {
				continue
			}
			for _, match := range packageIdentifier.FindAllStringSubmatch(string(data), -1) {
				ids = append(ids, match[1])
			}
		}
		return ids
	}
	return getPkgIDsFromDirectory(ctx, rt, pkg)
}

func getPkgIDsFromDirectory(ctx context.Context, rt *runtime.Runtime, path string) []string {
	infoPath := filepath.Join(path, "Contents", "Info.plist")
	command := "/usr/libexec/PlistBuddy -c \"print :CFBundleIdentifier\" " + shellQuote(infoPath)
	result := run(ctx, rt, process.Command{Name: command, Shell: true})
	out := strings.TrimSpace(string(result.Stdout))
	if !strings.Contains(out, "Does Not Exist") && out != "" {
		return []string{out}
	}
	return []string{}
}

type getMpkgIDsArgs struct {
	MPKG string `statekit:"required,name=mpkg"`
}
type getMpkgIDsFunc struct{}

func (getMpkgIDsFunc) Name() string        { return "macpackage.get_mpkg_ids" }
func (getMpkgIDsFunc) Args() any           { return getMpkgIDsArgs{} }
func (getMpkgIDsFunc) Platforms() []string { return []string{"darwin"} }
func (getMpkgIDsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacPackage(&res, &err)
	a := args.(*getMpkgIDsArgs)
	base := filepath.Dir(a.MPKG)
	command := "find " + shellQuote(base) + " -name '*.pkg'"
	result := run(ctx, rt, process.Command{Name: command, Shell: true})
	var ids []string
	for _, file := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(file) == "" {
			continue
		}
		values := getPkgIDs(ctx, rt, file)
		ids = append(ids, values...)
	}
	return ids, nil
}

func recoverMacPackage(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}

// Register installs the Darwin macpackage functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		installFunc{}, installAppFunc{}, uninstallAppFunc{}, mountFunc{}, unmountFunc{},
		installedPkgsFunc{}, getPkgIDFunc{}, getMpkgIDsFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
