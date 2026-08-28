// Package pkgutil implements Salt's Darwin pkgutil execution surface.
// It keeps the pkgutil virtual name separate from the generic pkg provider and
// sends native installer commands through the central Runner.
package pkgutil

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, int, error) {
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.ExitCode, result.Err
	}
	return string(result.Stdout), result.ExitCode, nil
}

func runInstall(ctx context.Context, rt *runtime.Runtime, source string) bool {
	_, code, err := run(ctx, rt, "installer", "-pkg", source, "-target", "/")
	return err == nil && code == 0
}

func pkgutilList(ctx context.Context, rt *runtime.Runtime) []string {
	stdout, _, err := run(ctx, rt, "pkgutil", "--pkgs")
	if err != nil {
		return []string{}
	}
	return strings.Split(stdout, "\n")
}

// ---------------------------------------------------------------------------
// list / is_installed

type listArgs struct{}
type listFunc struct{}

func (listFunc) Name() string        { return "pkgutil.list" }
func (listFunc) Args() any           { return listArgs{} }
func (listFunc) Platforms() []string { return []string{"darwin"} }
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPkgutil(&res, &err)
	return pkgutilList(ctx, rt), nil
}

type isInstalledArgs struct {
	PackageID string `statekit:"required,name=package_id"`
}
type isInstalledFunc struct{}

func (isInstalledFunc) Name() string        { return "pkgutil.is_installed" }
func (isInstalledFunc) Args() any           { return isInstalledArgs{} }
func (isInstalledFunc) Platforms() []string { return []string{"darwin"} }
func (isInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPkgutil(&res, &err)
	a := args.(*isInstalledArgs)
	for _, installed := range pkgutilList(ctx, rt) {
		if installed == a.PackageID {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// install / forget

type installArgs struct {
	Source    string `statekit:"required,name=source"`
	PackageID string `statekit:"required,name=package_id"`
}
type installFunc struct{}

func (installFunc) Name() string        { return "pkgutil.install" }
func (installFunc) Args() any           { return installArgs{} }
func (installFunc) Platforms() []string { return []string{"darwin"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPkgutil(&res, &err)
	a := args.(*installArgs)
	if installed, ierr := (isInstalledFunc{}).Execute(ctx, rt, &isInstalledArgs{PackageID: a.PackageID}); ierr == nil && installed == true {
		return true, nil
	}
	parsed, err := url.Parse(a.Source)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "" {
		return nil, fmt.Errorf("Unsupported scheme for source uri: %s", parsed.Scheme)
	}
	if !fileExists(rt, a.Source) {
		return nil, fmt.Errorf("File not found: %s", a.Source)
	}
	runInstall(ctx, rt, a.Source)
	installed, ierr := isInstalledFunc{}.Execute(ctx, rt, &isInstalledArgs{PackageID: a.PackageID})
	if ierr != nil {
		return nil, ierr
	}
	return installed, nil
}

type forgetArgs struct {
	PackageID string `statekit:"required,name=package_id"`
}
type forgetFunc struct{}

func (forgetFunc) Name() string        { return "pkgutil.forget" }
func (forgetFunc) Args() any           { return forgetArgs{} }
func (forgetFunc) Platforms() []string { return []string{"darwin"} }
func (forgetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPkgutil(&res, &err)
	a := args.(*forgetArgs)
	_, _, _ = run(ctx, rt, "pkgutil", "--forget", a.PackageID)
	installed, ierr := isInstalledFunc{}.Execute(ctx, rt, &isInstalledArgs{PackageID: a.PackageID})
	if ierr != nil {
		return nil, ierr
	}
	return installed == false, nil
}

func fileExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && !info.IsDir()
}

func recoverPkgutil(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}

// Register installs the Darwin pkgutil surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{}, isInstalledFunc{}, installFunc{}, forgetFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
