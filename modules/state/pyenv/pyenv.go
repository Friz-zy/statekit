// Package pyenv implements Salt's pyenv state functions: installed,
// absent, and install_pyenv, delegating to the registered pyenv.*
// execution functions.
//
// Reference: saltstack/salt/states/pyenv.py @ pinned revision. Behavioral
// tests mapped from saltstack/tests/pytests/unit/states/test_pyenv.py.
//
// Contract notes (init.md section 28):
//
//   - install_pyenv passes its `user` argument where upstream expects a
//     python version (a pinned upstream quirk — the state attempts to
//     install a python named after the user).
//   - The non-standard "default" key of upstream's result dict maps into
//     StateResult.Meta.
package pyenv

import (
	"context"
	"regexp"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execpyenv "github.com/friz-zy/statekit/modules/exec/pyenv"
)

var pythonPrefixRe = regexp.MustCompile(`^python-`)

func stripPythonPrefix(name string) string { return pythonPrefixRe.ReplaceAllString(name, "") }

type InstalledArgs struct {
	Name    string  `statekit:"required"`
	Default bool    `statekit:"name=default"`
	User    *string `statekit:"name=user"`
	Test    bool    `statekit:"name=test"`
}

type installedFunc struct{}

func (installedFunc) Name() string { return "pyenv.installed" }
func (installedFunc) Args() any    { return InstalledArgs{} }

func (installedFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*InstalledArgs)
	ret := result.New(a.Name, "", nil, map[string]any{})

	name := stripPythonPrefix(a.Name)
	if a.Test {
		ret.Comment = "python " + name + " is set to be installed"
		return ret
	}

	if !execBool(ctx, rt, "pyenv.is_installed", &execpyenv.IsInstalledArgs{Runas: a.User}) {
		ret.Result = result.Bool(false)
		ret.Comment = "pyenv is not installed."
		if !execBool(ctx, rt, "pyenv.install", &execpyenv.InstallArgs{Runas: a.User}) {
			ret.Comment = "pyenv failed to install"
			return ret
		}
	}
	return checkAndInstallPython(ctx, rt, ret, name, a.Default, strOr(a.User, ""))
}

type AbsentArgs struct {
	Name string  `statekit:"required"`
	User *string `statekit:"name=user"`
	Test bool    `statekit:"name=test"`
}

type absentFunc struct{}

func (absentFunc) Name() string { return "pyenv.absent" }
func (absentFunc) Args() any    { return AbsentArgs{} }

func (absentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*AbsentArgs)
	ret := result.New(a.Name, "", nil, map[string]any{})

	name := stripPythonPrefix(a.Name)
	if a.Test {
		ret.Comment = "python " + name + " is set to be uninstalled"
		return ret
	}

	if !execBool(ctx, rt, "pyenv.is_installed", &execpyenv.IsInstalledArgs{Runas: a.User}) {
		ret.Result = result.Bool(true)
		ret.Comment = "pyenv not installed, " + name + " not either"
		return ret
	}

	// _python_installed probe.
	defaultRes, derr := rt.Exec.Call(ctx, rt, "pyenv.default",
		&execpyenv.DefaultArgs{Runas: a.User})
	currentDefault := ""
	if derr == nil {
		s, _ := defaultRes.(string)
		currentDefault = s
	}
	found := false
	versionsRes, verr := rt.Exec.Call(ctx, rt, "pyenv.versions",
		&execpyenv.VersionsArgs{Runas: a.User})
	if verr == nil {
		if versions, ok := versionsRes.([]string); ok {
			for _, version := range versions {
				if version == name {
					found = true
					break
				}
			}
		}
	}

	if found {
		isDefault := currentDefault == name
		if isDefault {
			rt.Exec.Call(ctx, rt, "pyenv.default",
				&execpyenv.DefaultArgs{Python: strPtr("system"), Runas: a.User})
		}
		uninstalled := execBool(ctx, rt, "pyenv.uninstall_python",
			&execpyenv.UninstallPythonArgs{Python: name, Runas: a.User})
		if uninstalled {
			ret.Result = result.Bool(true)
			ret.Changes[name] = "Uninstalled"
			ret.Comment = "Successfully removed python"
			return ret
		}
		ret.Result = result.Bool(false)
		ret.Comment = "Failed to uninstall python"
		return ret
	}

	ret.Result = result.Bool(true)
	ret.Comment = "python " + name + " is already absent"
	return ret
}

type InstallPyenvArgs struct {
	Name string  `statekit:"required"`
	User *string `statekit:"name=user"`
	Test bool    `statekit:"name=test"`
}

type installPyenvFunc struct{}

func (installPyenvFunc) Name() string { return "pyenv.install_pyenv" }
func (installPyenvFunc) Args() any    { return InstallPyenvArgs{} }

func (installPyenvFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*InstallPyenvArgs)
	ret := result.New(a.Name, "", nil, map[string]any{})
	if a.Test {
		ret.Comment = "pyenv is set to be installed"
		return ret
	}

	user := strOr(a.User, "")
	if !execBool(ctx, rt, "pyenv.is_installed", &execpyenv.IsInstalledArgs{Runas: a.User}) {
		ret.Result = result.Bool(false)
		ret.Comment = "pyenv is not installed."
		if !execBool(ctx, rt, "pyenv.install", &execpyenv.InstallArgs{Runas: a.User}) {
			ret.Comment = "pyenv failed to install"
			return ret
		}
	}
	// Upstream passes the USER as the python version here — pinned quirk.
	return checkAndInstallPython(ctx, rt, ret, user, false, user)
}

// checkAndInstallPython mirrors _check_and_install_python.
func checkAndInstallPython(
	ctx context.Context,
	rt *runtime.Runtime,
	ret result.StateResult,
	python string,
	def bool,
	user string,
) result.StateResult {
	currentDefault, defaultErr := rt.Exec.Call(ctx, rt, "pyenv.default",
		&execpyenv.DefaultArgs{Runas: strPtr(user)})
	exists := false
	isDefault := false
	versionsRes, verr := rt.Exec.Call(ctx, rt, "pyenv.versions",
		&execpyenv.VersionsArgs{Runas: strPtr(user)})
	if verr == nil && defaultErr == nil {
		ds, _ := currentDefault.(string)
		if versions, ok := versionsRes.([]string); ok {
			for _, version := range versions {
				if version == python {
					exists = true
					isDefault = ds == python
					break
				}
			}
		}
	}

	if exists {
		ret.Result = result.Bool(true)
		ret.Comment = "Requested python exists."
		setMetaDefault(&ret, isDefault)
	} else {
		installedOK := execBool(ctx, rt, "pyenv.install_python",
			&execpyenv.InstallPythonArgs{Python: python, Runas: strPtr(user)})
		if installedOK {
			ret.Result = result.Bool(true)
			ret.Changes[python] = "Installed"
			ret.Comment = "Successfully installed python"
			setMetaDefault(&ret, def)
		} else {
			ret.Result = result.Bool(false)
			ret.Comment = "Could not install python."
			return ret
		}
	}

	if def {
		rt.Exec.Call(ctx, rt, "pyenv.default",
			&execpyenv.DefaultArgs{Python: strPtr(python), Runas: strPtr(user)})
	}
	return ret
}

func setMetaDefault(ret *result.StateResult, v bool) {
	if ret.Meta == nil {
		ret.Meta = &result.ResultMeta{}
	}
	if ret.Meta.Extra == nil {
		ret.Meta.Extra = map[string]any{}
	}
	ret.Meta.Extra["default"] = v
}

func execBool(ctx context.Context, rt *runtime.Runtime, name string, args any) bool {
	res, err := rt.Exec.Call(ctx, rt, name, args)
	if err != nil {
		return false
	}
	b, ok := res.(bool)
	return ok && b
}

func strOr(s *string, def string) string {
	if s != nil {
		return *s
	}
	return def
}

func strPtr(s string) *string { return &s }

// Register installs all pyenv state functions.
func Register(reg *runtime.StateRegistry) error {
	for _, fn := range []runtime.StateFunction{
		installedFunc{},
		absentFunc{},
		installPyenvFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
