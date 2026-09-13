// Package rbac implements Salt's Solaris RBAC execution family.
package rbac

import "github.com/friz-zy/statekit/internal/runtime"

// registerSolaris installs the complete public rbac_solaris surface. The
// functions are retained in the registry on Solaris only; every function also
// carries an explicit platform constraint so direct registry calls cannot
// bypass the GOOS gate.
func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		profileListFunc{}, profileGetFunc{}, profileAddFunc{}, profileRemoveFunc{},
		roleListFunc{}, roleGetFunc{}, roleAddFunc{}, roleRemoveFunc{},
		authListFunc{}, authGetFunc{}, authAddFunc{}, authRemoveFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// Register installs the Solaris RBAC functions when the runtime is Solaris.
// Linux deliberately receives no rbac names because the Salt family has no
// Linux implementation.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "solaris" {
		return registerSolaris(reg)
	}
	return nil
}
