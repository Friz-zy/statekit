// Package fmadm registers Salt's Solaris fmadm execution family.
package fmadm

import "github.com/friz-zy/statekit/internal/runtime"

// registerSolaris installs the complete public fmadm surface. The functions
// are registered on every build and each carries Platforms() == ["solaris"],
// allowing the registry to return UnsupportedError rather than accidentally
// exposing or executing Solaris commands on Linux.
func registerSolaris(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		listFunc{}, showFunc{}, configFunc{}, loadFunc{}, unloadFunc{}, resetFunc{},
		flushFunc{}, repairedFunc{}, replacedFunc{}, acquitFunc{}, faultyFunc{}, healthyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// Register installs the Solaris fmadm functions.
func Register(reg *runtime.ExecRegistry) error { return registerSolaris(reg) }
