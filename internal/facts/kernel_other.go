//go:build !linux

package facts

import "runtime"

func detectKernel() KernelFacts {
	return KernelFacts{Name: runtime.GOOS}
}
