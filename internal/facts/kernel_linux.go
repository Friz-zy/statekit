//go:build linux

package facts

import "syscall"

func detectKernel() KernelFacts {
	k := KernelFacts{Name: "linux"}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return k
	}
	k.Name = utsString(uts.Sysname[:])
	k.Release = utsString(uts.Release[:])
	k.Machine = utsString(uts.Machine[:])
	return k
}

// utsString converts the fixed-size kernel string arrays; element signedness
// varies per architecture (int8 on amd64, uint8 on arm).
func utsString[T int8 | uint8](chars []T) string {
	b := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
