package pkg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

var ErrUnsupportedYUM = errors.New("YUM capability is not supported by this package provider")

var yumArchitectures = map[string]struct{}{
	"x86_64": {}, "x86_64_v2": {}, "athlon": {}, "amd64": {}, "ia32e": {}, "ia64": {}, "geode": {},
	"i386": {}, "i486": {}, "i586": {}, "i686": {},
	"ppc": {}, "ppc64": {}, "ppc64le": {}, "ppc64iseries": {}, "ppc64pseries": {},
	"s390": {}, "s390x": {},
	"alpha": {}, "alphaev4": {}, "alphaev45": {}, "alphaev5": {}, "alphaev56": {}, "alphapca56": {}, "alphaev6": {}, "alphaev67": {}, "alphaev68": {}, "alphaev7": {},
	"armv5tel": {}, "armv5tejl": {}, "armv6l": {}, "armv6hl": {}, "armv7l": {}, "armv7hl": {}, "armv7hnl": {},
	"aarch64": {}, "sh3": {}, "sh4": {}, "sh4a": {}, "noarch": {},
}

func yumArch(name string) (string, bool) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	arch := name[i+1:]
	_, ok := yumArchitectures[arch]
	return arch, ok
}

func yumNormalizeName(name, osarch string) string {
	arch, known := yumArch(name)
	if !known {
		return name
	}
	base := name[:len(name)-len(arch)-1]
	// Salt's rpm.resolve_name keeps the suffix only for an architecture that
	// is distinct from the OS architecture and not a compatible 32-bit arch.
	if arch == "noarch" || arch == osarch || (arch == "x86_64_v2" && osarch == "x86_64") || (arch == "x86_64" && osarch == "x86_64_v2") || (is32RPMArch(arch) && is32RPMArch(osarch)) || (is32ARMArch(arch) && is32ARMArch(osarch)) {
		return base
	}
	return name
}

func is32RPMArch(arch string) bool {
	switch arch {
	case "i386", "i486", "i586", "i686":
		return true
	}
	return false
}
func is32ARMArch(arch string) bool {
	switch arch {
	case "armv5tel", "armv5tejl", "armv6l", "armv6hl", "armv7l", "armv7hl", "armv7hnl":
		return true
	}
	return false
}

func yumParseArch(name string) map[string]any {
	arch, known := yumArch(name)
	if !known {
		return map[string]any{"name": name, "arch": nil}
	}
	return map[string]any{"name": name[:len(name)-len(arch)-1], "arch": arch}
}

func (p *commandProvider) Yum(_ context.Context, rt *runtime.Runtime, function string, args any) (any, error) {
	if p.spec.manager != "yum" && p.spec.manager != "dnf" {
		return nil, ErrUnsupportedYUM
	}
	a, ok := args.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("YUM function %q: malformed arguments", function)
	}
	name, ok := a["name"].(string)
	if !ok {
		return nil, errors.New("argument \"name\" must be a string")
	}
	switch function {
	case "normalize_name":
		return yumNormalizeName(name, rt.Facts.CPU().Arch), nil
	case "parse_arch":
		return yumParseArch(name), nil
	default:
		return nil, fmt.Errorf("unknown YUM function %q", function)
	}
}
