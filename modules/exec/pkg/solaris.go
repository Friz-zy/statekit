package pkg

import (
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
	execsolarisips "github.com/friz-zy/statekit/modules/exec/solarisipspkg"
	execsolarispkg "github.com/friz-zy/statekit/modules/exec/solarispkg"
)

// registerSolaris is the no-facts fallback for the canonical package family;
// modern Solaris uses IPS. RegisterForRuntime below supplies the legacy
// Solaris 10 branch when BuildRuntime has a bounded OS-release fact.
func registerSolaris(reg *runtime.ExecRegistry) error {
	return execsolarisips.Register(reg)
}

// RegisterForRuntime selects the source module that owns the Solaris virtual
// pkg name. Solaris 10 reports kernel release 5.10 (or lower) and uses the
// legacy SVR4 provider; Solaris 11 reports 5.11+ and uses IPS. The selector is
// fact-driven so BuildRuntime never registers duplicate canonical names.
func RegisterForRuntime(reg *runtime.ExecRegistry, detected *facts.Facts) error {
	if detected == nil || detected.OS().Family != facts.FamilySolaris {
		return Register(reg)
	}
	if !solarisIPSRelease(detected.OS().Version) {
		return execsolarispkg.Register(reg)
	}
	return execsolarisips.Register(reg)
}

func solarisIPSRelease(version string) bool {
	parts := strings.SplitN(strings.TrimSpace(version), ".", 3)
	if len(parts) < 2 {
		return true
	}
	major, minor := 0, 0
	for _, digit := range parts[0] {
		if digit < '0' || digit > '9' {
			return true
		}
		major = major*10 + int(digit-'0')
	}
	for _, digit := range parts[1] {
		if digit < '0' || digit > '9' {
			return true
		}
		minor = minor*10 + int(digit-'0')
	}
	return major > 5 || (major == 5 && minor > 10)
}
