//go:build darwin

package facts

import "github.com/friz-zy/statekit/internal/process"

// detectOS gathers macOS identity via sw_vers through the central Runner
// (plans/porting.md E4). system_profiler/dscl-backed facts join the R6
// round, where they gain consumers.
func detectOS(runner process.Runner) OSFacts {
	return parseSwVers([]byte(runTool(runner, "sw_vers")))
}

// detectInitSystem reports launchd, the only macOS init system.
func detectInitSystem() string { return "launchd" }

// detectSecurity reports no SELinux/AppArmor module on darwin.
func detectSecurity() SecurityFacts { return SecurityFacts{} }
