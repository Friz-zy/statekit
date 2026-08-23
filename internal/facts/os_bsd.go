//go:build freebsd || openbsd || netbsd || dragonfly

package facts

import "github.com/friz-zy/statekit/internal/process"

// detectOS gathers BSD identity via sysctl (kern.ostype + kern.osrelease)
// through the central Runner (plans/porting.md E4). kenv-specific facts
// stay with the R8 round, where they gain consumers.
func detectOS(runner process.Runner) OSFacts {
	return parseBsdSysctl([]byte(runTool(runner, "sysctl", "-n", "kern.ostype", "kern.osrelease")))
}

// detectInitSystem reports rc, the rc.d service framework shared by the
// BSDs.
func detectInitSystem() string { return "rc" }

// detectSecurity reports no MAC module; MAC probes stay with R8.
func detectSecurity() SecurityFacts { return SecurityFacts{} }
