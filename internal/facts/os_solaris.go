//go:build solaris

package facts

import "github.com/friz-zy/statekit/internal/process"

// detectOS gathers Solaris identity from uname through the central Runner;
// no host filesystem or command is consulted directly by this provider.
func detectOS(runner process.Runner) OSFacts {
	return parseSolarisUname([]byte(runTool(runner, "uname", "-s", "-r")))
}

// Solaris Service Management Facility is the native init system.
func detectInitSystem() string { return "smf" }

// Solaris does not expose the Linux SELinux/AppArmor facts.
func detectSecurity() SecurityFacts { return SecurityFacts{} }
