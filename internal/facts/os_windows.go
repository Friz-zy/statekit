//go:build windows

package facts

import "github.com/friz-zy/statekit/internal/process"

// winOSQuery projects one Win32_OperatingSystem instance to compact JSON
// through CIM. Registry access via reg.exe stays with the R7 policy stack;
// identity needs no registry read.
const winOSQuery = `Get-CimInstance Win32_OperatingSystem | ` +
	`Select-Object -First 1 Caption,Version,BuildNumber | ConvertTo-Json -Compress`

// detectOS gathers Windows identity via a PowerShell CIM scriptlet run
// through the central Runner shell model (plans/porting.md E4).
func detectOS(runner process.Runner) OSFacts {
	return parseWinCIM([]byte(runShellTool(runner, winOSQuery)))
}

// detectInitSystem reports scm, the Windows Service Control Manager.
func detectInitSystem() string { return "scm" }

// detectSecurity reports no SELinux/AppArmor module on windows.
func detectSecurity() SecurityFacts { return SecurityFacts{} }
