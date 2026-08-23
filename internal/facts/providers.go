// Platform fact providers: GOOS-neutral parsers over recorded tool output.
//
// plans/porting.md enabler E4. Every per-GOOS provider shells out through
// the central Runner and feeds raw bytes into one of these parsers, so
// golden fixtures recorded from each OS image verify every platform
// hermetically on any build host.

package facts

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
)

// toolTimeout bounds each external fact-gathering command.
const toolTimeout = 10 * time.Second

// runTool executes one read-only detection command through the central
// Runner and returns trimmed stdout. Failures degrade to "": unknown facts
// are data here, mirroring how missing-file probes behave on linux.
func runTool(runner process.Runner, name string, args ...string) string {
	if runner == nil {
		return ""
	}
	res := runner.Run(context.Background(), process.Command{
		Name:    name,
		Args:    args,
		Timeout: toolTimeout,
	})
	if !res.OK() {
		return ""
	}
	return strings.TrimSpace(string(res.Stdout))
}

// runShellTool runs a script through the Runner's shell model for the
// compiling platform (POSIX sh locally; PowerShell on windows builds).
func runShellTool(runner process.Runner, script string) string {
	if runner == nil {
		return ""
	}
	res := runner.Run(context.Background(), process.Command{
		Name:    script,
		Shell:   true,
		Timeout: toolTimeout,
	})
	if !res.OK() {
		return ""
	}
	return strings.TrimSpace(string(res.Stdout))
}

// parseSwVers parses macOS `sw_vers` output ("Key:\tvalue" lines) into
// identity facts. Family macos drives brew/port manager selection. Output
// missing a product version degrades to empty facts.
func parseSwVers(out []byte) OSFacts {
	f := OSFacts{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			f.Name = value
		case "ProductVersion":
			f.Version = value
			f.ID = FamilyMacOS
			f.Family = FamilyMacOS
		case "BuildVersion":
			f.Build = value
		}
	}
	if f.ID == "" {
		return OSFacts{}
	}
	return f
}

// winCIM mirrors the projected Win32_OperatingSystem instance emitted by
// ConvertTo-Json in the windows detection scriptlet.
type winCIM struct {
	Caption     string `json:"Caption"`
	Version     string `json:"Version"`
	BuildNumber string `json:"BuildNumber"`
}

// parseWinCIM parses the JSON output of the windows CIM query. It accepts a
// single object or an array (ConvertTo-Json wraps multi-instance results).
func parseWinCIM(out []byte) OSFacts {
	var cim winCIM
	data := []byte(strings.TrimSpace(string(out)))
	if err := json.Unmarshal(data, &cim); err != nil {
		var many []winCIM
		if jsonErr := json.Unmarshal(data, &many); jsonErr != nil || len(many) == 0 {
			return OSFacts{}
		}
		cim = many[0]
	}
	return OSFacts{
		ID:      FamilyWindows,
		Name:    strings.TrimPrefix(cim.Caption, "Microsoft "),
		Family:  FamilyWindows,
		Version: cim.Version,
		Build:   cim.BuildNumber,
	}
}

// knownBsdOstypes gates parsed kern.ostype values; anything else means the
// probe failed and must degrade to empty facts rather than inventing an
// identity.
var knownBsdOstypes = map[string]struct{}{
	FamilyFreeBSD: {},
	FamilyOpenBSD: {},
	FamilyNetBSD:  {},
	"dragonfly":   {},
}

// parseBsdSysctl parses `sysctl -n kern.ostype kern.osrelease` output:
// line one is the OS type, line two the release.
func parseBsdSysctl(out []byte) OSFacts {
	lines := strings.FieldsFunc(string(out), func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) < 2 {
		return OSFacts{}
	}
	ostype := strings.ToLower(strings.TrimSpace(lines[0]))
	release := strings.TrimSpace(lines[1])
	if ostype == "" || release == "" {
		return OSFacts{}
	}
	if _, ok := knownBsdOstypes[ostype]; !ok {
		return OSFacts{}
	}
	return OSFacts{
		ID:      ostype,
		Name:    ostype,
		Family:  ostype,
		Version: release,
	}
}
