// status.pid and status.version: the R4-final status slice.
//
// Reference: saltstack/salt/modules/status.py:1607-1636 (pid) and
// 1639-1682 (version) @ pinned revision.
//
// Mechanism divergence (established R2.2 convention in this package):
// pid does not run the grains ps command. It scans /proc/<pid>/cmdline
// directly — arguments are NUL-separated and joined with single spaces,
// mirroring the ps -ef command column — with identical observable
// shapes: matching pids newline-joined (empty string when nothing
// matches), own pid excluded. The regex is Go RE2 with Python re.search
// "find anywhere" semantics; constructs Python re supports but RE2
// rejects (backreferences, lookaround) fail compilation and surface as
// a deterministic error before the scan, standing in for Salt's
// propagated re.error.
package status

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// maxProcVersionBytes bounds the /proc/version read; the real file is a
// few hundred bytes, and a pathological source degrades to Salt's
// OSError -> {} shape instead of an unbounded allocation.
const maxProcVersionBytes int64 = 4 << 10

type statusPidArgs struct {
	Sig string `statekit:"required,name=sig"`
}

type statusPidFunc struct {
	procOnly
}

func (statusPidFunc) Name() string { return "status.pid" }
func (statusPidFunc) Args() any    { return statusPidArgs{} }

// Execute mirrors pid(sig): return the pids of processes whose command
// line matches sig, own pid excluded, newline-joined; "" when none.
func (statusPidFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*statusPidArgs)
	sig, err := regexp.Compile(a.Sig)
	if err != nil {
		return nil, fmt.Errorf("status.pid: invalid signature %q: %w", a.Sig, err)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// /proc is a live kernel filesystem; the FS abstraction cannot
		// substitute it here (pid_list precedent).
		return nil, fmt.Errorf("could not scan /proc: %w", err)
	}
	ownPid := strconv.Itoa(os.Getpid())
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if _, convErr := strconv.Atoi(entry.Name()); convErr != nil {
			continue
		}
		data, readErr := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if readErr != nil || len(data) == 0 {
			// Kernel threads have an empty cmdline: no command column,
			// so no line to filter.
			continue
		}
		argv := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		// Carrier row: the pid occupies the second whitespace column so
		// the shared filter's split()[1] yields it exactly like the ps
		// -ef PID column; the leading repeat of the pid stands in for
		// the UID column the /proc scan does not provide. Regex scope is
		// therefore the pid carrier plus joined command line, not the
		// full ps row (documented divergence).
		lines = append(lines, entry.Name()+" "+entry.Name()+" "+strings.Join(argv, " "))
	}
	return strings.Join(filterPidLines(lines, ownPid, sig), "\n"), nil
}

// filterPidLines applies Salt's pid() line filter verbatim: lines
// containing the own-pid string anywhere are skipped (substring, not
// column — Salt's quirk of skipping foreign cmdlines that merely
// mention the pid survives), remaining lines are matched with re.search
// semantics, and the second whitespace-separated column (the ps PID
// column) is collected in input order.
func filterPidLines(lines []string, ownPid string, sig *regexp.Regexp) []string {
	pids := []string{}
	for _, line := range lines {
		if strings.Contains(line, ownPid) {
			continue
		}
		if !sig.MatchString(line) {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 2 {
			continue
		}
		pids = append(pids, comps[1])
	}
	return pids
}

type statusVersionArgs struct{}

type statusVersionFunc struct{}

func (statusVersionFunc) Name() string { return "status.version" }
func (statusVersionFunc) Args() any    { return statusVersionArgs{} }

// Execute mirrors version(): dispatch on the Facts kernel grain exactly
// like Salt's get_version dict. Only the Linux branch is implemented;
// the pinned dict's FreeBSD/Junos/OpenBSD sysctl and AIX oslevel
// branches are out of StateKit platform scope, so those kernels — and
// every kernel outside the dict, e.g. windows/darwin in cross-builds —
// return upstream's errmsg string exactly (documented divergence: BSD
// and AIX collapse into the unsupported contract instead of running
// their platform probes). Mixed return types mirror Salt: stripped
// /proc/version string on success, {} on read error, errmsg string
// otherwise.
func (statusVersionFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	if rt.Facts.Kernel().Name != "Linux" {
		return "This method is unsupported on the current operating system!", nil
	}
	data, err := runtime.ReadFileBounded(rt.FS, "/proc/version", maxProcVersionBytes)
	if err != nil {
		// Salt's linux_version maps OSError to {}.
		return map[string]any{}, nil
	}
	return strings.TrimSpace(string(data)), nil
}
