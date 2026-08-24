// Package ps implements Salt-compatible process/system statistics
// functions backed by a local /proc reader instead of psutil.
//
// Reference: saltstack/salt/modules/ps.py @ pinned revision.
//
// Contract notes (init.md section 28):
//   - psutil is a Python library dependency; StateKit reads /proc directly
//     (documented mechanism divergence, same observable shapes: identical
//     dict keys, numeric types, and failure strings).
//   - Every filesystem touch goes through the runtime FileSystem against
//     an injectable /proc root so suites stay hermetic.
//   - The kernel tick is assumed to be 100Hz (USER_HZ), matching psutil's
//     os.sysconf(SC_CLK_TCK) result on stock kernels.
//   - Signal delivery lives behind build-tagged files; the family declares
//     linux-only platform constraints because every contract is
//     /proc-based.
package ps

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux: every contract is /proc-based.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

const kernelHZ = 100

// procRoot is the injectable /proc prefix.
var procRoot = func(rt *runtime.Runtime) string { return "/proc" }

// userLookup stands in for pwd.getpwuid resolution.
var userLookup = func(uid string) (string, bool) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", false
	}
	return u.Username, true
}

// sleepHook isolates interval sleeps for tests.
var sleepHook = func(d time.Duration) { time.Sleep(d) }

// sendSignalFn wraps the platform signal delivery for tests.
var sendSignalFn = sendSignal

func joinProc(rt *runtime.Runtime, elems ...string) string {
	return procRoot(rt) + "/" + strings.Join(elems, "/")
}

// pids lists numeric /proc entries sorted ascending like psutil.pids().
func pids(rt *runtime.Runtime) []int64 {
	entries, err := rt.FS.ReadDir(joinProc(rt))
	if err != nil {
		return nil
	}
	var out []int64
	for _, entry := range entries {
		if pid, perr := strconv.ParseInt(entry.Name(), 10, 64); perr == nil {
			out = append(out, pid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type procStat struct {
	name       string
	state      string
	ppid       int64
	utime      float64
	stime      float64
	starttime  float64
	rssPages   int64
	vsizeBytes float64
}

// readStat parses /proc/<pid>/stat, splitting after the closing paren so
// comm names containing spaces or parens survive.
func readStat(rt *runtime.Runtime, pid int64) (*procStat, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, strconv.FormatInt(pid, 10), "stat"))
	if err != nil {
		return nil, err
	}
	raw := string(data)
	open := strings.IndexByte(raw, '(')
	closeIdx := strings.LastIndexByte(raw, ')')
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return nil, fmt.Errorf("malformed stat for %d", pid)
	}
	fields := strings.Fields(raw[closeIdx+1:])
	// After the comm paren strip, fields[i] holds upstream stat field i+3.
	num := func(field int) float64 {
		idx := field - 3
		if idx < 0 || idx >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseFloat(fields[idx], 64)
		return v
	}
	state := fields[0]
	ppid := int64(num(4))
	utime := num(14)
	stime := num(15)
	starttime := num(22)
	vsize := num(23)
	var rss int64
	if len(fields) > 21 {
		rss, _ = strconv.ParseInt(fields[21], 10, 64)
	}
	return &procStat{
		name:       raw[open+1 : closeIdx],
		state:      state,
		ppid:       ppid,
		utime:      utime,
		stime:      stime,
		starttime:  starttime,
		rssPages:   rss,
		vsizeBytes: vsize,
	}, nil
}

// readStatusUid returns the real uid line value from /proc/<pid>/status.
func readStatusUid(rt *runtime.Runtime, pid int64) string {
	data, err := rt.FS.ReadFile(joinProc(rt, strconv.FormatInt(pid, 10), "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func readCmdline(rt *runtime.Runtime, pid int64) []string {
	data, err := rt.FS.ReadFile(joinProc(rt, strconv.FormatInt(pid, 10), "cmdline"))
	if err != nil {
		return []string{}
	}
	parts := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return []string{}
	}
	return parts
}

// bootTimeSeconds reads the btime line of /proc/stat.
func bootTimeSeconds(rt *runtime.Runtime) (int64, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, "stat"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			return strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime")), 10, 64)
		}
	}
	return 0, fmt.Errorf("btime not found")
}

// createTime computes the epoch seconds a process started.
func createTime(rt *runtime.Runtime, st *procStat) (float64, error) {
	btime, err := bootTimeSeconds(rt)
	if err != nil {
		return 0, err
	}
	return float64(btime) + st.starttime/kernelHZ, nil
}

// procUsername resolves the owning username; failures give None.
func procUsername(rt *runtime.Runtime, pid int64) any {
	uid := readStatusUid(rt, pid)
	if uid == "" {
		return nil
	}
	if name, ok := userLookup(uid); ok {
		return name
	}
	return nil
}

// cpuTimesDict parses one "cpu[N] tick tick..." line into the psutil
// field dict; the optional trailing cpu index is dropped.
func cpuTimesDict(line string) map[string]any {
	rest := strings.TrimPrefix(line, "cpu")
	if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		rest = strings.TrimLeft(rest, "0123456789")
	}
	fields := strings.Fields(rest)
	labels := []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"}
	ret := map[string]any{}
	for i, label := range labels {
		if i >= len(fields) {
			break
		}
		v, _ := strconv.ParseFloat(fields[i], 64)
		ret[label] = v / kernelHZ
	}
	return ret
}

// readStatLines returns the raw cpu lines of /proc/stat (index 0 is the
// aggregate, following entries are per-cpu cpuN lines).
func readStatLines(rt *runtime.Runtime) ([]string, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, "stat"))
	if err != nil {
		return nil, err
	}
	var cpus []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && (line[3] == ' ' || line[3] >= '0' && line[3] <= '9') {
			cpus = append(cpus, line)
		}
	}
	return cpus, nil
}

// memInfoKV parses /proc/meminfo into kB values keyed by field name.
func memInfoKV(rt *runtime.Runtime) (map[string]int64, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, "meminfo"))
	if err != nil {
		return nil, err
	}
	kv := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseInt(fields[0], 10, 64)
		if err == nil {
			kv[strings.TrimSpace(line[:idx])] = v
		}
	}
	return kv, nil
}

// round1 mirrors Python round(x, 1).
func round1(v float64) float64 {
	return float64(int64(v*10+sign(v)*0.5)) / 10
}

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}

// --- top / pid queries --------------------------------------------------

type TopArgs struct {
	NumProcesses *int     `statekit:"name=num_processes"`
	Interval     *float64 `statekit:"name=interval"`
}

type topFunc struct{ linuxOnly }

func (topFunc) Name() string { return "ps.top" }
func (topFunc) Args() any    { return TopArgs{} }

// Execute samples per-process CPU usage across an interval and reports
// the busiest processes, mirroring ps.top's shape.
func (topFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*TopArgs)
	numProcesses := 5
	if a.NumProcesses != nil {
		numProcesses = *a.NumProcesses
	}
	interval := 3.0
	if a.Interval != nil {
		interval = *a.Interval
	}

	sample := func() map[int64]float64 {
		usage := map[int64]float64{}
		for _, pid := range pids(rt) {
			st, err := readStat(rt, pid)
			if err != nil {
				continue
			}
			if st.state == "Z" {
				usage[pid] = 0
				continue
			}
			usage[pid] = st.utime + st.stime
		}
		return usage
	}

	start := sample()
	sleepHook(time.Duration(interval * float64(time.Second)))
	end := sample()

	type usageEntry struct {
		diff float64
		pid  int64
	}
	var usage []usageEntry
	for pid, now := range end {
		startVal, ok := start[pid]
		if !ok {
			continue
		}
		usage = append(usage, usageEntry{diff: now - startVal, pid: pid})
	}
	sort.Slice(usage, func(i, j int) bool {
		if usage[i].diff == usage[j].diff {
			return usage[i].pid < usage[j].pid
		}
		return usage[i].diff > usage[j].diff
	})

	result := []any{}
	for _, entry := range usage {
		if len(result) >= numProcesses {
			break
		}
		st, err := readStat(rt, entry.pid)
		if err != nil {
			continue
		}
		cmd := readCmdline(rt, entry.pid)
		cmdField := any(cmd)
		if len(cmd) == 0 {
			cmdField = st.name
		}
		createTime, cerr := createTime(rt, st)
		if cerr != nil {
			createTime = 0
		}
		pageSize := int64(os.Getpagesize())
		result = append(result, map[string]any{
			"cmd":         cmdField,
			"user":        procUsername(rt, entry.pid),
			"status":      stateName(st.state),
			"pid":         entry.pid,
			"create_time": createTime,
			"cpu": map[string]any{
				"user":   st.utime / kernelHZ,
				"system": st.stime / kernelHZ,
			},
			"mem": map[string]any{
				"rss": st.rssPages * pageSize,
				"vms": int64(st.vsizeBytes),
			},
		})
	}
	return result, nil
}

type getPidsArgs struct{}

type getPIDListFunc struct{ linuxOnly }

func (getPIDListFunc) Name() string { return "ps.get_pid_list" }
func (getPIDListFunc) Args() any    { return getPidsArgs{} }
func (getPIDListFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	list := pids(rt)
	out := make([]any, 0, len(list))
	for _, pid := range list {
		out = append(out, pid)
	}
	return out, nil
}

// ProcInfoArgs mirrors Salt's proc_info signature.
type ProcInfoArgs struct {
	Pid   int64    `statekit:"required,name=pid"`
	Attrs []string `statekit:"name=attrs"`
}

type procInfoFunc struct{ linuxOnly }

func (procInfoFunc) Name() string { return "ps.proc_info" }
func (procInfoFunc) Args() any    { return ProcInfoArgs{} }

// Execute builds the psutil as_dict subset StateKit supports; unknown
// attributes raise like psutil's AttributeError path.
func (procInfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ProcInfoArgs)
	full := map[string]any{}
	st, err := readStat(rt, a.Pid)
	if err != nil {
		return nil, fmt.Errorf("process no longer exists")
	}
	createTimeF, _ := createTime(rt, st)
	cmd := readCmdline(rt, a.Pid)
	cpuTimes := map[string]any{"user": st.utime / kernelHZ, "system": st.stime / kernelHZ}
	pageSize := int64(os.Getpagesize())
	memInfo := map[string]any{"rss": st.rssPages * pageSize, "vms": int64(st.vsizeBytes)}
	full["pid"] = a.Pid
	full["name"] = st.name
	full["cmdline"] = cmd
	full["create_time"] = createTimeF
	full["status"] = stateName(st.state)
	full["username"] = procUsername(rt, a.Pid)
	full["cpu_times"] = cpuTimes
	full["memory_info"] = memInfo

	if len(a.Attrs) == 0 {
		return full, nil
	}
	filtered := map[string]any{}
	for _, attr := range a.Attrs {
		val, ok := full[attr]
		if !ok {
			return nil, fmt.Errorf("invalid attribute %q", attr)
		}
		filtered[attr] = val
	}
	return filtered, nil
}

// stateName maps the kernel process-state character to psutil's names.
func stateName(state string) string {
	switch state {
	case "R":
		return "running"
	case "S":
		return "sleeping"
	case "D":
		return "disk_sleep"
	case "T":
		return "stopped"
	case "t":
		return "tracing_stop"
	case "Z":
		return "zombie"
	case "X", "x":
		return "dead"
	case "K":
		return "wake_kill"
	case "W":
		return "waking"
	case "P":
		return "parked"
	case "I":
		return "idle"
	default:
		return state
	}
}

// matchProcs implements the shared pgrep/pkill walk: substring or regex
// matching over name/cmdline plus optional user filtering.
func matchProcs(ctx context.Context, rt *runtime.Runtime, pattern string, user *string, full, patternIsRegex bool) []int64 {
	var re *regexp.Regexp
	if patternIsRegex {
		re = regexp.MustCompile(pattern)
	}
	var matched []int64
	for _, pid := range pids(rt) {
		var processLine string
		if full {
			processLine = strings.Join(readCmdline(rt, pid), " ")
		} else {
			st, err := readStat(rt, pid)
			if err != nil {
				continue
			}
			processLine = st.name
		}
		var nameMatch bool
		if re != nil {
			nameMatch = re.MatchString(processLine)
		} else {
			nameMatch = strings.Contains(processLine, pattern)
		}
		if !nameMatch {
			continue
		}
		if user != nil && procUsername(rt, pid) != *user {
			continue
		}
		matched = append(matched, pid)
	}
	return matched
}
