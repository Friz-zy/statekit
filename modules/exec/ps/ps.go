package ps

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	cmdmod "github.com/friz-zy/statekit/modules/exec/cmd"
)

// --- kill / pkill / pgrep ----------------------------------------------

type KillPidArgs struct {
	Pid    int64 `statekit:"required,name=pid"`
	Signal *int  `statekit:"name=signal"`
}

type killPIDFunc struct{ linuxOnly }

func (killPIDFunc) Name() string { return "ps.kill_pid" }
func (killPIDFunc) Args() any    { return KillPidArgs{} }
func (killPIDFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KillPidArgs)
	signal := 15
	if a.Signal != nil {
		signal = *a.Signal
	}
	if _, err := readStat(rt, a.Pid); err != nil {
		return false, nil
	}
	if err := sendSignalFn(int(a.Pid), signal); err != nil {
		return false, nil
	}
	return true, nil
}

type PkillArgs struct {
	Pattern string  `statekit:"required,name=pattern"`
	User    *string `statekit:"name=user"`
	Signal  *int    `statekit:"name=signal"`
	Full    bool    `statekit:"name=full"`
}

type pkillFunc struct{ linuxOnly }

func (pkillFunc) Name() string { return "ps.pkill" }
func (pkillFunc) Args() any    { return PkillArgs{} }

func (pkillFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PkillArgs)
	signal := 15
	if a.Signal != nil {
		signal = *a.Signal
	}
	var killed []any
	for _, pid := range matchProcs(ctx, rt, a.Pattern, a.User, a.Full, false) {
		if err := sendSignalFn(int(pid), signal); err == nil {
			killed = append(killed, pid)
		}
	}
	if len(killed) == 0 {
		return nil, nil
	}
	return map[string]any{"killed": killed}, nil
}

type PgrepArgs struct {
	Pattern        string  `statekit:"required,name=pattern"`
	User           *string `statekit:"name=user"`
	Full           bool    `statekit:"name=full"`
	PatternIsRegex bool    `statekit:"name=pattern_is_regex"`
}

type pgrepFunc struct{ linuxOnly }

func (pgrepFunc) Name() string { return "ps.pgrep" }
func (pgrepFunc) Args() any    { return PgrepArgs{} }

// Execute returns matching pids or None when nothing matches.
func (pgrepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PgrepArgs)
	matched := matchProcs(ctx, rt, a.Pattern, a.User, a.Full, a.PatternIsRegex)
	if len(matched) == 0 {
		return nil, nil
	}
	out := make([]any, 0, len(matched))
	for _, pid := range matched {
		out = append(out, pid)
	}
	return out, nil
}

// --- CPU -----------------------------------------------------------------

type CpuPercentArgs struct {
	Interval *float64 `statekit:"name=interval"`
	PerCpu   bool     `statekit:"name=per_cpu"`
}

type cpuPercentFunc struct{ linuxOnly }

func (cpuPercentFunc) Name() string { return "ps.cpu_percent" }
func (cpuPercentFunc) Args() any    { return CpuPercentArgs{} }

// busyPercent computes psutil's busy share from two /proc/stat samples.
func busyPercent(before, after map[string]float64) float64 {
	sum := func(m map[string]float64) float64 {
		total := 0.0
		for _, v := range m {
			total += v
		}
		return total
	}
	idle := func(m map[string]float64) float64 { return m["idle"] + m["iowait"] }
	totalDelta := sum(after) - sum(before)
	idleDelta := idle(after) - idle(before)
	if totalDelta <= 0 {
		return 0
	}
	return (totalDelta - idleDelta) / totalDelta * 100
}

func (cpuPercentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CpuPercentArgs)
	interval := 0.1
	if a.Interval != nil {
		interval = *a.Interval
	}
	lines0, err := readStatLines(rt)
	if err != nil {
		return nil, err
	}
	sleepHook(durationSeconds(interval))
	lines1, err := readStatLines(rt)
	if err != nil {
		return nil, err
	}

	toMap := func(line string) map[string]float64 {
		m := map[string]float64{}
		for k, v := range cpuTimesDict(line) {
			m[k] = v.(float64)
		}
		return m
	}

	if !a.PerCpu {
		before, after := toMap(lines0[0]), toMap(lines1[0])
		return busyPercent(before, after), nil
	}
	out := []any{}
	for i := range lines0 {
		if i == 0 || i >= len(lines1) {
			continue
		}
		out = append(out, busyPercent(toMap(lines0[i]), toMap(lines1[i])))
	}
	return out, nil
}

type CpuTimesArgs struct {
	PerCpu bool `statekit:"name=per_cpu"`
}

type cpuTimesFunc struct{ linuxOnly }

func (cpuTimesFunc) Name() string { return "ps.cpu_times" }
func (cpuTimesFunc) Args() any    { return CpuTimesArgs{} }
func (cpuTimesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CpuTimesArgs)
	lines, err := readStatLines(rt)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no cpu information")
	}
	if a.PerCpu {
		out := []any{}
		for _, line := range lines[1:] {
			out = append(out, cpuTimesDict(line))
		}
		return out, nil
	}
	return cpuTimesDict(lines[0]), nil
}

// --- Memory ---------------------------------------------------------------

type virtualMemoryFunc struct{ linuxOnly }

func (virtualMemoryFunc) Name() string { return "ps.virtual_memory" }
func (virtualMemoryFunc) Args() any    { return struct{}{} }
func (virtualMemoryFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	kv, err := memInfoKV(rt)
	if err != nil {
		return nil, err
	}
	const kb = 1024
	total := kv["MemTotal"] * kb
	free := kv["MemFree"] * kb
	buffers := kv["Buffers"] * kb
	cached := (kv["Cached"] + kv["SReclaimable"] - kv["Shmem"]) * kb
	var available int64
	if v, ok := kv["MemAvailable"]; ok {
		available = v * kb
	} else {
		available = free + buffers + cached
	}
	used := total - available
	percent := 0.0
	if total > 0 {
		percent = round1(float64(used) / float64(total) * 100)
	}
	ret := map[string]any{
		"total":     total,
		"available": available,
		"percent":   percent,
		"used":      used,
		"free":      free,
		"active":    kv["Active"] * kb,
		"inactive":  kv["Inactive"] * kb,
		"buffers":   buffers,
		"cached":    cached,
		"shared":    kv["Shmem"] * kb,
		"slab":      kv["Slab"] * kb,
	}
	return ret, nil
}

type swapMemoryFunc struct{ linuxOnly }

func (swapMemoryFunc) Name() string { return "ps.swap_memory" }
func (swapMemoryFunc) Args() any    { return struct{}{} }
func (swapMemoryFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	kv, err := memInfoKV(rt)
	if err != nil {
		return nil, err
	}
	const kb = 1024
	pageSize := int64(os.Getpagesize())
	total := kv["SwapTotal"] * kb
	free := kv["SwapFree"] * kb
	used := total - free
	percent := 0.0
	if total > 0 {
		percent = round1(float64(used) / float64(total) * 100)
	}
	// pswpin/pswpout live in /proc/vmstat as page counts.
	swin, swout := int64(0), int64(0)
	if vs, verr := vmStatKV(rt); verr == nil {
		swin = vs["pswpin"] * pageSize
		swout = vs["pswpout"] * pageSize
	}
	return map[string]any{
		"total":   total,
		"used":    used,
		"free":    free,
		"percent": percent,
		"swin":    swin,
		"swout":   swout,
	}, nil
}

// vmStatKV parses /proc/vmstat counters.
func vmStatKV(rt *runtime.Runtime) (map[string]int64, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, "vmstat"))
	if err != nil {
		return nil, err
	}
	kv := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil {
			kv[fields[0]] = v
		}
	}
	return kv, nil
}

type TotalPhysicalMemoryArgs struct{}

type totalPhysicalMemoryFunc struct{ linuxOnly }

func (totalPhysicalMemoryFunc) Name() string { return "ps.total_physical_memory" }
func (totalPhysicalMemoryFunc) Args() any    { return TotalPhysicalMemoryArgs{} }
func (totalPhysicalMemoryFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	kv, err := memInfoKV(rt)
	if err != nil {
		return nil, err
	}
	return kv["MemTotal"] * 1024, nil
}

type NumCpusArgs struct{}

type numCpusFunc struct{ linuxOnly }

func (numCpusFunc) Name() string { return "ps.num_cpus" }
func (numCpusFunc) Args() any    { return NumCpusArgs{} }
func (numCpusFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	lines, err := readStatLines(rt)
	if err != nil {
		return nil, err
	}
	return int64(len(lines) - 1), nil
}

// --- Boot time --------------------------------------------------------------

type BootTimeArgs struct {
	TimeFormat *string `statekit:"name=time_format"`
}

type bootTimeFunc struct{ linuxOnly }

func (bootTimeFunc) Name() string { return "ps.boot_time" }
func (bootTimeFunc) Args() any    { return BootTimeArgs{} }

// strftimeLayout converts the common strftime directives into Go layouts;
// unknown directives raise like Salt's invalid format string path.
func strftimeLayout(format string) (string, error) {
	replacements := map[string]string{
		"%Y": "2006", "%m": "01", "%d": "02", "%H": "15", "%M": "04",
		"%S": "05", "%b": "Jan", "%e": "_2", "%a": "Mon", "%A": "Monday",
		"%B": "January", "%y": "06", "%p": "PM", "%I": "03", "%Z": "MST",
		"%z": "-0700", "%F": "2006-01-02", "%T": "15:04:05", "%%": "%",
	}
	out := format
	for directive, layout := range replacements {
		out = strings.ReplaceAll(out, directive, "\x00"+layout+"\x00")
	}
	// Any leftover % directive is unsupported.
	leftover := regexp.MustCompile("%.")
	if leftover.MatchString(strings.ReplaceAll(out, "\x00", "")) {
		return "", fmt.Errorf("Invalid format string")
	}
	return strings.ReplaceAll(out, "\x00", ""), nil
}

func (bootTimeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BootTimeArgs)
	btime, err := bootTimeSeconds(rt)
	if err != nil {
		return nil, err
	}
	if a.TimeFormat != nil {
		layout, cerr := strftimeLayout(*a.TimeFormat)
		if cerr != nil {
			return nil, &saltInvocationError{msg: cerr.Error()}
		}
		return timeFromUnix(btime).Format(layout), nil
	}
	return btime, nil
}

// saltInvocationError marks argument-level failures.
type saltInvocationError struct{ msg string }

func (e *saltInvocationError) Error() string { return e.msg }

// --- I/O counters -------------------------------------------------------------

type NetworkIoCountersArgs struct {
	Interface *string `statekit:"name=interface"`
}

type networkIOCountersFunc struct{ linuxOnly }

func (networkIOCountersFunc) Name() string { return "ps.network_io_counters" }
func (networkIOCountersFunc) Args() any    { return NetworkIoCountersArgs{} }

// parseNetDev parses /proc/net/dev rows into per-nic counter dicts.
func parseNetDev(data string) map[string]map[string]int64 {
	ret := map[string]map[string]int64{}
	for _, line := range strings.Split(data, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 11 {
			continue
		}
		numi := func(i int) int64 {
			v, _ := strconv.ParseInt(fields[i], 10, 64)
			return v
		}
		ret[name] = map[string]int64{
			"bytes_sent":   numi(8),
			"bytes_recv":   numi(0),
			"packets_sent": numi(9),
			"packets_recv": numi(1),
			"errin":        numi(2),
			"errout":       numi(10),
			"dropin":       numi(3),
			"dropout":      numi(11),
		}
	}
	return ret
}

func readNetDev(rt *runtime.Runtime) (map[string]map[string]int64, error) {
	data, err := rt.FS.ReadFile(joinProc(rt, "net", "dev"))
	if err != nil {
		return nil, err
	}
	stats := parseNetDev(string(data))
	if len(stats) == 0 {
		return nil, fmt.Errorf("no network interfaces found")
	}
	return stats, nil
}

func (networkIOCountersFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NetworkIoCountersArgs)
	stats, err := readNetDev(rt)
	if err != nil {
		return nil, err
	}
	if a.Interface == nil || *a.Interface == "" {
		total := map[string]int64{}
		for _, nic := range stats {
			for key, val := range nic {
				total[key] += val
			}
		}
		return toAnyMapInt(total), nil
	}
	nic, ok := stats[*a.Interface]
	if !ok {
		return false, nil
	}
	return toAnyMapInt(nic), nil
}

func toAnyMapInt(in map[string]int64) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type DiskIoCountersArgs struct {
	Device *string `statekit:"name=device"`
}

type diskIOCountersFunc struct{ linuxOnly }

func (diskIOCountersFunc) Name() string { return "ps.disk_io_counters" }
func (diskIOCountersFunc) Args() any    { return DiskIoCountersArgs{} }

// parseDiskStats maps /proc/diskstats into psutil's counter dicts; sector
// counts convert with the standard 512-byte assumption.
func parseDiskStats(data string) map[string]map[string]int64 {
	ret := map[string]map[string]int64{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		numi := func(i int) int64 {
			v, _ := strconv.ParseInt(fields[i], 10, 64)
			return v
		}
		name := fields[2]
		ret[name] = map[string]int64{
			"read_count":         numi(3),
			"write_count":        numi(7),
			"read_bytes":         numi(5) * 512,
			"write_bytes":        numi(9) * 512,
			"read_time":          numi(6),
			"write_time":         numi(10),
			"busy_time":          numi(12),
			"read_merged_count":  numi(4),
			"write_merged_count": numi(8),
		}
	}
	return ret
}

func (diskIOCountersFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DiskIoCountersArgs)
	data, err := rt.FS.ReadFile(joinProc(rt, "diskstats"))
	if err != nil {
		return nil, err
	}
	stats := parseDiskStats(string(data))
	if a.Device == nil || *a.Device == "" {
		total := map[string]int64{}
		for _, dev := range stats {
			for key, val := range dev {
				total[key] += val
			}
		}
		return toAnyMapInt(total), nil
	}
	dev, ok := stats[*a.Device]
	if !ok {
		return false, nil
	}
	return toAnyMapInt(dev), nil
}

// --- Users ---------------------------------------------------------------------

type GetUsersArgs struct{}

type getUsersFunc struct{ linuxOnly }

var utmpPath = func(rt *runtime.Runtime) string { return "/var/run/utmp" }

func (getUsersFunc) Name() string { return "ps.get_users" }
func (getUsersFunc) Args() any    { return GetUsersArgs{} }
func (getUsersFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(utmpPath(rt))
	if err != nil {
		return false, nil
	}
	const recordSize = 384
	var out []any
	for offset := 0; offset+recordSize <= len(data); offset += recordSize {
		rec := data[offset : offset+recordSize]
		rectype := int16LE(rec[0], rec[1])
		if rectype != 7 { // USER_PROCESS
			continue
		}
		out = append(out, map[string]any{
			"name":     nulString(rec[44:76]),
			"terminal": nulString(rec[8:40]),
			"started":  int64(int32LE(rec[340], rec[341], rec[342], rec[343])),
			"host":     strings.TrimRight(nulString(rec[76:332]), " "),
		})
	}
	if out == nil {
		out = []any{}
	}
	return out, nil
}

func int16LE(a, b byte) int {
	return int(a) | int(b)<<8
}

func int32LE(a, b, c, d byte) int32 {
	return int32(a) | int32(b)<<8 | int32(c)<<16 | int32(d)<<24
}

func nulString(b []byte) string {
	idx := 0
	for idx < len(b) && b[idx] != 0 {
		idx++
	}
	return string(b[:idx])
}

// --- CLI wrappers ---------------------------------------------------------------

type NameArgs struct {
	Name string `statekit:"required,name=name"`
}

// runTool mirrors __salt__["cmd.run"] for the wrapper functions.
func runTool(ctx context.Context, rt *runtime.Runtime, cmd string) (string, error) {
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run", &cmdmod.RunArgs{Cmd: cmd})
	if err != nil {
		return "", err
	}
	return resRaw.(string), nil
}

type lsofFunc struct{ linuxOnly }

func (lsofFunc) Name() string { return "ps.lsof" }
func (lsofFunc) Args() any    { return NameArgs{} }
func (lsofFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	out, err := runTool(ctx, rt, "lsof -c "+a.Name)
	if err != nil {
		return nil, err
	}
	return []any{a.Name, out}, nil
}

// whichGuard raises like salt.utils.decorators.path.which.
func whichGuard(exe string) error {
	if toolLookup(exe) {
		return nil
	}
	return fmt.Errorf("The '%s' binary was not found in $PATH.", exe)
}

// toolLookup mirrors salt.utils.path.which for wrapper guards.
var toolLookup = func(exe string) bool {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return true
		}
	}
	return false
}

type netstatFunc struct{ linuxOnly }

func (netstatFunc) Name() string { return "ps.netstat" }
func (netstatFunc) Args() any    { return NameArgs{} }
func (netstatFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if err := whichGuard("netstat"); err != nil {
		return nil, err
	}
	a := args.(*NameArgs)
	out, err := runTool(ctx, rt, "netstat -nap")
	if err != nil {
		return nil, err
	}
	return filterLines(out, a.Name), nil
}

type ssFunc struct{ linuxOnly }

func (ssFunc) Name() string { return "ps.ss" }
func (ssFunc) Args() any    { return NameArgs{} }
func (ssFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if err := whichGuard("ss"); err != nil {
		return nil, err
	}
	a := args.(*NameArgs)
	out, err := runTool(ctx, rt, "ss -neap")
	if err != nil {
		return nil, err
	}
	return filterLines(out, a.Name), nil
}

func filterLines(out, name string) []any {
	found := []any{}
	for _, info := range strings.Split(out, "\n") {
		if strings.Contains(info, name) {
			found = append(found, info)
		}
	}
	return []any{name, found}
}

type psauxFunc struct{ linuxOnly }

func (psauxFunc) Name() string { return "ps.psaux" }
func (psauxFunc) Args() any    { return NameArgs{} }

func (psauxFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NameArgs)
	pattern, perr := regexp.Compile(a.Name)
	if perr != nil {
		return nil, perr
	}
	saltException := regexp.MustCompile("salt.+ps.psaux.+")
	psAux, err := runTool(ctx, rt, "ps aux")
	if err != nil {
		return nil, err
	}
	found := []any{}
	nbLines := 0
	for _, info := range strings.Split(psAux, "\n") {
		if pattern.MatchString(info) && !saltException.MatchString(info) {
			nbLines++
			found = append(found, info)
		}
	}
	return []any{a.Name, found, strconv.Itoa(nbLines) + " occurrence(s)."}, nil
}

type StatusArgs struct {
	Status string `statekit:"required,name=status"`
}

type statusFunc struct{ linuxOnly }

func (statusFunc) Name() string { return "ps.status" }
func (statusFunc) Args() any    { return StatusArgs{} }

func (statusFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*StatusArgs)
	if a.Status == "" {
		return nil, &saltInvocationError{msg: "Filter is required for ps.status"}
	}
	ret := []any{}
	for _, pid := range pids(rt) {
		st, err := readStat(rt, pid)
		if err != nil {
			continue
		}
		if stateName(st.state) == a.Status {
			ret = append(ret, map[string]any{"pid": pid, "name": st.name})
		}
	}
	return ret, nil
}

// --- Disk partitions ---------------------------------------------------------

type DiskPartitionsArgs struct {
	All bool `statekit:"name=all"`
}

type diskPartitionsFunc struct{ linuxOnly }

func (diskPartitionsFunc) Name() string { return "ps.disk_partitions" }
func (diskPartitionsFunc) Args() any    { return DiskPartitionsArgs{} }

// nodevFilesystems reads /proc/filesystems and returns the nodev-marked
// types that psutil excludes unless all=True.
func nodevFilesystems(rt *runtime.Runtime) map[string]bool {
	nodev := map[string]bool{}
	data, err := rt.FS.ReadFile(joinProc(rt, "filesystems"))
	if err != nil {
		return nodev
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nodev\t") || strings.HasPrefix(line, "nodev ") {
			nodev[strings.TrimSpace(strings.TrimPrefix(line, "nodev"))] = true
		}
	}
	return nodev
}

func (diskPartitionsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DiskPartitionsArgs)
	data, err := rt.FS.ReadFile(joinProc(rt, "self", "mounts"))
	if err != nil {
		return nil, err
	}
	nodev := nodevFilesystems(rt)
	out := []any{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device, mountpoint, fstype, opts := fields[0], unescapeMount(fields[1]), fields[2], fields[3]
		if !a.All && (nodev[fstype] || device == "none") {
			continue
		}
		out = append(out, map[string]any{
			"device":     device,
			"mountpoint": mountpoint,
			"fstype":     fstype,
			"opts":       opts,
		})
	}
	return out, nil
}

// unescapeMount decodes the octal escapes /proc/mounts uses (\040 etc).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s)+1 {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type DiskUsageArgs struct {
	Path string `statekit:"required,name=path"`
}

type diskUsageFunc struct{ linuxOnly }

func (diskUsageFunc) Name() string { return "ps.disk_usage" }
func (diskUsageFunc) Args() any    { return DiskUsageArgs{} }

func (diskUsageFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DiskUsageArgs)
	var st statfsResult
	if err := statfs(a.Path, &st); err != nil {
		return nil, err
	}
	total := st.blocks * uint64(st.bsize)
	free := st.bfree * uint64(st.bsize)
	used := (st.blocks - st.bfree) * uint64(st.bsize)
	percent := 0.0
	if total > 0 {
		percent = round1(float64(used) / float64(total) * 100)
	}
	return map[string]any{
		"total":   total,
		"used":    used,
		"free":    free,
		"percent": percent,
	}, nil
}

type diskPartitionUsageFunc struct{ linuxOnly }

func (diskPartitionUsageFunc) Name() string { return "ps.disk_partition_usage" }
func (diskPartitionUsageFunc) Args() any    { return DiskPartitionsArgs{} }

func (diskPartitionUsageFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	partitions, err := diskPartitionsFunc{}.Execute(ctx, rt, args)
	if err != nil {
		return nil, err
	}
	list := partitions.([]any)
	for _, entryAny := range list {
		entry := entryAny.(map[string]any)
		usage, uerr := diskUsageFunc{}.Execute(ctx, rt, &DiskUsageArgs{
			Path: entry["mountpoint"].(string),
		})
		if uerr != nil {
			continue
		}
		for key, val := range usage.(map[string]any) {
			entry[key] = val
		}
	}
	return list, nil
}

// Register installs all ps-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		topFunc{},
		getPIDListFunc{},
		procInfoFunc{},
		killPIDFunc{},
		pkillFunc{},
		pgrepFunc{},
		cpuPercentFunc{},
		cpuTimesFunc{},
		virtualMemoryFunc{},
		swapMemoryFunc{},
		diskPartitionsFunc{},
		diskUsageFunc{},
		diskPartitionUsageFunc{},
		totalPhysicalMemoryFunc{},
		numCpusFunc{},
		bootTimeFunc{},
		networkIOCountersFunc{},
		diskIOCountersFunc{},
		getUsersFunc{},
		lsofFunc{},
		netstatFunc{},
		ssFunc{},
		psauxFunc{},
		statusFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
