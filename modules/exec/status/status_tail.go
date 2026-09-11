// Package status implements Salt's system-status surface: /proc parsers
// (Linux), process queries through the Runner, and the composite
// all_status/custom views, mirroring saltstack/salt/modules/status.py @
// pinned revision.
//
// Contract notes (init.md section 28): the Linux /proc parsers read via
// rt.FS (OS backend in production, MemoryFS in suites); non-Linux
// platforms return empty maps like upstream's platform dispatch falling
// through. master/ping_master/proxy_reconnect are master-minion functions
// and stay excluded.
package status

import (
	"context"
	"fmt"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

// psCommand resolves the process-listing command like __grains__["ps"];
// injectable, defaults to "ps -ef".
var psCommand = func() string { return "ps -ef" }

func number(s string) any {
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return f
	}
	return 0
}

func readFile(rt *runtime.Runtime, path string) string {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

type cpuinfoArgs struct{}

type cpuinfoFunc struct{}

func (cpuinfoFunc) Name() string { return "status.cpuinfo" }
func (cpuinfoFunc) Args() any    { return cpuinfoArgs{} }
func (cpuinfoFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	for _, line := range strings.Split(readFile(rt, "/proc/cpuinfo"), "\n") {
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "flags" {
			ret[key] = strings.Fields(value)
			continue
		}
		ret[key] = strings.TrimSpace(value)
	}
	return ret, nil
}

type cpustatsArgs struct{}

type cpustatsFunc struct{}

func (cpustatsFunc) Name() string { return "status.cpustats" }
func (cpustatsFunc) Args() any    { return cpustatsArgs{} }
func (cpustatsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	for _, line := range strings.Split(readFile(rt, "/proc/stat"), "\n") {
		if line == "" {
			continue
		}
		comps := strings.Fields(line)
		switch comps[0] {
		case "cpu":
			ret["cpu"] = map[string]any{
				"idle":    number(field(comps, 4)),
				"iowait":  number(field(comps, 5)),
				"irq":     number(field(comps, 6)),
				"nice":    number(field(comps, 2)),
				"softirq": number(field(comps, 7)),
				"steal":   number(field(comps, 8)),
				"system":  number(field(comps, 3)),
				"user":    number(field(comps, 1)),
			}
		case "intr":
			irqs := make([]any, 0, len(comps)-2)
			for _, x := range comps[2:] {
				irqs = append(irqs, number(x))
			}
			ret["intr"] = map[string]any{"total": number(field(comps, 1)), "irqs": irqs}
		case "softirq":
			softs := make([]any, 0, len(comps)-2)
			for _, x := range comps[2:] {
				softs = append(softs, number(x))
			}
			ret["softirq"] = map[string]any{"total": number(field(comps, 1)), "softirqs": softs}
		default:
			if len(comps) > 1 {
				ret[comps[0]] = number(comps[1])
			}
		}
	}
	return ret, nil
}

func field(comps []string, idx int) string {
	if idx < len(comps) {
		return comps[idx]
	}
	return "0"
}

type diskstatsArgs struct{}

type diskstatsFunc struct{}

func (diskstatsFunc) Name() string { return "status.diskstats" }
func (diskstatsFunc) Args() any    { return diskstatsArgs{} }
func (diskstatsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	for _, line := range strings.Split(readFile(rt, "/proc/diskstats"), "\n") {
		if line == "" {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 14 {
			continue
		}
		ret[comps[2]] = map[string]any{
			"major":                   number(comps[0]),
			"minor":                   number(comps[1]),
			"device":                  number(comps[2]),
			"reads_issued":            number(comps[3]),
			"reads_merged":            number(comps[4]),
			"sectors_read":            number(comps[5]),
			"ms_spent_reading":        number(comps[6]),
			"writes_completed":        number(comps[7]),
			"writes_merged":           number(comps[8]),
			"sectors_written":         number(comps[9]),
			"ms_spent_writing":        number(comps[10]),
			"io_in_progress":          number(comps[11]),
			"ms_spent_in_io":          number(comps[12]),
			"weighted_ms_spent_in_io": number(comps[13]),
		}
	}
	return ret, nil
}

type vmstatsArgs struct{}

type vmstatsFunc struct{}

func (vmstatsFunc) Name() string { return "status.vmstats" }
func (vmstatsFunc) Args() any    { return vmstatsArgs{} }
func (vmstatsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	for _, line := range strings.Split(readFile(rt, "/proc/vmstat"), "\n") {
		comps := strings.Fields(line)
		if len(comps) > 1 {
			ret[comps[0]] = number(comps[1])
		}
	}
	return ret, nil
}

type netstatsArgs struct{}

type netstatsFunc struct{}

func (netstatsFunc) Name() string { return "status.netstats" }
func (netstatsFunc) Args() any    { return netstatsArgs{} }

// Netstats mirrors linux_netstats: header/row line pairs per protocol.
func (netstatsFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	headers := []string{""}
	for _, line := range strings.Split(readFile(rt, "/proc/net/netstat"), "\n") {
		if line == "" {
			continue
		}
		comps := strings.Fields(line)
		if comps[0] == headers[0] {
			row := map[string]any{}
			for i := 1; i < len(headers) && i < len(comps); i++ {
				row[headers[i]] = number(comps[i])
			}
			ret[strings.TrimSuffix(headers[0], ":")] = row
		} else {
			headers = comps
		}
	}
	return ret, nil
}

type netdevArgs struct{}

type netdevFunc struct{}

func (netdevFunc) Name() string { return "status.netdev" }
func (netdevFunc) Args() any    { return netdevArgs{} }
func (netdevFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	ret := map[string]any{}
	if goruntime.GOOS != "linux" {
		return ret, nil
	}
	for _, line := range strings.Split(readFile(rt, "/proc/net/dev"), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		iface := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
		rest := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		// Upstream inserts the rx-bytes value again at index 1 before
		// indexing, shifting every subsequent field right by one.
		comps := append([]string{iface, fields[0]}, fields...)
		// Upstream indexes fields 2..17 of the whitespace-split row with
		// the iface name spliced at position 0 and rx bytes at 1.
		if len(comps) < 18 {
			continue
		}
		ret[comps[0]] = map[string]any{
			"iface":         comps[0],
			"rx_bytes":      number(comps[2]),
			"rx_compressed": number(comps[8]),
			"rx_drop":       number(comps[5]),
			"rx_errs":       number(comps[4]),
			"rx_fifo":       number(comps[6]),
			"rx_frame":      number(comps[7]),
			"rx_multicast":  number(comps[9]),
			"rx_packets":    number(comps[3]),
			"tx_bytes":      number(comps[10]),
			"tx_carrier":    number(comps[16]),
			"tx_colls":      number(comps[15]),
			"tx_compressed": number(comps[17]),
			"tx_drop":       number(comps[13]),
			"tx_errs":       number(comps[12]),
			"tx_fifo":       number(comps[14]),
			"tx_packets":    number(comps[11]),
		}
	}
	return ret, nil
}

type nprocArgs struct{}

type nprocFunc struct{}

func (nprocFunc) Name() string { return "status.nproc" }
func (nprocFunc) Args() any    { return nprocArgs{} }
func (nprocFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return goruntime.NumCPU(), nil
}

type procsArgs struct{}

type procsFunc struct{}

func (procsFunc) Name() string { return "status.procs" }
func (procsFunc) Args() any    { return procsArgs{} }

// Procs mirrors procs(): run the ps command (from facts when present,
// "ps -ef" fallback), parse USER/UID + PID + COMMAND/CMD columns by header
// index.
func (procsFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command(shellSplit(psCommand())...))
	lines := strings.Split(string(res.Stdout), "\n")
	ret := map[string]any{}
	if len(lines) == 0 {
		return ret, nil
	}
	guide := strings.Fields(lines[0])
	uind, pind, cind := 0, 0, 0
	if idx := indexOf(guide, "USER"); idx >= 0 {
		uind = idx
	} else if idx := indexOf(guide, "UID"); idx >= 0 {
		uind = idx
	}
	if idx := indexOf(guide, "PID"); idx >= 0 {
		pind = idx
	}
	if idx := indexOf(guide, "COMMAND"); idx >= 0 {
		cind = idx
	} else if idx := indexOf(guide, "CMD"); idx >= 0 {
		cind = idx
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		comps := strings.Fields(line)
		if pind >= len(comps) || uind >= len(comps) || cind >= len(comps) {
			continue
		}
		ret[comps[pind]] = map[string]any{
			"user": comps[uind],
			"cmd":  strings.Join(comps[cind:], " "),
		}
	}
	return ret, nil
}

type wArgs struct{}

type wFunc struct{}

func (wFunc) Name() string { return "status.w" }
func (wFunc) Args() any    { return wArgs{} }

// W mirrors w(): `w -fh` rows parsed into user records.
func (wFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	userList := []map[string]any{}
	res := rt.Runner.Run(ctx, runtime.Command("w", "-fh"))
	for _, row := range strings.Split(string(res.Stdout), "\n") {
		if row == "" {
			continue
		}
		comps := strings.Fields(row)
		if len(comps) < 6 {
			continue
		}
		userList = append(userList, map[string]any{
			"idle":  compAt(comps, 3),
			"jcpu":  compAt(comps, 4),
			"login": compAt(comps, 2),
			"pcpu":  compAt(comps, 5),
			"tty":   compAt(comps, 1),
			"user":  compAt(comps, 0),
			"what":  strings.Join(compSlice(comps, 6), " "),
		})
	}
	return userList, nil
}

type timeArgs struct {
	Format *string `statekit:"name=format"`
}

type timeFunc struct{}

// Time renders the current time through a converted strftime pattern.
// Supported directives mirror the common subset: %A %a %B %b %d %H %I %M
// %m %p %S %Y %y %% (documented subset).
func (timeFunc) Name() string { return "status.time_" }
func (timeFunc) Args() any    { return timeArgs{} }
func (timeFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*timeArgs)
	format := "%A, %d. %B %Y %I:%M%p"
	if a.Format != nil && *a.Format != "" {
		format = *a.Format
	}
	goLayout := strftimeToGo(format)
	return time.Now().Format(goLayout), nil
}

var strftimePairs = []struct{ py, goFmt string }{
	{"%A", "Monday"}, {"%a", "Mon"}, {"%B", "January"}, {"%b", "Jan"},
	{"%d", "02"}, {"%H", "15"}, {"%I", "03"}, {"%M", "04"}, {"%m", "01"},
	{"%p", "PM"}, {"%S", "05"}, {"%Y", "2006"}, {"%y", "06"}, {"%%", "%"},
}

func strftimeToGo(format string) string {
	out := format
	for _, pair := range strftimePairs {
		out = strings.ReplaceAll(out, pair.py, "\x00"+pair.goFmt+"\x00")
	}
	return strings.ReplaceAll(strings.ReplaceAll(out, "\x00", ""), "%", "%%")
}

type allStatusArgs struct{}

type allStatusFunc struct{}

func (allStatusFunc) Name() string { return "status.all_status" }
func (allStatusFunc) Args() any    { return allStatusArgs{} }

// AllStatus composes every probe; errors from individual probes degrade to
// empty maps exactly like upstream's platform dispatch.
func (allStatusFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	cpuinfoRes, _ := cpuinfoFunc{}.Execute(ctx, rt, &cpuinfoArgs{})
	cpustatsRes, _ := cpustatsFunc{}.Execute(ctx, rt, &cpustatsArgs{})
	diskstatsRes, _ := diskstatsFunc{}.Execute(ctx, rt, &diskstatsArgs{})
	vmstatsRes, _ := vmstatsFunc{}.Execute(ctx, rt, &vmstatsArgs{})
	netstatsRes, _ := netstatsFunc{}.Execute(ctx, rt, &netstatsArgs{})
	netdevRes, _ := netdevFunc{}.Execute(ctx, rt, &netdevArgs{})
	wRes, _ := wFunc{}.Execute(ctx, rt, &wArgs{})
	loadavgRes, _ := loadavgFunc{}.Execute(ctx, rt, &loadavgArgs{})
	meminfoRes, _ := meminfoFunc{}.Execute(ctx, rt, &meminfoArgs{})
	uptimeRes, _ := uptimeFunc{}.Execute(ctx, rt, &uptimeArgs{})
	diskusageRaw, _ := diskusageFunc{}.Execute(ctx, rt,
		map[string]any{"path": "/"})

	return map[string]any{
		"cpuinfo":   orEmptyMap(cpuinfoRes),
		"cpustats":  orEmptyMap(cpustatsRes),
		"diskstats": orEmptyMap(diskstatsRes),
		"diskusage": orEmptyValue(diskusageRaw),
		"loadavg":   orEmptyMap(loadavgRes),
		"meminfo":   orEmptyMap(meminfoRes),
		"netdev":    orEmptyMap(netdevRes),
		"netstats":  orEmptyMap(netstatsRes),
		"uptime":    orEmptyValue(uptimeRes),
		"vmstats":   orEmptyMap(vmstatsRes),
		"w":         orEmptyList(wRes),
	}, nil
}

type customArgs struct{}

type customFunc struct{}

// Custom mirrors custom(): reads config.option("status.<fn>.custom") lists
// and projects the named keys out of each probe's result. Without a config
// delegate it returns an empty map (same degradation model as pkgrepo).
func (customFunc) Name() string { return "status.custom" }
func (customFunc) Args() any    { return customArgs{} }
func (customFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	allRaw, err := allStatusFunc{}.Execute(ctx, rt, &allStatusArgs{})
	if err != nil {
		return nil, err
	}
	all := allRaw.(map[string]any)
	cfgOpt, ok := rt.Exec.Get("config.option")
	if !ok {
		return map[string]any{}, nil
	}
	ret := map[string]any{}
	for _, fnName := range []string{"cpuinfo", "cpustats", "diskstats", "loadavg",
		"meminfo", "vmstats", "netdev", "netstats", "w", "uptime", "diskusage"} {
		listAny, cerr := cfgOpt.(interface {
			Call(context.Context, *runtime.Runtime, string, any) (any, error)
		}).Call(ctx, rt, "config.option", map[string]any{
			"key": fmt.Sprintf("status.%s.custom", fnName),
		})
		if cerr != nil || listAny == nil {
			continue
		}
		items, ok := listAny.([]any)
		if !ok || len(items) == 0 {
			continue
		}
		fnData, ok := all[fnName].(map[string]any)
		if !ok {
			continue
		}
		filtered := map[string]any{}
		for _, item := range items {
			key := fmt.Sprintf("%v", item)
			if v, has := fnData[key]; has {
				filtered[key] = v
			}
		}
		ret[fnName] = filtered
	}
	return ret, nil
}

// RegisterTail installs the R4.5 status long-tail functions alongside the
// base set.
func RegisterTail(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		cpuinfoFunc{},
		cpustatsFunc{},
		diskstatsFunc{},
		vmstatsFunc{},
		netstatsFunc{},
		netdevFunc{},
		nprocFunc{},
		procsFunc{},
		wFunc{},
		timeFunc{},
		allStatusFunc{},
		customFunc{},
		statusPidFunc{},
		statusVersionFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
