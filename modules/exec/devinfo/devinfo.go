// Package devinfo implements Salt-compatible hardware probing through
// hwinfo plus udev-based device filtering.
//
// Reference: saltstack/salt/modules/devinfo.py @ pinned revision.
//
// Contract notes (init.md section 28):
//   - filter reads Salt's "disks" grain; StateKit derives the equivalent
//     device list from /sys/block behind an injectable hook.
//   - hwinfo's grains side-sections (efi, efi-secure-boot, mem_total,
//     fqdn, ip_interfaces, dns) are filled from direct system readers
//     (sysfs/procfs/resolv.conf/net.Interfaces) instead of the grains
//     subsystem; each reader is injectable for hermetic tests.
//   - Salt passes an argv LIST to cmd.run_stdout; StateKit hands the same
//     argv to the central Runner shell-free.
package devinfo

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execudev "github.com/friz-zy/statekit/modules/exec/udev"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// disksHook stands in for Salt's "disks" grain.
var disksHook = func(rt *runtime.Runtime) []string {
	entries, err := rt.FS.ReadDir("/sys/block/")
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out
}

// --- _udev / _match ----------------------------------------------------

// udevKey ports _udev: a dotted lower-case path ("e.id_bus") into the
// udev record; missing leaves read "n/a", an empty key returns the record.
func udevKey(udevInfo any, key string) any {
	k, rest, found := strings.Cut(key, ".")
	if k == "" {
		return udevInfo
	}
	record, ok := udevInfo.(map[string]any)
	if !ok {
		return "n/a"
	}
	upper := strings.ToUpper(k)
	if !found {
		if v, exists := record[upper]; exists {
			return v
		}
		return "n/a"
	}
	child, exists := record[upper]
	if !exists {
		child = map[string]any{}
	}
	return udevKey(child, rest)
}

// udevKeyAny adapts the typed entry point used by match.
func udevKeyAny(udevInfo map[string]any, key string) any {
	return udevKey(udevInfo, key)
}

// match ports _match: every match key's value must intersect the udev
// value (lists compare as sets); non-leaf keys are warned and skipped.
func match(udevInfo map[string]any, matchInfo map[string]any) bool {
	res := true
	for key, value := range matchInfo {
		udevValue := udevKeyAny(udevInfo, key)
		if _, isMap := udevValue.(map[string]any); isMap {
			// Not a leaf element: upstream logs and continues.
			continue
		}
		if !setsIntersect(value, udevValue) {
			res = false
		}
	}
	return res
}

// setsIntersect mirrors Python set(value) & set(udev_value) truthiness.
func setsIntersect(a, b any) bool {
	as := toSet(a)
	bs := toSet(b)
	for k := range as {
		if bs[k] {
			return true
		}
	}
	return false
}

func toSet(v any) map[string]bool {
	out := map[string]bool{}
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			out[scalarKey(item)] = true
		}
	case []string:
		for _, item := range t {
			out[item] = true
		}
	default:
		if v != nil {
			out[scalarKey(v)] = true
		}
	}
	return out
}

func scalarKey(v any) string {
	return fmt.Sprintf("%v", v)
}

// --- filter ------------------------------------------------------------

type FilterArgs struct {
	UdevIn map[string]any `statekit:"name=udev_in"`
	UdevEx map[string]any `statekit:"name=udev_ex"`
}

type filterFunc struct{ linuxOnly }

func (filterFunc) Name() string { return "devinfo.filter" }
func (filterFunc) Args() any    { return FilterArgs{} }

// Execute returns devices matching udev_in and not matching udev_ex,
// sorted like Salt's sorted().
func (filterFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FilterArgs)
	var devices []any
	var infos = map[string]map[string]any{}
	for _, dev := range disksHook(rt) {
		infoRaw, err := rt.Exec.Call(ctx, rt, "udev.info", &execudev.InfoArgs{Dev: dev})
		if err != nil {
			// Salt's dict-build propagates the udev.info failure.
			return nil, err
		}
		info, _ := infoRaw.(map[string]any)
		if info == nil {
			info = map[string]any{}
		}
		infos[dev] = info
		if len(a.UdevIn) > 0 && !match(infos[dev], a.UdevIn) {
			continue
		}
		if len(a.UdevEx) > 0 && match(infos[dev], a.UdevEx) {
			continue
		}
		devices = append(devices, dev)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].(string) < devices[j].(string)
	})
	if devices == nil {
		devices = []any{}
	}
	return devices, nil
}

// --- hwinfo parsers -----------------------------------------------------

// parseShort ports _hwinfo_parse_short: section headers end with ":",
// two-space lines are "key value" entries, four-space lines get numeric
// keys in encounter order.
func parseShort(report string) map[string]any {
	result := map[string]any{}
	var current map[string]any
	keyCounter := 0
	for _, line := range strings.Split(strings.Trim(report, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "    "):
			current[strconv.Itoa(keyCounter)] = strings.TrimSpace(line)
			keyCounter++
		case strings.HasPrefix(line, "  "):
			parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
			if len(parts) == 2 {
				current[parts[0]] = strings.TrimSpace(parts[1])
			} else {
				current[parts[0]] = ""
			}
		case strings.HasSuffix(line, ":"):
			key := line[:len(line)-1]
			value := map[string]any{}
			result[key] = value
			current = value
			keyCounter = 0
		default:
			// Upstream logs a parse error and drops the line.
		}
	}
	return result
}

// parseFull ports _hwinfo_parse_full including its quirks: the indent
// level recount truncates the stack on EVERY line (upstream's
// `len(result_stack) != result_stack` is always true), numeric keys stay
// strings ("01"), collisions widen into lists, Config Status parses into
// a dict, quoted models unwrap, and handle references become {"Handle":}.
func parseFull(report string) map[string]any {
	result := map[string]any{}
	var resultStack []map[string]any
	level := 0
	for _, raw := range strings.Split(strings.Trim(report, "\n"), "\n") {
		currentLevel := strings.Count(raw, "  ")
		resultStack = truncateStack(resultStack, currentLevel)
		level = currentLevel
		line := strings.TrimSpace(raw)

		if line == "" {
			continue
		}

		if level == 0 {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			subResult := map[string]any{}
			result[key] = subResult
			kv := strings.SplitN(strings.TrimSpace(parts[1]), ": ", 2)
			if len(kv) == 2 {
				subResult[kv[0]] = kv[1]
			} else if len(kv) == 1 && kv[0] != "" {
				subResult[kv[0]] = ""
			}
			resultStack = append(resultStack, subResult)
			level++
			continue
		}

		if strings.HasPrefix(line, "[") || !strings.Contains(line, ":") {
			if len(resultStack) == 0 {
				continue
			}
			note := line
			if strings.HasPrefix(note, "[") {
				note = note[1 : len(note)-1]
			}
			resultStack[len(resultStack)-1]["Note"] = note
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		var value any
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
		if len(resultStack) == 0 {
			continue
		}
		subResult := resultStack[len(resultStack)-1]

		strVal, _ := value.(string)
		if strVal != "" && !strings.HasPrefix(strVal, "#") && key != "El Torito info" {
			switch {
			case key == "I/O Port":
				key = "I/O Ports"
			case key == "Config Status":
				dict := map[string]any{}
				for _, item := range strings.Split(strVal, ", ") {
					kv := strings.SplitN(item, "=", 2)
					if len(kv) == 2 {
						dict[kv[0]] = kv[1]
					}
				}
				value = dict
			case key == "Driver" || key == "Driver Modules":
				var list []any
				for _, item := range strings.Split(strVal, ", ") {
					list = append(list, strings.ReplaceAll(item, "\"", ""))
				}
				value = list
			case key == "Tags" || key == "Device Files" || key == "Features":
				var list []any
				for _, item := range strings.Split(strVal, ",") {
					list = append(list, strings.TrimSpace(item))
				}
				value = list
			default:
				if strings.HasPrefix(strVal, "\"") {
					value = strVal[1 : len(strVal)-1]
				} else {
					value = strVal
				}
			}

			if existing, ok := subResult[key]; ok {
				var list []any
				if l, isList := existing.([]any); isList {
					list = l
				} else {
					list = []any{existing}
				}
				if !containsValue(list, value) {
					list = append(list, value)
				}
				if len(list) == 1 {
					value = list[0]
				} else {
					value = list
				}
			}
			subResult[key] = value
		} else {
			switch {
			case strings.HasPrefix(strVal, "#"):
				value = map[string]any{"Handle": strVal}
			case key == "El Torito info":
				items := strings.Split(strVal, ", ")
				entry := map[string]any{}
				if len(items) >= 2 {
					fields := strings.Fields(items[0])
					if len(fields) > 0 {
						entry["platform"] = fields[len(fields)-1]
					}
					if strings.Contains(items[1], "not") {
						entry["bootable"] = "no"
					} else {
						entry["bootable"] = "yes"
					}
				}
				value = entry
			default:
				value = map[string]any{}
			}
			subResult[key] = value
			if m, ok := value.(map[string]any); ok {
				resultStack = append(resultStack, m)
			}
			level++
		}
	}
	return result
}

func truncateStack(stack []map[string]any, level int) []map[string]any {
	if level < 0 {
		level = 0
	}
	if level > len(stack) {
		level = len(stack)
	}
	return stack[:level]
}

func containsValue(list []any, val any) bool {
	for _, item := range list {
		if scalarKey(item) == scalarKey(val) {
			return true
		}
	}
	return false
}

// --- grains-equivalent readers ------------------------------------------

var efiHook = func(rt *runtime.Runtime) bool {
	info, err := rt.FS.Stat("/sys/firmware/efi")
	return err == nil && info.IsDir()
}

var secureBootHook = func(rt *runtime.Runtime) bool {
	entries, err := rt.FS.ReadDir("/sys/firmware/efi/vars")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "SecureBoot-") {
			continue
		}
		data, err := rt.FS.ReadFile("/sys/firmware/efi/vars/" + entry.Name() + "/data")
		if err == nil && len(data) > 0 && data[0] == 1 {
			return true
		}
	}
	return false
}

var memTotalHook = func(rt *runtime.Runtime) int64 {
	data, err := rt.FS.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

var fqdnHook = func(rt *runtime.Runtime) string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

var ipInterfacesHook = func(rt *runtime.Runtime) map[string]any {
	ret := map[string]any{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ret
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		var list []any
		if err == nil {
			for _, addr := range addrs {
				list = append(list, stripCIDR(addr.String()))
			}
		}
		if list == nil {
			list = []any{}
		}
		ret[iface.Name] = list
	}
	return ret
}

func stripCIDR(addr string) string {
	if idx := strings.Index(addr, "/"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

var dnsHook = func(rt *runtime.Runtime) map[string]any {
	ret := map[string]any{"nameservers": []any{}}
	data, err := rt.FS.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ret
	}
	var ns []any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ns = append(ns, strings.TrimSpace(strings.TrimPrefix(line, "nameserver ")))
		}
	}
	if ns == nil {
		ns = []any{}
	}
	ret["nameservers"] = ns
	return ret
}

// hwinfoFunc mirrors devinfo.hwinfo.

type HwinfoArgs struct {
	Items   []string `statekit:"name=items"`
	Short   *bool    `statekit:"name=short"`
	Listmd  bool     `statekit:"name=listmd"`
	Devices []string `statekit:"name=devices"`
}

type hwinfoFunc struct{ linuxOnly }

func (hwinfoFunc) Name() string { return "devinfo.hwinfo" }
func (hwinfoFunc) Args() any    { return HwinfoArgs{} }

func (hwinfoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HwinfoArgs)
	items := a.Items
	if len(items) == 0 {
		items = []string{"bios", "cpu", "disk", "memory", "network", "partition"}
	}
	short := true
	if a.Short != nil {
		short = *a.Short
	}

	cmdArgs := []string{}
	for _, item := range items {
		cmdArgs = append(cmdArgs, "--"+item)
	}
	if short {
		cmdArgs = append(cmdArgs, "--short")
	}
	if a.Listmd {
		cmdArgs = append(cmdArgs, "--listmd")
	}
	for _, device := range a.Devices {
		cmdArgs = append(cmdArgs, "--only", device)
	}

	res := rt.Runner.Run(ctx, process.Command{Name: "hwinfo", Args: cmdArgs})
	if res.Err != nil {
		return nil, res.Err
	}
	out := string(res.Stdout)

	hasItem := func(name string) bool {
		for _, item := range items {
			if item == name {
				return true
			}
		}
		return false
	}

	result := map[string]any{
		"hwinfo": parse(out, short),
	}
	if hasItem("bios") {
		result["bios grains"] = map[string]any{
			"efi":             efiHook(rt),
			"efi-secure-boot": secureBootHook(rt),
		}
	}
	if hasItem("memory") {
		result["memory grains"] = map[string]any{
			"mem_total": memTotalHook(rt),
		}
	}
	if hasItem("network") {
		info := map[string]any{
			"fqdn":          fqdnHook(rt),
			"ip_interfaces": ipInterfacesHook(rt),
		}
		if !short {
			info["dns"] = dnsHook(rt)
		}
		result["network grains"] = info
	}
	return result, nil
}

func parse(report string, short bool) map[string]any {
	if short {
		return parseShort(report)
	}
	return parseFull(report)
}

// Register installs all devinfo-module execution functions under their
// CLI-facing __func_alias__ names (filter_ -> filter).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		filterFunc{},
		hwinfoFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
