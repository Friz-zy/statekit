// Package ethtool implements Salt-compatible network device parameter
// queries and changes through the ethtool CLI.
//
// Reference: saltstack/salt/modules/ethtool.py @ pinned revision.
//
// Contract notes (init.md section 28): Salt backs show_/set_ring,
// show_/set_coalesce, show_driver and set_offload with the python-ethtool
// library while the pause/features functions use the ethtool binary.
// StateKit implements everything through the CLI and parses it into the
// same key shapes (documented mechanism divergence, identical observable
// data). Failure strings ("Not supported", "Not implemented",
// "Not available", "Invalid arguments") are returned verbatim instead of
// errors, mirroring Salt's OSError handlers. Commands run with
// ignore_retcode semantics; a first output line starting with "Cannot"
// raises like _ethtool_command.
package ethtool

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// ethtoolBin mirrors salt.utils.path.which("ethtool"); overridable for
// hermetic tests.
var ethtoolBin = func() string {
	path, err := exec.LookPath("ethtool")
	if err != nil {
		return ""
	}
	return path
}

// ethtoolCommand ports _ethtool_command: builds the shell string Salt
// builds, runs it with ignore-retcode semantics through the central
// Runner, and turns a leading "Cannot" line into an error.
func ethtoolCommand(ctx context.Context, rt *runtime.Runtime, devname string, switches []string, params map[string]string) ([]string, error) {
	bin := ethtoolBin()
	if bin == "" {
		return nil, fmt.Errorf("Command 'ethtool' cannot be found")
	}
	parts := []string{bin}
	parts = append(parts, switches...)
	parts = append(parts, devname)
	for key, val := range params {
		parts = append(parts, key+" "+val)
	}
	cmd := strings.TrimSpace(strings.Join(parts, " "))
	res := rt.Runner.Run(ctx, process.Command{Name: cmd, Shell: true})
	if res.Err != nil {
		return nil, res.Err
	}
	var ret []string
	if out := strings.ReplaceAll(strings.TrimRight(string(res.Stdout), "\n"), "\r\n", "\n"); out != "" {
		ret = strings.Split(out, "\n")
	}
	// Only the FIRST line is inspected, exactly like upstream.
	if len(ret) > 0 && strings.HasPrefix(ret[0], "Cannot") {
		return nil, fmt.Errorf("%s", ret[0])
	}
	return ret, nil
}

// pythonReprList renders a []string like Python's repr for error messages.
func pythonReprList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, "'"+item+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// validateParams ports _validate_params: lowercased keys filtered to the
// valid set, booleans become on/off; nothing valid raises.
func validateParams(valid []string, kwargs map[string]any) (map[string]string, error) {
	validSet := map[string]bool{}
	for _, v := range valid {
		validSet[strings.ToLower(v)] = true
	}
	validated := map[string]string{}
	for key, val := range kwargs {
		key = strings.ToLower(key)
		if !validSet[key] {
			continue
		}
		switch t := val.(type) {
		case bool:
			if t {
				validated[key] = "on"
			} else {
				validated[key] = "off"
			}
		default:
			validated[key] = fmt.Sprintf("%v", t)
		}
	}
	if len(validated) == 0 {
		return nil, fmt.Errorf(
			"None of the valid parameters were provided: %s", pythonReprList(valid))
	}
	return validated, nil
}

// parseKeyValueLines parses "key: value" lines skipping blanks and the
// header (first line), preserving insertion order via the returned slice
// of pairs.
func parseKeyValueLines(lines []string) [][2]string {
	var pairs [][2]string
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		idx := strings.Index(line, ":")
		pairs = append(pairs, [2]string{
			strings.TrimSpace(line[:idx]),
			strings.TrimSpace(line[idx+1:]),
		})
	}
	return pairs
}

type DevnameArgs struct {
	Devname string `statekit:"required,name=devname"`
}

type KwargsArgs struct {
	Devname string         `statekit:"required,name=devname"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

// --- Ring parameters -------------------------------------------------

var ringMap = map[string]string{
	"rx":       "rx_pending",
	"rx_max":   "rx_max_pending",
	"rx_mini":  "rx_mini_pending",
	"rx_jumbo": "rx_jumbo_pending",
	"tx":       "tx_pending",
	"tx_max":   "tx_max_pending",
}

// ringOrder pins the reply shape of the python-ethtool library.
var ringOrder = []string{"rx", "rx_max", "rx_mini", "rx_mini_max", "rx_jumbo", "rx_jumbo_max", "tx", "tx_max"}

// parseRingOutput parses `ethtool -g`: the "Pre-set maximums" section
// feeds the *_max keys, "Current hardware settings" the plain keys.
// Kernel labels are RX / RX Mini / RX Jumbo / TX; values coerce to ints
// like python-ethtool's replies.
func parseRingOutput(out string) map[string]any {
	ret := map[string]any{}
	section := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Pre-set maximums"):
			section = "max"
			continue
		case strings.HasPrefix(line, "Current hardware settings"):
			section = "current"
			continue
		case line == "" || !strings.Contains(line, ":"):
			continue
		}
		idx := strings.Index(line, ":")
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		var target string
		switch {
		case section == "max":
			switch key {
			case "RX":
				target = "rx_max"
			case "RX Mini":
				target = "rx_mini_max"
			case "RX Jumbo":
				target = "rx_jumbo_max"
			case "TX":
				target = "tx_max"
			}
		default:
			switch key {
			case "RX":
				target = "rx"
			case "RX Mini":
				target = "rx_mini"
			case "RX Jumbo":
				target = "rx_jumbo"
			case "TX":
				target = "tx"
			}
		}
		if target != "" {
			ret[target] = coerceInt(val)
		}
	}
	return ret
}

// coerceInt converts numeric strings to int64 like the python-ethtool
// library values; anything else stays a string.
func coerceInt(val string) any {
	if n, err := strconv.ParseInt(val, 10, 64); err == nil {
		return n
	}
	return val
}

type showRingFunc struct{ linuxOnly }

func (showRingFunc) Name() string { return "ethtool.show_ring" }
func (showRingFunc) Args() any    { return DevnameArgs{} }
func (showRingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-g"}, nil)
	if err != nil {
		return "Not supported", nil
	}
	return remapRing(parseRingOutput(strings.Join(lines, "\n"))), nil
}

// remapRing keeps only the library-known keys so the reply shape matches
// python-ethtool's ring dict.
func remapRing(parsed map[string]any) map[string]any {
	ret := map[string]any{}
	for _, key := range ringOrder {
		if v, ok := parsed[key]; ok {
			ret[key] = v
		}
	}
	return ret
}

type setRingFunc struct{ linuxOnly }

func (setRingFunc) Name() string { return "ethtool.set_ring" }
func (setRingFunc) Args() any    { return KwargsArgs{} }
func (setRingFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KwargsArgs)
	currentRaw, err := showRingFunc{}.Execute(ctx, rt, &DevnameArgs{Devname: a.Devname})
	if err != nil {
		return "Not supported", nil
	}
	if s, ok := currentRaw.(string); ok {
		return s, nil
	}
	current := currentRaw.(map[string]any)

	changed := false
	params := map[string]string{}
	for key, val := range a.Kwargs {
		if _, ok := ringMap[key]; !ok {
			continue
		}
		if _, exists := current[key]; !exists {
			continue
		}
		if fmt.Sprintf("%v", current[key]) != fmt.Sprintf("%v", val) {
			params[key] = fmt.Sprintf("%v", val)
			changed = true
		}
	}
	if changed {
		lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-G"}, params)
		if err != nil {
			_ = lines
			return "Invalid arguments", nil
		}
	}
	show, _ := showRingFunc{}.Execute(ctx, rt, &DevnameArgs{Devname: a.Devname})
	return show, nil
}

// --- Coalescing -------------------------------------------------------

var coalesceMap = map[string]string{
	"pkt_rate_high":     "pkt_rate_high",
	"pkt_rate_low":      "pkt_rate_low",
	"sample_interval":   "rate_sample_interval",
	"rx_usecs":          "rx_coalesce_usecs",
	"rx_usecs_high":     "rx_coalesce_usecs_high",
	"rx_usecs_irq":      "rx_coalesce_usecs_irq",
	"rx_usecs_low":      "rx_coalesce_usecs_low",
	"rx_frames":         "rx_max_coalesced_frames",
	"rx_frames_high":    "rx_max_coalesced_frames_high",
	"rx_frames_irg":     "rx_max_coalesced_frames_irq",
	"rx_frames_low":     "rx_max_coalesced_frames_low",
	"stats_block_usecs": "stats_block_coalesce_usecs",
	"tx_usecs":          "tx_coalesce_usecs",
	"tx_usecs_high":     "tx_coalesce_usecs_high",
	"tx_usecs_irq":      "tx_coalesce_usecs_irq",
	"tx_usecs_low":      "tx_coalesce_usecs_low",
	"tx_frames":         "tx_max_coalesced_frames",
	"tx_frames_high":    "tx_max_coalesced_frames_high",
	"tx_frames_irq":     "tx_max_coalesced_frames_irq",
	"tx_frames_low":     "tx_max_coalesced_frames_low",
	"adaptive_rx":       "use_adaptive_rx_coalesce",
	"adaptive_tx":       "use_adaptive_tx_coalesce",
}

var coalesceRemap = map[string]string{}

func init() {
	for k, v := range coalesceMap {
		coalesceRemap[v] = k
	}
}

// parseCoalesceOutput parses `ethtool -c` including the combined
// "Adaptive RX: off\tTX: off" banner line.
func parseCoalesceOutput(out string) map[string]any {
	ret := map[string]any{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Adaptive RX:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Adaptive RX:"))
			if len(fields) >= 2 && fields[0] != "" {
				ret["adaptive_rx"] = fields[0]
			}
			for i, f := range fields {
				if f == "TX:" && i+1 < len(fields) {
					ret["adaptive_tx"] = fields[i+1]
				}
			}
			continue
		}
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		idx := strings.Index(line, ":")
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		ret[strings.ReplaceAll(key, "-", "_")] = val
	}
	return ret
}

type showCoalesceFunc struct{ linuxOnly }

func (showCoalesceFunc) Name() string { return "ethtool.show_coalesce" }
func (showCoalesceFunc) Args() any    { return DevnameArgs{} }
func (showCoalesceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-c"}, nil)
	if err != nil {
		return "Not supported", nil
	}
	parsed := parseCoalesceOutput(strings.Join(lines, "\n"))
	ret := map[string]any{}
	for kernel, short := range coalesceRemap {
		if v, ok := parsed[kernel]; ok {
			ret[short] = v
		}
	}
	return ret, nil
}

type setCoalesceFunc struct{ linuxOnly }

func (setCoalesceFunc) Name() string { return "ethtool.set_coalesce" }
func (setCoalesceFunc) Args() any    { return KwargsArgs{} }
func (setCoalesceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KwargsArgs)
	lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-c"}, nil)
	if err != nil {
		return "Not supported", nil
	}
	current := parseCoalesceOutput(strings.Join(lines, "\n"))

	changed := false
	cliParams := map[string]string{}
	for key, val := range a.Kwargs {
		kernel, ok := coalesceMap[key]
		if !ok {
			continue
		}
		if _, exists := current[kernel]; !exists {
			continue
		}
		strVal := fmt.Sprintf("%v", val)
		if boolVal, isBool := val.(bool); isBool {
			if boolVal {
				strVal = "on"
			} else {
				strVal = "off"
			}
		}
		if fmt.Sprintf("%v", current[kernel]) != strVal {
			cliParams[strings.ReplaceAll(key, "_", "-")] = strVal
			changed = true
		}
	}
	if changed {
		if _, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-C"}, cliParams); err != nil {
			return "Invalid arguments", nil
		}
	}
	show, _ := showCoalesceFunc{}.Execute(ctx, rt, &DevnameArgs{Devname: a.Devname})
	return show, nil
}

// --- Driver -----------------------------------------------------------

type showDriverFunc struct{ linuxOnly }

func (showDriverFunc) Name() string { return "ethtool.show_driver" }
func (showDriverFunc) Args() any    { return DevnameArgs{} }
func (showDriverFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-i"}, nil)
	if err != nil {
		return "Not implemented", nil
	}
	// `ethtool -i` has no header line; every line is a key:value pair.
	info := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		idx := strings.Index(line, ":")
		info[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	businfo, ok := info["bus-info"]
	if !ok {
		return "Not available", nil
	}
	return map[string]any{
		"driver":   info["driver"],
		"bus_info": businfo,
	}, nil
}

// --- Offload ----------------------------------------------------------

var offloadMap = map[string]string{
	"scatter-gather":               "scatter_gather",
	"tcp-segmentation-offload":     "tcp_segmentation_offload",
	"udp-fragmentation-offload":    "udp_fragmentation_offload",
	"generic-segmentation-offload": "generic_segmentation_offload",
}

type showOffloadFunc struct{ linuxOnly }

func (showOffloadFunc) Name() string { return "ethtool.show_offload" }
func (showOffloadFunc) Args() any    { return DevnameArgs{} }
func (showOffloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-k"}, nil)
	if err != nil {
		return map[string]any{
			"scatter_gather":               "not supported",
			"tcp_segmentation_offload":     "not supported",
			"udp_fragmentation_offload":    "not supported",
			"generic_segmentation_offload": "not supported",
		}, nil
	}
	features := parseFeatureLines(lines)
	offload := map[string]any{}
	for cliKey, saltKey := range offloadMap {
		if feat, ok := features[cliKey]; ok {
			state := "off"
			if feat.on {
				state = "on"
			}
			offload[saltKey] = state
			continue
		}
		offload[saltKey] = "not supported"
	}
	return offload, nil
}

type setOffloadFunc struct{ linuxOnly }

func (setOffloadFunc) Name() string { return "ethtool.set_offload" }
func (setOffloadFunc) Args() any    { return KwargsArgs{} }
func (setOffloadFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KwargsArgs)
	for key, val := range a.Kwargs {
		if key != "tcp_segmentation_offload" {
			continue
		}
		state := "off"
		if val == "on" {
			state = "on"
		}
		lines, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-K"}, map[string]string{"tso": state})
		if err != nil {
			_ = lines
			return "Not supported", nil
		}
	}
	show, _ := showOffloadFunc{}.Execute(ctx, rt, &DevnameArgs{Devname: a.Devname})
	return show, nil
}

// --- Pause / features (CLI-native upstream) ----------------------------

type showPauseFunc struct{ linuxOnly }

func (showPauseFunc) Name() string { return "ethtool.show_pause" }
func (showPauseFunc) Args() any    { return DevnameArgs{} }
func (showPauseFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	content, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-a"}, nil)
	if err != nil {
		return nil, err
	}
	data := map[string]any{}
	for _, pair := range parseKeyValueLines(content) {
		data[pair[0]] = pair[1] == "on"
	}
	return data, nil
}

type setPauseFunc struct{ linuxOnly }

func (setPauseFunc) Name() string { return "ethtool.set_pause" }
func (setPauseFunc) Args() any    { return KwargsArgs{} }
func (setPauseFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KwargsArgs)
	params, err := validateParams([]string{"autoneg", "rx", "tx"}, a.Kwargs)
	if err != nil {
		return nil, err
	}
	ret, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-A"}, params)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return true, nil
	}
	return ret, nil
}

// featureState mirrors Salt's {"on": bool, "fixed": bool} shape.
type featureState struct {
	on    bool
	fixed bool
}

// parseFeatureLines handles the indented sub-feature layout of
// `ethtool -k`, where continuation lines carry deeper indentation.
func parseFeatureLines(lines []string) map[string]featureState {
	data := map[string]featureState{}
	for _, line := range lines[1:] {
		if !strings.Contains(line, ":") {
			continue
		}
		stripped := strings.TrimSpace(line)
		idx := strings.Index(stripped, ":")
		key := strings.TrimSpace(stripped[:idx])
		value := strings.TrimSpace(stripped[idx+1:])
		fixed := strings.Contains(value, "fixed")
		if fixed {
			value = strings.Fields(value)[0]
		}
		data[key] = featureState{on: value == "on", fixed: fixed}
	}
	return data
}

type showFeaturesFunc struct{ linuxOnly }

func (showFeaturesFunc) Name() string { return "ethtool.show_features" }
func (showFeaturesFunc) Args() any    { return DevnameArgs{} }
func (showFeaturesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DevnameArgs)
	content, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-k"}, nil)
	if err != nil {
		return nil, err
	}
	data := map[string]any{}
	for key, feat := range parseFeatureLines(content) {
		data[key] = map[string]bool{"on": feat.on, "fixed": feat.fixed}
	}
	return data, nil
}

type setFeatureFunc struct{ linuxOnly }

func (setFeatureFunc) Name() string { return "ethtool.set_feature" }
func (setFeatureFunc) Args() any    { return KwargsArgs{} }
func (setFeatureFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*KwargsArgs)
	valid := []string{"rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro",
		"rxvlan", "txvlan", "ntuple", "rxhash"}
	params, err := validateParams(valid, a.Kwargs)
	if err != nil {
		return nil, err
	}
	ret, err := ethtoolCommand(ctx, rt, a.Devname, []string{"-K"}, params)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return true, nil
	}
	return strings.Join(ret, "\n"), nil
}

// Register installs all ethtool-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		showRingFunc{},
		showCoalesceFunc{},
		showDriverFunc{},
		setRingFunc{},
		setCoalesceFunc{},
		showOffloadFunc{},
		setOffloadFunc{},
		showPauseFunc{},
		setPauseFunc{},
		showFeaturesFunc{},
		setFeatureFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
