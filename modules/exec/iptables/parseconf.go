package iptables

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	cmdmod "github.com/friz-zy/statekit/modules/exec/cmd"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// iptablesPath mirrors salt.utils.path.which for iptables/ip6tables.
var iptablesPath = func(family string) string {
	name := "iptables"
	if family == "ipv6" {
		name = "ip6tables"
	}
	return toolLookupPath(name)
}

// toolLookupPath resolves a binary through $PATH.
var toolLookupPath = func(exe string) string {
	for _, dir := range strings.Split(osGetenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if pathExists(dir + "/" + exe) {
			return dir + "/" + exe
		}
	}
	return ""
}

// osFamilyHook / osHook stand in for the os_family/os grains _conf reads.
var (
	osFamilyHook = func(rt *runtime.Runtime) string { return "" }
	osHook       = func(rt *runtime.Runtime) string { return "" }
)

// hasOptionFn ports _has_option with an injectable seam for suites.
var hasOptionFn = func(ctx context.Context, rt *runtime.Runtime, option, family string) bool {
	cmd := fmt.Sprintf("%s --help", iptablesPath(family))
	out, err := runStdout(ctx, rt, cmd)
	if err != nil {
		return false
	}
	return strings.Contains(out, option)
}

// getNodeHex mirrors uuid.getnode()-based temporary chain naming; Python's
// hex() keeps the 0x prefix.
var getNodeHex = func() string {
	mac, ok := primaryMAC()
	if !ok {
		return "0x0"
	}
	return "0x" + mac
}

func runStdout(ctx context.Context, rt *runtime.Runtime, cmd string) (string, error) {
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run_stdout", &cmdmod.RunStdoutArgs{Cmd: cmd})
	if err != nil {
		return "", err
	}
	return resRaw.(string), nil
}

// runStderrIgnore mirrors __salt__["cmd.run_stderr"] calls whose exit
// codes Salt surfaces only through context; StateKit returns the stderr
// text directly.
func runStderr(ctx context.Context, rt *runtime.Runtime, cmd string) (string, error) {
	resRaw, err := rt.Exec.Call(ctx, rt, "cmd.run_stderr", &cmdmod.RunStderrArgs{Cmd: cmd})
	if err != nil {
		return "", err
	}
	return resRaw.(string), nil
}

// confPath ports _conf: distro-specific save-file locations keyed by the
// os_family grain. Unsupported platforms raise like upstream.
func confPath(rt *runtime.Runtime, family string) (string, error) {
	switch osFamilyHook(rt) {
	case "RedHat":
		if family == "ipv6" {
			return "/etc/sysconfig/ip6tables", nil
		}
		return "/etc/sysconfig/iptables", nil
	case "Arch":
		if family == "ipv6" {
			return "/etc/iptables/ip6tables.rules", nil
		}
		return "/etc/iptables/iptables.rules", nil
	case "Debian":
		if family == "ipv6" {
			return "/etc/iptables/rules.v6", nil
		}
		return "/etc/iptables/rules.v4", nil
	case "Suse":
		return "/etc/sysconfig/scripts/SuSEfirewall2-custom", nil
	case "Void":
		if family == "ipv4" {
			return "/etc/iptables/iptables.rules", nil
		}
		return "/etc/iptables/ip6tables.rules", nil
	case "NILinuxRT":
		if family == "ipv6" {
			return "/etc/natinst/share/ip6tables.conf", nil
		}
		return "/etc/natinst/share/iptables.conf", nil
	default:
		if osHook(rt) == "Alpine" {
			if family == "ipv6" {
				return "/etc/iptables/rules6-save", nil
			}
			return "/etc/iptables/rules-save", nil
		}
		return "", fmt.Errorf(
			"Saving iptables to file is not supported on %s. Please file an issue with SaltStack",
			osHook(rt))
	}
}

// confSaveFilters ports _conf_save_filters: config.option delegate or [].
func confSaveFilters(ctx context.Context, rt *runtime.Runtime) []string {
	if !lookup(ctx, rt, "config.option") {
		return nil
	}
	payload := struct {
		Key   string
		Value any
	}{Key: "iptables.save_filters"}
	resRaw, err := rt.Exec.Call(ctx, rt, "config.option", &payload)
	if err != nil {
		return nil
	}
	list, _ := resRaw.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprintf("%v", item))
	}
	return out
}

// regexIptablesSave ports _regex_iptables_save: drop lines matching any
// compiled filter; invalid patterns are skipped with a warning.
func regexIptablesSave(cmdOutput string, filters []string) string {
	var compiled []*regexp.Regexp
	for _, pattern := range filters {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	if len(compiled) == 0 {
		return cmdOutput
	}
	var kept strings.Builder
	for _, line := range splitKeepEnds(cmdOutput) {
		match := false
		for _, re := range compiled {
			if re.MatchString(line) {
				match = true
				break
			}
		}
		if !match {
			kept.WriteString(line)
		}
	}
	return kept.String()
}

// splitKeepEnds mirrors splitlines(True).
func splitKeepEnds(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func lookup(ctx context.Context, rt *runtime.Runtime, name string) bool {
	_, ok := rt.Exec.Get(name)
	return ok
}

// --- parsers -------------------------------------------------------------

type optionSpec struct {
	short string
	long  string
	dest  string
}

var (
	shortDest = map[string]string{}
	longDest  = map[string]string{}
)

func init() {
	for _, spec := range optionTable {
		if spec.short != "" {
			shortDest[spec.short] = spec.dest
		}
		if spec.long != "" {
			longDest[spec.long] = spec.dest
		}
	}
}

func lookupDest(token string) (string, bool) {
	if dest, ok := longDest[token]; ok {
		return dest, true
	}
	if dest, ok := shortDest[token]; ok {
		return dest, true
	}
	return "", false
}

// shlexSplit ports salt.utils.args.shlex_split for the shapes
// iptables-save emits: posix quotes and backslash escapes.
func shlexSplit(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inToken := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"' || c == '\'':
			quote := c
			i++
			inToken = true
			for i < len(s) && s[i] != quote {
				if quote == '"' && s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("no closing quotation")
			}
			i++
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i += 2
			inToken = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inToken {
				out = append(out, cur.String())
				cur.Reset()
				inToken = false
			}
			i++
		default:
			cur.WriteByte(c)
			i++
			inToken = true
		}
	}
	if inToken {
		out = append(out, cur.String())
	}
	return out, nil
}

// normalizeArgs ports the swap-and-merge preprocessing _parse_conf runs
// before argparse: leading "!" tokens swap with their flag, multi-word
// values fold into the preceding flag, and valueless flags gain "".
func normalizeArgs(tokens []string) []string {
	args := append([]string{}, tokens...)
	index := 0
	for index+1 < len(args) {
		swap := args[index] == "!" && strings.HasPrefix(args[index+1], "-")
		if swap {
			args[index], args[index+1] = args[index+1], args[index]
		}
		if strings.HasPrefix(args[index], "-") {
			index++
			if index >= len(args) {
				break
			}
			if strings.HasPrefix(args[index], "-") || (args[index] == "!" && !swap) {
				args = append(args[:index], append([]string{""}, args[index:]...)...)
			} else {
				for index+1 < len(args) && args[index+1] != "!" && !strings.HasPrefix(args[index+1], "-") {
					args[index] += " " + args[index+1]
					args = append(args[:index+1], args[index+2:]...)
				}
			}
		}
		index++
	}
	if len(args) > 0 && strings.HasPrefix(args[len(args)-1], "-") {
		args = append(args, "")
	}
	return args
}

// parseKnownRule emulates argparse parse_known_args over the normalized
// token stream: known flags collect values under their dest, unknown
// flags and bare "!" tokens fall into the ignored extras bucket.
func parseKnownRule(tokens []string) map[string][]string {
	parsed := map[string][]string{}
	args := normalizeArgs(tokens)
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "!" {
			continue
		}
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		dest, known := lookupDest(tok)
		if i+1 < len(args) && args[i+1] != "!" && !strings.HasPrefix(args[i+1], "-") {
			if known {
				parsed[dest] = append(parsed[dest], args[i+1])
			}
			i++
			continue
		}
		// A following flag means this one takes no value; argparse would
		// have errored, upstream pre-seeds "" instead.
		if known {
			parsed[dest] = append(parsed[dest], "")
		}
	}
	return parsed
}

// parseConf ports _parse_conf over the runtime FileSystem and registry.
// Upstream evaluates _conf() unconditionally first, so unsupported
// platforms raise before any file resolution happens.
func parseConf(ctx context.Context, rt *runtime.Runtime, confFile string, inMem bool, family string) (map[string]any, error) {
	if confFile == "" && !inMem {
		resolved, cerr := confPath(rt, family)
		if cerr != nil {
			return nil, cerr
		}
		confFile = resolved
	}

	var rules string
	if confFile != "" {
		data, err := rt.FS.ReadFile(confFile)
		if err != nil {
			return nil, err
		}
		rules = string(data)
	} else if inMem {
		out, rerr := runStdout(ctx, rt, iptablesPath(family)+"-save")
		if rerr != nil {
			return nil, rerr
		}
		rules = out
	} else {
		return nil, fmt.Errorf("A file was not found to parse")
	}

	ret := map[string]any{}
	table := ""
	for _, line := range strings.Split(rules, "\n") {
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.ReplaceAll(line, "*", "")
			ret[table] = map[string]any{}
		case strings.HasPrefix(line, ":"):
			comps := strings.Fields(line)
			chain := strings.ReplaceAll(comps[0], ":", "")
			entry := map[string]any{}
			ret[table].(map[string]any)[chain] = entry
			entry["policy"] = comps[1]
			counters := strings.NewReplacer("[", "", "]", "").Replace(comps[2])
			counts := strings.Split(counters, ":")
			entry["packet count"] = counts[0]
			entry["byte count"] = counts[1]
			entry["rules"] = []any{}
			entry["rules_comment"] = map[string]any{}
		case strings.HasPrefix(line, "-A") && table != "":
			tokens, serr := shlexSplit(line)
			if serr != nil {
				continue
			}
			parsed := parseKnownRule(tokens)
			chainList := parsed["append"]
			if len(chainList) == 0 {
				continue
			}
			chain := chainList[0]
			retArgs := map[string]any{}
			for key, vals := range parsed {
				if key == "append" || len(vals) == 0 {
					continue
				}
				nonEmpty := make([]any, 0, len(vals))
				for _, v := range vals {
					if v != "" {
						nonEmpty = append(nonEmpty, v)
					}
				}
				// Upstream keeps falsy-only lists out entirely.
				if len(nonEmpty) > 0 {
					retArgs[key] = nonEmpty
				}
			}
			tableMap := ret[table].(map[string]any)
			chainEntry, ok := tableMap[chain].(map[string]any)
			if !ok {
				continue
			}
			if comments, ok := parsed["comment"]; ok && len(comments) > 0 {
				comment := strings.Trim(comments[0], "\"")
				retArgsCopy := map[string]any{}
				for k, v := range retArgs {
					retArgsCopy[k] = v
				}
				chainEntry["rules_comment"].(map[string]any)[comment] = retArgsCopy
			}
			chainEntry["rules"] = append(chainEntry["rules"].([]any), retArgs)
		}
	}
	return ret, nil
}
