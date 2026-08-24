// Package hosts implements Salt-compatible /etc/hosts management.
//
// Reference: saltstack/salt/modules/hosts.py @ pinned revision.
package hosts

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func fsFileMode(m uint32) fs.FileMode { return fs.FileMode(m) }

const hostsPath = "/etc/hosts"

type parsedHosts struct {
	order []string // ip order of first appearance
	byIP  map[string][]string
	lines []string // original lines for lossless rewrite
}

func parseHosts(content string) parsedHosts {
	out := parsedHosts{byIP: map[string][]string{}, lines: strings.Split(content, "\n")}
	for _, line := range out.lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if _, seen := out.byIP[ip]; !seen {
			out.order = append(out.order, ip)
		}
		for _, name := range fields[1:] {
			out.byIP[ip] = appendUnique(out.byIP[ip], name)
		}
	}
	return out
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

type ListArgs struct{}

type listFunc struct{}

func (listFunc) Name() string { return "hosts.list_hosts" }
func (listFunc) Args() any    { return ListArgs{} }
func (listFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return nil, err
	}
	parsed := parseHosts(string(data))
	out := map[string]any{}
	for _, ip := range parsed.order {
		out[ip] = parsed.byIP[ip]
	}
	return out, nil
}

type AddArgs struct {
	IP      string   `statekit:"required,name=ip"`
	Aliases []string `statekit:"required,name=aliases"`
}

type addFunc struct{}

func (addFunc) Name() string { return "hosts.add_host" }
func (addFunc) Args() any    { return AddArgs{} }
func (addFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return nil, err
	}
	parsed := parseHosts(string(data))
	existing, ok := parsed.byIP[a.IP]
	var names []string
	for _, alias := range a.Aliases {
		if !contains(existing, alias) {
			names = append(names, alias)
		}
	}
	if len(names) == 0 {
		return true, nil
	}
	mode := fileMode(rt, hostsPath)
	if ok {
		all := append(existing, names...)
		parsed.byIP[a.IP] = all
		return true, writeFile(rt, render(parsed), mode)
	}
	parsed.lines = append(parsed.lines, a.IP+" "+strings.Join(a.Aliases, " "))
	parsed.order = append(parsed.order, a.IP)
	parsed.byIP[a.IP] = a.Aliases
	return true, writeFile(rt, render(parsed), mode)
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func render(parsed parsedHosts) string {
	rendered := map[string]bool{}
	lines := []string{}
	for _, line := range parsed.lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && !strings.HasPrefix(line, "#") {
			ip := fields[0]
			names := parsed.byIP[ip]
			if names == nil || rendered[ip] {
				continue
			}
			rendered[ip] = true
			lines = append(lines, ip+"\t"+strings.Join(names, "\t"))
			continue
		}
		lines = append(lines, line)
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

type RmArgs struct {
	IP   string `statekit:"required,name=ip"`
	Name string `statekit:"name=name"`
}

type rmFunc struct{}

func (rmFunc) Name() string { return "hosts.rm_host" }
func (rmFunc) Args() any    { return RmArgs{} }
func (rmFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmArgs)
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return false, nil
	}
	parsed := parseHosts(string(data))
	names, ok := parsed.byIP[a.IP]
	if !ok {
		return false, nil
	}
	if a.Name == "" {
		delete(parsed.byIP, a.IP)
	} else {
		filtered := []string{}
		for _, name := range names {
			if name != a.Name {
				filtered = append(filtered, name)
			}
		}
		if len(filtered) == len(names) {
			return false, nil
		}
		parsed.byIP[a.IP] = filtered
	}
	mode := fileMode(rt, hostsPath)
	return true, writeFile(rt, render(parsed), mode)
}

type GetIPArgs struct {
	Name string `statekit:"required,name=name"`
}

type getIPFunc struct{}

func (getIPFunc) Name() string { return "hosts.get_ip" }
func (getIPFunc) Args() any    { return GetIPArgs{} }
func (getIPFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetIPArgs)
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return "", nil
	}
	parsed := parseHosts(string(data))
	for _, ip := range parsed.order {
		for _, name := range parsed.byIP[ip] {
			if name == a.Name {
				return ip, nil
			}
		}
	}
	return "", nil
}

type HasPairArgs struct {
	IP    string `statekit:"required,name=ip"`
	Alias string `statekit:"required,name=alias"`
}

type hasPairFunc struct{}

func (hasPairFunc) Name() string { return "hosts.has_pair" }
func (hasPairFunc) Args() any    { return HasPairArgs{} }
func (hasPairFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HasPairArgs)
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return false, nil
	}
	parsed := parseHosts(string(data))
	return contains(parsed.byIP[a.IP], a.Alias), nil
}

type GetAliasArgs struct {
	IP string `statekit:"required,name=ip"`
}

type getAliasFunc struct{}

func (getAliasFunc) Name() string { return "hosts.get_alias" }
func (getAliasFunc) Args() any    { return GetAliasArgs{} }
func (getAliasFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetAliasArgs)
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return []string{}, nil
	}
	parsed := parseHosts(string(data))
	aliases, ok := parsed.byIP[a.IP]
	if !ok {
		return []string{}, nil
	}
	return append([]string{}, aliases...), nil
}

type SetHostArgs struct {
	IP      string `statekit:"required,name=ip"`
	Aliases string `statekit:"name=alias"`
	Comment string `statekit:"name=comment"`
}

type setHostFunc struct{}

func (setHostFunc) Name() string { return "hosts.set_host" }
func (setHostFunc) Args() any    { return SetHostArgs{} }

// setHost mirrors hosts.set_host: the first line matching the IP is
// replaced, later duplicates are blanked, and an alias-less call removes
// every entry for the IP.
func setHost(rt *runtime.Runtime, ip, aliases, comment string) bool {
	if _, err := rt.FS.Stat(hostsPath); err != nil {
		return false
	}
	lineToAdd := ip + "\t\t" + aliases
	if comment != "" {
		lineToAdd += "\t\t# " + comment
	}
	if strings.TrimSpace(aliases) == "" {
		lineToAdd = ""
	}
	data, err := rt.FS.ReadFile(hostsPath)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	overwritten := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != ip {
			continue
		}
		if !overwritten {
			lines[i] = lineToAdd
			overwritten = true
		} else {
			lines[i] = ""
		}
	}
	if !overwritten {
		// Ensure the previous line ends with a newline before appending.
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines[len(lines)-1] += "\n"
		}
		lines = append(lines, lineToAdd)
	}
	mode := fileMode(rt, hostsPath)
	if err := writeFile(rt, strings.Join(lines, "\n"), mode); err != nil {
		return false
	}
	return true
}

func (setHostFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetHostArgs)
	return setHost(rt, a.IP, a.Aliases, a.Comment), nil
}

func fileMode(rt *runtime.Runtime, path string) fs.FileMode {
	mode := fs.FileMode(0o644)
	if info, err := rt.FS.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return mode
}

func writeFile(rt *runtime.Runtime, content string, mode fs.FileMode) error {
	if err := rt.FS.WriteFile(hostsPath, []byte(content), mode); err != nil {
		return fmt.Errorf("could not update %s: %w", hostsPath, err)
	}
	return nil
}

// Register installs all hosts-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{listFunc{}, addFunc{}, rmFunc{}, getIPFunc{}, hasPairFunc{}, getAliasFunc{}, setHostFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
