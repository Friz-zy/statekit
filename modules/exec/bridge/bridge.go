// Package bridge implements Salt-compatible bridge management across
// Linux (brctl) and the BSD-like tools (ifconfig, brconfig).
//
// Reference: saltstack/salt/modules/bridge.py @ pinned revision.
//
// Contract notes (init.md section 28): the kernel grain resolves behind
// an injectable hook defaulting from GOOS. Upstream's parser carries a
// brname-persistence quirk that this port mirrors; a continuation line
// without a preceding bridge header surfaces as an error where upstream
// would raise an uncaught exception.
package bridge

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// supportedPlatforms lists every GOOS the family serves.
func (linuxLike) Platforms() []string {
	return []string{"linux", "freebsd", "netbsd", "openbsd"}
}

type linuxLike struct{}

// kernelHook mirrors __grains__["kernel"].
var kernelHook = func(rt *runtime.Runtime) string {
	switch goos() {
	case "linux":
		return "Linux"
	case "freebsd":
		return "FreeBSD"
	case "netbsd":
		return "NetBSD"
	case "openbsd":
		return "OpenBSD"
	default:
		return ""
	}
}

var bsdLike = map[string]bool{"FreeBSD": true, "NetBSD": true, "OpenBSD": true}

// toolPath mirrors salt.utils.path.which; injectable for suites.
var toolPath = func(ostool string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + ostool); err == nil {
			return dir + "/" + ostool
		}
	}
	return ""
}

// runText mirrors __salt__["cmd.run"](<string>, python_shell=False).
func runText(ctx context.Context, rt *runtime.Runtime, argv []string) string {
	res := rt.Runner.Run(ctx, process.Command{
		Name: argv[0],
		Args: append([]string{}, argv[1:]...),
	})
	if res.Err != nil {
		return res.Err.Error()
	}
	return string(res.Stdout)
}

func runRetcode(ctx context.Context, rt *runtime.Runtime, argv []string) int {
	res := rt.Runner.Run(ctx, process.Command{
		Name: argv[0],
		Args: append([]string{}, argv[1:]...),
	})
	if res.Err != nil {
		return -1
	}
	return res.ExitCode
}

// --- Linux internals ------------------------------------------------------

// linuxBrShow ports _linux_brshow including the brname-persistence quirk:
// single-token continuation lines append to the most recently seen bridge.
func linuxBrShow(ctx context.Context, rt *runtime.Runtime, br string) (any, error) {
	brctl := toolPath("brctl")
	if brctl == "" {
		return nil, fmt.Errorf("The bridge execution module failed to load: requires one of the following tool/os combinations: ifconfig on FreeBSD/OpenBSD, brctl on Linux or brconfig on NetBSD.")
	}
	var argv []string
	if br != "" {
		argv = []string{brctl, "show", br}
	} else {
		argv = []string{brctl, "show"}
	}

	brs := map[string]any{}
	brname := ""
	for _, line := range strings.Split(runText(ctx, rt, argv), "\n") {
		if strings.HasPrefix(line, "bridge name") {
			continue
		}
		vals := strings.Fields(line)
		if len(vals) == 0 {
			continue
		}
		if len(vals) > 1 {
			brname = vals[0]
			entry := map[string]any{
				"id":  vals[1],
				"stp": vals[2],
			}
			if len(vals) > 3 {
				entry["interfaces"] = []any{vals[3]}
			} else {
				entry["interfaces"] = []any{}
			}
			brs[brname] = entry
			continue
		}
		// Continuation line: upstream appends to the previous bridge and
		// crashes when no header was seen yet or interfaces were absent;
		// StateKit surfaces the same condition as an error.
		entry, ok := brs[brname].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed brctl output: interface %q without a bridge header", vals[0])
		}
		entry["interfaces"] = append(entry["interfaces"].([]any), vals[0])
	}

	if br != "" {
		entry, ok := brs[br].(map[string]any)
		if !ok {
			return nil, nil
		}
		return entry, nil
	}
	return brs, nil
}

func linuxBrAdd(ctx context.Context, rt *runtime.Runtime, br string) string {
	return runText(ctx, rt, []string{toolPath("brctl"), "addbr", br})
}

func linuxBrDel(ctx context.Context, rt *runtime.Runtime, br string) string {
	return runText(ctx, rt, []string{toolPath("brctl"), "delbr", br})
}

func linuxAddIf(ctx context.Context, rt *runtime.Runtime, br, iface string) string {
	return runText(ctx, rt, []string{toolPath("brctl"), "addif", br, iface})
}

func linuxDelIf(ctx context.Context, rt *runtime.Runtime, br, iface string) string {
	return runText(ctx, rt, []string{toolPath("brctl"), "delif", br, iface})
}

func linuxStp(ctx context.Context, rt *runtime.Runtime, br, state string) string {
	return runText(ctx, rt, []string{toolPath("brctl"), "stp", br, state})
}

// --- BSD internals ----------------------------------------------------------

func bsdBrShow(ctx context.Context, rt *runtime.Runtime, br string) any {
	if kernelHook(rt) == "NetBSD" {
		return netBSDBrShow(ctx, rt, br)
	}
	ifconfig := toolPath("ifconfig")

	ifaces := map[string]string{}
	if br != "" {
		ifaces[br] = br
	} else {
		for _, line := range strings.Split(
			runText(ctx, rt, []string{ifconfig, "-g", "bridge"}), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			ifaces[line] = line
		}
	}

	brs := map[string]any{}
	for iface := range ifaces {
		out := runText(ctx, rt, []string{ifconfig, iface})
		entry := map[string]any{"interfaces": []any{}, "stp": "no"}
		for _, line := range strings.Split(out, "\n") {
			stripped := strings.TrimLeft(line, " \t")
			if strings.HasPrefix(stripped, "member:") {
				fields := strings.Fields(stripped)
				if len(fields) > 1 {
					entry["interfaces"] = append(entry["interfaces"].([]any), fields[1])
				}
				if strings.Contains(stripped, "STP") {
					entry["stp"] = "yes"
				}
			}
		}
		brs[iface] = entry
	}

	if br != "" {
		return brs[br]
	}
	return brs
}

var netBSDIfaceRe = regexp.MustCompile(`^\s*([a-z0-9]+)\s.*<.*>`)

func netBSDBrShow(ctx context.Context, rt *runtime.Runtime, br string) any {
	brconfig := toolPath("brconfig")
	if brconfig == "" {
		return nil
	}
	var argv []string
	if br != "" {
		argv = []string{brconfig, br}
	} else {
		argv = []string{brconfig, "-a"}
	}

	brs := map[string]any{}
	startInt := false
	brname := ""
	for _, line := range strings.Split(runText(ctx, rt, argv), "\n") {
		if strings.HasPrefix(line, "bridge") {
			startInt = false
			brname = strings.Split(line, ":")[0]
			brs[brname] = map[string]any{"interfaces": []any{}, "stp": "no"}
		}
		if strings.Contains(line, "Interfaces:") {
			startInt = true
			continue
		}
		if startInt && brname != "" {
			if m := netBSDIfaceRe.FindStringSubmatch(line); m != nil {
				entry := brs[brname].(map[string]any)
				entry["interfaces"] = append(entry["interfaces"].([]any), m[1])
				if strings.Contains(line, "STP") {
					entry["stp"] = "yes"
				}
			}
		}
	}

	if br != "" {
		entry, ok := brs[br].(map[string]any)
		if !ok {
			return nil
		}
		return entry
	}
	return brs
}

func bsdBrAdd(ctx context.Context, rt *runtime.Runtime, br string) any {
	kernel := kernelHook(rt)
	ifconfig := toolPath("ifconfig")
	if br == "" {
		return false
	}
	if runRetcode(ctx, rt, []string{ifconfig, br, "create", "up"}) != 0 {
		return false
	}
	if kernel == "NetBSD" {
		brconfig := toolPath("brconfig")
		if runRetcode(ctx, rt, []string{brconfig, br, "up"}) != 0 {
			return false
		}
	}
	return true
}

func bsdBrDel(ctx context.Context, rt *runtime.Runtime, br string) any {
	ifconfig := toolPath("ifconfig")
	if br == "" {
		return false
	}
	return runText(ctx, rt, []string{ifconfig, br, "destroy"})
}

func bsdAddIf(ctx context.Context, rt *runtime.Runtime, br, iface string) any {
	kernel := kernelHook(rt)
	cmd := toolPath("ifconfig")
	brcmd := "addem"
	if kernel == "NetBSD" {
		cmd = toolPath("brconfig")
		brcmd = "add"
	}
	if br == "" || iface == "" {
		return false
	}
	return runText(ctx, rt, []string{cmd, br, brcmd, iface})
}

func bsdDelIf(ctx context.Context, rt *runtime.Runtime, br, iface string) any {
	kernel := kernelHook(rt)
	cmd := toolPath("ifconfig")
	brcmd := "deletem"
	if kernel == "NetBSD" {
		cmd = toolPath("brconfig")
		brcmd = "delete"
	}
	if br == "" || iface == "" {
		return false
	}
	return runText(ctx, rt, []string{cmd, br, brcmd, iface})
}

func bsdStp(ctx context.Context, rt *runtime.Runtime, br, state, iface string) any {
	cmd := toolPath("ifconfig")
	if kernelHook(rt) == "NetBSD" {
		cmd = toolPath("brconfig")
	}
	if br == "" || iface == "" {
		return false
	}
	return runText(ctx, rt, []string{cmd, br, state, iface})
}

// --- public surface -----------------------------------------------------------

type ShowArgs struct {
	Br *string `statekit:"name=br"`
}

type showFunc struct{ linuxLike }

func (showFunc) Name() string { return "bridge.show" }
func (showFunc) Args() any    { return ShowArgs{} }

// Execute returns bridges along with their enslaved interfaces.
func (showFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowArgs)
	br := ""
	if a.Br != nil {
		br = *a.Br
	}
	if bsdLike[kernelHook(rt)] {
		return bsdBrShow(ctx, rt, br), nil
	}
	return linuxBrShow(ctx, rt, br)
}

type ListArgs struct{}

type listFunc struct{ linuxLike }

func (listFunc) Name() string { return "bridge.list" }
func (listFunc) Args() any    { return ListArgs{} }

// Execute returns the machine's bridge names or None.
func (listFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	brsRaw, err := showFunc{}.Execute(ctx, rt, &ShowArgs{})
	if err != nil {
		return nil, err
	}
	brs, ok := brsRaw.(map[string]any)
	if !ok || len(brs) == 0 {
		return nil, nil
	}
	brlist := make([]any, 0, len(brs))
	for name := range brs {
		brlist = append(brlist, name)
	}
	return brlist, nil
}

type InterfacesArgs struct {
	Br *string `statekit:"name=br"`
}

type interfacesFunc struct{ linuxLike }

func (interfacesFunc) Name() string { return "bridge.interfaces" }
func (interfacesFunc) Args() any    { return InterfacesArgs{} }

func (interfacesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InterfacesArgs)
	if a.Br == nil || *a.Br == "" {
		return nil, nil
	}
	brRet, err := showFunc{}.Execute(ctx, rt, &ShowArgs{Br: a.Br})
	if err != nil {
		return nil, err
	}
	entry, ok := brRet.(map[string]any)
	if !ok || entry == nil {
		return nil, nil
	}
	return entry["interfaces"], nil
}

type FindInterfacesArgs struct {
	Names []string `statekit:"name=names"`
}

type findInterfacesFunc struct{ linuxLike }

func (findInterfacesFunc) Name() string { return "bridge.find_interfaces" }
func (findInterfacesFunc) Args() any    { return FindInterfacesArgs{} }

func (findInterfacesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FindInterfacesArgs)
	brsRaw, err := showFunc{}.Execute(ctx, rt, &ShowArgs{})
	if err != nil {
		return nil, err
	}
	brs, ok := brsRaw.(map[string]any)
	if !ok || len(brs) == 0 {
		return nil, nil
	}
	iflist := map[string]any{}
	for _, iface := range a.Names {
		for name, entryRaw := range brs {
			entry, ok := entryRaw.(map[string]any)
			if !ok {
				continue
			}
			interfaces, ok := entry["interfaces"].([]any)
			if !ok {
				continue
			}
			for _, candidate := range interfaces {
				if candidate.(string) == iface {
					iflist[iface] = name
					break
				}
			}
		}
	}
	return iflist, nil
}

type AddArgs struct {
	Br *string `statekit:"name=br"`
}

type addFunc struct{ linuxLike }

func (addFunc) Name() string { return "bridge.add" }
func (addFunc) Args() any    { return AddArgs{} }

func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	br := ""
	if a.Br != nil {
		br = *a.Br
	}
	if bsdLike[kernelHook(rt)] {
		return bsdBrAdd(ctx, rt, br), nil
	}
	return linuxBrAdd(ctx, rt, br), nil
}

type DeleteArgs struct {
	Br *string `statekit:"name=br"`
}

type deleteFunc struct{ linuxLike }

func (deleteFunc) Name() string { return "bridge.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }

func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	br := ""
	if a.Br != nil {
		br = *a.Br
	}
	if bsdLike[kernelHook(rt)] {
		return bsdBrDel(ctx, rt, br), nil
	}
	return linuxBrDel(ctx, rt, br), nil
}

type AddIfArgs struct {
	Br    *string `statekit:"name=br"`
	Iface *string `statekit:"name=iface"`
}

type addIfFunc struct{ linuxLike }

func (addIfFunc) Name() string { return "bridge.addif" }
func (addIfFunc) Args() any    { return AddIfArgs{} }

func (addIfFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddIfArgs)
	br := strArg(a.Br)
	iface := strArg(a.Iface)
	if bsdLike[kernelHook(rt)] {
		return bsdAddIf(ctx, rt, br, iface), nil
	}
	return linuxAddIf(ctx, rt, br, iface), nil
}

type DelIfArgs struct {
	Br    *string `statekit:"name=br"`
	Iface *string `statekit:"name=iface"`
}

type delIfFunc struct{ linuxLike }

func (delIfFunc) Name() string { return "bridge.delif" }
func (delIfFunc) Args() any    { return DelIfArgs{} }

func (delIfFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DelIfArgs)
	br := strArg(a.Br)
	iface := strArg(a.Iface)
	if bsdLike[kernelHook(rt)] {
		return bsdDelIf(ctx, rt, br, iface), nil
	}
	return linuxDelIf(ctx, rt, br, iface), nil
}

type StpArgs struct {
	Br    *string `statekit:"name=br"`
	State *string `statekit:"name=state"`
	Iface *string `statekit:"name=iface"`
}

type stpFunc struct{ linuxLike }

func (stpFunc) Name() string { return "bridge.stp" }
func (stpFunc) Args() any    { return StpArgs{} }

func (stpFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*StpArgs)
	br := strArg(a.Br)
	state := strArg(a.State)
	iface := strArg(a.Iface)
	kernel := kernelHook(rt)
	switch kernel {
	case "Linux":
		states := map[string]string{"enable": "on", "disable": "off"}
		mapped, ok := states[state]
		if !ok {
			// Upstream's states[state] raises KeyError uncaught.
			return nil, fmt.Errorf("invalid STP state %q", state)
		}
		return linuxStp(ctx, rt, br, mapped), nil
	case "FreeBSD", "NetBSD", "OpenBSD":
		states := map[string]string{"enable": "stp", "disable": "-stp"}
		mapped, ok := states[state]
		if !ok {
			return nil, fmt.Errorf("invalid STP state %q", state)
		}
		return bsdStp(ctx, rt, br, mapped, iface), nil
	default:
		return false, nil
	}
}

func strArg(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Register installs all bridge-module execution functions under their
// CLI-facing __func_alias__ names (list_ -> list).
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		showFunc{},
		listFunc{},
		interfacesFunc{},
		findInterfacesFunc{},
		addFunc{},
		deleteFunc{},
		addIfFunc{},
		delIfFunc{},
		stpFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
