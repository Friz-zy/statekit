// Package nftables implements Salt-compatible nftables management through
// the nft CLI. Upstream passes shell-style command strings with
// python_shell=False, so StateKit builds equivalent argv slices.
//
// Reference: saltstack/salt/modules/nftables.py @ pinned revision.
package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

var nftablesFamilies = map[string]string{
	"ipv4": "ip", "ip4": "ip", "ip": "ip",
	"ipv6": "ip6", "ip6": "ip6",
	"inet": "inet", "arp": "arp", "bridge": "bridge", "netdev": "netdev",
}

// nftBin mirrors salt.utils.path.which("nft"); injectable for suites.
var nftBin = func() string {
	for _, dir := range strings.Split(osGetenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if pathExists(dir + "/nft") {
			return dir + "/nft"
		}
	}
	return ""
}

// osFamilyHook / osHook stand in for the grains _conf reads.
var (
	osFamilyHook = func(rt *runtime.Runtime) string { return "" }
	osHook       = func(rt *runtime.Runtime) string { return "" }
)

func osGetenv(key string) string { return os.Getenv(key) }

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// decodeNftJSON decodes the {"nftables": [...]} envelope.
func decodeNftJSON(out string) ([]any, error) {
	var root struct {
		Nftables []any `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		return nil, err
	}
	return root.Nftables, nil
}

// directoryExists prefers the file.directory_exists delegate and falls
// back to a local stat when the file family is not registered
// (documented mechanism divergence).
func directoryExists(ctx context.Context, rt *runtime.Runtime, path string) bool {
	if _, ok := rt.Exec.Get("file.directory_exists"); ok {
		resRaw, err := rt.Exec.Call(ctx, rt, "file.directory_exists",
			struct{ Path string }{path})
		if err == nil {
			if b, ok := resRaw.(bool); ok {
				return b
			}
		}
	}
	info, err := rt.FS.Stat(path)
	return err == nil && info.IsDir()
}

// runText mirrors __salt__["cmd.run"](<string>, python_shell=False): Salt
// splits the string safely and executes without a shell, so StateKit runs
// the equivalent argv slice and returns stdout text.
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

func familyOf(family string) string {
	return nftablesFamilies[family]
}

// confPath ports _conf: one shared save file per supported distro,
// boolean false elsewhere.
func confPath(rt *runtime.Runtime) (string, bool) {
	switch osFamilyHook(rt) {
	case "RedHat", "Arch", "Debian":
		return "/etc/nftables", true
	default:
		if osHook(rt) == "Gentoo" {
			return "/etc/nftables", true
		}
		return "", false
	}
}

type VersionArgs struct{}

type versionFunc struct{ linuxOnly }

func (versionFunc) Name() string { return "nftables.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	out := runText(ctx, rt, []string{nftBin(), "--version"})
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected nftables version output")
	}
	return fields[1], nil
}

type GetSavedRulesArgs struct {
	ConfFile *string `statekit:"name=conf_file"`
}

type getSavedRulesFunc struct{ linuxOnly }

func (getSavedRulesFunc) Name() string { return "nftables.get_saved_rules" }
func (getSavedRulesFunc) Args() any    { return GetSavedRulesArgs{} }
func (getSavedRulesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetSavedRulesArgs)
	confFile := ""
	if a.ConfFile != nil {
		confFile = *a.ConfFile
	}
	if path, ok := confPath(rt); ok && confFile == "" {
		confFile = path
	}
	data, err := rt.FS.ReadFile(confFile)
	if err != nil {
		return nil, err
	}
	rules := []any{}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rules = append(rules, line)
	}
	return rules, nil
}

type ListTablesArgs struct {
	Family *string `statekit:"name=family"`
}

type listTablesFunc struct{ linuxOnly }

func (listTablesFunc) Name() string { return "nftables.list_tables" }
func (listTablesFunc) Args() any    { return ListTablesArgs{} }
func (listTablesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListTablesArgs)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	out := runText(ctx, rt, []string{
		nftBin(), "--json", "--numeric", "--numeric", "--numeric",
		"list", "tables", familyOf(family),
	})
	if out == "" {
		return []any{}, nil
	}
	tables := []any{}
	items, err := decodeNftJSON(out)
	if err != nil {
		return tables, nil
	}
	for _, itemAny := range items {
		item, ok := itemAny.(map[string]any)
		if !ok {
			continue
		}
		if _, isMeta := item["metainfo"]; isMeta {
			continue
		}
		if table, ok := item["table"]; ok {
			tables = append(tables, table)
		}
	}
	return tables, nil
}

type GetRulesArgs struct {
	Family *string `statekit:"name=family"`
}

type getRulesFunc struct{ linuxOnly }

func (getRulesFunc) Name() string { return "nftables.get_rules" }
func (getRulesFunc) Args() any    { return GetRulesArgs{} }

func (getRulesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRulesArgs)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	tablesRaw, err := listTablesFunc{}.Execute(ctx, rt, &ListTablesArgs{Family: &family})
	if err != nil {
		return nil, err
	}
	rules := []any{}
	for _, tableRaw := range tablesRaw.([]any) {
		table, _ := tableRaw.(map[string]any)
		name, _ := table["name"].(string)
		out := runText(ctx, rt, []string{
			nftBin(), "--numeric", "--numeric", "--numeric",
			"list", "table", familyOf(family), name,
		})
		rules = append(rules, out)
	}
	return rules, nil
}

type GetRulesJSONArgs struct {
	Family *string `statekit:"name=family"`
}

type getRulesJSONFunc struct{ linuxOnly }

func (getRulesJSONFunc) Name() string { return "nftables.get_rules_json" }
func (getRulesJSONFunc) Args() any    { return GetRulesJSONArgs{} }
func (getRulesJSONFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRulesJSONArgs)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	out := runText(ctx, rt, []string{
		nftBin(), "--numeric", "--numeric", "--numeric", "--json",
		"list", "ruleset", familyOf(family),
	})
	if out == "" {
		return []any{}, nil
	}
	root, err := decodeNftJSON(out)
	if err != nil {
		return []any{}, nil
	}
	return root, nil
}

type SaveArgs struct {
	Filename *string `statekit:"name=filename"`
	Family   *string `statekit:"name=family"`
}

type saveFunc struct{ linuxOnly }

func (saveFunc) Name() string { return "nftables.save" }
func (saveFunc) Args() any    { return SaveArgs{} }

// Execute dumps every unique family's rules into one file.
func (saveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SaveArgs)
	filename := ""
	if a.Filename != nil {
		filename = *a.Filename
	}
	if path, ok := confPath(rt); ok && filename == "" {
		filename = path
	}

	seen := map[string]bool{}
	var uniqueFamilies []string
	for _, canonical := range nftablesFamilies {
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		uniqueFamilies = append(uniqueFamilies, canonical)
	}

	rules := "#! nft -f\n"
	for _, canonical := range uniqueFamilies {
		display := reverseFamily(canonical)
		out, err := getRulesFunc{}.Execute(ctx, rt, &GetRulesArgs{Family: &display})
		if err != nil {
			return nil, err
		}
		list := out.([]any)
		if len(list) > 0 {
			rules += "\n"
		}
		for _, entry := range list {
			rules += entry.(string) + "\n"
		}
	}
	rules += "\n"

	if directoryExists(ctx, rt, filename) {
		filename = filename + "/salt-all-in-one.nft"
	}
	if err := rt.FS.WriteFile(filename, []byte(rules), 0o644); err != nil {
		return nil, fmt.Errorf("Problem writing to configuration file: %v", err)
	}
	return rules, nil
}

// reverseFamily mirrors the double-inverted family dictionary: each
// canonical family maps back to its first spelling.
func reverseFamily(canonical string) string {
	for spelling, canonical2 := range nftablesFamilies {
		if canonical2 == canonical && (spelling == "ipv4" || spelling == "ipv6" ||
			spelling == "inet" || spelling == "arp" || spelling == "bridge" ||
			spelling == "netdev") {
			return spelling
		}
	}
	return canonical
}

func processCommand(argv []string) process.Command {
	return process.Command{Name: argv[0], Args: append([]string{}, argv[1:]...)}
}
