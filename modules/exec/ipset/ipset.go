// Package ipset implements Salt-compatible ipset management through the
// ipset binary invoked as argv (upstream passes lists with
// python_shell=False, so no shell is involved on either side).
//
// Reference: saltstack/salt/modules/ipset.py @ pinned revision.
package ipset

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// ipsetBin mirrors salt.utils.path.which("ipset"); injectable for suites.
var ipsetBin = func() string { return lookPath("ipset") }

func lookPath(exe string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return dir + "/" + exe
		}
	}
	return ""
}

// runText runs ipset argv through the central Runner with ignore-retcode
// semantics, mirroring __salt__["cmd.run"](<list>, python_shell=False).
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

// runAllText is the retcode-aware variant backing _find_set_* and test.
func runAllText(ctx context.Context, rt *runtime.Runtime, argv []string) (int, string) {
	res := rt.Runner.Run(ctx, process.Command{
		Name: argv[0],
		Args: append([]string{}, argv[1:]...),
	})
	if res.Err != nil {
		return -1, ""
	}
	return res.ExitCode, string(res.Stdout)
}

var ipsetFamilies = map[string]string{
	"ipv4": "inet",
	"ip4":  "inet",
	"ipv6": "inet6",
	"ip6":  "inet6",
}

var ipsetSetTypes = map[string]bool{
	"bitmap:ip":         true,
	"bitmap:ip,mac":     true,
	"bitmap:port":       true,
	"hash:ip":           true,
	"hash:mac":          true,
	"hash:ip,port":      true,
	"hash:ip,port,ip":   true,
	"hash:ip,port,net":  true,
	"hash:net":          true,
	"hash:net,net":      true,
	"hash:net,iface":    true,
	"hash:net,port":     true,
	"hash:net,port,net": true,
	"hash:ip,mark":      true,
	"list:set":          true,
}

// createOptions mirrors _CREATE_OPTIONS; iteration order matches
// upstream's set() nondeterminism.
var createOptions = map[string]map[string]bool{}

// createOptionsRequired mirrors _CREATE_OPTIONS_REQUIRED (ordered).
var createOptionsRequired = map[string][]string{
	"bitmap:ip": {"range"}, "bitmap:ip,mac": {"range"}, "bitmap:port": {"range"},
}

// createOptionsWithoutValue mirrors _CREATE_OPTIONS_WITHOUT_VALUE.
var createOptionsWithoutValue = map[string]bool{"comment": true, "counters": true, "skbinfo": true}

// addOptions mirrors _ADD_OPTIONS.
var addOptions = map[string]map[string]bool{}

func init() {
	full := func(items ...string) map[string]bool {
		m := map[string]bool{}
		for _, item := range items {
			m[item] = true
		}
		return m
	}
	createOptions["bitmap:ip"] = full("range", "netmask", "timeout", "counters", "comment", "skbinfo")
	createOptions["bitmap:ip,mac"] = full("range", "timeout", "counters", "comment", "skbinfo")
	createOptions["bitmap:port"] = full("range", "timeout", "counters", "comment", "skbinfo")
	hashLike := full("family", "hashsize", "maxelem", "netmask", "timeout", "counters", "comment", "skbinfo")
	for _, t := range []string{"hash:ip", "hash:net", "hash:net,net", "hash:net,port",
		"hash:net,port,net", "hash:ip,port,ip", "hash:ip,port,net", "hash:ip,port",
		"hash:net,iface"} {
		createOptions[t] = hashLike
	}
	createOptions["hash:mac"] = full("hashsize", "maxelem", "timeout", "counters", "comment", "skbinfo")
	createOptions["hash:ip,mark"] = full("family", "markmask", "hashsize", "maxelem",
		"timeout", "counters", "comment", "skbinfo")
	createOptions["list:set"] = full("size", "timeout", "counters", "comment")

	addNoNomatch := full("timeout", "packets", "bytes", "skbmark", "skbprio", "skbqueue")
	addWithNomatch := full("timeout", "nomatch", "packets", "bytes", "skbmark", "skbprio", "skbqueue")
	createKeys := []string{"bitmap:ip", "bitmap:ip,mac", "bitmap:port"}
	for _, t := range createKeys[:2] {
		addOptions[t] = addNoNomatch
	}
	addOptions["bitmap:port"] = full("timeout", "packets", "bytes", "skbmark", "skbprio")
	addOptions["hash:ip"] = addNoNomatch
	addOptions["hash:mac"] = addNoNomatch
	for _, t := range []string{"hash:net", "hash:net,net", "hash:net,port",
		"hash:net,port,net", "hash:ip,port,net", "hash:ip,port", "hash:net,iface"} {
		addOptions[t] = addWithNomatch
	}
	addOptions["hash:ip,port,ip"] = addNoNomatch
	addOptions["hash:ip,mark"] = addNoNomatch
	addOptions["list:set"] = addNoNomatch
}

type VersionArgs struct{}

type versionFunc struct{ linuxOnly }

func (versionFunc) Name() string { return "ipset.version" }
func (versionFunc) Args() any    { return VersionArgs{} }

func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	out := runText(ctx, rt, []string{ipsetBin(), "--version"})
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected ipset version output")
	}
	return fields[1], nil
}

// NewSetArgs mirrors new_set's signature; kwargs carry the create options.
type NewSetArgs struct {
	Name    *string        `statekit:"name=name"`
	SetType *string        `statekit:"name=set_type"`
	Family  *string        `statekit:"name=family"`
	Comment bool           `statekit:"name=comment"`
	Kwargs  map[string]any `statekit:"name=kwargs"`
}

type newSetFunc struct{ linuxOnly }

func (newSetFunc) Name() string { return "ipset.new_set" }
func (newSetFunc) Args() any    { return NewSetArgs{} }

func (newSetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NewSetArgs)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	ipsetFamily, ok := ipsetFamilies[family]
	if !ok {
		return fmt.Sprintf("Error: %s is not a valid family", family), nil
	}
	if a.Name == nil || *a.Name == "" {
		return "Error: Set Name needs to be specified", nil
	}
	name := *a.Name
	setType := ""
	if a.SetType != nil {
		setType = *a.SetType
	}
	if setType == "" {
		return "Error: Set Type needs to be specified", nil
	}
	if !ipsetSetTypes[setType] {
		return "Error: Set Type is invalid", nil
	}
	for _, required := range createOptionsRequired[setType] {
		if _, has := a.Kwargs[required]; !has {
			return fmt.Sprintf("Error: %s is a required argument", required), nil
		}
	}

	argv := []string{ipsetBin(), "create", name, setType}
	options := createOptions[setType]
	for item := range options {
		val, has := a.Kwargs[item]
		if !has {
			continue
		}
		if createOptionsWithoutValue[item] {
			argv = append(argv, item)
		} else {
			argv = append(argv, item, fmt.Sprintf("%v", val))
		}
	}
	// Family only valid for certain set types.
	if options["family"] {
		argv = append(argv, "family", ipsetFamily)
	}
	if a.Comment {
		argv = append(argv, "comment")
	}
	out := runText(ctx, rt, argv)
	if out == "" {
		return true, nil
	}
	return out, nil
}

type DeleteSetArgs struct {
	Name   *string `statekit:"name=name"`
	Family *string `statekit:"name=family"`
}

type deleteSetFunc struct{ linuxOnly }

func (deleteSetFunc) Name() string { return "ipset.delete_set" }
func (deleteSetFunc) Args() any    { return DeleteSetArgs{} }

func (deleteSetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteSetArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	out := runText(ctx, rt, []string{ipsetBin(), "destroy", *a.Name})
	if out == "" {
		return true, nil
	}
	return out, nil
}

type RenameSetArgs struct {
	Name   *string `statekit:"name=name"`
	NewSet *string `statekit:"name=new_set"`
	Family *string `statekit:"name=family"`
}

type renameSetFunc struct{ linuxOnly }

func (renameSetFunc) Name() string { return "ipset.rename_set" }
func (renameSetFunc) Args() any    { return RenameSetArgs{} }

func (renameSetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RenameSetArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	if a.NewSet == nil || *a.NewSet == "" {
		return "Error: New name for set needs to be specified", nil
	}
	if findSetType(ctx, rt, *a.Name) == "" {
		return "Error: Set does not exist", nil
	}
	if findSetType(ctx, rt, *a.NewSet) != "" {
		return "Error: New Set already exists", nil
	}
	out := runText(ctx, rt, []string{ipsetBin(), "rename", *a.Name, *a.NewSet})
	if out == "" {
		return true, nil
	}
	return out, nil
}

type ListSetsArgs struct {
	Family *string `statekit:"name=family"`
}

type listSetsFunc struct{ linuxOnly }

func (listSetsFunc) Name() string { return "ipset.list_sets" }
func (listSetsFunc) Args() any    { return ListSetsArgs{} }

// Execute parses `ipset list -t` blocks into the bucket list upstream
// builds (leading empty dict included).
func (listSetsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	out := runText(ctx, rt, []string{ipsetBin(), "list", "-t"})
	count := 0
	sets := []any{map[string]any{}}
	for _, item := range strings.Split(out, "\n") {
		if item == "" {
			count++
			sets = append(sets, map[string]any{})
			continue
		}
		idx := strings.Index(item, ":")
		if idx < 0 {
			continue
		}
		key := item[:idx]
		value := ""
		if idx+1 < len(item) {
			value = item[idx+2:]
		} else if idx+1 == len(item) {
			value = ""
		}
		sets[count].(map[string]any)[key] = value
	}
	return sets, nil
}

type CheckSetArgs struct {
	Name   *string `statekit:"name=name"`
	Family *string `statekit:"name=family"`
}

type checkSetFunc struct{ linuxOnly }

func (checkSetFunc) Name() string { return "ipset.check_set" }
func (checkSetFunc) Args() any    { return CheckSetArgs{} }

func (checkSetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckSetArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	info := findSetInfo(ctx, rt, *a.Name)
	if info == nil {
		return false, nil
	}
	return true, nil
}

// --- set info / members -------------------------------------------------

func findSetInfo(ctx context.Context, rt *runtime.Runtime, name string) map[string]any {
	retcode, stdout := runAllText(ctx, rt, []string{ipsetBin(), "list", "-t", name})
	if retcode > 0 {
		return nil
	}
	setinfo := map[string]any{}
	for _, item := range strings.Split(stdout, "\n") {
		idx := strings.Index(item, ":")
		if idx < 0 {
			continue
		}
		value := ""
		if idx+2 <= len(item) {
			value = item[idx+2:]
		}
		setinfo[item[:idx]] = value
	}
	return setinfo
}

func findSetType(ctx context.Context, rt *runtime.Runtime, name string) string {
	info := findSetInfo(ctx, rt, name)
	if info == nil {
		return ""
	}
	t, _ := info["Type"].(string)
	return t
}

func findSetMembers(ctx context.Context, rt *runtime.Runtime, name string) []string {
	retcode, stdout := runAllText(ctx, rt, []string{ipsetBin(), "list", name})
	if retcode > 0 {
		return nil
	}
	var members []string
	started := false
	for _, line := range strings.Split(stdout, "\n") {
		if started {
			members = append(members, line)
		}
		if strings.Contains(line, "Members:") {
			started = true
		}
	}
	return members
}

// --- entries ---------------------------------------------------------------

type AddArgs struct {
	Name   *string        `statekit:"name=name"`
	Entry  *string        `statekit:"name=entry"`
	Family *string        `statekit:"name=family"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}

type addFunc struct{ linuxOnly }

func (addFunc) Name() string { return "ipset.add" }
func (addFunc) Args() any    { return AddArgs{} }

func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	if a.Entry == nil || *a.Entry == "" {
		return "Error: Entry needs to be specified", nil
	}
	name, entry := *a.Name, *a.Entry

	setInfo := findSetInfo(ctx, rt, name)
	if setInfo == nil {
		return fmt.Sprintf("Error: Set %s does not exist", name), nil
	}
	setType, _ := setInfo["Type"].(string)
	header, _ := setInfo["Header"].(string)

	cmd := []string{ipsetBin(), "add", "-exist", name}
	cmd = append(cmd, strings.Fields(entry)...)

	hasKwarg := func(keys ...string) bool {
		for _, key := range keys {
			if _, ok := a.Kwargs[key]; ok {
				return true
			}
		}
		return false
	}
	if _, ok := a.Kwargs["timeout"]; ok && !strings.Contains(header, "timeout") {
		return fmt.Sprintf("Error: Set %s not created with timeout support", name), nil
	}
	if hasKwarg("packets", "bytes") && !strings.Contains(header, "counters") {
		return fmt.Sprintf("Error: Set %s not created with counters support", name), nil
	}
	if _, ok := a.Kwargs["comment"]; ok {
		if !strings.Contains(header, "comment") {
			return fmt.Sprintf("Error: Set %s not created with comment support", name), nil
		}
		if !strings.Contains(entry, "comment") {
			comment, _ := a.Kwargs["comment"]
			cmd = append(cmd, "comment", fmt.Sprintf("%v", comment))
		}
	}
	if hasKwarg("skbmark", "skbprio", "skbqueue") && !strings.Contains(header, "skbinfo") {
		return fmt.Sprintf("Error: Set %s not created with skbinfo support", name), nil
	}

	options := addOptions[setType]
	for item := range options {
		val, ok := a.Kwargs[item]
		if !ok {
			continue
		}
		cmd = append(cmd, item, fmt.Sprintf("%v", val))
	}

	currentMembers := findSetMembers(ctx, rt, name)
	for _, member := range currentMembers {
		if member == entry {
			return fmt.Sprintf("Warn: Entry %s already exists in set %s", entry, name), nil
		}
	}

	out := runText(ctx, rt, cmd)
	if out == "" {
		return "Success", nil
	}
	return fmt.Sprintf("Error: %s", out), nil
}

type DeleteEntryArgs struct {
	Name   *string `statekit:"name=name"`
	Entry  *string `statekit:"name=entry"`
	Family *string `statekit:"name=family"`
}

type deleteEntryFunc struct{ linuxOnly }

func (deleteEntryFunc) Name() string { return "ipset.delete" }
func (deleteEntryFunc) Args() any    { return DeleteEntryArgs{} }

func (deleteEntryFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteEntryArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	if a.Entry == nil || *a.Entry == "" {
		return "Error: Entry needs to be specified", nil
	}
	name, entry := *a.Name, *a.Entry

	if findSetType(ctx, rt, name) == "" {
		return fmt.Sprintf("Error: Set %s does not exist", name), nil
	}
	out := runText(ctx, rt, []string{ipsetBin(), "del", name, entry})
	if out == "" {
		return "Success", nil
	}
	return fmt.Sprintf("Error: %s", out), nil
}

type CheckArgs struct {
	Name   *string `statekit:"name=name"`
	Entry  *string `statekit:"name=entry"`
	Family *string `statekit:"name=family"`
}

type checkFunc struct{ linuxOnly }

func (checkFunc) Name() string { return "ipset.check" }
func (checkFunc) Args() any    { return CheckArgs{} }

// Execute checks entry membership with the parsed-part containment rules.
func (checkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	if a.Entry == nil || *a.Entry == "" {
		return "Error: Entry needs to be specified", nil
	}
	name, entry := *a.Name, *a.Entry

	setType := findSetType(ctx, rt, name)
	if setType == "" {
		return fmt.Sprintf("Error: Set %s does not exist", name), nil
	}

	currentMembers := parseMembers(setType, findSetMembers(ctx, rt, name))
	if len(currentMembers) == 0 {
		return false, nil
	}
	entries := []any{parseMember(setType, entry)}

	for _, currentMember := range currentMembers {
		for _, candidate := range entries {
			if memberContains(toSlice(currentMember), toSlice(candidate)) {
				return true, nil
			}
		}
	}
	return false, nil
}

type TestArgs struct {
	Name   *string `statekit:"name=name"`
	Entry  *string `statekit:"name=entry"`
	Family *string `statekit:"name=family"`
}

type testFunc struct{ linuxOnly }

func (testFunc) Name() string { return "ipset.test" }
func (testFunc) Args() any    { return TestArgs{} }

func (testFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*TestArgs)
	if a.Name == nil || *a.Name == "" {
		return "Error: Set needs to be specified", nil
	}
	if a.Entry == nil || *a.Entry == "" {
		return "Error: Entry needs to be specified", nil
	}
	name, entry := *a.Name, *a.Entry
	if findSetType(ctx, rt, name) == "" {
		return fmt.Sprintf("Error: Set %s does not exist", name), nil
	}
	retcode, _ := runAllText(ctx, rt, []string{ipsetBin(), "test", name, entry})
	if retcode > 0 {
		return false, nil
	}
	return true, nil
}

type FlushArgs struct {
	Name   *string `statekit:"name=name"`
	Family *string `statekit:"name=family"`
}

type flushFunc struct{ linuxOnly }

func (flushFunc) Name() string { return "ipset.flush" }
func (flushFunc) Args() any    { return FlushArgs{} }

func (flushFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FlushArgs)
	argv := []string{ipsetBin(), "flush"}
	if a.Name != nil && *a.Name != "" {
		argv = append(argv, *a.Name)
	}
	out := runText(ctx, rt, argv)
	return out == "", nil
}

// Register installs all ipset-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		newSetFunc{},
		deleteSetFunc{},
		renameSetFunc{},
		listSetsFunc{},
		checkSetFunc{},
		addFunc{},
		deleteEntryFunc{},
		checkFunc{},
		testFunc{},
		flushFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
