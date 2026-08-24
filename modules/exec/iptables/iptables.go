package iptables

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type FamilyArgs struct {
	Family *string `statekit:"name=family"`
}

type versionFunc struct{ linuxOnly }

func (versionFunc) Name() string { return "iptables.version" }
func (versionFunc) Args() any    { return FamilyArgs{} }

// Execute returns the version token from "{cmd} --version".
func (versionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FamilyArgs)
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	out, err := runStdout(ctx, rt, fmt.Sprintf("%s --version", iptablesPath(family)))
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected iptables version output")
	}
	return fields[1], nil
}

// --- policies -------------------------------------------------------------

func policyFromParsed(rules map[string]any, table, chain string) any {
	tableMap, ok := rules[table].(map[string]any)
	if !ok {
		return nil
	}
	chainMap, ok := tableMap[chain].(map[string]any)
	if !ok {
		return nil
	}
	if policy, ok := chainMap["policy"]; ok {
		return policy
	}
	return nil
}

type GetSavedPolicyArgs struct {
	Table    *string `statekit:"name=table"`
	Chain    *string `statekit:"name=chain"`
	ConfFile *string `statekit:"name=conf_file"`
	Family   *string `statekit:"name=family"`
}

type getSavedPolicyFunc struct{ linuxOnly }

func (getSavedPolicyFunc) Name() string { return "iptables.get_saved_policy" }
func (getSavedPolicyFunc) Args() any    { return GetSavedPolicyArgs{} }
func (getSavedPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetSavedPolicyArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	confFile := ""
	if a.ConfFile != nil {
		confFile = *a.ConfFile
	}
	rules, err := parseConf(ctx, rt, confFile, false, family)
	if err != nil {
		return nil, err
	}
	return policyFromParsed(rules, table, *a.Chain), nil
}

type GetPolicyArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type getPolicyFunc struct{ linuxOnly }

func (getPolicyFunc) Name() string { return "iptables.get_policy" }
func (getPolicyFunc) Args() any    { return GetPolicyArgs{} }
func (getPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetPolicyArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	rules, err := parseConf(ctx, rt, "", true, family)
	if err != nil {
		return nil, err
	}
	return policyFromParsed(rules, table, *a.Chain), nil
}

type GetRulesArgs struct {
	Family *string `statekit:"name=family"`
}

type getRulesFunc struct{ linuxOnly }

func (getRulesFunc) Name() string { return "iptables.get_rules" }
func (getRulesFunc) Args() any    { return GetRulesArgs{} }
func (getRulesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRulesArgs)
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	return parseConf(ctx, rt, "", true, family)
}

type GetSavedRulesArgs struct {
	ConfFile *string `statekit:"name=conf_file"`
	Family   *string `statekit:"name=family"`
}

type getSavedRulesFunc struct{ linuxOnly }

func (getSavedRulesFunc) Name() string { return "iptables.get_saved_rules" }
func (getSavedRulesFunc) Args() any    { return GetSavedRulesArgs{} }
func (getSavedRulesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetSavedRulesArgs)
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	confFile := ""
	if a.ConfFile != nil {
		confFile = *a.ConfFile
	}
	return parseConf(ctx, rt, confFile, false, family)
}

// --- mutating commands -------------------------------------------------------

func waitFlag(ctx context.Context, rt *runtime.Runtime, family string) string {
	if hasOptionFn(ctx, rt, "--wait", family) {
		return "--wait"
	}
	return ""
}

type SetPolicyArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Policy *string `statekit:"name=policy"`
	Family *string `statekit:"name=family"`
}

type setPolicyFunc struct{ linuxOnly }

func (setPolicyFunc) Name() string { return "iptables.set_policy" }
func (setPolicyFunc) Args() any    { return SetPolicyArgs{} }

// Execute sets the chain policy; stderr text is returned verbatim.
func (setPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetPolicyArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	if a.Policy == nil || *a.Policy == "" {
		return "Error: Policy needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	cmd := fmt.Sprintf("%s %s -t %s -P %s %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, *a.Chain, *a.Policy)
	return runStderr(ctx, rt, cmd)
}

type SaveArgs struct {
	Filename *string `statekit:"name=filename"`
	Family   *string `statekit:"name=family"`
}

type saveFunc struct{ linuxOnly }

func (saveFunc) Name() string { return "iptables.save" }
func (saveFunc) Args() any    { return SaveArgs{} }

// Execute dumps the in-memory rules through "{cmd}-save" and persists them
// via the file.write delegate.
func (saveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SaveArgs)
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	filename := ""
	if a.Filename != nil {
		filename = *a.Filename
	}
	confPathValue, cerr := confPath(rt, family)
	if cerr != nil {
		return nil, cerr
	}
	if confPathValue != "" && filename == "" {
		filename = confPathValue
	}

	parentDirOf := filename
	if idx := strings.LastIndexByte(filename, '/'); idx > 0 {
		parentDirOf = filename[:idx]
	}
	if err := rt.FS.MkdirAll(parentDirOf, 0o755); err != nil {
		return nil, err
	}

	ipt, err := runStdout(ctx, rt, fmt.Sprintf("%s-save", iptablesPath(family)))
	if err != nil {
		return nil, err
	}
	if filters := confSaveFilters(ctx, rt); len(filters) > 0 {
		ipt = regexIptablesSave(ipt, filters)
	}
	if !lookup(ctx, rt, "file.write") {
		return nil, &runtime.UnsupportedError{Kind: "function", Name: "file.write"}
	}
	payload := struct {
		Path    string
		Content string
	}{filename, ipt}
	resRaw, ferr := rt.Exec.Call(ctx, rt, "file.write", &payload)
	if ferr != nil {
		return nil, ferr
	}
	return resRaw, nil
}

// runProbe executes a command and reports whether it exited zero,
// mirroring the retcode read of check()'s --check path. Hookable for
// hermetic suites.
var runProbe = func(rt *runtime.Runtime, cmd string) bool {
	res := rt.Runner.Run(ctx0(), probeCommand(cmd))
	return res.ExitCode == 0 && res.Err == nil
}

type CheckArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Rule   *string `statekit:"name=rule"`
	Family *string `statekit:"name=family"`
}

type checkFunc struct{ linuxOnly }

func (checkFunc) Name() string { return "iptables.check" }
func (checkFunc) Args() any    { return CheckArgs{} }

// Execute checks rule existence; without --check support it round-trips a
// temporary chain like upstream's fallback.
func (checkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	if a.Rule == nil || *a.Rule == "" {
		return "Error: Rule needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	iptCmd := iptablesPath(family)

	if hasOptionFn(ctx, rt, "--check", family) {
		cmd := fmt.Sprintf("%s -t %s -C %s %s", iptCmd, table, *a.Chain, *a.Rule)
		return runProbe(rt, cmd), nil
	}

	chainName := getNodeHex()
	runIgnore(ctx, rt, fmt.Sprintf("%s -t %s -N %s", iptCmd, table, chainName))
	runIgnore(ctx, rt, fmt.Sprintf("%s -t %s -A %s %s", iptCmd, table, chainName, *a.Rule))
	out, oerr := runStdout(ctx, rt, iptCmd+"-save")
	runIgnore(ctx, rt, fmt.Sprintf("%s -t %s -F %s", iptCmd, table, chainName))
	runIgnore(ctx, rt, fmt.Sprintf("%s -t %s -X %s", iptCmd, table, chainName))
	if oerr != nil {
		return false, nil
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "-A "+chainName) {
			replaced := strings.ReplaceAll(line, chainName, *a.Chain)
			for _, candidate := range lines {
				if candidate == replaced {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

type CheckChainArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type checkChainFunc struct{ linuxOnly }

func (checkChainFunc) Name() string { return "iptables.check_chain" }
func (checkChainFunc) Args() any    { return CheckChainArgs{} }

func (checkChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckChainArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	out, err := runStdout(ctx, rt, fmt.Sprintf("%s-save -t %s", iptablesPath(family), table))
	if err != nil {
		return false, nil
	}
	return strings.Contains(out, fmt.Sprintf(":%s ", *a.Chain)), nil
}

type NewChainArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type newChainFunc struct{ linuxOnly }

func (newChainFunc) Name() string { return "iptables.new_chain" }
func (newChainFunc) Args() any    { return NewChainArgs{} }

func (newChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NewChainArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	cmd := fmt.Sprintf("%s %s -t %s -N %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, *a.Chain)
	out, err := runStderr(ctx, rt, cmd)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return true, nil
	}
	return out, nil
}

type DeleteChainArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type deleteChainFunc struct{ linuxOnly }

func (deleteChainFunc) Name() string { return "iptables.delete_chain" }
func (deleteChainFunc) Args() any    { return DeleteChainArgs{} }

func (deleteChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteChainArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	cmd := fmt.Sprintf("%s %s -t %s -X %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, *a.Chain)
	out, err := runStderr(ctx, rt, cmd)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return true, nil
	}
	return out, nil
}

type AppendArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Rule   *string `statekit:"name=rule"`
	Family *string `statekit:"name=family"`
}

type appendFunc struct{ linuxOnly }

func (appendFunc) Name() string { return "iptables.append" }
func (appendFunc) Args() any    { return AppendArgs{} }

// Execute appends a rule unless it already exists (False then).
func (appendFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AppendArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	if a.Rule == nil || *a.Rule == "" {
		return "Error: Rule needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	existing, cerr := checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: a.Table, Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if cerr != nil {
		return nil, cerr
	}
	if b, ok := existing.(bool); ok && b {
		return false, nil
	}
	cmd := fmt.Sprintf("%s %s -t %s -A %s %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, *a.Chain, *a.Rule)
	out, err := runStderr(ctx, rt, cmd)
	if err != nil {
		return nil, err
	}
	return out == "", nil
}

type InsertArgs struct {
	Table    *string `statekit:"name=table"`
	Chain    *string `statekit:"name=chain"`
	Position *int64  `statekit:"name=position"`
	Rule     *string `statekit:"name=rule"`
	Family   *string `statekit:"name=family"`
}

type insertFunc struct{ linuxOnly }

func (insertFunc) Name() string { return "iptables.insert" }
func (insertFunc) Args() any    { return InsertArgs{} }

func (insertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InsertArgs)
	if a.Chain == nil || *a.Chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	if a.Position == nil {
		return "Error: Position needs to be specified or use append (-A)", nil
	}
	if a.Rule == nil || *a.Rule == "" {
		return "Error: Rule needs to be specified", nil
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	position := *a.Position
	if position < 0 {
		rules, rerr := parseConf(ctx, rt, "", true, family)
		if rerr != nil {
			return nil, rerr
		}
		tableMap, _ := rules[table].(map[string]any)
		chainMap, _ := tableMap[*a.Chain].(map[string]any)
		var size int
		if chainMap != nil {
			if ruleList, ok := chainMap["rules"].([]any); ok {
				size = len(ruleList)
			}
		}
		position = int64(size+int(position)) + 1
		if position == 0 {
			position = 1
		}
	}
	posStr := strconv.FormatInt(position, 10)

	existing, cerr := checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: a.Table, Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if cerr != nil {
		return nil, cerr
	}
	if b, ok := existing.(bool); ok && b {
		return false, nil
	}
	cmd := fmt.Sprintf("%s %s -t %s -I %s %s %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, *a.Chain, posStr, *a.Rule)
	return runStderr(ctx, rt, cmd)
}

type DeleteArgs struct {
	Table    *string `statekit:"name=table"`
	Chain    *string `statekit:"name=chain"`
	Position *string `statekit:"name=position"`
	Rule     *string `statekit:"name=rule"`
	Family   *string `statekit:"name=family"`
}

type deleteFunc struct{ linuxOnly }

func (deleteFunc) Name() string { return "iptables.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }

func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	if a.Position != nil && *a.Position != "" && a.Rule != nil && *a.Rule != "" {
		return "Error: Only specify a position or a rule, not both", nil
	}
	target := ""
	if a.Position != nil {
		target = *a.Position
	} else if a.Rule != nil {
		target = *a.Rule
	}
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	chain := ""
	if a.Chain != nil {
		chain = *a.Chain
	}
	cmd := fmt.Sprintf("%s %s -t %s -D %s %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, chain, target)
	return runStderr(ctx, rt, cmd)
}

type FlushArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  string  `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type flushFunc struct{ linuxOnly }

func (flushFunc) Name() string { return "iptables.flush" }
func (flushFunc) Args() any    { return FlushArgs{} }

func (flushFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FlushArgs)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}
	cmd := fmt.Sprintf("%s %s -t %s -F %s",
		iptablesPath(family), waitFlag(ctx, rt, family), table, a.Chain)
	return runStderr(ctx, rt, cmd)
}

// Register installs all iptables-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		buildRuleFunc{},
		getSavedRulesFunc{},
		getRulesFunc{},
		getSavedPolicyFunc{},
		getPolicyFunc{},
		setPolicyFunc{},
		saveFunc{},
		checkFunc{},
		checkChainFunc{},
		newChainFunc{},
		deleteChainFunc{},
		appendFunc{},
		insertFunc{},
		deleteFunc{},
		flushFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
