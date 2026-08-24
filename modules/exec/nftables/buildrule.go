package nftables

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// stateInternalKeywords mirrors salt.state.STATE_INTERNAL_KEYWORDS.
var stateInternalKeywords = []string{
	"onchanges", "onchanges_any", "onfail", "onfail_any", "onfail_all",
	"onfail_stop", "prereq", "prerequired", "watch", "watch_any", "require",
	"require_any", "listen",
	"onchanges_in", "onfail_in", "prereq_in", "watch_in", "require_in",
	"listen_in",
	"fun", "state", "check_cmd", "cmd_opts_exclude", "failhard", "onlyif",
	"unless", "creates", "retry", "order", "parallel", "prereq_in",
	"prerequired", "reload_modules", "reload_grains", "reload_pillar",
	"runas", "runas_password", "fire_event", "saltenv", "umask", "use",
	"use_in", "__env__", "__sls__", "__id__", "__orchestration_jid__",
	"__pub_user", "__pub_arg", "__pub_jid", "__pub_fun", "__pub_tgt",
	"__pub_ret", "__pub_pid", "__pub_tgt_type", "__prereq__",
	"__prerequired__", "__umask__",
}

// BuildRuleArgs mirrors build_rule's signature. Upstream tests pass
// full="True"/"true" strings, so the field keeps that shape.
type BuildRuleArgs struct {
	Table    *string        `statekit:"name=table"`
	Chain    *string        `statekit:"name=chain"`
	Command  *string        `statekit:"name=command"`
	Position string         `statekit:"name=position"`
	Full     *string        `statekit:"name=full"`
	Family   *string        `statekit:"name=family"`
	Kwargs   map[string]any `statekit:"name=kwargs"`
}

type buildRuleFunc struct{ linuxOnly }

func (buildRuleFunc) Name() string { return "nftables.build_rule" }
func (buildRuleFunc) Args() any    { return BuildRuleArgs{} }

func (buildRuleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BuildRuleArgs)
	ret := map[string]any{"comment": "", "rule": "", "result": false}
	setComment := func(comment, rule string, result bool) {
		ret["comment"] = comment
		if rule != "" || true {
			ret["rule"] = rule
		}
		ret["result"] = result
	}

	kwargs := map[string]any{}
	for k, v := range a.Kwargs {
		kwargs[k] = v
	}
	if v, ok := kwargs["target"]; ok {
		kwargs["jump"] = v
		delete(kwargs, "target")
	}
	for _, ignore := range stateInternalKeywords {
		delete(kwargs, ignore)
	}
	delete(kwargs, "chain")
	delete(kwargs, "save")
	delete(kwargs, "table")

	rule := ""
	proto := ""

	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	nftFamily, ok := nftablesFamilies[family]
	if !ok {
		return nil, fmt.Errorf("invalid family %q", family)
	}

	if v, ok := kwargs["if"]; ok {
		rule += fmt.Sprintf("meta iifname %v ", v)
		delete(kwargs, "if")
	}
	if v, ok := kwargs["of"]; ok {
		rule += fmt.Sprintf("meta oifname %v ", v)
		delete(kwargs, "of")
	}
	if v, ok := kwargs["proto"]; ok {
		proto = fmt.Sprintf("%v", v)
	}
	delete(kwargs, "state")
	if v, ok := kwargs["connstate"]; ok {
		rule += fmt.Sprintf("ct state { %v } ", v)
		delete(kwargs, "connstate")
	}
	if v, ok := kwargs["icmp-type"]; ok {
		rule += fmt.Sprintf("icmp type { %v } ", v)
		delete(kwargs, "icmp-type")
	}
	if v, ok := kwargs["pkttype"]; ok {
		rule += fmt.Sprintf("meta pkttype { %v } ", v)
		delete(kwargs, "pkttype")
	}
	if _, ok := kwargs["counter"]; ok {
		rule += "counter "
		delete(kwargs, "counter")
	}
	if _, ok := kwargs["saddr"]; ok {
		rule += fmt.Sprintf("ip saddr %v ", kwargs["saddr"])
		delete(kwargs, "saddr")
	} else if v, ok := kwargs["source"]; ok {
		rule += fmt.Sprintf("ip saddr %v ", v)
		delete(kwargs, "source")
	}
	if _, ok := kwargs["daddr"]; ok {
		rule += fmt.Sprintf("ip daddr %v ", kwargs["daddr"])
		delete(kwargs, "daddr")
	} else if v, ok := kwargs["destination"]; ok {
		rule += fmt.Sprintf("ip daddr %v ", v)
		delete(kwargs, "destination")
	}

	formatPort := func(key string) {
		v, ok := kwargs[key]
		if !ok {
			return
		}
		s := fmt.Sprintf("%v", v)
		s = strings.ReplaceAll(s, ":", "-")
		rule += fmt.Sprintf("%s { %s } ", key, s)
		delete(kwargs, key)
	}
	formatPort("dport")
	formatPort("sport")

	reverseSortPorts := func(key string) bool {
		v, ok := kwargs[key]
		if !ok {
			return false
		}
		parts := strings.Split(fmt.Sprintf("%v", v), ",")
		nums := make([]int, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				nums = append(nums, 0)
				continue
			}
			nums = append(nums, n)
		}
		for i := 0; i < len(nums); i++ {
			for j := i + 1; j < len(nums); j++ {
				if nums[j] > nums[i] {
					nums[i], nums[j] = nums[j], nums[i]
				}
			}
		}
		strs := make([]string, 0, len(nums))
		for _, n := range nums {
			strs = append(strs, strconv.Itoa(n))
		}
		// nftables reverse sorts the ports high to low; the rendered
		// keyword is singular even for the plural kwargs.
		label := strings.TrimSuffix(key, "s")
		rule += fmt.Sprintf("%s { %s } ", label, strings.Join(strs, ", "))
		delete(kwargs, key)
		return true
	}
	reverseSortPorts("dports")
	reverseSortPorts("sports")

	var afterJump []string
	if v, ok := kwargs["jump"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("%v ", v))
		delete(kwargs, "jump")
	}
	if v, ok := kwargs["j"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("%v ", v))
		delete(kwargs, "j")
	}
	if _, ok := kwargs["redirect-to"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("redirect to %v ", kwargs["redirect-to"]))
		delete(kwargs, "redirect-to")
	} else if v, ok := kwargs["to-port"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("redirect to %v ", v))
		delete(kwargs, "to-port")
	}
	if v, ok := kwargs["to-ports"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("--to-ports %v ", v))
		delete(kwargs, "to-ports")
	}
	if v, ok := kwargs["to-source"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("%v ", v))
		delete(kwargs, "to-source")
	}
	if v, ok := kwargs["to-destination"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("%v ", v))
		delete(kwargs, "to-destination")
	}
	if v, ok := kwargs["reject-with"]; ok {
		afterJump = append(afterJump, fmt.Sprintf("reject with %v ", v))
		delete(kwargs, "reject-with")
	}
	for _, item := range afterJump {
		rule += item
	}

	rule = strings.TrimSpace(rule)
	rule = strings.ReplaceAll(rule, "dport", fmt.Sprintf("%s dport", proto))
	rule = strings.ReplaceAll(rule, "sport", fmt.Sprintf("%s sport", proto))

	ret["rule"] = rule

	fullTruthy := false
	if a.Full != nil {
		switch *a.Full {
		case "True", "true":
			fullTruthy = true
		}
	}

	if fullTruthy {
		table := ""
		if a.Table != nil {
			table = *a.Table
		}
		chain := ""
		if a.Chain != nil {
			chain = *a.Chain
		}
		command := ""
		if a.Command != nil {
			command = *a.Command
		}
		if table == "" {
			setComment("Table needs to be specified", "", false)
			return ret, nil
		}
		if chain == "" {
			setComment("Chain needs to be specified", "", false)
			return ret, nil
		}
		if command == "" {
			setComment("Command needs to be specified", "", false)
			return ret, nil
		}
		switch command {
		case "Insert", "insert", "INSERT":
			if a.Position != "" {
				ret["rule"] = fmt.Sprintf("%s insert rule %s %s %s position %s %s",
					nftBin(), nftFamily, table, chain, a.Position, rule)
			} else {
				ret["rule"] = fmt.Sprintf("%s insert rule %s %s %s %s",
					nftBin(), nftFamily, table, chain, rule)
			}
		default:
			ret["rule"] = fmt.Sprintf("%s %s rule %s %s %s %s",
				nftBin(), command, nftFamily, table, chain, rule)
		}
	}

	if ret["rule"] != "" {
		ret["comment"] = "Successfully built rule"
	}
	ret["result"] = true
	return ret, nil
}

// --- existence checks ------------------------------------------------------

func checkResult(comment string, result bool) map[string]any {
	return map[string]any{"comment": comment, "result": result}
}

func strArg(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type CheckTableArgs struct {
	Table  *string `statekit:"name=table"`
	Family *string `statekit:"name=family"`
}

type checkTableFunc struct{ linuxOnly }

func (checkTableFunc) Name() string { return "nftables.check_table" }
func (checkTableFunc) Args() any    { return CheckTableArgs{} }

func (checkTableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckTableArgs)
	table := strArg(a.Table)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if table == "" {
		return checkResult("Table needs to be specified", false), nil
	}
	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{nftBin(), "list", "tables", nftFamily})
	if strings.Contains(out, fmt.Sprintf("table %s %s", nftFamily, table)) {
		return checkResult(fmt.Sprintf("Table %s in family %s exists", table, family), true), nil
	}
	return checkResult(fmt.Sprintf("Table %s in family %s does not exist", table, family), false), nil
}

type CheckChainArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type checkChainFunc struct{ linuxOnly }

func (checkChainFunc) Name() string { return "nftables.check_chain" }
func (checkChainFunc) Args() any    { return CheckChainArgs{} }

func (checkChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckChainArgs)
	chain := strArg(a.Chain)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{nftBin(), "list", "table", nftFamily, table})
	if strings.Contains(out, fmt.Sprintf("chain %s {", chain)) {
		return checkResult(fmt.Sprintf("Chain %s in table %s in family %s exists", chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf("Chain %s in table %s in family %s does not exist", chain, table, family), false), nil
}

type CheckArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Rule   *string `statekit:"name=rule"`
	Family *string `statekit:"name=family"`
}

type checkFunc struct{ linuxOnly }

func (checkFunc) Name() string { return "nftables.check" }
func (checkFunc) Args() any    { return CheckArgs{} }

func (checkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckArgs)
	chain := strArg(a.Chain)
	rule := strArg(a.Rule)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	if rule == "" {
		return checkResult("Rule needs to be specified", false), nil
	}

	effTable := table
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: &effTable, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{
		Table: &effTable, Chain: a.Chain, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}

	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{
		nftBin(), "--handle", "--numeric", "--numeric", "--numeric",
		"list", "chain", nftFamily, table, chain,
	})
	searchRule := rule + " #"
	exists := strings.Contains(out, searchRule)
	if exists {
		return checkResult(fmt.Sprintf(
			"Rule %s in chain %s in table %s in family %s exists",
			rule, chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Rule %s in chain %s in table %s in family %s does not exist",
		rule, chain, table, family), false), nil
}

type GetRuleHandleArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Rule   *string `statekit:"name=rule"`
	Family *string `statekit:"name=family"`
}

type getRuleHandleFunc struct{ linuxOnly }

func (getRuleHandleFunc) Name() string { return "nftables.get_rule_handle" }
func (getRuleHandleFunc) Args() any    { return GetRuleHandleArgs{} }

func (getRuleHandleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetRuleHandleArgs)
	chain := strArg(a.Chain)
	rule := strArg(a.Rule)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	if rule == "" {
		return checkResult("Rule needs to be specified", false), nil
	}

	effTable := table
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: &effTable, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{
		Table: &effTable, Chain: a.Chain, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: &effTable, Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}

	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{
		nftBin(), "--numeric", "--numeric", "--numeric", "--handle",
		"list", "chain", nftFamily, table, chain,
	})
	handleRe := regexp.MustCompile(regexp.QuoteMeta(rule) + ` # handle (\d+)`)
	for _, r := range regexp.MustCompile(`\n+`).Split(out, -1) {
		if m := handleRe.FindStringSubmatch(r); m != nil {
			return map[string]any{"result": true, "handle": m[1]}, nil
		}
	}
	return checkResult(fmt.Sprintf("Could not find rule %s", rule), false), nil
}

// --- mutating commands -------------------------------------------------------

type NewTableArgs struct {
	Table  *string `statekit:"name=table"`
	Family *string `statekit:"name=family"`
}

type newTableFunc struct{ linuxOnly }

func (newTableFunc) Name() string { return "nftables.new_table" }
func (newTableFunc) Args() any    { return NewTableArgs{} }

func (newTableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NewTableArgs)
	table := strArg(a.Table)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if table == "" {
		return checkResult("Table needs to be specified", false), nil
	}
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: a.Table, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] == true {
		return res, nil
	}
	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{nftBin(), "add", "table", nftFamily, table})
	if out == "" {
		return checkResult(fmt.Sprintf("Table %s in family %s created", table, family), true), nil
	}
	return checkResult(fmt.Sprintf("Table %s in family %s could not be created", table, family), false), nil
}

type DeleteTableArgs struct {
	Table  *string `statekit:"name=table"`
	Family *string `statekit:"name=family"`
}

type deleteTableFunc struct{ linuxOnly }

func (deleteTableFunc) Name() string { return "nftables.delete_table" }
func (deleteTableFunc) Args() any    { return DeleteTableArgs{} }

func (deleteTableFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteTableArgs)
	table := strArg(a.Table)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if table == "" {
		return checkResult("Table needs to be specified", false), nil
	}
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: a.Table, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{nftBin(), "delete", "table", nftFamily, table})
	if out == "" {
		return checkResult(fmt.Sprintf("Table %s in family %s deleted", table, family), true), nil
	}
	return checkResult(fmt.Sprintf("Table %s in family %s could not be deleted", table, family), false), nil
}

type NewChainArgs struct {
	Table     *string `statekit:"name=table"`
	Chain     *string `statekit:"name=chain"`
	TableType *string `statekit:"name=table_type"`
	Hook      *string `statekit:"name=hook"`
	Priority  *int64  `statekit:"name=priority"`
	Family    *string `statekit:"name=family"`
}

type newChainFunc struct{ linuxOnly }

func (newChainFunc) Name() string { return "nftables.new_chain" }
func (newChainFunc) Args() any    { return NewChainArgs{} }

func (newChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*NewChainArgs)
	chain := strArg(a.Chain)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	effTable := table
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: &effTable, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{
		Table: &effTable, Chain: a.Chain, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] == true {
		return checkResult(fmt.Sprintf(
			"Chain %s in table %s in family %s already exists", chain, table, family), false), nil
	}

	nftFamily := familyOf(family)
	cmd := []string{nftBin(), "--", "add", "chain", nftFamily, table, chain}
	hasType := a.TableType != nil && *a.TableType != ""
	hasHook := a.Hook != nil && *a.Hook != ""
	hasPriority := a.Priority != nil
	if hasType || hasHook || hasPriority {
		if hasType && hasHook && hasPriority {
			suffix := fmt.Sprintf(`\{ type %s hook %s priority %d\; \}`,
				*a.TableType, *a.Hook, *a.Priority)
			cmd = append(cmd, strings.Fields(suffix)...)
		} else {
			return checkResult("Table_type, hook, and priority required.", false), nil
		}
	}
	out := runText(ctx, rt, cmd)
	if out == "" {
		return checkResult(fmt.Sprintf(
			"Chain %s in table %s in family %s created", chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Chain %s in table %s in family %s could not be created", chain, table, family), false), nil
}

type DeleteChainArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type deleteChainFunc struct{ linuxOnly }

func (deleteChainFunc) Name() string { return "nftables.delete_chain" }
func (deleteChainFunc) Args() any    { return DeleteChainArgs{} }

func (deleteChainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteChainArgs)
	chain := strArg(a.Chain)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	effTable := table
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: &effTable, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{
		Table: &effTable, Chain: a.Chain, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{nftBin(), "delete", "chain", nftFamily, table, chain})
	if out == "" {
		return checkResult(fmt.Sprintf(
			"Chain %s in table %s in family %s deleted", chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Chain %s in table %s in family %s could not be deleted", chain, table, family), false), nil
}

type AppendArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Rule   *string `statekit:"name=rule"`
	Family *string `statekit:"name=family"`
}

type appendFunc struct{ linuxOnly }

func (appendFunc) Name() string { return "nftables.append" }
func (appendFunc) Args() any    { return AppendArgs{} }

func (appendFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AppendArgs)
	chain := strArg(a.Chain)
	rule := strArg(a.Rule)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	if rule == "" {
		return checkResult("Rule needs to be specified", false), nil
	}

	res, err := preflightRule(ctx, rt, effTablePtr(a.Table), a.Chain, a.Family)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	res, err = checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: effTablePtr(a.Table), Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] == true {
		return checkResult(fmt.Sprintf(
			"Rule %s chain %s in table %s in family %s already exists",
			rule, chain, table, family), false), nil
	}

	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{
		nftBin(), "add", "rule", nftFamily, table, chain, rule,
	})
	if out == "" {
		return checkResult(fmt.Sprintf(
			"Added rule \"%s\" chain %s in table %s in family %s.",
			rule, chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Failed to add rule \"%s\" chain %s in table %s in family %s.",
		rule, chain, table, family), false), nil
}

// effTablePtr materializes the documented default table so nested checks
// never see a nil pointer.
func effTablePtr(table *string) *string {
	if table != nil && *table != "" {
		return table
	}
	def := "filter"
	return &def
}

// preflightRule runs the shared table+chain checks and returns the failing
// dict when either misses (nil means both passed).
func preflightRule(ctx context.Context, rt *runtime.Runtime, table, chain, family *string) (any, error) {
	effTable := "filter"
	if table != nil && *table != "" {
		effTable = *table
	}
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{Table: &effTable, Family: family})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{Table: &effTable, Chain: chain, Family: family})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}
	return nil, nil
}

type InsertArgs struct {
	Table    *string `statekit:"name=table"`
	Chain    *string `statekit:"name=chain"`
	Position *string `statekit:"name=position"`
	Rule     *string `statekit:"name=rule"`
	Family   *string `statekit:"name=family"`
}

type insertFunc struct{ linuxOnly }

func (insertFunc) Name() string { return "nftables.insert" }
func (insertFunc) Args() any    { return InsertArgs{} }

func (insertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InsertArgs)
	chain := strArg(a.Chain)
	rule := strArg(a.Rule)
	position := strArg(a.Position)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return checkResult("Chain needs to be specified", false), nil
	}
	if rule == "" {
		return checkResult("Rule needs to be specified", false), nil
	}

	res, err := preflightRule(ctx, rt, effTablePtr(a.Table), a.Chain, a.Family)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	res, err = checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: effTablePtr(a.Table), Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] == true {
		return checkResult(fmt.Sprintf(
			"Rule %s chain %s in table %s in family %s already exists",
			rule, chain, table, family), false), nil
	}

	nftFamily := familyOf(family)
	var cmd []string
	if position != "" {
		cmd = []string{nftBin(), "insert", "rule", nftFamily, table, chain,
			"position", position, rule}
	} else {
		cmd = []string{nftBin(), "insert", "rule", nftFamily, table, chain, rule}
	}
	out := runText(ctx, rt, cmd)
	if out == "" {
		return checkResult(fmt.Sprintf(
			"Added rule \"%s\" chain %s in table %s in family %s.",
			rule, chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Failed to add rule \"%s\" chain %s in table %s in family %s.",
		rule, chain, table, family), false), nil
}

type DeleteArgs struct {
	Table    *string `statekit:"name=table"`
	Chain    *string `statekit:"name=chain"`
	Position *string `statekit:"name=position"`
	Rule     *string `statekit:"name=rule"`
	Family   *string `statekit:"name=family"`
}

type deleteFunc struct{ linuxOnly }

func (deleteFunc) Name() string { return "nftables.delete" }
func (deleteFunc) Args() any    { return DeleteArgs{} }

func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DeleteArgs)
	chain := strArg(a.Chain)
	rule := strArg(a.Rule)
	position := strArg(a.Position)
	table := strArg(a.Table)
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if position != "" && rule != "" {
		return checkResult("Only specify a position or a rule, not both", false), nil
	}

	res, err := preflightRule(ctx, rt, effTablePtr(a.Table), a.Chain, a.Family)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	res, err = checkFunc{}.Execute(ctx, rt, &CheckArgs{
		Table: effTablePtr(a.Table), Chain: a.Chain, Rule: a.Rule, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return checkResult(fmt.Sprintf(
			"Rule %s chain %s in table %s in family %s does not exist",
			rule, chain, table, family), false), nil
	}

	// nftables deletes rules by handle; resolve it from the rule text.
	target := position
	if target == "" {
		handleRes, herr := getRuleHandleFunc{}.Execute(ctx, rt, &GetRuleHandleArgs{
			Table: a.Table, Chain: a.Chain, Rule: a.Rule, Family: a.Family,
		})
		if herr != nil {
			return nil, herr
		}
		hr := handleRes.(map[string]any)
		if hr["result"] == true {
			target, _ = hr["handle"].(string)
		}
	}

	nftFamily := familyOf(family)
	out := runText(ctx, rt, []string{
		nftBin(), "delete", "rule", nftFamily, table, chain, "handle", target,
	})
	if out == "" {
		return checkResult(fmt.Sprintf(
			"Deleted rule \"%s\" in chain %s in table %s in family %s.",
			rule, chain, table, family), true), nil
	}
	return checkResult(fmt.Sprintf(
		"Failed to delete rule \"%s\" in chain %s  table %s in family %s",
		rule, chain, table, family), false), nil
}

type FlushArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type flushFunc struct{ linuxOnly }

func (flushFunc) Name() string { return "nftables.flush" }
func (flushFunc) Args() any    { return FlushArgs{} }

func (flushFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FlushArgs)
	chain := strArg(a.Chain)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	res, err := checkTableFunc{}.Execute(ctx, rt, &CheckTableArgs{
		Table: a.Table, Family: a.Family,
	})
	if err != nil {
		return nil, err
	}
	if res.(map[string]any)["result"] != true {
		return res, nil
	}

	nftFamily := familyOf(family)
	comment := ""
	var cmd []string
	if chain != "" {
		res, err = checkChainFunc{}.Execute(ctx, rt, &CheckChainArgs{
			Table: a.Table, Chain: a.Chain, Family: a.Family,
		})
		if err != nil {
			return nil, err
		}
		if res.(map[string]any)["result"] != true {
			return res, nil
		}
		cmd = []string{nftBin(), "flush", "chain", nftFamily, table, chain}
		comment = fmt.Sprintf("from chain %s in table %s in family %s.", chain, table, family)
	} else {
		cmd = []string{nftBin(), "flush", "table", nftFamily, table}
		comment = fmt.Sprintf("from table %s in family %s.", table, family)
	}
	out := runText(ctx, rt, cmd)
	if out == "" {
		return checkResult("Flushed rules "+comment, true), nil
	}
	return checkResult("Failed to flush rules "+comment, false), nil
}

// --- policies ----------------------------------------------------------------

type GetPolicyArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Family *string `statekit:"name=family"`
}

type getPolicyFunc struct{ linuxOnly }

func (getPolicyFunc) Name() string { return "nftables.get_policy" }
func (getPolicyFunc) Args() any    { return GetPolicyArgs{} }

// Execute mirrors upstream's double-index quirk: rules is already the
// inner list, so the "nftables" lookup always raises and the function
// falls through to None once the chain argument is present.
func (getPolicyFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*GetPolicyArgs)
	if strArg(a.Chain) == "" {
		return "Error: Chain needs to be specified", nil
	}
	return nil, nil
}

type SetPolicyArgs struct {
	Table  *string `statekit:"name=table"`
	Chain  *string `statekit:"name=chain"`
	Policy *string `statekit:"name=policy"`
	Family *string `statekit:"name=family"`
}

type setPolicyFunc struct{ linuxOnly }

func (setPolicyFunc) Name() string { return "nftables.set_policy" }
func (setPolicyFunc) Args() any    { return SetPolicyArgs{} }

func (setPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetPolicyArgs)
	chain := strArg(a.Chain)
	policy := strArg(a.Policy)
	table := "filter"
	if a.Table != nil && *a.Table != "" {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil && *a.Family != "" {
		family = *a.Family
	}
	if chain == "" {
		return "Error: Chain needs to be specified", nil
	}
	if policy == "" {
		return "Error: Policy needs to be specified", nil
	}

	rulesRaw, err := getRulesJSONFunc{}.Execute(ctx, rt, &GetRulesJSONArgs{Family: a.Family})
	if err != nil {
		return nil, err
	}
	rules, _ := rulesRaw.([]any)
	if len(rules) == 0 {
		return false, nil
	}

	chainInfo := map[string]any{}
	for _, entry := range rules {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		info, ok := entryMap["chain"].(map[string]any)
		if !ok {
			continue
		}
		if info["table"] == table && info["name"] == chain {
			chainInfo = info
			break
		}
	}
	if len(chainInfo) == 0 {
		return false, nil
	}
	ctype, hasType := chainInfo["type"]
	hook, hasHook := chainInfo["hook"]
	prio, hasPrio := chainInfo["prio"]
	if !hasType || !hasHook || !hasPrio {
		return false, nil
	}

	braced := fmt.Sprintf("{ type %v hook %v priority %v; policy %s; }",
		ctype, hook, prio, policy)
	res := rt.Runner.Run(ctx, processCommand([]string{
		nftBin(), "add", "chain", familyOf(family), table, chain, braced,
	}))
	if res.Err != nil {
		return false, nil
	}
	return res.ExitCode == 0, nil
}

// Register installs all nftables-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		buildRuleFunc{},
		getSavedRulesFunc{},
		listTablesFunc{},
		getRulesFunc{},
		getRulesJSONFunc{},
		saveFunc{},
		getRuleHandleFunc{},
		checkFunc{},
		checkChainFunc{},
		checkTableFunc{},
		newTableFunc{},
		deleteTableFunc{},
		newChainFunc{},
		deleteChainFunc{},
		appendFunc{},
		insertFunc{},
		deleteFunc{},
		flushFunc{},
		getPolicyFunc{},
		setPolicyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
