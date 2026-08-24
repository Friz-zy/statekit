package iptables

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// stateInternalKeywords mirrors salt.state.STATE_INTERNAL_KEYWORDS; these
// kwargs are dropped from build_rule input.
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

// afterJumpArguments pins the ordered jump-option list from man pages,
// exactly as upstream enumerates them (j/jump first).
var afterJumpArguments = []string{
	"j", "jump",
	"add-set", "and-mark", "and-tos", "checksum-fill", "clamp-mss-to-pmtu",
	"clustermac", "ctevents", "ctmask", "del-set", "ecn-tcp-remove",
	"exist", "expevents", "gateway", "hash-init", "hashmode", "helper",
	"label", "local-node", "log-ip-options", "log-level", "log-prefix",
	"log-tcp-options", "log-tcp-sequence", "log-uid", "mask", "new",
	"nfmask", "nflog-group", "nflog-prefix", "nflog-range",
	"nflog-threshold", "nodst", "notrack", "on-ip", "on-port", "or-mark",
	"or-tos", "persistent", "queue-balance", "queue-bypass", "queue-num",
	"random", "rateest-ewmalog", "rateest-interval", "rateest-name",
	"reject-with", "restore", "restore-mark", "save-mark", "selctx",
	"set-class", "set-dscp", "set-dscp-class", "set-mark", "set-mss",
	"set-tos", "set-xmark", "strip-options", "timeout", "to",
	"to-destination", "to-ports", "to-source", "total-nodes",
	"tproxy-mark", "ttl-dec", "ttl-inc", "ttl-set", "type", "ulog-cprange",
	"ulog-nlgroup", "ulog-prefix", "ulog-qthreshold", "xor-mark", "xor-tos",
	"zone",
	"dst-pfx", "hl-dec", "hl-inc", "hl-set", "hmark-dport-mask",
	"hmark-dst-prefix", "hmark-mod", "hmark-offset", "hmark-proto-mask",
	"hmark-rnd", "hmark-spi-mask", "hmark-sport-mask", "hmark-src-prefix",
	"hmark-tuple", "led-always-blink", "led-delay", "led-trigger-id",
	"queue-cpu-fanout", "src-pfx",
	"to-port",
	"addr", "and-mask", "delude", "honeypot", "or-mask", "prefix", "reset",
	"reuse", "set-mac", "shift", "static", "tarpit", "tname", "ttl",
}

var bangNotPat = regexp.MustCompile(`(!|not)\s?`)

var whitespaceRe = regexp.MustCompile(`\s`)

func anyToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", t)
	}
}

// BuildRuleArgs mirrors build_rule's signature; kwargs carry the rule
// options and are only reachable through structured input.
type BuildRuleArgs struct {
	Table    *string        `statekit:"name=table"`
	Chain    *string        `statekit:"name=chain"`
	Command  *string        `statekit:"name=command"`
	Position string         `statekit:"name=position"`
	Full     *bool          `statekit:"name=full"`
	Family   *string        `statekit:"name=family"`
	Kwargs   map[string]any `statekit:"name=kwargs"`
}

type buildRuleFunc struct{ linuxOnly }

func (buildRuleFunc) Name() string { return "iptables.build_rule" }
func (buildRuleFunc) Args() any    { return BuildRuleArgs{} }

func (buildRuleFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*BuildRuleArgs)
	table := "filter"
	if a.Table != nil {
		table = *a.Table
	}
	family := "ipv4"
	if a.Family != nil {
		family = *a.Family
	}

	rule, err := buildRuleImpl(ctx, rt, a.Kwargs, family)
	if err != nil {
		return nil, err
	}

	// The multiport protocol guard returns its error before the full
	// format path can ever see it.
	if strings.HasPrefix(rule, "Error: ") {
		return rule, nil
	}

	full := a.Full != nil && (*a.Full == true)
	if full {
		command := ""
		if a.Command != nil {
			command = *a.Command
		}
		position := a.Position
		if table == "" {
			return "Error: Table needs to be specified", nil
		}
		if a.Chain == nil || *a.Chain == "" {
			return "Error: Chain needs to be specified", nil
		}
		if command == "" {
			return "Error: Command needs to be specified", nil
		}
		flag := "--"
		if strings.Contains("ACDIRLSFZNXPE", command) {
			flag = "-"
		}
		wait := ""
		if hasOptionFn(ctx, rt, "--wait", family) {
			wait = "--wait"
		}
		return fmt.Sprintf("%s %s -t %s %s%s %s %s %s",
			iptablesPath(family), wait, table, flag, command, *a.Chain, position, rule), nil
	}
	return rule, nil
}

// buildRuleImpl ports build_rule's assembly order verbatim.
func buildRuleImpl(ctx context.Context, rt *runtime.Runtime, rawKwargs map[string]any, family string) (string, error) {
	kwargs := map[string]any{}
	for k, v := range rawKwargs {
		kwargs[k] = v
	}

	if v, ok := kwargs["target"]; ok {
		kwargs["jump"] = v
		delete(kwargs, "target")
	}
	delete(kwargs, "name")
	delete(kwargs, "state")
	for _, ignore := range stateInternalKeywords {
		delete(kwargs, ignore)
	}
	delete(kwargs, "chain")
	delete(kwargs, "save")
	delete(kwargs, "table")

	var rule []string
	protocol := false

	maybeNegation := func(arg string) string {
		value := anyToString(kwargs[arg])
		if strings.HasPrefix(value, "!") || strings.HasPrefix(value, "not") {
			kwargs[arg] = bangNotPat.ReplaceAllString(value, "")
			return "! "
		}
		return ""
	}

	if _, ok := kwargs["if"]; ok {
		neg := maybeNegation("if")
		rule = append(rule, fmt.Sprintf("%s-i %s", neg, anyToString(kwargs["if"])))
		delete(kwargs, "if")
	}
	if _, ok := kwargs["of"]; ok {
		neg := maybeNegation("of")
		rule = append(rule, fmt.Sprintf("%s-o %s", neg, anyToString(kwargs["of"])))
		delete(kwargs, "of")
	}

	matchIsPolicy := func() bool {
		m, ok := kwargs["match"]
		return ok && anyToString(m) == "policy"
	}
	if v, ok := kwargs["proto"]; ok && !matchIsPolicy() {
		kwargs["protocol"] = v
		delete(kwargs, "proto")
	}
	if _, ok := kwargs["protocol"]; ok && !protocol {
		neg := maybeNegation("protocol")
		rule = append(rule, fmt.Sprintf("%s-p %s", neg, anyToString(kwargs["protocol"])))
		protocol = true
		delete(kwargs, "protocol")
	} else if ok {
		delete(kwargs, "protocol")
	}

	if mv, ok := kwargs["match"]; ok {
		var matchValues []string
		switch t := mv.(type) {
		case []any:
			for _, item := range t {
				matchValues = append(matchValues, anyToString(item))
			}
		case []string:
			matchValues = append(matchValues, t...)
		default:
			matchValues = strings.Split(anyToString(mv), ",")
		}
		for _, match := range matchValues {
			rule = append(rule, "-m "+match)
			if nameVal, hasName := kwargs["name_"]; hasName &&
				strings.TrimSpace(match) != "" &&
				(strings.TrimSpace(match) == "pknock" ||
					strings.TrimSpace(match) == "quota2" ||
					strings.TrimSpace(match) == "recent") {
				rule = append(rule, "--name "+anyToString(nameVal))
				delete(kwargs, "name_")
			}
		}
		if _, hasProto := kwargs["proto"]; hasProto && matchIsPolicy() {
			neg := maybeNegation("proto")
			rule = append(rule, fmt.Sprintf("%s--proto %s", neg, anyToString(kwargs["proto"])))
			delete(kwargs, "proto")
		}
		delete(kwargs, "match")
	}

	if mv, ok := kwargs["match-set"]; ok {
		var sets []string
		switch t := mv.(type) {
		case []any:
			for _, item := range t {
				sets = append(sets, anyToString(item))
			}
		case []string:
			sets = append(sets, t...)
		default:
			sets = []string{anyToString(t)}
		}
		for _, matchSet := range sets {
			negative := ""
			if strings.HasPrefix(matchSet, "!") || strings.HasPrefix(matchSet, "not") {
				negative = "! "
				matchSet = bangNotPat.ReplaceAllString(matchSet, "")
			}
			rule = append(rule, fmt.Sprintf("-m set %s--match-set %s", negative, matchSet))
		}
		delete(kwargs, "match-set")
	}

	if _, ok := kwargs["connstate"]; ok {
		hasStateModule := false
		for _, entry := range rule {
			if entry == "-m state" {
				hasStateModule = true
				break
			}
		}
		if !hasStateModule {
			rule = append(rule, "-m state")
		}
		neg := maybeNegation("connstate")
		rule = append(rule, fmt.Sprintf("%s--state %s", neg, anyToString(kwargs["connstate"])))
		delete(kwargs, "connstate")
	}

	if _, ok := kwargs["dport"]; ok {
		neg := maybeNegation("dport")
		rule = append(rule, fmt.Sprintf("%s--dport %s", neg, anyToString(kwargs["dport"])))
		delete(kwargs, "dport")
	}
	if _, ok := kwargs["sport"]; ok {
		neg := maybeNegation("sport")
		rule = append(rule, fmt.Sprintf("%s--sport %s", neg, anyToString(kwargs["sport"])))
		delete(kwargs, "sport")
	}

	for _, multiportArg := range []string{"dports", "sports"} {
		mv, ok := kwargs[multiportArg]
		if !ok {
			continue
		}
		hasMultiport := false
		for _, entry := range rule {
			if entry == "-m multiport" {
				hasMultiport = true
				break
			}
		}
		if !hasMultiport {
			rule = append(rule, "-m multiport")
			if !protocol {
				return "Error: protocol must be specified", nil
			}
		}
		var dports string
		switch t := mv.(type) {
		case []any:
			anyNegative := false
			for _, item := range t {
				s := anyToString(item)
				if strings.HasPrefix(s, "!") || strings.HasPrefix(s, "not") {
					anyNegative = true
					break
				}
			}
			cleaned := make([]string, 0, len(t))
			for _, item := range t {
				s := anyToString(item)
				if anyNegative {
					s = bangNotPat.ReplaceAllString(s, "")
				}
				cleaned = append(cleaned, s)
			}
			if anyNegative {
				rule = append(rule, "!")
			}
			dports = strings.Join(cleaned, ",")
		default:
			s := anyToString(t)
			if strings.HasPrefix(s, "!") || strings.HasPrefix(s, "not") {
				dports = bangNotPat.ReplaceAllString(s, "")
				rule = append(rule, "!")
			} else {
				dports = s
			}
		}
		rule = append(rule, fmt.Sprintf("--%s %s", multiportArg, dports))
		delete(kwargs, multiportArg)
	}

	if cv, ok := kwargs["comment"]; ok {
		hasCommentModule := false
		for _, entry := range rule {
			if entry == "-m comment" {
				hasCommentModule = true
				break
			}
		}
		if !hasCommentModule {
			rule = append(rule, "-m comment")
		}
		rule = append(rule, fmt.Sprintf("--comment \"%s\"", anyToString(cv)))
		delete(kwargs, "comment")
	}

	if sv, ok := kwargs["set"]; ok && anyToString(sv) != "" {
		neg := maybeNegation("set")
		rule = append(rule, fmt.Sprintf("%s--match-set %s", neg, anyToString(kwargs["set"])))
		delete(kwargs, "set")
	}

	var afterJump []string
	for _, afterJumpArgument := range afterJumpArguments {
		v, ok := kwargs[afterJumpArgument]
		if !ok {
			continue
		}
		switch {
		case v == nil || anyToString(v) == "":
			afterJump = append(afterJump, "--"+afterJumpArgument)
		case whitespaceRe.MatchString(anyToString(v)):
			afterJump = append(afterJump, fmt.Sprintf("--%s \"%s\"", afterJumpArgument, anyToString(v)))
		default:
			afterJump = append(afterJump, fmt.Sprintf("--%s %s", afterJumpArgument, anyToString(v)))
		}
		delete(kwargs, afterJumpArgument)
	}

	// Leftover kwargs render generically. Structured maps do not preserve
	// upstream's insertion order, so multi-leftover ordering is
	// unspecified (documented divergence).
	for key := range kwargs {
		negation := maybeNegation(key)
		value := kwargs[key]
		flag := "-"
		if len(key) != 1 {
			flag = "--"
		}
		valText := ""
		if !(value == nil || anyToString(value) == "") {
			valText = " " + anyToString(value)
		}
		rule = append(rule, fmt.Sprintf("%s%s%s%s", negation, flag, key, valText))
	}

	rule = append(rule, afterJump...)
	return strings.Join(rule, " "), nil
}
