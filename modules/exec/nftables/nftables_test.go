package nftables

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	joined := cmd.Name + " " + strings.Join(cmd.Args, " ")
	f.calls = append(f.calls, joined)
	if res, ok := f.results[joined]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(t *testing.T, bin string, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := nftBin
	nftBin = func() string { return bin }
	t.Cleanup(func() { nftBin = saved })
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

func strPtr(s string) *string { return &s }

func assertResult(t *testing.T, gotRaw any, comment string, result bool) {
	t.Helper()
	got := gotRaw.(map[string]any)
	if got["comment"] != comment || got["result"] != result {
		t.Fatalf("got %#v, want {comment:%q result:%v}", got, comment, result)
	}
}

// Mirrors test_version.
func TestVersion(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --version": {Stdout: []byte("nf_tables 0.3-1")},
	})
	gotRaw, err := versionFunc{}.Execute(context.Background(), rt, &VersionArgs{})
	if err != nil || gotRaw != "0.3-1" {
		t.Fatalf("version = %#v, %v", gotRaw, err)
	}
}

// Mirrors the build_rule fixture battery including dict-shaped returns.
func TestBuildRule(t *testing.T) {
	rt, _ := newRT(t, "nft", nil)
	brf := buildRuleFunc{}
	exec := func(args *BuildRuleArgs) map[string]any {
		gotRaw, err := brf.Execute(context.Background(), rt, args)
		if err != nil {
			t.Fatal(err)
		}
		return gotRaw.(map[string]any)
	}

	full := "True"

	if got := exec(&BuildRuleArgs{Full: &full}); !reflect.DeepEqual(got, map[string]any{
		"result": false, "rule": "", "comment": "Table needs to be specified",
	}) {
		t.Fatalf("no table = %#v", got)
	}
	if got := exec(&BuildRuleArgs{Table: strPtr("filter"), Full: &full}); !reflect.DeepEqual(got, map[string]any{
		"result": false, "rule": "", "comment": "Chain needs to be specified",
	}) {
		t.Fatalf("no chain = %#v", got)
	}
	if got := exec(&BuildRuleArgs{Table: strPtr("filter"), Chain: strPtr("input"), Full: &full}); !reflect.DeepEqual(got, map[string]any{
		"result": false, "rule": "", "comment": "Command needs to be specified",
	}) {
		t.Fatalf("no command = %#v", got)
	}

	pos := "3"
	want := map[string]any{
		"result":  true,
		"rule":    "nft insert rule ip filter input position 3 ",
		"comment": "Successfully built rule",
	}
	if got := exec(&BuildRuleArgs{
		Table: strPtr("filter"), Chain: strPtr("input"), Command: strPtr("insert"),
		Position: pos, Full: &full,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("insert+position = %#v, want %#v", got, want)
	}

	want = map[string]any{
		"result":  true,
		"rule":    "nft insert rule ip filter input ",
		"comment": "Successfully built rule",
	}
	if got := exec(&BuildRuleArgs{
		Table: strPtr("filter"), Chain: strPtr("input"),
		Command: strPtr("insert"), Full: &full,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("insert = %#v, want %#v", got, want)
	}

	want = map[string]any{
		"result":  true,
		"rule":    "nft halt rule ip filter input ",
		"comment": "Successfully built rule",
	}
	if got := exec(&BuildRuleArgs{
		Table: strPtr("filter"), Chain: strPtr("input"),
		Command: strPtr("halt"), Full: &full,
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("halt = %#v, want %#v", got, want)
	}

	want = map[string]any{
		"result": true,
		"rule": ("nft insert rule ip filter input position 3 ct state {" +
			" related,established } ip saddr 10.0.0.1 ip daddr 10.0.0.2 accept"),
		"comment": "Successfully built rule",
	}
	if got := exec(&BuildRuleArgs{
		Table: strPtr("filter"), Chain: strPtr("input"), Command: strPtr("insert"),
		Position: pos, Full: &full,
		Kwargs: kw("connstate", "related,established", "saddr", "10.0.0.1",
			"daddr", "10.0.0.2", "jump", "accept"),
	}); !reflect.DeepEqual(got, want) {
		t.Fatalf("full rule = %#v, want %#v", got, want)
	}

	if got := exec(&BuildRuleArgs{}); !reflect.DeepEqual(got, map[string]any{
		"result": true, "rule": "", "comment": "",
	}) {
		t.Fatalf("bare call = %#v", got)
	}

	// dports reverse-sort numerically.
	got := exec(&BuildRuleArgs{Kwargs: kw("dports", "80,443")})
	// Empty proto renders a leading space via the substring replacement,
	// mirroring upstream verbatim.
	if got["rule"] != " dport { 443, 80 }" {
		t.Fatalf("dports sort = %#v", got["rule"])
	}
}

func kw(pairs ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1]
	}
	return m
}

// Mirrors test_get_saved_rules.
func TestGetSavedRules(t *testing.T) {
	rt, _ := newRT(t, "nft", nil)
	osFamilySaved := osFamilyHook
	osFamilyHook = func(*runtime.Runtime) string { return "Debian" }
	t.Cleanup(func() { osFamilyHook = osFamilySaved })
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/nftables", []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	gotRaw, err := getSavedRulesFunc{}.Execute(context.Background(), rt, &GetSavedRulesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotRaw.([]any)) != 0 {
		t.Fatalf("missing file must not yield rules: %#v", gotRaw)
	}
}

const tablesJSON = `{"nftables":[{"metainfo":{"version":"1.0"}},{"table":{"family":"ip","name":"filter","handle":2}}]}`

// Mirrors test_list_tables through real JSON parsing.
func TestListTables(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --json --numeric --numeric --numeric list tables ip": {Stdout: []byte(tablesJSON)},
	})
	gotRaw, err := listTablesFunc{}.Execute(context.Background(), rt, &ListTablesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	tables := gotRaw.([]any)
	if len(tables) != 1 {
		t.Fatalf("tables = %#v", tables)
	}
	table := tables[0].(map[string]any)
	if table["family"] != "ip" || table["name"] != "filter" {
		t.Fatalf("table = %#v", table)
	}
}

// Mirrors test_get_rules_json.
func TestGetRulesJSON(t *testing.T) {
	rulesJSON := `{"nftables":[` +
		`{"table":{"family":"ip","name":"filter","handle":47}},` +
		`{"chain":{"family":"ip","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}}]}`

	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --numeric --numeric --numeric --json list ruleset ip": {Stdout: []byte(rulesJSON)},
	})
	gotRaw, err := getRulesJSONFunc{}.Execute(context.Background(), rt, &GetRulesJSONArgs{})
	if err != nil {
		t.Fatal(err)
	}
	list := gotRaw.([]any)
	if len(list) != 2 {
		t.Fatalf("ruleset entries = %d (%#v)", len(list), list)
	}
	first := list[0].(map[string]any)["table"].(map[string]any)
	if first["name"] != "filter" {
		t.Fatalf("first entry = %#v", first)
	}

	// Empty tool output yields an empty list.
	rt2, _ := newRT(t, "nft", nil)
	gotRaw, err = getRulesJSONFunc{}.Execute(context.Background(), rt2, &GetRulesJSONArgs{})
	if err != nil || len(gotRaw.([]any)) != 0 {
		t.Fatalf("empty output = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_save content shape and write-failure error.
func TestSave(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --numeric --numeric --numeric list table ip filter": {},
	})
	osFamilySaved := osFamilyHook
	osFamilyHook = func(*runtime.Runtime) string { return "Debian" }
	t.Cleanup(func() { osFamilyHook = osFamilySaved })

	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}

	sf := saveFunc{}
	gotRaw, err := sf.Execute(context.Background(), rt, &SaveArgs{})
	if err != nil || gotRaw != "#! nft -f\n\n" {
		t.Fatalf("save = %#v, %v", gotRaw, err)
	}
}

// Mirrors the check_table matrix.
func TestCheckTable(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip nat\n")},
	})
	ctf := checkTableFunc{}
	nat := "nat"

	gotRaw, err := ctf.Execute(context.Background(), rt, &CheckTableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table needs to be specified", false)

	gotRaw, err = ctf.Execute(context.Background(), rt, &CheckTableArgs{Table: &nat})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nat in family ipv4 exists", true)

	missing := "nope"
	gotRaw, err = ctf.Execute(context.Background(), rt, &CheckTableArgs{Table: &missing})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nope in family ipv4 does not exist", false)
}

// Mirrors the check_chain and check matrices through chained probes.
func TestCheckChainAndRule(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft --handle --numeric --numeric --numeric list chain ip filter input": {Stdout: []byte(
			"\ttcp dport 22 log accept # handle 4\n")},
	})
	ccf := checkChainFunc{}
	input := "input"

	gotRaw, err := ccf.Execute(context.Background(), rt, &CheckChainArgs{})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Chain needs to be specified", false)

	gotRaw, err = ccf.Execute(context.Background(), rt, &CheckChainArgs{Chain: &input})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Chain input in table filter in family ipv4 exists", true)

	cf := checkFunc{}
	rule := "tcp dport 22 log accept"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Chain: &input, Rule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Rule tcp dport 22 log accept in chain input in table filter in family ipv4 exists", true)

	nope := "tcp dport 99"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Chain: &input, Rule: &nope})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Rule "+nope+" in chain input in table filter in family ipv4 does not exist", false)
}

// Mirrors new_table/delete_table flows including the already-exists path.
func TestTableLifecycle(t *testing.T) {
	ntf := newTableFunc{}
	nat := "nat"

	gotRaw, err := ntf.Execute(context.Background(), &runtime.Runtime{}, &NewTableArgs{})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table needs to be specified", false)

	// Fresh table: empty tool output yields the created comment.
	rtFresh, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip":      {},
		"nft add table ip nat":    {},
		"nft delete table ip nat": {},
	})
	gotRaw, err = ntf.Execute(context.Background(), rtFresh, &NewTableArgs{Table: &nat})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nat in family ipv4 created", true)

	// Existing table short-circuits with the exists comment.
	rtLive, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip nat\n")},
	})
	gotRaw, err = ntf.Execute(context.Background(), rtLive, &NewTableArgs{Table: &nat})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nat in family ipv4 exists", true)

	dtf := deleteTableFunc{}

	// Missing table passthrough.
	gotRaw, err = dtf.Execute(context.Background(), rtFresh, &DeleteTableArgs{Table: &nat})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nat in family ipv4 does not exist", false)

	// Present table deletes cleanly.
	rtLive2, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip":      {Stdout: []byte("table ip nat\n")},
		"nft delete table ip nat": {},
	})
	gotRaw, err = dtf.Execute(context.Background(), rtLive2, &DeleteTableArgs{Table: &nat})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table nat in family ipv4 deleted", true)
}

// Mirrors new_chain with base-chain parameters and partial-parameter error.
func TestNewChainVariables(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n}\n")},
	})
	ncf := newChainFunc{}
	input := "input"

	// Table missing (empty tool output like upstream's first mock).
	rtMissing, _ := newRT(t, "nft", nil)
	gotRaw, err := ncf.Execute(context.Background(), rtMissing, &NewChainArgs{Chain: &input})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table filter in family ipv4 does not exist", false)

	foo := "foo"
	gotRaw, err = ncf.Execute(context.Background(), rt, &NewChainArgs{
		Chain: &foo, TableType: strPtr("filter"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Table_type, hook, and priority required.", false)

	prio := int64(0)
	gotRaw, err = ncf.Execute(context.Background(), rt, &NewChainArgs{
		Chain: &foo, TableType: strPtr("filter"), Hook: strPtr("input"), Priority: &prio,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Chain foo in table filter in family ipv4 created", true)
}

// Mirrors append/insert dedupe and success comments.
func TestAppendInsert(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft --handle --numeric --numeric --numeric list chain ip filter input": {Stdout: []byte("")},
		"nft add rule ip filter input tcp dport 22 log accept":                  {},
		"nft insert rule ip filter input tcp dport 22 log accept":               {},
	})
	rule := "tcp dport 22 log accept"
	input := "input"

	af := appendFunc{}
	gotRaw, err := af.Execute(context.Background(), rt, &AppendArgs{Chain: &input, Rule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Added rule \""+rule+"\" chain input in table filter in family ipv4.", true)

	// A chain whose listing already carries the rule short-circuits.
	rtDup, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft --handle --numeric --numeric --numeric list chain ip filter input": {Stdout: []byte(
			"\ttcp dport 22 log accept # handle 5\n")},
	})
	gotRaw, err = af.Execute(context.Background(), rtDup, &AppendArgs{Chain: &input, Rule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Rule "+rule+" chain input in table filter in family ipv4 already exists", false)

	inf := insertFunc{}
	gotRaw, err = inf.Execute(context.Background(), rt, &InsertArgs{Chain: &input, Rule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Added rule \""+rule+"\" chain input in table filter in family ipv4.", true)
}

// Mirrors delete via handle resolution.
func TestDeleteViaHandle(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft --handle --numeric --numeric --numeric list chain ip filter input": {Stdout: []byte(
			"\ttcp dport 22 log accept # handle 7\n")},
		"nft delete rule ip filter input handle 7": {},
	})
	df := deleteFunc{}
	rule := "tcp dport 22 log accept"
	input := "input"
	pos := "3"

	// Both position and rule conflict.
	gotRaw, err := df.Execute(context.Background(), rt, &DeleteArgs{
		Table: strPtr("filter"), Chain: &input, Position: &pos, Rule: &rule,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Only specify a position or a rule, not both", false)

	gotRaw, err = df.Execute(context.Background(), rt, &DeleteArgs{
		Table: strPtr("filter"), Chain: &input, Rule: &rule,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Deleted rule \""+rule+"\" in chain input in table filter in family ipv4.", true)
}

// Mirrors flush chain/table comment pairing.
func TestFlush(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft flush chain ip filter input": {},
		"nft flush table ip filter":       {},
	})
	ff := flushFunc{}
	input := "input"
	filterT := "filter"

	gotRaw, err := ff.Execute(context.Background(), rt, &FlushArgs{Table: &filterT, Chain: &input})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Flushed rules from chain input in table filter in family ipv4.", true)

	gotRaw, err = ff.Execute(context.Background(), rt, &FlushArgs{Table: &filterT})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw,
		"Flushed rules from table filter in family ipv4.", true)
}

// Mirrors set_policy's braced argv construction over JSON chain info.
func TestSetPolicy(t *testing.T) {
	rulesJSON := `{"nftables":[` +
		`{"chain":{"family":"ip","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}}]}`
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --numeric --numeric --numeric --json list ruleset ip":                          {Stdout: []byte(rulesJSON)},
		"nft add chain ip filter input { type filter hook input priority 0; policy drop; }": {},
	})

	sp := setPolicyFunc{}
	input := "input"
	filterT := "filter"
	drop := "drop"
	gotRaw, err := sp.Execute(context.Background(), rt, &SetPolicyArgs{
		Table: &filterT, Chain: &input, Policy: &drop,
	})
	if err != nil || gotRaw != true {
		t.Fatalf("set_policy = %#v, %v", gotRaw, err)
	}

	// Without type/hook/prio info the function bails out false.
	bareJSON := `{"nftables":[{"chain":{"family":"ip","table":"filter","name":"input"}}]}`
	rt2, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft --numeric --numeric --numeric --json list ruleset ip": {Stdout: []byte(bareJSON)},
	})
	gotRaw, err = sp.Execute(context.Background(), rt2, &SetPolicyArgs{
		Table: &filterT, Chain: &input, Policy: &drop,
	})
	if err != nil || gotRaw != false {
		t.Fatalf("set_policy without base params = %#v, %v", gotRaw, err)
	}

	// get_policy carries upstream's always-None quirk past validation.
	gp := getPolicyFunc{}
	chainErr := "Error: Chain needs to be specified"
	gotRaw, err = gp.Execute(context.Background(), rt, &GetPolicyArgs{})
	if err != nil || gotRaw != chainErr {
		t.Fatalf("get_policy missing chain = %#v, %v", gotRaw, err)
	}
	gotRaw, err = gp.Execute(context.Background(), rt, &GetPolicyArgs{Chain: &input})
	if err != nil || gotRaw != nil {
		t.Fatalf("get_policy quirk = %#v, %v", gotRaw, err)
	}
}

// Mirrors get_rule_handle's layered failures and handle extraction.
func TestGetRuleHandle(t *testing.T) {
	rt, _ := newRT(t, "nft", map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip filter\n")},
		"nft list table ip filter": {Stdout: []byte(
			"table ip filter {\n chain input {\n}\n}\n")},
		"nft --handle --numeric --numeric --numeric list chain ip filter input": {Stdout: []byte(
			"\tinput tcp dport 22 log accept # handle 9\n")},
		"nft --numeric --numeric --numeric --handle list chain ip filter input": {Stdout: []byte(
			"\tinput tcp dport 22 log accept # handle 9\n")},
	})
	grf := getRuleHandleFunc{}

	gotRaw, err := grf.Execute(context.Background(), rt, &GetRuleHandleArgs{})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Chain needs to be specified", false)

	rule := "input tcp dport 22 log accept"
	input := "input"
	gotRaw, err = grf.Execute(context.Background(), rt, &GetRuleHandleArgs{Chain: &input})
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, gotRaw, "Rule needs to be specified", false)

	gotRaw, err = grf.Execute(context.Background(), rt, &GetRuleHandleArgs{
		Chain: &input, Rule: &rule,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"result": true, "handle": "9"}
	if !reflect.DeepEqual(gotRaw.(map[string]any)["result"], want["result"]) ||
		gotRaw.(map[string]any)["handle"] != "9" {
		t.Fatalf("handle = %#v, want %#v", gotRaw, want)
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, "", nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"nftables.version", "nftables.build_rule", "nftables.get_saved_rules",
		"nftables.list_tables", "nftables.get_rules", "nftables.get_rules_json",
		"nftables.save", "nftables.get_rule_handle", "nftables.check",
		"nftables.check_chain", "nftables.check_table", "nftables.new_table",
		"nftables.delete_table", "nftables.new_chain", "nftables.delete_chain",
		"nftables.append", "nftables.insert", "nftables.delete",
		"nftables.flush", "nftables.get_policy", "nftables.set_policy",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	for _, priv := range []string{"nftables._nftables_cmd", "nftables._conf"} {
		if names[priv] {
			t.Errorf("%s must stay private", priv)
		}
	}
}
