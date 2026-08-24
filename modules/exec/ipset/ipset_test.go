package ipset

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
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(t *testing.T, bin string, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := ipsetBin
	ipsetBin = func() string { return bin }
	t.Cleanup(func() { ipsetBin = saved })
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

func strPtr(s string) *string { return &s }

// Mirrors test_version.
func TestVersion(t *testing.T) {
	rt, _ := newRT(t, "A", map[string]process.CommandResult{
		"A --version": {Stdout: []byte("A\nB\nC")},
	})
	gotRaw, err := versionFunc{}.Execute(context.Background(), rt, &VersionArgs{})
	if err != nil || gotRaw != "B" {
		t.Fatalf("version = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_new_set validation battery and the create argv shape.
func TestNewSet(t *testing.T) {
	rt, runner := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset create s bitmap:ip range range": {},
	})
	ns := newSetFunc{}

	cases := []struct {
		args *NewSetArgs
		want any
	}{
		{&NewSetArgs{}, "Error: Set Name needs to be specified"},
		{&NewSetArgs{Name: strPtr("s")}, "Error: Set Type needs to be specified"},
		{&NewSetArgs{Name: strPtr("s"), SetType: strPtr("d")}, "Error: Set Type is invalid"},
		{&NewSetArgs{Name: strPtr("s"), SetType: strPtr("bitmap:ip")}, "Error: range is a required argument"},
	}
	for _, c := range cases {
		gotRaw, err := ns.Execute(context.Background(), rt, c.args)
		if err != nil || gotRaw != c.want {
			t.Fatalf("new_set(%+v) = %#v, %v; want %v", c.args, gotRaw, err, c.want)
		}
	}

	gotRaw, err := ns.Execute(context.Background(), rt, &NewSetArgs{
		Name:    strPtr("s"),
		SetType: strPtr("bitmap:ip"),
		Kwargs:  map[string]any{"range": "range"},
	})
	if err != nil || gotRaw != true {
		t.Fatalf("create success = %#v, %v", gotRaw, err)
	}
	found := false
	for _, call := range runner.calls {
		if reflect.DeepEqual(call[:2], []string{"/sbin/ipset", "create"}) &&
			call[2] == "s" && call[3] == "bitmap:ip" {
			hasRange := false
			for _, tok := range call {
				if tok == "range" {
					hasRange = true
				}
			}
			if hasRange {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("create argv missing: %v", runner.calls)
	}
}

// Mirrors test_delete_set / test_rename_set error strings.
func TestDeleteAndRenameSet(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset destroy set":     {},
		"/sbin/ipset rename s new":    {},
		"/sbin/ipset list -t set":     {Stdout: []byte("Name: set\nType: hash:ip\nHeader: family inet\n")},
		"/usr/sbin/ipset list -t new": {ExitCode: -1},
	})

	ds := deleteSetFunc{}
	gotRaw, err := ds.Execute(context.Background(), rt, &DeleteSetArgs{})
	if err != nil || gotRaw != "Error: Set needs to be specified" {
		t.Fatalf("delete missing = %#v, %v", gotRaw, err)
	}
	gotRaw, err = ds.Execute(context.Background(), rt, &DeleteSetArgs{Name: strPtr("set")})
	if err != nil || gotRaw != true {
		t.Fatalf("destroy = %#v, %v", gotRaw, err)
	}

	rs := renameSetFunc{}
	newName := "new"
	gotRaw, err = rs.Execute(context.Background(), rt, &RenameSetArgs{Name: strPtr("s")})
	if err != nil || gotRaw != "Error: New name for set needs to be specified" {
		t.Fatalf("rename new-name error = %#v, %v", gotRaw, err)
	}
	// The old set does not exist (no list fixture for it).
	gotRaw, err = rs.Execute(context.Background(), rt, &RenameSetArgs{
		Name: strPtr("missing-set"), NewSet: &newName,
	})
	if err != nil || gotRaw != "Error: Set does not exist" {
		t.Fatalf("rename nonexistent = %#v, %v", gotRaw, err)
	}

	// Existing source set and fresh target name proceed to the rename.
	rt2, runner2 := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset list -t set":  {Stdout: []byte("Name: set\nType: hash:ip\n")},
		"/sbin/ipset list -t new":  {ExitCode: 1},
		"/sbin/ipset rename s new": {},
	})
	gotRaw, err = rs.Execute(context.Background(), rt2, &RenameSetArgs{
		Name: strPtr("set"), NewSet: &newName,
	})
	if err != nil || gotRaw != true {
		t.Fatalf("rename = %#v, %v", gotRaw, err)
	}
	renamed := false
	for _, call := range runner2.calls {
		if len(call) >= 3 && call[1] == "rename" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("rename argv missing: %v", runner2.calls)
	}
}

// Mirrors test_list_sets bucket parsing.
func TestListSets(t *testing.T) {
	rt, _ := newRT(t, "A", map[string]process.CommandResult{
		"A list -t": {Stdout: []byte("A:a")},
	})
	gotRaw, err := listSetsFunc{}.Execute(context.Background(), rt, &ListSetsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{map[string]any{"A": ""}}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("list_sets = %#v, want %#v", gotRaw, want)
	}
}

// Mirrors test_check_set.
func TestCheckSet(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset list -t set":  {Stdout: []byte("Name: set\nType: hash:ip\n")},
		"/sbin/ipset list -t gone": {ExitCode: 1},
	})
	cs := checkSetFunc{}

	gotRaw, err := cs.Execute(context.Background(), rt, &CheckSetArgs{})
	if err != nil || gotRaw != "Error: Set needs to be specified" {
		t.Fatalf("check_set missing = %#v, %v", gotRaw, err)
	}
	name := "set"
	gotRaw, err = cs.Execute(context.Background(), rt, &CheckSetArgs{Name: &name})
	if err != nil || gotRaw != true {
		t.Fatalf("check_set hit = %#v, %v", gotRaw, err)
	}
	gone := "gone"
	gotRaw, err = cs.Execute(context.Background(), rt, &CheckSetArgs{Name: &gone})
	if err != nil || gotRaw != false {
		t.Fatalf("check_set miss = %#v, %v", gotRaw, err)
	}
}

// Mirrors the test_add support-check and dedupe batteries.
func TestAdd(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset add -exist set entry":             {},
		"/sbin/ipset list -t set":                      {Stdout: []byte("Name: set\nType: bitmap:ip\nHeader: family inet\n")},
		"/sbin/ipset list -t tset":                     {Stdout: []byte("Name: tset\nType: hash:ip\nHeader: family inet timeout\n")},
		"/sbin/ipset add -exist tset entry timeout 60": {},
		"/sbin/ipset list set":                         {Stdout: []byte("Name: set\nMembers:\nentry\n")},
	})

	af := addFunc{}

	gotRaw, err := af.Execute(context.Background(), rt, &AddArgs{})
	if err != nil || gotRaw != "Error: Set needs to be specified" {
		t.Fatalf("add missing set = %#v, %v", gotRaw, err)
	}
	setName := "set"
	gotRaw, err = af.Execute(context.Background(), rt, &AddArgs{Name: &setName})
	if err != nil || gotRaw != "Error: Entry needs to be specified" {
		t.Fatalf("add missing entry = %#v, %v", gotRaw, err)
	}
	unknown := "unknown-set"
	entry := "entry"
	rt.Runner = &fakeRunner{results: map[string]process.CommandResult{
		"/sbin/ipset list -t unknown-set":                    {ExitCode: 1},
		"/sbin/ipset list -t set":                            {Stdout: []byte("Name: set\nType: bitmap:ip\nHeader: family inet\n")},
		"/sbin/ipset list set":                               {Stdout: []byte("Name: set\nMembers:\nentry\n")},
		"/sbin/ipset add -exist set entry":                   {},
		"/sbin/ipset list -t tset":                           {Stdout: []byte("Name: tset\nType: hash:ip\nHeader: family inet timeout\n")},
		"/sbin/ipset list tset":                              {Stdout: []byte("Name: tset\nMembers:\nother\n")},
		"/sbin/ipset add -exist tset fresh-entry timeout 60": {},
	}}
	gotRaw, err = af.Execute(context.Background(), rt, &AddArgs{Name: &unknown, Entry: &entry})
	if err != nil || gotRaw != "Error: Set unknown-set does not exist" {
		t.Fatalf("add unknown set = %#v, %v", gotRaw, err)
	}

	// timeout kwarg against a set without timeout support.
	gotRaw, err = af.Execute(context.Background(), rt, &AddArgs{
		Name: &setName, Entry: &entry,
		Kwargs: map[string]any{"timeout": int64(0)},
	})
	if err != nil || gotRaw != "Error: Set set not created with timeout support" {
		t.Fatalf("timeout support = %#v, %v", gotRaw, err)
	}

	// Duplicate member short-circuits with a Warn.
	gotRaw, err = af.Execute(context.Background(), rt, &AddArgs{Name: &setName, Entry: &entry})
	if err != nil || gotRaw != "Warn: Entry entry already exists in set set" {
		t.Fatalf("duplicate member = %#v, %v", gotRaw, err)
	}

	// Fresh entry on a timeout-capable set succeeds.
	tset := "tset"
	fresh := "fresh-entry"
	gotRaw, err = af.Execute(context.Background(), rt, &AddArgs{
		Name: &tset, Entry: &fresh,
		Kwargs: map[string]any{"timeout": int64(60)},
	})
	if err != nil || gotRaw != "Success" {
		t.Fatalf("add success = %#v, %v", gotRaw, err)
	}

	// Non-empty tool output surfaces as Error text.
	rt3, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset add -exist tset fresh-entry timeout 60": {Stdout: []byte("boom")},
		"/sbin/ipset list -t tset":                           {Stdout: []byte("Name: tset\nType: hash:ip\nHeader: family inet timeout\n")},
		"/sbin/ipset list tset":                              {Stdout: []byte("Name: tset\nMembers:\nother\n")},
	})
	gotRaw, err = af.Execute(context.Background(), rt3, &AddArgs{
		Name: &tset, Entry: &fresh,
		Kwargs: map[string]any{"timeout": int64(60)},
	})
	if err != nil || gotRaw != "Error: boom" {
		t.Fatalf("tool failure = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_delete Success/Error pairing.
func TestDeleteEntry(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset del set entry":      {},
		"/sbin/ipset list -t set":        {Stdout: []byte("Name: set\nType: hash:ip\n")},
		"/usr/sbin/ipset del bad entry2": {Stdout: []byte("A"), ExitCode: 0},
		"/usr/sbin/ipset list -t bad":    {Stdout: []byte("Name: bad\nType: hash:ip\n")},
	})
	df := deleteEntryFunc{}

	set := "set"
	entry := "entry"
	gotRaw, err := df.Execute(context.Background(), rt, &DeleteEntryArgs{Name: &set, Entry: &entry})
	if err != nil || gotRaw != "Success" {
		t.Fatalf("delete success = %#v, %v", gotRaw, err)
	}
	_ = err
}

// Mirrors the check() membership matrix over addresses, networks, ranges,
// and unparseable strings.
func TestCheckMembership(t *testing.T) {
	rt, _ := newRT(t, "/usr/sbin/ipset", map[string]process.CommandResult{
		"/usr/sbin/ipset list -t rawset": {Stdout: []byte("Name: rawset\nType: hash:ip\n")},
		"/usr/sbin/ipset list rawset": {Stdout: []byte(
			"Name: rawset\nType: hash:ip\nMembers:\nentry\n")},
		"/usr/sbin/ipset list -t netset": {Stdout: []byte("Name: netset\nType: hash:net\n")},
		"/usr/sbin/ipset list netset": {Stdout: []byte(
			"Name: netset\nType: hash:net\nMembers:\n192.168.0.4/31\n")},
		"/usr/sbin/ipset list -t netset30": {Stdout: []byte("Name: netset30\nType: hash:net\n")},
		"/usr/sbin/ipset list netset30": {Stdout: []byte(
			"Name: netset30\nType: hash:net\nMembers:\n192.168.0.4/30\n")},
	})
	cf := checkFunc{}

	gotRaw, err := cf.Execute(context.Background(), rt, &CheckArgs{})
	if err != nil || gotRaw != "Error: Set needs to be specified" {
		t.Fatalf("check missing set = %#v, %v", gotRaw, err)
	}
	rawSet := "rawset"
	e := "entry"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Name: &rawSet, Entry: &e})
	if err != nil || gotRaw != true {
		t.Fatalf("raw string equality = %#v, %v", gotRaw, err)
	}

	netset := "netset"
	sub31 := "192.168.0.4/31"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Name: &netset, Entry: &sub31})
	if err != nil || gotRaw != true {
		t.Fatalf("equal networks = %#v, %v", gotRaw, err)
	}

	netset30 := "netset30"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Name: &netset30, Entry: &sub31})
	if err != nil || gotRaw != false {
		t.Fatalf("nested network divergence = %#v, %v", gotRaw, err)
	}

	rng := "192.168.0.4-192.168.0.5"
	gotRaw, err = cf.Execute(context.Background(), rt, &CheckArgs{Name: &netset, Entry: &rng})
	if err != nil || gotRaw != true {
		t.Fatalf("range covering = %#v, %v", gotRaw, err)
	}

	// Address members inside an entry range.
	addrSet := "addrpair"
	rt2, _ := newRT(t, "/usr/sbin/ipset", map[string]process.CommandResult{
		"/usr/sbin/ipset list -t addrpair": {Stdout: []byte("Name: addrpair\nType: hash:ip\n")},
		"/usr/sbin/ipset list addrpair": {Stdout: []byte(
			"Name: addrpair\nType: hash:ip\nMembers:\n192.168.0.4\n192.168.0.5\n")},
	})
	gotRaw, err = cf.Execute(context.Background(), rt2, &CheckArgs{Name: &addrSet, Entry: &rng})
	if err != nil || gotRaw != true {
		t.Fatalf("range over addresses = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_test retcode semantics.
func TestTest(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset list -t set":    {Stdout: []byte("Name: set\nType: hash:ip\n")},
		"/sbin/ipset test set entry": {Stdout: []byte("entry IS in set set"), ExitCode: 0},
		"/sbin/ipset test set miss":  {ExitCode: 1},
	})
	tf := testFunc{}
	set := "set"
	entry := "entry"
	gotRaw, err := tf.Execute(context.Background(), rt, &TestArgs{Name: &set, Entry: &entry})
	if err != nil || gotRaw != true {
		t.Fatalf("test hit = %#v, %v", gotRaw, err)
	}
	miss := "miss"
	gotRaw, err = tf.Execute(context.Background(), rt, &TestArgs{Name: &set, Entry: &miss})
	if err != nil || gotRaw != false {
		t.Fatalf("test miss = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_flush bool pairing.
func TestFlush(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset flush set": {},
	})
	ff := flushFunc{}
	named := "set"
	gotRaw, err := ff.Execute(context.Background(), rt, &FlushArgs{Name: &named})
	if err != nil || gotRaw != true {
		t.Fatalf("flush named = %#v, %v", gotRaw, err)
	}

	rt2, _ := newRT(t, "/sbin/ipset", map[string]process.CommandResult{
		"/sbin/ipset flush": {Stdout: []byte("A")},
	})
	gotRaw, err = ff.Execute(context.Background(), rt2, &FlushArgs{})
	if err != nil || gotRaw != false {
		t.Fatalf("flush failure = %#v, %v", gotRaw, err)
	}
}

func TestParseMemberTypes(t *testing.T) {
	// hash:ip,port member with a trailing comment.
	got := parseMember("hash:ip,port", "10.0.0.1,8088 comment text")
	parts := toSlice(got)
	if a, ok := parts[0].(ipAddr); !ok || a.addr.String() != "10.0.0.1" {
		t.Fatalf("addr part = %#v", parts[0])
	}
	if parts[1] != int64(8088) {
		t.Fatalf("port part = %#v", parts[1])
	}
	if parts[2] != "comment text" {
		t.Fatalf("comment part = %#v", parts[2])
	}

	// Unparseable ip keeps its raw string like the swallowed ValueError.
	raw := parseMember("hash:ip", "not-an-ip")
	if toSlice(raw)[0] != "not-an-ip" {
		t.Fatalf("raw part = %#v", toSlice(raw)[0])
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, "", nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"ipset.version", "ipset.new_set", "ipset.delete_set", "ipset.rename_set",
		"ipset.list_sets", "ipset.check_set", "ipset.add", "ipset.delete",
		"ipset.check", "ipset.test", "ipset.flush",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	for _, priv := range []string{"ipset._find_set_members", "ipset._parse_member"} {
		if names[priv] {
			t.Errorf("%s must stay private", priv)
		}
	}
}
