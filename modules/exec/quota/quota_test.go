package quota

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult // keyed by joined argv
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	if res, ok := f.results[cmd.Name]; ok {
		return res
	}
	return process.CommandResult{}
}

const repquotaUserFixture = `*** Report for user quotas on device /dev/sda1
Block grace time: 7days; Inode grace time: 7days
			Block limits				File limits
User		used	soft	hard	grace	used	soft	hard	grace
----------------------------------------------------------------------
root      --  100000       0       0             10     0     0
larry     +-  200000 1048576 2097152  6days      20     0     0
`

const repquotaGroupFixture = `*** Report for group quotas on device /dev/sda1
Block grace time: 7days; Inode grace time: 7days
			Block limits				File limits
Group		used	soft	hard	grace	used	soft	hard	grace
----------------------------------------------------------------------
painters  +-   50000  262144  524288  5days      5     0     0
`

func newRT(results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		Facts:  nil,
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	if err := Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

// TestReport pins the nested report shape and grace-time lists.
func TestReport(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"repquota -vp -u /media/data": {Stdout: []byte(repquotaUserFixture)},
		"repquota -vp -g /media/data": {Stdout: []byte(repquotaGroupFixture)},
	})
	gotRaw, err := reportFunc{}.Execute(context.Background(), rt, &ReportArgs{Mount: "/media/data"})
	if err != nil {
		t.Fatal(err)
	}
	mount := gotRaw.(map[string]any)["/media/data"].(map[string]any)
	users := mount["User Quotas"].(map[string]any)["Users"].(map[string]any)
	larry := users["larry"].(map[string]any)
	if larry["block-used"] != "200000" || larry["block-soft-limit"] != "1048576" ||
		larry["file-grace"] != "" {
		t.Fatalf("larry row = %v", larry)
	}
	uq := mount["User Quotas"].(map[string]any)
	if !reflect.DeepEqual(uq["Block Grace Time"], []string{"7days"}) {
		t.Fatalf("grace = %v", uq["Block Grace Time"])
	}
	groups := mount["Group Quotas"].(map[string]any)["Groups"].(map[string]any)
	if _, ok := groups["painters"]; !ok {
		t.Fatalf("groups = %v", groups)
	}
	if !reflect.DeepEqual(
		mount["Group Quotas"].(map[string]any)["Block Grace Time"],
		[]string{"7days"}) {
		t.Fatalf("group grace missing")
	}
	for _, call := range runner.calls {
		want := []string{"repquota", "-vp"}
		if strings.Join(call[:2], " ") != strings.Join(want, " ") {
			t.Fatalf("argv = %v", call)
		}
	}
}

// TestSetQuota covers the user path, the zero-fallback quirk, and errors.
func TestSetQuota(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"repquota -vp -u /media/data": {Stdout: []byte(repquotaUserFixture)},
		"setquota":                    {},
	})

	got, err := setFunc{}.Execute(context.Background(), rt, &SetArgs{
		Device:         "/media/data",
		User:           "larry",
		BlockSoftLimit: "1048576",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := got.(map[string]any)["User: larry"].(map[string]any)
	// Mirrors Salt's membership quirk: unspecified limits fall back to 0.
	if row["block-soft-limit"] != "1048576" || row["block-hard-limit"] != 0 ||
		row["file-soft-limit"] != 0 {
		t.Fatalf("set row = %v", row)
	}
	last := runner.calls[len(runner.calls)-1]
	want := []string{"setquota", "-u", "larry", "1048576", "0", "0", "0", "/media/data"}
	if !reflect.DeepEqual(last, want) {
		t.Fatalf("setquota argv = %v", last)
	}

	// Both user and group is an error (Salt raises SaltInvocationError).
	_, err = setFunc{}.Execute(context.Background(), rt, &SetArgs{
		Device: "/media/data", User: "a", Group: "b",
	})
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both error = %v", err)
	}

	// Neither user nor group.
	_, err = setFunc{}.Execute(context.Background(), rt, &SetArgs{Device: "/media/data"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("neither error = %v", err)
	}

	// Group path builds -g argv.
	fn := setFunc{}
	if _, err := fn.Execute(context.Background(), rt, &SetArgs{
		Device: "/media/data", Group: "painters",
	}); err != nil {
		t.Fatal(err)
	}
	last2 := runner.calls[len(runner.calls)-1]
	if !reflect.DeepEqual(last2,
		[]string{"setquota", "-g", "painters", "0", "0", "0", "0", "/media/data"}) {
		t.Fatalf("group argv = %v", last2)
	}

	// Tool failure surfaces stderr through the error text.
	rt2, _ := newRT(map[string]process.CommandResult{
		"setquota": {ExitCode: 1, Stderr: []byte("nope\n")},
	})
	_, err = setFunc{}.Execute(context.Background(), rt2, &SetArgs{
		Device: "/media/data", User: "u",
	})
	if err == nil || !strings.Contains(err.Error(), "Unable to set desired quota") ||
		!strings.Contains(err.Error(), "nope") {
		t.Fatalf("failure error = %v", err)
	}
}

func TestSimpleCommands(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{})

	got, err := onFunc{}.Execute(context.Background(), rt, &OnArgs{Device: "/dev/sda1"})
	if err != nil || got != true {
		t.Fatalf("on = %v %v", got, err)
	}
	got2, err := offFunc{}.Execute(context.Background(), rt, &OffArgs{Device: "/dev/sda1"})
	if err != nil || got2 != true {
		t.Fatalf("off = %v %v", got2, err)
	}
	if !reflect.DeepEqual(runner.calls[0], []string{"quotaon", "/dev/sda1"}) ||
		!reflect.DeepEqual(runner.calls[1], []string{"quotaoff", "/dev/sda1"}) {
		t.Fatalf("on/off argv = %v", runner.calls)
	}

	// warn runs quotawarn like Salt's code does.
	warnFunc{}.Execute(context.Background(), rt, &WarnArgs{})
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-1], []string{"quotawarn"}) {
		t.Fatalf("warn argv = %v", runner.calls)
	}

	// stats parses key: value pairs.
	rt3, _ := newRT(map[string]process.CommandResult{
		"quotastats": {Stdout: []byte("Number of dquot lookups: 1234\njunkline\n")},
	})
	statsRaw, err := statsFunc{}.Execute(context.Background(), rt3, &StatsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	stats := statsRaw.(map[string]any)
	if stats["Number of dquot lookups"] != "1234" || len(stats) != 1 {
		t.Fatalf("stats = %v", stats)
	}
}

func TestGetMode(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"quotaon": {Stdout: []byte(
			"group quota on /media/data (/dev/sda1) is on\n" +
				"user quota on /media/data (/dev/sda1) is off\n")},
	})
	gotRaw, err := getModeFunc{}.Execute(context.Background(), rt, &GetModeArgs{Device: "/media/data"})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	// Rows are keyed by the mountpoint token (comps[3]), like Salt.
	bucket := got["/media/data"].(map[string]any)
	if bucket["device"] != "/dev/sda1" || bucket["group"] != "on" || bucket["user"] != "off" {
		t.Fatalf("mode row = %v", bucket)
	}

	rt2, _ := newRT(map[string]process.CommandResult{
		"quotaon": {Stdout: []byte(
			"quotaon: Cannot find mountpoint /media/data on this system right now\n")},
	})
	got2, err := getModeFunc{}.Execute(context.Background(), rt2, &GetModeArgs{Device: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got2, map[string]any{"/x": "Not found"}) {
		t.Fatalf("not found = %v", got2)
	}

	rt3, _ := newRT(map[string]process.CommandResult{
		"quotaon": {Stdout: []byte(
			"quotaon: Mountpoint path /media/data (/dev/sda1) reported disabled now\n")},
	})
	got3, err := getModeFunc{}.Execute(context.Background(), rt3, &GetModeArgs{Device: "/d"})
	if err != nil {
		t.Fatal(err)
	}
	// comps[4] carries the parenthesized device token, mirroring Salt.
	if got3.(map[string]any)["(/dev/sda1)"] != "disabled" {
		t.Fatalf("mountpoint disabled = %v", got3)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 7 {
		t.Fatalf("registered %d functions", len(reg.Names()))
	}
	for _, name := range reg.Names() {
		fn, _ := reg.Get(name)
		if c, ok := fn.(interface{ Platforms() []string }); !ok ||
			strings.Join(c.Platforms(), ",") != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}
