package differential_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	execincron "github.com/friz-zy/statekit/modules/exec/incron"
	execlogrotate "github.com/friz-zy/statekit/modules/exec/logrotate"
	execout "github.com/friz-zy/statekit/modules/exec/out"
)

// R4.4 scope-pass tests: ret reports its returner exclusion; out renders
// through the supported outputters; incron manages tabs over the
// injectable FS; logrotate parses, gets and sets conf values.

func TestRetExclusions(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"ret.get_jid", "ret.get_fun", "ret.get_jids", "ret.get_minions"} {
		if _, ok := rt.Exec.Get(name); !ok {
			t.Fatalf("%s not registered", name)
		}
		fn, _ := rt.Exec.Get(name)
		res, callErr := fn.Execute(ctx, rt, map[string]any{})
		if res != nil || callErr == nil {
			t.Fatalf("%s should surface UnsupportedError", name)
		}
	}
}

func TestOutFormatters(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	data := map[string]any{"key": "value", "n": 1.0}

	// json format via registry.
	outFn := execout.OutFormatFunc{}
	res, ferr := outFn.Execute(ctx, rt, &execout.OutFormatArgs{Data: data, Out: "json"})
	if ferr != nil {
		t.Fatal(ferr)
	}
	s := res.(string)
	if !strings.Contains(s, `"key"`) || !strings.Contains(s, `"value"`) {
		t.Fatalf("json render = %q", s)
	}

	// nested default.
	res2, _ := outFn.Execute(ctx, rt, &execout.OutFormatArgs{Data: data})
	nested := res2.(string)
	if !strings.Contains(nested, "|_ key:") || !strings.Contains(nested, "value") {
		t.Fatalf("nested render = %q", nested)
	}

	// unknown outputter surfaces UnsupportedError.
	if _, err := outFn.Execute(ctx, rt, &execout.OutFormatArgs{Data: data, Out: "highstate"}); err == nil {
		t.Fatalf("unknown outputter accepted")
	}
}

func TestIncronLifecycle(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	scratch := filepath.Join(t.TempDir(), "incron")
	execincron.SetPaths(filepath.Join(scratch, "etc", "incron.d")+"/",
		filepath.Join(scratch, "var", "spool", "incron")+"/")
	defer func() { execincron.SetPaths("/etc/incron.d/", "/var/spool/incron/") }()

	// set_job on the system tab creates the file and returns "new".
	setFn := execincron.SetJobFunc{}
	got, err := setFn.Execute(ctx, rt, &execincron.SetJobArgs{
		User: "system", Path: "/var/log/app", Mask: "IN_MODIFY", Cmd: "logger hit",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "new" {
		t.Fatalf("set_job = %#v", got)
	}

	// Idempotent re-set returns "present".
	got, err = setFn.Execute(ctx, rt, &execincron.SetJobArgs{
		User: "system", Path: "/var/log/app", Mask: "IN_MODIFY", Cmd: "logger hit",
	})
	if err != nil || got != "present" {
		t.Fatalf("idempotent set_job = %#v, %v", got, err)
	}

	// list_tab shows the entry.
	listFn := execincron.ListTabFunc{}
	tabRes, lerr := listFn.Execute(ctx, rt, &execincron.ListTabArgs{User: "system"})
	if lerr != nil {
		t.Fatal(lerr)
	}
	tab := tabRes.(map[string]any)
	crons := tab["crons"].([]map[string]string)
	if len(crons) != 1 || crons[0]["path"] != "/var/log/app" ||
		crons[0]["mask"] != "IN_MODIFY" || crons[0]["cmd"] != "logger hit" {
		t.Fatalf("list_tab = %#v", crons)
	}

	// Invalid mask surfaces the verbatim message.
	got, err = setFn.Execute(ctx, rt, &execincron.SetJobArgs{
		User: "system", Path: "/x", Mask: "IN_BOGUS", Cmd: "c",
	})
	if err != nil || got != "Invalid mask type: IN_BOGUS" {
		t.Fatalf("invalid mask = %#v, %v", got, err)
	}

	// rm_job removes and reports.
	rmFn := execincron.RmJobFunc{}
	got, err = rmFn.Execute(ctx, rt, &execincron.RmJobArgs{
		User: "system", Path: "/var/log/app", Mask: "IN_MODIFY", Cmd: "logger hit",
	})
	if err != nil || got != "removed" {
		t.Fatalf("rm_job = %#v, %v", got, err)
	}
	got, err = rmFn.Execute(ctx, rt, &execincron.RmJobArgs{
		User: "system", Path: "/var/log/app", Mask: "IN_MODIFY", Cmd: "logger hit",
	})
	if err != nil || got != "absent" {
		t.Fatalf("second rm_job = %#v, %v", got, err)
	}
}

func TestLogrotateConfCycle(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	confFile := filepath.Join(t.TempDir(), "logrotate.conf")
	rt.FS.WriteFile(confFile, []byte(strings.Join([]string{
		"weekly",
		"rotate 4",
		"",
		"/var/log/wtmp {",
		"    monthly",
		"    create 0664 root utmp",
		"    rotate 1",
		"}",
		"",
		"# comment",
		"missingok",
		"",
	}, "\n")), 0o644)

	showFn := execlogrotate.ShowConfFunc{}
	confRes, cerr := showFn.Execute(ctx, rt, &execlogrotate.ShowConfArgs{
		ConfFile: strPtr(confFile),
	})
	if cerr != nil {
		t.Fatal(cerr)
	}
	conf := confRes.(map[string]any)
	if conf["weekly"] != true {
		t.Fatalf("weekly = %#v", conf["weekly"])
	}
	if conf["rotate"] != 4 {
		t.Fatalf("rotate = %#v", conf["rotate"])
	}
	wtmp, ok := conf["/var/log/wtmp"].(map[string]any)
	if !ok || wtmp["monthly"] != true || wtmp["create"] != "0664 root utmp" {
		t.Fatalf("wtmp stanza = %#v", wtmp)
	}

	getFn := execlogrotate.GetFunc{}
	got, gerr := getFn.Execute(ctx, rt, &execlogrotate.GetArgs{
		Key: "rotate", ConfFile: strPtr(confFile),
	})
	if gerr != nil || got != 4 {
		t.Fatalf("get rotate = %#v, %v", got, gerr)
	}
	got, gerr = getFn.Execute(ctx, rt, &execlogrotate.GetArgs{
		Key: "/var/log/wtmp", Value: strPtr("create"), ConfFile: strPtr(confFile),
	})
	if gerr != nil || got != "0664 root utmp" {
		t.Fatalf("get create = %#v, %v", got, gerr)
	}

	// set_ updates the scalar line in place.
	setFn := execlogrotate.SetFunc{}
	okRaw, serr := setFn.Execute(ctx, rt, &execlogrotate.SetArgs{
		Key: "rotate", Value: 6, ConfFile: strPtr(confFile),
	})
	ok, okOk := okRaw.(bool)
	if serr != nil || !okOk || !ok {
		t.Fatalf("set rotate = %#v, %v", okRaw, serr)
	}
	data, rerr := rt.FS.ReadFile(confFile)
	_ = rerr
	if !strings.Contains(string(data), "rotate 6\n") {
		t.Fatalf("rotate 6 missing:\n%s", string(data))
	}
}

func strPtr(s string) *string { return &s }
