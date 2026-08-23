package file

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

func newExtrasRT() *runtime.Runtime {
	return testRT()
}

func TestSearchAndContainsRegex(t *testing.T) {
	rt := newExtrasRT()
	rt.FS.MkdirAll("/logs", 0o755)
	rt.FS.WriteFile("/logs/app.log", []byte("INFO started\nERROR boom\n"), 0o644)

	value, err := (searchFunc{}).Execute(context.Background(), rt, &searchArgs{
		Path: "/logs/app.log", Pattern: `^ERROR\s+\w+`,
	})
	if err != nil || value != true {
		t.Fatalf("search = %v, %v", value, err)
	}
	value, _ = containsRegexFunc{}.Execute(context.Background(), rt, &containsRegexArgs{
		Path: "/logs/app.log", Regex: "FATAL",
	})
	if value != false {
		t.Fatal("contains_regex must be false without FATAL")
	}
}

func TestReplaceWithBackupAndCount(t *testing.T) {
	rt := newExtrasRT()
	rt.FS.MkdirAll("/conf", 0o755)
	rt.FS.WriteFile("/conf/a.conf", []byte("alpha beta alpha"), 0o640)

	applied, err := (replaceFunc{}).Execute(context.Background(), rt, &replaceArgs{
		Path: "/conf/a.conf", Pattern: "alpha", Repl: "omega", Count: 1, Backup: true,
	})
	if err != nil || applied != true {
		t.Fatalf("replace = %v, %v", applied, err)
	}
	data, _ := rt.FS.ReadFile("/conf/a.conf")
	if string(data) != "omega beta alpha" {
		t.Fatalf("count=1 replace wrong: %q", data)
	}
	backupData, _ := rt.FS.ReadFile("/conf/a.conf.bak")
	if string(backupData) != "alpha beta alpha" {
		t.Fatalf("backup missing or wrong: %q", backupData)
	}
	info, _ := rt.FS.Stat("/conf/a.conf")
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v", info.Mode())
	}
}

func TestReplaceNoMatchReportsFalse(t *testing.T) {
	rt := newExtrasRT()
	rt.FS.WriteFile("/f", []byte("static"), 0o644)
	applied, _ := replaceFunc{}.Execute(context.Background(), rt, &replaceArgs{
		Path: "/f", Pattern: "nomatch", Repl: "x",
	})
	if applied != false {
		t.Fatalf("no-match must report false, got %v", applied)
	}
}

func TestChownResolvesRoot(t *testing.T) {
	rt := newExtrasRT()
	rt.FS.WriteFile("/owned", []byte("x"), 0o644)
	if _, err := (chownFunc{}).Execute(context.Background(), rt, &chownArgs{
		Path: "/owned", User: "root", Group: "root",
	}); err != nil {
		t.Fatalf("chown root: %v", err)
	}
	if _, err := (chownFunc{}).Execute(context.Background(), rt, &chownArgs{
		Path: "/owned", User: "no-such-user-xyz",
	}); err == nil {
		t.Fatal("unknown user must fail")
	}
}
