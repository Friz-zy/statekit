package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execcmd "github.com/friz-zy/statekit/modules/exec/cmd"
)

func newRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	if err := execcmd.Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt
}

func TestRunStateExecutesAndReports(t *testing.T) {
	rt := newRT()
	res := (runFunc{}).Apply(context.Background(), rt, &runArgs{Name: "printf hello"})
	if !res.Succeeded() || res.Changes["retcode"].(int) != 0 {
		t.Fatalf("run result wrong: %+v", res)
	}
	if res.Changes["stdout"] != "hello" {
		t.Fatalf("stdout change = %v", res.Changes["stdout"])
	}

	failed := (runFunc{}).Apply(context.Background(), rt, &runArgs{Name: "sh -c 'exit 3'"})
	if failed.Succeeded() {
		t.Fatal("failing command must produce result false")
	}
	if failed.Changes["retcode"].(int) != 3 {
		t.Fatalf("retcode = %v", failed.Changes["retcode"])
	}
}

func TestRunStateCreatesSkipAndTestMode(t *testing.T) {
	rt := newRT()
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/hostname", []byte("host"), 0o644)
	skip := (runFunc{}).Apply(context.Background(), rt, &runArgs{
		Name: "/bin/echo done", Creates: []string{"/etc/hostname"},
	})
	if !skip.Succeeded() || skip.Changed() {
		t.Fatalf("creates skip wrong: %+v", skip)
	}
	if !strings.Contains(skip.Comment, "exists") {
		t.Fatalf("skip comment = %q", skip.Comment)
	}

	pending := (runFunc{}).Apply(context.Background(), rt, &runArgs{
		Name: "touch /tmp/x", Test: true,
	})
	if pending.Result != nil || pending.Changes["cmd"] != "touch /tmp/x" {
		t.Fatalf("test mode wrong: %+v", pending)
	}
}
