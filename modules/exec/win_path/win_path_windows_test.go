//go:build windows

package win_path

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type pathRunner struct{ calls []process.Command }

func (r *pathRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "reg.exe" && len(command.Args) > 1 && command.Args[0] == "query" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("PATH    REG_EXPAND_SZ    C:\\A;C:\\B;\r\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsPathRegistryAndNormalization(t *testing.T) {
	runner := &pathRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	paths, err := getSystemPath(context.Background(), rt)
	if err != nil || len(paths) != 2 || paths[0] != `C:\A` || paths[1] != `C:\B` {
		t.Fatalf("system path = %v %v", paths, err)
	}
	res, err := existsFunc{}.Execute(context.Background(), rt, &existsArgs{Path: `c:\a\`})
	if err != nil || res != true {
		t.Fatalf("exists = %v %v", res, err)
	}
	if result, err := (addFunc{}).Execute(context.Background(), rt, &addArgs{Path: "."}); err != nil || result != false {
		t.Fatalf("dot add = %v %v", result, err)
	}
}

func TestWindowsPathOrderingAndMutation(t *testing.T) {
	paths, changed := reorderPath([]string{"A", "B"}, "C", nil)
	if !changed || !strings.EqualFold(strings.Join(paths, ";"), "A;B;C") {
		t.Fatalf("append = %v %v", paths, changed)
	}
	paths, changed = reorderPath(paths, "C", intPtrPath(0))
	if !changed || !strings.EqualFold(strings.Join(paths, ";"), "C;A;B") {
		t.Fatalf("index move = %v %v", paths, changed)
	}
	paths, changed = removePath(paths, `a`)
	if !changed || !strings.EqualFold(strings.Join(paths, ";"), "C;B") {
		t.Fatalf("remove = %v %v", paths, changed)
	}

	oldGet, oldSet := localPathGet, localPathSet
	defer func() { localPathGet, localPathSet = oldGet, oldSet }()
	local := `C:\A;C:\B`
	localPathGet = func() string { return local }
	localPathSet = func(value string) error { local = value; return nil }
	runner := &pathRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := addFunc{}.Execute(context.Background(), rt, &addArgs{Path: `C:\C`, Index: intPtrPath(0), Rehash: boolPtrPath(false)})
	if err != nil || res != true || !strings.EqualFold(local, `C:\C;C:\A;C:\B`) {
		t.Fatalf("add = %v %v local=%q", res, err, local)
	}
	res, err = removeFunc{}.Execute(context.Background(), rt, &removeArgs{Path: `c:\c`, Rehash: boolPtrPath(false)})
	if err != nil || res != true || !strings.EqualFold(local, `C:\A;C:\B`) {
		t.Fatalf("remove = %v %v local=%q", res, err, local)
	}
}

func intPtrPath(value int) *int    { return &value }
func boolPtrPath(value bool) *bool { return &value }
