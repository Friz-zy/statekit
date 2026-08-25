package npm

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	script []process.CommandResult
	calls  [][]string
	dirs   []string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	f.dirs = append(f.dirs, cmd.Dir)
	if len(f.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := f.script[0]
	f.script = f.script[1:]
	return next
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	return rt, rt.Runner.(*fakeRunner)
}

func TestNpmInstallLocal(t *testing.T) {
	rt, runner := newRT()
	(installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Pkg: "left-pad@1.0.0", Cwd: "/app",
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "npm install left-pad@1.0.0" {
		t.Fatalf("argv = %q", got)
	}
	if runner.dirs[len(runner.dirs)-1] != "/app" {
		t.Fatalf("cwd not applied")
	}
}

func TestNpmListParses(t *testing.T) {
	rt, runner := newRT()
	runner.script = []process.CommandResult{
		{Stdout: []byte(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`), ExitCode: 0},
	}
	out, err := (listFunc{}).Execute(context.Background(), rt, &ListArgs{})
	if err != nil || !strings.Contains(out.(string), "lodash") {
		t.Fatalf("list = %v, %v", out, err)
	}
}

// Cache-trio tests pinning argv and return shapes from npm.py.
func TestCachePath(t *testing.T) {
	rt, runner := newRT()
	runner.script = []process.CommandResult{{Stdout: []byte("/home/user/.npm\n")}}
	got, err := (cachePathFunc{}).Execute(context.Background(), rt, &CachePathArgs{})
	if err != nil || got != "/home/user/.npm" {
		t.Fatalf("cache_path = %#v, %v", got, err)
	}
	if !equalSliceN(runner.calls[0], []string{"npm", "config", "get", "cache"}) {
		t.Fatalf("argv = %#v", runner.calls[0])
	}
}

func TestCacheList(t *testing.T) {
	rt, runner := newRT()
	runner.script = []process.CommandResult{{Stdout: []byte("empty")}}
	got, _ := (cacheListFunc{}).Execute(context.Background(), rt, &CacheListArgs{})
	if got != "empty" {
		t.Fatalf("cache_list = %#v", got)
	}

	runner.script = []process.CommandResult{{Stdout: []byte("~/.npm/lodash")}}
	got, _ = (cacheListFunc{}).Execute(context.Background(), rt,
		&CacheListArgs{Path: strPtrNP("lodash")})
	if got != "~/.npm/lodash" {
		t.Fatalf("cache_list path = %#v", got)
	}

	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("boom\n")}}
	listFn := cacheListFunc{}
	_, listErr := listFn.Execute(context.Background(), rt, &CacheListArgs{})
	if listErr == nil || listErr.Error() != "boom" {
		t.Fatalf("failure error = %v", listErr)
	}
}

func TestCacheClean(t *testing.T) {
	rt, runner := newRT()
	got, err := (cacheCleanFunc{}).Execute(context.Background(), rt,
		&CacheCleanArgs{Force: true})
	if err != nil || got != true {
		t.Fatalf("cache_clean = %#v, %v", got, err)
	}
	want := []string{"npm", "cache", "clean", "--force"}
	if len(runner.calls) != 1 || !equalSliceN(runner.calls[0], want) {
		t.Fatalf("argv = %#v", runner.calls[0])
	}

	got, err = (cacheCleanFunc{}).Execute(context.Background(), rt,
		&CacheCleanArgs{Path: strPtrNP("lodash")})
	if err != nil || got != true {
		t.Fatalf("path clean = %#v, %v", got, err)
	}
	want = []string{"npm", "cache", "clean", "lodash"}
	if !equalSliceN(runner.calls[len(runner.calls)-1], want) {
		t.Fatalf("path clean argv = %#v", runner.calls[len(runner.calls)-1])
	}

	runner.script = []process.CommandResult{{ExitCode: 1}}
	got, err = (cacheCleanFunc{}).Execute(context.Background(), rt, &CacheCleanArgs{})
	if err != nil || got != false {
		t.Fatalf("failed clean = %#v, %v", got, err)
	}
}

func equalSliceN(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func strPtrNP(s string) *string { return &s }
