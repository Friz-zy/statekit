package pkg

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// yumRepoPkgListReposFunc exercises the provider's Runtime.Exec boundary
// without letting direct-provider tests read a host repository definition.
type yumRepoPkgListReposFunc struct {
	repos map[string]any
	err   error
	calls int
}

func (*yumRepoPkgListReposFunc) Name() string { return "pkg.list_repos" }
func (*yumRepoPkgListReposFunc) Args() any    { return struct{}{} }
func (f *yumRepoPkgListReposFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	f.calls++
	if _, ok := args.(*struct{}); !ok {
		return nil, errors.New("unexpected list_repos argument type")
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.repos, nil
}

type yumRepoPkgNoWriteFS struct {
	*runtime.MemoryFS
	writes int
}

func (f *yumRepoPkgNoWriteFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	f.writes++
	return f.MemoryFS.WriteFile(name, data, perm)
}

func yumRepoPkgRuntime(t *testing.T, manager string, runner process.Runner, repos map[string]any) (*runtime.Runtime, *yumRepoPkgListReposFunc) {
	t.Helper()
	registry := runtime.NewExecRegistry()
	listRepos := &yumRepoPkgListReposFunc{repos: repos}
	if err := registry.Register(listRepos); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{
		Exec: registry, Runner: runner, FS: runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{CPU: &facts.CPUFacts{Arch: "x86_64"}}),
	}, listRepos
}

func callYumRepoPkgs(ctx context.Context, manager string, rt *runtime.Runtime, args map[string]any) (any, error) {
	return (&commandProvider{spec: rpmSpec(manager)}).Yum(ctx, rt, "list_repo_pkgs", args)
}

func TestYumListRepoPkgsDirectSelectorsAndOptions(t *testing.T) {
	for _, manager := range []string{"dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			runner := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("Available Packages\ndemo.x86_64 1.9-1 updates\nother.noarch 4-1 updates\n")},
				{Stdout: []byte("demo.x86_64 1.10-1 base\n")},
			}}
			fsys := &yumRepoPkgNoWriteFS{MemoryFS: runtime.NewMemoryFS()}
			rt := &runtime.Runtime{Runner: runner, FS: fsys, Facts: factsForYUMTest()}
			cacheonly := true
			got, err := callYumRepoPkgs(context.Background(), manager, rt, map[string]any{
				"fromrepo": "updates,base", "enablerepo": "ignored", "disablerepo": "also-ignored",
				"packages": []string{"demo*"}, "cacheonly": &cacheonly, "setopt": "best=True,exclude=other",
			})
			want := map[string][]string{"demo": {"1.10-1", "1.9-1"}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			wantArgv := [][]string{
				{manager, "--quiet", "--setopt=best=True", "--setopt=exclude=other", "--showduplicates", "repository-packages", "updates", "list", "-C", "demo*"},
				{manager, "--quiet", "--setopt=best=True", "--setopt=exclude=other", "--showduplicates", "repository-packages", "base", "list", "-C", "demo*"},
			}
			if gotArgv := commandArgvFromYUM(runner.commands); !reflect.DeepEqual(gotArgv, wantArgv) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, wantArgv)
			}
			for i, command := range runner.commands {
				if command.Shell || command.MaxStdoutBytes != yumRepoPkgsOutputLimit || command.MaxStderrBytes != yumRepoPkgsOutputLimit {
					t.Fatalf("command[%d]=%#v", i, command)
				}
			}
			if fsys.writes != 0 {
				t.Fatalf("repository query mutated filesystem %d times", fsys.writes)
			}
		})
	}
}

func TestYumListRepoPkgsSetoptListAndSupportedKwargs(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("demo.x86_64 1-1 base\n")}}}
	fsys := &yumRepoPkgNoWriteFS{MemoryFS: runtime.NewMemoryFS()}
	rt := &runtime.Runtime{Runner: runner, FS: fsys, Facts: factsForYUMTest()}
	got, err := callYumRepoPkgs(context.Background(), "dnf", rt, map[string]any{
		// The legacy repo alias is a supported _get_options kwarg. It must not
		// disappear at the provider boundary when fromrepo is omitted.
		"repo": "base", "disableexcludes": "main", "branch": "stable",
		"setopt": []string{"install_weak_deps=False,keepcache=True", "best=True"},
	})
	if err != nil || !reflect.DeepEqual(got, map[string][]string{"demo": {"1-1"}}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	want := [][]string{{"dnf", "--quiet", "--disableexcludes=main", "--branch=stable", "--setopt=install_weak_deps=False,keepcache=True", "--setopt=best=True", "--showduplicates", "repository-packages", "base", "list"}}
	if gotArgv := commandArgvFromYUM(runner.commands); !reflect.DeepEqual(gotArgv, want) || fsys.writes != 0 {
		t.Fatalf("argv=%#v writes=%d", gotArgv, fsys.writes)
	}
}

func TestYumListRepoPkgsDiscoverySelectionAndScalarForms(t *testing.T) {
	runner := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("alpha.x86_64 1-1 base\n")},
		{Stdout: []byte("enabled.x86_64 2-1 disabled\n")},
	}}
	repos := map[string]any{
		"updates":  map[string]any{"enabled": "1"},
		"base":     map[string]any{},
		"disabled": map[string]any{"enabled": "0"},
	}
	rt, listRepos := yumRepoPkgRuntime(t, "dnf", runner, repos)
	got, err := callYumRepoPkgs(context.Background(), "dnf", rt, map[string]any{
		"enablerepo": []any{"disabled", "*"}, "disablerepo": "updates,*", "packages": []string{"*"},
	})
	want := map[string][]string{"alpha": {"1-1"}, "enabled": {"2-1"}}
	if err != nil || !reflect.DeepEqual(got, want) || listRepos.calls != 1 {
		t.Fatalf("got=%#v err=%v discovery calls=%d", got, err, listRepos.calls)
	}
	if gotArgv, wantArgv := commandArgvFromYUM(runner.commands), [][]string{
		{"dnf", "--quiet", "--showduplicates", "repository-packages", "base", "list", "*"},
		{"dnf", "--quiet", "--showduplicates", "repository-packages", "disabled", "list", "*"},
	}; !reflect.DeepEqual(gotArgv, wantArgv) {
		t.Fatalf("argv=%#v want=%#v", gotArgv, wantArgv)
	}

	// Salt's scalar fallback stringifies direct values. This source vector must
	// not accidentally require discovery or turn an integer into an ignored arg.
	runner = &yumRecordingRunner{results: []process.CommandResult{{}}}
	rt = &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}
	got, err = callYumRepoPkgs(context.Background(), "dnf", rt, map[string]any{"fromrepo": 1, "enablerepo": 2, "disablerepo": 3})
	if err != nil || !reflect.DeepEqual(got, map[string][]string{}) || !reflect.DeepEqual(commandArgvFromYUM(runner.commands), [][]string{{"dnf", "--quiet", "--showduplicates", "repository-packages", "1", "list"}}) {
		t.Fatalf("scalar source form got=%#v err=%v argv=%#v", got, err, commandArgvFromYUM(runner.commands))
	}
}

func TestYumListRepoPkgsByrepoLooseVersionsAndDuplicates(t *testing.T) {
	outputBase := "Available Packages\ndemo.x86_64 1.9-1 @base\ndemo.x86_64 1.10-1 @base\ndemo.x86_64 1.10-1 @base\nforeign.i686 2.0-1 base\nignored.noarch 3-1 base\n"
	outputUpdates := "demo.x86_64 1.10-1 updates\n"
	byrepo := true
	runner := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(outputBase)}, {Stdout: []byte(outputUpdates)}}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}
	got, err := callYumRepoPkgs(context.Background(), "dnf", rt, map[string]any{
		"fromrepo": []string{"base", "updates"}, "byrepo": &byrepo, "packages": []string{"demo*", "foreign.i686"},
	})
	wantByrepo := map[string]map[string][]string{
		"base":    {"demo": {"1.10-1", "1.9-1"}, "foreign.i686": {"2.0-1"}},
		"updates": {"demo": {"1.10-1"}},
	}
	if err != nil || !reflect.DeepEqual(got, wantByrepo) {
		t.Fatalf("byrepo got=%#v err=%v want=%#v", got, err, wantByrepo)
	}

	runner = &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(outputBase)}, {Stdout: []byte(outputUpdates)}}}
	rt.Runner = runner
	got, err = callYumRepoPkgs(context.Background(), "dnf", rt, map[string]any{
		"fromrepo": []string{"base", "updates"}, "packages": []string{"demo*", "foreign.i686"},
	})
	want := map[string][]string{"demo": {"1.10-1", "1.10-1", "1.9-1"}, "foreign.i686": {"2.0-1"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregate got=%#v err=%v want=%#v", got, err, want)
	}
}

func TestYumListRepoPkgsCompletedOutputAndFailureBoundaries(t *testing.T) {
	runnerErr := errors.New("runner failed")
	newRuntime := func(result process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
		runner := &yumRecordingRunner{results: []process.CommandResult{result}}
		return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}, runner
	}
	args := map[string]any{"fromrepo": "base"}

	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want any
		err  error
	}{
		{"empty", process.CommandResult{}, map[string][]string{}, nil},
		{"malformed", process.CommandResult{Stdout: []byte("orphan.x86_64 1-1\n")}, map[string][]string{}, nil},
		{"source-error", process.CommandResult{ExitCode: 1, Stdout: []byte("Error: unavailable\n")}, map[string][]string{}, nil},
		{"nonzero-parseable", process.CommandResult{ExitCode: 1, Stderr: []byte("warning"), Stdout: []byte("demo.x86_64 1-1 base\n")}, map[string][]string{"demo": {"1-1"}}, nil},
		{"runner-error", process.CommandResult{Err: runnerErr}, nil, runnerErr},
		{"output-limit", process.CommandResult{StdoutTruncated: true}, nil, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newRuntime(tc.res)
			got, err := callYumRepoPkgs(context.Background(), "dnf", rt, args)
			if tc.err != nil {
				if got != nil || !errors.Is(err, tc.err) {
					t.Fatalf("got=%#v err=%v", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			if len(runner.commands) != 1 {
				t.Fatalf("commands=%d", len(runner.commands))
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	noCall := &yumNoCallRunner{}
	rt := &runtime.Runtime{Runner: noCall, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}
	if got, err := callYumRepoPkgs(canceled, "dnf", rt, args); got != nil || !errors.Is(err, context.Canceled) || noCall.calls != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, noCall.calls)
	}
}

func TestYumListRepoPkgsPrerequisitesAndLegacyYum(t *testing.T) {
	for _, tc := range []struct {
		name string
		rt   *runtime.Runtime
	}{
		{"missing-exec", &runtime.Runtime{Runner: &yumNoCallRunner{}, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}},
		{"missing-filesystem", &runtime.Runtime{Runner: &yumNoCallRunner{}, Exec: runtime.NewExecRegistry(), Facts: factsForYUMTest()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := callYumRepoPkgs(context.Background(), "dnf", tc.rt, map[string]any{})
			if got != nil || !errors.As(err, new(*runtime.UnsupportedError)) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}

	old := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("3.4.2\n")}}}
	oldRT := &runtime.Runtime{Runner: old, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}
	if got, err := callYumRepoPkgs(context.Background(), "yum", oldRT, map[string]any{"fromrepo": "base"}); got != nil || !errors.As(err, new(*runtime.UnsupportedError)) || !reflect.DeepEqual(commandArgvFromYUM(old.commands), [][]string{{"yum", "--version"}}) {
		t.Fatalf("legacy got=%#v err=%v argv=%#v", got, err, commandArgvFromYUM(old.commands))
	}

	modern := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("3.4.3\n")}, {Stdout: []byte("demo.x86_64 1-1 base\n")}}}
	modernRT := &runtime.Runtime{Runner: modern, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}
	got, err := callYumRepoPkgs(context.Background(), "yum", modernRT, map[string]any{"fromrepo": "base"})
	if err != nil || !reflect.DeepEqual(got, map[string][]string{"demo": {"1-1"}}) || !reflect.DeepEqual(commandArgvFromYUM(modern.commands), [][]string{{"yum", "--version"}, {"yum", "--quiet", "--showduplicates", "repository-packages", "base", "list"}}) {
		t.Fatalf("modern got=%#v err=%v argv=%#v", got, err, commandArgvFromYUM(modern.commands))
	}

	for _, manager := range []string{"zypper", "tdnf"} {
		t.Run(manager, func(t *testing.T) {
			noCall := &yumNoCallRunner{}
			got, err := callYumRepoPkgs(context.Background(), manager, &runtime.Runtime{Runner: noCall, FS: runtime.NewMemoryFS(), Facts: factsForYUMTest()}, map[string]any{"fromrepo": "base"})
			if got != nil || err == nil || noCall.calls != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, noCall.calls)
			}
			if manager == "zypper" && !errors.As(err, new(*runtime.UnsupportedError)) {
				t.Fatalf("zypper error=%v", err)
			}
		})
	}
}
