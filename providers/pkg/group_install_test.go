package pkg_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	execpkg "github.com/friz-zy/statekit/modules/exec/pkg"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

const groupInstallOutputLimit = 1 << 20

type groupInstallRunner struct {
	commands []process.Command
	results  []process.CommandResult
	afterRun func(int)
}

func (r *groupInstallRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	call := len(r.commands)
	r.commands = append(r.commands, command)
	result := process.CommandResult{}
	if len(r.results) > 0 {
		result, r.results = r.results[0], r.results[1:]
	}
	if r.afterRun != nil {
		r.afterRun(call)
	}
	return result
}

type groupInstallNoCallRunner struct{ calls int }

func (r *groupInstallNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{}
}

func newGroupInstallRuntime(t *testing.T, manager string, runner process.Runner) *runtime.Runtime {
	t.Helper()
	exec := runtime.NewExecRegistry()
	if err := execpkg.Register(exec); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	return &runtime.Runtime{
		Exec:      exec,
		Providers: providers,
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: facts.FamilyRedHat},
			CPU:     &facts.CPUFacts{Arch: "x86_64"},
		}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
}

func directYumProvider(t *testing.T, rt *runtime.Runtime) pkgprovider.YumProvider {
	t.Helper()
	provider, err := pkgprovider.Resolve(rt)
	if err != nil {
		t.Fatal(err)
	}
	yum, ok := provider.(pkgprovider.YumProvider)
	if !ok {
		t.Fatalf("provider %T does not expose Yum", provider)
	}
	return yum
}

func groupInstallInfo(name string, mandatory, defaults []string) string {
	var out strings.Builder
	out.WriteString("Group: ")
	out.WriteString(name)
	out.WriteString("\nMandatory Packages:\n")
	for _, member := range mandatory {
		out.WriteString(" ")
		out.WriteString(member)
		out.WriteString("\n")
	}
	out.WriteString("Default Packages:\n")
	for _, member := range defaults {
		out.WriteString(" ")
		out.WriteString(member)
		out.WriteString("\n")
	}
	return out.String()
}

func groupInstallListOutput(names []string) string {
	var out strings.Builder
	for _, name := range names {
		out.WriteString(name)
		out.WriteString(" 2\n")
	}
	return out.String()
}

func groupInstallArgv(commands []process.Command) [][]string {
	argv := make([][]string, 0, len(commands))
	for _, command := range commands {
		argv = append(argv, append([]string{command.Name}, command.Args...))
	}
	return argv
}

func assertGroupInstallBounds(t *testing.T, commands []process.Command) {
	t.Helper()
	for i, command := range commands {
		if command.Shell || command.MaxStdoutBytes != groupInstallOutputLimit || command.MaxStderrBytes != groupInstallOutputLimit {
			t.Fatalf("command[%d] is not bounded shell-free argv: %#v", i, command)
		}
	}
}

func cloneGroupInstallArgs(args map[string]any) map[string]any {
	copy := make(map[string]any, len(args))
	for key, value := range args {
		switch value := value.(type) {
		case []string:
			copy[key] = append([]string(nil), value...)
		case []any:
			copy[key] = append([]any(nil), value...)
		default:
			copy[key] = value
		}
	}
	return copy
}

func groupInstallChanges(names []string) map[string]any {
	changes := make(map[string]any, len(names))
	for _, name := range names {
		changes[name] = map[string]any{"old": "", "new": "2"}
	}
	return changes
}

func TestYumGroupInstallDirectNormalizesInputsAndUsesOneTransaction(t *testing.T) {
	groups := map[string]struct {
		mandatory []string
		defaults  []string
	}{
		"Group One": {
			mandatory: []string{"mandatory", "already", "dupe"},
			defaults:  []string{"default", "skip-one", "dupe"},
		},
		"Group Two": {
			mandatory: []string{"second", "dupe"},
			defaults:  []string{"default-two", "skip-two", "already"},
		},
	}
	cases := []struct {
		name       string
		args       map[string]any
		groupNames []string
		targets    []string
	}{
		{
			name:       "scalar group and scalar skip/include",
			args:       map[string]any{"name": "Group One", "skip": "skip-one", "include": "include-one"},
			groupNames: []string{"Group One"},
			targets:    []string{"default", "dupe", "include-one", "mandatory"},
		},
		{
			name:       "comma groups and comma skip/include",
			args:       map[string]any{"name": "Group One,Group Two", "skip": "skip-one,skip-two", "include": "include-one,include-two"},
			groupNames: []string{"Group One", "Group Two"},
			targets:    []string{"default", "default-two", "dupe", "include-one", "include-two", "mandatory", "second"},
		},
		{
			name:       "list groups and list skip/include",
			args:       map[string]any{"name": []any{"Group One", "Group Two"}, "skip": []any{"skip-one", "skip-two"}, "include": []string{"include-one", "include-two"}},
			groupNames: []string{"Group One", "Group Two"},
			targets:    []string{"default", "default-two", "dupe", "include-one", "include-two", "mandatory", "second"},
		},
	}

	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, tc := range cases {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				results := make([]process.CommandResult, 0, len(tc.groupNames)+4)
				for _, name := range tc.groupNames {
					group := groups[name]
					results = append(results, process.CommandResult{Stdout: []byte(groupInstallInfo(name, group.mandatory, group.defaults))})
				}
				results = append(results,
					process.CommandResult{Stdout: []byte("already 1\n")},
					process.CommandResult{Stdout: []byte("already 1\n")},
					process.CommandResult{},
					process.CommandResult{Stdout: []byte("already 1\n" + groupInstallListOutput(tc.targets))},
				)
				runner := &groupInstallRunner{results: results}
				rt := newGroupInstallRuntime(t, manager, runner)
				args := cloneGroupInstallArgs(tc.args)
				before := cloneGroupInstallArgs(args)
				got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", args)
				if err != nil || !reflect.DeepEqual(got, groupInstallChanges(tc.targets)) || !reflect.DeepEqual(args, before) {
					t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
				}

				want := make([][]string, 0, len(tc.groupNames)+4)
				for _, name := range tc.groupNames {
					want = append(want, []string{manager, "--quiet", "groupinfo", name})
				}
				list := []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
				want = append(want, list, list, append([]string{manager, "--assumeyes", "install"}, tc.targets...), list)
				if gotArgv := groupInstallArgv(runner.commands); !reflect.DeepEqual(gotArgv, want) {
					t.Fatalf("argv=%#v want=%#v", gotArgv, want)
				}
				assertGroupInstallBounds(t, runner.commands)
			})
		}
	}
}

func TestYumGroupInstallNoTargetsAndTestModeDoNotMutate(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager+"/already-installed", func(t *testing.T) {
			runner := &groupInstallRunner{results: []process.CommandResult{
				{Stdout: []byte(groupInstallInfo("Demo", []string{"already"}, []string{"also-already"}))},
				{Stdout: []byte("already 1\nalso-already 1\n")},
			}}
			rt := newGroupInstallRuntime(t, manager, runner)
			got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "Demo"})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			want := [][]string{{manager, "--quiet", "groupinfo", "Demo"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}}
			if gotArgv := groupInstallArgv(runner.commands); !reflect.DeepEqual(gotArgv, want) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, want)
			}
			assertGroupInstallBounds(t, runner.commands)
		})

		t.Run(manager+"/test-mode", func(t *testing.T) {
			runner := &groupInstallRunner{results: []process.CommandResult{
				{Stdout: []byte(groupInstallInfo("Demo", []string{"pending"}, nil))},
				{},
			}}
			rt := newGroupInstallRuntime(t, manager, runner)
			rt.Options.Test = true
			got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "Demo", "refresh": true})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			want := [][]string{{manager, "--quiet", "groupinfo", "Demo"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}}
			if gotArgv := groupInstallArgv(runner.commands); !reflect.DeepEqual(gotArgv, want) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, want)
			}
			assertGroupInstallBounds(t, runner.commands)
		})
	}
}

func TestYumGroupInstallForwardsRefreshThroughBoundedTransaction(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			runner := &groupInstallRunner{results: []process.CommandResult{
				{Stdout: []byte(groupInstallInfo("Demo", []string{"pending"}, nil))},
				{}, {}, {}, {},
				{Stdout: []byte("pending 2\n")},
			}}
			rt := newGroupInstallRuntime(t, manager, runner)
			got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "Demo", "refresh": true})
			if err != nil || !reflect.DeepEqual(got, groupInstallChanges([]string{"pending"})) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			refresh := []string{manager, "makecache", "--timer"}
			if manager == "yum" {
				refresh = []string{"yum", "-q", "makecache"}
			}
			list := []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
			want := [][]string{
				{manager, "--quiet", "groupinfo", "Demo"},
				list,
				refresh,
				list,
				{manager, "--assumeyes", "install", "pending"},
				list,
			}
			if gotArgv := groupInstallArgv(runner.commands); !reflect.DeepEqual(gotArgv, want) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, want)
			}
			assertGroupInstallBounds(t, runner.commands)
		})
	}
}

type malformedGroupInfoFunc struct{}

func (malformedGroupInfoFunc) Name() string { return "pkg.group_info" }
func (malformedGroupInfoFunc) Args() any    { return pkgprovider.YumGroupInfoArgs{} }
func (malformedGroupInfoFunc) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return map[string]any{"mandatory": "not-a-list", "default": []string{}}, nil
}

func TestYumGroupInstallRejectsMissingMalformedAndInvalidInputsBeforeMutation(t *testing.T) {
	t.Run("missing group stops before installed query", func(t *testing.T) {
		runner := &groupInstallRunner{results: []process.CommandResult{{Stdout: []byte("not group metadata\n")}}}
		rt := newGroupInstallRuntime(t, "yum", runner)
		got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "missing"})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("got=%#v err=%v commands=%#v", got, err, runner.commands)
		}
		assertGroupInstallBounds(t, runner.commands)
	})

	t.Run("malformed registered group info stops before runner", func(t *testing.T) {
		runner := &groupInstallNoCallRunner{}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		exec := runtime.NewExecRegistry()
		if err := exec.Register(malformedGroupInfoFunc{}); err != nil {
			t.Fatal(err)
		}
		rt := &runtime.Runtime{
			Exec: exec, Providers: providers,
			Facts: facts.ForTesting(facts.Overrides{Package: "yum", OS: &facts.OSFacts{Family: facts.FamilyRedHat}}),
			Runner: runner,
		}
		got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "Demo"})
		if got != nil || err == nil || runner.calls != 0 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, runner.calls)
		}
	})

	invalid := []map[string]any{
		{"name": nil},
		{"name": ""},
		{"name": ","},
		{"name": 1},
		{"name": []any{"Demo", 1}},
		{"name": "bad\nname"},
		{"name": "Demo", "skip": 1},
		{"name": "Demo", "include": []any{"bad\x00name"}},
		{"name": "Demo", "refresh": "true"},
		{"name": "Demo", "version": "1"},
	}
	for _, args := range invalid {
		runner := &groupInstallNoCallRunner{}
		rt := newGroupInstallRuntime(t, "dnf", runner)
		got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", args)
		if got != nil || err == nil || runner.calls != 0 {
			t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, runner.calls)
		}
	}
}

func TestYumGroupInstallMutationFailureCancellationAndOutputLimitSkipPostQuery(t *testing.T) {
	mutationResults := []struct {
		name  string
		result process.CommandResult
		check func(string, error) bool
	}{
		{
			name: "nonzero",
			result: process.CommandResult{ExitCode: 9, Stderr: []byte("install failed")},
			check: func(manager string, err error) bool { return err != nil && err.Error() == manager+" exited with code 9: install failed" },
		},
		{
			name: "runner error",
			result: process.CommandResult{Err: errors.New("runner failed")},
			check: func(_ string, err error) bool { return err != nil && err.Error() == "runner failed" },
		},
		{
			name: "oversized output",
			result: process.CommandResult{Stdout: make([]byte, groupInstallOutputLimit+1)},
			check: func(_ string, err error) bool { return errors.Is(err, process.ErrOutputLimit) },
		},
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, tc := range mutationResults {
			t.Run(manager+"/"+tc.name, func(t *testing.T) {
				runner := &groupInstallRunner{results: []process.CommandResult{
					{Stdout: []byte(groupInstallInfo("Demo", []string{"pending"}, nil))},
					{}, {}, tc.result,
					{Stdout: []byte("post-query-must-not-run 1\n")},
				}}
				rt := newGroupInstallRuntime(t, manager, runner)
				got, err := directYumProvider(t, rt).Yum(context.Background(), rt, "group_install", map[string]any{"name": "Demo"})
				if got != nil || !tc.check(manager, err) || len(runner.commands) != 4 {
					t.Fatalf("got=%#v err=%v commands=%#v", got, err, groupInstallArgv(runner.commands))
				}
				assertGroupInstallBounds(t, runner.commands)
			})
		}
	}

	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager+"/cancellation after mutation skips post query", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &groupInstallRunner{results: []process.CommandResult{
				{Stdout: []byte(groupInstallInfo("Demo", []string{"pending"}, nil))},
				{}, {}, {},
				{Stdout: []byte("post-query-must-not-run 1\n")},
			}, afterRun: func(call int) {
				if call == 3 {
					cancel()
				}
			}}
			rt := newGroupInstallRuntime(t, manager, runner)
			got, err := directYumProvider(t, rt).Yum(ctx, rt, "group_install", map[string]any{"name": "Demo"})
			if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 4 {
				t.Fatalf("got=%#v err=%v commands=%#v", got, err, groupInstallArgv(runner.commands))
			}
			assertGroupInstallBounds(t, runner.commands)
		})
	}
}
