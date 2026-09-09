package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperPatternsRegistryRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

func (r *zypperPatternsRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperPatternsProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	functions := []struct {
		name       string
		label      string
		prototype  any
		args       any
		argNames   []string
		results    []process.CommandResult
		wantResult any
		wantArgv   [][]string
	}{
		{
			name:      "pkg.list_patterns",
			prototype: ZypperListPatternsArgs{},
			args:      &ZypperListPatternsArgs{Refresh: zypperRegistryBoolPtr(true), Root: zypperRegistryStringPtr("/target")},
			argNames:  []string{"refresh", "root"},
			results: []process.CommandResult{
				{},
				{Stdout: []byte(`<stream><search-result><solvable-list><solvable name="base" summary="Base" status="installed"/></solvable-list></search-result></stream>`)},
			},
			wantResult: map[string]any{"base": map[string]any{"installed": true, "summary": "Base"}},
			wantArgv: [][]string{
				{"zypper", "--non-interactive", "refresh", "--force"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
			},
		},
		{
			name:      "pkg.list_installed_patterns",
			prototype: ZypperListInstalledPatternsArgs{},
			args:      &ZypperListInstalledPatternsArgs{Root: zypperRegistryStringPtr("/target")},
			argNames:  []string{"root"},
			results: []process.CommandResult{
				{Stdout: []byte("pattern() = hidden\n")},
				{Stdout: []byte(`<stream><search-result><solvable-list><solvable name="base" summary="Base" status="installed"/><solvable name="hidden" status="not-installed"/></solvable-list></search-result></stream>`)},
			},
			wantResult: map[string]any{
				"base":   map[string]any{"installed": true, "summary": "Base"},
				"hidden": map[string]any{"installed": true, "summary": "Non-visible pattern"},
			},
			wantArgv: [][]string{
				{"rpm", "--root", "/target", "-q", "--provides", "--whatprovides", "pattern()"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
			},
		},
		{
			name:      "pkg.list_installed_patterns",
			label:     "pkg.list_installed_patterns.empty-and-nested",
			prototype: ZypperListInstalledPatternsArgs{},
			args:      &ZypperListInstalledPatternsArgs{Root: zypperRegistryStringPtr("/target")},
			argNames:  []string{"root"},
			results: []process.CommandResult{
				{Stdout: []byte("pattern() = \npattern() = hidden\n")},
				{Stdout: []byte(`<stream><solvable summary="absent" status="not-installed"/><solvable name="nested" summary="outer" status="installed"><solvable name="nested" summary="inner" status="not-installed"/></solvable><solvable name="" summary="empty" status="installed"/></stream>`)},
			},
			wantResult: map[string]any{
				"":       map[string]any{"installed": true, "summary": "empty"},
				"hidden": map[string]any{"installed": true, "summary": "Non-visible pattern"},
			},
			wantArgv: [][]string{
				{"rpm", "--root", "/target", "-q", "--provides", "--whatprovides", "pattern()"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "se", "-t", "pattern"},
			},
		},
	}

	for _, tc := range functions {
		label := tc.label
		if label == "" {
			label = tc.name
		}
		t.Run(label, func(t *testing.T) {
			fn, ok := reg.Get(tc.name)
			if !ok {
				t.Fatalf("missing %s", tc.name)
			}
			strict, ok := fn.(runtime.ProviderArgsStrict)
			if !ok || !strict.ProviderArgsStrict() {
				t.Fatalf("%s is not strict", tc.name)
			}
			if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(tc.prototype) {
				t.Fatalf("canonical Args type=%v want=%v", got, reflect.TypeOf(tc.prototype))
			}
			if got, err := config.ArgumentNames(tc.prototype); err != nil || !reflect.DeepEqual(got, tc.argNames) {
				t.Fatalf("arg names=%v err=%v want=%v", got, err, tc.argNames)
			}
			if !reflect.DeepEqual(reg.ProviderCapabilities(tc.name), []string{"zypperpkg"}) {
				t.Fatalf("capabilities=%v", reg.ProviderCapabilities(tc.name))
			}

			for _, manager := range []string{"apt", "yum"} {
				runner := &zypperPatternsRegistryRunner{}
				rt := zypperRegistryRuntime(manager, runner)
				if _, err := reg.ResolveArgs(rt, tc.name); err == nil {
					t.Fatalf("%s unexpectedly resolved for %s", tc.name, manager)
				}
				if got, err := reg.Call(context.Background(), rt, tc.name, tc.args); got != nil || err == nil || len(runner.calls) != 0 {
					t.Fatalf("%s/%s got=%#v err=%v calls=%d", tc.name, manager, got, err, len(runner.calls))
				}
			}

			runner := &zypperPatternsRegistryRunner{results: append([]process.CommandResult(nil), tc.results...)}
			rt := zypperRegistryRuntime("zypper", runner)
			prototype, err := reg.ResolveArgs(rt, tc.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(tc.prototype) || !reflect.DeepEqual(prototype, tc.prototype) {
				t.Fatalf("prototype=%#v err=%v", prototype, err)
			}
			got, err := reg.Call(context.Background(), rt, tc.name, tc.args)
			if err != nil || !reflect.DeepEqual(got, tc.wantResult) || len(runner.calls) != len(tc.wantArgv) {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
			for i, command := range runner.calls {
				if argv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(argv, tc.wantArgv[i]) {
					t.Fatalf("argv[%d]=%v want=%v", i, argv, tc.wantArgv[i])
				}
			}
		})
	}

	if got := countExecName(reg.Names(), "pkg.list_patterns"); got != 1 {
		t.Fatalf("list_patterns registration count=%d", got)
	}
	if got := countExecName(reg.Names(), "pkg.list_installed_patterns"); got != 1 {
		t.Fatalf("list_installed_patterns registration count=%d", got)
	}
}

func TestZypperPatternsRegistryPreservesLexicalNamespaceSemantics(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &zypperPatternsRegistryRunner{results: []process.CommandResult{{Stdout: []byte(`<stream xmlns="urn:default" xmlns:ns="urn:prefixed"><ns:solvable name="ignored" summary="Ignored" status="installed"/><solvable name="nested" summary="outer" status="installed"><solvable name="nested" summary="inner" status="not-installed"/></solvable><solvable name="default" summary="Default" status="installed"/></stream>`)}}}
	rt := zypperRegistryRuntime("zypper", runner)
	got, err := reg.Call(context.Background(), rt, "pkg.list_patterns", &ZypperListPatternsArgs{})
	want := map[string]any{
		"default": map[string]any{"installed": true, "summary": "Default"},
		"nested":  map[string]any{"installed": false, "summary": "inner"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d want=%#v", got, err, len(runner.calls), want)
	}
	if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "se", "-t", "pattern"}) {
		t.Fatalf("argv=%v", argv)
	}
}

func zypperRegistryBoolPtr(value bool) *bool       { return &value }
func zypperRegistryStringPtr(value string) *string { return &value }

func countExecName(names []string, want string) int {
	count := 0
	for _, name := range names {
		if name == want {
			count++
		}
	}
	return count
}
