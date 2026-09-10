package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperProductsRegistryRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

func (r *zypperProductsRegistryRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperListProductsProviderAwareRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	functions := []struct {
		name       string
		args       any
		argNames   []string
		results    []process.CommandResult
		wantResult any
		wantArgv   [][]string
	}{
		{
			name:     "pkg.list_products",
			args:     &ZypperListProductsArgs{All: zypperRegistryBoolPtr(true), Refresh: zypperRegistryBoolPtr(true), Root: zypperRegistryStringPtr("/target")},
			argNames: []string{"all", "refresh", "root"},
			results: []process.CommandResult{
				{},
				{Stdout: []byte(`<stream><product-list><product name="SLES" version="15-SP4" isbase="true" installed="1" productline="SLES"><endoflife text="2028-07-31" time_t="1853904000"/><description>SUSE Linux</description></product></product-list></stream>`)},
			},
			wantResult: []any{map[string]any{
				"name": "SLES", "version": "15-SP4", "isbase": true, "installed": true, "productline": "SLES",
				"eol": "2028-07-31", "eol_t": int64(1853904000), "description": "SUSE Linux",
			}},
			wantArgv: [][]string{
				{"zypper", "--non-interactive", "refresh", "--force"},
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "products"},
			},
		},
		{
			name:     "pkg.list_products",
			args:     &ZypperListProductsArgs{},
			argNames: []string{"all", "refresh", "root"},
			results: []process.CommandResult{
				{Stdout: []byte(`<stream><product-list/></stream>`)},
			},
			wantResult: []any{},
			wantArgv: [][]string{
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--disable-repositories", "products", "-i"},
			},
		},
	}

	for _, tc := range functions {
		t.Run(tc.name, func(t *testing.T) {
			fn, ok := reg.Get(tc.name)
			if !ok {
				t.Fatalf("missing %s", tc.name)
			}
			strict, ok := fn.(runtime.ProviderArgsStrict)
			if !ok || !strict.ProviderArgsStrict() {
				t.Fatalf("%s is not strict", tc.name)
			}
			if got := reflect.TypeOf(fn.Args()); got != reflect.TypeOf(ZypperListProductsArgs{}) {
				t.Fatalf("canonical Args type=%v", got)
			}
			if got, err := config.ArgumentNames(ZypperListProductsArgs{}); err != nil || !reflect.DeepEqual(got, tc.argNames) {
				t.Fatalf("arg names=%v err=%v want=%v", got, err, tc.argNames)
			}
			if !reflect.DeepEqual(reg.ProviderCapabilities(tc.name), []string{"zypperpkg"}) {
				t.Fatalf("capabilities=%v", reg.ProviderCapabilities(tc.name))
			}

			for _, manager := range []string{"apt", "yum"} {
				runner := &zypperProductsRegistryRunner{}
				rt := zypperRegistryRuntime(manager, runner)
				if _, err := reg.ResolveArgs(rt, tc.name); err == nil {
					t.Fatalf("%s unexpectedly resolved for %s", tc.name, manager)
				}
				if got, err := reg.Call(context.Background(), rt, tc.name, tc.args); got != nil || err == nil || len(runner.calls) != 0 {
					t.Fatalf("%s/%s got=%#v err=%v calls=%d", tc.name, manager, got, err, len(runner.calls))
				}
			}

			runner := &zypperProductsRegistryRunner{results: append([]process.CommandResult(nil), tc.results...)}
			rt := zypperRegistryRuntime("zypper", runner)
			prototype, err := reg.ResolveArgs(rt, tc.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(ZypperListProductsArgs{}) || !reflect.DeepEqual(prototype, ZypperListProductsArgs{}) {
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

	if got := countExecName(reg.Names(), "pkg.list_products"); got != 1 {
		t.Fatalf("list_products registration count=%d", got)
	}
}

func TestZypperListProductsRegistryDefaultsPassThroughProvider(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &zypperProductsRegistryRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><product-list><product name="SLES" isbase="true" installed="1"/></product-list></stream>`)},
	}}
	rt := zypperRegistryRuntime("zypper", runner)
	got, err := reg.Call(context.Background(), rt, "pkg.list_products", &ZypperListProductsArgs{})
	want := []any{map[string]any{"name": "SLES", "isbase": true, "installed": true, "description": ""}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
		t.Fatalf("defaults got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	// The no-FS registry runtime proves list_products never touches the
	// filesystem when no productline attribute is present.
	if fs := rt.FS.(*execZypperNoCallFS); fs.calls != 0 {
		t.Fatalf("filesystem calls=%d", fs.calls)
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--disable-repositories", "products", "-i"}; !reflect.DeepEqual(append([]string{runner.calls[0].Name}, runner.calls[0].Args...), want) {
		t.Fatalf("argv=%v", append([]string{runner.calls[0].Name}, runner.calls[0].Args...))
	}
}
