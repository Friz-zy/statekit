package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type yumExecNoCallRunner struct{ calls int }

func (r *yumExecNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	panic("runner invoked")
}

func TestYumLongtailRegistryAndPureCalls(t *testing.T) {
	for _, manager := range []string{"yum", "dnf"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecNoCallRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Runner: runner, Providers: runtime.NewProviderRegistry()}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			name string
			args any
			want any
		}{
			{"pkg.normalize_name", &NormalizeNameArgs{Name: "zsh.x86_64"}, "zsh"},
			{"pkg.parse_arch", &ParseArchArgs{Name: "zsh.x86_64"}, map[string]any{"name": "zsh", "arch": "x86_64"}},
		} {
			fn, ok := reg.Get(tt.name)
			if !ok {
				t.Fatalf("missing %s", tt.name)
			}
			if got := fn.Args(); reflect.TypeOf(got) != reflect.TypeOf(tt.args).Elem() {
				t.Fatalf("%s Args type=%T", tt.name, got)
			}
			if got := reg.ProviderCapabilities(tt.name); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg"}) {
				t.Fatalf("%s caps=%v", tt.name, got)
			}
			got, err := reg.Call(context.Background(), rt, tt.name, tt.args)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s got=%#v err=%v", tt.name, got, err)
			}
		}
		for _, tt := range []struct {
			name string
			args any
		}{
			{"pkg.normalize_name", nil},
			{"pkg.normalize_name", "zsh.x86_64"},
			{"pkg.normalize_name", map[string]any{"name": "zsh.x86_64"}},
			{"pkg.normalize_name", (*NormalizeNameArgs)(nil)},
			{"pkg.normalize_name", &AutoremoveArgs{}},
			{"pkg.parse_arch", nil},
			{"pkg.parse_arch", 1},
			{"pkg.parse_arch", map[string]any{"name": "zsh.x86_64"}},
			{"pkg.parse_arch", (*ParseArchArgs)(nil)},
			{"pkg.parse_arch", &AutoremoveArgs{}},
		} {
			if got, err := reg.Call(context.Background(), rt, tt.name, tt.args); got != nil || err == nil || err.Error() != tt.name+": malformed arguments" {
				t.Errorf("%s malformed args got=%#v err=%v", tt.name, got, err)
			}
		}
		for _, fn := range longtailFunctions() {
			name := fn.Name()
			if reflect.DeepEqual(reg.ProviderCapabilities(name), []string{"aptpkg"}) {
				if _, err := reg.Call(context.Background(), rt, name, fn.Args()); !errors.Is(err, pkgprovider.ErrUnsupportedAPT) {
					t.Fatalf("%s on %s: error=%v", name, manager, err)
				}
			}
		}
		if runner.calls != 0 {
			t.Fatalf("%s runner calls=%d", manager, runner.calls)
		}
	}
}
