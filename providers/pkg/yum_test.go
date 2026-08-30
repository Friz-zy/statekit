package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type yumNoCallRunner struct{ calls int }

func (r *yumNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{}
}

func TestYumNormalizeNameSourceVectors(t *testing.T) {
	tests := []struct {
		name, osarch, want string
	}{
		{"pkg.x86_64", "x86_64", "pkg"},
		{"pkg.i686", "x86_64", "pkg.i686"},
		{"pkg.aarch64", "aarch64", "pkg"},
		{"pkg.noarch", "x86_64", "pkg"},
		{"pkg.sparc", "x86_64", "pkg.sparc"},
		{"pkg.sparcv8", "x86_64", "pkg.sparcv8"},
		{"pkg.sparcv9", "x86_64", "pkg.sparcv9"},
		{"pkg.sparcv9v", "x86_64", "pkg.sparcv9v"},
		{"pkg.sparc64", "x86_64", "pkg.sparc64"},
		{"pkg.sparc64v", "x86_64", "pkg.sparc64v"},
		{"pkg.custom", "x86_64", "pkg.custom"},
		{"pkg", "x86_64", "pkg"},
		{"pkg.x86_64", "i686", "pkg.x86_64"},
		{"pkg.noarch", "i686", "pkg"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.osarch, func(t *testing.T) {
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: tt.osarch}})}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "normalize_name", map[string]any{"name": tt.name})
			if err != nil || got != tt.want {
				t.Fatalf("got=%#v err=%v want=%q", got, err, tt.want)
			}
		})
	}
}

func TestYumParseArchSourceVectors(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want map[string]any
	}{
		{"pkg.x86_64", map[string]any{"name": "pkg", "arch": "x86_64"}},
		{"pkg.i686", map[string]any{"name": "pkg", "arch": "i686"}},
		{"pkg.aarch64", map[string]any{"name": "pkg", "arch": "aarch64"}},
		{"pkg.noarch", map[string]any{"name": "pkg", "arch": "noarch"}},
		{"pkg.sparc", map[string]any{"name": "pkg.sparc", "arch": nil}},
		{"pkg.sparcv8", map[string]any{"name": "pkg.sparcv8", "arch": nil}},
		{"pkg.sparcv9", map[string]any{"name": "pkg.sparcv9", "arch": nil}},
		{"pkg.sparcv9v", map[string]any{"name": "pkg.sparcv9v", "arch": nil}},
		{"pkg.sparc64", map[string]any{"name": "pkg.sparc64", "arch": nil}},
		{"pkg.sparc64v", map[string]any{"name": "pkg.sparc64v", "arch": nil}},
		{"pkg.custom", map[string]any{"name": "pkg.custom", "arch": nil}},
		{"pkg", map[string]any{"name": "pkg", "arch": nil}},
		{"", map[string]any{"name": "", "arch": nil}},
	} {
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{}, "parse_arch", map[string]any{"name": tt.in})
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%q: got=%#v err=%v want=%#v", tt.in, got, err, tt.want)
		}
	}
}

func TestYumRejectsMalformedInputWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Runner: r}
	for _, args := range []any{nil, map[string]any{}, map[string]any{"name": 42}} {
		if _, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "normalize_name", args); err == nil {
			t.Fatalf("args=%#v accepted", args)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}
