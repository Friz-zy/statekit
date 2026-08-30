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

func TestYumVersionCmpSourceVectors(t *testing.T) {
	// Vectors follow salt/utils/pkg/rpm.py:168-351
	// (_rpmvercmp, evr_compare, and version_to_evr).
	tests := []struct {
		name, left, right string
		ignore            bool
		want              int
	}{
		{"equal", "1.2-3", "1.2-3", false, 0},
		{"epoch", "1:1.0-1", "0:9.9-9", false, 1},
		{"signed epoch", "-1:1.0", "0:1.0", false, -1},
		{"ignore epoch", "1:1.0-1", "0:1.0-1", true, 0},
		{"version", "1.10", "1.9", false, 1},
		{"release", "1.0-2", "1.0-1", false, 1},
		{"leading zeros", "1.01", "1.1", false, 0},
		{"numeric alpha", "1.0", "1.a", false, 1},
		{"punctuation", "1.0.1", "1_0_1", false, 0},
		{"tilde", "1.0~rc1", "1.0", false, -1},
		{"caret", "1.0", "1.0^git1", false, -1},
		{"missing release lower", "1.0", "1.0-99", false, -1},
		{"missing release upper", "1.0-99", "1.0", false, 1},
		{"missing release equal", "1.0", "1.0-", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{}, "version_cmp", map[string]any{
				"pkg1": tt.left, "pkg2": tt.right, "ignore_epoch": tt.ignore,
			})
			if err != nil || value != tt.want {
				t.Fatalf("got=%#v err=%v want=%d", value, err, tt.want)
			}
		})
	}
}

func TestYumVersionToEVRSourceEpochVectors(t *testing.T) {
	// Python int(epoch) vectors from salt/utils/pkg/rpm.py:168-351.
	for _, tt := range []struct {
		name, input, want string
	}{
		{"arabic-indic", "١٢:1.0", "12"},
		{"devanagari", "१२:1.0", "12"},
		{"signed whitespace", "  +१२  :1.0", "12"},
		{"negative", "-१२:1.0", "-12"},
		{"negative zero canonical", "-٠:1.0", "0"},
		{"huge", "999999999999999999999999999999999999999999999999999999:1.0", "999999999999999999999999999999999999999999999999999999"},
		{"roman rejected fallback", "Ⅻ:1.0", "0"},
		{"fraction rejected fallback", "½:1.0", "0"},
		{"superscript rejected fallback", "²:1.0", "0"},
		{"invalid rejected fallback", "12x:1.0", "0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			epoch, _, _ := yumVersionToEVR(tt.input)
			if epoch != tt.want {
				t.Fatalf("yumVersionToEVR(%q) epoch=%q want=%q", tt.input, epoch, tt.want)
			}
		})
	}
}

func TestYumVersionCmpAcceptsSourceValuesWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Runner: r}
	for _, tt := range []struct {
		left, right string
		want        int
	}{
		{"", "1.0", -1}, {"1.0", "", 1}, {"wat:1.0", "1.0", 0},
		{"1:", "1.0", 1}, {"-1", "1.0", -1}, {"1.0-", "1.0", 0},
		{"1.0 bad", "1.0", 1}, {"1:2:1.0", "1.0", 1},
	} {
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "version_cmp", map[string]any{
			"pkg1": tt.left, "pkg2": tt.right,
		})
		if err != nil || got != tt.want {
			t.Errorf("%q/%q got=%#v err=%v want=%d", tt.left, tt.right, got, err, tt.want)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumVersionCmpUnicodeSourceVectors(t *testing.T) {
	for _, tt := range []struct {
		left, right string
		want        int
	}{
		{"1.0α", "1.0β", -1},
		{"1.0α", "1.0a", 1},
		{"1.٠", "1.2", 1},
		{"1.①", "1.1", 1},
		{"1.፩", "1.1", 1},
		{"1.⑴", "1.1", 1},
		{"1.²", "1.1", 1},
		{"1.½", "1.1", -1},
		{"1.Ⅻ", "1.1", -1},
		{"1.①", "1.②", -1},
		{"1.①①", "1.①", 1},
		{"1.１２", "1.２", 1},
		{"1.0~α", "1.0", -1},
		{"1.0^α", "1.0", 1},
		{"1.0+α", "1.0_β", -1},
		{"1+0", "1_0", 0},
		{"1/0", "1.0", 0},
	} {
		got := yumVersionCmp(tt.left, tt.right, false)
		if got != tt.want {
			t.Errorf("%q/%q got=%v want=%d", tt.left, tt.right, got, tt.want)
		}
	}
}

func TestPythonDigitPredicateSourceVectors(t *testing.T) {
	// These assertions mirror Python str.isdigit() on the pinned Unicode
	// version: Other_Digit values are true, while other numeric categories are
	// deliberately false.
	for _, tt := range []struct {
		name string
		r    rune
		want bool
	}{
		{"ascii digit", '7', true},
		{"circled digit", '①', true},
		{"ethiopic digit", '፩', true},
		{"parenthesized digit", '⑴', true},
		{"superscript digit", '²', true},
		{"fraction", '½', false},
		{"roman numeral", 'Ⅻ', false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := pythonDigit(tt.r); got != tt.want {
				t.Fatalf("pythonDigit(%U)=%v want=%v", tt.r, got, tt.want)
			}
		})
	}
}

func TestYumVersionCmpRejectsTypesWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Runner: r}
	for _, args := range []map[string]any{
		{"pkg1": 1, "pkg2": "1"}, {"pkg1": "1", "pkg2": nil}, {"pkg1": "1", "pkg2": "1", "ignore_epoch": "no"},
	} {
		if got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), rt, "version_cmp", args); got != nil || err == nil {
			t.Errorf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}
