package gotemplate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

type cancelAfterChecks struct {
	context.Context
	remaining int
}

type cancelAfterCalls struct {
	context.Context
	stopAt int
	calls  int
}

func cancellationAt(target string) (context.Context, map[string]bool) {
	base, cancel := context.WithCancel(context.Background())
	entered := make(map[string]bool)
	observer := checkpointObserver(func(label string) {
		entered[label] = true
		if label == target {
			cancel()
		}
	})
	return context.WithValue(base, checkpointObserverKey{}, observer), entered
}

func (c *cancelAfterCalls) Err() error {
	c.calls++
	if c.calls >= c.stopAt {
		return context.Canceled
	}
	return nil
}

func (c *cancelAfterChecks) Err() error {
	if c.remaining == 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

type unsupportedStruct struct{ Value string }

var adversarialMethodCalls int

type hostileString string
type hostileInt int
type hostileFloat float64
type hostileBool bool
type hostileMap map[string]any
type hostileSlice []any

func hostileCalled()                               { adversarialMethodCalls++; panic("hostile method invoked") }
func (hostileString) String() string               { hostileCalled(); return "" }
func (hostileString) Format(fmt.State, rune)       { hostileCalled() }
func (hostileString) MarshalJSON() ([]byte, error) { hostileCalled(); return nil, nil }
func (hostileString) MarshalYAML() (any, error)    { hostileCalled(); return nil, nil }
func (hostileInt) String() string                  { hostileCalled(); return "" }
func (hostileInt) Format(fmt.State, rune)          { hostileCalled() }
func (hostileInt) MarshalJSON() ([]byte, error)    { hostileCalled(); return nil, nil }
func (hostileInt) MarshalYAML() (any, error)       { hostileCalled(); return nil, nil }
func (hostileFloat) String() string                { hostileCalled(); return "" }
func (hostileFloat) Format(fmt.State, rune)        { hostileCalled() }
func (hostileFloat) MarshalJSON() ([]byte, error)  { hostileCalled(); return nil, nil }
func (hostileFloat) MarshalYAML() (any, error)     { hostileCalled(); return nil, nil }
func (hostileBool) String() string                 { hostileCalled(); return "" }
func (hostileBool) Format(fmt.State, rune)         { hostileCalled() }
func (hostileBool) MarshalJSON() ([]byte, error)   { hostileCalled(); return nil, nil }
func (hostileBool) MarshalYAML() (any, error)      { hostileCalled(); return nil, nil }
func (hostileMap) String() string                  { hostileCalled(); return "" }
func (hostileSlice) String() string                { hostileCalled(); return "" }

func TestCanonicalizationDoesNotExposeNamedMethods(t *testing.T) {
	adversarialMethodCalls = 0
	cases := []struct {
		name  string
		value any
		want  any
	}{
		{"string", hostileString("text"), "text"},
		{"int", hostileInt(7), int64(7)},
		{"float", hostileFloat(1.5), float64(1.5)},
		{"bool", hostileBool(true), true},
		{"map", hostileMap{"x": hostileString("y")}, map[string]any{"x": "y"}},
		{"slice", hostileSlice{hostileInt(3)}, []any{int64(3)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkedValue(context.Background(), tc.value)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("checkedValue() = %#v, %v; want %#v", got, err, tc.want)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tc.want) {
				t.Fatalf("canonical type = %T; want %T", got, tc.want)
			}
			if _, err := toJSON(tc.value); err != nil {
				t.Fatalf("toJSON: %v", err)
			}
			if _, err := toYAML(tc.value); err != nil {
				t.Fatalf("toYAML: %v", err)
			}
		})
	}
	if adversarialMethodCalls != 0 {
		t.Fatalf("invoked %d adversarial methods", adversarialMethodCalls)
	}
	if out, err := Render(context.Background(), Request{Contents: "{{.s}} {{.i}} {{.f}} {{.b}}", Context: map[string]any{
		"s": hostileString("text"), "i": hostileInt(7), "f": hostileFloat(1.5), "b": hostileBool(true),
	}}); err != nil || out != "text 7 1.5 true" {
		t.Fatalf("render = %q, %v", out, err)
	}
}

var _ fmt.Stringer = hostileString("")
var _ json.Marshaler = hostileString("")

func TestRenderMergesDefaultsAndContext(t *testing.T) {
	out, err := Render(context.Background(), Request{
		Contents: "{{.name}} {{.onlyDefault}}",
		Defaults: map[string]any{"name": "default", "onlyDefault": "present"},
		Context:  map[string]any{"name": "context"},
	})
	if err != nil || out != "context present" {
		t.Fatalf("Render() = %q, %v", out, err)
	}
}

func TestRenderRejectsMissingAndUnsupportedValues(t *testing.T) {
	if _, err := Render(context.Background(), Request{Contents: "{{.missing}}"}); err == nil {
		t.Fatal("missing key did not fail")
	}
	if _, err := Render(context.Background(), Request{Contents: "ok", Context: map[string]any{"bad": func() {}}}); err == nil {
		t.Fatal("function context did not fail")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := Render(context.Background(), Request{Contents: "ok", Context: cycle}); err == nil {
		t.Fatal("cyclic context did not fail")
	}
	if _, err := Render(context.Background(), Request{Contents: "{{.n}}", Context: map[string]any{"n": math.Inf(1)}}); err == nil {
		t.Fatal("infinite float did not fail")
	}
}

func TestRenderRejectsUnsupportedValuesDeterministicallyWithoutMutation(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{name: "channel", value: make(chan int), want: "gotemplate: invalid value for \"bad\": unsupported value type chan int"},
		{name: "pointer", value: new(int), want: "gotemplate: invalid value for \"bad\": unsupported value type *int"},
		{name: "struct", value: unsupportedStruct{}, want: "gotemplate: invalid value for \"bad\": unsupported value type gotemplate.unsupportedStruct"},
		{name: "non-string-key map", value: map[int]string{1: "one"}, want: "gotemplate: invalid value for \"bad\": unsupported map type map[int]string"},
		{name: "function", value: func() {}, want: "gotemplate: invalid value for \"bad\": unsupported value type func()"},
		{name: "cycle", value: cycle, want: "gotemplate: invalid value for \"bad\": cyclic value"},
		{name: "non-finite float", value: math.Inf(1), want: "gotemplate: invalid value for \"bad\": non-finite float"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"bad": tc.value}
			_, first := Render(context.Background(), Request{Contents: "ok", Context: input})
			_, second := Render(context.Background(), Request{Contents: "ok", Context: input})
			if first == nil || first.Error() != tc.want || second == nil || second.Error() != first.Error() {
				t.Fatalf("errors = %v, %v; want %q", first, second, tc.want)
			}
			unchanged := tc.name == "function" || reflect.DeepEqual(input["bad"], tc.value)
			if !unchanged {
				t.Fatal("input value was modified")
			}
			if tc.name == "cycle" {
				self, ok := cycle["self"].(map[string]any)
				if !ok || len(self) != 1 {
					t.Fatal("cycle input was modified")
				}
			}
		})
	}
}

func TestRenderHelpersAndLimits(t *testing.T) {
	out, err := Render(context.Background(), Request{Contents: `{{toJSON .value}}|{{(fromJSON "{\"x\":2}").x}}|{{(fromYAML "x: 3").x}}|{{toYAML .value}}`, Context: map[string]any{"value": map[string]any{"x": 1}}})
	if err != nil || !strings.Contains(out, `{"x":1}|2|3|`) || !strings.Contains(out, "x: 1") {
		t.Fatalf("helper output = %q, %v", out, err)
	}
	if _, err := Render(context.Background(), Request{Contents: strings.Repeat("x", MaxBytes+1)}); !errors.Is(err, ErrSourceLimit) {
		t.Fatalf("source error = %v", err)
	}
	if _, err := Render(context.Background(), Request{Contents: "{{.x}}", Context: map[string]any{"x": strings.Repeat("x", MaxBytes+1)}}); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("output error = %v", err)
	}
}

func TestRenderOnlyExposesExplicitHelpersAndRejectsRecursion(t *testing.T) {
	if _, err := Render(context.Background(), Request{Contents: "{{env \"HOME\"}}"}); err == nil {
		t.Fatal("unsafe helper was available")
	}
	if _, err := Render(context.Background(), Request{Contents: `{{define "loop"}}{{template "loop"}}{{end}}{{template "loop"}}`}); err == nil {
		t.Fatal("recursive template did not fail")
	}
	if _, err := Render(context.Background(), Request{Contents: "{{range .items}}x{{end}}", Context: map[string]any{"items": []any{"x"}}}); !errors.Is(err, ErrUnboundedControl) {
		t.Fatalf("range error = %v", err)
	}
}

func TestRenderRejectsASTNodeAndDepthBudgetsBeforeExecution(t *testing.T) {
	nodes := strings.Repeat("{{if true}}x{{end}}", maxASTNodes)
	if _, err := Render(context.Background(), Request{Contents: nodes}); !errors.Is(err, ErrASTLimit) {
		t.Fatalf("node budget error = %v", err)
	}
	deep := strings.Repeat("{{if true}}", maxASTDepth+1) + "x" + strings.Repeat("{{end}}", maxASTDepth+1)
	if _, err := Render(context.Background(), Request{Contents: deep}); !errors.Is(err, ErrASTLimit) {
		t.Fatalf("depth budget error = %v", err)
	}
}

func TestRenderCancellationDuringBoundedExecution(t *testing.T) {
	ctx, entered := cancellationAt("template Execute")
	templateText := strings.Repeat("x", MaxBytes)
	_, err := Render(ctx, Request{Contents: templateText})
	if !entered["template Execute"] {
		t.Fatal("template Execute was not entered")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("execution cancellation = %v", err)
	}
}

func TestCancellationStopsValidationAndNormalizationAtFiniteCheckpoints(t *testing.T) {
	values := make([]any, 2048)
	ctx := &cancelAfterChecks{Context: context.Background(), remaining: 4}
	if out, err := Render(ctx, Request{Contents: "ok", Context: map[string]any{"values": values}}); !errors.Is(err, context.Canceled) || out != "" {
		t.Fatalf("validation cancellation = %q, %v", out, err)
	}
}

func TestCancellationStopsJSONYAMLParseAndEncode(t *testing.T) {
	largeJSON := `{"items":[` + strings.TrimSuffix(strings.Repeat(`1,`, 2048), ",") + `]}`
	largeYAML := "items:\n" + strings.Repeat("  - 1\n", 2048)
	cases := []struct {
		name string
		call func(context.Context) (any, error)
	}{
		{"json parse", func(ctx context.Context) (any, error) { return fromJSONWith(ctx, largeJSON) }},
		{"yaml parse", func(ctx context.Context) (any, error) { return fromYAMLWith(ctx, largeYAML) }},
		{"json encode", func(ctx context.Context) (any, error) {
			return toJSONWith(ctx, map[string]any{"items": valuesForCancellation(2048)})
		}},
		{"yaml encode", func(ctx context.Context) (any, error) {
			return toYAMLWith(ctx, map[string]any{"items": valuesForCancellation(2048)})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := map[string]string{"json parse": "JSON decode", "yaml parse": "YAML decode", "json encode": "JSON encode", "yaml encode": "YAML encode"}[tc.name]
			ctx, entered := cancellationAt(target)
			result, err := tc.call(ctx)
			if !entered[target] {
				t.Fatalf("%s was not entered", target)
			}
			if !errors.Is(err, context.Canceled) || result != nil && result != "" {
				t.Fatalf("cancellation = %#v, %v", result, err)
			}
		})
	}
}

func valuesForCancellation(n int) []any {
	values := make([]any, n)
	for i := range values {
		values[i] = i
	}
	return values
}

func TestCancellationStopsSourceASTAndFormattingPreflight(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		request Request
	}{
		{name: "source scan", target: "source scan", request: Request{Contents: strings.Repeat("x", MaxBytes)}},
		{name: "template parse", target: "template parse", request: Request{Contents: "ok"}},
		{name: "AST walk", target: "AST walk", request: Request{Contents: strings.Repeat("{{if true}}x{{end}}", 1000)}},
		{name: "formatting preflight", target: "formatting preflight", request: Request{Contents: `{{printf "%s" .value}}`, Context: map[string]any{"value": strings.Repeat("x", 4096)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, entered := cancellationAt(tc.target)
			out, err := Render(ctx, tc.request)
			if !entered[tc.target] {
				t.Fatalf("%s was not entered", tc.target)
			}
			// text/template parsing is synchronous; cancellation immediately
			// before Parse is observed by the bounded post-parse checkpoint.
			if !errors.Is(err, context.Canceled) || out != "" {
				t.Fatalf("cancellation = %q, %v", out, err)
			}
		})
	}
}

func TestRenderCancellationAndNamedTemplate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Render(ctx, Request{Contents: "ok"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	out, err := RenderNamed(context.Background(), Request{Contents: `{{define "chosen"}}ok {{.v}}{{end}}`, Context: map[string]any{"v": "value"}}, "chosen")
	if err != nil || out != "ok value" {
		t.Fatalf("RenderNamed() = %q, %v", out, err)
	}
}

func TestSortKeysCancellationOccursDuringSort(t *testing.T) {
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%04d", len(keys)-i)
	}
	ctx := &cancelAfterCalls{Context: context.Background(), stopAt: 2}
	if err := sortKeys(ctx, keys); !errors.Is(err, context.Canceled) {
		t.Fatalf("sortKeys error = %v, want cancellation", err)
	}
	if ctx.calls < 2 {
		t.Fatalf("sort was not entered: %d context checks", ctx.calls)
	}
}

func TestCheckingWriterCancellationOccursBetweenBoundedChunks(t *testing.T) {
	ctx := &cancelAfterCalls{Context: context.Background(), stopAt: 2}
	w := &checkingWriter{ctx: ctx, limit: MaxBytes, budget: -1}
	n, err := w.Write(bytes.Repeat([]byte{'x'}, checkpointInterval*3))
	if !errors.Is(err, context.Canceled) || n != checkpointInterval {
		t.Fatalf("Write = %d, %v; want one bounded chunk and cancellation", n, err)
	}
	if w.Len() != checkpointInterval {
		t.Fatalf("writer length = %d, want %d", w.Len(), checkpointInterval)
	}
}

func TestRenderRejectsAggregateValueBudget(t *testing.T) {
	values := make([]any, maxValueNodes+1)
	_, err := Render(context.Background(), Request{Contents: "ok", Context: map[string]any{"values": values}})
	if !errors.Is(err, errValueBudget) {
		t.Fatalf("budget error = %v", err)
	}
}

func TestHelpersRejectOversizedInputsAndFormatting(t *testing.T) {
	if _, err := Render(context.Background(), Request{Contents: `{{fromJSON .input}}`, Context: map[string]any{"input": strings.Repeat(" ", MaxBytes+1)}}); !errors.Is(err, errValueBudget) {
		t.Fatalf("fromJSON budget error = %v", err)
	}
	if _, err := Render(context.Background(), Request{Contents: `{{printf "%s" .value}}`, Context: map[string]any{"value": strings.Repeat("x", maxValueBytes-16)}}); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("bounded printf error = %v", err)
	}
}

func TestSerializationStreamsAndBoundsEncodedValues(t *testing.T) {
	if got, err := toJSON(map[string]any{"n": int64(9223372036854775807), "nested": []any{true, "x"}}); err != nil || got != `{"n":9223372036854775807,"nested":[true,"x"]}` {
		t.Fatalf("toJSON exact output = %q, %v", got, err)
	}
	if got, err := toYAML(map[string]any{"n": int64(7), "nested": []any{true, "x"}}); err != nil || got != "\"n\": 7\nnested:\n    - true\n    - x\n" {
		t.Fatalf("toYAML exact output = %q, %v", got, err)
	}
	largeInts := make([]int64, maxValueNodes/2)
	if got, err := toJSON(largeInts); !errors.Is(err, ErrOutputLimit) || got != "" {
		t.Fatalf("large JSON = %d bytes, %v; want empty bounded result", len(got), err)
	}
	if got, err := toYAML(largeInts); !errors.Is(err, ErrOutputLimit) || got != "" {
		t.Fatalf("large YAML = %d bytes, %v; want empty bounded result", len(got), err)
	}
	largeMap := make(map[string]any, maxValueNodes/2)
	for i := 0; i < maxValueNodes/2; i++ {
		largeMap[fmt.Sprintf("k%d", i)] = int64(i)
	}
	if got, err := toJSON(largeMap); !errors.Is(err, ErrOutputLimit) || len(got) > MaxBytes {
		t.Fatalf("large map JSON = %d bytes, %v", len(got), err)
	}
}

func TestJSONFloatFormattingMatchesEncodingJSON(t *testing.T) {
	values := []float64{math.Copysign(0, -1), 1e-6, 1e-7, 1e20, 1e21, -1e-7, -1e20, -1e21, 1.2345678901234567}
	for _, value := range values {
		wantBytes, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := toJSON(value)
		if err != nil || got != string(wantBytes) {
			t.Fatalf("float %g: got %q, want %q (err %v)", value, got, wantBytes, err)
		}
	}
	nested := map[string]any{"values": []any{float64(1e-7), float64(1e20), math.Copysign(0, -1), map[string]any{"n": float64(1e21)}}}
	wantBytes, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	got, err := toJSON(nested)
	if err != nil || got != string(wantBytes) || len(got) > MaxBytes {
		t.Fatalf("nested floats: got %q, want %q (err %v)", got, wantBytes, err)
	}
}

func TestJSONInvalidUTF8MatchesEncodingJSON(t *testing.T) {
	invalid := string([]byte{'a', 0xff, 0xfe, 'b', 0xc3, 'c'})
	validReplacement := "valid � replacement"
	cases := []any{
		invalid,
		map[string]any{
			"invalid-key-\xff": invalid,
			"nested":           []any{invalid, map[string]any{"value": invalid}},
			"replacement":      validReplacement,
		},
	}
	for _, value := range cases {
		want, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := toJSON(value)
		if err != nil || got != string(want) {
			t.Fatalf("invalid UTF-8: got %q, want %q (err %v)", got, want, err)
		}
	}
}

func TestFormattingRejectsAmplificationBeforeFmt(t *testing.T) {
	large := strings.Repeat("x", maxValueBytes-16)
	cases := []string{
		`{{printf "%1000000000s" ""}}`,
		`{{printf "%.1000000000s" ""}}`,
		`{{printf "%*s" 100 "x"}}`,
		`{{printf "%s%s" .x .x}}`,
		`{{printf "%" "x"}}`,
	}
	for _, contents := range cases {
		contextValues := map[string]any{"x": large}
		if _, err := Render(context.Background(), Request{Contents: contents, Context: contextValues}); err == nil {
			t.Fatalf("format %q was accepted", contents)
		}
		if contextValues["x"] != large {
			t.Fatalf("format mutated input")
		}
	}
	if got, err := boundedPrintf(context.Background(), "%s %d %v", "text", 7, true); err != nil || got != "text 7 true" {
		t.Fatalf("ordinary printf = %q, %v", got, err)
	}
	if got, err := boundedPrint(context.Background(), "a", 2); err != nil || got != "a2" {
		t.Fatalf("ordinary print = %q, %v", got, err)
	}
}

func TestFormattingQuotedStringsUseConservativeOverflowSafeBudget(t *testing.T) {
	values := []string{
		string([]byte{'a', 0, 1, 0x1f, 0xff, 0xfe}),
		"non-BMP: \U0001f600",
	}
	for _, value := range values {
		for _, format := range []string{"%q", "%#v"} {
			got, err := boundedPrintf(context.Background(), format, value)
			want := fmt.Sprintf(format, value)
			if err != nil || got != want {
				t.Fatalf("boundedPrintf(%q): got %q, %v; want %q", format, got, err, want)
			}
		}
	}

	large := strings.Repeat("\x00", maxFormatBytes/4)
	for _, format := range []string{"%q", "%#v", "%q%q", "%#v %#v"} {
		if err := preflightFormat(context.Background(), format, []any{large, large}); err == nil {
			t.Fatalf("preflight accepted potentially amplifying format %q", format)
		}
	}
	if err := preflightFormat(context.Background(), "%q", []any{strings.Repeat("x", maxFormatBytes/4-2)}); err != nil {
		t.Fatalf("boundary quoted string rejected: %v", err)
	}
}

func TestFormattingCanonicalContainersRemainBounded(t *testing.T) {
	value := map[string]any{"text": "value", "items": []any{int64(3), true}}
	if got, err := boundedPrintf(context.Background(), "%v", value); err != nil || got != fmt.Sprintf("%v", value) {
		t.Fatalf("ordinary container formatting = %q, %v", got, err)
	}
	if got, err := boundedPrintf(context.Background(), "%#v", value); err != nil || got != fmt.Sprintf("%#v", value) {
		t.Fatalf("quoted container formatting = %q, %v", got, err)
	}
}
