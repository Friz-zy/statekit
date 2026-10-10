package config

import (
	"reflect"
	"strings"
	"testing"
)

type sampleArgs struct {
	Name    string   `statekit:"required"`
	Version string   `statekit:"name=version"`
	Enable  bool     `statekit:"name=enable"`
	Retries int      `statekit:"name=retries"`
	Ratio   float64  `statekit:"name=ratio"`
	Tags    []string `statekit:"name=tags"`
	Test    bool     `statekit:"name=test"`
}

func TestDecodeDefaultsAndStructured(t *testing.T) {
	args := &sampleArgs{}
	structured := map[string]any{"name": "curl", "version": "8.14.1", "retries": 3}
	if err := Decode(args, structured, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if args.Name != "curl" || args.Version != "8.14.1" || args.Retries != 3 {
		t.Fatalf("structured values lost: %+v", args)
	}
}

func TestFlagsOverrideStructured(t *testing.T) {
	args := &sampleArgs{}
	structured := map[string]any{"name": "curl", "version": "8.0"}
	provided := map[string]string{"version": "9.1", "enable": "true", "retries": "5"}
	if err := Decode(args, structured, provided); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if args.Version != "9.1" {
		t.Fatalf("CLI flags must override structured input: %+v", args)
	}
	if !args.Enable {
		t.Fatal("bool flag conversion broken")
	}
	if args.Retries != 5 {
		t.Fatal("int flag conversion broken")
	}
}

func TestUnknownArgumentRejected(t *testing.T) {
	args := &sampleArgs{}
	err := Decode(args, map[string]any{"nmae": "typo"}, nil)
	unknown, ok := err.(*UnknownArgumentError)
	if !ok {
		t.Fatalf("expected UnknownArgumentError, got %v", err)
	}
	if unknown.Name != "nmae" {
		t.Fatalf("unknown name = %q", unknown.Name)
	}
	err = Decode(args, nil, map[string]string{"bogus": "x"})
	if _, ok := err.(*UnknownArgumentError); !ok {
		t.Fatalf("expected UnknownArgumentError for flag, got %v", err)
	}
}

func TestRequiredValidation(t *testing.T) {
	args := &sampleArgs{}
	err := Decode(args, map[string]any{"version": "1"}, nil)
	missing, ok := err.(*MissingRequiredError)
	if !ok || missing.Name != "name" {
		t.Fatalf("expected MissingRequiredError{name}, got %v", err)
	}
}

func TestListConversion(t *testing.T) {
	args := &sampleArgs{}
	if err := Decode(args, map[string]any{
		"name": "x",
		"tags": []any{"a", "b"},
	}, nil); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if !reflect.DeepEqual(args.Tags, []string{"a", "b"}) {
		t.Fatalf("tags = %v", args.Tags)
	}

	args2 := &sampleArgs{}
	if err := Decode(args2, map[string]any{"name": "x"}, map[string]string{"tags": "a, b,c"}); err != nil {
		t.Fatalf("flag list decode: %v", err)
	}
	if !reflect.DeepEqual(args2.Tags, []string{"a", "b", "c"}) {
		t.Fatalf("comma split tags = %v", args2.Tags)
	}
}

func TestNormalizeBoolArgs(t *testing.T) {
	template := sampleArgs{}
	got, err := NormalizeBoolArgs([]string{"--enable", "true", "--test", "--name", "curl", "-o", "json"}, template)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	// Spaced bool gets "=" form; bare bool followed by a flag stays bare;
	// non-bool flags keep their separate value tokens.
	want := []string{"--enable=true", "--test", "--name", "curl", "-o", "json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
}

func TestNewFlagSetBoolBareForm(t *testing.T) {
	fs, err := NewFlagSet("sample", sampleArgs{})
	if err != nil {
		t.Fatalf("flagset: %v", err)
	}
	if err := fs.Parse([]string{"--enable"}); err != nil {
		t.Fatalf("bare bool flag must parse: %v", err)
	}
	if v, _ := ProvidedValues(fs)["enable"]; v != "true" {
		t.Fatalf("bare bool value = %q", v)
	}
}

func TestFloatAndNumberCoercion(t *testing.T) {
	args := &sampleArgs{}
	if err := Decode(args, map[string]any{"name": "x", "ratio": json_number(0.5)}, nil); err != nil {
		t.Fatalf("float decode: %v", err)
	}
	if args.Ratio != 0.5 {
		t.Fatalf("ratio = %v", args.Ratio)
	}
	args2 := &sampleArgs{}
	if err := Decode(args2, map[string]any{"name": 640}, nil); err != nil {
		t.Fatalf("int-to-string coercion: %v", err)
	}
	if args2.Name != "640" {
		t.Fatalf("numeric name = %q", args2.Name)
	}
}

func json_number(f float64) any { return f }

type mapArgs struct {
	Name    string            `statekit:"required"`
	Labels  map[string]string `statekit:"name=labels"`
	Payload map[string]any    `statekit:"name=payload"`
}

type unionArgs struct {
	Name  string `statekit:"required"`
	Value any    `statekit:"required,name=value"`
}

func TestAnyFieldSupportsScalarFlagsAndStructuredValues(t *testing.T) {
	args := &unionArgs{}
	if err := Decode(args, map[string]any{
		"name": "plist", "value": map[string]any{"enabled": true},
	}, nil); err != nil {
		t.Fatalf("structured any decode: %v", err)
	}
	value, ok := args.Value.(map[string]any)
	if !ok || value["enabled"] != true {
		t.Fatalf("structured any value = %#v", args.Value)
	}
	args = &unionArgs{}
	if err := Decode(args, nil, map[string]string{"name": "plist", "value": "true"}); err != nil {
		t.Fatalf("flag any decode: %v", err)
	}
	if args.Value != "true" {
		t.Fatalf("flag any value = %#v", args.Value)
	}
	fs, err := NewFlagSet("union", unionArgs{})
	if err != nil || fs.Lookup("value") == nil {
		t.Fatalf("any flag = %v", err)
	}
}

type pointerAnyArgs struct {
	Other *any `statekit:"required,name=other"`
}

type pointerAnyAlias = any

type pointerAnyAliasArgs struct {
	Value *pointerAnyAlias `statekit:"name=value"`
}

type definedPointerAny *any

type definedPointerAnyArgs struct {
	Value definedPointerAny `statekit:"name=value"`
}

type namedEmptyInterface interface{}

type namedInterfacePointerArgs struct {
	Value *namedEmptyInterface `statekit:"name=value"`
}

type nonemptyInterface interface{ String() string }

type nonemptyInterfacePointerArgs struct {
	Value *nonemptyInterface `statekit:"name=value"`
}

type nestedPointerAnyArgs struct {
	Value **any `statekit:"name=value"`
}

// TestPointerAnyTriStateBinding opts only *any into pointer assignment while
// preserving nil outer, explicit nil inner, and explicit empty-string states.
func TestPointerAnyTriStateBinding(t *testing.T) {
	names, err := ArgumentNames(pointerAnyArgs{})
	if err != nil || !reflect.DeepEqual(names, []string{"other"}) {
		t.Fatalf("argument names = %v, err = %v", names, err)
	}
	fs, err := NewFlagSet("pointer-any", pointerAnyArgs{})
	if err != nil || fs.Lookup("other") == nil {
		t.Fatalf("*any flag = %v, err = %v", fs, err)
	}
	if _, err := ArgumentNames(pointerAnyAliasArgs{}); err != nil {
		t.Fatalf("true alias of any must be accepted: %v", err)
	}
	aliasFlags, err := NewFlagSet("pointer-any-alias", pointerAnyAliasArgs{})
	if err != nil || aliasFlags.Lookup("value") == nil {
		t.Fatalf("true alias of any flag = %v, err = %v", aliasFlags, err)
	}
	flaggedAlias := &pointerAnyAliasArgs{}
	if err := Decode(flaggedAlias, nil, map[string]string{"value": "alias-flag"}); err != nil ||
		flaggedAlias.Value == nil || *flaggedAlias.Value != "alias-flag" {
		t.Fatalf("true alias flag assignment = %#v, err = %v", flaggedAlias.Value, err)
	}
	structuredAlias := &pointerAnyAliasArgs{}
	if err := Decode(structuredAlias, map[string]any{"value": int(7)}, nil); err != nil ||
		structuredAlias.Value == nil || *structuredAlias.Value != int(7) {
		t.Fatalf("true alias structured assignment = %#v, err = %v", structuredAlias.Value, err)
	}

	omitted := &pointerAnyArgs{}
	if err := Decode(omitted, nil, nil); err == nil {
		t.Fatal("required nil outer *any must fail")
	} else if missing, ok := err.(*MissingRequiredError); !ok || missing.Name != "other" {
		t.Fatalf("missing error = %#v, want MissingRequiredError{other}", err)
	}

	var innerNil any
	explicitNull := &pointerAnyArgs{}
	if err := Decode(explicitNull, map[string]any{"other": nil}, nil); err != nil {
		t.Fatalf("decode explicit null: %v", err)
	}
	if explicitNull.Other == nil || *explicitNull.Other != nil {
		t.Fatalf("null must be nonnil outer/nil inner, got %#v", explicitNull.Other)
	}
	if err := Decode(&pointerAnyArgs{Other: &innerNil}, map[string]any{"other": nil}, nil); err != nil {
		t.Fatalf("null over reused target: %v", err)
	}

	empty := &pointerAnyArgs{}
	if err := Decode(empty, map[string]any{"other": ""}, nil); err != nil {
		t.Fatalf("decode explicit empty: %v", err)
	}
	if empty.Other == nil || *empty.Other != "" {
		t.Fatalf("empty string must remain a nonnil pointer value, got %#v", empty.Other)
	}

	var retained any = "keep"
	reused := &pointerAnyArgs{Other: &retained}
	prior := reused.Other
	if err := Decode(reused, map[string]any{}, nil); err != nil || reused.Other != prior || *reused.Other != "keep" {
		t.Fatalf("omission on reused target = %#v, err=%v", reused.Other, err)
	}
	if err := Decode(reused, map[string]any{"other": nil}, nil); err != nil {
		t.Fatalf("null on reused target: %v", err)
	}
	if reused.Other == nil || reused.Other == prior || *reused.Other != nil {
		t.Fatalf("null must replace reused pointer with fresh nil interface: %#v", reused.Other)
	}

	flagged := &pointerAnyArgs{}
	if err := Decode(flagged, map[string]any{"other": nil}, map[string]string{"other": "0007"}); err != nil {
		t.Fatalf("flag over structured null: %v", err)
	}
	if flagged.Other == nil || *flagged.Other != "0007" {
		t.Fatalf("flag precedence value = %#v", flagged.Other)
	}
	flagged = &pointerAnyArgs{}
	if err := Decode(flagged, map[string]any{"other": 7}, map[string]string{"other": ""}); err != nil {
		t.Fatalf("empty flag over structured value: %v", err)
	}
	if flagged.Other == nil || *flagged.Other != "" {
		t.Fatalf("empty flag must stay an explicit string: %#v", flagged.Other)
	}

	for _, value := range []any{false, int(0), float64(1.5)} {
		args := &pointerAnyArgs{}
		if err := Decode(args, map[string]any{"other": value}, nil); err != nil {
			t.Fatalf("decode %#v: %v", value, err)
		}
		if args.Other == nil || reflect.TypeOf(*args.Other) != reflect.TypeOf(value) || !reflect.DeepEqual(*args.Other, value) {
			t.Fatalf("dynamic value changed: got %#v, want %#v", args.Other, value)
		}
	}
	var typedNil any = (*int)(nil)
	args := &pointerAnyArgs{}
	if err := Decode(args, map[string]any{"other": typedNil}, nil); err != nil {
		t.Fatalf("decode typed nil: %v", err)
	}
	if args.Other == nil || reflect.TypeOf(*args.Other) != reflect.TypeOf((*int)(nil)) || *args.Other == nil {
		t.Fatalf("typed nil dynamic type was flattened: %#v", args.Other)
	}
}

func TestPointerAnyRejectsOtherPointerShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target any
	}{
		{"pointer to named empty interface", namedInterfacePointerArgs{}},
		{"pointer to nonempty interface", nonemptyInterfacePointerArgs{}},
		{"nested pointer", nestedPointerAnyArgs{}},
		{"defined pointer to any", definedPointerAnyArgs{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ArgumentNames(tc.target); err == nil {
				t.Fatalf("unsupported pointer shape accepted: %T", tc.target)
			}
			if _, err := NewFlagSet("unsupported", tc.target); err == nil {
				t.Fatalf("unsupported pointer shape generated flags: %T", tc.target)
			}
		})
	}
}

func TestDecodeRejectsDefinedPointerAnyWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		structured map[string]any
		provided   map[string]string
	}{
		{"structured map", map[string]any{"value": "replacement"}, nil},
		{"flag input", nil, map[string]string{"value": "replacement"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := any("preserved")
			initial := definedPointerAny(&prior)
			target := &definedPointerAnyArgs{Value: initial}
			err := Decode(target, tc.structured, tc.provided)
			if err == nil || !strings.Contains(err.Error(), "unsupported pointer type") {
				t.Fatalf("Decode error = %v, want unsupported pointer type", err)
			}
			if target.Value != initial || *target.Value != "preserved" {
				t.Fatalf("Decode mutated defined pointer destination: got %#v, value=%#v", target.Value, *target.Value)
			}
		})
	}
}

type plainAnyRegressionArgs struct {
	Value any `statekit:"required,name=value"`
}

// TestPlainAnyBindingRemainsUnchanged protects the existing non-pointer any
// semantics independently of the new opt-in *any presence representation.
func TestPlainAnyBindingRemainsUnchanged(t *testing.T) {
	var typedNil any = (*int)(nil)
	for _, value := range []any{
		map[string]any{"x": true}, int(3), float64(3), true, typedNil, "text",
	} {
		args := &plainAnyRegressionArgs{}
		if err := Decode(args, map[string]any{"value": value}, nil); err != nil {
			t.Fatalf("plain any decode %#v: %v", value, err)
		}
		if !reflect.DeepEqual(args.Value, value) || reflect.TypeOf(args.Value) != reflect.TypeOf(value) {
			t.Fatalf("plain any value = %#v (%T), want %#v (%T)", args.Value, args.Value, value, value)
		}
	}
	args := &plainAnyRegressionArgs{Value: "prior"}
	if err := Decode(args, map[string]any{"value": nil}, nil); err == nil || args.Value != nil {
		t.Fatalf("required plain any null = %#v, err=%v; null must reset then fail required", args.Value, err)
	}
	if err := Decode(&plainAnyRegressionArgs{}, nil, nil); err == nil {
		t.Fatal("required plain any nil must remain missing")
	}
}

func TestMapFieldsFromStructuredInput(t *testing.T) {
	args := &mapArgs{}
	structured := map[string]any{
		"name":    "x",
		"labels":  map[string]any{"env": "prod", "tier": "1"},
		"payload": map[string]any{"mode": "worker", "level": "info", "retries": 3},
	}
	if err := Decode(args, structured, nil); err != nil {
		t.Fatalf("decode maps: %v", err)
	}
	if args.Labels["env"] != "prod" || args.Payload["level"] != "info" {
		t.Fatalf("maps lost: %+v %+v", args.Labels, args.Payload)
	}
	if args.Payload["retries"] != float64(3) && args.Payload["retries"] != int(3) &&
		args.Payload["retries"] != int64(3) {
		t.Fatalf("numeric payload = %#v", args.Payload["retries"])
	}

	bad := &mapArgs{}
	structuredBad := map[string]any{
		"name": "x", "labels": map[string]any{"env": []any{"a"}},
	}
	if err := Decode(bad, structuredBad, nil); err == nil {
		t.Fatal("non-scalar label must fail")
	}
}

func TestMapFieldsHaveNoCLIFlag(t *testing.T) {
	fs, err := NewFlagSet("maps", mapArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("payload") != nil || fs.Lookup("labels") != nil {
		t.Fatal("map fields must not generate CLI flags")
	}
}

type triStateArgs struct {
	Name  string `statekit:"required"`
	Force *bool  `statekit:"name=force"`
}

func TestPointerBoolTriState(t *testing.T) {
	// Omitted everywhere: pointer stays nil so the function default wins.
	args := &triStateArgs{Name: "x"}
	if err := Decode(args, nil, nil); err != nil {
		t.Fatalf("decode omitted: %v", err)
	}
	if args.Force != nil {
		t.Fatalf("omitted force must stay nil, got %v", *args.Force)
	}

	// Structured input sets the pointer.
	structured := map[string]any{"name": "x", "force": true}
	args2 := &triStateArgs{}
	if err := Decode(args2, structured, nil); err != nil {
		t.Fatalf("decode structured: %v", err)
	}
	if args2.Force == nil || !*args2.Force {
		t.Fatalf("structured force = %+v", args2.Force)
	}

	// Explicit CLI flag wins and can set false.
	args3 := &triStateArgs{}
	if err := Decode(args3, structured, map[string]string{"force": "false"}); err != nil {
		t.Fatalf("decode flag: %v", err)
	}
	if args3.Force == nil || *args3.Force {
		t.Fatalf("flag force = %+v", args3.Force)
	}
}

func TestPointerBoolFlagForms(t *testing.T) {
	fs, err := NewFlagSet("tristate", triStateArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("force") == nil {
		t.Fatal("*bool must generate a CLI flag")
	}
	normalized, err := NormalizeBoolArgs([]string{"--force", "true", "--name", "x"}, triStateArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized[0] != "--force=true" {
		t.Fatalf("spaced bool not normalized: %v", normalized)
	}
}

type triStringArgs struct {
	Password *string `statekit:"name=password"`
}

type triIntArgs struct {
	CacheValidTime *int `statekit:"name=cache_valid_time"`
}

type triInt64Args struct {
	Value *int64 `statekit:"name=value"`
}

func TestPointerIntegerArgumentNamesAndFlag(t *testing.T) {
	names, err := ArgumentNames(triIntArgs{})
	if err != nil || !reflect.DeepEqual(names, []string{"cache_valid_time"}) {
		t.Fatalf("argument names=%v err=%v", names, err)
	}
	fs, err := NewFlagSet("integer", triIntArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("cache_valid_time") == nil {
		t.Fatal("*int must generate a CLI string flag")
	}
	normalized, err := NormalizeBoolArgs([]string{"--cache_valid_time", "0"}, triIntArgs{})
	if err != nil || !reflect.DeepEqual(normalized, []string{"--cache_valid_time", "0"}) {
		t.Fatalf("integer flag must not be normalized as bool: %v err=%v", normalized, err)
	}
	args := &triIntArgs{}
	if err := Decode(args, nil, map[string]string{"cache_valid_time": "0"}); err != nil {
		t.Fatalf("zero flag decode: %v", err)
	}
	if args.CacheValidTime == nil || *args.CacheValidTime != 0 {
		t.Fatalf("explicit zero flag = %+v", args.CacheValidTime)
	}
}

func TestPointerIntegerStructuredTriStateAndCoercion(t *testing.T) {
	omitted := &triIntArgs{}
	if err := Decode(omitted, nil, nil); err != nil {
		t.Fatal(err)
	}
	if omitted.CacheValidTime != nil {
		t.Fatalf("omitted integer must stay nil, got %v", *omitted.CacheValidTime)
	}
	for _, tc := range []struct {
		name  string
		value any
		want  int
	}{
		{"int", 15, 15},
		{"int64", int64(16), 16},
		{"float", float64(17), 17},
		{"string", "18", 18},
		{"zero", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &triIntArgs{}
			if err := Decode(args, map[string]any{"cache_valid_time": tc.value}, nil); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if args.CacheValidTime == nil || *args.CacheValidTime != tc.want {
				t.Fatalf("decoded = %+v, want %d", args.CacheValidTime, tc.want)
			}
		})
	}
	args := &triIntArgs{}
	if err := Decode(args, map[string]any{"cache_valid_time": 1}, map[string]string{"cache_valid_time": "19"}); err != nil {
		t.Fatalf("flag precedence: %v", err)
	}
	if args.CacheValidTime == nil || *args.CacheValidTime != 19 {
		t.Fatalf("flag precedence = %+v", args.CacheValidTime)
	}

	args64 := &triInt64Args{}
	if err := Decode(args64, map[string]any{"value": int64(1)}, nil); err != nil || args64.Value == nil || *args64.Value != 1 {
		t.Fatalf("*int64 decode = %+v err=%v", args64.Value, err)
	}
}

func TestPointerIntegerRejectsInvalidAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"fraction", 1.5},
		{"wrong type", true},
		{"string overflow", "9223372036854775808"},
		{"float overflow", float64(9223372036854775808)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Decode(&triInt64Args{}, map[string]any{"value": tc.value}, nil); err == nil {
				t.Fatal("expected deterministic conversion error")
			}
		})
	}
	if err := Decode(&triIntArgs{}, nil, map[string]string{"cache_valid_time": "9223372036854775808"}); err == nil {
		t.Fatal("overflowing integer flag must fail")
	}
}

func TestStructuredIntegerNativeBoundsAndNarrowRange(t *testing.T) {
	bits := reflect.TypeOf(int(0)).Bits()
	max := int64(1<<(bits-1) - 1)
	min := -max - 1
	for _, tc := range []struct {
		name  string
		value int64
		want  int
	}{
		{"max", max, int(max)},
		{"min", min, int(min)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &sampleArgs{}
			if err := Decode(args, map[string]any{"name": "x", "retries": tc.value}, nil); err != nil {
				t.Fatalf("decode %s: %v", tc.name, err)
			}
			if args.Retries != tc.want {
				t.Fatalf("retries = %d, want %d", args.Retries, tc.want)
			}
		})
	}

	narrow := reflect.New(reflect.TypeOf(int8(0))).Elem()
	if err := setIntScalar(narrow, 127); err != nil || narrow.Int() != 127 {
		t.Fatalf("narrow max: value=%d err=%v", narrow.Int(), err)
	}
	narrow.SetInt(0)
	if err := setIntScalar(narrow, -128); err != nil || narrow.Int() != -128 {
		t.Fatalf("narrow min: value=%d err=%v", narrow.Int(), err)
	}
	for _, value := range []int64{128, -129} {
		narrow.SetInt(0)
		if err := setIntScalar(narrow, value); err == nil {
			t.Fatalf("set narrow %d: expected overflow", value)
		}
		if narrow.Int() != 0 {
			t.Fatalf("set narrow %d changed target to %d", value, narrow.Int())
		}
	}
	if bits < 64 {
		args := &sampleArgs{}
		if err := Decode(args, map[string]any{"name": "x", "retries": int64(max) + 1}, nil); err == nil {
			t.Fatal("int64-to-int overflow must fail")
		}
	}
}

func TestPointerStringTriState(t *testing.T) {
	args := &triStringArgs{}
	if err := Decode(args, nil, nil); err != nil {
		t.Fatalf("decode omitted: %v", err)
	}
	if args.Password != nil {
		t.Fatalf("omitted password must stay nil, got %q", *args.Password)
	}
	structured := map[string]any{"password": ""}
	if err := Decode(args, structured, nil); err != nil {
		t.Fatalf("decode structured: %v", err)
	}
	if args.Password == nil || *args.Password != "" {
		t.Fatalf("explicit empty must be preserved, got %+v", args.Password)
	}
	flagged := &triStringArgs{}
	if err := Decode(flagged, nil, map[string]string{"password": "secret"}); err != nil {
		t.Fatalf("decode flag: %v", err)
	}
	if flagged.Password == nil || *flagged.Password != "secret" {
		t.Fatalf("flag password = %+v", flagged.Password)
	}
}

type anyListArgs struct {
	Pkgs []any `statekit:"name=pkgs"`
}

func TestAnySliceStructured(t *testing.T) {
	// Structured list-of-dicts survives decoding with map values intact.
	structured := map[string]any{
		"pkgs": []any{
			map[string]any{"vim": "9.0"},
			map[string]any{"curl": nil},
			"plain",
		},
	}
	args := &anyListArgs{}
	if err := Decode(args, structured, nil); err != nil {
		t.Fatalf("decode structured: %v", err)
	}
	want := []any{map[string]any{"vim": "9.0"}, map[string]any{"curl": nil}, "plain"}
	if !reflect.DeepEqual(args.Pkgs, want) {
		t.Fatalf("pkgs = %#v, want %#v", args.Pkgs, want)
	}

	// Omitted stays nil.
	empty := &anyListArgs{}
	if err := Decode(empty, nil, nil); err != nil || empty.Pkgs != nil {
		t.Fatalf("omitted pkgs = %v, %v", empty.Pkgs, err)
	}

	// No CLI flag is generated; flags cannot express dict lists.
	fs, err := NewFlagSet("anylist", anyListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("pkgs") != nil {
		t.Fatal("[]any fields must not generate CLI flags")
	}
	if err := Decode(&anyListArgs{}, nil, map[string]string{"pkgs": "x"}); err == nil {
		t.Fatal("flag-provided pkgs must be rejected")
	}
}

func TestAnySliceYAMLStringCoercion(t *testing.T) {
	// A YAML string mirrors salt.utils.yaml.safe_load coercion: valid lists
	// parse into real elements...
	args := &anyListArgs{}
	structured := map[string]any{"pkgs": `[{"foo": "1"}]`}
	if err := Decode(args, structured, nil); err != nil {
		t.Fatalf("decode yaml string: %v", err)
	}
	want := []any{map[string]any{"foo": "1"}}
	if !reflect.DeepEqual(args.Pkgs, want) {
		t.Fatalf("coerced = %#v, want %#v", args.Pkgs, want)
	}

	// ...non-list YAML degrades to a single wrapped element that downstream
	// validation rejects, mirroring Salt's invalid-element path.
	degenerate := &anyListArgs{}
	if err := Decode(degenerate, map[string]any{"pkgs": "sources"}, nil); err != nil {
		t.Fatalf("decode degenerate string: %v", err)
	}
	if !reflect.DeepEqual(degenerate.Pkgs, []any{"sources"}) {
		t.Fatalf("degenerate coercion = %#v", degenerate.Pkgs)
	}
}

// TestPointerStringSliceStructuredNullClearsPopulatedTarget pins the reuse
// contract of the tri-state list: an explicitly null structured value
// resets the field to nil even when the target already carries a value,
// while an omitted key leaves any prior value untouched, and an explicit
// CLI flag still wins over structured null.
func TestPointerStringSliceStructuredNullClearsPopulatedTarget(t *testing.T) {
	populated := &optionalListArgs{Subsystems: strPtr("usb", "block")}
	if err := Decode(populated, map[string]any{"subsystems": nil}, nil); err != nil {
		t.Fatalf("decode structured null: %v", err)
	}
	if populated.Subsystems != nil {
		t.Fatalf("explicit structured null must clear a populated target, got %v", *populated.Subsystems)
	}

	emptyPrior := &optionalListArgs{Subsystems: strPtr()}
	if err := Decode(emptyPrior, map[string]any{"subsystems": nil}, nil); err != nil {
		t.Fatalf("decode structured null over empty list: %v", err)
	}
	if emptyPrior.Subsystems != nil {
		t.Fatalf("explicit structured null must clear a pointer-to-empty target, got %v", *emptyPrior.Subsystems)
	}

	omitted := &optionalListArgs{Subsystems: strPtr("usb")}
	if err := Decode(omitted, map[string]any{}, nil); err != nil {
		t.Fatalf("decode omitted: %v", err)
	}
	if omitted.Subsystems == nil || !reflect.DeepEqual(*omitted.Subsystems, []string{"usb"}) {
		t.Fatalf("omitted key must leave the prior value untouched, got %v", omitted.Subsystems)
	}

	precedence := &optionalListArgs{Subsystems: strPtr("usb")}
	if err := Decode(precedence, map[string]any{"subsystems": nil},
		map[string]string{"subsystems": "pci"}); err != nil {
		t.Fatalf("decode flag over null: %v", err)
	}
	if precedence.Subsystems == nil || !reflect.DeepEqual(*precedence.Subsystems, []string{"pci"}) {
		t.Fatalf("explicit CLI flag must beat structured null, got %v", precedence.Subsystems)
	}
}

func strPtr(values ...string) *[]string {
	list := append([]string(nil), values...)
	return &list
}

// boundedListArgs carries exportdb's exact filter ceilings on a decoded
// argument; smallBoundedListArgs uses smaller limits so the total-bytes
// check is independently reachable (256x256 makes the udev aggregate the
// exact arithmetic maximum).
type boundedListArgs struct {
	Subsystems *[]string `statekit:"name=subsystems,maxentries=256,maxentrybytes=256,maxtotalbytes=65536"`
}

type smallBoundedListArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=8,maxentrybytes=16,maxtotalbytes=32"`
}

func joinCSV(items ...string) string {
	return strings.Join(items, ",")
}

// TestPointerStringSliceBoundedCLILimits proves the CLI comma value is
// bounded before any destination allocation: entry count, entry bytes,
// aggregate bytes, and a raw-value ceiling that also rejects
// delimiter-heavy inputs regardless of how few tokens they keep.
func TestPointerStringSliceBoundedCLILimits(t *testing.T) {
	repeat := func(n, l int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("s", l)
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"256 entries", joinCSV(repeat(256, 1)...), false},
		{"257 entries", joinCSV(repeat(257, 1)...), true},
		{"256 byte entry", strings.Repeat("s", 256), false},
		{"257 byte entry", strings.Repeat("s", 257), true},
		{"aggregate 64 KiB", joinCSV(repeat(256, 256)...), false},
		{"exact 65792-byte raw ceiling", " " + joinCSV(repeat(256, 256)...), false},
		{"raw ceiling exceeded by padding", joinCSV(repeat(256, 256)...) + "," + strings.Repeat(" ", 300), true},
		{"delimiter heavy within ceiling", strings.Repeat(",", 65500), false},
		{"delimiter heavy over ceiling", strings.Repeat(",", 65793), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &boundedListArgs{}
			err := Decode(args, nil, map[string]string{"subsystems": tc.raw})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected bounded-list rejection")
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Fatalf("diagnostic leaked value: %v", err)
				}
				if args.Subsystems != nil {
					t.Fatalf("rejected input must not materialize a list, got %v", *args.Subsystems)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid bounded value rejected: %v", err)
			}
		})
	}

	// The valid maxima decode to the exact expected content, not just an
	// absent error: 256 single-byte entries, the 64 KiB aggregate as 256
	// entries of 256 bytes, and the exact 65,792-byte raw boundary
	// (65,791 content bytes plus one trimmable padding byte).
	maxEntries := &boundedListArgs{}
	if err := Decode(maxEntries, nil, map[string]string{"subsystems": joinCSV(repeat(256, 1)...)}); err != nil {
		t.Fatalf("256-entry max: %v", err)
	}
	if maxEntries.Subsystems == nil || len(*maxEntries.Subsystems) != 256 || (*maxEntries.Subsystems)[0] != "s" ||
		(*maxEntries.Subsystems)[255] != "s" {
		t.Fatalf("256-entry max content = %v", maxEntries.Subsystems)
	}
	maxTotal := &boundedListArgs{}
	maxTotalRaw := joinCSV(repeat(256, 256)...)
	if err := Decode(maxTotal, nil, map[string]string{"subsystems": maxTotalRaw}); err != nil {
		t.Fatalf("64 KiB aggregate max: %v", err)
	}
	if maxTotal.Subsystems == nil || len(*maxTotal.Subsystems) != 256 ||
		len((*maxTotal.Subsystems)[42]) != 256 || (*maxTotal.Subsystems)[42] != strings.Repeat("s", 256) {
		t.Fatalf("64 KiB aggregate content = %v", maxTotal.Subsystems)
	}
	exactRaw := &boundedListArgs{}
	exactRawValue := " " + maxTotalRaw // 1 + 65536 + 255 = 65,792 bytes exactly
	if len(exactRawValue) != 65792 {
		t.Fatalf("test construction: raw length = %d, want 65792", len(exactRawValue))
	}
	if err := Decode(exactRaw, nil, map[string]string{"subsystems": exactRawValue}); err != nil {
		t.Fatalf("exact 65792-byte raw boundary: %v", err)
	}
	if exactRaw.Subsystems == nil || len(*exactRaw.Subsystems) != 256 {
		t.Fatalf("exact raw boundary content = %v", exactRaw.Subsystems)
	}

	// Secret-looking over-limit values never reach the error text.
	err := Decode(&boundedListArgs{}, nil,
		map[string]string{"subsystems": strings.Repeat("SECRET-ENTRY", 40)})
	if err == nil || strings.Contains(err.Error(), "SECRET-ENTRY") {
		t.Fatalf("value-free bounded error required: %v", err)
	}
}

// TestPointerStringSliceBoundedTotalBytes reaches the aggregate check with
// limits whose count and entry caps alone cannot trigger it.
func TestPointerStringSliceBoundedTotalBytes(t *testing.T) {
	ok := &smallBoundedListArgs{}
	if err := Decode(ok, nil, map[string]string{"tags": joinCSV(strings.Repeat("a", 16), strings.Repeat("b", 16))}); err != nil {
		t.Fatalf("exact total must pass: %v", err)
	}
	if ok.Tags == nil || len(*ok.Tags) != 2 {
		t.Fatalf("tags = %v", ok.Tags)
	}
	over := &smallBoundedListArgs{}
	err := Decode(over, nil, map[string]string{"tags": joinCSV(
		strings.Repeat("a", 16), strings.Repeat("b", 16), strings.Repeat("c", 1))})
	if err == nil {
		t.Fatal("aggregate over the total cap must fail")
	}
	if over.Tags != nil {
		t.Fatalf("over-total input must not materialize, got %v", *over.Tags)
	}
}

// TestPointerStringSliceBoundedStructured applies the same ceilings to
// structured arrays before the destination copy, keeping the strict
// element typing and the tri-state semantics.
func TestPointerStringSliceBoundedStructured(t *testing.T) {
	repeat := func(n, l int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = strings.Repeat("s", l)
		}
		return out
	}
	if err := Decode(&boundedListArgs{}, map[string]any{"subsystems": repeat(256, 1)}, nil); err != nil {
		t.Fatalf("256 structured entries must pass: %v", err)
	}
	if err := Decode(&boundedListArgs{}, map[string]any{"subsystems": repeat(257, 1)}, nil); err == nil {
		t.Fatal("257 structured entries must fail")
	}
	if err := Decode(&boundedListArgs{}, map[string]any{"subsystems": repeat(1, 256)}, nil); err != nil {
		t.Fatalf("256-byte structured entry must pass: %v", err)
	}
	err := Decode(&boundedListArgs{}, map[string]any{"subsystems": repeat(1, 257)}, nil)
	if err == nil {
		t.Fatal("257-byte structured entry must fail")
	}
	if strings.Contains(err.Error(), "ssss") {
		t.Fatalf("structured entry diagnostic leaked value bytes: %v", err)
	}
	// Custom limits reach the structured aggregate check independently.
	err = Decode(&smallBoundedListArgs{}, map[string]any{"tags": []any{
		strings.Repeat("a", 16), strings.Repeat("b", 16), "c"}}, nil)
	if err == nil {
		t.Fatal("structured aggregate over the total cap must fail")
	}

	// Tri-state semantics keep working on bounded fields.
	omitted := &boundedListArgs{}
	if err := Decode(omitted, nil, nil); err != nil || omitted.Subsystems != nil {
		t.Fatalf("omitted bounded list = %v, %v", omitted.Subsystems, err)
	}
	nulled := &boundedListArgs{Subsystems: strPtr("usb")}
	if err := Decode(nulled, map[string]any{"subsystems": nil}, nil); err != nil || nulled.Subsystems != nil {
		t.Fatalf("structured null bounded list = %v, %v", nulled.Subsystems, err)
	}
	emptyList := &boundedListArgs{}
	if err := Decode(emptyList, map[string]any{"subsystems": []any{}}, nil); err != nil {
		t.Fatalf("structured empty bounded list: %v", err)
	}
	if emptyList.Subsystems == nil || *emptyList.Subsystems == nil || len(*emptyList.Subsystems) != 0 {
		t.Fatalf("structured empty bounded list = %v", emptyList.Subsystems)
	}
	precedence := &boundedListArgs{}
	if err := Decode(precedence, map[string]any{"subsystems": repeat(2, 1)},
		map[string]string{"subsystems": "pci"}); err != nil {
		t.Fatalf("bounded precedence: %v", err)
	}
	if precedence.Subsystems == nil || !reflect.DeepEqual(*precedence.Subsystems, []string{"pci"}) {
		t.Fatalf("bounded precedence = %v", precedence.Subsystems)
	}
}

type badListLimitTargets struct {
	Name string   `statekit:"name=name,maxentries=4"`
	Tags []string `statekit:"name=tags,maxentries=4"`
}

type partialListLimitArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=4"`
}

type zeroListLimitArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=0,maxentrybytes=0,maxtotalbytes=0"`
}

// plainBoundedListArgs declares complete, valid limits on an ordinary
// []string field: the ceiling mechanism is reserved for tri-state pointer
// lists, so this schema must be rejected.
type plainBoundedListArgs struct {
	Tags []string `statekit:"name=tags,maxentries=8,maxentrybytes=16,maxtotalbytes=32"`
}

type dupEntriesLimitArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=4,maxentries=8,maxentrybytes=16,maxtotalbytes=32"`
}

type dupEntryBytesLimitArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=4,maxentrybytes=16,maxentrybytes=8,maxtotalbytes=32"`
}

type dupTotalLimitArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=4,maxentrybytes=16,maxtotalbytes=32,maxtotalbytes=64"`
}

// dupEntriesMissingTotalArgs evades a pure occurrence count: three option
// occurrences with maxentries duplicated and maxtotalbytes missing. Only
// explicit distinct-key tracking rejects it.
type dupEntriesMissingTotalArgs struct {
	Tags *[]string `statekit:"name=tags,maxentries=4,maxentries=8,maxentrybytes=16"`
}

// TestListLimitTagValidation keeps the per-field ceiling mechanism
// explicit: limits are all-or-nothing (each of the three distinct keys
// exactly once), positive, and valid only on *[]string tri-state fields —
// never on ordinary []string or non-list fields.
func TestListLimitTagValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target any
	}{
		{"non-list field", badListLimitTargets{}},
		{"incomplete set", partialListLimitArgs{}},
		{"non-positive values", zeroListLimitArgs{}},
		{"ordinary slice with limits", plainBoundedListArgs{}},
		{"duplicate maxentries", dupEntriesLimitArgs{}},
		{"duplicate maxentrybytes", dupEntryBytesLimitArgs{}},
		{"duplicate maxtotalbytes", dupTotalLimitArgs{}},
		{"duplicate displacing missing key", dupEntriesMissingTotalArgs{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ArgumentNames(tc.target); err == nil {
				t.Fatalf("invalid list-limit tags must fail spec validation: %T", tc.target)
			}
			if _, err := NewFlagSet("bad", tc.target); err == nil {
				t.Fatalf("invalid list-limit tags must fail flagset construction: %T", tc.target)
			}
		})
	}
	if _, err := ArgumentNames(boundedListArgs{}); err != nil {
		t.Fatalf("valid *[]string list-limit tags must pass: %v", err)
	}
}

// TestUntaggedPlainSliceCompatibilityStaysCoercing pins the historical
// ordinary []string semantics now that bounded lists are pointer-only:
// structured scalars still coerce to a single-element list.
func TestUntaggedPlainSliceCompatibilityStaysCoercing(t *testing.T) {
	tags := &sampleArgs{}
	if err := Decode(tags, map[string]any{"name": "x", "tags": "usb"}, nil); err != nil {
		t.Fatalf("plain slice scalar coercion: %v", err)
	}
	if !reflect.DeepEqual(tags.Tags, []string{"usb"}) {
		t.Fatalf("plain slice scalar coercion = %#v", tags.Tags)
	}
	if err := Decode(tags, map[string]any{"name": "x", "tags": 7}, nil); err != nil {
		t.Fatalf("plain slice numeric coercion must stay: %v", err)
	}
	if !reflect.DeepEqual(tags.Tags, []string{"7"}) {
		t.Fatalf("plain slice numeric coercion = %#v", tags.Tags)
	}
}

type optionalListArgs struct {
	Subsystems *[]string `statekit:"name=subsystems"`
}

// TestPointerStringSliceTriState pins the optional-list contract used by
// tri-state list arguments such as udev.exportdb's subsystems: omitted and
// structured null stay nil (caller default), structured [] is a pointer to a
// nonnil empty list (select none), structured lists must be arrays of
// strings, CLI comma syntax follows splitList, and an explicitly empty CLI
// value stays a nonnil empty list rather than reverting to nil.
func TestPointerStringSliceTriState(t *testing.T) {
	omitted := &optionalListArgs{}
	if err := Decode(omitted, nil, nil); err != nil {
		t.Fatalf("decode omitted: %v", err)
	}
	if omitted.Subsystems != nil {
		t.Fatalf("omitted subsystems must stay nil, got %v", *omitted.Subsystems)
	}

	nullList := &optionalListArgs{}
	if err := Decode(nullList, map[string]any{"subsystems": nil}, nil); err != nil {
		t.Fatalf("decode structured null: %v", err)
	}
	if nullList.Subsystems != nil {
		t.Fatalf("structured null subsystems must stay nil, got %v", *nullList.Subsystems)
	}

	emptyList := &optionalListArgs{}
	if err := Decode(emptyList, map[string]any{"subsystems": []any{}}, nil); err != nil {
		t.Fatalf("decode structured empty: %v", err)
	}
	if emptyList.Subsystems == nil || *emptyList.Subsystems == nil {
		t.Fatalf("structured [] must set a pointer to a nonnil empty list, got %v", emptyList.Subsystems)
	}

	list := &optionalListArgs{}
	if err := Decode(list, map[string]any{"subsystems": []any{"usb", "block"}}, nil); err != nil {
		t.Fatalf("decode structured list: %v", err)
	}
	if list.Subsystems == nil || !reflect.DeepEqual(*list.Subsystems, []string{"usb", "block"}) {
		t.Fatalf("structured list = %v", list.Subsystems)
	}

	flagList := &optionalListArgs{}
	if err := Decode(flagList, map[string]any{"subsystems": []any{"usb"}},
		map[string]string{"subsystems": "pci, usb,block"}); err != nil {
		t.Fatalf("decode flag list: %v", err)
	}
	if flagList.Subsystems == nil || !reflect.DeepEqual(*flagList.Subsystems, []string{"pci", "usb", "block"}) {
		t.Fatalf("flag list = %v, want explicit CLI values to override structured", flagList.Subsystems)
	}

	emptyFlag := &optionalListArgs{}
	if err := Decode(emptyFlag, nil, map[string]string{"subsystems": ""}); err != nil {
		t.Fatalf("decode explicit empty flag: %v", err)
	}
	if emptyFlag.Subsystems == nil || *emptyFlag.Subsystems == nil {
		t.Fatalf("--subsystems= must stay a nonnil empty list, got %v", emptyFlag.Subsystems)
	}

	names, err := ArgumentNames(optionalListArgs{})
	if err != nil || !reflect.DeepEqual(names, []string{"subsystems"}) {
		t.Fatalf("argument names = %v, err = %v", names, err)
	}
	fs, err := NewFlagSet("optionallist", optionalListArgs{})
	if err != nil {
		t.Fatalf("flagset: %v", err)
	}
	if fs.Lookup("subsystems") == nil {
		t.Fatal("*[]string must generate a CLI flag")
	}
}

// TestPointerStringSliceStrictStructured rejects every non-array structured
// shape before any Runner sees it, with value-free diagnostics.
func TestPointerStringSliceStrictStructured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"scalar string", "usb"},
		{"bool", true},
		{"number", 3},
		{"object", map[string]any{"usb": "block"}},
		{"nested array", []any{[]any{"usb"}}},
		{"non-string element", []any{"usb", 7}},
		{"bool element", []any{true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Decode(&optionalListArgs{}, map[string]any{"subsystems": tc.value}, nil)
			if err == nil {
				t.Fatal("expected a conversion error")
			}
		})
	}

	// Diagnostics stay value-free: a secret-looking scalar must never reach
	// the error text.
	err := Decode(&optionalListArgs{}, map[string]any{"subsystems": "SUBSYS-SECRET-VALUE"}, nil)
	if err == nil {
		t.Fatal("structured scalar must be rejected")
	}
	if strings.Contains(err.Error(), "SUBSYS-SECRET-VALUE") {
		t.Fatalf("diagnostic leaked the rejected value: %v", err)
	}
}

type unsupportedPtrSliceArgs struct {
	Bad *[]int `statekit:"name=bad"`
}

type unsupportedPtrAnySliceArgs struct {
	Bad *[]any `statekit:"name=bad"`
}

// TestPointerSliceSupportIsStringOnly keeps the pointer-slice allowance at
// exactly *[]string: other element kinds keep failing spec validation.
func TestPointerSliceSupportIsStringOnly(t *testing.T) {
	if _, err := ArgumentNames(unsupportedPtrSliceArgs{}); err == nil {
		t.Fatal("*[]int must stay unsupported")
	}
	if _, err := ArgumentNames(unsupportedPtrAnySliceArgs{}); err == nil {
		t.Fatal("*[]any must stay unsupported")
	}
	if _, err := NewFlagSet("bad", unsupportedPtrSliceArgs{}); err == nil {
		t.Fatal("unsupported pointer slice must fail flagset construction")
	}
	if err := Decode(&unsupportedPtrSliceArgs{}, nil, nil); err == nil {
		t.Fatal("unsupported pointer slice must fail decode")
	}
}
