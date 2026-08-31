package config

import (
	"reflect"
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
