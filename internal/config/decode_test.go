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
