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
