package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestChannelsLoadScopedBoundedStructuredInput(t *testing.T) {
	const bound = 128
	oversize := `{"query":"` + strings.Repeat("synthetic-marker-", 9) + `"}`
	file := writeTemp(t, t.TempDir(), "request.json", oversize)
	for _, ch := range []Channels{
		{Stdin: true, Data: []byte(oversize), MaxBytes: bound},
		{Config: oversize, MaxBytes: bound},
		{File: file, MaxBytes: bound},
	} {
		got, err := ch.Load()
		if err == nil || got != nil || strings.Contains(err.Error(), "synthetic-marker") {
			t.Fatalf("oversized structured input returned %#v err=%v", got, err)
		}
	}
	got, err := (Channels{Config: `{"query":"safe"}`, MaxBytes: bound}).Load()
	if err != nil || got["query"] != "safe" {
		t.Fatalf("bounded valid config %#v err=%v", got, err)
	}
}

func TestParseStructured(t *testing.T) {
	fromJSON, err := ParseStructured([]byte(`{"name":"curl","version":"8.14.1"}`))
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if fromJSON["name"] != "curl" || fromJSON["version"] != "8.14.1" {
		t.Fatalf("json parse lost data: %v", fromJSON)
	}

	fromYAML, err := ParseStructured([]byte("name: curl\nversion: \"8.14.1\"\n"))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if fromYAML["name"] != "curl" {
		t.Fatalf("yaml parse lost data: %v", fromYAML)
	}

	empty, err := ParseStructured([]byte("   \n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty input must yield empty map, got %v err=%v", empty, err)
	}

	if _, err := ParseStructured([]byte("- a\n- b\n")); err == nil {
		t.Fatal("top-level list must be rejected")
	}
	if _, err := ParseStructured([]byte("just a scalar")); err == nil {
		t.Fatal("top-level scalar must be rejected")
	}
}

// TestParseStructuredOtherNumericTransportMatrix pins the distinct raw
// dynamic types produced by JSON-first input and YAML fallback. Binding is
// intentionally not allowed to rescue JSON float64 numbers into integers.
func TestParseStructuredOtherNumericTransportMatrix(t *testing.T) {
	type parserRow struct {
		name      string
		token     string
		jsonType  reflect.Type
		jsonValue any
		yamlType  reflect.Type
		yamlValue any
	}
	typeOf := func(v any) reflect.Type { return reflect.TypeOf(v) }
	rows := []parserRow{
		{name: "null", token: "null", jsonValue: nil, yamlValue: nil},
		{name: "empty string", token: `""`, jsonType: typeOf(""), jsonValue: "", yamlType: typeOf(""), yamlValue: ""},
		{name: "quoted digits", token: `"0007"`, jsonType: typeOf(""), jsonValue: "0007", yamlType: typeOf(""), yamlValue: "0007"},
		{name: "zero", token: "0", jsonType: typeOf(float64(0)), jsonValue: float64(0), yamlType: typeOf(int(0)), yamlValue: int(0)},
		{name: "negative one", token: "-1", jsonType: typeOf(float64(0)), jsonValue: float64(-1), yamlType: typeOf(int(0)), yamlValue: int(-1)},
		{name: "minimum signed 64", token: "-9223372036854775808", jsonType: typeOf(float64(0)), jsonValue: float64(-9223372036854775808)},
		{name: "maximum signed 64", token: "9223372036854775807", jsonType: typeOf(float64(0)), jsonValue: float64(9223372036854775807)},
		{name: "signed maximum plus one", token: "9223372036854775808", jsonType: typeOf(float64(0)), jsonValue: float64(9223372036854775808), yamlType: typeOf(uint64(0)), yamlValue: uint64(9223372036854775808)},
		{name: "uint64 maximum", token: "18446744073709551615", jsonType: typeOf(float64(0)), jsonValue: float64(18446744073709551615), yamlType: typeOf(uint64(0)), yamlValue: uint64(18446744073709551615)},
		{name: "below signed minimum", token: "-9223372036854775809", jsonType: typeOf(float64(0)), jsonValue: float64(-9223372036854775809), yamlType: typeOf(float64(0)), yamlValue: float64(-9223372036854775809)},
		{name: "above unsigned maximum", token: "18446744073709551616", jsonType: typeOf(float64(0)), jsonValue: float64(18446744073709551616), yamlType: typeOf(float64(0)), yamlValue: float64(18446744073709551616)},
		{name: "fraction", token: "1.5", jsonType: typeOf(float64(0)), jsonValue: float64(1.5), yamlType: typeOf(float64(0)), yamlValue: float64(1.5)},
		{name: "decimal point", token: "1.0", jsonType: typeOf(float64(0)), jsonValue: float64(1), yamlType: typeOf(float64(0)), yamlValue: float64(1)},
		{name: "true", token: "true", jsonType: typeOf(true), jsonValue: true, yamlType: typeOf(true), yamlValue: true},
		{name: "false", token: "false", jsonType: typeOf(false), jsonValue: false, yamlType: typeOf(false), yamlValue: false},
		{name: "array", token: "[0]", jsonType: typeOf([]any{}), jsonValue: []any{float64(0)}, yamlType: typeOf([]any{}), yamlValue: []any{int(0)}},
		{name: "object", token: `{"x":0}`, jsonType: typeOf(map[string]any{}), jsonValue: map[string]any{"x": float64(0)}, yamlType: typeOf(map[string]any{}), yamlValue: map[string]any{"x": int(0)}},
	}

	min64, max64 := int64(-9223372036854775808), int64(9223372036854775807)
	for i := range rows {
		switch rows[i].name {
		case "minimum signed 64":
			rows[i].yamlValue = min64
			if reflect.TypeOf(int(0)).Bits() == 64 {
				rows[i].yamlType = typeOf(int(0))
				rows[i].yamlValue = int(min64)
			} else {
				rows[i].yamlType = typeOf(int64(0))
			}
		case "maximum signed 64":
			rows[i].yamlValue = max64
			if reflect.TypeOf(int(0)).Bits() == 64 {
				rows[i].yamlType = typeOf(int(0))
				rows[i].yamlValue = int(max64)
			} else {
				rows[i].yamlType = typeOf(int64(0))
			}
		}
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			jsonInput := []byte(`{"name":"synthetic","other":` + row.token + `}`)
			parsedJSON, err := ParseStructured(jsonInput)
			if err != nil {
				t.Fatalf("JSON parse: %v", err)
			}
			jsonValue, jsonPresent := parsedJSON["other"]
			if !jsonPresent || (row.jsonType == nil && jsonValue != nil) ||
				(row.jsonType != nil && reflect.TypeOf(jsonValue) != row.jsonType) ||
				!reflect.DeepEqual(jsonValue, row.jsonValue) {
				t.Fatalf("JSON raw other = %#v (%T), present=%v; want %#v (%v), present=true", jsonValue, jsonValue, jsonPresent, row.jsonValue, row.jsonType)
			}

			yamlInput := []byte("name: synthetic\nother: " + row.token + "\n")
			if row.name == "null" {
				yamlInput = []byte("name: synthetic\nother:\n")
			}
			parsedYAML, err := ParseStructured(yamlInput)
			if err != nil {
				t.Fatalf("YAML fallback parse: %v", err)
			}
			yamlValue, yamlPresent := parsedYAML["other"]
			if !yamlPresent || (row.yamlType == nil && yamlValue != nil) ||
				(row.yamlType != nil && reflect.TypeOf(yamlValue) != row.yamlType) ||
				!reflect.DeepEqual(yamlValue, row.yamlValue) {
				t.Fatalf("YAML raw other = %#v (%T), present=%v; want %#v (%v), present=true", yamlValue, yamlValue, yamlPresent, row.yamlValue, row.yamlType)
			}
		})
	}

	missing, err := ParseStructured([]byte(`{"name":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := missing["other"]; ok {
		t.Fatal("omitted other must remain absent from the parsed map")
	}
}

func TestChannelsValidateConflicts(t *testing.T) {
	cases := []struct {
		name string
		ch   Channels
		err  bool
	}{
		{"flags only", Channels{}, false},
		{"config+file", Channels{Config: "{}", File: "x.yaml"}, false},
		{"stdin+file", Channels{Stdin: true, File: "x.yaml"}, true},
		{"dash+config", Channels{Dash: true, Config: "{}"}, true},
		{"stdin alone", Channels{Stdin: true}, false},
	}
	for _, tc := range cases {
		err := tc.ch.Validate()
		if tc.err && err == nil {
			t.Fatalf("%s: expected conflict error", tc.name)
		}
		if !tc.err && err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
	}
}

func TestMergeIntoDeep(t *testing.T) {
	dst := map[string]any{"nested": map[string]any{"a": 1, "b": 2}, "keep": true}
	src := map[string]any{"nested": map[string]any{"b": 20, "c": 30}}
	mergeInto(dst, src)
	nested := dst["nested"].(map[string]any)
	if nested["a"] != 1 || nested["b"] != 20 || nested["c"] != 30 || dst["keep"] != true {
		t.Fatalf("deep merge broken: %v", nested)
	}
}

func TestChannelsLoadPrecedenceConfigOverFile(t *testing.T) {
	dir := t.TempDir()
	file := writeTemp(t, dir, "req.yaml", "text: from-file\n")
	ch := Channels{
		File:   file,
		Config: `{"text": "from-config"}`,
	}
	merged, err := ch.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if merged["text"] != "from-config" {
		t.Fatalf("config must win over file within structured tier: %v", merged)
	}
}

func TestChannelsLoadStdinDataInjected(t *testing.T) {
	ch := Channels{Stdin: true, Data: []byte("text: piped\n")}
	merged, err := ch.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if merged["text"] != "piped" {
		t.Fatalf("stdin channel broken: %v", merged)
	}
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
