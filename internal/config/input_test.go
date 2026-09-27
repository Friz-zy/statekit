package config

import (
	"os"
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
