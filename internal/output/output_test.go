package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/result"
)

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":     FormatText,
		"json": FormatJSON,
		"JSON": FormatJSON,
		"yaml": FormatYAML,
		"text": FormatText,
	}
	for input, want := range cases {
		got, err := ParseFormat(input)
		if err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("unknown format must fail")
	}
}

func TestEncodeJSON(t *testing.T) {
	var b bytes.Buffer
	res := result.Success("nginx", "Service nginx is running")
	if err := Encode(&b, FormatJSON, res); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, b.String())
	}
	if back["result"] != true || back["changes"] == nil {
		t.Fatalf("core fields missing: %s", b.String())
	}
}

func TestEncodeYAML(t *testing.T) {
	var b bytes.Buffer
	res := result.TestPending("curl", "Package curl would be installed", map[string]any{
		"curl": map[string]any{"old": "", "new": "latest"},
	})
	if err := Encode(&b, FormatYAML, res); err != nil {
		t.Fatalf("encode: %v", err)
	}
	out := b.String()
	for _, want := range []string{"result: null", "comment: Package curl would be installed", "new: latest"} {
		if !strings.Contains(out, want) {
			t.Fatalf("yaml output missing %q:\n%s", want, out)
		}
	}
}

func TestStateResultText(t *testing.T) {
	text := StateResultText(result.Success("example", "Success!"))
	want := "name: example\nresult: true\ncomment: Success!\nchanges: {}\n"
	if text != want {
		t.Fatalf("text =\n%q\nwant\n%q", text, want)
	}
}

func TestResultWord(t *testing.T) {
	if ResultWord(nil) != "null" || ResultWord(result.Bool(true)) != "true" || ResultWord(result.Bool(false)) != "false" {
		t.Fatal("ResultWord tri-state broken")
	}
}

func TestEncodePlainTextScalars(t *testing.T) {
	var b bytes.Buffer
	if err := Encode(&b, FormatText, "hello"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if b.String() != "hello\n" {
		t.Fatalf("plain text scalar = %q", b.String())
	}
}
