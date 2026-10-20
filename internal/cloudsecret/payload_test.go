package cloudsecret

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFormatPayloadRawAndTextAreByteExact(t *testing.T) {
	raw := []byte{0x00, 0xff, '\n', 'x'}
	got, err := FormatPayload(raw, FormatRaw, "")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("raw payload was changed")
	}
	got, err = FormatPayload([]byte("plain"), FormatText, "")
	if err != nil || string(got) != "plain" {
		t.Fatal("text payload was changed")
	}
	for _, invalid := range [][]byte{{0xff}, []byte("line\n")} {
		if _, err := FormatPayload(invalid, FormatText, ""); !errors.Is(err, ErrInvalidPayload) {
			t.Fatal("invalid text payload was accepted")
		}
	}
	if _, err := FormatPayload(raw, FormatRaw, "/key"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("raw format accepted a key path")
	}
}

func TestFormatPayloadRawAndTextRetainPrivateOutputOwnership(t *testing.T) {
	for _, format := range []Format{FormatRaw, FormatText} {
		input := []byte("synthetic")
		output, err := FormatPayload(input, format, "")
		if err != nil || !bytes.Equal(output, input) {
			t.Fatal("raw or text format changed the payload")
		}
		output[0] = 'X'
		if input[0] != 's' {
			t.Fatal("formatted output aliases provider-owned payload bytes")
		}
		input[1] = 'Y'
		if output[1] != 'y' {
			t.Fatal("provider mutation changed the private formatted output")
		}
	}
}

func TestFormatPayloadStructuredEncodingOwnsOutputWithoutSourceCopy(t *testing.T) {
	input := []byte(`{"value":"synthetic"}`)
	output, err := FormatPayload(input, FormatJSON, "")
	if err != nil || !bytes.Equal(output, input) {
		t.Fatal("structured format changed its logical payload")
	}
	output[2] = 'X'
	if string(input) != `{"value":"synthetic"}` {
		t.Fatal("structured output aliases the provider payload")
	}
}

func TestFormatPayloadPreservesStructuredJSONTypes(t *testing.T) {
	doc := []byte(`{"s":"value","n":27,"b":true,"z":null,"o":{"x":1},"a":[false]}`)
	for _, test := range []struct {
		path string
		want string
	}{
		{"/s", `"value"`},
		{"/n", "27"},
		{"/b", "true"},
		{"/z", "null"},
		{"/o", `{"x":1}`},
		{"/a", `[false]`},
	} {
		got, err := FormatPayload(doc, FormatJSON, test.path)
		if err != nil || string(got) != test.want {
			t.Fatal("JSON selection did not preserve the selected value type")
		}
	}
}

func TestFormatPayloadPreservesStructuredYAMLTypes(t *testing.T) {
	doc := []byte("s: value\nn: 27\nb: true\nz: null\no: {x: 1}\na: [false]\n")
	for _, test := range []struct {
		path string
		want string
	}{
		{"/s", "value\n"},
		{"/n", "27\n"},
		{"/b", "true\n"},
		{"/z", "null\n"},
		{"/o", "x: 1\n"},
		{"/a", "- false\n"},
	} {
		got, err := FormatPayload(doc, FormatYAML, test.path)
		if err != nil || string(got) != test.want {
			t.Fatal("YAML selection did not preserve the selected value type")
		}
	}
}

func TestFormatPayloadRejectsDuplicateKeysAndAmbiguousYAML(t *testing.T) {
	for _, test := range []struct {
		format Format
		data   string
	}{
		{FormatJSON, `{"x":1,"x":2}`},
		{FormatYAML, "x: 1\nx: 2\n"},
		{FormatYAML, "base: &b {x: 1}\ncopy: *b\n"},
		{FormatYAML, "base: {x: 1}\ncopy: {<<: *base}\n"},
		{FormatYAML, "x: !custom value\n"},
		{FormatYAML, "1: value\n"},
		{FormatYAML, "x: 1\n---\ny: 2\n"},
	} {
		if _, err := FormatPayload([]byte(test.data), test.format, ""); !errors.Is(err, ErrInvalidPayload) {
			t.Fatal("ambiguous or duplicate document was accepted")
		}
	}
}

func TestYAMLStructuralBoundariesAndNearMaximumAdversarialInput(t *testing.T) {
	withinDepth := strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth)
	if _, err := FormatPayload([]byte(withinDepth), FormatYAML, ""); err != nil {
		t.Fatal("YAML document at the depth limit was rejected")
	}
	overDepth := strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1)
	if _, err := FormatPayload([]byte(overDepth), FormatYAML, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("over-depth YAML document was accepted")
	}

	withinScalar := strings.Repeat("s", MaxScalarBytes)
	if _, err := FormatPayload([]byte(withinScalar), FormatYAML, ""); err != nil {
		t.Fatal("YAML scalar at the byte limit was rejected")
	}
	overScalar := strings.Repeat("s", MaxScalarBytes+1)
	if _, err := FormatPayload([]byte(overScalar), FormatYAML, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("over-limit YAML scalar was accepted")
	}

	withinNodes := paddedYAMLSequence(MaxNodes-1, MaxPayloadBytes)
	if _, err := FormatPayload(withinNodes, FormatYAML, ""); err != nil {
		t.Fatal("YAML document at the node limit was rejected")
	}
	nearMaximum := paddedYAMLSequence(MaxNodes, MaxPayloadBytes)
	if len(nearMaximum) != MaxPayloadBytes {
		t.Fatal("adversarial YAML fixture did not reach the byte ceiling")
	}
	if _, err := parseYAML(nearMaximum); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("near-maximum YAML document over the node limit was accepted")
	}
	if _, err := FormatPayload(append(nearMaximum, 'x'), FormatYAML, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("YAML input above the byte limit was accepted")
	}
}

func paddedYAMLSequence(values, totalBytes int) []byte {
	var builder strings.Builder
	builder.Grow(totalBytes)
	builder.WriteByte('[')
	for i := 0; i < values; i++ {
		if i != 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('0')
	}
	builder.WriteString("]\n#")
	if builder.Len() < totalBytes {
		builder.WriteString(strings.Repeat("x", totalBytes-builder.Len()))
	}
	return []byte(builder.String())
}

func TestFormatPayloadRFC6901AndBounds(t *testing.T) {
	doc := []byte(`{"a/b":{"~key":["first","second"]}}`)
	got, err := FormatPayload(doc, FormatJSON, "/a~1b/~0key/1")
	if err != nil || string(got) != `"second"` {
		t.Fatal("RFC 6901 escaping or array selection failed")
	}
	for _, pointer := range []string{"not-a-pointer", "/a~2b", "/a~1b/~0key/01", "/absent"} {
		if _, err := FormatPayload(doc, FormatJSON, pointer); !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("invalid pointer was not rejected")
		}
	}
	if _, err := FormatPayload([]byte(strings.Repeat("x", MaxPayloadBytes+1)), FormatText, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("oversized payload was accepted")
	}
	if _, err := FormatPayload([]byte(`"`+strings.Repeat("x", MaxScalarBytes+1)+`"`), FormatJSON, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("oversized scalar was accepted")
	}
	deep := strings.Repeat("[", MaxDepth+2) + "0" + strings.Repeat("]", MaxDepth+2)
	if _, err := FormatPayload([]byte(deep), FormatJSON, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("over-depth document was accepted")
	}
	nodes := "[" + strings.Repeat("0,", MaxNodes) + "0]"
	if _, err := FormatPayload([]byte(nodes), FormatJSON, ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatal("over-node-budget document was accepted")
	}
}
