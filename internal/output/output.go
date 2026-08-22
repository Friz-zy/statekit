// Package output renders command results as JSON, YAML, or text.
//
// Reference: plans/init.md section 8. Machine-readable formats (json, yaml)
// are the stable API; text is a human convenience rendering.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"gopkg.in/yaml.v3"
)

// Format identifies an output format.
type Format string

// Supported output formats.
const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
	FormatText Format = "text"
)

// ParseFormat validates a user-supplied format name; empty selects text.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case "":
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatYAML:
		return FormatYAML, nil
	case FormatText:
		return FormatText, nil
	default:
		return "", fmt.Errorf("invalid output format %q (want json, yaml, or text)", s)
	}
}

// Encode writes v to w in the requested format.
func Encode(w io.Writer, format Format, v any) error {
	switch format {
	case FormatJSON:
		return encodeJSON(w, v)
	case FormatYAML:
		return encodeYAML(w, v)
	case FormatText:
		return encodeText(w, v)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func encodeYAML(w io.Writer, v any) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return enc.Close()
}

// Text renders StateResult values with the Salt-compatible layout and
// everything else via YAML (plain scalars and flat maps render identically).
func encodeText(w io.Writer, v any) error {
	if state, ok := v.(result.StateResult); ok {
		_, err := io.WriteString(w, StateResultText(state))
		return err
	}
	return encodeYAML(w, v)
}

// StateResultText renders a state result for humans.
func StateResultText(r result.StateResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\n", r.Name)
	fmt.Fprintf(&b, "result: %s\n", ResultWord(r.Result))
	if r.Comment != "" {
		fmt.Fprintf(&b, "comment: %s\n", r.Comment)
	}
	switch {
	case len(r.Changes) == 0:
		b.WriteString("changes: {}\n")
	default:
		b.WriteString("changes:\n")
		if rendered, err := yaml.Marshal(r.Changes); err == nil {
			for _, line := range strings.Split(strings.TrimRight(string(rendered), "\n"), "\n") {
				fmt.Fprintf(&b, "  %s\n", line)
			}
		}
	}
	return b.String()
}

// ResultWord renders the tri-state Salt result value.
func ResultWord(p *bool) string {
	switch {
	case p == nil:
		return "null"
	case *p:
		return "true"
	default:
		return "false"
	}
}
