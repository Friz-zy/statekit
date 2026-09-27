// Package config resolves the four input channels (flags, inline YAML/JSON,
// files, stdin) into typed function arguments with Salt-compatible
// precedence: function defaults < structured input < explicit CLI flags.
//
// Reference: plans/init.md sections 6-7.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// ConflictError reports ambiguous input channel combinations.
type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return e.Message }

// Channels describes which structured input channels were supplied on the
// command line. Data carries pre-read stdin bytes for hermetic testing;
// when Data is nil and a stdin channel is active, os.Stdin is consumed.
type Channels struct {
	Config string // --config inline YAML/JSON
	File   string // --file path to YAML/JSON
	Stdin  bool   // --stdin flag
	Dash   bool   // "-" positional argument
	Data   []byte
	// MaxBytes scopes a pre-decode, pre-allocation limit to sensitive
	// functions. Zero keeps existing callers' input behavior unchanged.
	MaxBytes int
}

var ErrStructuredInputLimit = errors.New("structured input exceeds limit")

func (c Channels) structuredRequested() bool { return c.Config != "" || c.File != "" }

// Validate rejects ambiguous combinations such as --stdin + --file or
// --stdin + --config until an explicit merge mechanism exists.
func (c Channels) Validate() error {
	if c.Stdin || c.Dash {
		if c.File != "" {
			return &ConflictError{Message: "--stdin cannot be combined with --file"}
		}
		if c.Config != "" {
			return &ConflictError{Message: "--stdin cannot be combined with --config"}
		}
	}
	return nil
}

// Load merges every requested structured channel into one map. Within the
// structured tier the documented order is stdin < file < config; explicit
// CLI flags are layered above all of these by Decode.
func (c Channels) Load() (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	merged := map[string]any{}

	if c.Stdin || c.Dash {
		data := c.Data
		if c.MaxBytes > 0 && len(data) > c.MaxBytes {
			return nil, ErrStructuredInputLimit
		}
		if data == nil {
			var input io.Reader = os.Stdin
			if c.MaxBytes > 0 {
				input = io.LimitReader(input, int64(c.MaxBytes)+1)
			}
			raw, err := io.ReadAll(input)
			if err != nil {
				if c.MaxBytes > 0 {
					return nil, fmt.Errorf("stdin: read failed")
				}
				return nil, fmt.Errorf("stdin: %w", err)
			}
			data = raw
		}
		if c.MaxBytes > 0 && len(data) > c.MaxBytes {
			return nil, ErrStructuredInputLimit
		}
		parsed, err := ParseStructured(data)
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		mergeInto(merged, parsed)
	}

	if c.File != "" {
		var data []byte
		if c.MaxBytes > 0 {
			file, err := os.Open(c.File)
			if err != nil {
				return nil, fmt.Errorf("--file: read failed")
			}
			data, err = io.ReadAll(io.LimitReader(file, int64(c.MaxBytes)+1))
			_ = file.Close()
			if err != nil {
				return nil, fmt.Errorf("--file: read failed")
			}
			if len(data) > c.MaxBytes {
				return nil, ErrStructuredInputLimit
			}
		} else {
			var err error
			data, err = os.ReadFile(c.File)
			if err != nil {
				return nil, fmt.Errorf("--file %q: %w", c.File, err)
			}
		}
		parsed, err := ParseStructured(data)
		if err != nil {
			if c.MaxBytes > 0 {
				return nil, fmt.Errorf("--file: %w", err)
			}
			return nil, fmt.Errorf("--file %q: %w", c.File, err)
		}
		mergeInto(merged, parsed)
	}

	if c.Config != "" {
		if c.MaxBytes > 0 && len(c.Config) > c.MaxBytes {
			return nil, ErrStructuredInputLimit
		}
		parsed, err := ParseStructured([]byte(c.Config))
		if err != nil {
			return nil, fmt.Errorf("--config: %w", err)
		}
		mergeInto(merged, parsed)
	}

	return merged, nil
}

// ParseStructured decodes inline JSON or YAML into an object map.
// Empty input yields an empty map. The top level must be an object.
func ParseStructured(data []byte) (map[string]any, error) {
	trimmed := trimSpaceBytes(data)
	if len(trimmed) == 0 {
		return map[string]any{}, nil
	}

	asJSON := map[string]any{}
	if err := json.Unmarshal(trimmed, &asJSON); err == nil {
		return asJSON, nil
	}

	asYAML := map[string]any{}
	if err := yaml.Unmarshal(trimmed, &asYAML); err == nil {
		return asYAML, nil
	}

	return nil, fmt.Errorf("structured input must be a YAML or JSON object")
}

// mergeInto deep-merges src on top of dst; nested objects merge recursively,
// any other value replaces the destination.
func mergeInto(dst, src map[string]any) {
	for key, value := range src {
		if innerSrc, ok := value.(map[string]any); ok {
			if innerDst, ok := dst[key].(map[string]any); ok {
				mergeInto(innerDst, innerSrc)
				continue
			}
		}
		dst[key] = value
	}
}

func trimSpaceBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpaceByte(b[start]) {
		start++
	}
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}
