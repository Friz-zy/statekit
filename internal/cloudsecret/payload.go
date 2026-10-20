package cloudsecret

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type parseBudget struct{ nodes int }

// FormatPayload validates and formats the provider bytes completely before a
// caller may write to a sink. Raw and text output is privately copied; structured
// output is newly encoded and owned by the caller.
func FormatPayload(payload []byte, format Format, keyPath string) ([]byte, error) {
	if len(payload) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	switch format {
	case FormatRaw:
		if keyPath != "" {
			return nil, ErrInvalidRequest
		}
		return append([]byte(nil), payload...), nil
	case FormatText:
		if keyPath != "" {
			return nil, ErrInvalidRequest
		}
		if !utf8.Valid(payload) || containsLineBreak(payload) {
			return nil, ErrInvalidPayload
		}
		return append([]byte(nil), payload...), nil
	case FormatJSON, FormatYAML:
		if !utf8.Valid(payload) {
			return nil, ErrInvalidPayload
		}
	default:
		return nil, ErrInvalidRequest
	}
	if keyPath != "" {
		if err := ValidateKeyPath(keyPath); err != nil {
			return nil, err
		}
	}

	var value any
	var err error
	if format == FormatJSON {
		value, err = parseJSON(payload)
	} else {
		value, err = parseYAML(payload)
	}
	if err != nil {
		return nil, ErrInvalidPayload
	}
	if keyPath != "" {
		value, err = selectJSONPointer(value, keyPath)
		if err != nil {
			return nil, err
		}
	}

	var encoded []byte
	if format == FormatJSON {
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			return nil, ErrInvalidPayload
		}
		encoded = bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	} else {
		var err error
		encoded, err = yaml.Marshal(value)
		if err != nil {
			return nil, ErrInvalidPayload
		}
	}
	if len(encoded) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	return encoded, nil
}

func containsLineBreak(payload []byte) bool {
	for len(payload) > 0 {
		r, size := utf8.DecodeRune(payload)
		if r == '\r' || r == '\n' || r == '\u0085' || r == '\u2028' || r == '\u2029' {
			return true
		}
		payload = payload[size:]
	}
	return false
}

// ValidateKeyPath checks RFC 6901 syntax without needing the payload document.
// The empty pointer is the valid root pointer.
func ValidateKeyPath(pointer string) error {
	if pointer == "" {
		return nil
	}
	if !utf8.ValidString(pointer) || pointer[0] != '/' {
		return ErrInvalidRequest
	}
	for _, segment := range strings.Split(pointer[1:], "/") {
		if _, err := decodePointerSegment(segment); err != nil {
			return ErrInvalidRequest
		}
	}
	return nil
}

func parseJSON(payload []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	budget := &parseBudget{}
	value, err := parseJSONValue(decoder, 0, budget)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidPayload
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, depth int, budget *parseBudget) (any, error) {
	if depth > MaxDepth || chargeNode(budget) != nil {
		return nil, ErrInvalidPayload
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidPayload
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, ErrInvalidPayload
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > MaxScalarBytes || chargeNode(budget) != nil {
					return nil, ErrInvalidPayload
				}
				if _, exists := object[key]; exists {
					return nil, ErrInvalidPayload
				}
				child, err := parseJSONValue(decoder, depth+1, budget)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
				return nil, ErrInvalidPayload
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := parseJSONValue(decoder, depth+1, budget)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
				return nil, ErrInvalidPayload
			}
			return array, nil
		default:
			return nil, ErrInvalidPayload
		}
	case string:
		if len(value) > MaxScalarBytes {
			return nil, ErrInvalidPayload
		}
		return value, nil
	case json.Number:
		if len(value) > MaxScalarBytes {
			return nil, ErrInvalidPayload
		}
		return value, nil
	case bool:
		return value, nil
	case nil:
		return nil, nil
	default:
		return nil, ErrInvalidPayload
	}
}

func chargeNode(budget *parseBudget) error {
	budget.nodes++
	if budget.nodes > MaxNodes {
		return ErrInvalidPayload
	}
	return nil
}

func parseYAML(payload []byte) (any, error) {
	// yaml.v3 materializes the complete Node tree before this structural walk.
	// Callers cap raw input at MaxPayloadBytes, but MaxDepth/MaxNodes/MaxScalarBytes
	// are not pre-allocation heap bounds; peak allocation remains library-dependent.
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalidPayload
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, ErrInvalidPayload
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) > 1 {
		return nil, ErrInvalidPayload
	}
	if len(document.Content) == 0 {
		return nil, nil
	}
	budget := &parseBudget{}
	return convertYAMLNode(document.Content[0], 0, budget)
}

func convertYAMLNode(node *yaml.Node, depth int, budget *parseBudget) (any, error) {
	if node == nil || depth > MaxDepth || chargeNode(budget) != nil || node.Kind == yaml.AliasNode {
		return nil, ErrInvalidPayload
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, ErrInvalidPayload
		}
		return convertYAMLNode(node.Content[0], depth, budget)
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, ErrInvalidPayload
		}
		values := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := convertYAMLNode(child, depth+1, budget)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, ErrInvalidPayload
		}
		values := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" || keyNode.Tag == "!!merge" || len(keyNode.Value) > MaxScalarBytes || chargeNode(budget) != nil {
				return nil, ErrInvalidPayload
			}
			if _, exists := values[keyNode.Value]; exists {
				return nil, ErrInvalidPayload
			}
			value, err := convertYAMLNode(node.Content[i+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			values[keyNode.Value] = value
		}
		return values, nil
	case yaml.ScalarNode:
		if len(node.Value) > MaxScalarBytes || !utf8.ValidString(node.Value) {
			return nil, ErrInvalidPayload
		}
		switch node.Tag {
		case "!!str", "!!null", "!!bool", "!!int", "!!float":
		default:
			return nil, ErrInvalidPayload
		}
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, ErrInvalidPayload
		}
		if number, ok := value.(float64); ok && (math.IsNaN(number) || math.IsInf(number, 0)) {
			return nil, ErrInvalidPayload
		}
		switch value.(type) {
		case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			return value, nil
		case nil:
			return nil, nil
		default:
			return nil, ErrInvalidPayload
		}
	default:
		return nil, ErrInvalidPayload
	}
}

func selectJSONPointer(value any, pointer string) (any, error) {
	if pointer == "" {
		return value, nil
	}
	if pointer[0] != '/' {
		return nil, ErrInvalidRequest
	}
	for _, raw := range strings.Split(pointer[1:], "/") {
		segment, err := decodePointerSegment(raw)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		switch current := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = current[segment]
			if !ok {
				return nil, ErrInvalidRequest
			}
		case []any:
			if segment == "" || (len(segment) > 1 && segment[0] == '0') {
				return nil, ErrInvalidRequest
			}
			for i := 0; i < len(segment); i++ {
				if segment[i] < '0' || segment[i] > '9' {
					return nil, ErrInvalidRequest
				}
			}
			index, err := strconv.Atoi(segment)
			if err != nil || index >= len(current) {
				return nil, ErrInvalidRequest
			}
			value = current[index]
		default:
			return nil, ErrInvalidRequest
		}
	}
	return value, nil
}

func decodePointerSegment(segment string) (string, error) {
	var builder strings.Builder
	for i := 0; i < len(segment); i++ {
		if segment[i] != '~' {
			builder.WriteByte(segment[i])
			continue
		}
		if i+1 >= len(segment) {
			return "", ErrInvalidRequest
		}
		i++
		switch segment[i] {
		case '0':
			builder.WriteByte('~')
		case '1':
			builder.WriteByte('/')
		default:
			return "", ErrInvalidRequest
		}
	}
	return builder.String(), nil
}
