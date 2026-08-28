package config

import (
	"flag"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// tagKey is the single-source struct tag driving CLI flag generation,
// structured key names, and required validation (plan section 41).
const tagKey = "statekit"

// fieldSpec is the decoded statekit struct tag for one argument field.
type fieldSpec struct {
	index    int
	name     string // canonical argument name: flag name and structured input key
	field    string // Go field name for diagnostics
	required bool
}

// UnknownArgumentError reports an argument that the target function does not
// declare, matching Salt's behavior on unexpected kwargs.
type UnknownArgumentError struct {
	Name  string
	Known []string
}

func (e *UnknownArgumentError) Error() string {
	return fmt.Sprintf("unknown argument %q; known arguments: %s", e.Name, strings.Join(e.Known, ", "))
}

// MissingRequiredError reports an unset argument tagged required.
type MissingRequiredError struct {
	Name string
}

func (e *MissingRequiredError) Error() string {
	return fmt.Sprintf("missing required argument %q", e.Name)
}

func specsFor(t reflect.Type) ([]fieldSpec, error) {
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("args target must be a struct, got %s", t)
	}
	specs := make([]fieldSpec, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Anonymous {
			continue
		}
		if err := checkSupportedKind(f.Type); err != nil {
			return nil, fmt.Errorf("field %s: %w", f.Name, err)
		}
		spec := fieldSpec{index: i, name: strings.ToLower(f.Name), field: f.Name}
		if tag := f.Tag.Get(tagKey); tag != "" {
			for _, part := range strings.Split(tag, ",") {
				part = strings.TrimSpace(part)
				switch {
				case part == "":
				case part == "required":
					spec.required = true
				case strings.HasPrefix(part, "name="):
					spec.name = strings.TrimPrefix(part, "name=")
				default:
					return nil, fmt.Errorf("field %s: unsupported %s tag option %q", f.Name, tagKey, part)
				}
			}
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func checkSupportedKind(t reflect.Type) error {
	switch t.Kind() {
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64:
		return nil
	case reflect.Interface:
		if t.NumMethod() == 0 {
			// Salt has a small number of genuinely union-valued arguments
			// (for example macdefaults.write's plist value). Keep this
			// explicit: only interface{} is accepted, not arbitrary
			// interfaces with hidden behavior.
			return nil
		}
		return fmt.Errorf("unsupported interface type %s (only any)", t)
	case reflect.Pointer:
		// Pointer fields carry tri-state options: nil keeps the Salt
		// function default when the caller omits the argument entirely.
		if t.Elem().Kind() == reflect.Bool || t.Elem().Kind() == reflect.String {
			return nil
		}
		return fmt.Errorf("unsupported pointer type *%s (only *bool, *string)", t.Elem())
	case reflect.Slice:
		switch t.Elem().Kind() {
		case reflect.String:
			return nil
		case reflect.Interface:
			// []any carries Salt's list-of-dicts schemas (pkgs, sources,
			// attr packages); supplied exclusively through structured input.
			return nil
		}
		return fmt.Errorf("unsupported slice element type %s (only []string, []any)", t.Elem())
	case reflect.Map:
		if t.Key().Kind() == reflect.String &&
			(t.Elem().Kind() == reflect.Interface || t.Elem().Kind() == reflect.String) {
			return nil
		}
		return fmt.Errorf("unsupported map type %s (only map[string]string / map[string]any)", t)
	default:
		return fmt.Errorf("unsupported argument type %s (supported: string, bool, int, int64, float64, []string)", t)
	}
}

func specNames(specs []fieldSpec) []string {
	names := make([]string, len(specs))
	for i, s := range specs {
		names[i] = s.name
	}
	sort.Strings(names)
	return names
}

// ArgumentNames lists canonical argument names declared by an args template.
func ArgumentNames(template any) ([]string, error) {
	templateType := reflect.TypeOf(template)
	if templateType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("args template must be a struct, got %s", templateType)
	}
	specs, err := specsFor(templateType)
	if err != nil {
		return nil, err
	}
	return specNames(specs), nil
}

// NewFlagSet builds a FlagSet declaring one flag per args-struct field.
// Bool fields become real boolean flags so bare forms such as --test work;
// all other fields are string flags whose conversion happens in Decode.
func NewFlagSet(name string, argsTemplate any) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	templateType := reflect.TypeOf(argsTemplate)
	if templateType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("args template must be a struct, got %s", templateType)
	}
	specs, err := specsFor(templateType)
	if err != nil {
		return nil, err
	}
	for _, s := range specs {
		usage := "set " + s.name
		if s.required {
			usage += " (required)"
		}
		fieldType := templateType.Field(s.index).Type
		if fieldType.Kind() == reflect.Bool ||
			(fieldType.Kind() == reflect.Pointer && fieldType.Elem().Kind() == reflect.Bool) {
			fs.Bool(s.name, false, usage)
			continue
		}
		if fieldType.Kind() == reflect.Map {
			// Maps are supplied exclusively through structured input.
			continue
		}
		if fieldType.Kind() == reflect.Interface {
			// Union-valued arguments accept a scalar flag and retain
			// richer values through structured input.
			fs.String(s.name, "", usage)
			continue
		}
		if fieldType.Kind() == reflect.Slice && fieldType.Elem().Kind() == reflect.Interface {
			// []any list-of-dicts schemas are structured-input only.
			continue
		}
		fs.String(s.name, "", usage)
	}
	return fs, nil
}

// ProvidedValues collects only the flags explicitly set on argv.
func ProvidedValues(fs *flag.FlagSet) map[string]string {
	provided := map[string]string{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = f.Value.String() })
	return provided
}

// NormalizeBoolArgs rewrites spaced boolean arguments to their "=" form so
// both `--enable true` and bare `--test` parse uniformly.
func NormalizeBoolArgs(argv []string, argsTemplate any) ([]string, error) {
	templateType := reflect.TypeOf(argsTemplate)
	if templateType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("args template must be a struct, got %s", templateType)
	}
	boolFlags := map[string]bool{}
	for _, s := range specsForLenient(templateType) {
		ft := templateType.Field(s.index).Type
		if ft.Kind() == reflect.Bool ||
			(ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Bool) {
			boolFlags[s.name] = true
		}
	}

	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		name, isFlag := flagName(tok)
		if !isFlag || !boolFlags[name] || strings.Contains(tok, "=") {
			out = append(out, tok)
			continue
		}
		if i+1 < len(argv) {
			if _, nextIsFlag := flagName(argv[i+1]); !nextIsFlag && argv[i+1] != "" {
				out = append(out, tok+"="+argv[i+1])
				i++
				continue
			}
		}
		out = append(out, tok)
	}
	return out, nil
}

// flagName extracts the canonical name from a "-x"/"--x" token.
func flagName(tok string) (string, bool) {
	if len(tok) < 2 || !strings.HasPrefix(tok, "-") {
		return "", false
	}
	name := strings.TrimLeft(tok, "-")
	if name == "" || strings.Contains(name, "=") {
		if strings.Contains(name, "=") {
			name = strings.SplitN(name, "=", 2)[0]
		} else {
			return "", false
		}
	}
	return name, true
}

// specsForLenient skips malformed tags instead of failing; used only by
// normalization which runs before strict validation surfaces errors.
func specsForLenient(t reflect.Type) []fieldSpec {
	specs, err := specsFor(t)
	if err != nil {
		return nil
	}
	return specs
}

// Decode fills target (pointer to struct) from structured input overlaid by
// explicitly provided CLI flag values. Unknown keys are rejected; missing
// required fields fail validation after merging.
func Decode(target any, structured map[string]any, provided map[string]string) error {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("decode target must be a struct pointer")
	}
	elem := rv.Elem()
	specs, err := specsFor(elem.Type())
	if err != nil {
		return err
	}
	known := make(map[string]fieldSpec, len(specs))
	for _, s := range specs {
		known[s.name] = s
	}
	names := specNames(specs)

	for key := range structured {
		if _, ok := known[key]; !ok {
			return &UnknownArgumentError{Name: key, Known: names}
		}
	}
	for key := range provided {
		if _, ok := known[key]; !ok {
			return &UnknownArgumentError{Name: key, Known: names}
		}
	}

	for _, s := range specs {
		field := elem.Field(s.index)
		if raw, ok := provided[s.name]; ok {
			if err := assignFromFlag(field, s.name, raw); err != nil {
				return err
			}
			continue
		}
		if raw, ok := structured[s.name]; ok {
			if err := assignFromValue(field, s.name, raw); err != nil {
				return err
			}
		}
	}

	return ValidateRequired(target)
}

// ValidateRequired checks every required-tagged field is non-zero.
func ValidateRequired(target any) error {
	elem := reflect.ValueOf(target)
	if elem.Kind() != reflect.Pointer || elem.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("validate target must be a struct pointer")
	}
	elem = elem.Elem()
	specs, err := specsFor(elem.Type())
	if err != nil {
		return err
	}
	for _, s := range specs {
		if !s.required {
			continue
		}
		if elem.Field(s.index).IsZero() {
			return &MissingRequiredError{Name: s.name}
		}
	}
	return nil
}

func assignError(name string, value, want any) error {
	return fmt.Errorf("argument %q: cannot use %T as %T", name, value, want)
}

func assignFromFlag(field reflect.Value, name, raw string) error {
	if field.Kind() != reflect.Pointer {
		// non-pointer path below
	} else if field.Type().Elem().Kind() == reflect.Bool {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("argument %q: invalid boolean %q", name, raw)
		}
		field.Set(reflect.ValueOf(&b))
		return nil
	} else if field.Type().Elem().Kind() == reflect.String {
		s := raw
		field.Set(reflect.ValueOf(&s))
		return nil
	}
	switch field.Kind() {
	case reflect.Interface:
		field.Set(reflect.ValueOf(raw))
	case reflect.String:
		field.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("argument %q: invalid boolean %q", name, raw)
		}
		field.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("argument %q: invalid integer %q", name, raw)
		}
		field.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("argument %q: invalid number %q", name, raw)
		}
		field.SetFloat(f)
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.Interface {
			return fmt.Errorf("argument %q: list-of-dicts argument must be provided via structured input", name)
		}
		field.Set(reflect.ValueOf(splitList(raw)))
	default:
		return assignError(name, raw, field.Interface())
	}
	return nil
}

// splitList splits a comma-separated flag value into list items.
func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func assignFromValue(field reflect.Value, name string, v any) error {
	if field.Kind() == reflect.Pointer &&
		(field.Type().Elem().Kind() == reflect.Bool || field.Type().Elem().Kind() == reflect.String) {
		tmp := reflect.New(field.Type().Elem()).Elem()
		if err := assignFromValue(tmp, name, v); err != nil {
			return err
		}
		ptr := reflect.New(field.Type().Elem())
		ptr.Elem().Set(tmp)
		field.Set(ptr)
		return nil
	}
	switch field.Kind() {
	case reflect.Interface:
		if v == nil {
			field.Set(reflect.Zero(field.Type()))
			return nil
		}
		value := reflect.ValueOf(v)
		if value.Type().AssignableTo(field.Type()) || field.Type().NumMethod() == 0 {
			field.Set(value)
			return nil
		}
		return assignError(name, v, field.Interface())
	case reflect.String:
		s, err := toStringScalar(v)
		if err != nil {
			return assignError(name, v, "")
		}
		field.SetString(s)
	case reflect.Bool:
		b, err := toBoolScalar(v)
		if err != nil {
			return assignError(name, v, false)
		}
		field.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := toIntScalar(v)
		if err != nil {
			return assignError(name, v, int64(0))
		}
		field.SetInt(n)
	case reflect.Float64:
		f, err := toFloatScalar(v)
		if err != nil {
			return assignError(name, v, float64(0))
		}
		field.SetFloat(f)
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.Interface {
			items, err := toAnySlice(v)
			if err != nil {
				return fmt.Errorf("argument %q: %w", name, err)
			}
			field.Set(reflect.ValueOf(items))
			return nil
		}
		items, err := toStringSlice(v)
		if err != nil {
			return assignError(name, v, []string{})
		}
		field.Set(reflect.ValueOf(items))
	case reflect.Map:
		m, err := toTypedMap(field.Type(), v)
		if err != nil {
			return fmt.Errorf("argument %q: %w", name, err)
		}
		field.Set(reflect.ValueOf(m))
	default:
		return assignError(name, v, field.Interface())
	}
	return nil
}

// toTypedMap converts a decoded YAML/JSON object into the field's concrete
// map type (map[string]any or map[string]string).
func toTypedMap(t reflect.Type, v any) (any, error) {
	raw, ok := v.(map[string]any)
	if !ok {
		if m, isMap := v.(map[string]string); isMap && t.Elem().Kind() == reflect.String {
			return m, nil
		}
		return nil, fmt.Errorf("expected an object")
	}
	switch t.Elem().Kind() {
	case reflect.Interface:
		out := make(map[string]any, len(raw))
		for key, value := range raw {
			out[key] = value
		}
		return out, nil
	case reflect.String:
		out := make(map[string]string, len(raw))
		for key, value := range raw {
			s, err := toStringScalar(value)
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", key, err)
			}
			out[key] = s
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported map value type")
	}
}

func toStringScalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case int:
		return strconv.Itoa(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	default:
		return "", fmt.Errorf("not a scalar")
	}
}

func toBoolScalar(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		return strconv.ParseBool(t)
	case int:
		if t == 0 {
			return false, nil
		}
		if t == 1 {
			return true, nil
		}
		return false, fmt.Errorf("not a boolean")
	case int64:
		if t == 0 {
			return false, nil
		}
		if t == 1 {
			return true, nil
		}
		return false, fmt.Errorf("not a boolean")
	case float64:
		if t == 0 {
			return false, nil
		}
		if t == 1 {
			return true, nil
		}
		return false, fmt.Errorf("not a boolean")
	default:
		return false, fmt.Errorf("not a boolean")
	}
}

func toIntScalar(v any) (int64, error) {
	switch t := v.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		if t != float64(int64(t)) {
			return 0, fmt.Errorf("not an integer")
		}
		return int64(t), nil
	case string:
		return strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func toFloatScalar(v any) (float64, error) {
	switch t := v.(type) {
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case float64:
		return t, nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(t), 64)
	default:
		return 0, fmt.Errorf("not a number")
	}
}

// toAnySlice converts a decoded YAML/JSON array into []any, normalizing
// mappings to map[string]any so list-of-dicts schemas survive decoding.
// A string input mirrors Salt's utils.yaml.safe_load coercion for
// pkgs/sources schemas: valid YAML lists are used directly, anything else
// degrades to a single-element list that downstream validation rejects the
// same way Salt's invalid-element path does.
func toAnySlice(v any) ([]any, error) {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			item, err := normalizeAny(item)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, nil
	case string:
		var parsed any
		if err := yaml.Unmarshal([]byte(t), &parsed); err != nil || parsed == nil {
			return []any{t}, nil
		}
		if list, ok := parsed.([]any); ok {
			return toAnySlice(list)
		}
		return []any{parsed}, nil
	default:
		return nil, fmt.Errorf("expected a list")
	}
}

func normalizeAny(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for key, val := range t {
			norm, err := normalizeAny(val)
			if err != nil {
				return nil, err
			}
			out[key] = norm
		}
		return out, nil
	case []any:
		return toAnySlice(t)
	case []string:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, item)
		}
		return out, nil
	default:
		return v, nil
	}
}

func toStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, err := toStringScalar(item)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		s, err := toStringScalar(v)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
}
