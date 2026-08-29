// Package gotemplate provides the bounded native Go-template renderer used by
// the explicitly non-Salt gotemplate execution module.
package gotemplate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// MaxBytes bounds both supplied template source and rendered output.
const MaxBytes = 1 << 20

// Value budgets are deliberately below machine limits. They bound validation,
// normalization, and helper serialization before any amplifying operation.
const (
	checkpointInterval = 256
	maxValueNodes      = 100000
	maxValueDepth      = 128
	maxValueBytes      = 4 << 20
	maxEncodedBytes    = MaxBytes
	// maxFormatBytes bounds both formatted output and the temporary work that
	// fmt may perform for one directive.  Formats whose upper bound is unknown
	// are rejected before fmt is called.
	maxFormatBytes      = MaxBytes
	maxFormatDirectives = 1024
	// Go templates are intentionally limited to finite, statically inspectable
	// control flow.  This is the R4.9a ceiling; an interruptible evaluator is
	// the upgrade path if loops or template calls are needed in the future.
	maxASTNodes      = 10000
	maxASTDepth      = 64
	maxASTWork       = 20000
	maxExecutionWork = 100000
)

// checkpointObserverKey is private and only used by same-package tests to
// prove entry into a bounded operation. Normal callers observe only ctx.Err.
type checkpointObserverKey struct{}

type checkpointObserver func(string)

func observeCheckpoint(ctx context.Context, label string) {
	if observer, ok := ctx.Value(checkpointObserverKey{}).(checkpointObserver); ok {
		observer(label)
	}
}

var (
	ErrSourceLimit      = errors.New("gotemplate: template source exceeds 1 MiB")
	ErrOutputLimit      = errors.New("gotemplate: rendered output exceeds 1 MiB")
	ErrASTLimit         = errors.New("gotemplate: template exceeds finite AST budget")
	ErrUnboundedControl = errors.New("gotemplate: unbounded template control flow is not supported")
)

// Request contains all data available to a template. Defaults are overlaid by
// Context into a new map; neither input is modified.
type Request struct {
	Contents string
	Context  map[string]any
	Defaults map[string]any
}

// Render parses and executes supplied Go-template contents. It permits only
// finite control flow (substitutions, if, and with); ranges and template calls
// are rejected before execution. It does not access the host filesystem or
// execute processes. This deliberate R4.9a ceiling can be lifted by adding an
// interruptible evaluator with explicit loop and invocation quotas.
func Render(ctx context.Context, request Request) (string, error) {
	return render(ctx, request, "", false)
}

// RenderNamed executes a named template definition from supplied contents.
func RenderNamed(ctx context.Context, request Request, name string) (string, error) {
	return render(ctx, request, name, true)
}

func render(ctx context.Context, request Request, name string, named bool) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(request.Contents) > MaxBytes {
		return "", ErrSourceLimit
	}
	if err := checkSource(ctx, request.Contents); err != nil {
		return "", err
	}
	data, err := mergedData(ctx, request.Defaults, request.Context)
	if err != nil {
		return "", err
	}
	observeCheckpoint(ctx, "template parse")
	t, err := template.New("render").Option("missingkey=error").Funcs(template.FuncMap{
		"toJSON":   func(value any) (string, error) { return toJSONWith(ctx, value) },
		"toYAML":   func(value any) (string, error) { return toYAMLWith(ctx, value) },
		"fromJSON": func(input string) (any, error) { return fromJSONWith(ctx, input) },
		"fromYAML": func(input string) (any, error) { return fromYAMLWith(ctx, input) },
		"printf":   func(format string, args ...any) (string, error) { return boundedPrintf(ctx, format, args...) },
		"print":    func(args ...any) (string, error) { return boundedPrint(ctx, args...) },
		"println":  func(args ...any) (string, error) { return boundedPrintln(ctx, args...) },
	}).Parse(request.Contents)
	// text/template parsing is synchronous and has a finite, MaxBytes-bounded
	// non-interruptible section; preflight and the AST walk bound cancellation
	// latency around that standard-library section.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("gotemplate: parse: %w", err)
	}
	if err := validateAST(ctx, t, name, named); err != nil {
		return "", err
	}
	writer := &checkingWriter{ctx: ctx, limit: MaxBytes, budget: maxExecutionWork}
	observeCheckpoint(ctx, "template Execute")
	if named {
		err = t.ExecuteTemplate(writer, name, data)
	} else {
		err = t.Execute(writer, data)
	}
	if err != nil {
		if errors.Is(err, ErrOutputLimit) {
			return writer.String(), ErrOutputLimit
		}
		if cerr := ctx.Err(); cerr != nil {
			return writer.String(), cerr
		}
		return writer.String(), fmt.Errorf("gotemplate: execute: %w", err)
	}
	return writer.String(), nil
}

type astBudget struct {
	nodes int
	work  int
}

func validateAST(ctx context.Context, t *template.Template, name string, named bool) error {
	observeCheckpoint(ctx, "AST walk")
	b := astBudget{}
	for _, child := range t.Templates() {
		if named && child.Name() != name && child.Name() != "render" {
			continue
		}
		if err := walkAST(ctx, child.Tree.Root, 0, &b); err != nil {
			return err
		}
	}
	return nil
}

func walkAST(ctx context.Context, node parse.Node, depth int, b *astBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if node == nil {
		return nil
	}
	if value := reflect.ValueOf(node); value.Kind() == reflect.Ptr && value.IsNil() {
		return nil
	}
	if depth > maxASTDepth || b.nodes >= maxASTNodes || b.work >= maxASTWork {
		return ErrASTLimit
	}
	b.nodes++
	b.work++
	switch n := node.(type) {
	case *parse.RangeNode, *parse.TemplateNode, *parse.BreakNode, *parse.ContinueNode:
		return ErrUnboundedControl
	case *parse.ListNode:
		for _, child := range n.Nodes {
			if err := walkAST(ctx, child, depth+1, b); err != nil {
				return err
			}
		}
	case *parse.IfNode:
		if err := walkAST(ctx, n.Pipe, depth+1, b); err != nil {
			return err
		}
		if err := walkAST(ctx, n.List, depth+1, b); err != nil {
			return err
		}
		return walkAST(ctx, n.ElseList, depth+1, b)
	case *parse.WithNode:
		if err := walkAST(ctx, n.Pipe, depth+1, b); err != nil {
			return err
		}
		if err := walkAST(ctx, n.List, depth+1, b); err != nil {
			return err
		}
		return walkAST(ctx, n.ElseList, depth+1, b)
	case *parse.ActionNode:
		return walkAST(ctx, n.Pipe, depth+1, b)
	case *parse.PipeNode:
		for _, decl := range n.Decl {
			if err := walkAST(ctx, decl, depth+1, b); err != nil {
				return err
			}
		}
		for _, cmd := range n.Cmds {
			if err := walkAST(ctx, cmd, depth+1, b); err != nil {
				return err
			}
		}
	case *parse.CommandNode:
		for _, arg := range n.Args {
			if err := walkAST(ctx, arg, depth+1, b); err != nil {
				return err
			}
		}
	}
	return nil
}

func mergedData(ctx context.Context, defaults, contextValues map[string]any) (map[string]any, error) {
	budget := valueBudget{}
	if err := budget.addMap(ctx, defaults); err != nil {
		return nil, err
	}
	if err := budget.addMap(ctx, contextValues); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(defaults)+len(contextValues))
	for _, source := range []map[string]any{defaults, contextValues} {
		for key, value := range source {
			normalized, err := normalize(ctx, value, make(map[visit]bool))
			if err != nil {
				return nil, fmt.Errorf("gotemplate: invalid value for %q: %w", key, err)
			}
			out[key] = normalized
		}
	}
	return out, nil
}

var errValueBudget = errors.New("value exceeds finite budget")

type valueBudget struct{ nodes, scalarBytes int }

func (b *valueBudget) addMap(ctx context.Context, m map[string]any) error {
	if len(m) > maxValueNodes-b.nodes {
		return errValueBudget
	}
	for key, value := range m {
		if err := checkpoint(ctx, b.nodes); err != nil {
			return err
		}
		if len(key) > maxValueBytes-b.scalarBytes {
			return fmt.Errorf("gotemplate: invalid value for %q: %w", key, errValueBudget)
		}
		b.scalarBytes += len(key)
		b.nodes++
		if err := b.add(ctx, reflect.ValueOf(value), 1, make(map[visit]bool)); err != nil {
			if errors.Is(err, errValueBudget) {
				return errValueBudget
			}
			return fmt.Errorf("gotemplate: invalid value for %q: %w", key, err)
		}
	}
	return nil
}

func (b *valueBudget) add(ctx context.Context, v reflect.Value, depth int, stack map[visit]bool) error {
	if err := checkpoint(ctx, b.nodes); err != nil {
		return err
	}
	if depth > maxValueDepth || b.nodes >= maxValueNodes {
		return errValueBudget
	}
	if !v.IsValid() || (v.Kind() == reflect.Interface && v.IsNil()) {
		b.nodes++
		return nil
	}
	if v.Kind() == reflect.Interface {
		return b.add(ctx, v.Elem(), depth, stack)
	}
	b.nodes++
	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return nil
	case reflect.String:
		if len(v.String()) > maxValueBytes-b.scalarBytes {
			return errValueBudget
		}
		b.scalarBytes += len(v.String())
		return nil
	case reflect.Slice, reflect.Map:
		if v.IsNil() {
			return nil
		}
		marker := visit{v.Type(), v.Pointer()}
		if stack[marker] {
			return errors.New("cyclic value")
		}
		stack[marker] = true
		defer delete(stack, marker)
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				if err := b.add(ctx, v.Index(i), depth+1, stack); err != nil {
					return err
				}
			}
			return nil
		}
		if v.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("unsupported map type %s", v.Type())
		}
		if v.Len() > maxValueNodes-b.nodes {
			return errValueBudget
		}
		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key().String()
			if len(key) > maxValueBytes-b.scalarBytes {
				return errValueBudget
			}
			b.scalarBytes += len(key)
			if err := b.add(ctx, iter.Value(), depth+1, stack); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported value type %s", v.Type())
	}
}

func checkedValue(ctx context.Context, value any) (any, error) {
	b := valueBudget{}
	if err := b.add(ctx, reflect.ValueOf(value), 1, make(map[visit]bool)); err != nil {
		return nil, err
	}
	return normalize(ctx, value, make(map[visit]bool))
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

func normalize(ctx context.Context, value any, stack map[visit]bool) (any, error) {
	return normalizeValue(ctx, reflect.ValueOf(value), stack)
}

func normalizeValue(ctx context.Context, v reflect.Value, stack map[visit]bool) (any, error) {
	if err := checkpoint(ctx, 0); err != nil {
		return nil, err
	}
	if !v.IsValid() || (v.Kind() == reflect.Interface && v.IsNil()) {
		return nil, nil
	}
	if v.Kind() == reflect.Interface {
		return normalizeValue(ctx, v.Elem(), stack)
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.String:
		return v.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint(), nil
	case reflect.Float32, reflect.Float64:
		if math.IsInf(v.Float(), 0) || math.IsNaN(v.Float()) {
			return nil, errors.New("non-finite float")
		}
		return v.Float(), nil
	case reflect.Slice:
		if v.IsNil() {
			return nil, nil
		}
		marker := visit{v.Type(), v.Pointer()}
		if stack[marker] {
			return nil, errors.New("cyclic value")
		}
		stack[marker] = true
		defer delete(stack, marker)
		out := make([]any, v.Len())
		for i := range out {
			item, err := normalizeValue(ctx, v.Index(i), stack)
			if err != nil {
				return nil, err
			}
			out[i] = item
		}
		return out, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported map type %s", v.Type())
		}
		if v.IsNil() {
			return nil, nil
		}
		marker := visit{v.Type(), v.Pointer()}
		if stack[marker] {
			return nil, errors.New("cyclic value")
		}
		stack[marker] = true
		defer delete(stack, marker)
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			item, err := normalizeValue(ctx, iter.Value(), stack)
			if err != nil {
				return nil, err
			}
			out[iter.Key().String()] = item
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported value type %s", v.Type())
	}
}

func toJSON(value any) (string, error) {
	return toJSONWith(context.Background(), value)
}

func toJSONWith(ctx context.Context, value any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	value, err := checkedValue(ctx, value)
	if err != nil {
		return "", err
	}
	fits, err := encodingFits(ctx, value)
	if err != nil {
		return "", err
	}
	if !fits {
		return "", ErrOutputLimit
	}
	w := &checkingWriter{ctx: ctx, limit: maxEncodedBytes, budget: maxExecutionWork}
	observeCheckpoint(ctx, "JSON encode")
	if err := writeJSON(ctx, w, value); err != nil {
		return "", err
	}
	return w.String(), nil
}

func toYAML(value any) (string, error) {
	return toYAMLWith(context.Background(), value)
}

func toYAMLWith(ctx context.Context, value any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	value, err := checkedValue(ctx, value)
	if err != nil {
		return "", err
	}
	fits, err := encodingFits(ctx, value)
	if err != nil {
		return "", err
	}
	if !fits {
		return "", ErrOutputLimit
	}
	w := &checkingWriter{ctx: ctx, limit: maxEncodedBytes, budget: maxExecutionWork}
	encoder := yaml.NewEncoder(w)
	observeCheckpoint(ctx, "YAML encode")
	if err := ctx.Err(); err != nil {
		return "", err
	}
	err = encoder.Encode(value)
	if cerr := ctx.Err(); cerr != nil {
		return "", cerr
	}
	closeErr := encoder.Close()
	if cerr := ctx.Err(); cerr != nil {
		return "", cerr
	}
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return w.String(), nil
}

func writeJSON(ctx context.Context, w *checkingWriter, value any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch v := value.(type) {
	case nil:
		return writeText(w, "null")
	case bool:
		if v {
			return writeText(w, "true")
		}
		return writeText(w, "false")
	case string:
		return writeJSONString(w, v)
	case int64:
		return writeText(w, strconv.FormatInt(v, 10))
	case uint64:
		return writeText(w, strconv.FormatUint(v, 10))
	case float64:
		return writeText(w, formatJSONFloat(v))
	case []any:
		if err := writeText(w, "["); err != nil {
			return err
		}
		for i, item := range v {
			if i > 0 {
				if err := writeText(w, ","); err != nil {
					return err
				}
			}
			if err := writeJSON(ctx, w, item); err != nil {
				return err
			}
		}
		return writeText(w, "]")
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if err := checkpoint(ctx, len(keys)); err != nil {
				return err
			}
			keys = append(keys, key)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sortKeys(ctx, keys); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeText(w, "{"); err != nil {
			return err
		}
		for i, key := range keys {
			if i > 0 {
				if err := writeText(w, ","); err != nil {
					return err
				}
			}
			if err := writeJSONString(w, key); err != nil {
				return err
			}
			if err := writeText(w, ":"); err != nil {
				return err
			}
			if err := writeJSON(ctx, w, v[key]); err != nil {
				return err
			}
		}
		return writeText(w, "}")
	default:
		return errors.New("gotemplate: unsupported canonical JSON value")
	}
}

// sortKeys is an iterative, O(n log n) merge sort.  Each comparison/copy is
// charged to a bounded checkpoint interval so cancellation cannot be delayed
// by the map-key ordering pass.
func sortKeys(ctx context.Context, keys []string) error {
	if len(keys) < 2 {
		return ctx.Err()
	}
	tmp := make([]string, len(keys))
	checks := 0
	checkpointSort := func() error {
		checks++
		if checks%checkpointInterval == 0 {
			return ctx.Err()
		}
		return nil
	}
	for width := 1; width < len(keys); width *= 2 {
		for left := 0; left < len(keys); left += 2 * width {
			mid, right := left+width, left+2*width
			if mid > len(keys) {
				mid = len(keys)
			}
			if right > len(keys) {
				right = len(keys)
			}
			i, j, out := left, mid, left
			for i < mid && j < right {
				if err := checkpointSort(); err != nil {
					return err
				}
				if keys[i] <= keys[j] {
					tmp[out], i = keys[i], i+1
				} else {
					tmp[out], j = keys[j], j+1
				}
				out++
			}
			for i < mid {
				if err := checkpointSort(); err != nil {
					return err
				}
				tmp[out], i, out = keys[i], i+1, out+1
			}
			for j < right {
				if err := checkpointSort(); err != nil {
					return err
				}
				tmp[out], j, out = keys[j], j+1, out+1
			}
		}
		copy(keys, tmp)
		if err := checkpointSort(); err != nil {
			return err
		}
		if width > len(keys)/2 {
			break
		}
	}
	return ctx.Err()
}

// formatJSONFloat follows encoding/json's shortest representation and its
// fixed/exponent cutovers without buffering the enclosing value.
func formatJSONFloat(v float64) string {
	if v == 0 {
		if math.Signbit(v) {
			return "-0"
		}
		return "0"
	}
	abs := math.Abs(v)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	text := strconv.FormatFloat(v, 'e', -1, 64)
	e := strings.IndexByte(text, 'e')
	if e >= 0 && e+2 < len(text) && text[e+2] == '0' {
		text = text[:e+2] + strings.TrimLeft(text[e+2:], "0")
	}
	return text
}

func writeText(w *checkingWriter, text string) error { _, err := w.Write([]byte(text)); return err }

func writeJSONString(w *checkingWriter, text string) error {
	if err := writeText(w, "\""); err != nil {
		return err
	}
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			if err := writeText(w, `\ufffd`); err != nil {
				return err
			}
			i++
			continue
		}
		switch r {
		case '\\':
			if err := writeText(w, `\\`); err != nil {
				return err
			}
		case '"':
			if err := writeText(w, `\"`); err != nil {
				return err
			}
		case '\b':
			if err := writeText(w, `\b`); err != nil {
				return err
			}
		case '\f':
			if err := writeText(w, `\f`); err != nil {
				return err
			}
		case '\n':
			if err := writeText(w, `\n`); err != nil {
				return err
			}
		case '\r':
			if err := writeText(w, `\r`); err != nil {
				return err
			}
		case '\t':
			if err := writeText(w, `\t`); err != nil {
				return err
			}
		default:
			if r < 0x20 {
				if err := writeText(w, `\u00`+fmt.Sprintf("%02x", r)); err != nil {
					return err
				}
			} else if r == '<' {
				if err := writeText(w, `\u003c`); err != nil {
					return err
				}
			} else if r == '>' {
				if err := writeText(w, `\u003e`); err != nil {
					return err
				}
			} else if r == '&' {
				if err := writeText(w, `\u0026`); err != nil {
					return err
				}
			} else if r == '\u2028' {
				if err := writeText(w, `\u2028`); err != nil {
					return err
				}
			} else if r == '\u2029' {
				if err := writeText(w, `\u2029`); err != nil {
					return err
				}
			} else if err := writeText(w, text[i:i+size]); err != nil {
				return err
			}
		}
		i += size
	}
	return writeText(w, "\"")
}

func fromJSON(input string) (any, error) {
	return fromJSONWith(context.Background(), input)
}

func fromJSONWith(ctx context.Context, input string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) > MaxBytes {
		return nil, errValueBudget
	}
	var value any
	decoder := json.NewDecoder(&contextReader{ctx: ctx, r: strings.NewReader(input)})
	observeCheckpoint(ctx, "JSON decode")
	if err := decoder.Decode(&value); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, errors.New("invalid JSON input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, errors.New("invalid JSON input")
	}
	return checkedValue(ctx, value)
}

// DecodeJSON decodes a rendered JSON document using the same bounded,
// cancellable decoder as the template helpers.
func DecodeJSON(ctx context.Context, input string) (any, error) { return fromJSONWith(ctx, input) }

func fromYAML(input string) (any, error) {
	return fromYAMLWith(context.Background(), input)
}

func fromYAMLWith(ctx context.Context, input string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) > MaxBytes {
		return nil, errValueBudget
	}
	var value any
	decoder := yaml.NewDecoder(&contextReader{ctx: ctx, r: strings.NewReader(input)})
	observeCheckpoint(ctx, "YAML decode")
	if err := decoder.Decode(&value); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, errors.New("invalid YAML input")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, errors.New("invalid YAML input")
	}
	return checkedValue(ctx, value)
}

// DecodeYAML decodes a rendered YAML document using the same bounded,
// cancellable decoder as the template helpers.
func DecodeYAML(ctx context.Context, input string) (any, error) { return fromYAMLWith(ctx, input) }

func encodingFits(ctx context.Context, value any) (bool, error) {
	b := valueBudget{}
	if err := b.add(ctx, reflect.ValueOf(value), 1, make(map[visit]bool)); err != nil {
		if errors.Is(err, errValueBudget) {
			return false, nil
		}
		return false, err
	}
	// Strings can expand sixfold when JSON-escaped; YAML has comparable quoting
	// overhead. The structural allowance is finite and overflow-safe.
	// Include structural punctuation and the largest ordinary numeric token;
	// this is conservative and all arithmetic is bounded before subtraction.
	if b.nodes > maxEncodedBytes/32 || b.scalarBytes > maxEncodedBytes/6 {
		return false, nil
	}
	return b.nodes*32 <= maxEncodedBytes-b.scalarBytes*6, nil
}

func boundedPrintf(ctx context.Context, format string, args ...any) (string, error) {
	if err := preflightFormat(ctx, format, args); err != nil {
		return "", err
	}
	return boundedFormat(ctx, func(w *checkingWriter) error { _, err := fmt.Fprintf(w, format, args...); return err })
}
func boundedPrint(ctx context.Context, args ...any) (string, error) {
	if err := preflightPrint(ctx, args, false); err != nil {
		return "", err
	}
	return boundedFormat(ctx, func(w *checkingWriter) error { _, err := fmt.Fprint(w, args...); return err })
}
func boundedPrintln(ctx context.Context, args ...any) (string, error) {
	if err := preflightPrint(ctx, args, true); err != nil {
		return "", err
	}
	return boundedFormat(ctx, func(w *checkingWriter) error { _, err := fmt.Fprintln(w, args...); return err })
}

func preflightFormat(ctx context.Context, format string, args []any) error {
	observeCheckpoint(ctx, "formatting preflight")
	if len(format) > maxFormatBytes {
		return ErrOutputLimit
	}
	total, arg, directives := 0, 0, 0
	for i := 0; i < len(format); i++ {
		if err := checkpoint(ctx, i); err != nil {
			return err
		}
		if format[i] != '%' {
			if total == maxFormatBytes {
				return ErrOutputLimit
			}
			total++
			continue
		}
		if i+1 == len(format) {
			return errors.New("gotemplate: malformed printf format")
		}
		i++
		if format[i] == '%' {
			if total == maxFormatBytes {
				return ErrOutputLimit
			}
			total++
			continue
		}
		directives++
		if directives > maxFormatDirectives {
			return ErrOutputLimit
		}
		if format[i] == '[' {
			return errors.New("gotemplate: indexed printf arguments are not supported")
		}
		sharp := false
		for stringsIndexByte("#0+- ", format[i]) >= 0 {
			if format[i] == '#' {
				sharp = true
			}
			i++
			if i >= len(format) {
				return errors.New("gotemplate: malformed printf format")
			}
		}
		width, next, ok := boundedDigits(ctx, format, i)
		if !ok {
			if err := ctx.Err(); err != nil {
				return err
			}
			return errors.New("gotemplate: malformed printf width")
		}
		i = next
		if i < len(format) && format[i] == '*' {
			return errors.New("gotemplate: dynamic printf width is not supported")
		}
		precision := -1
		if i < len(format) && format[i] == '.' {
			i++
			precision, i, ok = boundedDigits(ctx, format, i)
			if !ok {
				if err := ctx.Err(); err != nil {
					return err
				}
				return errors.New("gotemplate: malformed printf precision")
			}
			if i == 0 || (i > 0 && (i == len(format) || format[i-1] == '.')) {
				return errors.New("gotemplate: malformed printf precision")
			}
			if i < len(format) && format[i] == '*' {
				return errors.New("gotemplate: dynamic printf precision is not supported")
			}
		}
		if i >= len(format) {
			return errors.New("gotemplate: malformed printf directive")
		}
		verb := format[i]
		if verb == '%' {
			if total == maxFormatBytes {
				return ErrOutputLimit
			}
			total++
			continue
		}
		if arg >= len(args) {
			return errors.New("gotemplate: printf argument bound is unknown")
		}
		quoted := verb == 'q' || (verb == 'v' && sharp)
		budget, bounded := formatArgBudget(ctx, args[arg], verb, quoted)
		if !bounded {
			return ErrOutputLimit
		}
		// Precision bounds the input for ordinary string verbs. It does not
		// safely bound quoted output: one input byte may become a four-byte
		// escape, so retain the conservative whole-input estimate there.
		if precision >= 0 && !quoted && budget > precision {
			budget = precision
		}
		if width > budget {
			budget = width
		}
		if budget > maxFormatBytes-total {
			return ErrOutputLimit
		}
		total += budget
		arg++
	}
	return nil
}

func boundedDigits(ctx context.Context, s string, i int) (int, int, bool) {
	value := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		if err := checkpoint(ctx, i); err != nil {
			return 0, i, false
		}
		digit := int(s[i] - '0')
		if value > maxFormatBytes/10 || (value == maxFormatBytes/10 && digit > maxFormatBytes%10) {
			return 0, i, false
		}
		value = value*10 + digit
		i++
	}
	return value, i, true
}

func formatArgBudget(ctx context.Context, value any, verb byte, quoted bool) (int, bool) {
	if s, ok := value.(string); ok {
		if verb == 'x' || verb == 'X' {
			return boundedBudget(len(s), 2, 0)
		}
		if quoted {
			// fmt's quoted forms can emit \xNN for control bytes and invalid
			// UTF-8, and must also accommodate escaped Unicode and delimiters.
			return boundedBudget(len(s), 4, 2)
		}
		return boundedBudget(len(s), 1, 0)
	}
	b := valueBudget{}
	if b.add(ctx, reflect.ValueOf(value), 1, make(map[visit]bool)) != nil {
		return 0, false
	}
	if quoted {
		// %#v quotes strings nested in canonical maps/slices. The node
		// allowance covers type names, separators, and container syntax.
		return boundedParts(b.scalarBytes, 4, b.nodes, 64)
	}
	return boundedParts(b.scalarBytes, 6, b.nodes, 32)
}

func boundedBudget(length, multiplier, overhead int) (int, bool) {
	if length > (maxFormatBytes-overhead)/multiplier {
		return 0, false
	}
	return length*multiplier + overhead, true
}

func boundedParts(first, firstMultiplier, second, secondMultiplier int) (int, bool) {
	firstBudget, ok := boundedBudget(first, firstMultiplier, 0)
	if !ok || second > (maxFormatBytes-firstBudget)/secondMultiplier {
		return 0, false
	}
	return firstBudget + second*secondMultiplier, true
}

func preflightPrint(ctx context.Context, args []any, newline bool) error {
	total := 0
	for _, arg := range args {
		if err := ctx.Err(); err != nil {
			return err
		}
		budget, bounded := formatArgBudget(ctx, arg, 'v', false)
		if !bounded {
			return ErrOutputLimit
		}
		if budget > maxFormatBytes-total {
			return ErrOutputLimit
		}
		total += budget
		if total == maxFormatBytes {
			return ErrOutputLimit
		}
		total++
	}
	if newline && total == maxFormatBytes {
		return ErrOutputLimit
	}
	return nil
}

func stringsIndexByte(chars string, c byte) int {
	for i := range chars {
		if chars[i] == c {
			return i
		}
	}
	return -1
}
func boundedFormat(ctx context.Context, fn func(*checkingWriter) error) (string, error) {
	w := &checkingWriter{ctx: ctx, limit: MaxBytes, budget: -1}
	if err := fn(w); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return w.String(), nil
}

type checkingWriter struct {
	ctx    context.Context
	limit  int
	budget int
	bytes.Buffer
}

// checkSource checkpoints finite source chunks before handing the source to
// text/template. The parser itself has a bounded, synchronous section.
func checkSource(ctx context.Context, source string) error {
	observeCheckpoint(ctx, "source scan")
	for i := 0; i < len(source); i += checkpointInterval {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func checkpoint(ctx context.Context, n int) error {
	if n%checkpointInterval == 0 {
		return ctx.Err()
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > checkpointInterval {
		p = p[:checkpointInterval]
	}
	n, err := r.r.Read(p)
	if cerr := r.ctx.Err(); cerr != nil {
		return n, cerr
	}
	return n, err
}

func (w *checkingWriter) Write(p []byte) (int, error) {
	observeCheckpoint(w.ctx, "checkingWriter")
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.budget >= 0 {
		if w.budget == 0 {
			return 0, ErrASTLimit
		}
		w.budget--
	}
	remaining := w.limit - w.Len()
	if remaining <= 0 {
		return 0, ErrOutputLimit
	}
	limited := len(p) > remaining
	if limited {
		p = p[:remaining]
	}
	written := 0
	for written < len(p) {
		end := written + checkpointInterval
		if end > len(p) {
			end = len(p)
		}
		if written > 0 {
			if err := w.ctx.Err(); err != nil {
				return written, err
			}
		}
		before := written
		n, err := w.Buffer.Write(p[written:end])
		written += n
		if err != nil {
			return written, err
		}
		if n != end-before {
			return written, io.ErrShortWrite
		}
	}
	if written > 0 {
		if err := w.ctx.Err(); err != nil {
			return written, err
		}
	}
	if limited {
		return written, ErrOutputLimit
	}
	return written, nil
}
