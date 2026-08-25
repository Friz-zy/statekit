// Package out renders JSON-serializable data through the available
// outputters, mirroring saltstack/salt/modules/out.py @ pinned revision.
//
// Contract notes (init.md section 28): upstream dispatches to the full
// salt.output framework (nested/highstate/...). StateKit supports json and
// yaml through internal/output plus a minimal nested renderer; unknown
// formats surface UnsupportedError (documented subset).
package out

import (
	"context"
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/output"
	"github.com/friz-zy/statekit/internal/runtime"
)

type OutFormatArgs struct {
	Data any    `statekit:"required,name=data"`
	Out  string `statekit:"name=out"`
}

type OutFormatFunc struct{}

func (OutFormatFunc) Name() string { return "out.out_format" }
func (OutFormatFunc) Args() any    { return OutFormatArgs{} }

// render dispatches by format name.
func render(data any, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		var b strings.Builder
		if err := output.Encode(&b, output.FormatJSON, data); err != nil {
			return "", err
		}
		return b.String(), nil
	case "yaml":
		var b strings.Builder
		if err := output.Encode(&b, output.FormatYAML, data); err != nil {
			return "", err
		}
		return b.String(), nil
	case "", "nested":
		return nestedRender(data, ""), nil
	default:
		return "", &runtime.UnsupportedError{Kind: "outputter", Name: format}
	}
}

// nestedRender mirrors the shape of Salt's nested outputter: scalar values
// print bare, maps print "|_- key:" headers with two-space indentation.
func nestedRender(data any, indent string) string {
	var b strings.Builder
	switch x := data.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(indent + "|_ " + k + ":")
			if sub, isMap := x[k].(map[string]any); isMap {
				b.WriteString("\n")
				b.WriteString(nestedRender(sub, indent+"  "))
			} else if list, isList := x[k].([]any); isList {
				b.WriteString("\n")
				for _, item := range list {
					b.WriteString(indent + "  |_- ")
					b.WriteString(scalarString(item) + "\n")
				}
			} else {
				b.WriteString(" " + scalarString(x[k]) + "\n")
			}
		}
	case []any:
		for _, item := range x {
			if sub, isMap := item.(map[string]any); isMap {
				b.WriteString(nestedRender(sub, indent))
				continue
			}
			b.WriteString(indent + "|_- " + scalarString(item) + "\n")
		}
	default:
		b.WriteString(indent + scalarString(data) + "\n")
	}
	return b.String()
}

func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	}
	return fmt.Sprintf("%v", v)
}

func (OutFormatFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*OutFormatArgs)
	format := a.Out
	if format == "" {
		format = "nested"
	}
	return render(a.Data, format)
}

type StringFormatArgs = OutFormatArgs

type StringFormatFunc struct{}

// StringFormat renders then strips ANSI escape sequences. The nested/json/
// yaml renderers never emit them, so the strip is a no-op kept for parity.
func (StringFormatFunc) Name() string { return "out.string_format" }
func (StringFormatFunc) Args() any    { return StringFormatArgs{} }
func (StringFormatFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*StringFormatArgs)
	format := a.Out
	if format == "" {
		format = "nested"
	}
	res, err := render(a.Data, format)
	if err != nil {
		return nil, err
	}
	return stripANSI(res), nil
}

var ansiRe = ansiPattern()

func ansiPattern() *regexpT { return compileANSI() }

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

type HtmlFormatArgs = OutFormatArgs

type HtmlFormatFunc struct{}

// HTMLFormat wraps the rendered text in a minimal HTML document with the
// content HTML-escaped inside <pre> tags.
func (HtmlFormatFunc) Name() string { return "out.html_format" }
func (HtmlFormatFunc) Args() any    { return HtmlFormatArgs{} }
func (HtmlFormatFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*HtmlFormatArgs)
	format := a.Out
	if format == "" {
		format = "nested"
	}
	text, err := render(a.Data, format)
	if err != nil {
		return nil, err
	}
	escaped := html.EscapeString(text)
	return "<html><body>\n<pre>\n" + escaped + "</pre>\n</body></html>", nil
}

// Register installs all out-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		OutFormatFunc{},
		StringFormatFunc{},
		HtmlFormatFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
