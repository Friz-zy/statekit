// Package gotemplate exposes the opt-in native text/template surface. It is
// deliberately separate from Salt-compatible jinja.* functions.
package gotemplate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"

	renderer "github.com/friz-zy/statekit/internal/renderer/gotemplate"
	"github.com/friz-zy/statekit/internal/runtime"
)

type renderArgs struct {
	Contents string         `statekit:"required,name=contents"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
}

type importArgs struct {
	Path     string         `statekit:"required,name=path"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
}

type loadMapArgs struct {
	Path     string         `statekit:"required,name=path"`
	Value    string         `statekit:"required,name=value"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
}

func readTemplateSource(fsys runtime.FileSystem, path string) ([]byte, error) {
	contents, err := runtime.ReadFileBounded(fsys, path, renderer.MaxBytes)
	if errors.Is(err, runtime.ErrReadLimit) {
		return nil, renderer.ErrSourceLimit
	}
	return contents, err
}

type renderFunc struct{}

func (renderFunc) Name() string { return "gotemplate.render" }
func (renderFunc) Args() any    { return renderArgs{} }
func (renderFunc) Execute(ctx context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*renderArgs)
	return renderer.Render(ctx, renderer.Request{Contents: a.Contents, Context: a.Context, Defaults: a.Defaults})
}

type importYAMLFunc struct{}

func (importYAMLFunc) Name() string { return "gotemplate.import_yaml" }
func (importYAMLFunc) Args() any    { return importArgs{} }
func (importYAMLFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := args.(*importArgs)
	contents, err := readTemplateSource(rt.FS, a.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_yaml %s: %w", a.Path, err)
	}
	rendered, err := renderer.Render(ctx, renderer.Request{Contents: string(contents), Context: a.Context, Defaults: a.Defaults})
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_yaml %s: %w", a.Path, err)
	}
	var value any
	value, err = renderer.DecodeYAML(ctx, rendered)
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_yaml %s: %w", a.Path, err)
	}
	return value, nil
}

type importJSONFunc struct{}

func (importJSONFunc) Name() string { return "gotemplate.import_json" }
func (importJSONFunc) Args() any    { return importArgs{} }
func (importJSONFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := args.(*importArgs)
	contents, err := readTemplateSource(rt.FS, a.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_json %s: %w", a.Path, err)
	}
	rendered, err := renderer.Render(ctx, renderer.Request{Contents: string(contents), Context: a.Context, Defaults: a.Defaults})
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_json %s: %w", a.Path, err)
	}
	value, err := renderer.DecodeJSON(ctx, rendered)
	if err != nil {
		return nil, fmt.Errorf("gotemplate.import_json %s: %w", a.Path, err)
	}
	return value, nil
}

var templateName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type loadMapFunc struct{}

func (loadMapFunc) Name() string { return "gotemplate.load_map" }
func (loadMapFunc) Args() any    { return loadMapArgs{} }

// Execute renders only the supplied named definition, then decodes that
// output as YAML. Value is a template identifier, never executable source.
func (loadMapFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := args.(*loadMapArgs)
	if !templateName.MatchString(a.Value) {
		return nil, fmt.Errorf("gotemplate.load_map: invalid template name %q", a.Value)
	}
	contents, err := readTemplateSource(rt.FS, a.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gotemplate.load_map %s: %w", a.Path, err)
	}
	rendered, err := renderer.RenderNamed(ctx, renderer.Request{Contents: string(contents), Context: a.Context, Defaults: a.Defaults}, a.Value)
	if err != nil {
		return nil, fmt.Errorf("gotemplate.load_map %s: %w", a.Path, err)
	}
	value, err := renderer.DecodeYAML(ctx, rendered)
	if err != nil {
		return nil, fmt.Errorf("gotemplate.load_map %s: %w", a.Path, err)
	}
	return value, nil
}

// Register installs all native Go-template execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{renderFunc{}, importYAMLFunc{}, importJSONFunc{}, loadMapFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
