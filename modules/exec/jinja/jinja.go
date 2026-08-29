// Package jinja implements the minimal jinja helper surface allowed by the
// templating ADR: data-file imports only. The bridge supports only bounded
// literals, variables, conditionals, assignments, and load_map's tojson;
// this is not full Salt/Jinja parity and deliberately has no loader parity.
//
// Reference: saltstack/salt/modules/jinja.py @ pinned revision.
package jinja

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/friz-zy/statekit/internal/renderer/gotemplate"
	jinjarenderer "github.com/friz-zy/statekit/internal/renderer/jinja"
	"github.com/friz-zy/statekit/internal/runtime"
)

// ErrJinjaUnavailable is returned when no candidate Python has Jinja2.
var ErrJinjaUnavailable = jinjarenderer.ErrJinjaUnavailable

var (
	ErrRead            = errors.New("jinja: unable to read source")
	ErrInvalidRendered = errors.New("jinja: invalid rendered document")
)

type importYAMLArgs struct {
	Path string `statekit:"required,name=path"`
}

type importYAMLFunc struct{}

// ImportYAML renders the source through the bounded Python Jinja bridge, then
// decodes the rendered YAML in Go. Salt-specific loaders and globals are not
// implemented by this phase.
func (importYAMLFunc) Name() string { return "jinja.import_yaml" }
func (importYAMLFunc) Args() any    { return importYAMLArgs{} }
func (importYAMLFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*importYAMLArgs)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, err := readSource(rt, a.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, stableReadError(err)
	}
	rendered, err := jinjarenderer.Render(ctx, rt.Runner, jinjarenderer.Request{Operation: "render", Source: string(data)})
	if err != nil {
		return false, err
	}
	var doc any
	var yerr error
	if doc, yerr = gotemplate.DecodeYAML(ctx, rendered); yerr != nil {
		return false, stableDecodeError(yerr)
	}
	return doc, nil
}

type importJSONArgs struct {
	Path string `statekit:"required,name=path"`
}

type importJSONFunc struct{}

func (importJSONFunc) Name() string { return "jinja.import_json" }
func (importJSONFunc) Args() any    { return importJSONArgs{} }
func (importJSONFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*importJSONArgs)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, err := readSource(rt, a.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, stableReadError(err)
	}
	rendered, err := jinjarenderer.Render(ctx, rt.Runner, jinjarenderer.Request{Operation: "render", Source: string(data)})
	if err != nil {
		return false, err
	}
	var doc any
	var jerr error
	if doc, jerr = gotemplate.DecodeJSON(ctx, rendered); jerr != nil {
		return false, stableDecodeError(jerr)
	}
	return doc, nil
}

type loadMapArgs struct {
	Path  string `statekit:"required,name=path"`
	Value string `statekit:"required,name=value"`
}

type loadMapFunc struct{}

// LoadMap renders a map template and returns only the requested identifier.
func (loadMapFunc) Name() string { return "jinja.load_map" }
func (loadMapFunc) Args() any    { return loadMapArgs{} }
func (loadMapFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*loadMapArgs)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, err := readSource(rt, a.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, stableReadError(err)
	}
	rendered, err := jinjarenderer.Render(ctx, rt.Runner, jinjarenderer.Request{Operation: "load_map", Source: string(data), Value: a.Value})
	if err != nil {
		return false, err
	}
	var doc any
	var jerr error
	if doc, jerr = gotemplate.DecodeJSON(ctx, rendered); jerr != nil {
		return false, stableDecodeError(jerr)
	}
	return doc, nil
}

func readSource(rt *runtime.Runtime, path string) ([]byte, error) {
	return runtime.ReadFileBounded(rt.FS, path, jinjarenderer.MaxBytes)
}

func stableReadError(err error) error {
	if errors.Is(err, runtime.ErrReadLimit) {
		return fmt.Errorf("%w: %w", ErrRead, runtime.ErrReadLimit)
	}
	return ErrRead
}

func stableDecodeError(err error) error {
	// Preserve only bounded, path-free categories for callers that need to
	// distinguish resource failures; decoder text itself is not public.
	return fmt.Errorf("%w: %w", ErrInvalidRendered, err)
}

// Register installs all jinja-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		importYAMLFunc{},
		importJSONFunc{},
		loadMapFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
