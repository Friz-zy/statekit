// Package jinja implements the minimal jinja helper surface allowed by the
// templating ADR: data-file imports only. Variable/substitution rendering
// is scoped separately; full Jinja stays excluded.
//
// Reference: saltstack/salt/modules/jinja.py @ pinned revision.
package jinja

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	"gopkg.in/yaml.v3"
)

type importYAMLArgs struct {
	Path string `statekit:"required,name=path"`
}

type importYAMLFunc struct{}

// ImportYAML loads YAML data from the given path. Upstream wraps the file
// in a jinja import template; the minimal engine reads and parses directly
// (documented divergence).
func (importYAMLFunc) Name() string { return "jinja.import_yaml" }
func (importYAMLFunc) Args() any    { return importYAMLArgs{} }
func (importYAMLFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*importYAMLArgs)
	data, err := rt.FS.ReadFile(a.Path)
	if err != nil {
		return false, nil
	}
	var doc any
	if yerr := yaml.Unmarshal(data, &doc); yerr != nil {
		return false, fmt.Errorf("Unable to import yaml from %s: %v", a.Path, yerr)
	}
	return doc, nil
}

type importJSONArgs struct {
	Path string `statekit:"required,name=path"`
}

type importJSONFunc struct{}

func (importJSONFunc) Name() string { return "jinja.import_json" }
func (importJSONFunc) Args() any    { return importJSONArgs{} }
func (importJSONFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*importJSONArgs)
	data, err := rt.FS.ReadFile(a.Path)
	if err != nil {
		return false, nil
	}
	var doc any
	if jerr := json.Unmarshal(data, &doc); jerr != nil {
		return false, fmt.Errorf("Unable to import json from %s: %v", a.Path, jerr)
	}
	return doc, nil
}

type loadMapArgs struct {
	Path  string `statekit:"required,name=path"`
	Value string `statekit:"required,name=value"`
}

type loadMapFunc struct{}

// LoadMap loads the map at path. Upstream renders an import template; the
// minimal engine parses the file as YAML (the dominant map.jinja shape —
// templates with logic surface parse errors honestly).
func (loadMapFunc) Name() string { return "jinja.load_map" }
func (loadMapFunc) Args() any    { return loadMapArgs{} }
func (loadMapFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*loadMapArgs)
	data, err := rt.FS.ReadFile(a.Path)
	if err != nil {
		return false, nil
	}
	content := strings.TrimSpace(string(data))
	if strings.Contains(content, "{%") || strings.Contains(content, "{{") {
		return false, fmt.Errorf(
			"template logic in %s exceeds the minimal jinja subset", a.Path)
	}
	var doc any
	if yerr := yaml.Unmarshal([]byte(content), &doc); yerr != nil {
		return false, fmt.Errorf("Unable to load map from %s: %v", a.Path, yerr)
	}
	return doc, nil
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
