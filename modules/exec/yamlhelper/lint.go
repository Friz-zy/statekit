// Package yaml implements Salt's yaml helper: structural linting of YAML
// sources over gopkg.in/yaml.v3 (the existing dependency).
//
// Reference: saltstack/salt/modules/yaml.py @ pinned revision. Divergence:
// upstream shells out to the yamllint tool including style rules; StateKit
// validates syntax and structure only.
package yamlhelper

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
	"gopkg.in/yaml.v3"
)

type lintArgs struct {
	Source  string  `statekit:"required,name=source"`
	Saltenv *string `statekit:"name=saltenv"`
}

type lintFunc struct{}

// Lint parses the source as YAML and reports syntax problems. A salt://
// source hits the cp.cache_file boundary like every other family; local
// paths read directly. Valid documents return False (no issues); problems
// return the list of error strings.
func (lintFunc) Name() string { return "yaml.lint" }
func (lintFunc) Args() any    { return lintArgs{} }
func (lintFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*lintArgs)
	var content []byte
	switch {
	case strings.HasPrefix(a.Source, "salt://"):
		return false, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	default:
		data, err := rt.FS.ReadFile(a.Source)
		if err != nil {
			return false, fmt.Errorf("Template was unable to be cached")
		}
		content = data
	}

	var doc any
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return []string{err.Error()}, nil
	}
	return false, nil
}

// Register installs all yaml-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{lintFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
