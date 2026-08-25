// Package temp implements Salt's temp module: temporary directories and
// files over the injectable filesystem, mirroring saltstack/salt/modules/
// temp.py @ pinned revision.
package temp

import (
	"context"
	"path/filepath"

	"github.com/friz-zy/statekit/internal/runtime"
)

// defaultScratchDir keeps temporary artifacts inside the project
// workspace instead of the shared OS temp directory.
const defaultScratchDir = ".statekit/tmp"

func resolveParent(rt *runtime.Runtime, parent string) string {
	if parent == "" {
		parent = defaultScratchDir
	}
	// MkdirTemp requires an existing parent; create the project-local
	// scratch root on demand.
	rt.FS.MkdirAll(parent, 0o700)
	return parent
}

type DirArgs struct {
	Suffix *string `statekit:"name=suffix"`
	Prefix *string `statekit:"name=prefix"`
	Parent *string `statekit:"name=parent"`
}

type DirFunc struct{}

func (DirFunc) Name() string { return "temp.dir" }
func (DirFunc) Args() any    { return DirArgs{} }
func (DirFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DirArgs)
	prefix := strOr(a.Prefix)
	if prefix == "" {
		prefix = "tmp"
	}
	parent := resolveParent(rt, strOr(a.Parent))
	return rt.FS.MkdirTemp(parent, prefix+"*"+strOr(a.Suffix))
}

type FileArgs struct {
	Suffix *string `statekit:"name=suffix"`
	Prefix *string `statekit:"name=prefix"`
	Parent *string `statekit:"name=parent"`
}

type FileFunc struct{}

func (FileFunc) Name() string { return "temp.file" }
func (FileFunc) Args() any    { return FileArgs{} }

// File mirrors mkstemp + close: the created path returns with empty
// contents. MkdirTemp backs the unique-name generation because the
// filesystem abstraction has no O_CREAT|O_EXCL primitive.
func (FileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FileArgs)
	prefix := strOr(a.Prefix)
	if prefix == "" {
		prefix = "tmp"
	}
	parent := resolveParent(rt, strOr(a.Parent))
	dir, err := rt.FS.MkdirTemp(parent, prefix+"*"+strOr(a.Suffix))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rt.FS.Remove(dir) }()
	path := filepath.Join(dir, "file")
	if werr := rt.FS.WriteFile(path, nil, 0o600); werr != nil {
		return nil, werr
	}
	return path, nil
}

func strOr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// Register installs all temp-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{DirFunc{}, FileFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
