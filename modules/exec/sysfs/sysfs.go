// Package sysfs implements Salt-compatible SysFS access functions.
//
// Reference: saltstack/salt/modules/sysfs.py @ pinned revision.
//
// Contract notes (init.md section 28): missing keys, failed writes, empty
// attribute values, and unreadable files surface as boolean false exactly
// like Salt's broad-except handlers, not as Go errors. Attribute values are
// coerced to int then float like Salt's read(). Salt opens attributes with
// O_NONBLOCK to survive kernel pipe interfaces; StateKit reads through the
// runtime FileSystem (regular-file semantics), a documented caveat for
// pipe-backed attributes.
package sysfs

import (
	"context"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux: SysFS is a
// Linux contract (catalog platform marker is_linux).
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

// resolvePath follows symlink chains through the FileSystem abstraction,
// mirroring os.path.realpath semantics: each component is resolved in
// order, so ".." pops against the already-resolved prefix (critical for
// paths like /sys/block/sda/../queue when sda is a symlink chain). It
// reports failure for dangling chains instead of returning the last hop.
func resolvePath(fsys runtime.FileSystem, target string) (string, bool) {
	if !filepath.IsAbs(target) {
		return "", false
	}
	pending := strings.Split(target, "/")
	cur := ""
	hops := 0
	for len(pending) > 0 {
		seg := pending[0]
		pending = pending[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			idx := strings.LastIndexByte(cur, '/')
			if idx <= 0 {
				cur = ""
			} else {
				cur = cur[:idx]
			}
			continue
		}
		next := cur + "/" + seg
		info, err := fsys.Lstat(next)
		if err != nil {
			// Non-strict realpath keeps unresolvable tails verbatim.
			cur = next
			continue
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		hops++
		if hops > 40 {
			return "", false
		}
		link, err := fsys.Readlink(next)
		if err != nil {
			return "", false
		}
		if filepath.IsAbs(link) {
			cur = ""
			pending = append(strings.Split(link, "/"), pending...)
			continue
		}
		base := ""
		if idx := strings.LastIndexByte(cur, '/'); idx > 0 {
			base = cur[:idx]
		}
		pending = append(strings.Split(filepath.Join(base, link), "/"), pending...)
	}
	if cur == "" {
		cur = "/"
	}
	return cur, true
}

// joinSys concatenates without lexical cleanup so ".." survives until
// symlink-aware resolution, matching os.path.join.
func joinSys(base, rel string) string {
	if base == "" {
		return rel
	}
	if rel == "" {
		return base
	}
	if strings.HasSuffix(base, "/") {
		return base + rel
	}
	return base + "/" + rel
}

// exists reports whether the resolved path stat'able (follows symlinks).
func exists(fsys runtime.FileSystem, target string) bool {
	_, err := fsys.Stat(target)
	return err == nil
}

func isDir(fsys runtime.FileSystem, target string) bool {
	info, err := fsys.Stat(target)
	return err == nil && info.IsDir()
}

// TargetArgs mirrors Salt's target signature; full defaults to True so the
// tri-state pointer preserves the documented default when omitted.
type TargetArgs struct {
	Key  string `statekit:"required"`
	Full *bool  `statekit:"name=full"`
}

type targetFunc struct {
	linuxOnly
}

func (targetFunc) Name() string { return "sysfs.target" }
func (targetFunc) Args() any    { return TargetArgs{} }
func (targetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*TargetArgs)
	full := true
	if a.Full != nil {
		full = *a.Full
	}
	resolved, ok := sysfsTarget(rt, a.Key)
	if !ok {
		return false, nil
	}
	if full {
		return resolved, nil
	}
	return filepath.Base(resolved), nil
}

// sysfsTarget ports sysfs.target: prefixes /sys, resolves symlinks, and
// reports unknown keys as false.
func sysfsTarget(rt *runtime.Runtime, key string) (string, bool) {
	if !strings.HasPrefix(key, "/sys") {
		key = joinSys("/sys", key)
	}
	resolved, ok := resolvePath(rt.FS, key)
	if !ok || !exists(rt.FS, resolved) {
		return "", false
	}
	return resolved, true
}

// WriteArgs mirrors Salt's write signature.
type WriteArgs struct {
	Key   string `statekit:"required"`
	Value string `statekit:"required,name=value"`
}

type writeFunc struct {
	linuxOnly
}

func (writeFunc) Name() string { return "sysfs.write" }
func (writeFunc) Args() any    { return WriteArgs{} }

// Execute writes "value\n" and reports failure as false, never an error,
// matching Salt's broad except.
func (writeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*WriteArgs)
	key, ok := sysfsTarget(rt, a.Key)
	if !ok {
		return false, nil
	}
	if err := rt.FS.WriteFile(key, []byte(a.Value+"\n"), 0o644); err != nil {
		return false, nil
	}
	return true, nil
}

// ReadArgs mirrors Salt's read signature. The key accepts one path or a
// list of paths relative to root; a single scalar keeps Salt's string-form
// contract (bare value), while multiple keys produce the tree form.
type ReadArgs struct {
	Key  []any  `statekit:"name=key"`
	Root string `statekit:"name=root"`
}

type readFunc struct {
	linuxOnly
}

func (readFunc) Name() string { return "sysfs.read" }
func (readFunc) Args() any    { return ReadArgs{} }

func (readFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ReadArgs)
	switch {
	case len(a.Key) == 0:
		return false, nil
	case len(a.Key) == 1:
		single, ok := a.Key[0].(string)
		if !ok {
			return false, nil
		}
		return readOne(rt, a.Root, single), nil
	default:
		res := map[string]any{}
		for _, entry := range a.Key {
			key, ok := entry.(string)
			if !ok {
				continue
			}
			val := readOne(rt, a.Root, key)
			if val != false {
				res[key] = val
			}
		}
		return res, nil
	}
}

// readOne reads a single SysFS location; directories expand into a nested
// tree over their readable interfaces.
func readOne(rt *runtime.Runtime, root, key string) any {
	joined := joinSys(root, key)
	target, ok := sysfsTarget(rt, joined)
	if !ok {
		return false
	}
	if isDir(rt.FS, target) {
		intfsRaw, err := interfacesFunc{}.Execute(context.Background(), rt, &InterfacesArgs{Root: target})
		if err != nil {
			return false
		}
		intfs := intfsRaw.(map[string]any)
		result := map[string]any{}
		for _, group := range []string{"r", "rw"} {
			for _, subkeyAny := range intfs[group].([]any) {
				subkey := subkeyAny.(string)
				subval := readOne(rt, target, subkey)
				if subval == false {
					continue
				}
				parts := strings.Split(subkey, "/")
				leaf := parts[len(parts)-1]
				parents := parts[:len(parts)-1]
				cursor := result
				for _, parent := range parents {
					next, ok := cursor[parent].(map[string]any)
					if !ok {
						next = map[string]any{}
						cursor[parent] = next
					}
					cursor = next
				}
				cursor[leaf] = subval
			}
		}
		return result
	}
	data, err := rt.FS.ReadFile(target)
	if err != nil {
		return false
	}
	val := strings.TrimSpace(string(data))
	if val == "" {
		return false
	}
	if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(val, 64); err == nil {
		return parsed
	}
	return val
}

// AttrArgs mirrors Salt's attr signature; the omitted value keeps the
// read behavior (tri-state pointer preserving value=None).
type AttrArgs struct {
	Key   string  `statekit:"required"`
	Value *string `statekit:"name=value"`
}

type attrFunc struct {
	linuxOnly
}

func (attrFunc) Name() string { return "sysfs.attr" }
func (attrFunc) Args() any    { return AttrArgs{} }
func (attrFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AttrArgs)
	key, ok := sysfsTarget(rt, a.Key)
	if !ok {
		return false, nil
	}
	if isDir(rt.FS, key) {
		return key, nil
	}
	if a.Value != nil {
		wf := writeFunc{}
		return wf.Execute(ctx, rt, &WriteArgs{Key: key, Value: *a.Value})
	}
	rf := readFunc{}
	return rf.Execute(ctx, rt, &ReadArgs{Key: []any{key}})
}

// InterfacesArgs mirrors Salt's interfaces signature.
type InterfacesArgs struct {
	Root string `statekit:"name=root"`
}

type interfacesFunc struct {
	linuxOnly
}

func (interfacesFunc) Name() string { return "sysfs.interfaces" }
func (interfacesFunc) Args() any    { return InterfacesArgs{} }

// Execute walks root without following symlinks and classifies every file
// by its owner read/write permission bits: r, w, rw.
func (interfacesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InterfacesArgs)
	root, ok := sysfsTarget(rt, a.Root)
	if !ok || !isDir(rt.FS, root) {
		return false, nil
	}
	var reads, writes, readwrites []any
	walkInterfaces(rt, root, root, &reads, &writes, &readwrites)
	return map[string]any{"r": reads, "w": writes, "rw": readwrites}, nil
}

func walkInterfaces(rt *runtime.Runtime, root, current string, reads, writes, readwrites *[]any) {
	entries, err := rt.FS.ReadDir(current)
	if err != nil {
		return
	}
	for _, entry := range entries {
		full := filepath.Join(current, entry.Name())
		if entry.IsDir() {
			// os_walk(followlinks=False) does not descend symlinked dirs.
			if entry.Type()&fs.ModeSymlink != 0 {
				continue
			}
			walkInterfaces(rt, root, full, reads, writes, readwrites)
			continue
		}
		info, err := rt.FS.Stat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		mode := info.Mode()
		isR := mode&0o400 != 0
		isW := mode&0o200 != 0
		rel, err := filepath.Rel(root, full)
		if err != nil {
			continue
		}
		switch {
		case isW && isR:
			*readwrites = append(*readwrites, rel)
		case isW:
			*writes = append(*writes, rel)
		case isR:
			*reads = append(*reads, rel)
		}
	}
}

// Register installs all sysfs-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		attrFunc{},
		writeFunc{},
		readFunc{},
		targetFunc{},
		interfacesFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
