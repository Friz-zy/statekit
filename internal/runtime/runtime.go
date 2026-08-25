// Package runtime defines the explicit runtime object passed to every
// function, replacing Salt's implicit dunder globals
// (__salt__, __states__, __grains__, __opts__, __pillar__, __context__).
//
// Reference: plans/init.md sections 13, 16, 18-19, 37-38, 41, 46.
package runtime

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/registry"
	"github.com/friz-zy/statekit/internal/result"
)

// ExecFunction is a registered execution function, the equivalent of a
// function in Salt execution modules (salt/modules/*).
type ExecFunction interface {
	// Name is the full "module.function" identifier.
	Name() string
	// Args returns a zero-value argument struct whose `statekit` struct tags
	// single-source the CLI flags, structured input keys, and validation.
	Args() any
	// Execute receives a pointer to a decoded copy of the argument struct.
	Execute(ctx context.Context, rt *Runtime, args any) (any, error)
}

// StateFunction is a registered state function, the equivalent of a function
// in Salt state modules (salt/states/*).
type StateFunction interface {
	// Name is the full "module.function" identifier.
	Name() string
	// Args returns a zero-value argument struct whose `statekit` struct tags
	// single-source the CLI flags, structured input keys, and validation.
	Args() any
	// Apply receives a pointer to a decoded copy of the argument struct.
	Apply(ctx context.Context, rt *Runtime, args any) result.StateResult
}

// UnsupportedError reports an unknown function, state, or provider name.
// The CLI maps it to exit code 3.
type UnsupportedError struct {
	Kind string // "function", "state", or "provider"
	Name string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("unsupported %s %q", e.Kind, e.Name)
}

// ExecRegistry holds execution functions keyed by "module.function".
type ExecRegistry struct {
	reg *registry.Registry[ExecFunction]
}

// NewExecRegistry creates an empty execution registry.
func NewExecRegistry() *ExecRegistry { return &ExecRegistry{reg: registry.New[ExecFunction]()} }

// Register adds an execution function under its declared name.
func (r *ExecRegistry) Register(fn ExecFunction) error { return r.reg.Register(fn.Name(), fn) }

// Get looks up an execution function by full name.
func (r *ExecRegistry) Get(name string) (ExecFunction, bool) { return r.reg.Get(name) }

// Names lists execution functions available on the current platform,
// sorted lexicographically.
func (r *ExecRegistry) Names() []string { return r.filterNames(r.reg.Names()) }

func (r *ExecRegistry) filterNames(names []string) []string {
	goos := CurrentGOOS()
	out := make([]string, 0, len(names))
	for _, name := range names {
		if fn, ok := r.reg.Get(name); ok && SupportsPlatform(fn, goos) {
			out = append(out, name)
		}
	}
	return out
}

// Len returns the number of registered functions.
func (r *ExecRegistry) Len() int { return r.reg.Len() }

// Call invokes a registered execution function by name. Functions declared
// for other platforms surface as unsupported on this one.
func (r *ExecRegistry) Call(ctx context.Context, rt *Runtime, name string, args any) (any, error) {
	fn, ok := r.reg.Get(name)
	if !ok || !SupportsPlatform(fn, CurrentGOOS()) {
		return nil, &UnsupportedError{Kind: "function", Name: name}
	}
	return fn.Execute(ctx, rt, args)
}

// StateRegistry holds state functions keyed by "module.function".
type StateRegistry struct {
	reg *registry.Registry[StateFunction]
}

// NewStateRegistry creates an empty state registry.
func NewStateRegistry() *StateRegistry { return &StateRegistry{reg: registry.New[StateFunction]()} }

// Register adds a state function under its declared name.
func (r *StateRegistry) Register(fn StateFunction) error { return r.reg.Register(fn.Name(), fn) }

// Get looks up a state function by full name.
func (r *StateRegistry) Get(name string) (StateFunction, bool) { return r.reg.Get(name) }

// Names lists registered state functions sorted lexicographically.
func (r *StateRegistry) Names() []string { return r.reg.Names() }

// Len returns the number of registered functions.
func (r *StateRegistry) Len() int { return r.reg.Len() }

// Apply invokes a registered state function by name. Functions declared
// for other platforms surface as unsupported on this one.
func (r *StateRegistry) Apply(ctx context.Context, rt *Runtime, name string, args any) (result.StateResult, error) {
	fn, ok := r.reg.Get(name)
	if !ok || !SupportsPlatform(fn, CurrentGOOS()) {
		return result.StateResult{}, &UnsupportedError{Kind: "state", Name: name}
	}
	return fn.Apply(ctx, rt, args), nil
}

// Selector picks the provider name for its kind based on local facts.
type Selector func(f *facts.Facts) (string, error)

// ProviderRegistry stores providers grouped by kind ("pkg", "service", ...)
// and resolves them through kind-specific fact-driven selectors, mirroring
// Salt's virtual-module mechanism.
type ProviderRegistry struct {
	mu        sync.RWMutex
	kinds     map[string]*registry.Registry[any]
	selectors map[string]Selector
}

// NewProviderRegistry creates an empty provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		kinds:     make(map[string]*registry.Registry[any]),
		selectors: make(map[string]Selector),
	}
}

// Register adds a provider implementation under kind and name.
func (r *ProviderRegistry) Register(kind, name string, provider any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg := r.kinds[kind]
	if reg == nil {
		reg = registry.New[any]()
		r.kinds[kind] = reg
	}
	return reg.Register(name, provider)
}

// SetSelector installs the fact-driven selection callback for kind.
func (r *ProviderRegistry) SetSelector(kind string, sel Selector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selectors[kind] = sel
}

// Names lists provider names registered for kind, sorted; empty for unknown kinds.
func (r *ProviderRegistry) Names(kind string) []string {
	r.mu.RLock()
	reg := r.kinds[kind]
	r.mu.RUnlock()
	if reg == nil {
		return []string{}
	}
	return reg.Names()
}

// Resolve selects the provider for kind using the registered selector and
// the given facts. A single registered provider resolves without selector;
// multiple providers require one.
func (r *ProviderRegistry) Resolve(f *facts.Facts, kind string) (any, string, error) {
	r.mu.RLock()
	reg, sel := r.kinds[kind], r.selectors[kind]
	r.mu.RUnlock()

	if reg == nil || reg.Len() == 0 {
		return nil, "", &UnsupportedError{Kind: "provider", Name: kind}
	}

	name := ""
	switch {
	case sel != nil:
		picked, err := sel(f)
		if err != nil {
			return nil, "", err
		}
		name = picked
	case reg.Len() == 1:
		name = reg.Names()[0]
	default:
		return nil, "", fmt.Errorf("provider registry: no selector registered for kind %q", kind)
	}

	provider, ok := reg.Get(name)
	if !ok {
		return nil, name, &UnsupportedError{Kind: "provider", Name: kind + "." + name}
	}
	return provider, name, nil
}

// RuntimeOptions carries process-wide options.
type RuntimeOptions struct {
	// Test is reserved for a process-wide dry-run default. Canonical test
	// mode remains the per-state --test flag matching Salt's test=True.
	Test bool
}

// Command builds a shell-free argv command for the central Runner.
func Command(argv ...string) process.Command {
	if len(argv) == 0 {
		return process.Command{}
	}
	return process.Command{Name: argv[0], Args: append([]string{}, argv[1:]...)}
}

// Runtime is the explicit dependency object handed to every function,
// replacing Salt's dynamic dunder dictionaries.
type Runtime struct {
	Exec      *ExecRegistry
	States    *StateRegistry
	Facts     *facts.Facts
	Providers *ProviderRegistry
	Runner    process.Runner
	FS        FileSystem
	Options   RuntimeOptions
}

// FileSystem abstracts the filesystem operations modules rely on so behavior
// can be tested hermetically. It mirrors the small os subset the project
// needs instead of hiding normal filesystem APIs (plan section 38).
type FileSystem interface {
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	MkdirTemp(dir, pattern string) (string, error)
	Remove(name string) error
	RemoveAll(path string) error
	Rename(oldpath, newpath string) error
	Symlink(oldname, newname string) error
	Link(oldname, newname string) error
	Glob(pattern string) ([]string, error)
	Readlink(name string) (string, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Chmod(name string, mode fs.FileMode) error
	Chown(name string, uid, gid int) error
}

// OSFileSystem is the production FileSystem backed by the os package.
type OSFileSystem struct{}

// NewOSFileSystem returns the real-filesystem implementation.
func NewOSFileSystem() *OSFileSystem { return &OSFileSystem{} }

// Stat implements FileSystem following symlinks.
func (OSFileSystem) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }

// Lstat implements FileSystem without following the final symlink.
func (OSFileSystem) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

// ReadFile implements FileSystem.
func (OSFileSystem) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

// WriteFile implements FileSystem.
func (OSFileSystem) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(name, data, perm)
}

// MkdirAll implements FileSystem.
func (OSFileSystem) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }

// MkdirTemp implements FileSystem.
func (OSFileSystem) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}

// Remove implements FileSystem.
func (OSFileSystem) Remove(name string) error { return os.Remove(name) }

// RemoveAll implements FileSystem.
func (OSFileSystem) RemoveAll(path string) error { return os.RemoveAll(path) }

// Rename implements FileSystem.
func (OSFileSystem) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

// Symlink implements FileSystem.
func (OSFileSystem) Symlink(oldname, newname string) error { return os.Symlink(oldname, newname) }

// Link implements FileSystem (hard links).
func (OSFileSystem) Link(oldname, newname string) error { return os.Link(oldname, newname) }

// Glob implements FileSystem.
func (OSFileSystem) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// Readlink implements FileSystem.
func (OSFileSystem) Readlink(name string) (string, error) { return os.Readlink(name) }

// ReadDir implements FileSystem.
func (OSFileSystem) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }

// Chmod implements FileSystem.
func (OSFileSystem) Chmod(name string, mode fs.FileMode) error { return os.Chmod(name, mode) }

// Chown implements FileSystem.
func (OSFileSystem) Chown(name string, uid, gid int) error { return os.Chown(name, uid, gid) }

type memNode struct {
	dir     bool
	mode    fs.FileMode
	modTime time.Time
	data    []byte
	link    string // non-empty marks a symlink whose value is link
	uid     int
	gid     int
}

func (n *memNode) fileInfo(name string) fs.FileInfo { return memInfo{name: name, node: n} }

type memInfo struct {
	name string
	node *memNode
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64 {
	if i.node.link != "" {
		return int64(len(i.node.link))
	}
	return int64(len(i.node.data))
}
func (i memInfo) Mode() fs.FileMode {
	if i.node.link != "" {
		return fs.ModeSymlink | 0o777
	}
	if i.node.dir {
		return i.node.mode | fs.ModeDir
	}
	return i.node.mode
}
func (i memInfo) ModTime() time.Time { return i.node.modTime }
func (i memInfo) IsDir() bool        { return i.node.dir }
func (i memInfo) Sys() any           { return nil }

type memDirEntry struct {
	info fs.FileInfo
}

func (e memDirEntry) Name() string               { return e.info.Name() }
func (e memDirEntry) IsDir() bool                { return e.info.IsDir() }
func (e memDirEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e memDirEntry) Info() (fs.FileInfo, error) { return e.info, nil }

// MemoryFS is an in-memory FileSystem for hermetic testing.
// All paths are treated as absolute; the root directory always exists.
type MemoryFS struct {
	mu    sync.Mutex
	nodes map[string]*memNode
	seq   int
}

// NewMemoryFS returns a MemoryFS containing the root directory and /tmp,
// mirroring a minimal POSIX layout.
func NewMemoryFS() *MemoryFS {
	fs := &MemoryFS{nodes: make(map[string]*memNode)}
	now := time.Unix(0, 0).UTC()
	fs.nodes["/"] = &memNode{dir: true, mode: 0o755, modTime: now}
	fs.nodes["/tmp"] = &memNode{dir: true, mode: 0o1777, modTime: now}
	return fs
}

func (m *MemoryFS) norm(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := filepath.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func (m *MemoryFS) now() time.Time {
	m.seq++
	return time.Unix(int64(m.seq), 0).UTC()
}

func pathError(op, path string, err error) error {
	return &fs.PathError{Op: op, Path: path, Err: err}
}

// getResolved returns the node at p following symlinks.
func (m *MemoryFS) getResolved(op, p string) (*memNode, error) {
	current := m.norm(p)
	for hop := 0; hop < 40; hop++ {
		node, ok := m.nodes[current]
		if !ok {
			return nil, pathError(op, p, fs.ErrNotExist)
		}
		if node.link == "" {
			return node, nil
		}
		target := node.link
		if !strings.HasPrefix(target, "/") {
			target = path.Join(path.Dir(current), target)
		}
		current = m.norm(target)
	}
	return nil, pathError(op, p, syscall.ELOOP)
}

// Stat implements FileSystem following symlinks.
func (m *MemoryFS) Stat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.getResolved("stat", name)
	if err != nil {
		return nil, err
	}
	return node.fileInfo(path.Base(m.norm(name))), nil
}

// Lstat implements FileSystem without following a final symlink.
func (m *MemoryFS) Lstat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, ok := m.nodes[m.norm(name)]
	if !ok {
		return nil, pathError("lstat", name, fs.ErrNotExist)
	}
	return node.fileInfo(path.Base(m.norm(name))), nil
}

// ReadFile implements FileSystem following symlinks.
func (m *MemoryFS) ReadFile(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.getResolved("open", name)
	if err != nil {
		return nil, err
	}
	if node.dir {
		return nil, pathError("read", name, syscall.EISDIR)
	}
	out := make([]byte, len(node.data))
	copy(out, node.data)
	return out, nil
}

// WriteFile implements FileSystem, requiring the parent directory to exist.
func (m *MemoryFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.norm(name)
	parent := path.Dir(p)
	parentNode, err := m.getResolved("open", parent)
	if err != nil {
		return pathError("open", name, fs.ErrNotExist)
	}
	if !parentNode.dir {
		return pathError("open", name, syscall.ENOTDIR)
	}
	existing, ok := m.nodes[p]
	if ok && existing.dir {
		return pathError("open", name, syscall.EISDIR)
	}
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	m.nodes[p] = &memNode{mode: perm.Perm(), data: dataCopy, modTime: m.now()}
	return nil
}

// MkdirAll implements FileSystem.
func (m *MemoryFS) MkdirAll(pathName string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.norm(pathName)
	node, err := m.getResolved("mkdir", p)
	if err == nil {
		if node.dir {
			return nil
		}
		return pathError("mkdir", pathName, syscall.ENOTDIR)
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	current := ""
	for _, part := range parts {
		current += "/" + part
		existing, ok := m.nodes[current]
		if ok {
			if !existing.dir {
				return pathError("mkdir", pathName, fs.ErrExist)
			}
			continue
		}
		m.nodes[current] = &memNode{dir: true, mode: perm.Perm(), modTime: m.now()}
	}
	return nil
}

// MkdirTemp implements FileSystem creating a unique directory under dir.
func (m *MemoryFS) MkdirTemp(dir, pattern string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	base := dir
	if base == "" {
		base = "/tmp"
	}
	base = m.norm(base)
	parentNode, err := m.getResolved("mkdirtemp", base)
	if err != nil {
		return "", err
	}
	if !parentNode.dir {
		return "", pathError("mkdirtemp", base, syscall.ENOTDIR)
	}
	prefix, suffix := pattern, ""
	if idx := strings.LastIndexByte(pattern, '*'); idx >= 0 {
		prefix, suffix = pattern[:idx], pattern[idx+1:]
	}
	for attempt := 0; attempt < 10000; attempt++ {
		m.seq++
		name := prefix + strconv.Itoa(m.seq) + suffix
		full := path.Join(base, name)
		if _, taken := m.nodes[full]; taken {
			continue
		}
		m.nodes[full] = &memNode{dir: true, mode: 0o700, modTime: m.now()}
		return full, nil
	}
	return "", pathError("mkdirtemp", base, fs.ErrExist)
}

// Remove implements FileSystem removing files, symlinks, and empty directories.
func (m *MemoryFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.norm(name)
	if p == "/" {
		return pathError("remove", name, syscall.EBUSY)
	}
	node, ok := m.nodes[p]
	if !ok {
		return pathError("remove", name, fs.ErrNotExist)
	}
	if node.dir {
		if child := m.firstChildLocked(p); child != "" {
			return pathError("remove", name, syscall.ENOTEMPTY)
		}
	}
	delete(m.nodes, p)
	return nil
}

func (m *MemoryFS) firstChildLocked(p string) string {
	prefix := strings.TrimSuffix(p, "/") + "/"
	for candidate := range m.nodes {
		if candidate != p && strings.HasPrefix(candidate, prefix) {
			return candidate
		}
	}
	return ""
}

// RemoveAll implements FileSystem removing a subtree.
func (m *MemoryFS) RemoveAll(pathName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.norm(pathName)
	if p == "/" {
		for key := range m.nodes {
			delete(m.nodes, key)
		}
		m.nodes["/"] = &memNode{dir: true, mode: 0o755, modTime: m.now()}
		return nil
	}
	if _, ok := m.nodes[p]; !ok {
		return nil
	}
	prefix := p + "/"
	for key := range m.nodes {
		if key == p || strings.HasPrefix(key, prefix) {
			delete(m.nodes, key)
		}
	}
	return nil
}

// Rename implements FileSystem following os.Rename edge cases.
func (m *MemoryFS) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	from, to := m.norm(oldpath), m.norm(newpath)
	node, ok := m.nodes[from]
	if !ok {
		return pathError("rename", oldpath, fs.ErrNotExist)
	}
	if to == "/" {
		return pathError("rename", newpath, syscall.EBUSY)
	}
	if target, exists := m.nodes[to]; exists {
		if target.dir && node.dir && m.firstChildLocked(to) != "" {
			return pathError("rename", newpath, syscall.ENOTEMPTY)
		}
		if target.dir && !node.dir {
			return pathError("rename", newpath, syscall.EISDIR)
		}
	}
	m.nodes[to] = node
	delete(m.nodes, from)
	if node.dir {
		prefix := from + "/"
		moved := map[string]*memNode{}
		for key, val := range m.nodes {
			if strings.HasPrefix(key, prefix) {
				moved[to+"/"+strings.TrimPrefix(key, prefix)] = val
				delete(m.nodes, key)
			}
		}
		for key, val := range moved {
			m.nodes[key] = val
		}
	}
	return nil
}

// Symlink implements FileSystem.
func (m *MemoryFS) Symlink(oldname, newname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	to := m.norm(newname)
	if _, exists := m.nodes[to]; exists {
		return pathError("symlink", newname, fs.ErrExist)
	}
	parentNode, err := m.getResolved("symlink", path.Dir(to))
	if err != nil {
		return pathError("symlink", newname, fs.ErrNotExist)
	}
	if !parentNode.dir {
		return pathError("symlink", newname, syscall.ENOTDIR)
	}
	m.nodes[to] = &memNode{link: oldname, modTime: m.now()}
	return nil
}

// Readlink implements FileSystem.
// Link implements hard links for the memory filesystem by sharing content:
// writes through either name diverge afterwards (documented limitation).
func (m *MemoryFS) Link(oldname, newname string) error {
	data, err := m.ReadFile(oldname)
	if err != nil {
		return err
	}
	info, serr := m.Stat(oldname)
	if serr != nil {
		return serr
	}
	return m.WriteFile(newname, data, info.Mode().Perm())
}

// Glob implements FileSystem over the in-memory tree.
func (m *MemoryFS) Glob(pattern string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for path := range m.nodes {
		ok, gerr := filepath.Match(filepath.Clean(pattern), path)
		if gerr == nil && ok {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *MemoryFS) Readlink(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, ok := m.nodes[m.norm(name)]
	if !ok {
		return "", pathError("readlink", name, fs.ErrNotExist)
	}
	if node.link == "" {
		return "", pathError("readlink", name, syscall.EINVAL)
	}
	return node.link, nil
}

// ReadDir implements FileSystem listing immediate children sorted by name.
func (m *MemoryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.getResolved("open", name)
	if err != nil {
		return nil, err
	}
	if !node.dir {
		return nil, pathError("readdirent", name, syscall.ENOTDIR)
	}
	prefix := strings.TrimSuffix(m.norm(name), "/") + "/"
	entries := []fs.DirEntry{}
	for key, val := range m.nodes {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if strings.Contains(rest, "/") {
			continue
		}
		entries = append(entries, memDirEntry{info: val.fileInfo(rest)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// Chmod implements FileSystem following symlinks.
func (m *MemoryFS) Chmod(name string, mode fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.getResolved("chmod", name)
	if err != nil {
		return err
	}
	node.mode = mode.Perm()
	node.modTime = m.now()
	return nil
}

// Chown implements FileSystem following symlinks.
func (m *MemoryFS) Chown(name string, uid, gid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.getResolved("chown", name)
	if err != nil {
		return err
	}
	node.uid, node.gid = uid, gid
	return nil
}
