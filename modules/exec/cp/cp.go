// Package cp implements Salt's cp module for local sources: the
// master-minion fileserver (salt://, list_master, push/recv) is
// permanently excluded, so only the file:// and bare-local-path arms are
// live; salt:// surfaces UnsupportedError like every other family, and
// remote schemes surface UnsupportedError until a fetcher lands.
//
// Reference: saltstack/salt/modules/cp.py @ pinned revision
// (references/salt.lock).
package cp

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/filesum"
	"github.com/friz-zy/statekit/internal/runtime"
)

var validProtoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file|s3|swift)://`)

func isSaltURL(path string) bool { return strings.HasPrefix(path, "salt://") }

func hasScheme(path string) bool { return validProtoRe.MatchString(path) }

func stripFileScheme(path string) string {
	return strings.TrimPrefix(path, "file://")
}

type CacheFileArgs struct {
	Path    string  `statekit:"required,name=path"`
	Saltenv *string `statekit:"name=saltenv"`
}

type CacheFileFunc struct{}

// CacheFile mirrors cache_file for local sources: readable local absolute
// paths return unchanged (no remote cache exists — documented divergence);
// salt:// stays permanently excluded.
func (CacheFileFunc) Name() string { return "cp.cache_file" }
func (CacheFileFunc) Args() any    { return CacheFileArgs{} }
func (CacheFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CacheFileArgs)
	if isSaltURL(a.Path) {
		return false, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}
	path := filepath.Clean(strings.TrimPrefix(a.Path, "file://"))
	if info, err := rt.FS.Stat(path); err != nil || info.IsDir() {
		return false, nil
	}
	return path, nil
}

type cacheLocalFileArgs struct {
	Path string `statekit:"required,name=path"`
}

type CacheLocalFileFunc struct{}

// CacheLocalFile mirrors cache_local_file: StateKit has no fileserver cache,
// so the readable local path returns as-is (documented divergence).
func (CacheLocalFileFunc) Name() string { return "cp.cache_local_file" }
func (CacheLocalFileFunc) Args() any    { return cacheLocalFileArgs{} }
func (CacheLocalFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*cacheLocalFileArgs)
	if _, err := rt.FS.Stat(a.Path); err != nil {
		return "", nil
	}
	return a.Path, nil
}

type IsCachedArgs struct {
	Path    string  `statekit:"required,name=path"`
	Saltenv *string `statekit:"name=saltenv"`
}

type IsCachedFunc struct{}

// IsCached mirrors is_cached: local paths are always cached; a salt:// URL
// yields "" upstream when the file cannot be fetched.
func (IsCachedFunc) Name() string { return "cp.is_cached" }
func (IsCachedFunc) Args() any    { return IsCachedArgs{} }
func (IsCachedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IsCachedArgs)
	if isSaltURL(a.Path) {
		return "", nil
	}
	path := filepath.Clean(strings.TrimPrefix(a.Path, "file://"))
	if _, err := rt.FS.Stat(path); err != nil {
		return "", nil
	}
	return path, nil
}

type GetFileArgs struct {
	Path     string  `statekit:"required,name=path"`
	Dest     *string `statekit:"name=dest"`
	Makedirs bool    `statekit:"name=makedirs"`
	Saltenv  *string `statekit:"name=saltenv"`
}

type GetFileFunc struct{}

// GetFile mirrors get_file for local sources: copies path into dest (or
// into dest's directory basename when dest ends with a separator). Remote
// and salt:// schemes surface UnsupportedError.
func (GetFileFunc) Name() string { return "cp.get_file" }
func (GetFileFunc) Args() any    { return GetFileArgs{} }
func (GetFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetFileArgs)
	if isSaltURL(a.Path) || (hasScheme(a.Path) && !strings.HasPrefix(a.Path, "file://")) {
		return false, &runtime.UnsupportedError{Kind: "function", Name: "cp.get_file"}
	}
	src := filepath.Clean(strings.TrimPrefix(a.Path, "file://"))
	data, rerr := rt.FS.ReadFile(src)
	if rerr != nil {
		return "", nil
	}
	dest := strOrPtr(a.Dest)
	if dest == "" {
		return string(data), nil
	}
	target := dest
	if strings.HasSuffix(dest, "/") {
		target = filepath.Clean(filepath.Join(dest, filepath.Base(src)))
	} else if info, derr := rt.FS.Stat(dest); derr == nil && info.IsDir() {
		target = filepath.Join(dest, filepath.Base(src))
	}
	if a.Makedirs {
		rt.FS.MkdirAll(filepath.Dir(target), 0o755)
	}
	if werr := rt.FS.WriteFile(target, data, 0o644); werr != nil {
		return "", nil
	}
	return target, nil
}

type GetURLArgs struct {
	Path       string  `statekit:"required,name=path"`
	Dest       *string `statekit:"name=dest"`
	Makedirs   bool    `statekit:"name=makedirs"`
	Saltenv    *string `statekit:"name=saltenv"`
	SourceHash *string `statekit:"name=source_hash"`
}

type GetURLFunc struct{}

// GetURL mirrors get_url: file:// and bare local paths resolve on the
// filesystem; an empty dest returns the contents instead of caching;
// remote schemes surface UnsupportedError.
func (GetURLFunc) Name() string { return "cp.get_url" }
func (GetURLFunc) Args() any    { return GetURLArgs{} }
func (GetURLFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetURLArgs)
	if isSaltURL(a.Path) || (hasScheme(a.Path) && !strings.HasPrefix(a.Path, "file://")) {
		return false, &runtime.UnsupportedError{Kind: "function", Name: "cp.get_url"}
	}
	src := filepath.Clean(strings.TrimPrefix(a.Path, "file://"))
	data, rerr := rt.FS.ReadFile(src)
	if rerr != nil {
		return false, nil
	}
	dest := ""
	if a.Dest != nil {
		dest = *a.Dest
	}
	if dest == "" {
		return string(data), nil
	}
	target := dest
	if strings.HasSuffix(dest, "/") {
		target = filepath.Clean(filepath.Join(dest, filepath.Base(src)))
	} else if info, derr := rt.FS.Stat(dest); derr == nil && info.IsDir() {
		target = filepath.Join(dest, filepath.Base(src))
	}
	if a.Makedirs {
		rt.FS.MkdirAll(filepath.Dir(target), 0o755)
	}
	if werr := rt.FS.WriteFile(target, data, 0o644); werr != nil {
		return false, nil
	}
	return target, nil
}

type GetFileStrArgs struct {
	Path    string  `statekit:"required,name=path"`
	Saltenv *string `statekit:"name=saltenv"`
}

type GetFileStrFunc struct{}

func (GetFileStrFunc) Name() string { return "cp.get_file_str" }
func (GetFileStrFunc) Args() any    { return GetFileStrArgs{} }
func (GetFileStrFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetFileStrArgs)
	res, err := GetFileFunc{}.Execute(ctx, rt, &GetFileArgs{
		Path: a.Path, Dest: nil, Saltenv: a.Saltenv,
	})
	if err != nil {
		return false, err
	}
	return res, nil
}

type StatFileArgs struct {
	Path    string  `statekit:"required,name=path"`
	Saltenv *string `statekit:"name=saltenv"`
	Octal   *bool   `statekit:"name=octal"`
}

type StatFileFunc struct{}

// StatFile mirrors cp.stat_file for local sources: an absolute (or file://)
// path returns its mode as a zero-padded octal string by default, or the
// integer permission bits with octal=False. salt:// requires the excluded
// master fileserver and surfaces UnsupportedError like list_master.
func (StatFileFunc) Name() string { return "cp.stat_file" }
func (StatFileFunc) Args() any    { return StatFileArgs{} }
func (StatFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*StatFileArgs)
	if isSaltURL(a.Path) {
		return nil, masterUnsupported("cp.stat_file")
	}
	path := filepath.Clean(strings.TrimPrefix(a.Path, "file://"))
	info, err := rt.FS.Stat(path)
	if err != nil {
		return nil, nil
	}
	octal := true
	if a.Octal != nil {
		octal = *a.Octal
	}
	if octal {
		return fmt.Sprintf("%04o", info.Mode().Perm()), nil
	}
	return int(info.Mode().Perm()), nil
}

type HashFileArgs struct {
	Path    string  `statekit:"required,name=path"`
	Form    *string `statekit:"name=form"`
	Saltenv *string `statekit:"name=saltenv"`
}

type HashFileFunc struct{}

func (HashFileFunc) Name() string { return "cp.hash_file" }
func (HashFileFunc) Args() any    { return HashFileArgs{} }
func (HashFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*HashFileArgs)
	form := "sha256"
	if a.Form != nil && *a.Form != "" {
		form = *a.Form
	}
	h, herr := filesum.New(form)
	if herr != nil {
		return "", herr
	}
	data, rerr := rt.FS.ReadFile(a.Path)
	if rerr != nil {
		return "", nil
	}
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// --- master-dependent surface ---------------------------------------------------

type unsupportedMaster struct{ fn string }

func (e *unsupportedMaster) Error() string {
	return fmt.Sprintf("%s requires a Salt master fileserver (master-minion architecture excluded)", e.fn)
}

func (e *unsupportedMaster) UnsupportedKind() string { return "master-minion" }

func masterUnsupported(fn string) error { return &unsupportedMaster{fn: fn} }

type emptyArgs struct{}

type ListMasterFunc struct{}

func (ListMasterFunc) Name() string { return "cp.list_master" }
func (ListMasterFunc) Args() any    { return emptyArgs{} }
func (ListMasterFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, masterUnsupported("cp.list_master")
}

type ListMasterDirsFunc struct{}

func (ListMasterDirsFunc) Name() string { return "cp.list_master_dirs" }
func (ListMasterDirsFunc) Args() any    { return emptyArgs{} }
func (ListMasterDirsFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, masterUnsupported("cp.list_master_dirs")
}

type ListMasterSymlinksFunc struct{}

func (ListMasterSymlinksFunc) Name() string { return "cp.list_master_symlinks" }
func (ListMasterSymlinksFunc) Args() any    { return emptyArgs{} }
func (ListMasterSymlinksFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, masterUnsupported("cp.list_master_symlinks")
}

type ListStatesFunc struct{}

func (ListStatesFunc) Name() string { return "cp.list_states" }
func (ListStatesFunc) Args() any    { return emptyArgs{} }
func (ListStatesFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, masterUnsupported("cp.list_states")
}

type pushFunc struct{}

func (pushFunc) Name() string { return "cp.push" }
func (pushFunc) Args() any    { return emptyArgs{} }
func (pushFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return false, masterUnsupported("cp.push")
}

type pushDirFunc struct{}

func (pushDirFunc) Name() string { return "cp.push_dir" }
func (pushDirFunc) Args() any    { return emptyArgs{} }
func (pushDirFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return false, masterUnsupported("cp.push_dir")
}

type recvFunc struct{}

func (recvFunc) Name() string { return "cp.recv" }
func (recvFunc) Args() any    { return emptyArgs{} }
func (recvFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return nil, masterUnsupported("cp.recv")
}

// Register installs all cp-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		CacheFileFunc{},
		CacheLocalFileFunc{},
		IsCachedFunc{},
		GetFileFunc{},
		GetURLFunc{},
		GetFileStrFunc{},
		HashFileFunc{},
		StatFileFunc{},
		ListMasterFunc{},
		ListMasterDirsFunc{},
		ListMasterSymlinksFunc{},
		ListStatesFunc{},
		pushFunc{},
		pushDirFunc{},
		recvFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

func strOrPtr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
