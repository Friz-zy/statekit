// Package file implements Salt-compatible filesystem execution functions.
//
// Reference: saltstack/salt/modules/file.py @ pinned revision. All operations
// flow through the runtime FileSystem abstraction so behavior is testable.
package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// expandUser mirrors Salt's os.path.expanduser handling.
func expandUser(path string) string {
	if path == "~" {
		if home, err := userHome(); err == nil {
			return home
		}
		return path
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		if home, err := userHome(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return path
}

var userHome = func() (string, error) {
	if u, err := user.Current(); err == nil {
		return u.HomeDir, nil
	}
	return "", fmt.Errorf("cannot resolve home directory")
}

type fileExistsArgs struct {
	Path string `statekit:"required"`
}

type fileExistsFunc struct{}

func (fileExistsFunc) Name() string { return "file.file_exists" }
func (fileExistsFunc) Args() any    { return fileExistsArgs{} }
func (fileExistsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*fileExistsArgs)
	info, err := rt.FS.Stat(expandUser(a.Path))
	if err != nil || info.IsDir() {
		return false, nil
	}
	return true, nil
}

type directoryExistsArgs struct {
	Path string `statekit:"required"`
}

type directoryExistsFunc struct{}

func (directoryExistsFunc) Name() string { return "file.directory_exists" }
func (directoryExistsFunc) Args() any    { return directoryExistsArgs{} }
func (directoryExistsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*directoryExistsArgs)
	info, err := rt.FS.Stat(expandUser(a.Path))
	if err != nil || !info.IsDir() {
		return false, nil
	}
	return true, nil
}

type removeArgs struct {
	Path string `statekit:"required"`
}

type removeFunc struct{}

func (removeFunc) Name() string { return "file.remove" }
func (removeFunc) Args() any    { return removeArgs{} }
func (removeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*removeArgs)
	path := expandUser(a.Path)
	if !filepath.IsAbs(path) {
		// Salt raises SaltInvocationError for relative paths.
		return nil, fmt.Errorf("file path must be absolute: %s", path)
	}
	if _, err := rt.FS.Lstat(path); err != nil {
		return false, nil
	}
	if err := rt.FS.RemoveAll(path); err != nil {
		return nil, fmt.Errorf("could not remove '%s': %w", path, err)
	}
	return true, nil
}

type renameArgs struct {
	Src string `statekit:"required"`
	Dst string `statekit:"required"`
}

type renameFunc struct{}

func (renameFunc) Name() string { return "file.rename" }
func (renameFunc) Args() any    { return renameArgs{} }
func (renameFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*renameArgs)
	src, dst := expandUser(a.Src), expandUser(a.Dst)
	if _, err := rt.FS.Lstat(src); err != nil {
		return false, nil
	}
	if err := rt.FS.Rename(src, dst); err != nil {
		return nil, fmt.Errorf("could not rename '%s' to '%s': %w", src, dst, err)
	}
	return true, nil
}

type copyArgs struct {
	Src            string `statekit:"required"`
	Dst            string `statekit:"required"`
	Recurse        bool   `statekit:"name=recurse"`
	RemoveExisting bool   `statekit:"name=remove_existing"`
}

type copyFunc struct{}

func (copyFunc) Name() string { return "file.copy" }
func (copyFunc) Args() any    { return copyArgs{} }
func (copyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*copyArgs)
	src, dst := expandUser(a.Src), expandUser(a.Dst)
	info, err := rt.FS.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("could not stat '%s': %w", src, err)
	}
	if a.RemoveExisting {
		rt.FS.RemoveAll(dst)
	}
	if info.IsDir() && a.Recurse {
		if err := copyTree(rt, src, dst); err != nil {
			return nil, err
		}
		return true, nil
	}
	if info.IsDir() {
		return nil, fmt.Errorf("'%s' is a directory; use recurse=true to copy directories", src)
	}
	data, err := rt.FS.ReadFile(src)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(dst); dir != "" && dir != "." {
		if err := rt.FS.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if err := rt.FS.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return nil, err
	}
	return true, nil
}

func copyTree(rt *runtime.Runtime, src, dst string) error {
	entries, err := rt.FS.ReadDir(src)
	if err != nil {
		return err
	}
	if err := rt.FS.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		s := filepath.Join(src, entry.Name())
		d := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyTree(rt, s, d); err != nil {
				return err
			}
			continue
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			target, err := rt.FS.Readlink(s)
			if err != nil {
				return err
			}
			rt.FS.Remove(d)
			if err := rt.FS.Symlink(target, d); err != nil {
				return err
			}
			continue
		}
		data, err := rt.FS.ReadFile(s)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if info, err := rt.FS.Stat(s); err == nil {
			mode = info.Mode().Perm()
		}
		if err := rt.FS.WriteFile(d, data, mode); err != nil {
			return err
		}
	}
	return nil
}

type readArgs struct {
	Path   string `statekit:"required"`
	Binary bool   `statekit:"name=binary"`
}

type readFunc struct{}

func (readFunc) Name() string { return "file.read" }
func (readFunc) Args() any    { return readArgs{} }
func (readFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*readArgs)
	data, err := rt.FS.ReadFile(expandUser(a.Path))
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

type writeArgs struct {
	Path    string `statekit:"required"`
	Content string `statekit:"name=contents"`
	Append  bool   `statekit:"name=append"`
	Mode    string `statekit:"name=mode"`
}

type writeFunc struct{}

func (writeFunc) Name() string { return "file.write" }
func (writeFunc) Args() any    { return writeArgs{} }
func (writeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*writeArgs)
	path := expandUser(a.Path)
	var data []byte
	if a.Append {
		existing, err := rt.FS.ReadFile(path)
		if err != nil && !errorsIsNotExist(err) {
			return nil, err
		}
		data = append(existing, []byte(a.Content)...)
	} else {
		data = []byte(a.Content)
	}
	perm := fs.FileMode(0o644)
	if a.Mode != "" {
		parsed, err := parseOctal(a.Mode)
		if err != nil {
			return nil, err
		}
		perm = parsed
	}
	if err := rt.FS.WriteFile(path, data, perm); err != nil {
		return nil, err
	}
	return true, nil
}

type containsArgs struct {
	Path string `statekit:"required"`
	Text string `statekit:"required,name=text"`
}

type containsFunc struct{}

func (containsFunc) Name() string { return "file.contains" }
func (containsFunc) Args() any    { return containsArgs{} }
func (containsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*containsArgs)
	data, err := rt.FS.ReadFile(expandUser(a.Path))
	if err != nil {
		if errorsIsNotExist(err) {
			return false, nil
		}
		return nil, err
	}
	return strings.Contains(string(data), a.Text), nil
}

type appendArgs struct {
	Path  string   `statekit:"required"`
	Lines []string `statekit:"name=args"`
}

type appendFunc struct{}

func (appendFunc) Name() string { return "file.append" }
func (appendFunc) Args() any    { return appendArgs{} }
func (appendFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*appendArgs)
	path := expandUser(a.Path)
	existing, err := rt.FS.ReadFile(path)
	if err != nil && !errorsIsNotExist(err) {
		return nil, err
	}
	out := existing
	for _, line := range a.Lines {
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, []byte(line)...)
		out = append(out, '\n')
	}
	if err := rt.FS.WriteFile(path, out, 0o644); err != nil {
		return nil, err
	}
	return true, nil
}

type mkdirArgs struct {
	DirPath string `statekit:"required,name=dir_path"`
	User    string `statekit:"name=user"`
	Group   string `statekit:"name=group"`
	Mode    string `statekit:"name=mode"`
}

type mkdirFunc struct{}

func (mkdirFunc) Name() string { return "file.mkdir" }
func (mkdirFunc) Args() any    { return mkdirArgs{} }
func (mkdirFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*mkdirArgs)
	if a.User != "" || a.Group != "" {
		// Intentional divergence (plan section 39): ownership changes are
		// handled through dedicated user/group tooling, not file.mkdir.
		return nil, fmt.Errorf("user/group options are not supported by statekit file.mkdir")
	}
	mode := fs.FileMode(0o755)
	if a.Mode != "" {
		parsed, err := parseOctal(a.Mode)
		if err != nil {
			return nil, err
		}
		mode = parsed
	}
	path := expandUser(a.DirPath)
	info, err := rt.FS.Stat(path)
	switch {
	case err == nil && info.IsDir():
		return true, nil
	case err == nil:
		return nil, fmt.Errorf("'%s' exists and is not a directory", path)
	}
	if err := rt.FS.MkdirAll(path, mode); err != nil {
		return nil, err
	}
	return true, nil
}

type touchNameArgs struct {
	Name string `statekit:"required"`
}

type touchFunc struct{}

func (touchFunc) Name() string { return "file.touch" }
func (touchFunc) Args() any    { return touchNameArgs{} }
func (touchFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*touchNameArgs)
	path := expandUser(a.Name)
	if _, err := rt.FS.Lstat(path); err == nil {
		return true, nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		rt.FS.MkdirAll(dir, 0o755)
	}
	if err := rt.FS.WriteFile(path, nil, 0o644); err != nil {
		return nil, err
	}
	return true, nil
}

type statsArgs struct {
	Path           string `statekit:"required"`
	FollowSymlinks bool   `statekit:"name=follow_symlinks"`
}

type statsFunc struct{}

func (statsFunc) Name() string { return "file.stats" }
func (statsFunc) Args() any    { return statsArgs{} }
func (statsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statsArgs)
	path := expandUser(a.Path)
	var info fs.FileInfo
	var err error
	if a.FollowSymlinks {
		info, err = rt.FS.Stat(path)
	} else {
		info, err = rt.FS.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	return statMap(info), nil
}

func statMap(info fs.FileInfo) map[string]any {
	mode := info.Mode()
	size := int64(0)
	if mode.IsRegular() || mode&fs.ModeSymlink != 0 {
		size = info.Size()
	}
	return map[string]any{
		"size":       size,
		"mode":       fmt.Sprintf("%04o", mode.Perm()),
		"type":       fileType(mode),
		"atime":      info.ModTime().Unix(),
		"mtime":      info.ModTime().Unix(),
		"ctime":      info.ModTime().Unix(),
		"uid":        uidOf(info),
		"gid":        gidOf(info),
		"inode":      0,
		"dev":        0,
		"nlink":      1,
		"isdir":      info.IsDir(),
		"issym":      mode&fs.ModeSymlink != 0,
		"executable": mode.Perm()&0o111 != 0,
	}
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSymlink != 0:
		return "link"
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeNamedPipe != 0:
		return "fifo"
	case mode&fs.ModeSocket != 0:
		return "socket"
	default:
		return "file"
	}
}

type readlinkArgs struct {
	Path         string `statekit:"required"`
	Canonicalize bool   `statekit:"name=canonicalize"`
}

type readlinkFunc struct{}

func (readlinkFunc) Name() string { return "file.readlink" }
func (readlinkFunc) Args() any    { return readlinkArgs{} }
func (readlinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*readlinkArgs)
	target, err := rt.FS.Readlink(expandUser(a.Path))
	if err != nil {
		return nil, err
	}
	if a.Canonicalize {
		resolved := target
		for depth := 0; depth < 40; depth++ {
			next, err := rt.FS.Readlink(resolved)
			if err != nil {
				break
			}
			resolved = next
		}
		target = resolved
	}
	return target, nil
}

// parseOctal parses "0755"-style mode strings.
func parseOctal(mode string) (fs.FileMode, error) {
	parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(mode), "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode %q", mode)
	}
	return fs.FileMode(parsed).Perm(), nil
}

func errorsIsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// Register installs all file-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "windows" {
		return registerWindowsFile(reg)
	}
	for _, fn := range []runtime.ExecFunction{
		fileExistsFunc{}, directoryExistsFunc{}, removeFunc{}, renameFunc{}, copyFunc{},
		readFunc{}, writeFunc{}, containsFunc{}, appendFunc{}, mkdirFunc{},
		touchFunc{}, statsFunc{}, readlinkFunc{},
		searchFunc{}, containsRegexFunc{}, replaceFunc{}, chownFunc{}, chgrpFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
