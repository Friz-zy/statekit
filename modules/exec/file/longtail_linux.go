//go:build linux

package file

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

func registerLongtail(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		findFunc{}, psedFunc{}, lineFunc{}, statvfsFunc{},
		listBackupsFunc{}, listBackupsDirFunc{}, restoreBackupFunc{}, deleteBackupFunc{},
		grepFunc{}, openFilesFunc{}, moveFunc{}, diskusageFunc{}, containsGlobFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// find/grep/contains_glob

type findArgs struct {
	Path   string         `statekit:"required"`
	Args   []any          `statekit:"name=args"`
	Kwargs map[string]any `statekit:"name=kwargs"`
}
type findFunc struct{}

func (findFunc) Name() string        { return "file.find" }
func (findFunc) Args() any           { return findArgs{} }
func (findFunc) Platforms() []string { return []string{"linux"} }
func (findFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*findArgs)
	kwargs := a.Kwargs
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	for _, value := range a.Args {
		if text, ok := value.(string); ok {
			if text == "delete" {
				kwargs["delete"] = "f"
			} else if text == "print" {
				kwargs["print"] = "path"
			}
		}
	}
	roots := []string{expandUser(a.Path)}
	if matches, err := rt.FS.Glob(expandUser(a.Path)); err == nil && len(matches) > 0 {
		roots = matches
	}
	maxDepth := intOptionFile(kwargs, "maxdepth", -1)
	minDepth := intOptionFile(kwargs, "mindepth", 0)
	var found []string
	for _, root := range roots {
		findWalk(rt, root, 0, maxDepth, minDepth, kwargs, &found)
	}
	sort.Strings(found)
	if deleteValue, ok := kwargs["delete"]; ok && deleteValue != false {
		for _, name := range found {
			_ = rt.FS.RemoveAll(name)
		}
	}
	return found, nil
}

func findWalk(rt *runtime.Runtime, name string, depth, maxDepth, minDepth int, options map[string]any, found *[]string) {
	info, err := rt.FS.Lstat(name)
	if err != nil {
		return
	}
	if depth >= minDepth && findMatches(name, info, rt, options) {
		*found = append(*found, name)
	}
	if !info.IsDir() || (maxDepth >= 0 && depth >= maxDepth) || info.Mode()&fs.ModeSymlink != 0 {
		return
	}
	entries, err := rt.FS.ReadDir(name)
	if err != nil {
		return
	}
	for _, entry := range entries {
		findWalk(rt, filepath.Join(name, entry.Name()), depth+1, maxDepth, minDepth, options, found)
	}
}

func findMatches(name string, info fs.FileInfo, rt *runtime.Runtime, options map[string]any) bool {
	if pattern, ok := options["name"].(string); ok {
		matched, _ := filepath.Match(pattern, filepath.Base(name))
		if !matched {
			return false
		}
	}
	if pattern, ok := options["iname"].(string); ok {
		matched, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(filepath.Base(name)))
		if !matched {
			return false
		}
	}
	for _, key := range []string{"regex", "iregex"} {
		if pattern, ok := options[key].(string); ok {
			if key == "iregex" {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil || !re.MatchString(name) {
				return false
			}
		}
	}
	if types, ok := options["type"].(string); ok && types != "a" {
		kind := "f"
		if info.IsDir() {
			kind = "d"
		} else if info.Mode()&fs.ModeSymlink != 0 {
			kind = "l"
		}
		if !strings.Contains(types, kind) {
			return false
		}
	}
	if size, ok := options["size"].(string); ok && !matchFileSize(info.Size(), size) {
		return false
	}
	if pattern, ok := options["grep"].(string); ok && !info.IsDir() {
		data, err := rt.FS.ReadFile(name)
		if err != nil {
			return false
		}
		matched, err := regexp.MatchString(pattern, string(data))
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func matchFileSize(size int64, expression string) bool {
	if expression == "" {
		return true
	}
	operator := byte(0)
	if expression[0] == '+' || expression[0] == '-' {
		operator = expression[0]
		expression = expression[1:]
	}
	multiplier := int64(1)
	if len(expression) > 0 {
		switch expression[len(expression)-1] {
		case 'k', 'K':
			multiplier, expression = 1024, expression[:len(expression)-1]
		case 'm', 'M':
			multiplier, expression = 1024*1024, expression[:len(expression)-1]
		case 'g', 'G':
			multiplier, expression = 1024*1024*1024, expression[:len(expression)-1]
		case 't', 'T':
			multiplier, expression = 1024*1024*1024*1024, expression[:len(expression)-1]
		}
	}
	wanted, err := strconv.ParseInt(expression, 10, 64)
	if err != nil {
		return false
	}
	wanted *= multiplier
	switch operator {
	case '+':
		return size > wanted
	case '-':
		return size < wanted
	default:
		return size == wanted
	}
}

type grepArgs struct {
	Path    string `statekit:"required"`
	Pattern string `statekit:"required"`
	Opts    []any  `statekit:"name=opts"`
}
type grepFunc struct{}

func (grepFunc) Name() string        { return "file.grep" }
func (grepFunc) Args() any           { return grepArgs{} }
func (grepFunc) Platforms() []string { return []string{"linux"} }
func (grepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*grepArgs)
	paths := []string{expandUser(a.Path)}
	if matches, err := rt.FS.Glob(expandUser(a.Path)); err == nil && len(matches) > 0 {
		paths = matches
	}
	argv := []string{"grep"}
	for _, value := range a.Opts {
		argv = append(argv, fmt.Sprint(value))
	}
	argv = append(argv, a.Pattern)
	argv = append(argv, paths...)
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	return map[string]any{"stdout": string(result.Stdout), "stderr": string(result.Stderr), "retcode": result.ExitCode, "cmd": argv}, result.Err
}

type containsGlobArgs struct {
	Path     string `statekit:"required"`
	GlobExpr string `statekit:"required,name=glob_expr"`
}
type containsGlobFunc struct{}

func (containsGlobFunc) Name() string        { return "file.contains_glob" }
func (containsGlobFunc) Args() any           { return containsGlobArgs{} }
func (containsGlobFunc) Platforms() []string { return []string{"linux"} }
func (containsGlobFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*containsGlobArgs)
	data, e := rt.FS.ReadFile(expandUser(a.Path))
	if e != nil {
		return false, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		matched, _ := filepath.Match(a.GlobExpr, line)
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// line/psed/template

type lineArgs struct {
	Path        string  `statekit:"required"`
	Content     *string `statekit:"name=content"`
	Match       *string `statekit:"name=match"`
	Mode        *string `statekit:"name=mode"`
	Location    *string `statekit:"name=location"`
	Before      *string `statekit:"name=before"`
	After       *string `statekit:"name=after"`
	ShowChanges *bool   `statekit:"name=show_changes"`
	Backup      *bool   `statekit:"name=backup"`
	Quiet       *bool   `statekit:"name=quiet"`
	Indent      *bool   `statekit:"name=indent"`
}
type lineFunc struct{}

func (lineFunc) Name() string        { return "file.line" }
func (lineFunc) Args() any           { return lineArgs{} }
func (lineFunc) Platforms() []string { return []string{"linux"} }
func (lineFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	a := args.(*lineArgs)
	path := expandUser(a.Path)
	data, e := rt.FS.ReadFile(path)
	if e != nil {
		if a.Quiet != nil && *a.Quiet {
			return false, nil
		}
		return nil, e
	}
	content := ""
	if a.Content != nil {
		content = *a.Content
	}
	mode := ""
	if a.Mode != nil {
		mode = *a.Mode
	}
	lines := splitFileLines(string(data))
	old := append([]string(nil), lines...)
	match := content
	if a.Match != nil {
		match = *a.Match
	}
	indices := matchingLines(lines, match)
	changed := false
	switch mode {
	case "delete":
		for i := len(indices) - 1; i >= 0; i-- {
			lines = append(lines[:indices[i]], lines[indices[i]+1:]...)
			changed = true
		}
	case "replace":
		if len(indices) > 0 {
			lines[indices[0]] = content + lineEnding(lines[indices[0]])
			changed = stringLines(old) != stringLines(lines)
		}
	case "ensure", "insert":
		if len(indices) == 0 {
			at := len(lines)
			if mode == "insert" && a.Location != nil && *a.Location == "start" {
				at = 0
			}
			if mode == "ensure" && a.Before != nil {
				at = firstLineMatching(lines, *a.Before)
			} else if mode == "ensure" && a.After != nil {
				at = lastLineMatching(lines, *a.After) + 1
			}
			if at < 0 {
				at = len(lines)
			}
			lines = append(lines, "")
			copy(lines[at+1:], lines[at:])
			lines[at] = content + "\n"
			changed = true
		}
	}
	if !changed {
		if a.ShowChanges == nil || *a.ShowChanges {
			return "", nil
		}
		return false, nil
	}
	if a.Backup != nil && *a.Backup {
		if e := rt.FS.WriteFile(path+".bak", data, 0o644); e != nil {
			return nil, e
		}
	}
	if e := rt.FS.WriteFile(path, []byte(stringLines(lines)), 0o644); e != nil {
		return nil, e
	}
	if a.ShowChanges != nil && !(*a.ShowChanges) {
		return true, nil
	}
	return fmt.Sprintf("--- %s\n+++ %s\n", path, path), nil
}
func splitFileLines(value string) []string {
	if value == "" {
		return []string{}
	}
	return strings.SplitAfter(value, "\n")
}
func stringLines(lines []string) string { return strings.Join(lines, "") }
func lineEnding(line string) string {
	if strings.HasSuffix(line, "\n") {
		return "\n"
	}
	return ""
}
func matchingLines(lines []string, pattern string) []int {
	out := []int{}
	for i, line := range lines {
		trim := strings.TrimSuffix(line, "\n")
		if pattern == "" || trim == pattern {
			out = append(out, i)
			continue
		}
		if re, e := regexp.Compile(pattern); e == nil && re.MatchString(trim) {
			out = append(out, i)
		}
	}
	return out
}
func firstLineMatching(lines []string, pattern string) int {
	for i, line := range lines {
		if strings.Contains(line, pattern) {
			return i
		}
	}
	return -1
}
func lastLineMatching(lines []string, pattern string) int {
	last := -1
	for i, line := range lines {
		if strings.Contains(line, pattern) {
			last = i
		}
	}
	return last
}

type psedArgs struct {
	Path      string  `statekit:"required"`
	Before    string  `statekit:"required"`
	After     string  `statekit:"required"`
	Limit     string  `statekit:"name=limit"`
	Backup    *string `statekit:"name=backup"`
	Flags     *string `statekit:"name=flags"`
	EscapeAll bool    `statekit:"name=escape_all"`
	Multi     bool    `statekit:"name=multi"`
}
type psedFunc struct{}

func (psedFunc) Name() string        { return "file.psed" }
func (psedFunc) Args() any           { return psedArgs{} }
func (psedFunc) Platforms() []string { return []string{"linux"} }
func (psedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*psedArgs)
	path := expandUser(a.Path)
	data, e := rt.FS.ReadFile(path)
	if e != nil {
		return false, nil
	}
	if a.Backup == nil || *a.Backup != "" {
		backup := ".bak"
		if a.Backup != nil {
			backup = *a.Backup
		}
		if e := rt.FS.WriteFile(path+backup, data, 0o644); e != nil {
			return nil, e
		}
	}
	pattern := a.Before
	if a.Flags != nil && strings.Contains(strings.ToLower(*a.Flags), "i") {
		pattern = "(?i)" + pattern
	}
	re, e := regexp.Compile(pattern)
	if e != nil {
		return nil, e
	}
	text := string(data)
	if a.Multi {
		count := -1
		if a.Flags != nil && !strings.Contains(*a.Flags, "g") {
			count = 1
		}
		text = re.ReplaceAllStringFunc(text, func(s string) string { return re.ReplaceAllString(s, a.After) })
		_ = count
	} else {
		lines := strings.SplitAfter(text, "\n")
		for i, line := range lines {
			if a.Limit != "" {
				ok, _ := regexp.MatchString(a.Limit, line)
				if !ok {
					continue
				}
			}
			lines[i] = re.ReplaceAllString(line, a.After)
		}
		text = strings.Join(lines, "")
	}
	if e := rt.FS.WriteFile(path, []byte(text), 0o644); e != nil {
		return nil, e
	}
	return true, nil
}

func applyTemplateOnContents(contents, template string) (any, error) {
	if template == "" || template == "None" {
		return contents, nil
	}
	return nil, fmt.Errorf("template engine %q is unsupported by the local runtime", template)
}

// ---------------------------------------------------------------------------
// backups

type backupListArgs struct {
	Path  string `statekit:"required"`
	Limit *int   `statekit:"name=limit"`
}
type listBackupsFunc struct{}

func (listBackupsFunc) Name() string        { return "file.list_backups" }
func (listBackupsFunc) Args() any           { return backupListArgs{} }
func (listBackupsFunc) Platforms() []string { return []string{"linux"} }
func (listBackupsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*backupListArgs)
	return listBackupsFor(rt, expandUser(a.Path), a.Limit, false)
}

type listBackupsDirFunc struct{}

func (listBackupsDirFunc) Name() string        { return "file.list_backups_dir" }
func (listBackupsDirFunc) Args() any           { return backupListArgs{} }
func (listBackupsDirFunc) Platforms() []string { return []string{"linux"} }
func (listBackupsDirFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*backupListArgs)
	return listBackupsFor(rt, expandUser(a.Path), a.Limit, true)
}
func backupRoot(rt *runtime.Runtime) string { return filepath.Join(cachedirOf(rt), "file_backup") }
func backupStamp(base string, name string) (time.Time, bool) {
	prefix := base + "_"
	if !strings.HasPrefix(name, prefix) {
		return time.Time{}, false
	}
	stamp := strings.TrimPrefix(name, prefix)
	for _, layout := range []string{"Mon_Jan_02_15:04:05_000000_2006", "Mon_Jan_02_15:04:05_2006"} {
		if value, e := time.Parse(layout, stamp); e == nil {
			return value, true
		}
	}
	return time.Time{}, false
}
func listBackupsFor(rt *runtime.Runtime, path string, limit *int, dir bool) (map[int]map[string]any, error) {
	parent, base := filepath.Split(path)
	parent = strings.TrimPrefix(parent, string(filepath.Separator))
	root := filepath.Join(backupRoot(rt), parent)
	entries, e := rt.FS.ReadDir(root)
	if e != nil {
		return map[int]map[string]any{}, nil
	}
	type item struct {
		when     time.Time
		location string
		size     int64
	}
	items := []item{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		candidate := entry.Name()
		if dir {
			candidateBase := strings.SplitN(candidate, "_", 2)[0]
			if candidateBase == "" {
				continue
			}
			base = candidateBase
		}
		when, ok := backupStamp(base, candidate)
		if !ok {
			continue
		}
		info, e := rt.FS.Stat(filepath.Join(root, candidate))
		if e != nil {
			continue
		}
		items = append(items, item{when, filepath.Join(root, candidate), info.Size()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].when.After(items[j].when) })
	max := len(items)
	if limit != nil && *limit >= 0 && *limit < max {
		max = *limit
	}
	out := map[int]map[string]any{}
	for i := 0; i < max; i++ {
		out[i] = map[string]any{"Backup Time": items[i].when.Format("Mon Jan 02 2006 15:04:05.000000"), "Size": items[i].size, "Location": items[i].location}
	}
	return out, nil
}

type backupIDArgs struct {
	Path     string `statekit:"required"`
	BackupID any    `statekit:"required,name=backup_id"`
}
type restoreBackupFunc struct{}

func (restoreBackupFunc) Name() string        { return "file.restore_backup" }
func (restoreBackupFunc) Args() any           { return backupIDArgs{} }
func (restoreBackupFunc) Platforms() []string { return []string{"linux"} }
func (restoreBackupFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*backupIDArgs)
	id, e := backupIndex(a.BackupID)
	if e != nil {
		return map[string]any{"result": false, "comment": fmt.Sprintf("Invalid backup_id '%v'", a.BackupID)}, nil
	}
	backups, _ := listBackupsFor(rt, expandUser(a.Path), nil, false)
	backup, ok := backups[id]
	if !ok {
		return map[string]any{"result": false, "comment": fmt.Sprintf("backup_id '%v' does not exist for %s", a.BackupID, a.Path)}, nil
	}
	data, e := rt.FS.ReadFile(backup["Location"].(string))
	if e != nil {
		return map[string]any{"result": false, "comment": e.Error()}, nil
	}
	if e = rt.FS.WriteFile(expandUser(a.Path), data, 0o644); e != nil {
		return map[string]any{"result": false, "comment": e.Error()}, nil
	}
	return map[string]any{"result": true, "comment": fmt.Sprintf("Successfully restored %s to %s", backup["Location"], a.Path)}, nil
}

type deleteBackupFunc struct{}

func (deleteBackupFunc) Name() string        { return "file.delete_backup" }
func (deleteBackupFunc) Args() any           { return backupIDArgs{} }
func (deleteBackupFunc) Platforms() []string { return []string{"linux"} }
func (deleteBackupFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*backupIDArgs)
	id, e := backupIndex(a.BackupID)
	if e != nil {
		return map[string]any{"result": false, "comment": fmt.Sprintf("Invalid backup_id '%v'", a.BackupID)}, nil
	}
	backups, _ := listBackupsFor(rt, expandUser(a.Path), nil, false)
	backup, ok := backups[id]
	if !ok {
		return map[string]any{"result": false, "comment": fmt.Sprintf("backup_id '%v' does not exist for %s", a.BackupID, a.Path)}, nil
	}
	if e = rt.FS.Remove(backup["Location"].(string)); e != nil {
		return map[string]any{"result": false, "comment": e.Error()}, nil
	}
	return map[string]any{"result": true, "comment": fmt.Sprintf("Successfully removed %s", backup["Location"])}, nil
}
func backupIndex(value any) (int, error) {
	switch x := value.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		n, e := strconv.Atoi(x)
		return n, e
	default:
		return 0, fmt.Errorf("invalid")
	}
}

// ---------------------------------------------------------------------------
// open files/move/disk usage/statvfs

type openFilesArgs struct {
	ByPID bool `statekit:"name=by_pid"`
}
type openFilesFunc struct{}

func (openFilesFunc) Name() string        { return "file.open_files" }
func (openFilesFunc) Args() any           { return openFilesArgs{} }
func (openFilesFunc) Platforms() []string { return []string{"linux"} }
func (openFilesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*openFilesArgs)
	files := map[string][]int{}
	pids := map[int][]string{}
	entries, e := rt.FS.ReadDir("/proc")
	if e != nil {
		return map[string][]int{}, nil
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || !entry.IsDir() {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, _ := rt.FS.ReadDir(fdDir)
		for _, fd := range fds {
			target, e := rt.FS.Readlink(filepath.Join(fdDir, fd.Name()))
			if e != nil {
				continue
			}
			if _, e = rt.FS.Stat(target); e != nil {
				continue
			}
			if !containsString(pids[pid], target) {
				pids[pid] = append(pids[pid], target)
				files[target] = append(files[target], pid)
			}
		}
	}
	for _, values := range files {
		sort.Ints(values)
	}
	if a.ByPID {
		return pids, nil
	}
	return files, nil
}
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

type moveArgs struct {
	Src                   string `statekit:"required"`
	Dst                   string `statekit:"required"`
	DisallowCopyAndUnlink bool   `statekit:"name=disallow_copy_and_unlink"`
}
type moveFunc struct{}

func (moveFunc) Name() string        { return "file.move" }
func (moveFunc) Args() any           { return moveArgs{} }
func (moveFunc) Platforms() []string { return []string{"linux"} }
func (moveFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*moveArgs)
	src, dst := expandUser(a.Src), expandUser(a.Dst)
	if !filepath.IsAbs(src) {
		return nil, fmt.Errorf("Source path must be absolute.")
	}
	if !filepath.IsAbs(dst) {
		return nil, fmt.Errorf("Destination path must be absolute.")
	}
	if e := rt.FS.Rename(src, dst); e == nil {
		return map[string]any{"result": true, "comment": fmt.Sprintf("'%s' moved to '%s'", src, dst)}, nil
	} else if a.DisallowCopyAndUnlink {
		return nil, e
	}
	info, infoErr := rt.FS.Lstat(src)
	if infoErr != nil {
		return nil, infoErr
	}
	if info.IsDir() {
		if e := copyTree(rt, src, dst); e != nil {
			return nil, e
		}
	} else {
		data, e := rt.FS.ReadFile(src)
		if e != nil {
			return nil, e
		}
		if e := rt.FS.WriteFile(dst, data, info.Mode().Perm()); e != nil {
			return nil, e
		}
	}
	if e := rt.FS.RemoveAll(src); e != nil {
		return nil, e
	}
	return map[string]any{"result": true, "comment": fmt.Sprintf("'%s' moved to '%s'", src, dst)}, nil
}

type diskusageArgs struct {
	Path string `statekit:"required"`
}
type diskusageFunc struct{}

func (diskusageFunc) Name() string        { return "file.diskusage" }
func (diskusageFunc) Args() any           { return diskusageArgs{} }
func (diskusageFunc) Platforms() []string { return []string{"linux"} }
func (diskusageFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*diskusageArgs)
	var total int64
	var walk func(string)
	walk = func(path string) {
		info, e := rt.FS.Lstat(path)
		if e != nil {
			return
		}
		if !info.IsDir() {
			total += info.Size()
			return
		}
		entries, e := rt.FS.ReadDir(path)
		if e != nil {
			return
		}
		for _, entry := range entries {
			walk(filepath.Join(path, entry.Name()))
		}
	}
	walk(expandUser(a.Path))
	return total, nil
}

type statvfsArgs struct {
	Path string `statekit:"required"`
}
type statvfsFunc struct{}

func (statvfsFunc) Name() string        { return "file.statvfs" }
func (statvfsFunc) Args() any           { return statvfsArgs{} }
func (statvfsFunc) Platforms() []string { return []string{"linux"} }
func (statvfsFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*statvfsArgs)
	if !filepath.IsAbs(a.Path) {
		return nil, fmt.Errorf("File path must be absolute.")
	}
	var stat syscall.Statfs_t
	if e := syscall.Statfs(expandUser(a.Path), &stat); e != nil {
		return nil, fmt.Errorf("Could not statvfs '%s'", a.Path)
	}
	return map[string]any{"f_bavail": stat.Bavail, "f_bfree": stat.Bfree, "f_blocks": stat.Blocks, "f_bsize": stat.Bsize, "f_favail": stat.Ffree, "f_ffree": stat.Ffree, "f_files": stat.Files, "f_flag": stat.Flags, "f_frsize": stat.Frsize, "f_namemax": stat.Namelen}, nil
}
func intOptionFile(options map[string]any, key string, fallback int) int {
	if value, ok := options[key]; ok {
		switch x := value.(type) {
		case int:
			return x
		case float64:
			return int(x)
		case string:
			n, e := strconv.Atoi(x)
			if e == nil {
				return n
			}
		}
	}
	return fallback
}
