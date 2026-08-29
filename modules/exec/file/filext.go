package file

// File long-tail part 1 (R4.1): path utilities, text edits, directory
// operations, and links, mirroring saltstack/salt/modules/file.py @
// pinned revision (references/salt.lock).

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func strOrPtr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func orDefault(s *string, def string) string {
	if s != nil && *s != "" {
		return *s
	}
	return def
}

// --- pure path utilities ------------------------------------------------------

type pathArgs struct {
	Path string `statekit:"required,name=path"`
}

type basenameFunc struct{}

func (basenameFunc) Name() string { return "file.basename" }
func (basenameFunc) Args() any    { return pathArgs{} }
func (basenameFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*pathArgs)
	return filepath.Base(a.Path), nil
}

type dirnameFunc struct{}

func (dirnameFunc) Name() string { return "file.dirname" }
func (dirnameFunc) Args() any    { return pathArgs{} }
func (dirnameFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*pathArgs)
	return filepath.Dir(a.Path), nil
}

type normpathFunc struct{}

func (normpathFunc) Name() string { return "file.normpath" }
func (normpathFunc) Args() any    { return pathArgs{} }
func (normpathFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*pathArgs)
	return filepath.Clean(a.Path), nil
}

type pardirFunc struct{}

func (pardirFunc) Name() string { return "file.pardir" }
func (pardirFunc) Args() any    { return struct{}{} }
func (pardirFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return "..", nil
}

type joinArgs struct {
	Args []string `statekit:"name=args"`
}

type joinFunc struct{}

// Join mirrors os.path.join + normpath semantics: later absolute
// components reset the base.
func (joinFunc) Name() string { return "file.join" }
func (joinFunc) Args() any    { return joinArgs{} }
func (joinFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*joinArgs)
	joined := ""
	for _, part := range a.Args {
		if strings.HasPrefix(part, "/") {
			joined = part
			continue
		}
		if joined == "" {
			joined = part
		} else if strings.HasSuffix(joined, "/") {
			joined += part
		} else {
			joined += "/" + part
		}
	}
	return filepath.Clean(joined), nil
}

type pathExistsGlobArgs struct {
	Path string `statekit:"required,name=path"`
}

type pathExistsGlobFunc struct{}

func (pathExistsGlobFunc) Name() string { return "file.path_exists_glob" }
func (pathExistsGlobFunc) Args() any    { return pathExistsGlobArgs{} }
func (pathExistsGlobFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pathExistsGlobArgs)
	matches, err := rt.FS.Glob(filepath.Clean(a.Path))
	if err != nil {
		return false, nil
	}
	return len(matches) > 0, nil
}

// --- text edits -----------------------------------------------------------------

type prependArgs struct {
	Path string   `statekit:"required,name=path"`
	Args []string `statekit:"name=args"`
}

type prependFunc struct{}

func (prependFunc) Name() string { return "file.prepend" }
func (prependFunc) Args() any    { return prependArgs{} }

func (prependFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*prependArgs)
	path := expandUser(a.Path)

	var contents []string
	if data, err := rt.FS.ReadFile(path); err == nil {
		text := strings.TrimSuffix(string(data), "\n")
		if text != "" || len(data) > 0 {
			contents = strings.Split(text, "\n")
		}
	}

	var preface []string
	for _, line := range a.Args {
		preface = append(preface, line+"\n")
	}

	out := strings.Join(preface, "") + strings.Join(append([]string{}, contents...), "")
	if len(contents) > 0 && len(a.Args) >= 0 {
		out = strings.Join(preface, "") + strings.Join(contents, "\n") + "\n"
	}
	if werr := rt.FS.WriteFile(path, []byte(out), 0o644); werr != nil {
		return nil, werr
	}
	return fmt.Sprintf("Prepended %d lines to %q", len(a.Args), path), nil
}

type seekReadArgs struct {
	Path   string `statekit:"required,name=path"`
	Size   int    `statekit:"required,name=size"`
	Offset int    `statekit:"required,name=offset"`
}

type seekReadFunc struct{}

func (seekReadFunc) Name() string { return "file.seek_read" }
func (seekReadFunc) Args() any    { return seekReadArgs{} }
func (seekReadFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*seekReadArgs)
	path := expandUser(a.Path)
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if a.Offset > len(data) {
		a.Offset = len(data)
	}
	end := a.Offset + a.Size
	if end > len(data) {
		end = len(data)
	}
	return string(data[a.Offset:end]), nil
}

type seekWriteArgs struct {
	Path   string `statekit:"required,name=path"`
	Data   string `statekit:"required,name=data"`
	Offset int    `statekit:"required,name=offset"`
}

type seekWriteFunc struct{}

func (seekWriteFunc) Name() string { return "file.seek_write" }
func (seekWriteFunc) Args() any    { return seekWriteArgs{} }
func (seekWriteFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*seekWriteArgs)
	path := expandUser(a.Path)
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		data = []byte{}
	}
	buf := make([]byte, 0, a.Offset+len(a.Data))
	if a.Offset > len(data) {
		buf = append(buf, data...)
		buf = append(buf, make([]byte, a.Offset-len(data))...)
	} else {
		buf = append(buf, data[:a.Offset]...)
	}
	buf = append(buf, a.Data...)
	buf = append(buf, data[min(a.Offset+len(a.Data), len(data)):]...)
	if werr := rt.FS.WriteFile(path, buf, 0o644); werr != nil {
		return nil, werr
	}
	return len(a.Data), nil
}

type truncateArgs struct {
	Path   string `statekit:"required,name=path"`
	Length int    `statekit:"required,name=length"`
}

type truncateFunc struct{}

func (truncateFunc) Name() string { return "file.truncate" }
func (truncateFunc) Args() any    { return truncateArgs{} }
func (truncateFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*truncateArgs)
	path := expandUser(a.Path)
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	length := a.Length
	if length > len(data) {
		length = len(data)
	}
	return nil, rt.FS.WriteFile(path, data[:length], 0o644)
}

// commentLine implements the shared engine behind comment/uncomment.
func commentLine(rt *runtime.Runtime, path, regex, char string, cmnt bool, backup *string) (bool, error) {
	if cmnt {
		regex = fmt.Sprintf("%s(%s)%s",
			map[bool]string{true: "^", false: ""}[strings.HasPrefix(regex, "^")],
			strings.TrimSuffix(strings.TrimPrefix(regex, "^"), "$"),
			map[bool]string{true: "$", false: ""}[strings.HasSuffix(regex, "$")])
	} else {
		regex = fmt.Sprintf("^%s\\s*(%s)%s", char,
			strings.TrimSuffix(strings.TrimPrefix(regex, "^"), "$"),
			map[bool]string{true: "$", false: ""}[strings.HasSuffix(regex, "$")])
	}

	path = expandUser(path)
	re, err := regexp.Compile(regex)
	if err != nil {
		return false, err
	}
	info, statErr := rt.FS.Stat(path)
	if statErr != nil || info.IsDir() {
		return false, fmt.Errorf("File not found: %s", path)
	}
	data, rerr := rt.FS.ReadFile(path)
	if rerr != nil {
		return false, fmt.Errorf("Unable to open file '%s'. Exception: %v", path, rerr)
	}
	if containsNul(data) {
		return false, fmt.Errorf("Cannot perform string replacements on a binary file: %s", path)
	}

	found := false
	lines := splitKeepEnds(string(data))
	newLines := make([]string, len(lines))
	copy(newLines, lines)
	for i, line := range lines {
		// Python's $ also matches before a trailing newline; match on the
		// newline-stripped text to reproduce that anchoring.
		if re.MatchString(strings.TrimRight(line, "\n")) {
			found = true
			if cmnt {
				newLines[i] = char + line
			} else {
				newLines[i] = strings.TrimLeft(line, char)
			}
		}
	}
	if !found {
		return false, nil
	}

	if backup != nil && *backup != "" {
		rt.FS.WriteFile(path+*backup, data, 0o644)
	}
	return true, rt.FS.WriteFile(path, []byte(strings.Join(newLines, "")), 0o644)
}

func containsNul(data []byte) bool {
	return strings.ContainsRune(string(data), '\x00')
}

// splitKeepEnds mirrors iterating file lines with newline characters kept.
func splitKeepEnds(content string) []string {
	var out []string
	start := 0
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			out = append(out, content[start:i+1])
			start = i + 1
		}
	}
	if start < len(content) {
		out = append(out, content[start:])
	}
	return out
}

type commentLineArgs struct {
	Path   string  `statekit:"required,name=path"`
	Regex  string  `statekit:"required,name=regex"`
	Char   string  `statekit:"name=char"`
	Cmnt   *bool   `statekit:"name=cmnt"`
	Backup *string `statekit:"name=backup"`
}

type commentLineFunc struct{}

func (commentLineFunc) Name() string { return "file.comment_line" }
func (commentLineFunc) Args() any    { return commentLineArgs{} }
func (commentLineFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*commentLineArgs)
	char := "#"
	if a.Char != "" {
		char = a.Char
	}
	cmnt := true
	if a.Cmnt != nil {
		cmnt = *a.Cmnt
	}
	backup := ".bak"
	if a.Backup != nil {
		backup = *a.Backup
	}
	return commentLine(rt, expandUser(a.Path), a.Regex, char, cmnt, &backup)
}

type commentArgs struct {
	Path   string  `statekit:"required,name=path"`
	Regex  string  `statekit:"required,name=regex"`
	Char   string  `statekit:"name=char"`
	Backup *string `statekit:"name=backup"`
}

type commentFunc struct{}

func (commentFunc) Name() string { return "file.comment" }
func (commentFunc) Args() any    { return commentArgs{} }
func (commentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*commentArgs)
	char := "#"
	if a.Char != "" {
		char = a.Char
	}
	backup := ".bak"
	if a.Backup != nil {
		backup = *a.Backup
	}
	return commentLine(rt, expandUser(a.Path), a.Regex, char, true, &backup)
}

type uncommentFunc struct{}

func (uncommentFunc) Name() string { return "file.uncomment" }
func (uncommentFunc) Args() any    { return commentArgs{} }
func (uncommentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*commentArgs)
	char := "#"
	if a.Char != "" {
		char = a.Char
	}
	backup := ".bak"
	if a.Backup != nil {
		backup = *a.Backup
	}
	return commentLine(rt, expandUser(a.Path), a.Regex, char, false, &backup)
}

// --- blockreplace ------------------------------------------------------------------

var blockReplaceDefaults = struct {
	markerStart string
	markerEnd   string
}{markerStart: "#-- start managed zone --", markerEnd: "#-- end managed zone --"}

type blockreplaceArgs struct {
	Path              string  `statekit:"required,name=path"`
	MarkerStart       *string `statekit:"name=marker_start"`
	MarkerEnd         *string `statekit:"name=marker_end"`
	Content           *string `statekit:"name=content"`
	AppendIfNotFound  bool    `statekit:"name=append_if_not_found"`
	PrependIfNotFound bool    `statekit:"name=prepend_if_not_found"`
	Backup            *string `statekit:"name=backup"`
	DryRun            bool    `statekit:"name=dry_run"`
	ShowChanges       *bool   `statekit:"name=show_changes"`
	AppendNewline     *bool   `statekit:"name=append_newline"`
	InsertBeforeMatch *string `statekit:"name=insert_before_match"`
	InsertAfterMatch  *string `statekit:"name=insert_after_match"`
}

type blockreplaceFunc struct{}

func (blockreplaceFunc) Name() string { return "file.blockreplace" }
func (blockreplaceFunc) Args() any    { return blockreplaceArgs{} }

func (blockreplaceFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*blockreplaceArgs)
	markerStart := blockReplaceDefaults.markerStart
	if a.MarkerStart != nil {
		markerStart = *a.MarkerStart
	}
	markerEnd := blockReplaceDefaults.markerEnd
	if a.MarkerEnd != nil {
		markerEnd = *a.MarkerEnd
	}
	content := ""
	if a.Content != nil {
		content = *a.Content
	}

	if a.InsertBeforeMatch != nil && !isStringy(a.InsertBeforeMatch) {
		return nil, fmt.Errorf("RegEx expected in insert_before_match parameter.")
	}
	if a.InsertAfterMatch != nil && !isStringy(a.InsertAfterMatch) {
		return nil, fmt.Errorf("RegEx expected in insert_after_match parameter.")
	}

	appendNewline := false
	appendNewlineGiven := false
	if a.AppendNewline != nil {
		appendNewline = *a.AppendNewline
		appendNewlineGiven = true
	}
	if !appendNewlineGiven && !strings.HasSuffix(content, "\n") {
		appendNewline = true
	}

	splitContent := []string{}
	for _, winLine := range strings.Split(content, "\r\n") {
		splitContent = append(splitContent, strings.Split(winLine, "\n")...)
	}
	lineCount := len(splitContent)

	addContent := func(linesep string, lines []string, includeMarkerStart bool, endLine string) []string {
		if lines == nil {
			lines = []string{}
			includeMarkerStart = true
		}
		if endLine == "" {
			endLine = markerEnd
		}
		endLine = strings.TrimRight(endLine, "\r\n") + linesep

		if includeMarkerStart {
			lines = append(lines, markerStart+linesep)
		}
		if len(splitContent) > 0 {
			for index, contentLine := range splitContent {
				index++
				if index != lineCount {
					lines = append(lines, contentLine+linesep)
				} else {
					if appendNewline {
						lines = append(lines, contentLine+linesep)
						lines = append(lines, endLine)
					} else {
						lines = append(lines, contentLine+endLine)
					}
				}
			}
		} else {
			lines = append(lines, endLine)
		}
		return lines
	}

	path := expandUser(a.Path)
	data, rerr := rt.FS.ReadFile(path)
	if rerr != nil {
		return nil, fmt.Errorf("Failed to read from %s: %v", path, rerr)
	}

	linesep := ""
	inBlock := false
	blockFound := false
	origFile := splitKeepEnds(string(data))
	newFile := []string{}
	for _, line := range origFile {
		writeLine := true
		if linesep == "" {
			if strings.HasSuffix(line, "\r\n") {
				linesep = "\r\n"
			} else if strings.HasSuffix(line, "\n") {
				linesep = "\n"
			}
		}
		if strings.Contains(line, markerStart) {
			inBlock = true
		} else if inBlock {
			writeLine = false
			if pos := strings.Index(line, markerEnd); pos != -1 {
				inBlock = false
				blockFound = true
				newFile = addContent(linesep, newFile, false, line[pos:])
			}
		}
		if writeLine {
			newFile = append(newFile, line)
		}
	}
	if linesep == "" {
		linesep = "\n"
	}

	if inBlock {
		return nil, fmt.Errorf(
			"Unterminated marked block. End of file reached before marker_end.")
	}

	if !blockFound {
		switch {
		case a.PrependIfNotFound:
			prepended := addContent(linesep, nil, true, "")
			newFile = append(prepended, newFile...)
			blockFound = true
		case a.AppendIfNotFound:
			if len(newFile) > 0 && !strings.HasSuffix(newFile[len(newFile)-1], linesep) {
				newFile[len(newFile)-1] += linesep
			}
			newFile = addContent(linesep, newFile, true, "")
			blockFound = true
		case a.InsertBeforeMatch != nil || a.InsertAfterMatch != nil:
			matchRegex := ""
			insertAfter := false
			if a.InsertAfterMatch != nil {
				matchRegex, insertAfter = *a.InsertAfterMatch, true
			} else {
				matchRegex = *a.InsertBeforeMatch
			}
			re := regexp.MustCompile(matchRegex)
			matchIdx := -1
			for i, item := range origFile {
				if re.MatchString(item) {
					matchIdx = i
					break
				}
			}
			if matchIdx >= 0 {
				for _, inserted := range addContent(linesep, nil, true, "") {
					if insertAfter {
						matchIdx++
					}
					newFile = insertAt(newFile, matchIdx, inserted)
					if !insertAfter {
						matchIdx++
					}
				}
				blockFound = true
			}
		default:
			return nil, fmt.Errorf("Cannot edit marked block. Markers were not found in file.")
		}
	}
	if !blockFound {
		return nil, fmt.Errorf("Cannot edit marked block. Markers were not found in file.")
	}

	diff := unifiedDiff(origFile, newFile)
	hasChanges := diff != ""
	if hasChanges && !a.DryRun {
		backup := ".bak"
		if a.Backup != nil {
			backup = *a.Backup
		}
		if backup != "False" && backup != "" {
			origData := strings.Join(origFile, "")
			rt.FS.WriteFile(path+backup, []byte(origData), 0o644)
		}
		rt.FS.WriteFile(path, []byte(strings.Join(newFile, "")), 0o644)
	}

	showChanges := true
	if a.ShowChanges != nil {
		showChanges = *a.ShowChanges
	}
	if showChanges {
		return diff, nil
	}
	return hasChanges, nil
}

func isStringy(s *string) bool { return s != nil }

func insertAt(slice []string, idx int, value string) []string {
	slice = append(slice[:idx], append([]string{value}, slice[idx:]...)...)
	return slice
}

// --- directories --------------------------------------------------------------------

type makedirsArgs struct {
	Path  string  `statekit:"required,name=path"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type makedirsFunc struct{}

// Makedirs mirrors makedirs_: ensure the PARENT directory chain of path
// exists, walking up and creating top-down with per-directory messages.
func (makedirsFunc) Name() string { return "file.makedirs_" }
func (makedirsFunc) Args() any    { return makedirsArgs{} }
func (makedirsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*makedirsArgs)
	path := expandUser(a.Path)
	mode := normalizeMode(strOrPtr(a.Mode))

	dirname := filepath.Clean(filepath.Dir(path))
	if info, err := rt.FS.Stat(dirname); err == nil && info.IsDir() {
		return fmt.Sprintf("Directory '%s' already exists", dirname), nil
	}
	if _, err := rt.FS.Lstat(dirname); err == nil {
		return fmt.Sprintf("The path '%s' already exists and is not a directory", dirname), nil
	}

	var toCreate []string
	for {
		if info, err := rt.FS.Stat(dirname); err == nil && info.IsDir() {
			break
		}
		toCreate = append(toCreate, dirname)
		current := dirname
		dirname = filepath.Dir(dirname)
		if current == dirname {
			return nil, fmt.Errorf(
				"Recursive creation for path '%s' would result in an "+
					"infinite loop. Please use an absolute path.", dirname)
		}
	}
	for i := len(toCreate) - 1; i >= 0; i-- {
		mkdirInternal(rt, toCreate[i], mode)
	}
	return nil, nil
}

type makedirsPermsArgs struct {
	Name  string  `statekit:"required,name=name"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
	Mode  *string `statekit:"name=mode"`
}

type makedirsPermsFunc struct{}

func (makedirsPermsFunc) Name() string { return "file.makedirs_perms" }
func (makedirsPermsFunc) Args() any    { return makedirsPermsArgs{} }
func (makedirsPermsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*makedirsPermsArgs)
	name := expandUser(a.Name)
	mode := normalizeMode(orDefault(a.Mode, "0755"))
	if err := rt.FS.MkdirAll(name, permFromMode(mode)); err != nil {
		return nil, err
	}
	rt.FS.Chmod(name, permFromMode(mode))
	return nil, nil
}

func normalizeMode(mode string) string {
	if mode == "" {
		return ""
	}
	trimmed := strings.TrimLeft(mode, "0")
	if trimmed == "" {
		return "0000"
	}
	// Salt normalizes to a four-digit octal string.
	for len(trimmed) < 4 {
		trimmed = "0" + trimmed
	}
	return trimmed
}

func permFromMode(mode string) fs.FileMode {
	n, err := strconvParseOctal(mode)
	if err != nil {
		return 0o755
	}
	return fs.FileMode(n)
}

func strconvParseOctal(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, fmt.Errorf("invalid octal digit %q", c)
		}
		n = n*8 + int64(c-'0')
	}
	return n, nil
}

func mkdirInternal(rt *runtime.Runtime, dir, mode string) {
	perm := fs.FileMode(0o755)
	if mode != "" {
		perm = permFromMode(mode)
	}
	rt.FS.MkdirAll(dir, perm)
	if mode != "" {
		rt.FS.Chmod(dir, perm)
	}
}

type readdirArgs struct {
	Path string `statekit:"required,name=path"`
}

type readdirFunc struct{}

func (readdirFunc) Name() string { return "file.readdir" }
func (readdirFunc) Args() any    { return readdirArgs{} }
func (readdirFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*readdirArgs)
	path := expandUser(a.Path)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Dir path must be absolute.")
	}
	info, err := rt.FS.Stat(path)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("A valid directory was not specified.")
	}
	entries, err := rt.FS.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := []string{".", ".."}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names[2:])
	return names, nil
}

type rmdirArgs struct {
	Path      string `statekit:"required,name=path"`
	Recurse   bool   `statekit:"name=recurse"`
	Verbose   bool   `statekit:"name=verbose"`
	OlderThan int    `statekit:"name=older_than"`
}

type rmdirFunc struct{}

func (rmdirFunc) Name() string { return "file.rmdir" }
func (rmdirFunc) Args() any    { return rmdirArgs{} }
func (rmdirFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*rmdirArgs)
	path := expandUser(a.Path)
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("File path must be absolute.")
	}
	if info, err := rt.FS.Stat(path); err != nil || !info.IsDir() {
		return false, fmt.Errorf("A valid directory was not specified.")
	}

	ret := false
	deleted := []string{}
	errors := []any{}

	removeDir := func(dir string) bool {
		entries, err := rt.FS.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			errors = append(errors, map[string]string{
				dir: "directory not empty",
			})
			return false
		}
		if err := rt.FS.Remove(dir); err != nil {
			errors = append(errors, map[string]string{dir: err.Error()})
			return false
		}
		deleted = append(deleted, dir)
		return true
	}

	if a.Recurse {
		ok := true
		var walk func(dir string)
		walk = func(dir string) {
			entries, err := rt.FS.ReadDir(dir)
			if err != nil {
				return
			}
			subdirs := []string{}
			for _, entry := range entries {
				if entry.IsDir() {
					sub := filepath.Join(dir, entry.Name())
					subdirs = append(subdirs, sub)
					walk(sub)
				}
			}
			// Remove deepest-first.
			for i := len(subdirs) - 1; i >= 0; i-- {
				if !removeDir(subdirs[i]) {
					ok = false
				}
			}
		}
		walk(path)
		ret = ok
	}

	if removeDir(path) {
		ret = true
	} else {
		ret = false
	}

	if a.Verbose {
		return map[string]any{
			"deleted": deleted,
			"errors":  errors,
			"result":  ret,
		}, nil
	}
	return ret, nil
}

// --- links -----------------------------------------------------------------------------

type linkArgs struct {
	Src  string `statekit:"required,name=src"`
	Path string `statekit:"required,name=path"`
}

type linkFunc struct{}

func (linkFunc) Name() string { return "file.link" }
func (linkFunc) Args() any    { return linkArgs{} }
func (linkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*linkArgs)
	src := expandUser(a.Src)
	if !filepath.IsAbs(src) {
		return nil, fmt.Errorf("File path must be absolute.")
	}
	if err := rt.FS.Link(src, expandUser(a.Path)); err != nil {
		return nil, fmt.Errorf("Could not create '%s': %v", a.Path, err)
	}
	return true, nil
}

type isHardlinkArgs struct {
	Path string `statekit:"required,name=path"`
}

type isHardlinkFunc struct{}

func (isHardlinkFunc) Name() string { return "file.is_hardlink" }
func (isHardlinkFunc) Args() any    { return isHardlinkArgs{} }
func (isHardlinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*isHardlinkArgs)
	info, err := rt.FS.Lstat(expandUser(a.Path))
	if err != nil {
		return false, nil
	}
	return hardlinked(info), nil
}

type IsLinkArgs struct {
	Path   string `statekit:"required,name=path"`
	Nostat bool   `statekit:"name=nostat"`
}

type isLinkFunc struct{}

func (isLinkFunc) Name() string { return "file.is_link" }
func (isLinkFunc) Args() any    { return IsLinkArgs{} }
func (isLinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*IsLinkArgs)
	info, err := rt.FS.Lstat(expandUser(a.Path))
	if err != nil {
		return false, nil
	}
	return info.Mode()&fs.ModeSymlink != 0, nil
}

type SymlinkArgs struct {
	Src            string `statekit:"required,name=src"`
	Path           string `statekit:"required,name=path"`
	Force          bool   `statekit:"name=force"`
	Atomic         bool   `statekit:"name=atomic"`
	FollowSymlinks bool   `statekit:"name=follow_symlinks"`
}

type symlinkFunc struct{}

func (symlinkFunc) Name() string { return "file.symlink" }
func (symlinkFunc) Args() any    { return SymlinkArgs{} }
func (symlinkFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SymlinkArgs)
	path := expandUser(a.Path)
	src := expandUser(a.Src)

	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Link path must be absolute: %s", path)
	}

	exists := func(p string) bool {
		if a.FollowSymlinks {
			_, err := rt.FS.Stat(p)
			return err == nil
		}
		_, err := rt.FS.Lstat(p)
		return err == nil
	}

	if target, err := rt.FS.Readlink(path); err == nil {
		if filepath.Clean(target) == filepath.Clean(src) {
			return true, nil
		}
		if a.Force {
			rt.FS.Remove(path)
		}
	} else if exists(path) {
		if a.Force {
			rt.FS.Remove(path)
		}
	}
	if err := rt.FS.Symlink(src, path); err != nil {
		return nil, fmt.Errorf("Could not create '%s': %v", path, err)
	}
	return true, nil
}

// RegisterExt installs the R4.1 long-tail functions alongside the base set.
func RegisterExt(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "windows" {
		return nil
	}
	for _, fn := range []runtime.ExecFunction{
		basenameFunc{},
		dirnameFunc{},
		normpathFunc{},
		pardirFunc{},
		joinFunc{},
		pathExistsGlobFunc{},
		prependFunc{},
		seekReadFunc{},
		seekWriteFunc{},
		truncateFunc{},
		commentLineFunc{},
		commentFunc{},
		uncommentFunc{},
		blockreplaceFunc{},
		makedirsFunc{},
		makedirsPermsFunc{},
		readdirFunc{},
		rmdirFunc{},
		linkFunc{},
		isHardlinkFunc{},
		isLinkFunc{},
		symlinkFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// unifiedDiff renders a unified diff (three context lines) like
// salt.utils.stringutils.get_diff, which wraps difflib.unified_diff.
func unifiedDiff(oldLines, newLines []string) string {
	oldText := strings.Join(oldLines, "")
	newText := strings.Join(newLines, "")
	if oldText == newText {
		return ""
	}
	n, m := len(oldLines), len(newLines)
	// LCS table (config files are small; linear memory would be an
	// optimization without behavioral impact).
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type op struct {
		tag  byte // ' ', '-', '+'
		line string
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case oldLines[i] == newLines[j]:
			ops = append(ops, op{' ', oldLines[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, op{'-', oldLines[i]})
			i++
		default:
			ops = append(ops, op{'+', newLines[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', oldLines[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', newLines[j]})
	}

	const ctx = 3
	var out []string
	idx := 0
	for idx < len(ops) {
		if ops[idx].tag == ' ' {
			idx++
			continue
		}
		start := idx - ctx
		if start < 0 {
			start = 0
		}
		end := idx
		count := 0
		for end < len(ops) && count <= ctx {
			if ops[end].tag != ' ' {
				count = 0
			} else {
				count++
			}
			end++
		}
		if end > len(ops) {
			end = len(ops)
		}
		out = append(out, fmt.Sprintf("@@ -%d +%d @@\n", start+1, start+1))
		for k := start; k < end; k++ {
			out = append(out, string(ops[k].tag)+ops[k].line+"\n")
		}
		idx = end
	}
	return strings.Join(out, "")
}
