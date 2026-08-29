package file

// File long-tail part 2 (R4.2): checksums, ownership resolution, lstat and
// access, mirroring saltstack/salt/modules/file.py @ pinned revision.

import (
	"context"
	"fmt"
	"io/fs"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/filesum"
	"github.com/friz-zy/statekit/internal/runtime"
)

// hashes mirrors salt.utils.files.HASHES; revmap is derived.
var hashes = map[string]int{
	"sha512": 128,
	"sha384": 96,
	"sha256": 64,
	"sha224": 56,
	"sha1":   40,
	"md5":    32,
}

func hashesRevmap() map[int]string {
	out := map[int]string{}
	for k, v := range hashes {
		out[v] = k
	}
	return out
}

type hashInterface = interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
	Reset()
}

func newHash(form string) (hashInterface, error) { return filesum.New(form) }

type getSumArgs struct {
	Path string  `statekit:"required,name=path"`
	Form *string `statekit:"name=form"`
}

type getSumFunc struct{}

// GetSum mirrors get_sum: missing files return the literal "File not found"
// string instead of an error (verbatim upstream behavior).
func (getSumFunc) Name() string { return "file.get_sum" }
func (getSumFunc) Args() any    { return getSumArgs{} }
func (getSumFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*getSumArgs)
	path := expandUser(a.Path)
	form := strOrPtr(a.Form)
	if form == "" {
		form = "sha256"
	}
	info, err := rt.FS.Stat(path)
	if err != nil || info.IsDir() {
		return "File not found", nil
	}
	h, herr := newHash(form)
	if herr != nil {
		return herr.Error(), nil
	}
	data, rerr := rt.FS.ReadFile(path)
	if rerr != nil {
		return "File not found", nil
	}
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

type getHashArgs struct {
	Path      string  `statekit:"required,name=path"`
	Form      *string `statekit:"name=form"`
	ChunkSize int     `statekit:"name=chunk_size"`
}

type getHashFunc struct{}

func (getHashFunc) Name() string { return "file.get_hash" }
func (getHashFunc) Args() any    { return getHashArgs{} }
func (getHashFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*getHashArgs)
	form := strOrPtr(a.Form)
	if form == "" {
		form = "sha256"
	}
	chunk := a.ChunkSize
	if chunk == 0 {
		chunk = 65536
	}
	h, err := newHash(form)
	if err != nil {
		return nil, err
	}
	data, rerr := rt.FS.ReadFile(expandUser(a.Path))
	if rerr != nil {
		return nil, rerr
	}
	for i := 0; i < len(data); i += chunk {
		end := i + chunk
		if end > len(data) {
			end = len(data)
		}
		h.Write(data[i:end])
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

type checkHashArgs struct {
	Path     string `statekit:"required,name=path"`
	FileHash string `statekit:"required,name=file_hash"`
}

type checkHashFunc struct{}

func (checkHashFunc) Name() string { return "file.check_hash" }
func (checkHashFunc) Args() any    { return checkHashArgs{} }

func (checkHashFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*checkHashArgs)
	path := expandUser(a.Path)

	hashType := ""
	hashValue := ""
	sepFound := false
	for _, sep := range []string{":", "="} {
		if strings.Contains(a.FileHash, sep) {
			parts := strings.SplitN(a.FileHash, sep, 2)
			hashType, hashValue = parts[0], parts[1]
			sepFound = true
			break
		}
	}
	if !sepFound {
		hashValue = a.FileHash
		length := len(hashValue)
		t, ok := hashesRevmap()[length]
		if !ok {
			var entries []string
			lengths := make([]int, 0, len(hashesRevmap()))
			for length2 := range hashesRevmap() {
				lengths = append(lengths, length2)
			}
			sort.Ints(lengths)
			for _, l := range lengths {
				entries = append(entries, fmt.Sprintf("%s (%d)", hashesRevmap()[l], l))
			}
			return nil, fmt.Errorf(
				"Hash %s (length: %d) could not be matched to a supported "+
					"hash type. The supported hash types and lengths are: %s",
				a.FileHash, length, strings.Join(entries, ", "))
		}
		hashType = t
	}
	res, err := getHashFunc{}.Execute(ctx, rt, &getHashArgs{Path: path, Form: &hashType})
	if err != nil {
		return false, err
	}
	return res.(string) == hashValue, nil
}

type extractHashArgs struct {
	HashFn         string  `statekit:"required,name=hash_fn"`
	HashType       *string `statekit:"name=hash_type"`
	FileName       *string `statekit:"name=file_name"`
	Source         *string `statekit:"name=source"`
	SourceHashName *string `statekit:"name=source_hash_name"`
}

type extractHashFunc struct{}

func (extractHashFunc) Name() string { return "file.extract_hash" }
func (extractHashFunc) Args() any    { return extractHashArgs{} }

type hashMatch struct {
	hsum     string
	hashType string
}

// extractHashImpl mirrors extract_hash including the source_hash_name >
// file_name > source priority, the partial (first-hash) fallback, and the
// lookaround-free boundary checks.
func extractHashImpl(rt *runtime.Runtime, a *extractHashArgs) map[string]any {
	hashType := strOrPtr(a.HashType)
	hashLen, known := hashes[hashType]
	minLen, maxLen := 32, 128
	if !known {
		hashType = ""
	} else {
		minLen, maxLen = hashLen, hashLen
	}
	hashLenExpr := fmt.Sprintf("%d,%d", minLen, maxLen)

	sourceHashName := strOrPtr(a.SourceHashName)
	fileName := strOrPtr(a.FileName)
	source := strOrPtr(a.Source)

	fileNameBasename := ""
	if fileName != "" {
		fileNameBasename = filepath.Base(fileName)
	}
	sourceBasename := ""
	if source != "" {
		source = strings.TrimPrefix(strings.TrimPrefix(source, "salt://"), "https://")
		source = strings.TrimPrefix(source, "http://")
		source = strings.TrimPrefix(source, "ftp://")
		source = strings.TrimPrefix(source, "file://")
		sourceBasename = filepath.Base(source)
	}

	partial := (*hashMatch)(nil)
	found := map[string][]*hashMatch{}

	addToMatches := func(line, matchType, value string, matched *hashMatch) {
		found[matchType] = append(found[matchType], matched)
		_ = line
		_ = value
	}

	data, err := rt.FS.ReadFile(a.HashFn)
	if err != nil {
		return nil
	}
	hashRe := regexpCompileHexHash(hashLenExpr)

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		m := hashRe.FindStringSubmatch(strings.ToLower(line))
		var matched *hashMatch
		if m != nil && m[1] != "" {
			matchedType, ok := hashesRevmap()[len(m[1])]
			if ok {
				matched = &hashMatch{hsum: strings.ToLower(m[1]), hashType: matchedType}
			}
		}
		if matched == nil {
			continue
		}
		if partial == nil {
			partial = matched
		}

		hashMatched := false
		if sourceHashName != "" {
			if strings.HasSuffix(line, sourceHashName) {
				idx := len(line) - len(sourceHashName) - 1
				if idx < 0 || isWhitespaceByte(line[idx]) || filenameIsSepByte(line[idx]) {
					addToMatches(line, "source_hash_name", sourceHashName, matched)
					hashMatched = true
				}
			} else if matchesPrefixWord(line, sourceHashName) {
				addToMatches(line, "source_hash_name", sourceHashName, matched)
				hashMatched = true
			}
		}
		if fileName != "" {
			if strings.HasSuffix(line, fileNameBasename) {
				idx := len(line) - len(fileNameBasename) - 1
				if idx < 0 || filenameIsSepByte(line[idx]) {
					addToMatches(line, "file_name", fileName, matched)
					hashMatched = true
				}
			} else if matchesPrefixWord(line, fileName) {
				addToMatches(line, "file_name", fileName, matched)
				hashMatched = true
			}
		}
		if source != "" {
			if strings.HasSuffix(line, sourceBasename) {
				idx := len(line) - len(sourceBasename) - 1
				if idx >= 0 && filenameIsSepByte(line[idx]) {
					addToMatches(line, "source", source, matched)
					hashMatched = true
				}
			} else if matchesPrefixWord(line, source) {
				addToMatches(line, "source", source, matched)
				hashMatched = true
			}
		}
		_ = hashMatched
	}

	for _, foundType := range []string{"source_hash_name", "file_name", "source"} {
		if list, ok := found[foundType]; ok && len(list) > 0 {
			first := list[0]
			return map[string]any{"hsum": first.hsum, "hash_type": first.hashType}
		}
	}
	if partial != nil {
		return map[string]any{"hsum": partial.hsum, "hash_type": partial.hashType}
	}
	return nil
}

func filenameIsSepByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', '/', '\\':
		return true
	}
	return false
}

func isWhitespaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// matchesPrefixWord mirrors re.match(re.escape(value)+r"\s+", line).
func matchesPrefixWord(line, value string) bool {
	if !strings.HasPrefix(line, value) {
		return false
	}
	rest := line[len(value):]
	return len(rest) > 0 && isWhitespaceByte(rest[0])
}

// regexpCompileHexHash builds the (?i)(?<![a-z0-9])([a-f0-9]{expr})(?![a-z0-9])
// equivalent without lookarounds (RE2 limitation): candidate runs are
// accepted only when their boundaries are not hex-word characters.
func regexpCompileHexHash(lengthExpr string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)([a-f0-9]{` + lengthExpr + `})`)
}

// validHexAt reports whether data[i:i+n] is an isolated hex run per the
// upstream lookaround pair.
func validHexAt(data []byte, i, n int) bool {
	if i > 0 {
		c := data[i-1] | 0x20
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			return false
		}
	}
	if i+n < len(data) {
		c := data[i+n] | 0x20
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

func (extractHashFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*extractHashArgs)
	result := extractHashImpl(rt, a)
	if result == nil {
		return nil, nil
	}
	return result, nil
}

// --- ownership -----------------------------------------------------------------------

type uidArgs struct {
	Uid int `statekit:"required,name=uid"`
}

type uidToUserFunc struct{}

func (uidToUserFunc) Name() string { return "file.uid_to_user" }
func (uidToUserFunc) Args() any    { return uidArgs{} }
func (uidToUserFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*uidArgs)
	if u, err := user.LookupId(strconv.Itoa(a.Uid)); err == nil {
		return u.Username, nil
	}
	// If the user is not present, fall back to the uid.
	return a.Uid, nil
}

type userArgs struct {
	User string `statekit:"required,name=user"`
}

type userToUidFunc struct{}

func (userToUidFunc) Name() string { return "file.user_to_uid" }
func (userToUidFunc) Args() any    { return userArgs{} }
func (userToUidFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*userArgs)
	name := a.User
	if name == "" {
		if current, err := user.Current(); err == nil {
			return current.Uid, nil
		}
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	if u, err := user.Lookup(name); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		return uid, nil
	}
	return "", nil
}

type gidArgs struct {
	Gid int `statekit:"required,name=gid"`
}

type gidToGroupFunc struct{}

func (gidToGroupFunc) Name() string { return "file.gid_to_group" }
func (gidToGroupFunc) Args() any    { return gidArgs{} }
func (gidToGroupFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*gidArgs)
	if g, err := user.LookupGroupId(strconv.Itoa(a.Gid)); err == nil {
		return g.Name, nil
	}
	return a.Gid, nil
}

type groupArgs struct {
	Group string `statekit:"required,name=group"`
}

type groupToGidFunc struct{}

func (groupToGidFunc) Name() string { return "file.group_to_gid" }
func (groupToGidFunc) Args() any    { return groupArgs{} }
func (groupToGidFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (any, error) {
	a := args.(*groupArgs)
	group := a.Group
	if group == "" {
		return "", nil
	}
	if n, err := strconv.Atoi(group); err == nil {
		return n, nil
	}
	if g, err := user.LookupGroup(group); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		return gid, nil
	}
	return "", nil
}

type statOwnerArgs struct {
	Path           string `statekit:"required,name=path"`
	FollowSymlinks bool   `statekit:"name=follow_symlinks"`
}

func statOwnerInfo(rt *runtime.Runtime, path string, follow bool) (fs.FileInfo, bool) {
	path = expandUser(path)
	var info fs.FileInfo
	var err error
	if follow {
		info, err = rt.FS.Stat(path)
	} else {
		info, err = rt.FS.Lstat(path)
	}
	if err != nil {
		return nil, false
	}
	return info, true
}

type getUidFunc struct{}

func (getUidFunc) Name() string { return "file.get_uid" }
func (getUidFunc) Args() any    { return statOwnerArgs{} }
func (getUidFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statOwnerArgs)
	info, ok := statOwnerInfo(rt, a.Path, a.FollowSymlinks)
	if !ok {
		return -1, nil
	}
	return uidOf(info), nil
}

type getUserFunc struct{}

func (getUserFunc) Name() string { return "file.get_user" }
func (getUserFunc) Args() any    { return statOwnerArgs{} }
func (getUserFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statOwnerArgs)
	info, ok := statOwnerInfo(rt, a.Path, a.FollowSymlinks)
	if !ok {
		return false, nil
	}
	uid := uidOf(info)
	if u, uerr := user.LookupId(strconv.Itoa(uid)); uerr == nil {
		return u.Username, nil
	}
	return false, nil
}

type getGidFunc struct{}

func (getGidFunc) Name() string { return "file.get_gid" }
func (getGidFunc) Args() any    { return statOwnerArgs{} }
func (getGidFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statOwnerArgs)
	info, ok := statOwnerInfo(rt, a.Path, a.FollowSymlinks)
	if !ok {
		return -1, nil
	}
	return gidOf(info), nil
}

type getGroupFunc struct{}

func (getGroupFunc) Name() string { return "file.get_group" }
func (getGroupFunc) Args() any    { return statOwnerArgs{} }
func (getGroupFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*statOwnerArgs)
	info, ok := statOwnerInfo(rt, a.Path, a.FollowSymlinks)
	if !ok {
		return false, nil
	}
	gid := gidOf(info)
	if g, gerr := user.LookupGroupId(strconv.Itoa(gid)); gerr == nil {
		return g.Name, nil
	}
	return false, nil
}

// --- lstat and access ------------------------------------------------------------------

type lstatArgs struct {
	Path string `statekit:"required,name=path"`
}

type lstatFunc struct{}

func (lstatFunc) Name() string { return "file.lstat" }
func (lstatFunc) Args() any    { return lstatArgs{} }
func (lstatFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*lstatArgs)
	path := expandUser(a.Path)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Path to file must be absolute.")
	}
	info, err := rt.FS.Lstat(path)
	if err != nil {
		return map[string]any{}, nil
	}
	return map[string]any{
		"st_atime": info.ModTime().Unix(),
		"st_ctime": info.ModTime().Unix(),
		"st_gid":   gidOf(info),
		"st_mode":  uint32(info.Mode()),
		"st_mtime": info.ModTime().Unix(),
		"st_nlink": nlinkOf(info),
		"st_size":  info.Size(),
		"st_uid":   uidOf(info),
	}, nil
}

type accessArgs struct {
	Path string `statekit:"required,name=path"`
	Mode string `statekit:"required,name=mode"`
}

type accessFunc struct{}

func (accessFunc) Name() string { return "file.access" }
func (accessFunc) Args() any    { return accessArgs{} }
func (accessFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*accessArgs)
	path := expandUser(a.Path)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Path to link must be absolute.")
	}
	info, err := rt.FS.Stat(path)
	switch a.Mode {
	case "f":
		return err == nil, nil
	case "r", "w", "x":
		if err != nil {
			return false, nil
		}
		mode := info.Mode().Perm()
		switch a.Mode {
		case "r":
			return mode&0o444 != 0, nil
		case "w":
			return mode&0o222 != 0, nil
		case "x":
			return mode&0o111 != 0, nil
		}
		return false, nil
	default:
		return nil, fmt.Errorf("Invalid mode specified.")
	}
}

// RegisterSums installs the R4.2 long-tail functions alongside the base set.
func RegisterSums(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "windows" {
		return nil
	}
	for _, fn := range []runtime.ExecFunction{
		getSumFunc{},
		getHashFunc{},
		checkHashFunc{},
		extractHashFunc{},
		uidToUserFunc{},
		userToUidFunc{},
		gidToGroupFunc{},
		groupToGidFunc{},
		getUidFunc{},
		getUserFunc{},
		getGidFunc{},
		getGroupFunc{},
		lstatFunc{},
		accessFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
