package file

// File managed-source meta family (R4.7): the machinery behind
// salt.states.file.managed — manage_file, the check_* probes, perms,
// attributes, SELinux contexts and the diff/backup utilities they need.
//
// Reference: saltstack/salt/modules/file.py @ pinned revision
// (references/salt.lock), plus salt/utils/files.py (copyfile, backup_minion,
// normalize_mode) and salt/utils/stringutils.py (get_diff,
// get_conditional_diff, is_binary). The unified diff is a faithful port of
// difflib.SequenceMatcher/unified_diff so StateKit output matches Salt's
// byte-for-byte.
//
// Documented boundaries:
//   - templated sources are excluded by the minimal-jinja ADR: the template
//     registry is empty, so every template hits upstream's verbatim
//     "Specified template format ... is not supported" reply;
//   - remote (http/ftp/swift/s3) and salt:// sources surface the cp family
//     boundaries exactly like the other file functions;
//   - signature verification parameters require the gpg family (R5 round)
//     and surface UnsupportedError when set;
//   - master-fileserver source lists degrade to an empty list (master-minion
//     excluded), so only local entries of a source list can match;
//   - __context__ caching in source_list is not reproduced (StateKit calls
//     stay stateless).

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	user2 "os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"github.com/friz-zy/statekit/modules/exec/cp"
)

// ---------------------------------------------------------------------------
// injectable hooks

var (
	metaWhich = func(exe string) (string, bool) {
		p := lookPathBin(exe)
		return p, p != ""
	}
	metaNow = time.Now
	tmpSeq  = func() int64 { return time.Now().UnixNano() }
)

// defaultCacheDir mirrors the workspace-hygiene rule from R4.3: scratch and
// cache paths stay inside the project tree unless a config delegate says
// otherwise.
const defaultCacheDir = ".statekit"

func cachedirOf(rt *runtime.Runtime) string {
	if _, ok := rt.Exec.Get("config.get"); ok {
		res, err := rt.Exec.Call(context.Background(), rt, "config.get",
			map[string]any{"key": "cachedir"})
		if err == nil {
			if s, isStr := res.(string); isStr && s != "" {
				return s
			}
		}
	}
	return defaultCacheDir
}

// configOption mirrors __salt__["config.option"] with graceful degradation
// when no config module is registered (same pattern as pyenv/pip/pkgrepo).
func configOptionStr(rt *runtime.Runtime, key string) string {
	fn, ok := rt.Exec.Get("config.option")
	if !ok {
		return ""
	}
	res, err := rt.Exec.Call(context.Background(), rt, fn.Name(),
		map[string]any{"key": key})
	if err != nil || res == nil {
		return ""
	}
	if s, isStr := res.(string); isStr {
		return s
	}
	return ""
}

func testMode(rt *runtime.Runtime) bool { return rt.Options.Test }

// ---------------------------------------------------------------------------
// normalize_mode (salt.utils.files.normalize_mode)

func normalizeAny(mode any) any {
	if mode == nil {
		return nil
	}
	s, ok := mode.(string)
	if !ok {
		s = fmt.Sprintf("%v", mode)
	}
	s = strings.ReplaceAll(s, "0o", "0")
	s = strings.Trim(strings.TrimSpace(s), "\"'")
	s = strings.TrimLeft(s, "0")
	return fmt.Sprintf("%04s", s)
}

func modeString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		r := normalizeAny(t)
		if r == nil {
			return ""
		}
		return r.(string)
	case int:
		return normalizeAny(strconv.Itoa(t)).(string)
	case int64:
		return normalizeAny(strconv.FormatInt(t, 10)).(string)
	default:
		return normalizeAny(fmt.Sprintf("%v", t)).(string)
	}
}

// ---------------------------------------------------------------------------
// _error helper

func errorRet(ret map[string]any, msg string) map[string]any {
	ret["result"] = false
	ret["comment"] = msg
	return ret
}

// ---------------------------------------------------------------------------
// metaRet models Salt's mutable state-return dict through the meta family.

type metaRet struct {
	Name        string
	Changes     map[string]any
	Comment     []string
	OrigComment string
	Result      *bool
	SkipReq     bool
	Warnings    []string
}

func newMetaRet(name string) *metaRet {
	return &metaRet{Name: name, Changes: map[string]any{}, Result: triTrue()}
}

func triTrue() *bool  { b := true; return &b }
func triFalse() *bool { b := false; return &b }

func retFromMap(m map[string]any, defName string) *metaRet {
	r := newMetaRet(defName)
	if m == nil {
		return r
	}
	if s, ok := m["name"].(string); ok && s != "" {
		r.Name = expandUser(s)
	}
	if cm, ok := m["changes"].(map[string]any); ok {
		r.Changes = cm
	} else {
		r.Changes = map[string]any{}
	}
	if s, ok := m["comment"].(string); ok {
		r.OrigComment = s
	}
	if b, ok := m["result"].(bool); ok {
		r.Result = &b
	}
	return r
}

func (r *metaRet) toMap() map[string]any {
	comment := r.OrigComment
	if comment != "" || len(r.Comment) > 0 {
		parts := r.Comment
		if comment != "" {
			parts = append([]string{comment}, r.Comment...)
		}
		comment = strings.Join(parts, "; ")
	}
	var resultVal any = false
	if r.Result == nil {
		resultVal = nil // Salt's result=None (test-mode pending)
	} else {
		resultVal = *r.Result
	}
	out := map[string]any{
		"name":    r.Name,
		"changes": r.Changes,
		"comment": comment,
		"result":  resultVal,
	}
	if r.SkipReq {
		out["skip_req"] = true
	}
	if len(r.Warnings) > 0 {
		out["warnings"] = r.Warnings
	}
	return out
}

// ---------------------------------------------------------------------------
// stats() port (Salt-shaped dict used across the meta family).

func uidToUserName(uid int) any {
	if u, err := user2.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return uid
}

func gidToGroupName(gid int) any {
	if g, err := user2.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return g.Name
	}
	return gid
}

// resolveTarget mirrors os.path.realpath / abspath over the FS abstraction.
func resolveTarget(rt *runtime.Runtime, path string, follow bool) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if !follow {
		return abs
	}
	cur := path
	for hop := 0; hop < 40; hop++ {
		info, err := rt.FS.Lstat(cur)
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			break
		}
		target, rerr := rt.FS.Readlink(cur)
		if rerr != nil {
			break
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = target
	}
	abs, err = filepath.Abs(cur)
	if err != nil {
		return cur
	}
	return abs
}

func statsImpl(rt *runtime.Runtime, path string, hashType *string, followSymlinks bool) (map[string]any, error) {
	path = expandUser(path)
	var info fs.FileInfo
	var err error
	if followSymlinks {
		info, err = rt.FS.Stat(path)
	} else {
		info, err = rt.FS.Lstat(path)
	}
	if err != nil {
		// Broken symlinks still carry a stat; anything else is missing.
		if info2, e2 := rt.FS.Lstat(path); e2 == nil {
			info = info2
		} else {
			return nil, fmt.Errorf("Path not found: %s", path)
		}
	}
	mode := info.Mode().Perm()
	ret := map[string]any{
		"inode":  inodeOf(info),
		"uid":    uidOf(info),
		"gid":    gidOf(info),
		"group":  gidToGroupName(gidOf(info)),
		"user":   uidToUserName(uidOf(info)),
		"atime":  info.ModTime().Unix(),
		"mtime":  info.ModTime().Unix(),
		"ctime":  info.ModTime().Unix(),
		"size":   info.Size(),
		"mode":   normalizeAny(fmt.Sprintf("%04o", mode)),
		"type":   fileType(info.Mode()),
		"target": resolveTarget(rt, path, followSymlinks),
	}
	if hashType != nil && *hashType != "" {
		res, herr := getHashFunc{}.Execute(context.Background(), rt,
			&getHashArgs{Path: path, Form: hashType})
		if herr != nil {
			return nil, herr
		}
		ret["sum"] = res
	}
	switch {
	case info.IsDir():
		ret["type"] = "dir"
	case info.Mode()&fs.ModeSymlink != 0:
		ret["type"] = "link"
	case info.Mode()&fs.ModeDevice != 0 && info.Mode()&fs.ModeCharDevice != 0:
		ret["type"] = "char"
	case info.Mode()&fs.ModeDevice != 0:
		ret["type"] = "block"
	case info.Mode().IsRegular():
		ret["type"] = "file"
	case info.Mode()&fs.ModeNamedPipe != 0:
		ret["type"] = "pipe"
	case info.Mode()&fs.ModeSocket != 0:
		ret["type"] = "socket"
	}
	return ret, nil
}

func chmodMode(rt *runtime.Runtime, path string, mode any) error {
	parsed, err := parseOctal(modeString(mode))
	if err != nil {
		return err
	}
	return rt.FS.Chmod(path, parsed)
}

// ---------------------------------------------------------------------------
// binary detection (salt.utils.stringutils.is_binary / salt.utils.files
// .is_text / .is_binary) and _binary_replace.

func isBinaryData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	textCharacters := make([]bool, 256)
	for i := 32; i < 127; i++ {
		textCharacters[i] = true
	}
	for _, b := range []byte("\n\r\t\f\b") {
		textCharacters[b] = true
	}
	multibyteOK := utf8.Valid(data)
	if !multibyteOK {
		// Python tolerates a truncated multibyte character at the very end.
		for cut := 1; cut <= 3 && cut < len(data); cut++ {
			if utf8.Valid(data[:len(data)-cut]) {
				multibyteOK = true
				break
			}
		}
	}
	if multibyteOK {
		for i := 128; i < 256; i++ {
			textCharacters[i] = true
		}
	}
	nontext := 0
	for _, b := range data {
		if !textCharacters[b] {
			nontext++
		}
	}
	return float64(nontext)/float64(len(data)) > 0.30
}

func filesIsBinary(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, rerr := rt.FS.ReadFile(path)
	if rerr != nil {
		return false
	}
	if len(data) > 2048 {
		data = data[:2048]
	}
	return isBinaryData(data)
}

func filesIsText(rt *runtime.Runtime, path string) bool {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return false
	}
	if len(data) > 512 {
		data = data[:512]
	}
	return !isBinaryData(data)
}

func binaryReplace(rt *runtime.Runtime, oldPath, newPath string) string {
	oldIsBin := !filesIsText(rt, oldPath)
	newIsBin := !filesIsText(rt, newPath)
	switch {
	case oldIsBin && newIsBin:
		return "Replace binary file"
	case oldIsBin:
		return "Replace binary file with text file"
	case newIsBin:
		return "Replace text file with binary file"
	}
	return ""
}

// ---------------------------------------------------------------------------
// difflib port: SequenceMatcher + unified_diff + get_conditional_diff.

type seqMatch struct{ a, b, size int }

type sequenceMatcher struct {
	a, b    []string
	b2j     map[string][]int
	popular map[string]bool
}

func newSequenceMatcher(a, b []string) *sequenceMatcher {
	m := &sequenceMatcher{a: a, b: b, popular: map[string]bool{}}
	m.chainB()
	return m
}

func (m *sequenceMatcher) chainB() {
	m.b2j = map[string][]int{}
	for i, elt := range m.b {
		m.b2j[elt] = append(m.b2j[elt], i)
	}
	// isjunk is always None in Salt's usage; autojunk stays enabled.
	if n := len(m.b); n >= 200 {
		ntest := n/100 + 1
		for elt, idxs := range m.b2j {
			if len(idxs) > ntest {
				m.popular[elt] = true
				delete(m.b2j, elt)
			}
		}
	}
}

func (m *sequenceMatcher) findLongestMatch(alo, ahi, blo, bhi int) seqMatch {
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := map[int]int{}
		for _, j := range m.b2j[m.a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	return seqMatch{besti, bestj, bestsize}
}

func (m *sequenceMatcher) getMatchingBlocks() []seqMatch {
	type quad struct{ alo, ahi, blo, bhi int }
	queue := []quad{{0, len(m.a), 0, len(m.b)}}
	var matched []seqMatch
	for len(queue) > 0 {
		q := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		mt := m.findLongestMatch(q.alo, q.ahi, q.blo, q.bhi)
		if mt.size > 0 {
			matched = append(matched, mt)
			if q.alo < mt.a && q.blo < mt.b {
				queue = append(queue, quad{q.alo, mt.a, q.blo, mt.b})
			}
			if mt.a+mt.size < q.ahi && mt.b+mt.size < q.bhi {
				queue = append(queue, quad{mt.a + mt.size, q.ahi, mt.b + mt.size, q.bhi})
			}
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].a != matched[j].a {
			return matched[i].a < matched[j].a
		}
		if matched[i].b != matched[j].b {
			return matched[i].b < matched[j].b
		}
		return matched[i].size < matched[j].size
	})
	var out []seqMatch
	i1, j1, k1 := 0, 0, 0
	for _, m2 := range matched {
		if i1+k1 == m2.a && j1+k1 == m2.b {
			k1 += m2.size
			continue
		}
		if k1 > 0 {
			out = append(out, seqMatch{i1, j1, k1})
		}
		i1, j1, k1 = m2.a, m2.b, m2.size
	}
	if k1 > 0 {
		out = append(out, seqMatch{i1, j1, k1})
	}
	out = append(out, seqMatch{len(m.a), len(m.b), 0})
	return out
}

// opcode tags mirror difflib: 'r' replace, 'd' delete, 'i' insert, 'e' equal.
func (m *sequenceMatcher) getOpcodes() [][]int {
	i, j := 0, 0
	var answer [][]int
	for _, m2 := range m.getMatchingBlocks() {
		a2, b2, size := m2.a, m2.b, m2.size
		tag := byte(0)
		switch {
		case i < a2 && j < b2:
			tag = 'r'
		case i < a2:
			tag = 'd'
		case j < b2:
			tag = 'i'
		}
		if tag != 0 {
			answer = append(answer, []int{int(tag), i, a2, j, b2})
		}
		i, j = a2+size, b2+size
		if size > 0 {
			answer = append(answer, []int{int('e'), a2, i, b2, j})
		}
	}
	return answer
}

func (m *sequenceMatcher) getGroupedOpcodes(n int) [][][]int {
	codes := m.getOpcodes()
	if len(codes) == 0 {
		codes = [][]int{{int('e'), 0, 1, 0, 1}}
	}
	if codes[0][0] == int('e') {
		codes[0][1] = maxInt(codes[0][1], codes[0][2]-n)
		codes[0][3] = maxInt(codes[0][3], codes[0][4]-n)
	}
	lastIdx := len(codes) - 1
	if codes[lastIdx][0] == int('e') {
		codes[lastIdx][2] = minInt(codes[lastIdx][2], codes[lastIdx][1]+n)
		codes[lastIdx][4] = minInt(codes[lastIdx][4], codes[lastIdx][3]+n)
	}
	nn := n + n
	var groups [][][]int
	group := [][]int{}
	for _, code := range codes {
		tag, i1, i2, j1, j2 := code[0], code[1], code[2], code[3], code[4]
		if tag == int('e') && i2-i1 > nn {
			group = append(group, []int{tag, i1, minInt(i2, i1+n), j1, minInt(j2, j1+n)})
			groups = append(groups, group)
			group = [][]int{{tag, maxInt(i1, i2-n), i2, maxInt(j1, j2-n), j2}}
			continue
		}
		group = append(group, []int{tag, i1, i2, j1, j2})
	}
	if len(group) > 0 && !(len(group) == 1 && group[0][0] == int('e')) {
		groups = append(groups, group)
	}
	return groups
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatRangeUnified(start, stop int) string {
	beginning := start + 1
	length := stop - start
	if length == 1 {
		return strconv.Itoa(beginning)
	}
	if length == 0 {
		beginning--
	}
	return fmt.Sprintf("%d,%d", beginning, length)
}

// splitLinesKeepEnds mirrors binary readlines(): split on "\n" only,
// keeping the terminator on each line.
func splitLinesKeepEnds(data string) []string {
	if data == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i+1])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// unifiedDiffDifflib renders difflib.unified_diff(a, b, fromfile, tofile,
// n=3, lineterm="\n") joined into one string. Headers are emitted even when
// the file names are empty, exactly like CPython.
func unifiedDiffDifflib(a, b []string, fromfile, tofile string) string {
	sm := newSequenceMatcher(a, b)
	var out []string
	started := false
	for _, group := range sm.getGroupedOpcodes(3) {
		if !started {
			started = true
			out = append(out, "--- "+fromfile+"\n")
			out = append(out, "+++ "+tofile+"\n")
		}
		first, last := group[0], group[len(group)-1]
		file1 := formatRangeUnified(first[1], last[2])
		file2 := formatRangeUnified(first[3], last[4])
		out = append(out, "@@ -"+file1+" +"+file2+" @@\n")
		for _, op := range group {
			tag, i1, i2, j1, j2 := op[0], op[1], op[2], op[3], op[4]
			if tag == int('e') {
				for _, line := range a[i1:i2] {
					out = append(out, " "+line)
				}
				continue
			}
			if tag == int('r') || tag == int('d') {
				for _, line := range a[i1:i2] {
					out = append(out, "-"+line)
				}
			}
			if tag == int('r') || tag == int('i') {
				for _, line := range b[j1:j2] {
					out = append(out, "+"+line)
				}
			}
		}
	}
	return strings.Join(out, "")
}

// conditionalDiff ports stringutils.get_conditional_diff.
func conditionalDiff(a, b []string, ignoreOrdering, ignoreWhitespace bool, ignoreCommentCharacters []string) (bool, string) {
	diffText := unifiedDiffDifflib(a, b, "", "")
	diffLines := splitLinesKeepEnds(diffText)
	hasChanges := false
	if ignoreWhitespace || ignoreOrdering || len(ignoreCommentCharacters) > 0 {
		var adds, subs []string
		for _, line := range diffLines {
			trimmed := strings.TrimSuffix(line, "\n")
			if strings.HasPrefix(trimmed, "+++") || strings.HasPrefix(trimmed, "---") {
				continue
			}
			if len(trimmed) == 0 || (trimmed[0] != '+' && trimmed[0] != '-') {
				continue
			}
			oper := trimmed[0]
			body := trimmed[1:]
			for _, char := range ignoreCommentCharacters {
				if idx := strings.Index(body, char); idx >= 0 {
					body = body[:idx]
				}
			}
			if ignoreWhitespace {
				body = strings.TrimSpace(body)
			}
			if body != "" && oper == '+' {
				adds = append(adds, body)
			} else if body != "" && oper == '-' {
				subs = append(subs, body)
			}
		}
		if !equalSorted(adds, subs) {
			hasChanges = true
		}
	} else {
		hasChanges = len(diffLines) > 0
	}
	return hasChanges, diffText
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// copyfile + backup machinery (salt.utils.files.copyfile / backup_minion).

func mkstempNamed(rt *runtime.Runtime, dir, prefix string) (string, error) {
	name := fmt.Sprintf("%s%d", prefix, tmpSeq())
	path := filepath.Join(dir, name)
	if err := rt.FS.WriteFile(path, nil, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func cleanTmp(rt *runtime.Runtime, path string) {
	if path == "" {
		return
	}
	tmpDir := os.TempDir()
	if strings.HasPrefix(path, tmpDir+string(os.PathSeparator)) ||
		strings.HasPrefix(path, defaultCacheDir+string(os.PathSeparator)) ||
		strings.HasPrefix(path, cachedirOf(rt)+string(os.PathSeparator)) {
		rt.FS.Remove(path)
	}
}

// backupMinion ports salt.utils.files.backup_minion: copies dest under
// bkroot/<path>/<name>_<timestamp>, preserving owner and mode.
func backupMinion(rt *runtime.Runtime, path, bkroot string) error {
	dname, bname := filepath.Split(path)
	srcDir := strings.TrimPrefix(dname, string(os.PathSeparator))
	info, err := rt.FS.Stat(path)
	if err != nil {
		return err
	}
	now := metaNow()
	stamp := now.Format("Mon_Jan_02_15:04:05_2006")
	msecs := fmt.Sprintf("%06d", now.Nanosecond()/1000%1000000)
	stamp = stamp[:len(stamp)-4] + msecs + "_" + stamp[len(stamp)-4:]
	bkPath := filepath.Join(bkroot, srcDir, fmt.Sprintf("%s_%s", bname, stamp))
	if err := rt.FS.MkdirAll(filepath.Dir(bkPath), 0o755); err != nil {
		return err
	}
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return err
	}
	if err := rt.FS.WriteFile(bkPath, data, info.Mode().Perm()); err != nil {
		return err
	}
	rt.FS.Chown(bkPath, uidOf(info), gidOf(info))
	return nil
}

// copyfileImpl ports salt.utils.files.copyfile: atomic-ish replace with
// optional minion-side backups and post-move owner/mode restoration.
func copyfileImpl(rt *runtime.Runtime, source, dest, backupMode, cachedir string) error {
	sInfo, err := rt.FS.Stat(source)
	if err != nil || !sInfo.Mode().IsRegular() {
		return fmt.Errorf("[Errno 2] No such file or directory: %s", source)
	}
	if dInfo, derr := rt.FS.Stat(filepath.Dir(dest)); derr != nil || !dInfo.IsDir() {
		return fmt.Errorf("[Errno 2] No such file or directory: %s", filepath.Dir(dest))
	}
	tgt, terr := mkstempNamed(rt, filepath.Dir(dest), filepath.Base(dest))
	if terr != nil {
		return terr
	}
	data, rerr := rt.FS.ReadFile(source)
	if rerr != nil {
		return rerr
	}
	if werr := rt.FS.WriteFile(tgt, data, 0o600); werr != nil {
		return werr
	}
	bkroot := ""
	if cachedir != "" {
		bkroot = filepath.Join(cachedir, "file_backup")
	}
	if (backupMode == "minion" || backupMode == "both") && bkroot != "" {
		if _, exists := rt.FS.Stat(dest); exists == nil {
			backupMinion(rt, dest, bkroot)
		}
	}
	var fstat fs.FileInfo
	if fstat, err = rt.FS.Stat(dest); err != nil {
		fstat = nil
	}
	if err := rt.FS.Rename(tgt, dest); err != nil {
		cleanTmp(rt, tgt)
		return err
	}
	if fstat != nil {
		rt.FS.Chown(dest, uidOf(fstat), gidOf(fstat))
		rt.FS.Chmod(dest, fstat.Mode().Perm())
	}
	restoreconAfterCopy(rt, dest)
	return nil
}

func restoreconAfterCopy(rt *runtime.Runtime, dest string) {
	path, ok := metaWhich("restorecon")
	if !ok {
		return
	}
	enforce := ""
	if sel, has := rt.Exec.Get("selinux.getenforce"); has {
		res, err := rt.Exec.Call(context.Background(), rt, sel.Name(), struct{}{})
		if err == nil {
			if s, isStr := res.(string); isStr {
				enforce = s
			}
		}
	}
	if enforce != "Enforcing" {
		return
	}
	rt.Runner.Run(context.Background(), process.Command{Name: path, Args: []string{dest}})
}

// ---------------------------------------------------------------------------
// attrs trio: lsattr / chattr / _cmp_attrs through the central Runner.

var chattrHasExtendedAttrs = func(rt *runtime.Runtime) bool {
	tune2fs, ok := metaWhich("tune2fs")
	if !ok {
		return false
	}
	res := rt.Runner.Run(context.Background(), runtime.Command(tune2fs))
	match := regexp.MustCompile(`tune2fs ([0-9\.]+)`).FindSubmatch(res.Stdout)
	if match == nil {
		return false
	}
	return versionGreater(string(match[1]), "1.41.12")
}

func versionGreater(have, need string) bool {
	parse := func(v string) []int {
		var out []int
		for _, part := range strings.Split(v, ".") {
			n, err := strconv.Atoi(part)
			if err != nil {
				out = append(out, 0)
				continue
			}
			out = append(out, n)
		}
		return out
	}
	h, n := parse(have), parse(need)
	for i := 0; i < len(h) || i < len(n); i++ {
		hv, nv := 0, 0
		if i < len(h) {
			hv = h[i]
		}
		if i < len(n) {
			nv = n[i]
		}
		if hv != nv {
			return hv > nv
		}
	}
	return false
}

func lsattrImpl(rt *runtime.Runtime, path string) (map[string][]string, bool, error) {
	if _, ok := metaWhich("lsattr"); !ok {
		return nil, false, nil
	}
	if _, err := rt.FS.Stat(path); err != nil {
		return nil, true, fmt.Errorf("File or directory does not exist: %s", path)
	}
	res := rt.Runner.Run(context.Background(), runtime.Command("lsattr", path))
	results := map[string][]string{}
	pattern := `[aAcCdDeijPsStTu]`
	if !chattrHasExtendedAttrs(rt) {
		pattern = `[acdijstuADST]`
	}
	re := regexp.MustCompile(pattern)
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "lsattr: ") {
			continue
		}
		fields := strings.SplitN(strings.TrimLeft(line, " "), " ", 2)
		if len(fields) != 2 {
			continue
		}
		fileName := strings.TrimLeft(fields[1], " ")
		results[fileName] = re.FindAllString(fields[0], -1)
	}
	return results, true, nil
}

type attrChanges struct {
	added   string
	removed string
}

func cmpAttrs(rt *runtime.Runtime, path string, attrs string) *attrChanges {
	lattrs, ok, err := lsattrImpl(rt, path)
	if err != nil || !ok || lattrs == nil {
		return nil
	}
	current := ""
	if vals, found := lattrs[path]; found {
		current = strings.Join(vals, "")
	}
	newSet := map[rune]bool{}
	for _, r := range attrs {
		newSet[r] = true
	}
	oldSet := map[rune]bool{}
	for _, r := range current {
		oldSet[r] = true
	}
	// The "e" attribute can be set but never reset.
	if oldSet['e'] {
		newSet['e'] = true
	}
	var added, removed []rune
	for r := range newSet {
		if !oldSet[r] {
			added = append(added, r)
		}
	}
	for r := range oldSet {
		if !newSet[r] {
			removed = append(removed, r)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	return &attrChanges{added: string(added), removed: string(removed)}
}

// ---------------------------------------------------------------------------
// SELinux context helpers through the Runner.

func getSelinuxContextImpl(rt *runtime.Runtime, path string) string {
	res := rt.Runner.Run(context.Background(), runtime.Command("stat", "-c", "%C", path))
	if res.OK() {
		return strings.TrimRight(string(res.Stdout), "\n")
	}
	return fmt.Sprintf("No selinux context information is available for %s", path)
}

func setSelinuxContextImpl(rt *runtime.Runtime, path string, userRole, role, setType, rng *string, persist bool) (any, error) {
	if (userRole == nil || *userRole == "") && (role == nil || *role == "") &&
		(setType == nil || *setType == "") && (rng == nil || *rng == "") {
		return false, nil
	}
	if persist {
		res := map[string]any{"retcode": 0}
		if fctx, has := rt.Exec.Get("selinux.fcontext_add_policy"); has {
			out, err := rt.Exec.Call(context.Background(), rt, fctx.Name(), map[string]any{
				"path":      path,
				"sel_type":  strPtrVal(setType),
				"sel_user":  strPtrVal(userRole),
				"sel_level": strPtrVal(rng),
			})
			if err == nil {
				if m, isMap := out.(map[string]any); isMap {
					res = m
				}
			} else {
				res["retcode"] = 1
			}
		} else {
			res["retcode"] = 1
		}
		if rc, ok := res["retcode"].(int); ok && rc != 0 {
			return nil, fmt.Errorf("Problem setting fcontext: %v", res)
		}
	}
	cmd := []string{"chcon"}
	if userRole != nil && *userRole != "" {
		cmd = append(cmd, "-u", *userRole)
	}
	if role != nil && *role != "" {
		cmd = append(cmd, "-r", *role)
	}
	if setType != nil && *setType != "" {
		cmd = append(cmd, "-t", *setType)
	}
	if rng != nil && *rng != "" {
		cmd = append(cmd, "-l", *rng)
	}
	cmd = append(cmd, path)
	result := rt.Runner.Run(context.Background(), runtime.Command(cmd...))
	if result.OK() {
		return getSelinuxContextImpl(rt, path), nil
	}
	return false, nil
}

func strPtrVal(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// ---------------------------------------------------------------------------
// URL helpers mirroring urllib.parse usage in salt.modules.file.

var validProtos = []string{"salt", "file", "http", "https", "ftp", "swift", "s3"}
var remoteProtos = []string{"http", "https", "ftp", "swift", "s3"}

func inList(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// parseSourceURL returns the raw scheme ("" for bare paths) and the
// netloc+path join upstream feeds to os.path.
func parseSourceURL(source string) (scheme, joined string) {
	u, err := url.Parse(source)
	if err != nil {
		return "", source
	}
	scheme = u.Scheme
	joined = strings.TrimSuffix(filepath.Join(u.Host, u.Path), string(os.PathSeparator))
	return scheme, joined
}

// redactHTTPBasicAuth mirrors salt.utils.url.redact_http_basic_auth.
var basicAuthRe = regexp.MustCompile(`([a-z][a-z0-9+.\-]*)://([^/@\s:]+):([^@\s]+)@`)

func redactHTTPBasicAuth(source string) string {
	return basicAuthRe.ReplaceAllString(source, "$1://")
}

func hexDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func hashesRevmapSorted() ([]int, []string) {
	lengths := make([]int, 0, len(hashes))
	for _, l := range hashes {
		lengths = append(lengths, l)
	}
	sort.Ints(lengths)
	names := make([]string, 0, len(lengths))
	rev := hashesRevmap()
	for _, l := range lengths {
		names = append(names, fmt.Sprintf("%s (%d)", rev[l], l))
	}
	return lengths, names
}

// ensureNoSigParams surfaces the gpg-family boundary for signature
// verification parameters (gpg lands in R5).
func ensureNoSigParams(params map[string]any) error {
	for _, v := range params {
		switch t := v.(type) {
		case nil:
			continue
		case *string:
			if t != nil && *t != "" {
				return &runtime.UnsupportedError{Kind: "function", Name: "gpg.verify"}
			}
		case *bool:
			if t != nil && *t {
				return &runtime.UnsupportedError{Kind: "function", Name: "gpg.verify"}
			}
		}
	}
	return nil
}

// callDelegate resolves an execution-function delegate through the registry,
// mirroring Salt's __salt__ lookups. Missing delegates surface as errors so
// callers can degrade explicitly.
func callDelegate(rt *runtime.Runtime, name string, args any) (any, error) {
	if _, ok := rt.Exec.Get(name); !ok {
		return nil, fmt.Errorf("%s is not available", name)
	}
	return rt.Exec.Call(context.Background(), rt, name, args)
}

func cacheFileDelegate(rt *runtime.Runtime, source, saltenv string) (string, error) {
	env := saltenv
	res, err := callDelegate(rt, "cp.cache_file", &cp.CacheFileArgs{
		Path: source, Saltenv: &env,
	})
	if err != nil {
		return "", err
	}
	switch v := res.(type) {
	case string:
		return v, nil
	case bool:
		if !v {
			return "", nil
		}
	}
	return "", nil
}

func hashFileDelegate(rt *runtime.Runtime, source, saltenv string) (string, error) {
	env := saltenv
	res, err := callDelegate(rt, "cp.hash_file", &cp.HashFileArgs{
		Path: source, Saltenv: &env,
	})
	if err != nil {
		return "", err
	}
	if s, ok := res.(string); ok {
		return s, nil
	}
	return "", nil
}

func isCachedDelegate(rt *runtime.Runtime, source, saltenv string) (string, bool) {
	env := saltenv
	res, err := callDelegate(rt, "cp.is_cached", &cp.IsCachedArgs{
		Path: source, Saltenv: &env,
	})
	if err != nil {
		return "", false
	}
	s, _ := res.(string)
	return s, true
}

func statFileDelegate(rt *runtime.Runtime, source, saltenv string) (string, bool) {
	env := saltenv
	octal := true
	res, err := callDelegate(rt, "cp.stat_file", &cp.StatFileArgs{
		Path: source, Saltenv: &env, Octal: &octal,
	})
	if err != nil {
		return "", false
	}
	s, _ := res.(string)
	return s, true
}

// ---------------------------------------------------------------------------
// file.source_list

type sourceListArgs struct {
	Source     any     `statekit:"required,name=source"`
	SourceHash *string `statekit:"name=source_hash"`
	Saltenv    *string `statekit:"name=saltenv"`
}

type sourceListFunc struct{}

func (sourceListFunc) Name() string { return "file.source_list" }
func (sourceListFunc) Args() any    { return sourceListArgs{} }
func (sourceListFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*sourceListArgs)
	saltenv := strOrPtr(a.Saltenv)
	src, hash := sourceListImpl(rt, a.Source, strOrPtr(a.SourceHash), saltenv)
	return []any{src, hash}, nil
}

// sourceListImpl mirrors source_list; master file lists degrade to empty
// because cp.list_master* are master-minion exclusions.
func sourceListImpl(rt *runtime.Runtime, source any, sourceHash, saltenv string) (string, string) {
	sources, isList := source.([]any)
	if !isList {
		return fmt.Sprintf("%v", source), sourceHash
	}
	_ = sources
	// mfiles/mdirs stay empty: no master fileserver exists in StateKit.
	retSrc := ""
	retHash := ""
	for _, entry := range source.([]any) {
		switch single := entry.(type) {
		case map[string]any:
			if len(single) != 1 {
				continue
			}
			var singleSrc, singleHash string
			for k, v := range single {
				singleSrc = k
				if s, ok := v.(string); ok && s != "" {
					singleHash = s
				} else {
					singleHash = sourceHash
				}
			}
			proto, _ := parseSourceURL(singleSrc)
			lower := strings.ToLower(proto)
			if lower == "salt" {
				// No master list to match against; entry cannot be verified.
				continue
			}
			if strings.HasPrefix(lower, "http") || lower == "ftp" {
				// Upstream HEAD-probes via salt.utils.http.query; StateKit has
				// no fetcher yet, so the URL cannot be verified here.
				panicUnsupported(rt, "salt.utils.http.query")
			}
			if lower == "file" || strings.HasPrefix(singleSrc, "/") {
				p := filepath.Clean(strings.TrimPrefix(singleSrc, "file://"))
				if _, err := rt.FS.Stat(p); err == nil {
					return singleSrc, singleHash
				}
			}
		case string:
			proto, _ := parseSourceURL(single)
			lower := strings.ToLower(proto)
			if lower == "salt" {
				continue
			}
			if strings.HasPrefix(lower, "http") || lower == "ftp" {
				panicUnsupported(rt, "salt.utils.http.query")
			}
			if lower == "file" || proto == "" {
				p := filepath.Clean(strings.TrimPrefix(single, "file://"))
				if _, err := rt.FS.Stat(p); err == nil {
					return single, sourceHash
				}
			}
		}
	}
	if retSrc == "" {
		panicCmdExec("none of the specified sources were found")
	}
	return retSrc, retHash
}

// panicUnsupported/panicCmdExec convert internal boundary hits into the
// error-returning contract via panic/recover inside Execute wrappers.
func panicUnsupported(rt *runtime.Runtime, fn string) {
	panic(&runtime.UnsupportedError{Kind: "function", Name: fn})
}

type cmdExecError struct{ msg string }

func (e *cmdExecError) Error() string { return e.msg }

// metaError carries a partially populated state-return alongside the
// failure message, mirroring Salt's _error(ret, ...) replies from
// manage_file where accumulated changes survive the failure.
type metaError struct {
	msg string
	ret *metaRet
}

func (e *metaError) Error() string { return e.msg }

func panicCmdExec(msg string) { panic(&cmdExecError{msg: msg}) }

// panicRetErr mirrors _error(ret, ...): flips result to false, installs the
// comment, then unwinds with the populated return attached.
func panicRetErr(ret *metaRet, msg string) {
	ret.Result = triFalse()
	ret.OrigComment = msg
	ret.Comment = nil
	panic(&metaError{msg: msg, ret: ret})
}

func recoverMeta(v *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case *metaError:
			if e.ret != nil {
				*v = e.ret.toMap()
				return
			}
			*errPtr = e
		case *cmdExecError:
			*errPtr = e
		case *runtime.UnsupportedError:
			*errPtr = e
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

// ---------------------------------------------------------------------------
// file.get_source_sum

type getSourceSumArgs struct {
	FileName       *string `statekit:"name=file_name"`
	Source         *string `statekit:"name=source"`
	SourceHash     string  `statekit:"required,name=source_hash"`
	SourceHashName *string `statekit:"name=source_hash_name"`
	Saltenv        *string `statekit:"name=saltenv"`
	VerifySSL      *bool   `statekit:"name=verify_ssl"`
	SourceHashSig  *string `statekit:"name=source_hash_sig"`
	SignedByAny    *string `statekit:"name=signed_by_any"`
	SignedByAll    *string `statekit:"name=signed_by_all"`
	Keyring        *string `statekit:"name=keyring"`
	Gnupghome      *string `statekit:"name=gnupghome"`
	SigBackend     *string `statekit:"name=sig_backend"`
}

type getSourceSumFunc struct{}

func (getSourceSumFunc) Name() string { return "file.get_source_sum" }
func (getSourceSumFunc) Args() any    { return getSourceSumArgs{} }
func (getSourceSumFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*getSourceSumArgs)
	if err := ensureNoSigParams(map[string]any{
		"sig": a.SourceHashSig, "any": a.SignedByAny, "all": a.SignedByAll,
	}); err != nil {
		return nil, err
	}
	sum := getSourceSumImpl(rt, strOrPtr(a.FileName), strOrPtr(a.Source),
		a.SourceHash, strOrPtr(a.SourceHashName), strOrPtr(a.Saltenv))
	return sum, nil
}

func invalidSourceHashFormat(sourceHash string) error {
	_, names := hashesRevmapSorted()
	return fmt.Errorf(
		"Source hash %s format is invalid. The supported formats are: "+
			"1) a hash, 2) an expression in the format <hash_type>=<hash>, or "+
			"3) either a path to a local file containing hashes, or a URI of "+
			"a remote hash file. Supported protocols for remote hash files "+
			"are: %s. The hash may also not be of a valid length, the "+
			"following are supported hash types and lengths: %s.",
		redactHTTPBasicAuth(sourceHash),
		strings.Join(validProtos, ", "),
		strings.Join(names, ", "))
}

func getSourceSumImpl(rt *runtime.Runtime, fileName, source, sourceHash, sourceHashName, saltenv string) map[string]any {
	hashFn := ""
	if filepath.IsAbs(sourceHash) {
		hashFn = sourceHash
	} else {
		proto, _ := parseSourceURL(sourceHash)
		if inList(validProtos, strings.ToLower(proto)) || (proto != "" && strings.ToLower(proto) == "file") ||
			inList(validProtos, proto) {
			cached, cerr := cacheFileDelegate(rt, sourceHash, saltenv)
			if cerr != nil {
				panic(cerr)
			}
			if cached == "" {
				panicCmdExec(fmt.Sprintf("Source hash file %s not found",
					redactHTTPBasicAuth(sourceHash)))
			}
			hashFn = cached
		} else if proto != "" {
			panic(invalidSourceHashFormat(sourceHash))
		}
	}
	if hashFn != "" {
		ret := extractHashImpl(rt, &extractHashArgs{
			HashFn:         hashFn,
			FileName:       strPtr(fileName),
			Source:         strPtr(source),
			SourceHashName: strPtr(sourceHashName),
		})
		if ret == nil {
			panic(invalidSourceHashFormat(sourceHash))
		}
		hsum, _ := ret["hsum"].(string)
		ret["hsum"] = strings.ToLower(hsum)
		return ret
	}
	// The source_hash is a hash expression.
	ret := map[string]any{}
	hashType := ""
	hsum := ""
	if idx := strings.Index(sourceHash, "="); idx >= 0 {
		hashType = strings.TrimSpace(sourceHash[:idx])
		hsum = strings.TrimSpace(sourceHash[idx+1:])
	} else {
		if !hexDigitsOnly(sourceHash) {
			panic(invalidSourceHashFormat(sourceHash))
		}
		hsum = sourceHash
		rev := hashesRevmap()
		if t, ok := rev[len(sourceHash)]; ok {
			hashType = t
		} else {
			panic(invalidSourceHashFormat(sourceHash))
		}
	}
	if _, known := hashes[hashType]; !known {
		names := make([]string, 0, len(hashes))
		for k := range hashes {
			names = append(names, k)
		}
		sort.Strings(names)
		panicCmdExec(fmt.Sprintf(
			"Invalid hash type '%s'. Supported hash types are: %s. "+
				"Either remove the hash type and simply use '%s' as the "+
				"source_hash, or change the hash type to a supported type.",
			hashType, strings.Join(names, ", "), hsum))
	}
	if _, known := hashesRevmap()[len(hsum)]; !known {
		panic(invalidSourceHashFormat(sourceHash))
	}
	if len(hsum) != hashes[hashType] {
		panicCmdExec(fmt.Sprintf(
			"Invalid length (%d) for hash type '%s'. Either "+
				"remove the hash type and simply use '%s' as the "+
				"source_hash, or change the hash type to '%s'",
			len(hsum), hashType, hsum, hashesRevmap()[len(hsum)]))
	}
	ret["hash_type"] = hashType
	ret["hsum"] = strings.ToLower(hsum)
	return ret
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// file.get_managed

type getManagedArgs struct {
	Name                    string         `statekit:"required"`
	Template                *string        `statekit:"name=template"`
	Source                  *string        `statekit:"name=source"`
	SourceHash              *string        `statekit:"name=source_hash"`
	SourceHashName          *string        `statekit:"name=source_hash_name"`
	User                    *string        `statekit:"name=user"`
	Group                   *string        `statekit:"name=group"`
	Mode                    *string        `statekit:"name=mode"`
	Attrs                   *string        `statekit:"name=attrs"`
	Saltenv                 *string        `statekit:"name=saltenv"`
	Context                 map[string]any `statekit:"name=context"`
	Defaults                map[string]any `statekit:"name=defaults"`
	SkipVerify              *bool          `statekit:"name=skip_verify"`
	VerifySSL               *bool          `statekit:"name=verify_ssl"`
	UseEtag                 *bool          `statekit:"name=use_etag"`
	SourceHashSig           *string        `statekit:"name=source_hash_sig"`
	SignedByAny             *string        `statekit:"name=signed_by_any"`
	SignedByAll             *string        `statekit:"name=signed_by_all"`
	Keyring                 *string        `statekit:"name=keyring"`
	Gnupghome               *string        `statekit:"name=gnupghome"`
	IgnoreOrdering          *bool          `statekit:"name=ignore_ordering"`
	IgnoreWhitespace        *bool          `statekit:"name=ignore_whitespace"`
	IgnoreCommentCharacters *string        `statekit:"name=ignore_comment_characters"`
	SigBackend              *string        `statekit:"name=sig_backend"`
}

type getManagedFunc struct{}

func (getManagedFunc) Name() string { return "file.get_managed" }
func (getManagedFunc) Args() any    { return getManagedArgs{} }
func (getManagedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*getManagedArgs)
	if serr := ensureNoSigParams(map[string]any{
		"sig": a.SourceHashSig, "any": a.SignedByAny, "all": a.SignedByAll,
		"keyring": a.Keyring, "gnupghome": a.Gnupghome,
	}); serr != nil {
		return nil, serr
	}
	sfn, sum, comment := getManagedImpl(rt, getManagedOpts(a))
	return []any{sfn, sum, comment}, nil
}

type managedOpts struct {
	name, template, source, sourceHash, sourceHashName string
	skipVerify, useEtag                                bool
	saltenv                                            string
	sig                                                map[string]any
}

func getManagedOpts(a *getManagedArgs) managedOpts {
	return managedOpts{
		name:           expandUser(a.Name),
		template:       strOrPtr(a.Template),
		source:         strOrPtr(a.Source),
		sourceHash:     strOrPtr(a.SourceHash),
		sourceHashName: strOrPtr(a.SourceHashName),
		skipVerify:     a.SkipVerify != nil && *a.SkipVerify,
		useEtag:        a.UseEtag != nil && *a.UseEtag,
		saltenv:        strOrPtr(a.Saltenv),
		sig: map[string]any{
			"verify_ssl": a.VerifySSL, "source_hash_sig": a.SourceHashSig,
			"signed_by_any": a.SignedByAny, "signed_by_all": a.SignedByAll,
			"keyring": a.Keyring, "gnupghome": a.Gnupghome, "sig_backend": a.SigBackend,
		},
	}
}

func getManagedImpl(rt *runtime.Runtime, o managedOpts) (string, map[string]any, string) {
	sfn := ""
	sourceSum := map[string]any{}
	localSum := func(path string) map[string]any {
		res, _ := getHashFunc{}.Execute(context.Background(), rt,
			&getHashArgs{Path: path, Form: strPtr("sha256")})
		return map[string]any{"hsum": res, "hash_type": "sha256"}
	}
	if o.source != "" {
		scheme, parsedPath := parseSourceURL(o.source)
		unixLocalSource := scheme == "file" || scheme == ""
		if scheme == "" {
			parsedPath = o.source
			sfn = o.source
			if _, err := rt.FS.Stat(sfn); err != nil {
				return "", map[string]any{}, fmt.Sprintf("Local file source %s does not exist", sfn)
			}
		} else if scheme == "file" {
			sfn = parsedPath
			if _, err := rt.FS.Stat(sfn); err != nil {
				return "", map[string]any{}, fmt.Sprintf("Local file source %s does not exist", sfn)
			}
		}
		if scheme != "" && len(strings.ToLower(scheme)) == 1 && strings.ToLower(scheme)[0] >= 'a' && strings.ToLower(scheme)[0] <= 'z' {
			// Windows drive letter reparse; treated as file:// like upstream.
			parsedPath = scheme + ":" + parsedPath
			scheme = "file"
		}
		if scheme == "salt" {
			hsum, herr := hashFileDelegate(rt, o.source, o.saltenv)
			if herr != nil || hsum == "" {
				return "", map[string]any{}, fmt.Sprintf("Source file %s not found in saltenv '%s'", o.source, o.saltenv)
			}
			sourceSum["hsum"] = hsum
		} else if o.sourceHash == "" && unixLocalSource {
			sourceSum = localSum(parsedPath)
		} else if o.sourceHash == "" && strings.HasPrefix(o.source, "/") {
			sourceSum = localSum(o.source)
		} else {
			if !o.skipVerify {
				if o.sourceHash != "" {
					sum := getSourceSumImpl(rt, o.name, o.source, o.sourceHash,
						o.sourceHashName, o.saltenv)
					if sum == nil {
						return "", map[string]any{}, fmt.Sprintf("Unable to manage file: invalid source hash")
					}
					sourceSum = sum
				} else if !o.useEtag {
					return "", map[string]any{}, fmt.Sprintf(
						"Unable to verify upstream hash of source file %s, "+
							"please set source_hash or set skip_verify to True",
						redactHTTPBasicAuth(o.source))
				}
			}
		}
	}
	if o.source != "" && (o.template != "" || inList(remoteProtos, strings.ToLower(schemeOf(o.source)))) {
		cacheRefetch := false
		cachedDest, _ := isCachedDelegate(rt, o.source, o.saltenv)
		if cachedDest != "" && (o.sourceHash != "" || o.skipVerify || o.useEtag) {
			htype := "sha256"
			if v, ok := sourceSum["hash_type"].(string); ok && v != "" {
				htype = v
			}
			cachedSum, _ := getHashFunc{}.Execute(context.Background(), rt,
				&getHashArgs{Path: cachedDest, Form: strPtr(htype)})
			if o.skipVerify {
				sfn = cachedDest
				sourceSum = map[string]any{"hsum": cachedSum, "hash_type": htype}
			} else if o.useEtag || cachedSum != sourceSum["hsum"] {
				cacheRefetch = true
			} else {
				sfn = cachedDest
			}
		}
		if sfn == "" || cacheRefetch {
			cached, cerr := cacheFileDelegate(rt, o.source, o.saltenv)
			if cerr != nil {
				return "", map[string]any{}, fmt.Sprintf("Failed to cache %s: %s",
					redactHTTPBasicAuth(o.source), cerr.Error())
			}
			sfn = cached
		}
		if sfn == "" {
			if _, serr := rt.FS.Stat(sfn); serr != nil {
				return sfn, map[string]any{}, fmt.Sprintf("Source file '%s' not found",
					redactHTTPBasicAuth(o.source))
			}
		} else if _, serr := rt.FS.Stat(sfn); serr != nil {
			return sfn, map[string]any{}, fmt.Sprintf("Source file '%s' not found",
				redactHTTPBasicAuth(o.source))
		}
		if sfn == o.name {
			panicCmdExec("Source file cannot be the same as destination")
		}
		if o.template != "" {
			// Minimal-jinja ADR: the template registry carries no renderers,
			// so every template hits upstream's unsupported-format reply.
			return sfn, map[string]any{},
				fmt.Sprintf("Specified template format %s is not supported", o.template)
		}
	}
	return sfn, sourceSum, ""
}

func schemeOf(source string) string {
	scheme, _ := parseSourceURL(source)
	return scheme
}

// ---------------------------------------------------------------------------
// file.get_diff

type getDiffArgs struct {
	File1                   string  `statekit:"required,name=file1"`
	File2                   string  `statekit:"required,name=file2"`
	Saltenv                 *string `statekit:"name=saltenv"`
	ShowFilenames           *bool   `statekit:"name=show_filenames"`
	ShowChanges             *bool   `statekit:"name=show_changes"`
	Template                *bool   `statekit:"name=template"`
	SourceHashFile1         *string `statekit:"name=source_hash_file1"`
	SourceHashFile2         *string `statekit:"name=source_hash_file2"`
	IgnoreOrdering          *bool   `statekit:"name=ignore_ordering"`
	IgnoreWhitespace        *bool   `statekit:"name=ignore_whitespace"`
	IgnoreCommentCharacters *string `statekit:"name=ignore_comment_characters"`
}

type getDiffFunc struct{}

func (getDiffFunc) Name() string { return "file.get_diff" }
func (getDiffFunc) Args() any    { return getDiffArgs{} }
func (getDiffFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*getDiffArgs)
	out := getDiffImpl(rt,
		strOrPtr(a.Saltenv),
		a.File1, a.File2,
		a.ShowFilenames == nil || *a.ShowFilenames,
		a.ShowChanges == nil || *a.ShowChanges,
		a.Template != nil && *a.Template,
		strOrPtr(a.SourceHashFile1), strOrPtr(a.SourceHashFile2),
		a.IgnoreOrdering != nil && *a.IgnoreOrdering,
		a.IgnoreWhitespace != nil && *a.IgnoreWhitespace,
		strOrPtr(a.IgnoreCommentCharacters))
	return out, nil
}

func obfuscateTemplates(rt *runtime.Runtime) bool {
	v, ok := configOptionAny(rt, "obfuscate_templates")
	if !ok {
		return false
	}
	b, isBool := v.(bool)
	return isBool && b
}

func configOptionAny(rt *runtime.Runtime, key string) (any, bool) {
	fn, ok := rt.Exec.Get("config.option")
	if !ok {
		return nil, false
	}
	res, err := rt.Exec.Call(context.Background(), rt, fn.Name(),
		map[string]any{"key": key})
	if err != nil {
		return nil, false
	}
	return res, true
}

func readLines(rt *runtime.Runtime, path string) ([]string, error) {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", path, pathErrStr(err))
	}
	return splitLinesKeepEnds(string(data)), nil
}

func pathErrStr(err error) string {
	type strErr interface{ Error() string }
	var msg string
	if pe, ok := err.(interface{ Unwrap() error }); ok {
		if inner := pe.Unwrap(); inner != nil {
			msg = inner.Error()
		}
	}
	if msg == "" {
		msg = err.(strErr).Error()
	}
	return msg
}

var _ = getDiffImpl

func getDiffImpl(rt *runtime.Runtime, saltenv, file1, file2 string,
	showFilenames, showChanges, template bool,
	sourceHashFile1, sourceHashFile2 string,
	ignoreOrdering, ignoreWhitespace bool, ignoreCommentCharacters string) any {

	files := []string{file1, file2}
	sourceHashes := []string{sourceHashFile1, sourceHashFile2}
	var paths []string
	var errors []string
	for i, filename := range files {
		args := map[string]any{"path": filename, "saltenv": saltenv}
		if sourceHashes[i] != "" {
			args["source_hash"] = sourceHashes[i]
		}
		cachedPath, cerr := cacheFileDelegate(rt, filename, saltenv)
		if cerr != nil {
			errors = append(errors, cerr.Error())
			continue
		}
		_ = args
		if cachedPath == "" {
			errors = append(errors, fmt.Sprintf("File %s not found", filename))
			continue
		}
		paths = append(paths, cachedPath)
	}
	if len(errors) > 0 {
		panicCmdExec("Failed to cache one or more files")
	}
	lines1, rerr1 := readLines(rt, paths[0])
	if rerr1 != nil {
		panicCmdExec(rerr1.Error())
	}
	lines2, rerr2 := readLines(rt, paths[1])
	if rerr2 != nil {
		panicCmdExec(rerr2.Error())
	}
	anyIgnore := ignoreOrdering || ignoreWhitespace || ignoreCommentCharacters != ""
	if !equalLineSlices(lines1, lines2) {
		if template && obfuscateTemplates(rt) {
			return "<Obfuscated Template>"
		} else if !showChanges {
			return "<show_changes=False>"
		}
		bdiff := binaryReplace(rt, paths[0], paths[1])
		if bdiff != "" {
			return bdiff
		}
		fromfile, tofile := "", ""
		if showFilenames {
			fromfile, tofile = paths[0], paths[1]
		}
		if anyIgnore {
			hasChanges, diffText := conditionalDiff(lines1, lines2,
				ignoreOrdering, ignoreWhitespace,
				splitComments(ignoreCommentCharacters))
			_ = hasChanges
			return diffText
		}
		return unifiedDiffDifflib(lines1, lines2, fromfile, tofile)
	} else if anyIgnore {
		return []any{false, ""}
	}
	return ""
}

func equalLineSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func splitComments(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// ---------------------------------------------------------------------------
// file.check_file_meta

type checkFileMetaArgs struct {
	Name                    string         `statekit:"required"`
	Sfn                     *string        `statekit:"name=sfn"`
	Source                  *string        `statekit:"name=source"`
	SourceSum               map[string]any `statekit:"name=source_sum"`
	User                    *string        `statekit:"name=user"`
	Group                   *string        `statekit:"name=group"`
	Mode                    *string        `statekit:"name=mode"`
	Attrs                   *string        `statekit:"name=attrs"`
	Saltenv                 *string        `statekit:"name=saltenv"`
	Contents                *string        `statekit:"name=contents"`
	Seuser                  *string        `statekit:"name=seuser"`
	Serole                  *string        `statekit:"name=serole"`
	Setype                  *string        `statekit:"name=setype"`
	Serange                 *string        `statekit:"name=serange"`
	VerifySSL               *bool          `statekit:"name=verify_ssl"`
	FollowSymlinks          *bool          `statekit:"name=follow_symlinks"`
	IgnoreOrdering          *bool          `statekit:"name=ignore_ordering"`
	IgnoreWhitespace        *bool          `statekit:"name=ignore_whitespace"`
	IgnoreCommentCharacters *string        `statekit:"name=ignore_comment_characters"`
	NewFileDiff             *bool          `statekit:"name=new_file_diff"`
}

type checkFileMetaFunc struct{}

func (checkFileMetaFunc) Name() string { return "file.check_file_meta" }
func (checkFileMetaFunc) Args() any    { return checkFileMetaArgs{} }
func (checkFileMetaFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*checkFileMetaArgs)
	return checkFileMetaImpl(rt, a), nil
}

func (a *checkFileMetaArgs) flags() ignoreFlags {
	return ignoreFlags{
		ordering:   a.IgnoreOrdering != nil && *a.IgnoreOrdering,
		whitespace: a.IgnoreWhitespace != nil && *a.IgnoreWhitespace,
		comment:    strOrPtr(a.IgnoreCommentCharacters),
	}
}

type ignoreFlags struct {
	ordering, whitespace bool
	comment              string
}

func (f ignoreFlags) anySet() bool { return f.ordering || f.whitespace || f.comment != "" }
func (f ignoreFlags) comments() []string {
	if f.comment == "" {
		return nil
	}
	return []string{f.comment}
}

// checkFileMetaImpl mirrors check_file_meta; when any ignore_* flag is set
// the return is the (has_changes, changes) tuple like upstream.
func checkFileMetaImpl(rt *runtime.Runtime, a *checkFileMetaArgs) any {
	flags := a.flags()
	changes := map[string]any{}
	hasChanges := false
	sourceSum := a.SourceSum
	if sourceSum == nil {
		sourceSum = map[string]any{}
	}
	follow := a.FollowSymlinks != nil && *a.FollowSymlinks

	var lstats map[string]any
	var htype *string
	if v, ok := sourceSum["hash_type"].(string); ok && v != "" {
		htype = strPtr(v)
	}
	lstats, lerr := statsImpl(rt, expandUser(a.Name), htype, follow)
	if lerr != nil {
		lstats = map[string]any{}
	}
	if len(lstats) == 0 && !flags.anySet() && (a.NewFileDiff == nil || !*a.NewFileDiff) {
		changes["newfile"] = a.Name
		if flags.anySet() {
			return []any{true, changes}
		}
		return changes
	}

	if hsum, ok := sourceSum["hsum"].(string); ok {
		lsum, _ := lstats["sum"].(string)
		if hsum != lsum {
			sfn := strOrPtr(a.Sfn)
			if sfn == "" && strOrPtr(a.Source) != "" {
				cached, cerr := cacheFileDelegate(rt, strOrPtr(a.Source), strOrPtr(a.Saltenv))
				if cerr != nil {
					panic(cerr)
				}
				sfn = cached
			}
			if sfn != "" {
				if flags.anySet() {
					lines1, e1 := readLines(rt, expandUser(a.Name))
					lines2, e2 := readLines(rt, sfn)
					switch {
					case e1 != nil:
						changes["diff"] = pathErrStr(e1)
					case e2 != nil:
						changes["diff"] = pathErrStr(e2)
					default:
						hasChanges, changes["diff"] = conditionalDiff(lines1, lines2,
							flags.ordering, flags.whitespace, flags.comments())
					}
				} else if len(lstats) > 0 {
					diff := getDiffImpl(rt, "", expandUser(a.Name), sfn,
						false, true, true, "", "", false, false, "")
					changes["diff"] = diff
				} else {
					tmpEmpty, terr := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
					if terr == nil {
						changes["diff"] = getDiffImpl(rt, "", tmpEmpty, sfn,
							false, true, false, "", "", false, false, "")
						cleanTmp(rt, tmpEmpty)
					}
				}
			} else {
				changes["sum"] = "Checksum differs"
			}
		}
	}

	if a.Contents != nil {
		tmp, terr := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
		if terr != nil {
			panic(terr)
		}
		if werr := rt.FS.WriteFile(tmp, []byte(*a.Contents), 0o600); werr != nil {
			panic(werr)
		}
		var differences any
		if flags.anySet() {
			lines1, e1 := readLines(rt, expandUser(a.Name))
			lines2, e2 := readLines(rt, tmp)
			switch {
			case e1 != nil:
				differences = pathErrStr(e1)
			case e2 != nil:
				differences = pathErrStr(e2)
			default:
				hasChanges, differences = conditionalDiff(lines1, lines2,
					flags.ordering, flags.whitespace, flags.comments())
			}
		} else if len(lstats) > 0 {
			differences = getDiffImpl(rt, "", expandUser(a.Name), tmp,
				false, true, false, "", "", false, false, "")
		} else {
			tmpEmpty, terr2 := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
			if terr2 == nil {
				differences = getDiffImpl(rt, "", tmpEmpty, tmp,
					false, true, false, "", "", false, false, "")
				cleanTmp(rt, tmpEmpty)
			}
		}
		cleanTmp(rt, tmp)
		if differences != nil && differences != "" {
			if obfuscateTemplates(rt) {
				changes["diff"] = "<Obfuscated Template>"
			} else {
				changes["diff"] = differences
			}
		}
	}

	if len(lstats) == 0 {
		if flags.anySet() {
			return []any{hasChanges, changes}
		}
		return changes
	}

	userStr := strOrPtr(a.User)
	groupStr := strOrPtr(a.Group)
	if userStr != "" && !looseEqual(userStr, lstats["user"]) && !looseEqual(userStr, lstats["uid"]) {
		changes["user"] = userStr
	}
	if groupStr != "" && !looseEqual(groupStr, lstats["group"]) && !looseEqual(groupStr, lstats["gid"]) {
		changes["group"] = groupStr
	}
	smode := modeString(lstats["mode"])
	modeNorm := ""
	if a.Mode != nil {
		modeNorm = modeString(*a.Mode)
		if modeNorm != smode {
			changes["mode"] = modeNorm
		}
	}
	if a.Attrs != nil {
		if diff := cmpAttrs(rt, expandUser(a.Name), *a.Attrs); diff != nil &&
			(diff.added != "" || diff.removed != "") {
			changes["attrs"] = *a.Attrs
		}
	}
	if seuserOrRole(strOrPtr(a.Seuser), strOrPtr(a.Serole), strOrPtr(a.Setype), strOrPtr(a.Serange)) {
		ctx := getSelinuxContextImpl(rt, expandUser(a.Name))
		parts := strings.Split(ctx, ":")
		if len(parts) < 4 {
			// Upstream crashes here (ValueError then an AttributeError on
			// exc.strerror); StateKit records the failure instead — Salt bug
			// intentionally fixed per init.md section 28.
			changes["selinux"] = fmt.Sprintf("Failed to get selinux attributes for %s", a.Name)
		} else {
			currentSeuser, currentSerole, currentSetype, currentSerange :=
				parts[0], parts[1], parts[2], parts[3]
			if strOrPtr(a.Seuser) != "" && strOrPtr(a.Seuser) != currentSeuser {
				changes["selinux"] = map[string]any{"user": strOrPtr(a.Seuser)}
			}
			if strOrPtr(a.Serole) != "" && strOrPtr(a.Serole) != currentSerole {
				changes["selinux"] = map[string]any{"role": strOrPtr(a.Serole)}
			}
			if strOrPtr(a.Setype) != "" && strOrPtr(a.Setype) != currentSetype {
				changes["selinux"] = map[string]any{"type": strOrPtr(a.Setype)}
			}
			if strOrPtr(a.Serange) != "" && strOrPtr(a.Serange) != currentSerange {
				changes["selinux"] = map[string]any{"range": strOrPtr(a.Serange)}
			}
		}
	}
	if flags.anySet() {
		return []any{hasChanges, changes}
	}
	return changes
}

func seuserOrRole(vals ...string) bool {
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}

// looseEqual reproduces Python's type-sensitive equality for owner checks:
// "1000" and 1000 are never equal.
func looseEqual(a, b any) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case int:
		bv, ok := b.(int)
		return ok && av == bv
	case int64:
		bv, ok := b.(int64)
		return ok && av == bv
	}
	return false
}

// ---------------------------------------------------------------------------
// file.check_managed_changes

type checkManagedChangesArgs struct {
	Name                    string         `statekit:"required"`
	Source                  any            `statekit:"name=source"`
	SourceHash              *string        `statekit:"name=source_hash"`
	SourceHashName          *string        `statekit:"name=source_hash_name"`
	User                    *string        `statekit:"name=user"`
	Group                   *string        `statekit:"name=group"`
	Mode                    *string        `statekit:"name=mode"`
	Attrs                   *string        `statekit:"name=attrs"`
	Template                *string        `statekit:"name=template"`
	Context                 map[string]any `statekit:"name=context"`
	Defaults                map[string]any `statekit:"name=defaults"`
	Saltenv                 *string        `statekit:"name=saltenv"`
	Contents                *string        `statekit:"name=contents"`
	SkipVerify              *bool          `statekit:"name=skip_verify"`
	KeepMode                *bool          `statekit:"name=keep_mode"`
	Seuser                  *string        `statekit:"name=seuser"`
	Serole                  *string        `statekit:"name=serole"`
	Setype                  *string        `statekit:"name=setype"`
	Serange                 *string        `statekit:"name=serange"`
	VerifySSL               *bool          `statekit:"name=verify_ssl"`
	FollowSymlinks          *bool          `statekit:"name=follow_symlinks"`
	IgnoreOrdering          *bool          `statekit:"name=ignore_ordering"`
	IgnoreWhitespace        *bool          `statekit:"name=ignore_whitespace"`
	IgnoreCommentCharacters *string        `statekit:"name=ignore_comment_characters"`
	NewFileDiff             *bool          `statekit:"name=new_file_diff"`
}

type checkManagedChangesFunc struct{}

func (checkManagedChangesFunc) Name() string { return "file.check_managed_changes" }
func (checkManagedChangesFunc) Args() any    { return checkManagedChangesArgs{} }
func (checkManagedChangesFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*checkManagedChangesArgs)
	return checkManagedChangesImpl(rt, a), nil
}

func checkManagedChangesImpl(rt *runtime.Runtime, a *checkManagedChangesArgs) any {
	saltenv := strOrPtr(a.Saltenv)
	source, sourceHash := sourceListImpl(rt, a.Source, strOrPtr(a.SourceHash), saltenv)

	sfn := ""
	var sourceSum map[string]any
	if a.Contents == nil {
		sfn2, sourceSum, comments := getManagedImpl(rt, managedOpts{
			name:           expandUser(a.Name),
			template:       strOrPtr(a.Template),
			source:         source,
			sourceHash:     sourceHash,
			sourceHashName: strOrPtr(a.SourceHashName),
			skipVerify:     a.SkipVerify != nil && *a.SkipVerify,
			saltenv:        saltenv,
			sig:            map[string]any{"verify_ssl": a.VerifySSL},
		})
		sfn = sfn2
		if hsum, ok := sourceSum["hsum"].(string); ok {
			sourceSum["hsum"] = strings.ToLower(hsum)
		}
		if comments != "" {
			cleanTmp(rt, sfn)
			return []any{false, comments}
		}
		if a.KeepMode != nil && *a.KeepMode && sfn != "" && source != "" {
			scheme := strings.ToLower(schemeOf(source))
			if scheme == "salt" || scheme == "file" || scheme == "" && strings.HasPrefix(source, "/") ||
				strings.HasPrefix(source, "/") {
				if m, ok := statFileDelegate(rt, source, saltenv); ok && m != "" {
					a.Mode = strPtr(m)
				}
			}
		}
		_ = sfn
	}
	flags := ignoreFlags{
		ordering:   a.IgnoreOrdering != nil && *a.IgnoreOrdering,
		whitespace: a.IgnoreWhitespace != nil && *a.IgnoreWhitespace,
		comment:    strOrPtr(a.IgnoreCommentCharacters),
	}
	cfmArgs := &checkFileMetaArgs{
		Name: a.Name, Sfn: strPtr(sfn), Source: strPtr(source),
		SourceSum: sourceSum, User: a.User, Group: a.Group, Mode: a.Mode,
		Attrs: a.Attrs, Saltenv: a.Saltenv, Contents: a.Contents,
		Seuser: a.Seuser, Serole: a.Serole, Setype: a.Setype, Serange: a.Serange,
		VerifySSL: a.VerifySSL, FollowSymlinks: a.FollowSymlinks,
		IgnoreOrdering: a.IgnoreOrdering, IgnoreWhitespace: a.IgnoreWhitespace,
		IgnoreCommentCharacters: a.IgnoreCommentCharacters, NewFileDiff: a.NewFileDiff,
	}
	_ = flags
	cleanTmp(rt, sfn)
	return checkFileMetaImpl(rt, cfmArgs)
}

// ---------------------------------------------------------------------------
// file.check_managed

type checkManagedArgs struct {
	Name           string         `statekit:"required"`
	Source         any            `statekit:"name=source"`
	SourceHash     *string        `statekit:"name=source_hash"`
	SourceHashName *string        `statekit:"name=source_hash_name"`
	User           *string        `statekit:"name=user"`
	Group          *string        `statekit:"name=group"`
	Mode           *string        `statekit:"name=mode"`
	Attrs          *string        `statekit:"name=attrs"`
	Template       *string        `statekit:"name=template"`
	Context        map[string]any `statekit:"name=context"`
	Defaults       map[string]any `statekit:"name=defaults"`
	Saltenv        *string        `statekit:"name=saltenv"`
	Contents       *string        `statekit:"name=contents"`
	SkipVerify     *bool          `statekit:"name=skip_verify"`
	Seuser         *string        `statekit:"name=seuser"`
	Serole         *string        `statekit:"name=serole"`
	Setype         *string        `statekit:"name=setype"`
	Serange        *string        `statekit:"name=serange"`
	FollowSymlinks *bool          `statekit:"name=follow_symlinks"`
}

type checkManagedFunc struct{}

func (checkManagedFunc) Name() string { return "file.check_managed" }
func (checkManagedFunc) Args() any    { return checkManagedArgs{} }
func (checkManagedFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*checkManagedArgs)
	return checkManagedImpl(rt, a), nil
}

func checkManagedImpl(rt *runtime.Runtime, a *checkManagedArgs) any {
	saltenv := strOrPtr(a.Saltenv)
	source, sourceHash := sourceListImpl(rt, a.Source, strOrPtr(a.SourceHash), saltenv)

	sfn := ""
	if a.Contents == nil {
		sfn2, _, comments := getManagedImpl(rt, managedOpts{
			name:           expandUser(a.Name),
			template:       strOrPtr(a.Template),
			source:         source,
			sourceHash:     sourceHash,
			sourceHashName: strOrPtr(a.SourceHashName),
			skipVerify:     a.SkipVerify != nil && *a.SkipVerify,
			saltenv:        saltenv,
			sig:            map[string]any{"verify_ssl": boolPtr(true)},
		})
		sfn = sfn2
		if comments != "" {
			cleanTmp(rt, sfn)
			return []any{false, comments}
		}
	}
	cfmArgs := &checkFileMetaArgs{
		Name: a.Name, Sfn: strPtr(sfn), Source: strPtr(source),
		SourceSum: nil, User: a.User, Group: a.Group, Mode: a.Mode,
		Attrs: a.Attrs, Saltenv: a.Saltenv, Contents: a.Contents,
		Seuser: a.Seuser, Serole: a.Serole, Setype: a.Setype, Serange: a.Serange,
		VerifySSL: boolPtr(true), FollowSymlinks: a.FollowSymlinks,
	}
	changesAny := checkFileMetaImpl(rt, cfmArgs)
	changes := map[string]any{}
	if m, ok := changesAny.(map[string]any); ok {
		changes = m
	}
	// Files under the temp directory skip permission management.
	if strings.HasPrefix(expandUser(a.Name), os.TempDir()) {
		for _, key := range []string{"user", "group", "mode"} {
			delete(changes, key)
		}
	}
	cleanTmp(rt, sfn)
	if len(changes) > 0 {
		keys := make([]string, 0, len(changes))
		for k := range changes {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic ordering; upstream keeps insertion order
		var comments strings.Builder
		comments.WriteString("The following values are set to be changed:\n")
		for _, k := range keys {
			fmt.Fprintf(&comments, "%s: %v\n", k, changes[k])
		}
		return []any{nil, comments.String()}
	}
	return []any{true, fmt.Sprintf("The file %s is in the correct state", a.Name)}
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// file.check_perms

type checkPermsArgs struct {
	Name           string         `statekit:"required"`
	Ret            map[string]any `statekit:"name=ret"`
	User           *string        `statekit:"name=user"`
	Group          *string        `statekit:"name=group"`
	Mode           *string        `statekit:"name=mode"`
	Attrs          *string        `statekit:"name=attrs"`
	FollowSymlinks *bool          `statekit:"name=follow_symlinks"`
	Seuser         *string        `statekit:"name=seuser"`
	Serole         *string        `statekit:"name=serole"`
	Setype         *string        `statekit:"name=setype"`
	Serange        *string        `statekit:"name=serange"`
}

type checkPermsFunc struct{}

func (checkPermsFunc) Name() string { return "file.check_perms" }
func (checkPermsFunc) Args() any    { return checkPermsArgs{} }
func (checkPermsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*checkPermsArgs)
	ret := retFromMap(a.Ret, expandUser(a.Name))
	out, perms := checkPermsImpl(rt, a.Name, ret,
		strOrPtr(a.User), strOrPtr(a.Group), modeArg(a.Mode), strOrPtr(a.Attrs),
		a.FollowSymlinks != nil && *a.FollowSymlinks,
		strOrPtr(a.Seuser), strOrPtr(a.Serole), strOrPtr(a.Setype), strOrPtr(a.Serange))
	return []any{out.toMap(), perms}, nil
}

func modeArg(m *string) any {
	if m == nil {
		return nil
	}
	return *m
}

func isDir(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && info.IsDir()
}

func isLink(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Lstat(path)
	return err == nil && info.Mode()&fs.ModeSymlink != 0
}

func setModeImpl(rt *runtime.Runtime, path string, mode any) error {
	return chmodMode(rt, path, modeString(mode))
}

func chownAny(rt *runtime.Runtime, path string, user, group any, useLchown bool) error {
	resolve := func(v any, lookup func(string) (int, bool)) (int, bool, error) {
		switch t := v.(type) {
		case nil:
			return -1, false, nil
		case int:
			return t, true, nil
		case int64:
			return int(t), true, nil
		case string:
			if t == "" {
				return -1, false, nil
			}
			id, ok := lookup(t)
			if !ok {
				return -1, false, fmt.Errorf("name lookup failed for %q", t)
			}
			return id, true, nil
		}
		return -1, false, nil
	}
	uid, hasUID, uerr := resolve(user, func(name string) (int, bool) {
		u, err := user2.Lookup(name)
		if err != nil {
			return 0, false
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			return 0, false
		}
		return id, true
	})
	if uerr != nil {
		return fmt.Errorf("user %v not found", user)
	}
	gid, hasGID, gerr := resolve(group, func(name string) (int, bool) {
		g, err := user2.LookupGroup(name)
		if err != nil {
			return 0, false
		}
		id, err := strconv.Atoi(g.Gid)
		if err != nil {
			return 0, false
		}
		return id, true
	})
	if gerr != nil {
		return fmt.Errorf("group %v not found", group)
	}
	uidVal, gidVal := -1, -1
	if hasUID {
		uidVal = uid
	}
	if hasGID {
		gidVal = gid
	}
	if useLchown {
		return rt.FS.Lchown(path, uidVal, gidVal)
	}
	return rt.FS.Chown(path, uidVal, gidVal)
}

func checkPermsImpl(rt *runtime.Runtime, name string, ret *metaRet,
	user, group string, mode any, attrs string, followSymlinks bool,
	seuser, serole, setype, serange string) (*metaRet, map[string]any) {

	name = expandUser(name)
	mode = normalizeAny(mode)
	perms := map[string]any{}

	cur, serr := statsImpl(rt, name, nil, followSymlinks)
	if serr != nil {
		panicCmdExec(serr.Error())
	}
	isLinkPath := isLink(rt, name)

	perms["luser"] = cur["user"]
	perms["lgroup"] = cur["group"]
	perms["lmode"] = cur["mode"]

	isDirPath := isDir(rt, name)

	if user != "" && !looseEqual(user, cur["user"]) && !looseEqual(user, cur["uid"]) {
		perms["cuser"] = user
	}
	if group != "" && !looseEqual(group, cur["group"]) && !looseEqual(group, cur["gid"]) {
		perms["cgroup"] = group
	}

	if _, hasCuser := perms["cuser"]; hasCuser {
		applyChown(rt, name, ret, cur, isLinkPath && !followSymlinks, user, group)
	} else if _, hasCgroup := perms["cgroup"]; hasCgroup {
		applyChown(rt, name, ret, cur, isLinkPath && !followSymlinks, user, group)
	}

	// Mode changes if needed
	if mode != nil {
		if !testMode(rt) {
			if !(isLinkPath && !followSymlinks) {
				if modeString(mode) != modeString(cur["mode"]) {
					perms["cmode"] = mode
					setModeImpl(rt, name, mode)
				}
			}
		}
	}

	// verify user/group/mode changes
	post, perr := statsImpl(rt, name, nil, followSymlinks)
	if perr != nil {
		panicCmdExec(perr.Error())
	}
	if user != "" {
		if !looseEqual(user, post["user"]) && !looseEqual(user, post["uid"]) {
			if testMode(rt) {
				ret.Changes["user"] = user
			} else {
				ret.Result = triFalse()
				ret.Comment = append(ret.Comment, fmt.Sprintf("Failed to change user to %s", user))
			}
		} else if _, ok := perms["cuser"]; ok {
			ret.Changes["user"] = user
		}
	}
	if group != "" {
		if !looseEqual(group, post["group"]) && !looseEqual(group, post["gid"]) {
			if testMode(rt) {
				ret.Changes["group"] = group
			} else {
				ret.Result = triFalse()
				ret.Comment = append(ret.Comment, fmt.Sprintf("Failed to change group to %s", group))
			}
		} else if _, ok := perms["cgroup"]; ok {
			ret.Changes["group"] = group
		}
	}
	if mode != nil {
		if !(isLinkPath && !followSymlinks) {
			if modeString(mode) != modeString(post["mode"]) {
				if testMode(rt) {
					ret.Changes["mode"] = mode
				} else {
					ret.Result = triFalse()
					ret.Comment = append(ret.Comment, fmt.Sprintf("Failed to change mode to %s", modeString(mode)))
				}
			} else if _, ok := perms["cmode"]; ok {
				ret.Changes["mode"] = mode
			}
		}
	}

	// attrs
	if attrs != "" && !isDirPath {
		if !(isLinkPath && !followSymlinks) {
			diffAttrs := cmpAttrs(rt, name, attrs)
			if diffAttrs != nil && (diffAttrs.added != "" || diffAttrs.removed != "") {
				lattrs, _, lerr := lsattrImpl(rt, name)
				oldStr := ""
				if lerr == nil && lattrs != nil {
					if vals, found := lattrs[name]; found {
						oldStr = strings.Join(vals, "")
					}
				}
				changes := map[string]any{"old": oldStr, "new": nil}
				if testMode(rt) {
					changes["new"] = attrs
				} else {
					if diffAttrs.added != "" {
						chattrImpl(rt, []string{name}, "add", diffAttrs.added, "", "")
					}
					if diffAttrs.removed != "" {
						chattrImpl(rt, []string{name}, "remove", diffAttrs.removed, "", "")
					}
					cmpAgain := cmpAttrs(rt, name, attrs)
					if cmpAgain != nil && (cmpAgain.added != "" || cmpAgain.removed != "") {
						ret.Result = triFalse()
						ret.Comment = append(ret.Comment, fmt.Sprintf("Failed to change attributes to %s", attrs))
						lattrs2, _, _ := lsattrImpl(rt, name)
						if lattrs2 != nil {
							if vals, found := lattrs2[name]; found {
								changes["new"] = strings.Join(vals, "")
							}
						}
					} else {
						changes["new"] = attrs
					}
				}
				if changes["old"] != changes["new"] {
					ret.Changes["attrs"] = changes
				}
			}
		}
	}

	// selinux
	if goosIdent() == "linux" && seuserOrRole(seuser, serole, setype, serange) {
		ctx := getSelinuxContextImpl(rt, name)
		parts := strings.Split(ctx, ":")
		selinuxError := false
		var currentSeuser, currentSerole, currentSetype, currentSerange string
		if len(parts) < 4 {
			// Upstream logs the failure; StateKit mirrors the comment.
			ret.Result = triFalse()
			ret.Comment = append(ret.Comment, "Failed to get selinux attributes")
			selinuxError = true
		} else {
			currentSeuser, currentSerole, currentSetype, currentSerange =
				parts[0], parts[1], parts[2], parts[3]
		}
		if !selinuxError {
			requestedSeuser := ""
			requestedSerole := ""
			requestedSetype := ""
			requestedSerange := ""
			if seuser != "" && seuser != currentSeuser {
				requestedSeuser = seuser
			}
			if serole != "" && serole != currentSerole {
				requestedSerole = serole
			}
			if setype != "" && setype != currentSetype {
				requestedSetype = setype
			}
			if serange != "" && serange != currentSerange {
				requestedSerange = serange
			}
			if seuserOrRole(requestedSeuser, requestedSerole, requestedSetype, requestedSerange) {
				selinuxChangeNew := ""
				selinuxChangeOrig := ""
				if requestedSeuser != "" {
					selinuxChangeNew += fmt.Sprintf("User: %s ", requestedSeuser)
					selinuxChangeOrig += fmt.Sprintf("User: %s ", currentSeuser)
				}
				if requestedSerole != "" {
					selinuxChangeNew += fmt.Sprintf("Role: %s ", requestedSerole)
					selinuxChangeOrig += fmt.Sprintf("Role: %s ", currentSerole)
				}
				if requestedSetype != "" {
					selinuxChangeNew += fmt.Sprintf("Type: %s ", requestedSetype)
					selinuxChangeOrig += fmt.Sprintf("Type: %s ", currentSetype)
				}
				if requestedSerange != "" {
					selinuxChangeNew += fmt.Sprintf("Range: %s ", requestedSerange)
					selinuxChangeOrig += fmt.Sprintf("Range: %s ", currentSerange)
				}
				if testMode(rt) {
					ret.Comment = append(ret.Comment, fmt.Sprintf("File %s selinux context to be updated", name))
					ret.Result = nil
					ret.Changes["selinux"] = map[string]any{
						"Old": strings.TrimRight(selinuxChangeOrig, " "),
						"New": strings.TrimRight(selinuxChangeNew, " "),
					}
				} else {
					if (requestedSeuser != "" || requestedSerole != "" || requestedSerange != "") &&
						requestedSetype == "" {
						requestedSetype = currentSetype
					}
					result, err := setSelinuxContextImpl(rt, name,
						optStr(requestedSeuser), optStr(requestedSerole),
						optStr(requestedSetype), optStr(requestedSerange), true)
					if err != nil {
						ret.Result = triFalse()
						ret.Comment = append(ret.Comment, "Failed to set selinux attributes")
						selinuxError = true
					} else if s, ok := result.(string); ok {
						rparts := strings.Split(s, ":")
						if len(rparts) < 4 {
							ret.Result = triFalse()
							ret.Comment = append(ret.Comment, "Failed to set selinux attributes")
							selinuxError = true
						} else {
							currentSeuser, currentSerole, currentSetype, currentSerange =
								rparts[0], rparts[1], rparts[2], rparts[3]
						}
					}
					if !selinuxError {
						ret.Comment = append(ret.Comment, fmt.Sprintf("The file %s is set to be changed", name))
						if requestedSeuser != "" && currentSeuser != requestedSeuser {
							ret.Comment = append(ret.Comment, "Unable to update seuser context")
							ret.Result = triFalse()
						}
						if requestedSerole != "" && currentSerole != requestedSerole {
							ret.Comment = append(ret.Comment, "Unable to update serole context")
							ret.Result = triFalse()
						}
						if requestedSetype != "" && currentSetype != requestedSetype {
							ret.Comment = append(ret.Comment, "Unable to update setype context")
							ret.Result = triFalse()
						}
						if requestedSerange != "" && currentSerange != requestedSerange {
							ret.Comment = append(ret.Comment, "Unable to update serange context")
							ret.Result = triFalse()
						}
						ret.Changes["selinux"] = map[string]any{
							"Old": strings.TrimRight(selinuxChangeOrig, " "),
							"New": strings.TrimRight(selinuxChangeNew, " "),
						}
					}
				}
			}
		}
	}

	if testMode(rt) && len(ret.Changes) > 0 {
		ret.Result = nil
	}
	return ret, perms
}

func applyChown(rt *runtime.Runtime, name string, ret *metaRet,
	cur map[string]any, useLchown bool, user, group string) {
	if !testMode(rt) {
		curUser := anyOrStr(user, cur["user"])
		curGroup := anyOrStr(group, cur["group"])
		err := chownAny(rt, name, curUser, curGroup, useLchown)
		if err != nil {
			ret.Result = triFalse()
			ret.Comment = append(ret.Comment, err.Error())
		} else if !useLchown || !isLink(rt, name) {
			// Python os.chown resets suid/sgid; restore the previous mode.
			setModeImpl(rt, name, cur["mode"])
		}
	}
}

// anyOrStr keeps an explicit value or falls back to the current stat value,
// preserving upstream's ability to pass numeric uids through os.chown.
func anyOrStr(explicit string, fallback any) any {
	if explicit != "" {
		return explicit
	}
	return fallback
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---------------------------------------------------------------------------
// chattr internals + public lsattr/chattr/lchown

// chattrImpl mirrors the chattr() body: argv assembly and success contract
// (empty output means success).
func chattrImpl(rt *runtime.Runtime, files []string, operator, attributes, flags, version string) bool {
	if operator != "add" && operator != "remove" {
		panicCmdExec("Need an operator: 'add' or 'remove' to modify attributes.")
	}
	if attributes == "" {
		panicCmdExec("Need attributes: [aAcCdDeijPsStTu]")
	}
	cmd := []string{"chattr"}
	switch operator {
	case "add":
		cmd = append(cmd, "+"+attributes)
	case "remove":
		cmd = append(cmd, "-"+attributes)
	}
	if flags != "" {
		cmd = append(cmd, "-"+flags)
	}
	if version != "" {
		cmd = append(cmd, "-v", version)
	}
	cmd = append(cmd, files...)
	res := rt.Runner.Run(context.Background(), runtime.Command(cmd...))
	return string(res.Stdout) == ""
}

type lsattrArgs struct {
	Path string `statekit:"required,name=path"`
}

type lsattrFunc struct{}

func (lsattrFunc) Name() string { return "file.lsattr" }
func (lsattrFunc) Args() any    { return lsattrArgs{} }
func (lsattrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*lsattrArgs)
	results, ok, err := lsattrImpl(rt, expandUser(a.Path))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return results, nil
}

type chattrArgs struct {
	Files      []string `statekit:"required,name=files"`
	Operator   *string  `statekit:"name=operator"`
	Attributes *string  `statekit:"name=attributes"`
	Flags      *string  `statekit:"name=flags"`
	Version    *string  `statekit:"name=version"`
}

type chattrFunc struct{}

func (chattrFunc) Name() string { return "file.chattr" }
func (chattrFunc) Args() any    { return chattrArgs{} }
func (chattrFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*chattrArgs)
	ok := chattrImpl(rt, a.Files,
		strOrPtr(a.Operator), strOrPtr(a.Attributes),
		strOrPtr(a.Flags), strOrPtr(a.Version))
	return ok, nil
}

type lchownArgs struct {
	Path  string  `statekit:"required,name=path"`
	User  *string `statekit:"name=user"`
	Group *string `statekit:"name=group"`
}

type lchownFunc struct{}

func (lchownFunc) Name() string { return "file.lchown" }
func (lchownFunc) Args() any    { return lchownArgs{} }
func (lchownFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*lchownArgs)
	path := expandUser(a.Path)
	var userVal, groupVal any
	if a.User != nil {
		userVal = *a.User
	}
	if a.Group != nil {
		groupVal = *a.Group
	}
	if err := chownAny(rt, path, userVal, groupVal, true); err != nil {
		return "", fmt.Errorf("chown failed: %w", err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// SELinux public wrappers

type getSelinuxContextArgs struct {
	Path string `statekit:"required,name=path"`
}

type getSelinuxContextFunc struct{}

func (getSelinuxContextFunc) Name() string { return "file.get_selinux_context" }
func (getSelinuxContextFunc) Args() any    { return getSelinuxContextArgs{} }
func (getSelinuxContextFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*getSelinuxContextArgs)
	return getSelinuxContextImpl(rt, expandUser(a.Path)), nil
}

type setSelinuxContextArgs struct {
	Path    string  `statekit:"required,name=path"`
	User    *string `statekit:"name=user"`
	Role    *string `statekit:"name=role"`
	Type    *string `statekit:"name=type"`
	Range   *string `statekit:"name=range"`
	Persist *bool   `statekit:"name=persist"`
}

type setSelinuxContextFunc struct{}

func (setSelinuxContextFunc) Name() string { return "file.set_selinux_context" }
func (setSelinuxContextFunc) Args() any    { return setSelinuxContextArgs{} }
func (setSelinuxContextFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setSelinuxContextArgs)
	persist := a.Persist != nil && *a.Persist
	return setSelinuxContextImpl(rt, expandUser(a.Path), a.User, a.Role, a.Type, a.Range, persist)
}

type restoreconArgs struct {
	Path      string `statekit:"required,name=path"`
	Recursive *bool  `statekit:"name=recursive"`
}

type restoreconFunc struct{}

func (restoreconFunc) Name() string { return "file.restorecon" }
func (restoreconFunc) Args() any    { return restoreconArgs{} }
func (restoreconFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*restoreconArgs)
	cmd := []string{"restorecon", "-F"}
	if a.Recursive != nil && *a.Recursive {
		cmd = []string{"restorecon", "-FR"}
	}
	cmd = append(cmd, expandUser(a.Path))
	res := rt.Runner.Run(context.Background(), runtime.Command(cmd...))
	return res.OK(), nil
}

// ---------------------------------------------------------------------------
// file.manage_file

type manageFileArgs struct {
	Name                    string         `statekit:"required"`
	Sfn                     *string        `statekit:"name=sfn"`
	Ret                     map[string]any `statekit:"name=ret"`
	Source                  *string        `statekit:"name=source"`
	SourceSum               map[string]any `statekit:"name=source_sum"`
	User                    *string        `statekit:"name=user"`
	Group                   *string        `statekit:"name=group"`
	Mode                    *string        `statekit:"name=mode"`
	Attrs                   *string        `statekit:"name=attrs"`
	Saltenv                 *string        `statekit:"name=saltenv"`
	Backup                  *string        `statekit:"name=backup"`
	Makedirs                *bool          `statekit:"name=makedirs"`
	Template                *string        `statekit:"name=template"`
	ShowChanges             *bool          `statekit:"name=show_changes"`
	Contents                *string        `statekit:"name=contents"`
	DirMode                 *string        `statekit:"name=dir_mode"`
	FollowSymlinks          *bool          `statekit:"name=follow_symlinks"`
	SkipVerify              *bool          `statekit:"name=skip_verify"`
	KeepMode                *bool          `statekit:"name=keep_mode"`
	Encoding                *string        `statekit:"name=encoding"`
	EncodingErrors          *string        `statekit:"name=encoding_errors"`
	Seuser                  *string        `statekit:"name=seuser"`
	Serole                  *string        `statekit:"name=serole"`
	Setype                  *string        `statekit:"name=setype"`
	Serange                 *string        `statekit:"name=serange"`
	VerifySSL               *bool          `statekit:"name=verify_ssl"`
	UseEtag                 *bool          `statekit:"name=use_etag"`
	Signature               *string        `statekit:"name=signature"`
	SourceHashSig           *string        `statekit:"name=source_hash_sig"`
	SignedByAny             *string        `statekit:"name=signed_by_any"`
	SignedByAll             *string        `statekit:"name=signed_by_all"`
	Keyring                 *string        `statekit:"name=keyring"`
	Gnupghome               *string        `statekit:"name=gnupghome"`
	IgnoreOrdering          *bool          `statekit:"name=ignore_ordering"`
	IgnoreWhitespace        *bool          `statekit:"name=ignore_whitespace"`
	IgnoreCommentCharacters *string        `statekit:"name=ignore_comment_characters"`
	NewFileDiff             *bool          `statekit:"name=new_file_diff"`
	SigBackend              *string        `statekit:"name=sig_backend"`
}

type manageFileFunc struct{}

func (manageFileFunc) Name() string { return "file.manage_file" }
func (manageFileFunc) Args() any    { return manageFileArgs{} }
func (manageFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMeta(&res, &err)
	a := args.(*manageFileArgs)
	ret := manageFileImpl(rt, a)
	return ret.toMap(), nil
}

func (a *manageFileArgs) flags() ignoreFlags {
	return ignoreFlags{
		ordering:   a.IgnoreOrdering != nil && *a.IgnoreOrdering,
		whitespace: a.IgnoreWhitespace != nil && *a.IgnoreWhitespace,
		comment:    strOrPtr(a.IgnoreCommentCharacters),
	}
}

func manageFileImpl(rt *runtime.Runtime, a *manageFileArgs) *metaRet {
	name := expandUser(a.Name)
	hasChanges := false
	flags := a.flags()
	source := strOrPtr(a.Source)
	saltenv := strOrPtr(a.Saltenv)
	followSymlinks := a.FollowSymlinks == nil || *a.FollowSymlinks
	showChanges := a.ShowChanges == nil || *a.ShowChanges

	if serr := ensureNoSigParams(map[string]any{
		"signature": a.Signature, "sig": a.SourceHashSig,
		"any": a.SignedByAny, "all": a.SignedByAll,
		"keyring": a.Keyring, "gnupghome": a.Gnupghome,
	}); serr != nil {
		panic(serr)
	}
	if enc := strOrPtr(a.Encoding); enc != "" && enc != "utf-8" && enc != "utf8" {
		// Python codecs are not reproduced; only UTF-8 passes through.
		panic(&runtime.UnsupportedError{Kind: "function", Name: "codecs.encode"})
	}

	checkWebSourceHash := source != "" &&
		strings.ToLower(schemeOf(source)) != "salt" &&
		!(a.SkipVerify != nil && *a.SkipVerify) &&
		!(a.UseEtag != nil && *a.UseEtag)

	ret := retFromMap(a.Ret, name)
	// upstream manage_file starts from an empty comment accumulator and
	// keeps the incoming string as orig_comment for the final join.
	ret.Comment = nil

	sourceSum := a.SourceSum
	if sourceSum != nil {
		if hsum, ok := sourceSum["hsum"].(string); ok {
			sourceSum["hsum"] = strings.ToLower(hsum)
		}
	}

	sfn := strOrPtr(a.Sfn)
	defaultHashType := func() string {
		if v, ok := configOptionAny(rt, "hash_type"); ok {
			if s, isStr := v.(string); isStr && s != "" {
				return s
			}
		}
		return "sha256"
	}

	if source != "" {
		if sfn == "" {
			cached, cerr := cacheFileDelegate(rt, source, saltenv)
			if cerr != nil || cached == "" {
				panicRetErr(ret, fmt.Sprintf("Source file '%s' not found", source))
			}
			sfn = cached
			htype := defaultHashType()
			if v, ok := sourceSum["hash_type"].(string); ok && v != "" {
				htype = v
			}
			sum, _ := getHashFunc{}.Execute(context.Background(), rt,
				&getHashArgs{Path: sfn, Form: strPtr(htype)})
			sourceSum = map[string]any{"hash_type": htype, "hsum": sum}
		}
		if a.KeepMode != nil && *a.KeepMode {
			scheme := strings.ToLower(schemeOf(source))
			if scheme == "salt" || scheme == "file" || scheme == "" {
				if m, ok := statFileDelegate(rt, source, saltenv); ok && m != "" {
					a.Mode = strPtr(m)
				}
			}
		}
	}

	targetIsFile := false
	targetIsLink := false
	if info, err := rt.FS.Stat(name); err == nil && info.Mode().IsRegular() {
		targetIsFile = true
	}
	targetIsLink = isLink(rt, name)

	if targetIsFile || targetIsLink {
		realName := name
		if targetIsLink && followSymlinks {
			realName = resolveTarget(rt, name, true)
		}
		var nameSum any
		if source != "" && !(!followSymlinks && isLink(rt, realName)) {
			htype := defaultHashType()
			if v, ok := sourceSum["hash_type"].(string); ok && v != "" {
				htype = v
			}
			res, herr := getHashFunc{}.Execute(context.Background(), rt,
				&getHashArgs{Path: realName, Form: strPtr(htype)})
			if herr == nil {
				nameSum = res
			}
		}
		needsReplace := false
		if source != "" {
			if nameSum == nil {
				needsReplace = true
			} else {
				want, ok := sourceSum["hsum"].(string)
				if !ok {
					want = defaultHashType()
				}
				needsReplace = want != nameSum.(string)
			}
		}
		if needsReplace {
			if sfn == "" {
				cached, cerr := cacheFileDelegate(rt, source, saltenv)
				if cerr != nil || cached == "" {
					panicRetErr(ret, fmt.Sprintf("Source file '%s' not found", source))
				}
				sfn = cached
			}
			if checkWebSourceHash {
				dlSum, _ := getHashFunc{}.Execute(context.Background(), rt,
					&getHashArgs{Path: sfn, Form: strPtr(sourceSumType(sourceSum, defaultHashType()))})
				if dlSum != sourceSum["hsum"] {
					ret.OrigComment = fmt.Sprintf(
						"Specified %s checksum for %s (%s) does not match "+
							"actual checksum (%s). If the 'source_hash' value "+
							"refers to a remote file with multiple possible "+
							"matches, then it may be necessary to set "+
							"'source_hash_name'.",
						sourceSum["hash_type"], source, sourceSum["hsum"], dlSum)
					ret.Result = triFalse()
					return ret
				}
			}
			if obfuscateTemplates(rt) {
				ret.Changes["diff"] = "<Obfuscated Template>"
			} else if !showChanges {
				ret.Changes["diff"] = "<show_changes=False>"
			} else {
				if flags.anySet() {
					lines1, e1 := readLines(rt, realName)
					lines2, e2 := readLines(rt, sfn)
					switch {
					case e1 != nil:
						ret.Changes["diff"] = pathErrStr(e1)
					case e2 != nil:
						ret.Changes["diff"] = pathErrStr(e2)
					default:
						hc, diffText := conditionalDiff(lines1, lines2,
							flags.ordering, flags.whitespace, flags.comments())
						hasChanges = hc
						if diffText != "" {
							ret.Changes["diff"] = diffText
						}
					}
				} else {
					diff := getDiffImpl(rt, "", realName, sfn,
						false, true, false, "", "", false, false, "")
					if diff != "" {
						ret.Changes["diff"] = diff
					}
				}
			}
			if cerr := copyfileImpl(rt, sfn, realName,
				backupModeOf(rt, strOrPtr(a.Backup)), cachedirOf(rt)); cerr != nil {
				cleanTmp(rt, sfn)
				panicRetErr(ret, fmt.Sprintf("Failed to commit change: %s", cerr.Error()))
			}
		}

		if a.Contents != nil {
			tmp, terr := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
			if terr != nil {
				panic(terr)
			}
			if werr := rt.FS.WriteFile(tmp, []byte(*a.Contents), 0o600); werr != nil {
				panic(werr)
			}
			var differences any
			if flags.anySet() {
				lines1, e1 := readLines(rt, realName)
				lines2, e2 := readLines(rt, tmp)
				switch {
				case e1 != nil:
					ret.Warnings = append(ret.Warnings,
						fmt.Sprintf("Failed to detect changes to file: %s", pathErrStr(e1)))
					differences = ""
				case e2 != nil:
					ret.Warnings = append(ret.Warnings,
						fmt.Sprintf("Failed to detect changes to file: %s", pathErrStr(e2)))
					differences = ""
				default:
					hasChanges, differences = conditionalDiff(lines1, lines2,
						flags.ordering, flags.whitespace, flags.comments())
				}
			} else {
				differences = getDiffImpl(rt, "", realName, tmp,
					false, showChanges, true, "", "", false, false, "")
			}
			if differences != nil && differences != "" {
				ret.Changes["diff"] = differences
				if cerr := copyfileImpl(rt, tmp, realName,
					backupModeOf(rt, strOrPtr(a.Backup)), cachedirOf(rt)); cerr != nil {
					cleanTmp(rt, tmp)
					panicRetErr(ret, fmt.Sprintf("Failed to commit change: %s", cerr.Error()))
				}
			}
			cleanTmp(rt, tmp)
		}

		if targetIsLink && !followSymlinks {
			if sfn == "" {
				cached, cerr := cacheFileDelegate(rt, source, saltenv)
				if cerr != nil || cached == "" {
					panicRetErr(ret, fmt.Sprintf("Source file '%s' not found", source))
				}
				sfn = cached
			}
			if checkWebSourceHash {
				dlSum, _ := getHashFunc{}.Execute(context.Background(), rt,
					&getHashArgs{Path: sfn, Form: strPtr(sourceSumType(sourceSum, defaultHashType()))})
				if dlSum != sourceSum["hsum"] {
					ret.OrigComment = fmt.Sprintf(
						"Specified %s checksum for %s (%s) does not match actual checksum (%s)",
						sourceSum["hash_type"], name, sourceSum["hsum"], dlSum)
					ret.Result = triFalse()
					return ret
				}
			}
			if cerr := copyfileImpl(rt, sfn, name,
				backupModeOf(rt, strOrPtr(a.Backup)), cachedirOf(rt)); cerr != nil {
				cleanTmp(rt, sfn)
				panicRetErr(ret, fmt.Sprintf("Failed to commit change: %s", cerr.Error()))
			}
			ret.Changes["diff"] = "Replace symbolic link with regular file"
		}

		out, _ := checkPermsImpl(rt, name, ret,
			strOrPtr(a.User), strOrPtr(a.Group), modeArg(a.Mode), strOrPtr(a.Attrs),
			followSymlinks, strOrPtr(a.Seuser), strOrPtr(a.Serole),
			strOrPtr(a.Setype), strOrPtr(a.Serange))

		if len(out.Changes) > 0 {
			out.Comment = nil // recomputed below via OrigComment join
			out.OrigComment = fmt.Sprintf("File %s updated", name)
			if flags.anySet() && !hasChanges {
				out.SkipReq = true
			}
		} else if len(out.Changes) == 0 && out.Result != nil && *out.Result {
			out.Comment = nil
			out.OrigComment = fmt.Sprintf("File %s is in the correct state", name)
		}
		cleanTmp(rt, sfn)
		return out
	}

	// Target file does not exist.
	containDir := filepath.Dir(name)
	setModeAndMakeDirs := func() {
		dirMode := strOrPtr(a.DirMode)
		mode := modeArg(a.Mode)
		if dirMode == "" && mode != nil {
			modeList := []rune(fmt.Sprintf("%v", mode))
			if len(modeList) > 3 {
				modeList = modeList[len(modeList)-3:]
			}
			for idx, part := range modeList {
				if part != '0' {
					n, _ := strconv.Atoi(string(part))
					modeList[idx] = rune('0' + n | 1)
				}
			}
			dirMode = string(modeList)
		}
		var modePtr *string
		if dirMode != "" {
			modePtr = strPtr(dirMode)
		}
		makedirsFunc{}.Execute(context.Background(), rt, &makedirsArgs{
			Path: name + "/", User: a.User, Group: a.Group,
			Mode: modePtr,
		})
	}

	if source != "" {
		if sfn == "" {
			cached, cerr := cacheFileDelegate(rt, source, saltenv)
			if cerr != nil || cached == "" {
				panicRetErr(ret, fmt.Sprintf("Source file '%s' not found", source))
			}
			sfn = cached
		}
		if checkWebSourceHash {
			dlSum, _ := getHashFunc{}.Execute(context.Background(), rt,
				&getHashArgs{Path: sfn, Form: strPtr(sourceSumType(sourceSum, defaultHashType()))})
			if dlSum != sourceSum["hsum"] {
				ret.OrigComment = fmt.Sprintf(
					"Specified %s checksum for %s (%s) does not match actual checksum (%s)",
					sourceSum["hash_type"], name, sourceSum["hsum"], dlSum)
				ret.Result = triFalse()
				return ret
			}
		}
		ret.Changes["diff"] = "New file"
		if a.NewFileDiff != nil && *a.NewFileDiff {
			tmpEmpty, terr := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
			if terr == nil {
				ret.Changes["diff"] = getDiffImpl(rt, "", tmpEmpty, sfn,
					false, true, false, "", "", false, false, "")
				cleanTmp(rt, tmpEmpty)
			}
		}
		if !isDir(rt, containDir) {
			if a.Makedirs != nil && *a.Makedirs {
				setModeAndMakeDirs()
			} else {
				cleanTmp(rt, sfn)
				delete(ret.Changes, "diff")
				panicRetErr(ret, "Parent directory not present")
			}
		}
	} else {
		if !isDir(rt, containDir) {
			if a.Makedirs != nil && *a.Makedirs {
				setModeAndMakeDirs()
			} else {
				cleanTmp(rt, sfn)
				delete(ret.Changes, "diff")
				panicRetErr(ret, "Parent directory not present")
			}
		}
		if a.Contents == nil {
			if !testMode(rt) {
				tres, terr := touchFunc{}.Execute(context.Background(), rt,
					&touchNameArgs{Name: name})
				if terr != nil || tres != true {
					panicCmdExec(fmt.Sprintf("Empty file %s not created", name))
				}
				ret.Changes["new"] = fmt.Sprintf("file %s created", name)
				ret.OrigComment = "Empty file"
			}
		} else {
			if !testMode(rt) {
				tres, terr := touchFunc{}.Execute(context.Background(), rt,
					&touchNameArgs{Name: name})
				if terr != nil || tres != true {
					panicCmdExec(fmt.Sprintf("File %s not created", name))
				}
				ret.Changes["diff"] = "New file"
			}
		}
	}

	if a.Contents != nil {
		tmp, terr := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
		if terr != nil {
			panic(terr)
		}
		if werr := rt.FS.WriteFile(tmp, []byte(*a.Contents), 0o600); werr != nil {
			panic(werr)
		}
		if a.NewFileDiff != nil && *a.NewFileDiff && ret.Changes["diff"] == "New file" {
			tmpEmpty, terr2 := mkstempNamed(rt, os.TempDir(), "__salt.tmp.")
			if terr2 == nil {
				ret.Changes["diff"] = getDiffImpl(rt, "", tmpEmpty, tmp,
					false, true, false, "", "", false, false, "")
				cleanTmp(rt, tmpEmpty)
			}
		}
		copyfileImpl(rt, tmp, name, backupModeOf(rt, strOrPtr(a.Backup)), cachedirOf(rt))
		cleanTmp(rt, tmp)
	} else if sfn != "" {
		copyfileImpl(rt, sfn, name, backupModeOf(rt, strOrPtr(a.Backup)), cachedirOf(rt))
		cleanTmp(rt, sfn)
	}

	mode := modeArg(a.Mode)
	if mode == nil && goosIdent() != "windows" {
		old := currentUmask()
		newMode := (0o777 &^ old) & 0o666
		mode = fmt.Sprintf("%04o", newMode)
	}

	out, _ := checkPermsImpl(rt, name, ret,
		strOrPtr(a.User), strOrPtr(a.Group), mode, strOrPtr(a.Attrs),
		false, strOrPtr(a.Seuser), strOrPtr(a.Serole),
		strOrPtr(a.Setype), strOrPtr(a.Serange))

	if len(out.Comment) == 0 && out.OrigComment == "" {
		out.OrigComment = "File " + name + " updated"
	}
	if testMode(rt) {
		out.OrigComment = "File " + name + " not updated"
		out.Comment = nil
	} else if len(out.Changes) == 0 && out.Result != nil && *out.Result {
		out.OrigComment = "File " + name + " is in the correct state"
		out.Comment = nil
	}
	cleanTmp(rt, sfn)

	if flags.anySet() && len(out.Changes) > 0 && !hasChanges {
		out.SkipReq = true
	}
	return out
}

func sourceSumType(sourceSum map[string]any, def string) string {
	if v, ok := sourceSum["hash_type"].(string); ok && v != "" {
		return v
	}
	return def
}

func backupModeOf(rt *runtime.Runtime, backup string) string {
	if backup != "" {
		return backup
	}
	return configOptionStr(rt, "backup_mode")
}

// RegisterMeta installs the R4.7 managed-source meta family.
func RegisterMeta(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		sourceListFunc{},
		getManagedFunc{},
		getSourceSumFunc{},
		getDiffFunc{},
		checkFileMetaFunc{},
		checkManagedChangesFunc{},
		checkManagedFunc{},
		checkPermsFunc{},
		manageFileFunc{},
		lsattrFunc{},
		chattrFunc{},
		lchownFunc{},
		getSelinuxContextFunc{},
		setSelinuxContextFunc{},
		restoreconFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
