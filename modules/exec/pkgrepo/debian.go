package pkgrepo

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// Debian APT sources engine: a contract port of salt/utils/pkg/deb.py @
// pinned revision (references/salt.lock). SourceEntry/SourcesList/
// Deb822SourceEntry/Deb822Section mirror the upstream classes including
// their serialization quirks; every file operation flows through
// runtime.Runtime.FS so suites run hermetically.

// System paths are package variables so suites can redirect them exactly
// like Salt's tests patch _APT_SOURCES_LIST/_APT_SOURCES_PARTSDIR.
var (
	aptSourcesList  = "/etc/apt/sources.list"
	aptSourcesParts = "/etc/apt/sources.list.d/"
	aptKeyringDir   = "/etc/apt/keyrings"
)

// stringToBool mirrors salt.utils.pkg.deb.string_to_bool.
func stringToBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "no", "false", "without", "off", "disable", "0":
		return false, nil
	case "yes", "true", "with", "on", "enable", "1":
		return true, nil
	}
	return false, fmt.Errorf("Unable to convert to boolean: %s", s)
}

// isTrue mirrors salt.utils.data.is_true (int/float > 0, "true" strings,
// Go truthiness).
func isTrue(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil && strings.TrimSpace(v) != "" {
			return f > 0
		}
		return strings.ToLower(v) == "true"
	case float64:
		return v > 0
	case int:
		return v > 0
	case int32:
		return v > 0
	case int64:
		return v > 0
	}
	return true
}

// --- deb822 section --------------------------------------------------------

type tagEntry struct {
	key   string
	value string
}

// deb822Section is one deb822 stanza with ordered tags plus header/footer
// comments, mirroring Deb822Section.
type deb822Section struct {
	tags   []tagEntry
	header []string
	footer []string
}

var deb822TagRe = regexp.MustCompile(`^(\S+):\s*(\S.*)?$`)

func parseDeb822Section(sectionString string) (*deb822Section, error) {
	s := &deb822Section{}
	var rawData []string
	for _, line := range splitLines(sectionString) {
		if strings.HasPrefix(line, "#") {
			if len(rawData) > 0 {
				s.footer = append(s.footer, line)
			} else {
				s.header = append(s.header, line)
			}
			continue
		}
		rawData = append(rawData, line)
	}

	tag := ""
	value := ""
	store := func() { s.tags = append(s.tags, tagEntry{tag, strings.TrimSpace(value)}) }
	closed := false
	for _, line := range rawData {
		m := deb822TagRe.FindStringSubmatch(line)
		switch {
		case m != nil:
			if tag != "" && !closed {
				store()
			}
			tag, value, closed = m[1], m[2], false
		case line == "" && tag != "":
			// Blank lines close the current value but upstream keeps the
			// tag armed, so later continuations re-extend it before the
			// final store. Ported verbatim.
			store()
			closed = true
		default:
			value = value + "\n" + line
			closed = false
		}
	}
	if tag != "" && !closed {
		store()
	}
	return s, nil
}

// splitLines mirrors Python str.splitlines(): a trailing newline does not
// produce an empty final element.
func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// get returns the tag value case-insensitively; ok=false when missing.
func (s *deb822Section) get(key string) (string, bool) {
	lower := strings.ToLower(key)
	for _, t := range s.tags {
		if strings.ToLower(t.key) == lower {
			return t.value, true
		}
	}
	return "", false
}

// set stores the tag under its original spelling when present.
func (s *deb822Section) set(key, val string) {
	lower := strings.ToLower(key)
	for i := range s.tags {
		if strings.ToLower(s.tags[i].key) == lower {
			s.tags[i] = tagEntry{key, val}
			return
		}
	}
	s.tags = append(s.tags, tagEntry{key, val})
}

// del removes the tag case-insensitively.
func (s *deb822Section) del(key string) {
	lower := strings.ToLower(key)
	for i := range s.tags {
		if strings.ToLower(s.tags[i].key) == lower {
			s.tags = append(s.tags[:i], s.tags[i+1:]...)
			return
		}
	}
}

func (s *deb822Section) empty() bool { return len(s.tags) == 0 }

func (s *deb822Section) String() string {
	var b strings.Builder
	b.WriteString(strings.Join(s.header, "\n"))
	if len(s.header) > 0 {
		b.WriteString("\n")
	}
	for _, t := range s.tags {
		if t.value != "" {
			b.WriteString(fmt.Sprintf("%s: %s\n", t.key, t.value))
		}
	}
	b.WriteString(strings.Join(s.footer, "\n"))
	if len(s.footer) > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// --- deb822 source entry ----------------------------------------------------

// deb822SourceEntry mirrors Deb822SourceEntry (.sources stanzas).
type deb822SourceEntry struct {
	section *deb822Section
	file    string
	line    string
}

func newDeb822SourceEntryFromSection(section *deb822Section, file string) *deb822SourceEntry {
	e := &deb822SourceEntry{file: file}
	if section == nil {
		e.section = &deb822Section{}
	} else {
		e.section = section
	}
	e.line = e.section.String()
	return e
}

// multiTag reads a whitespace-separated tag through split_source_line like
// the upstream multi-value properties.
func (e *deb822SourceEntry) multiTag(key string) []string {
	v, ok := e.section.get(key)
	if !ok || v == "" {
		return nil
	}
	return splitSourceLine(v)
}

func (e *deb822SourceEntry) Types() []string         { return e.multiTag("Types") }
func (e *deb822SourceEntry) URIs() []string          { return e.multiTag("URIs") }
func (e *deb822SourceEntry) Suites() []string        { return e.multiTag("Suites") }
func (e *deb822SourceEntry) Comps() []string         { return e.multiTag("Components") }
func (e *deb822SourceEntry) Architectures() []string { return e.multiTag("Architectures") }

// Type/Dist mirror the deprecated single-value properties: raw tag text.
func (e *deb822SourceEntry) Type() (string, bool) { return e.section.get("Types") }
func (e *deb822SourceEntry) Dist() (string, bool) { return e.section.get("Suites") }

func (e *deb822SourceEntry) SignedBy() (string, bool) { return e.section.get("Signed-By") }

func (e *deb822SourceEntry) SetTypes(v []string) {
	if v == nil {
		e.section.del("Types")
		return
	}
	e.section.set("Types", strings.Join(v, " "))
}
func (e *deb822SourceEntry) SetURIs(v []string) {
	if v == nil {
		e.section.del("URIs")
		return
	}
	e.section.set("URIs", strings.Join(v, " "))
}
func (e *deb822SourceEntry) SetSuites(v []string) {
	if v == nil {
		e.section.del("Suites")
		return
	}
	e.section.set("Suites", strings.Join(v, " "))
}
func (e *deb822SourceEntry) SetComps(v []string) {
	if v == nil {
		e.section.del("Components")
		return
	}
	e.section.set("Components", strings.Join(v, " "))
}
func (e *deb822SourceEntry) SetArchitectures(v []string) {
	if v == nil {
		e.section.del("Architectures")
		return
	}
	e.section.set("Architectures", strings.Join(v, " "))
}
func (e *deb822SourceEntry) SetSignedBy(v string) {
	if v == "" {
		e.section.del("Signed-By")
		return
	}
	e.section.set("Signed-By", v)
}

// Disabled mirrors the Enabled-tag inversion.
func (e *deb822SourceEntry) Disabled() (bool, error) {
	raw, ok := e.section.get("Enabled")
	if !ok {
		raw = "yes"
	}
	enabled, err := stringToBool(raw)
	if err != nil {
		return false, err
	}
	return !enabled, nil
}

func (e *deb822SourceEntry) SetDisabled(disabled bool) {
	if disabled {
		e.section.set("Enabled", "no")
		return
	}
	e.section.del("Enabled")
}

// Trusted returns nil when the Trusted tag is absent.
func (e *deb822SourceEntry) Trusted() (*bool, error) {
	raw, ok := e.section.get("Trusted")
	if !ok {
		return nil, nil
	}
	val, err := stringToBool(raw)
	if err != nil {
		return nil, err
	}
	return &val, nil
}

func (e *deb822SourceEntry) SetTrusted(value any) error {
	switch v := value.(type) {
	case bool:
		if v {
			e.section.set("Trusted", "yes")
		} else {
			e.section.set("Trusted", "no")
		}
	case int:
		e.setNumericTrusted(float64(v))
	case float64:
		e.setNumericTrusted(v)
	case string:
		val, err := stringToBool(v)
		if err != nil {
			return err
		}
		e.writeTrusted(val)
	default:
		e.section.del("Trusted")
	}
	return nil
}

func (e *deb822SourceEntry) setNumericTrusted(v float64) {
	switch v {
	case 1:
		e.section.set("Trusted", "yes")
	case 0:
		e.section.set("Trusted", "no")
	default:
		e.section.del("Trusted")
	}
}

func (e *deb822SourceEntry) writeTrusted(val bool) {
	if val {
		e.section.set("Trusted", "yes")
	} else {
		e.section.set("Trusted", "no")
	}
}

func (e *deb822SourceEntry) Comment() string { return strings.Join(e.section.header, "\n") }

func (e *deb822SourceEntry) SetComment(comment string) {
	lines := splitLines(comment)
	allCommented := true
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			allCommented = false
			break
		}
	}
	if !allCommented {
		out := make([]string, 0, len(lines))
		for _, l := range lines {
			if strings.HasPrefix(l, "#") {
				out = append(out, l)
			} else {
				out = append(out, "#"+l)
			}
		}
		lines = out
	}
	e.section.header = lines
}

// Invalid reports whether the stanza carries no tags at all.
func (e *deb822SourceEntry) Invalid() bool { return e.section.empty() }

// String renders the stanza trimmed, matching __str__.
func (e *deb822SourceEntry) String() string { return strings.TrimSpace(e.section.String()) }

// matches mirrors the deb822 __eq__ operator used by removal paths.
func (e *deb822SourceEntry) matchesDisabledTypeURIDistComps(
	disabled bool, typ string, uris []string, dist string, comps []string,
) (bool, error) {
	selfDisabled, err := e.Disabled()
	if err != nil {
		return false, err
	}
	if selfDisabled != disabled || mustType(e) != typ || mustDist(e) != dist {
		return false, nil
	}
	selfURIs := map[string]bool{}
	for _, u := range e.URIs() {
		selfURIs[strings.TrimRight(u, "/")] = true
	}
	other := map[string]bool{}
	for _, u := range uris {
		other[strings.TrimRight(u, "/")] = true
	}
	if !equalSets(selfURIs, other) {
		return false, nil
	}
	return equalSlices(e.Comps(), comps), nil
}

// --- classic sources.list entry ---------------------------------------------

var cdromRe = regexp.MustCompile(`^(.*)(cdrom:.*/)(.*)$`)

// invalidParse mirrors _invalid: classifies a sources.list line into
// disabled/invalid/comment plus the token list used by parsing.
func invalidParse(line string) (disabled, invalid bool, comment string, repoLine []string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false, true, "", nil
	}
	if strings.HasPrefix(line, "#") {
		disabled = true
		line = line[1:]
	}
	if idx := strings.Index(line, "#"); idx > 0 {
		comment = line[idx+1:]
		line = line[:idx]
	}
	stripped := strings.TrimSpace(line)
	probeLine := stripped
	multiline := false
	if nl := strings.Index(probeLine, "\n"); nl >= 0 {
		// Python's "." never crosses newlines, so the cdrom probe only ever
		// sees text up to the first physical newline.
		probeLine = probeLine[:nl]
		multiline = true
	}
	if m := cdromRe.FindStringSubmatch(probeLine); m != nil {
		repoLine = append(repoLine, strings.Fields(m[1])...)
		repoLine = append(repoLine, strings.TrimSpace(m[2]))
		repoLine = append(repoLine, strings.Fields(m[3])...)
	} else if multiline {
		repoLine = strings.Fields(stripped)
	} else {
		repoLine = strings.Fields(stripped)
	}
	if len(repoLine) == 0 ||
		(repoLine[0] != "deb" && repoLine[0] != "deb-src" &&
			repoLine[0] != "rpm" && repoLine[0] != "rpm-src") ||
		len(repoLine) < 3 {
		return disabled, true, comment, repoLine
	}
	if strings.HasPrefix(repoLine[1], "[") {
		hasClose := false
		for _, tok := range repoLine[1:] {
			if strings.HasSuffix(tok, "]") {
				hasClose = true
				break
			}
		}
		if !hasClose {
			return disabled, true, comment, repoLine
		}
	}
	return disabled, false, comment, repoLine
}

// optValue carries one []-option as parsed by _get_opts.
type optValue struct {
	full  string
	value string
	arch  []string
}

var bracketOptRe = regexp.MustCompile(`\[(.*?=.*?)]`)

// getSourceOpts mirrors _get_opts over the FIRST [k=v ...] group in line.
func getSourceOpts(line string) map[string]*optValue {
	m := bracketOptRe.FindStringSubmatch(line)
	ret := map[string]*optValue{}
	if m == nil {
		return ret
	}
	opts := strings.TrimSuffix(strings.TrimPrefix(strings.TrimRight(m[0], "]"), "["), "]")
	opts = strings.TrimSpace(opts)
	var archValues []string
	for _, opt := range strings.Fields(opts) {
		name, val, found := strings.Cut(opt, "=")
		switch {
		case strings.HasPrefix(opt, "arch") && found:
			archValues = append(archValues, strings.Split(val, ",")...)
			ret["arch"] = &optValue{full: opt, value: val, arch: append([]string{}, archValues...)}
		case strings.HasPrefix(opt, "signed-by"):
			ret["signedby"] = &optValue{full: opt, value: val}
		default:
			ret[name] = &optValue{full: opt, value: val}
		}
	}
	return ret
}

// splitSourceLine mirrors SourceEntry.split_source_line's bracket-aware walk.
func splitSourceLine(line string) []string {
	line = strings.TrimSpace(line)
	var pieces []string
	tmp := ""
	pFound := false
	spaceFound := false
	flushPiece := func(next string) {
		pieces = append(pieces, tmp)
		tmp = next
	}
	for _, c := range line {
		switch {
		case c == '[':
			if spaceFound {
				spaceFound = false
				pFound = true
				flushPiece(string(c))
			} else {
				pFound = true
				tmp += string(c)
			}
		case c == ']':
			pFound = false
			tmp += string(c)
		case spaceFound && !isSpaceByte(c):
			spaceFound = false
			flushPiece(string(c))
		case isSpaceByte(c) && !pFound:
			spaceFound = true
		default:
			tmp += string(c)
		}
	}
	if len(tmp) > 0 {
		pieces = append(pieces, tmp)
	}
	return pieces
}

func isSpaceByte(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// sourceEntry mirrors the classic one-line SourceEntry.
type sourceEntry struct {
	disabled      bool
	invalid       bool
	comment       string
	typ           string
	architectures []string
	signedby      string
	trusted       *bool
	uri           string
	dist          string
	comps         []string
	line          string
	file          string
}

// newSourceEntry mirrors SourceEntry.__init__ + parse. The returned error
// corresponds to SaltInvocationError for malformed definitions and
// ValueError for .sources targets.
func newSourceEntry(line, file string) (*sourceEntry, error) {
	e := &sourceEntry{line: line}
	if file == "" {
		file = aptSourcesList
	}
	if strings.HasSuffix(file, ".sources") {
		return nil, fmt.Errorf("Classic SourceEntry cannot be written to .sources file")
	}
	e.file = file
	if _, err := e.parse(line); err != nil {
		return nil, err
	}
	return e, nil
}

// parse mirrors SourceEntry.parse; ok=false marks an invalid line.
func (e *sourceEntry) parse(line string) (bool, error) {
	disabled, invalid, comment, repoLine := invalidParse(line)
	e.disabled, e.invalid, e.comment = disabled, invalid, comment
	if invalid {
		return false, nil
	}
	if strings.HasPrefix(repoLine[1], "[") {
		stripped := make([]string, 0, len(repoLine))
		for _, tok := range repoLine {
			trimmed := strings.Trim(tok, "[]")
			if trimmed != "" {
				stripped = append(stripped, trimmed)
			}
		}
		repoLine = stripped
		opts := getSourceOpts(e.line)
		if o, ok := opts["arch"]; ok {
			e.architectures = append(e.architectures, o.arch...)
		}
		if o, ok := opts["signedby"]; ok {
			e.signedby = o.value
		}
		if o, ok := opts["trusted"]; ok {
			val, err := coerceTrusted(o.value)
			if err != nil {
				return false, err
			}
			e.trusted = val
		}
		for _, o := range opts {
			if o.full == "" {
				continue
			}
			idx := indexOf(repoLine, o.full)
			if idx < 0 {
				idx = indexOf(repoLine, "["+o.full+"]")
			}
			if idx >= 0 {
				repoLine = append(repoLine[:idx], repoLine[idx+1:]...)
			}
		}
	}
	if len(repoLine) < 3 {
		return false, fmt.Errorf("Invalid repository definition: %s", strings.Join(repoLine, " "))
	}
	e.typ = repoLine[0]
	e.uri = repoLine[1]
	e.dist = repoLine[2]
	e.comps = append([]string{}, repoLine[3:]...)
	return true, nil
}

// coerceTrusted mirrors the classic entry's trusted setter.
func coerceTrusted(trusted any) (*bool, error) {
	switch v := trusted.(type) {
	case bool:
		return &v, nil
	case string:
		val, err := stringToBool(v)
		if err != nil {
			return nil, err
		}
		return &val, nil
	case int:
		b := v == 1
		return &b, nil
	case float64:
		b := v == 1
		return &b, nil
	}
	return nil, nil
}

// Types/URIs/Suites are the deb822-compatible views on classic entries.
func (e *sourceEntry) Types() []string { return []string{e.typ} }
func (e *sourceEntry) URIs() []string  { return []string{e.uri} }

func (e *sourceEntry) Suites() []string {
	if e.dist != "" {
		return []string{e.dist}
	}
	return nil
}

func (e *sourceEntry) SetSuites(suites []string) error {
	if len(suites) > 1 {
		return fmt.Errorf("Only one suite is possible for non deb822 source entry")
	}
	if len(suites) == 1 {
		e.dist = suites[0]
		return nil
	}
	e.dist = ""
	return nil
}

// RepoLine renders the canonical line including options and comment.
func (e *sourceEntry) RepoLine() string {
	if e.invalid {
		return e.line
	}
	var parts []string
	if e.disabled {
		parts = append(parts, "#")
	}
	parts = append(parts, e.typ)
	opts := getSourceOpts(e.line)
	if len(e.architectures) > 0 {
		o, ok := opts["arch"]
		if !ok {
			o = &optValue{}
			opts["arch"] = o
		}
		o.full = fmt.Sprintf("arch=%s", strings.Join(e.architectures, ","))
		o.value = strings.Join(e.architectures, ",")
	}
	if e.signedby != "" {
		o, ok := opts["signedby"]
		if !ok {
			o = &optValue{}
			opts["signedby"] = o
		}
		o.full = fmt.Sprintf("signed-by=%s", e.signedby)
		o.value = e.signedby
	}
	if e.trusted != nil && *e.trusted {
		o, ok := opts["trusted"]
		if !ok {
			o = &optValue{}
			opts["trusted"] = o
		}
		o.value = "yes"
		o.full = "trusted=yes"
	}
	if o, ok := opts["trusted"]; ok && o.value == "no" {
		delete(opts, "trusted")
	}
	var ordered []string
	for _, o := range opts {
		if o.full != "" {
			ordered = append(ordered, o.full)
		}
	}
	if len(ordered) > 0 {
		parts = append(parts, fmt.Sprintf("[%s]", strings.Join(ordered, " ")))
	}
	parts = append(parts, e.uri, e.dist, strings.Join(e.comps, " "))
	if e.comment != "" {
		parts = append(parts, "#"+e.comment)
	}
	return strings.Join(parts, " ") + "\n"
}

func (e *sourceEntry) String() string { return strings.TrimSpace(e.RepoLine()) }

// sameRepo mirrors SourceEntry.__eq__.
func (e *sourceEntry) sameRepo(other *sourceEntry) bool {
	return e.disabled == other.disabled &&
		e.typ == other.typ &&
		strings.TrimRight(e.uri, "/") == strings.TrimRight(other.uri, "/") &&
		e.dist == other.dist &&
		equalSlices(e.comps, other.comps)
}

// --- sources list ------------------------------------------------------------

// sourcesList mirrors SourcesList across sources.list, *.list and *.sources
// part files. Entries are either *sourceEntry or *deb822SourceEntry.
type sourcesList struct {
	list []any
}

func newSourcesList(rt *runtime.Runtime) *sourcesList {
	s := &sourcesList{}
	s.refresh(rt)
	return s
}

func (s *sourcesList) refresh(rt *runtime.Runtime) {
	s.list = nil
	if info, err := rt.FS.Stat(aptSourcesList); err == nil && info.Mode().IsRegular() {
		s.load(rt, aptSourcesList)
	}
	if entries, err := rt.FS.ReadDir(aptSourcesParts); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".sources") && !strings.HasSuffix(name, ".list") {
				continue
			}
			path := filepath.Join(aptSourcesParts, name)
			if info, err := rt.FS.Stat(path); err == nil && info.Mode().IsRegular() {
				s.load(rt, path)
			}
		}
	}
}

func (s *sourcesList) load(rt *runtime.Runtime, path string) {
	data, err := rt.FS.ReadFile(path)
	if err != nil {
		return
	}
	if strings.HasSuffix(path, ".sources") {
		for _, section := range loadDeb822Sections(string(data)) {
			s.list = append(s.list, newDeb822SourceEntryFromSection(section, path))
		}
		return
	}
	for _, raw := range splitFileLines(string(data)) {
		source, err := newSourceEntry(raw, path)
		if err != nil {
			// Upstream logs and abandons the rest of the file while keeping
			// entries already parsed from it.
			return
		}
		s.list = append(s.list, source)
	}
}

func splitFileLines(content string) []string {
	content = strings.TrimSuffix(content, "\n")
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

// loadDeb822Sections mirrors SourcesList.load_deb822_sections: blank lines
// separate stanzas.
func loadDeb822Sections(content string) []*deb822Section {
	var sections []*deb822Section
	current := ""
	flush := func() {
		if current != "" {
			sec, _ := parseDeb822Section(current)
			sections = append(sections, sec)
			current = ""
		}
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) != "" {
			current += line + "\n"
			continue
		}
		flush()
	}
	flush()
	return sections
}

// add mirrors SourcesList.add, including the deb822/classic branching. The
// classic result is returned first, the deb822 result second.
func (s *sourcesList) add(
	typ, uri, dist string,
	origComps []string,
	comment any,
	pos int,
	file string,
	architectures []string,
	signedby string,
	suites []string,
	trusted any,
	types []string,
	parent *deb822SourceEntry,
	uris []string,
) (*sourceEntry, *deb822SourceEntry, error) {
	typ = strings.TrimSpace(typ)
	disabled := strings.HasPrefix(typ, "#")
	if disabled {
		typ = strings.TrimLeft(typ[1:], " ")
	}
	if architectures == nil {
		architectures = []string{}
	}
	comps := append([]string{}, origComps...)

	if file == "" {
		file = aptSourcesList
	}
	if strings.HasSuffix(file, ".sources") {
		entry := newDeb822SourceEntryFromSection(nil, file)
		if parent != nil {
			for _, t := range parent.section.tags {
				entry.section.set(t.key, t.value)
			}
		}
		if types != nil {
			entry.SetTypes(types)
		} else {
			entry.SetTypes([]string{typ})
		}
		if uris != nil {
			entry.SetURIs(uris)
		} else {
			entry.SetURIs([]string{uri})
		}
		if suites != nil {
			entry.SetSuites(suites)
		} else {
			entry.SetSuites([]string{dist})
		}
		entry.SetComps(comps)
		if len(architectures) > 0 {
			entry.SetArchitectures(architectures)
		}
		if cs, ok := comment.([]string); ok {
			entry.section.header = cs
		} else {
			text, _ := comment.(string)
			entry.section.header = []string{text}
		}
		entry.SetDisabled(disabled)
		if signedby != "" {
			entry.SetSignedBy(signedby)
		}
		if trusted != false {
			if err := entry.SetTrusted(trusted); err != nil {
				return nil, nil, err
			}
		}
		if pos < 0 {
			s.list = append(s.list, entry)
		} else {
			s.insert(pos, entry)
		}
		return nil, entry, nil
	}

	extAttrs := ""
	if len(architectures) > 0 {
		extAttrs = fmt.Sprintf("arch=%s", strings.Join(architectures, ","))
	}
	if signedby != "" {
		if extAttrs != "" {
			extAttrs += " "
		}
		extAttrs += fmt.Sprintf("signed-by=%s", signedby)
	}
	includeTrusted, err := truthyAny(trusted)
	if err != nil {
		return nil, nil, err
	}
	if includeTrusted {
		if extAttrs != "" {
			extAttrs += " "
		}
		extAttrs += "trusted=yes"
	}
	parts := []string{}
	if disabled {
		parts = append(parts, "#")
	}
	parts = append(parts, typ)
	if extAttrs != "" {
		parts = append(parts, "["+extAttrs+"]")
	}
	parts = append(parts, uri, dist)
	parts = append(parts, comps...)
	commentText, _ := comment.(string)
	if commentText != "" {
		parts = append(parts, "#"+commentText)
	}
	line := strings.Join(parts, " ") + "\n"

	newEntry, err := newSourceEntry(line, "")
	if err != nil {
		return nil, nil, err
	}
	newEntry.file = file
	if pos < 0 {
		s.list = append(s.list, newEntry)
	} else {
		s.insert(pos, newEntry)
	}
	return newEntry, nil, nil
}

// truthyAny evaluates Salt's `if trusted:` probes over decoded YAML scalars.
func truthyAny(value any) (bool, error) {
	switch v := value.(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case string:
		b, err := stringToBool(v)
		if err != nil {
			// Non-empty garbage strings are truthy for Python's `if`.
			return v != "", nil
		}
		return b, nil
	case int:
		return v != 0, nil
	case float64:
		return v != 0, nil
	}
	return true, nil
}

func (s *sourcesList) insert(pos int, entry any) {
	s.list = append(s.list, nil)
	copy(s.list[pos+1:], s.list[pos:])
	s.list[pos] = entry
}

// remove drops the first identical classic entry or exact deb822 pointer.
func (s *sourcesList) remove(target any) bool {
	switch t := target.(type) {
	case *sourceEntry:
		for i, item := range s.list {
			if se, ok := item.(*sourceEntry); ok && se.sameRepo(t) {
				s.list = append(s.list[:i], s.list[i+1:]...)
				return true
			}
		}
	case *deb822SourceEntry:
		for i, item := range s.list {
			if item == target {
				s.list = append(s.list[:i], s.list[i+1:]...)
				return true
			}
		}
	}
	return false
}

// save mirrors SourcesList.save including the empty-list header write and
// the between-deb822 blank separator quirk.
func (s *sourcesList) save(rt *runtime.Runtime) {
	if len(s.list) == 0 {
		header := "## See sources.list(5) for more information, especialy\n" +
			"# Remember that you can only use http, ftp or file URIs\n" +
			"# CDROMs are managed through the apt-cdrom tool.\n"
		// Upstream swallows FileNotFoundError: no apt directory means no
		// file gets created.
		rt.FS.WriteFile(aptSourcesList, []byte(header), 0o644)
		return
	}
	files := map[string][]string{}
	var order []string
	for _, source := range s.list {
		var file, rendered string
		isDeb822 := false
		switch e := source.(type) {
		case *sourceEntry:
			file, rendered = e.file, e.String()+"\n"
		case *deb822SourceEntry:
			file, rendered, isDeb822 = e.file, e.String()+"\n", true
		}
		if _, seen := files[file]; !seen {
			files[file] = nil
			order = append(order, file)
		} else if isDeb822 {
			files[file] = append(files[file], "\n")
		}
		files[file] = append(files[file], rendered)
	}
	for _, file := range order {
		rt.FS.WriteFile(file, []byte(strings.Join(files[file], "")), 0o644)
	}
}

func indexOf(list []string, needle string) int {
	for i, item := range list {
		if item == needle {
			return i
		}
	}
	return -1
}

func equalSlices(a, b []string) bool {
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

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// combineComments mirrors salt.utils.pkg.deb.combine_comments.
func combineComments(comments any) string {
	var parts []string
	switch c := comments.(type) {
	case []string:
		parts = c
	case []any:
		for _, item := range c {
			parts = append(parts, scalarString(item))
		}
	case string:
		parts = []string{c}
	default:
		parts = []string{scalarString(comments)}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// scalarString renders YAML scalars the way Python str() would.
func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case int:
		return fmt.Sprintf("%d", x)
	}
	return fmt.Sprintf("%v", v)
}

// stripURI mirrors salt.utils.pkg.deb.strip_uri.
func stripURI(repo string) string {
	parts := strings.Split(repo, " ")
	for i, val := range parts {
		if strings.HasPrefix(val, "http://") ||
			strings.HasPrefix(val, "https://") ||
			strings.HasPrefix(val, "ftp://") {
			parts[i] = strings.TrimRight(val, "/")
		}
	}
	return strings.Join(parts, " ")
}
