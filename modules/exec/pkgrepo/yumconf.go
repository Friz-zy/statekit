package pkgrepo

import (
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// INI/configparser support for the yum/dnf repository files. This is a
// contract port of the configparser behaviors yumpkg.py relies on @ pinned
// revision: raw _sections views, lowercased option keys, "=" / ":" delimiters
// resolved by first occurrence, indented continuation lines joined with
// "\n", full-line #/; comments, DEFAULT sections invisible to section
// iteration, strict duplicate detection, and MissingSectionHeaderError.

// missingSectionHeader mirrors configparser.MissingSectionHeaderError.
type missingSectionHeaderError struct{ line string }

func (e *missingSectionHeaderError) Error() string {
	return "Missing section header before first option/continuation line"
}

// duplicateOptionError / duplicateSectionError mirror the strict-mode
// errors surfaced when strict parsing is requested.
type duplicateOptionError struct{ section, key string }

func (e *duplicateOptionError) Error() string {
	return fmt.Sprintf("option %q in section %q already exists", e.key, e.section)
}

type duplicateSectionError struct{ name string }

func (e *duplicateSectionError) Error() string {
	return fmt.Sprintf("section %q already exists", e.name)
}

// iniSection keeps one parsed section with ordered, lowercased options.
type iniSection struct {
	name    string
	options []kvPair
}

type kvPair struct {
	key   string
	value string
}

// iniConfig is the raw _sections view: no defaults merging, no
// interpolation, insertion order preserved.
type iniConfig struct {
	sections []iniSection
}

func (c *iniConfig) find(name string) *iniSection {
	for i := range c.sections {
		if c.sections[i].name == name {
			return &c.sections[i]
		}
	}
	return nil
}

// get returns the option value case-insensitively (configparser keys are
// stored lowercased).
func (s *iniSection) get(key string) (string, bool) {
	lower := strings.ToLower(key)
	for _, kv := range s.options {
		if kv.key == lower {
			return kv.value, true
		}
	}
	return "", false
}

// set replaces or appends preserving original position for existing keys.
func (s *iniSection) set(key, value string) {
	lower := strings.ToLower(key)
	for i := range s.options {
		if s.options[i].key == lower {
			s.options[i].value = value
			return
		}
	}
	s.options = append(s.options, kvPair{lower, value})
}

func (s *iniSection) delete(key string) {
	lower := strings.ToLower(key)
	for i := range s.options {
		if s.options[i].key == lower {
			s.options = append(s.options[:i], s.options[i+1:]...)
			return
		}
	}
}

func (s *iniSection) keys() []string {
	out := make([]string, 0, len(s.options))
	for _, kv := range s.options {
		out = append(out, kv.key)
	}
	return out
}

// parseConfigparser mirrors ConfigParser(strict=strict).read() over one
// file's content.
func parseConfigparser(content string, strict bool) (*iniConfig, error) {
	cfg := &iniConfig{}
	cur := (*iniSection)(nil)
	pendingKey := ""

	for _, rawLine := range splitLinesKeep(content) {
		line := strings.TrimSuffix(rawLine, "\r")
		stripped := strings.TrimSpace(line)

		if stripped == "" {
			continue
		}
		// Full-line comments only: inline comment prefixes default to off.
		if strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, ";") {
			continue
		}

		if strings.HasPrefix(stripped, "[") && strings.HasSuffix(stripped, "]") && len(stripped) > 1 {
			name := stripped[1 : len(stripped)-1]
			if name == "DEFAULT" {
				// Defaults live outside _sections and stay invisible to the
				// section iteration yum relies on.
				cur = nil
				pendingKey = ""
				continue
			}
			if strict && cfg.find(name) != nil {
				return nil, &duplicateSectionError{name: name}
			}
			if existing := cfg.find(name); existing != nil {
				cur = existing
			} else {
				cfg.sections = append(cfg.sections, iniSection{name: name})
				cur = &cfg.sections[len(cfg.sections)-1]
			}
			pendingKey = ""
			continue
		}

		// Continuation lines start with whitespace and extend the pending
		// option with a newline join.
		if len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t') {
			if cur == nil || pendingKey == "" {
				return nil, &missingSectionHeaderError{line: stripped}
			}
			value, _ := cur.get(pendingKey)
			cur.set(pendingKey, value+"\n"+stripped)
			continue
		}

		key, value, found := cutFirstDelimiter(stripped)
		if !found {
			if cur == nil {
				return nil, &missingSectionHeaderError{line: stripped}
			}
			// A non-delimiter line inside a section without indentation is
			// treated by upstream as an option parse error; configparser
			// raises there, so propagate a matching failure.
			return nil, fmt.Errorf("source contains parsing errors: %q", stripped)
		}
		if cur == nil {
			return nil, &missingSectionHeaderError{line: stripped}
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if strict {
			if _, exists := cur.get(key); exists {
				return nil, &duplicateOptionError{section: cur.name, key: key}
			}
		}
		cur.set(key, value)
		pendingKey = key
	}
	return cfg, nil
}

// cutFirstDelimiter splits on the earliest of "=" / ":" like configparser's
// delimiter resolution.
func cutFirstDelimiter(line string) (key, value string, found bool) {
	eq := strings.Index(line, "=")
	colon := strings.Index(line, ":")
	switch {
	case eq >= 0 && (colon < 0 || eq < colon):
		return line[:eq], line[eq+1:], true
	case colon >= 0:
		return line[:colon], line[colon+1:], true
	}
	return "", "", false
}

func splitLinesKeep(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// combineRpmComments mirrors salt.utils.pkg.rpm.combine_comments: every
// comment normalized to "# text" lines joined with newlines.
func combineRpmComments(comments []string) string {
	var out []string
	for _, comment := range comments {
		trimmed := strings.TrimLeft(comment, "#")
		trimmed = strings.TrimLeft(trimmed, " ")
		out = append(out, fmt.Sprintf("# %s", trimmed))
	}
	return strings.Join(out, "\n")
}

// getCoprRepo mirrors _get_copr_repo's pure string mapping.
func getCoprRepo(copr string) string {
	body := strings.SplitN(copr, ":", 2)[1]
	parts := strings.SplitN(body, "/", 2)
	return fmt.Sprintf("copr:copr.fedorainfracloud.org:%s:%s", parts[0], parts[1])
}

// yumConfSearchPaths mirrors the yum/dnf config lookup order; injectable.
var yumConfSearchPaths = []string{
	"/etc/yum/yum.conf",
	"/etc/yum.conf",
	"/etc/dnf/dnf.conf",
	"/etc/tdnf/tdnf.conf",
}

// yumDefaultReposDirs mirrors the built-in reposdir fallback; injectable.
var yumDefaultReposDirs = []string{"/etc/yum/repos.d", "/etc/yum.repos.d"}

// getYumConfig mirrors _get_yum_config: defaults overlaid with [main]
// options from the first existing config path.
func getYumConfig(rt *runtime.Runtime, strict bool) (map[string]any, error) {
	conf := map[string]any{
		"reposdir": append([]string{}, yumDefaultReposDirs...),
	}
	fn := ""
	for _, path := range yumConfSearchPaths {
		if info, err := rt.FS.Stat(path); err == nil && !info.IsDir() {
			fn = path
			break
		}
	}
	if fn == "" {
		return nil, fmt.Errorf("No suitable yum config file found in: %s",
			pyListRepr(yumConfSearchPaths))
	}
	data, err := rt.FS.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("Unable to read from %s: %v", fn, err)
	}
	cp, perr := parseConfigparser(string(data), strict)
	if perr != nil {
		// Upstream lets configparser errors escape read(); mirror that.
		return nil, perr
	}
	main := cp.find("main")
	if main == nil {
		// Upstream warns and keeps internal defaults.
		return conf, nil
	}
	for _, key := range main.keys() {
		val, _ := main.get(key)
		switch key {
		case "reposdir", "commands", "excludes":
			var parts []string
			for _, piece := range strings.Split(val, ",") {
				parts = append(parts, strings.TrimSpace(piece))
			}
			conf[key] = parts
		default:
			conf[key] = val
		}
	}
	return conf, nil
}

func getYumConfigValue(rt *runtime.Runtime, name string, strict bool) (any, error) {
	conf, err := getYumConfig(rt, strict)
	if err != nil {
		return nil, err
	}
	return conf[name], nil
}

// normalizeYumBasedir mirrors _normalize_basedir: comma-string or list,
// falling back to the reposdir config value.
func normalizeYumBasedir(rt *runtime.Runtime, basedir any, strict bool) ([]string, error) {
	switch v := basedir.(type) {
	case nil:
	case string:
		if v == "" {
			basedir = nil
		} else {
			var parts []string
			for _, piece := range strings.Split(v, ",") {
				parts = append(parts, strings.TrimSpace(piece))
			}
			basedir = parts
		}
	case []string:
		basedir = v
	case []any:
		var parts []string
		for _, item := range v {
			parts = append(parts, scalarString(item))
		}
		basedir = parts
	}
	list, ok := basedir.([]string)
	if !ok || len(list) == 0 {
		val, err := getYumConfigValue(rt, "reposdir", strict)
		if err != nil {
			return nil, err
		}
		list, ok = val.([]string)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("Could not determine any repo directories")
		}
	}
	return list, nil
}

// pyListRepr renders a []string the way Python str(list) does inside error
// messages.
func pyListRepr(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		q := item
		if strings.Contains(q, `'`) && !strings.Contains(q, `"`) {
			q = `"` + q + `"`
		} else {
			q = "'" + strings.ReplaceAll(q, `\`, `\\`) + "'"
		}
		quoted = append(quoted, q)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
