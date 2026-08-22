package main

import (
	"regexp"
	"sort"
	"strings"
)

// Parameter describes one Salt function parameter extracted from source.
type Parameter struct {
	Name    string  `yaml:"name"`
	Default *string `yaml:"default,omitempty"`
	Kind    string  `yaml:"kind,omitempty"` // "", "*", or "**"
}

// SourceRef points at the origin of a catalog entry.
type SourceRef struct {
	Path   string `yaml:"path"`
	Symbol string `yaml:"symbol"`
}

// TestRef records a mapped Salt test file and its test count.
type TestRef struct {
	Path      string `yaml:"path"`
	Functions int    `yaml:"functions"`
}

// Entry is one Salt function inventory record (plan section 20).
type Entry struct {
	Function              string      `yaml:"function"`
	Source                SourceRef   `yaml:"source"`
	Summary               string      `yaml:"summary,omitempty"`
	Parameters            []Parameter `yaml:"parameters,omitempty"`
	ExecutionDependencies []string    `yaml:"execution_dependencies,omitempty"`
	UtilityDependencies   []string    `yaml:"utility_dependencies,omitempty"`
	Tests                 []TestRef   `yaml:"tests,omitempty"`
}

// ModuleDoc is the per-module catalog document written under docs/catalog/.
type ModuleDoc struct {
	Kind            string   `yaml:"kind"`
	Module          string   `yaml:"module"`
	SourceModule    string   `yaml:"source_module"`
	Virtual         bool     `yaml:"virtual,omitempty"`
	Path            string   `yaml:"path"`
	PlatformMarkers []string `yaml:"platform_markers,omitempty"`
	Functions       []Entry  `yaml:"functions"`
}

var (
	virtualNameRe = regexp.MustCompile(`(?m)^__virtualname__\s*=\s*["']([^"']+)["']`)
	defRe         = regexp.MustCompile(`^def\s+([A-Za-z_]\w*)\s*\((.*)$`)
	execDepRe     = regexp.MustCompile(`__salt__\[\s*["']([A-Za-z0-9_.]+)["']\s*\]`)
	utilDepRe     = regexp.MustCompile(`__utils__\[\s*["']([A-Za-z0-9_.]+)["']\s*\]`)
	platformRe    = regexp.MustCompile(`\bis_(windows|linux|freebsd|openbsd|netbsd|darwin|sunos|aix|junos)\b`)
	testDefRe     = regexp.MustCompile(`(?m)^def\s+(test_\w+)\s*\(`)
)

// parseModule turns one Salt module file into a ModuleDoc.
//
// Structure (functions, signatures, summaries) is parsed from the original
// source; dependency and marker scans run on docstring/comment-stripped text
// so documentation examples never pollute the inventory.
func parseModule(kind, relPath, stem, content string) ModuleDoc {
	stripped := stripDocstrings(content)
	doc := ModuleDoc{
		Kind:         kind,
		Module:       stem,
		SourceModule: stem,
		Path:         relPath,
	}
	if m := virtualNameRe.FindStringSubmatch(stripped); m != nil {
		doc.Module = m[1]
		doc.Virtual = true
	}
	markers := map[string]bool{}
	for _, m := range platformRe.FindAllStringSubmatch(stripped, -1) {
		markers["is_"+m[1]] = true
	}
	for marker := range markers {
		doc.PlatformMarkers = append(doc.PlatformMarkers, marker)
	}
	sort.Strings(doc.PlatformMarkers)

	deps := uniqSorted(execDepRe.FindAllStringSubmatch(stripped, -1))
	utils := uniqSorted(utilDepRe.FindAllStringSubmatch(stripped, -1))

	for _, fn := range topLevelFunctions(content) {
		if strings.HasPrefix(fn.name, "__") {
			continue
		}
		entry := Entry{
			Function: fn.name,
			Source: SourceRef{
				Path:   relPath,
				Symbol: fn.name,
			},
			Summary:               fn.summary,
			Parameters:            fn.parameters,
			ExecutionDependencies: filterDeps(depsFor(deps, content, fn)),
			UtilityDependencies:   filterDeps(depsFor(utils, content, fn)),
		}
		doc.Functions = append(doc.Functions, entry)
	}
	return doc
}

type parsedFunction struct {
	name       string
	parameters []Parameter
	summary    string
	bodyEnd    int
}

// topLevelFunctions finds column-0 defs and their signatures in stripped
// Python source, handling multiline signatures and computing each function's
// indentation-bounded body extent.
func topLevelFunctions(src string) []parsedFunction {
	lines := strings.Split(src, "\n")
	var out []parsedFunction
	for i := 0; i < len(lines); i++ {
		m := defRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		fn := parsedFunction{name: m[1]}
		open := strings.IndexByte(lines[i], '(')
		if open < 0 {
			continue
		}
		sig := lines[i][open:]
		end := i
		for strings.Count(sig, "(") > strings.Count(sig, ")") && end+1 < len(lines) {
			end++
			sig += "\n" + lines[end]
		}
		closeIdx := strings.LastIndexByte(sig, ')')
		if closeIdx > 0 {
			fn.parameters = parseParameters(sig[1:closeIdx])
		}
		fn.bodyEnd = bodyExtent(lines, end)
		fn.summary = summaryAfter(lines, end)
		out = append(out, fn)
	}
	return out
}

// bodyExtent returns the last line index of an indented function body
// starting after the signature line at defLine.
func bodyExtent(lines []string, defLine int) int {
	last := defLine
	for j := defLine + 1; j < len(lines); j++ {
		line := lines[j]
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		last = j
	}
	return last
}

// parseParameters splits a signature body on top-level commas and extracts
// names, raw defaults, and vararg kinds.
func parseParameters(sig string) []Parameter {
	var params []Parameter
	for _, token := range splitTopLevel(sig) {
		token = strings.TrimSpace(token)
		switch token {
		case "":
		case "*":
			params = append(params, Parameter{Name: "*", Kind: "*"})
		default:
			p := Parameter{}
			switch {
			case strings.HasPrefix(token, "**"):
				p.Name, p.Kind = strings.TrimPrefix(token, "**"), "**"
			case strings.HasPrefix(token, "*"):
				p.Name, p.Kind = strings.TrimPrefix(token, "*"), "*"
			default:
				if eq := indexDefault(token); eq >= 0 {
					name := strings.TrimSpace(token[:eq])
					value := strings.TrimSpace(token[eq+1:])
					p.Name = name
					p.Default = &value
				} else {
					p.Name = token
				}
			}
			params = append(params, p)
		}
	}
	return params
}

// indexDefault finds the first '=' outside brackets and quotes; -1 when the
// parameter has no default. Annotation colons are tolerated.
func indexDefault(token string) int {
	depth := 0
	quote := byte(0)
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == '=' && depth == 0:
			if i+1 < len(token) && token[i+1] == '=' {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

// splitTopLevel splits on commas that sit outside brackets and quotes.
func splitTopLevel(s string) []string {
	var parts []string
	depth := 0
	quote := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// summaryAfter captures the first meaningful docstring line following a def.
func summaryAfter(lines []string, defEnd int) string {
	for i := defEnd + 1; i < len(lines) && i <= defEnd+4; i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, `"""`) || strings.HasPrefix(line, "'''"):
			q := line[:3]
			rest := strings.TrimSpace(strings.TrimPrefix(line, q))
			rest = strings.TrimSuffix(rest, q)
			rest = strings.TrimSpace(rest)
			if rest != "" {
				return firstSentence(rest)
			}
			for j := i + 1; j < len(lines); j++ {
				next := strings.TrimSpace(lines[j])
				if next == "" {
					continue
				}
				next = strings.TrimSuffix(next, q)
				next = strings.TrimSpace(next)
				if next != "" {
					return firstSentence(next)
				}
				break
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "\n"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

// depsFor returns exec dependencies referenced within the function's own body
// span; module-level fallback keeps entries useful for single-function files.
func depsFor(all []string, src string, fn parsedFunction) []string {
	lines := strings.Split(src, "\n")
	if fn.bodyEnd+1 > len(lines) {
		return all
	}
	scope := strings.Join(lines[:fn.bodyEnd+1], "\n")
	found := map[string]bool{}
	for _, dep := range all {
		if strings.Contains(scope, "'"+dep+"'") || strings.Contains(scope, "\""+dep+"\"") {
			found[dep] = true
		}
	}
	out := make([]string, 0, len(found))
	for dep := range found {
		out = append(out, dep)
	}
	sort.Strings(out)
	return out
}

// stripDocstrings replaces triple-quoted block and comment contents with
// spaces (newlines preserved) so later regex scans do not match documentation
// examples while line structure stays intact.
func stripDocstrings(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i := 0
	for i < len(src) {
		if i+3 <= len(src) && (src[i:i+3] == `"""` || src[i:i+3] == "'''") {
			quote := src[i : i+3]
			b.WriteString(quote)
			i += 3
			for i < len(src) {
				if strings.HasPrefix(src[i:], quote) {
					b.WriteString(quote)
					i += 3
					break
				}
				switch {
				case src[i] == '\\' && i+1 < len(src):
					b.WriteString("  ")
					i += 2
					continue
				case src[i] == '\n':
					b.WriteByte('\n')
				default:
					b.WriteByte(' ')
				}
				i++
			}
			continue
		}
		if src[i] == '#' {
			for i < len(src) && src[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

func uniqSorted(matches [][]string) []string {
	set := map[string]bool{}
	for _, m := range matches {
		if m[1] != "" {
			set[m[1]] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// filterDeps removes obvious non-module references (empty, dunder-only).
func filterDeps(deps []string) []string {
	out := deps[:0]
	for _, d := range deps {
		if !strings.HasPrefix(d, "__") {
			out = append(out, d)
		}
	}
	return out
}

// countTestFunctions counts "def test_*" occurrences in a Salt test file.
func countTestFunctions(content string) int {
	return len(testDefRe.FindAllStringSubmatch(content, -1))
}
