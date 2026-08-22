// Package ini implements Salt-compatible INI file management.
//
// Reference: saltstack/salt/modules/ini_manage.py @ pinned revision. Files
// are parsed and rewritten through the runtime FileSystem; comments and
// unknown top-level lines are preserved.
package ini

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type document struct {
	order    []string
	sections map[string]*section
}

type section struct {
	order  []string
	values map[string]string
	lines  []string // untouched non-key lines (comments, blanks)
}

func newDocument() *document {
	return &document{sections: map[string]*section{
		"": {order: []string{}, values: map[string]string{}},
	}}
}

func (d *document) ensure(name string) *section {
	if s, ok := d.sections[name]; ok {
		return s
	}
	d.order = append(d.order, name)
	s := &section{order: []string{}, values: map[string]string{}}
	d.sections[name] = s
	return s
}

func parseINI(content, separator string) (*document, error) {
	if separator == "" {
		return nil, fmt.Errorf("separator must not be empty")
	}
	doc := newDocument()
	current := doc.sections[""]
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			current.lines = append(current.lines, line)
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && len(trimmed) >= 2:
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
			current = doc.ensure(name)
		default:
			key, value, ok := strings.Cut(line, separator)
			if !ok {
				current.lines = append(current.lines, line)
				continue
			}
			key = strings.TrimSpace(key)
			if _, seen := current.values[key]; !seen {
				current.order = append(current.order, key)
			}
			current.values[key] = strings.TrimSpace(value)
		}
	}
	return doc, nil
}

func (d *document) serialize(separator string) string {
	var b strings.Builder
	writeSection := func(name string, s *section) {
		if name != "" {
			b.WriteString("[" + name + "]\n")
		}
		for _, line := range s.lines {
			b.WriteString(line + "\n")
		}
		for _, key := range s.order {
			b.WriteString(key + " " + separator + " " + s.values[key] + "\n")
		}
	}
	if root, ok := d.sections[""]; ok {
		writeSection("", root)
	}
	for _, name := range d.order {
		if name != "" {
			writeSection(name, d.sections[name])
		}
	}
	out := b.String()
	return strings.TrimRight(out, "\n") + "\n"
}

func writeFile(rt *runtime.Runtime, path string, doc *document, separator string) error {
	mode := fs.FileMode(0o644)
	if info, err := rt.FS.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return rt.FS.WriteFile(path, []byte(doc.serialize(separator)), mode)
}

func load(rt *runtime.Runtime, file, separator string) (*document, error) {
	if separator == "" {
		separator = "="
	}
	data, err := rt.FS.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return parseINI(string(data), separator)
}

func toStringMap(v any) (map[string]string, bool) {
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for key, value := range raw {
		switch t := value.(type) {
		case string:
			out[key] = t
		case int:
			out[key] = fmt.Sprintf("%d", t)
		case int64:
			out[key] = fmt.Sprintf("%d", t)
		case float64:
			out[key] = fmt.Sprintf("%g", t)
		case bool:
			out[key] = fmt.Sprintf("%t", t)
		default:
			return nil, false
		}
	}
	return out, true
}
