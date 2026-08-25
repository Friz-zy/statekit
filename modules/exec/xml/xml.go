// Package xml implements Salt's xml module over encoding/xml, mirroring
// saltstack/salt/modules/xml.py @ pinned revision.
//
// Contract notes (init.md section 28): ElementTree's .find() supports a
// limited xpath subset; this port handles the same shapes hermetic tests
// exercise — bare "tag", "parent/child" paths, ".//tag" descendant search,
// and "[@attr='value']" predicates on the final segment (documented
// subset).
package xml

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type node struct {
	name     string
	attr     map[string]string
	text     strings.Builder
	children []*node
}

func parseDocument(data []byte) (*node, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	root := &node{name: "#document"}
	stack := []*node{root}
	for {
		tok, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local, attr: map[string]string{}}
			for _, a := range t.Attr {
				n.attr[a.Name.Local] = a.Value
			}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			cur := stack[len(stack)-1]
			cur.text.Write(t)
		}
	}
	if len(root.children) == 0 {
		return nil, fmt.Errorf("no XML root element found")
	}
	return root.children[0], nil
}

func writeDocument(rt *runtime.Runtime, root *node, file string) error {
	var b strings.Builder
	writeNode(&b, root, 0)
	return rt.FS.WriteFile(file, []byte(b.String()), 0o644)
}

func writeNode(b *strings.Builder, n *node, depth int) {
	if n.name == "#document" {
		for _, c := range n.children {
			writeNode(b, c, depth)
		}
		return
	}
	indent := strings.Repeat("    ", depth)
	b.WriteString(indent + "<" + n.name)
	for k, v := range n.attr {
		b.WriteString(fmt.Sprintf(" %s=%q", k, v))
	}
	text := n.text.String()
	children := n.children
	if text == "" && len(children) == 0 {
		b.WriteString("/>\n")
		return
	}
	b.WriteString(">")
	b.WriteString(text)
	for _, c := range children {
		b.WriteString("\n")
		writeNode(b, c, depth+1)
	}
	if len(children) > 0 {
		b.WriteString("\n" + indent)
	}
	b.WriteString("</" + n.name + ">")
}

// findElement resolves the supported xpath subset against the tree.
func findElement(root *node, expr string) *node {
	expr = strings.TrimPrefix(expr, "./")
	descendant := false
	if rest, ok := strings.CutPrefix(expr, ".//"); ok {
		expr = rest
		descendant = true
	}
	segs := strings.Split(expr, "/")
	final := segs[len(segs)-1]
	tag, predicate := splitPredicate(final)
	segs[len(segs)-1] = tag

	var current []*node
	if descendant {
		current = collectDescendants(root)
	} else {
		current = []*node{root}
	}
	for i, seg := range segs {
		if seg == "." || seg == "" {
			continue
		}
		var next []*node
		for _, cur := range current {
			for _, child := range cur.children {
				if child.name == seg {
					next = append(next, child)
				}
			}
		}
		current = next
		if i < len(segs)-1 && len(current) == 0 {
			return nil
		}
	}
	for _, cand := range current {
		if cand.name == tag && predicateMatches(cand, predicate) {
			return cand
		}
	}
	return nil
}

func collectDescendants(root *node) []*node {
	var out []*node
	var walk func(n *node)
	walk = func(n *node) {
		for _, c := range n.children {
			out = append(out, c)
			walk(c)
		}
	}
	walk(root)
	return out
}

func splitPredicate(final string) (string, string) {
	if idx := strings.Index(final, "[@"); idx >= 0 && strings.HasSuffix(final, "]") {
		return final[:idx], final[idx+2 : len(final)-1]
	}
	return final, ""
}

func predicateMatches(n *node, predicate string) bool {
	if predicate == "" {
		return true
	}
	key, value, found := strings.Cut(predicate, "=")
	if !found {
		return false
	}
	value = strings.Trim(value, `'"`)
	return n.attr[strings.TrimSpace(key)] == value
}

type GetValueArgs struct {
	File    string `statekit:"required,name=file"`
	Element string `statekit:"required,name=element"`
}

type GetValueFunc struct{}

func (GetValueFunc) Name() string { return "xml.get_value" }
func (GetValueFunc) Args() any    { return GetValueArgs{} }
func (GetValueFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetValueArgs)
	data, err := rt.FS.ReadFile(a.File)
	if err != nil {
		return false, nil
	}
	root, perr := parseDocument(data)
	if perr != nil {
		return false, nil
	}
	el := findElement(root, a.Element)
	if el == nil {
		return false, nil
	}
	return el.text.String(), nil
}

type SetValueArgs struct {
	File    string `statekit:"required,name=file"`
	Element string `statekit:"required,name=element"`
	Value   any    `statekit:"name=value"`
}

type SetValueFunc struct{}

func (SetValueFunc) Name() string { return "xml.set_value" }
func (SetValueFunc) Args() any    { return SetValueArgs{} }
func (SetValueFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetValueArgs)
	data, err := rt.FS.ReadFile(a.File)
	if err != nil {
		return false, nil
	}
	root, perr := parseDocument(data)
	if perr != nil {
		return false, nil
	}
	el := findElement(root, a.Element)
	if el == nil {
		return false, nil
	}
	el.text.Reset()
	el.text.WriteString(scalarString(a.Value))
	return true, writeDocument(rt, root, a.File)
}

type GetAttributeArgs struct {
	File    string `statekit:"required,name=file"`
	Element string `statekit:"required,name=element"`
}

type GetAttributeFunc struct{}

func (GetAttributeFunc) Name() string { return "xml.get_attribute" }
func (GetAttributeFunc) Args() any    { return GetAttributeArgs{} }
func (GetAttributeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetAttributeArgs)
	data, err := rt.FS.ReadFile(a.File)
	if err != nil {
		return false, nil
	}
	root, perr := parseDocument(data)
	if perr != nil {
		return false, nil
	}
	el := findElement(root, a.Element)
	if el == nil || el.attr == nil {
		return false, nil
	}
	return el.attr, nil
}

type SetAttributeArgs struct {
	File    string `statekit:"required,name=file"`
	Element string `statekit:"required,name=element"`
	Key     string `statekit:"required,name=key"`
	Value   any    `statekit:"name=value"`
}

type SetAttributeFunc struct{}

func (SetAttributeFunc) Name() string { return "xml.set_attribute" }
func (SetAttributeFunc) Args() any    { return SetAttributeArgs{} }
func (SetAttributeFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetAttributeArgs)
	data, err := rt.FS.ReadFile(a.File)
	if err != nil {
		return false, nil
	}
	root, perr := parseDocument(data)
	if perr != nil {
		return false, nil
	}
	el := findElement(root, a.Element)
	if el == nil {
		return false, nil
	}
	if el.attr == nil {
		el.attr = map[string]string{}
	}
	el.attr[a.Key] = scalarString(a.Value)
	return true, writeDocument(rt, root, a.File)
}

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
	}
	return fmt.Sprintf("%v", v)
}

// Register installs all xml-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		GetValueFunc{},
		SetValueFunc{},
		GetAttributeFunc{},
		SetAttributeFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
