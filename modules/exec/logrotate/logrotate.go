// Package logrotate manages logrotate configuration, mirroring
// saltstack/salt/modules/logrotate.py and saltstack/salt/states/logrotate.py
// @ pinned revision.
//
// Contract notes (init.md section 28): script directives
// (prerotate/postrotate/firstaction/lastaction/preremove) keep opaque body
// lines so embedded shell commands don't collapse into dict keys (issue
// #68293 round-trip behavior included in dictToStanza).
package logrotate

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultConf = "/etc/logrotate.conf"

var scriptDirectives = []string{
	"firstaction", "lastaction", "prerotate", "postrotate", "preremove",
}

func isScriptDirective(name string) bool {
	for _, d := range scriptDirectives {
		if d == name {
			return true
		}
	}
	return false
}

func convertIfInt(value string) any {
	if n, err := strconv.Atoi(value); err == nil {
		return n
	}
	return value
}

func parseConf(rt *runtime.Runtime, confFile string) map[string]any {
	ret := map[string]any{}
	mode := "single"
	var multiNames []string
	multi := map[string]any{}
	var prevComps []string
	scriptDirective := ""
	var scriptBody []string

	data, err := rt.FS.ReadFile(confFile)
	if err != nil {
		return ret
	}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(strings.TrimSuffix(rawLine, "\r"), "\n")
		stripped := strings.TrimSpace(line)

		if scriptDirective != "" {
			if stripped == "endscript" {
				if mode == "multi" {
					multi[scriptDirective] = append([]string{}, scriptBody...)
				} else {
					ret[scriptDirective] = append([]string{}, scriptBody...)
				}
				scriptDirective = ""
				scriptBody = nil
				continue
			}
			scriptBody = append(scriptBody, stripped)
			continue
		}

		line = stripped
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		comps := strings.Fields(line)

		if strings.Contains(line, "{") && !strings.Contains(line, "}") {
			mode = "multi"
			if len(comps) == 1 && len(prevComps) > 0 {
				multiNames = prevComps
			} else if len(comps) > 1 {
				multiNames = comps[:len(comps)-1]
			}
			prevComps = comps
			continue
		}
		if strings.Contains(line, "}") {
			mode = "single"
			for _, name := range multiNames {
				ret[name] = multi
			}
			multiNames = nil
			multi = map[string]any{}
			prevComps = comps
			continue
		}

		var target map[string]any
		if mode == "multi" {
			target = multi
		} else {
			target = ret
		}

		if comps[0] == "include" && len(comps) > 1 {
			includeDir := comps[1]
			entries, derr := rt.FS.ReadDir(includeDir)
			if derr != nil {
				prevComps = comps
				continue
			}
			includeFilesAny, ok := ret["include files"]
			var includeFiles map[string]any
			if !ok {
				includeFiles = map[string]any{}
				ret["include files"] = includeFiles
			} else {
				includeFiles = includeFilesAny.(map[string]any)
			}
			for _, entry := range entries {
				name := entry.Name()
				listAny, seen := includeFiles[name]
				var list []string
				if !seen {
					list = []string{}
					includeFiles[name] = list
				} else {
					list = listAny.([]string)
				}
				includePath := filepath.Join(includeDir, name)
				includeConf := parseConf(rt, includePath)
				for fileKey, fileVal := range includeConf {
					ret[fileKey] = fileVal
					includeFiles[name] = append(list, fileKey)
					list = includeFiles[name].([]string)
				}
			}
			prevComps = comps
			continue
		}

		if isScriptDirective(comps[0]) && len(comps) == 1 {
			scriptDirective = comps[0]
			scriptBody = nil
			prevComps = comps
			continue
		}

		prevComps = comps

		switch {
		case len(comps) > 2:
			target[comps[0]] = strings.Join(comps[1:], " ")
		case len(comps) > 1:
			target[comps[0]] = convertIfInt(comps[1])
		default:
			target[comps[0]] = true
		}
	}
	return ret
}

type ShowConfArgs struct {
	ConfFile *string `statekit:"name=conf_file"`
}

type ShowConfFunc struct{}

func (ShowConfFunc) Name() string { return "logrotate.show_conf" }
func (ShowConfFunc) Args() any    { return ShowConfArgs{} }
func (ShowConfFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowConfArgs)
	return parseConf(rt, orDefault(a.ConfFile, defaultConf)), nil
}

type GetArgs struct {
	Key      string  `statekit:"required,name=key"`
	Value    *string `statekit:"name=value"`
	ConfFile *string `statekit:"name=conf_file"`
}

type GetFunc struct{}

func (GetFunc) Name() string { return "logrotate.get" }
func (GetFunc) Args() any    { return GetArgs{} }
func (GetFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetArgs)
	conf := parseConf(rt, orDefault(a.ConfFile, defaultConf))
	stanza, ok := conf[a.Key]
	if !ok {
		return false, nil
	}
	if a.Value != nil && *a.Value != "" {
		stanzaMap, isMap := stanza.(map[string]any)
		if !isMap {
			return false, nil
		}
		if v, has := stanzaMap[*a.Value]; has {
			return v, nil
		}
		return false, nil
	}
	return stanza, nil
}

// dictToStanza mirrors _dict_to_stanza including the script-block emission
// fix from issue #68293.
func dictToStanza(key string, stanza map[string]any) string {
	keys := make([]string, 0, len(stanza))
	for k := range stanza {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ret := ""
	for _, skey := range keys {
		value := stanza[skey]
		if isScriptDirective(skey) {
			if list, ok := value.([]string); ok {
				ret += fmt.Sprintf("    %s\n", skey)
				for _, bodyLine := range list {
					ret += fmt.Sprintf("        %s\n", bodyLine)
				}
				ret += "    endscript\n"
				continue
			}
		}
		if b, ok := value.(bool); ok && b {
			ret += fmt.Sprintf("    %s\n", skey)
			continue
		}
		ret += fmt.Sprintf("    %s %v\n", skey, value)
	}
	return fmt.Sprintf("%s {\n%s}", key, ret)
}

type SetArgs struct {
	Key      string  `statekit:"required,name=key"`
	Value    any     `statekit:"required,name=value"`
	Setting  *string `statekit:"name=setting"`
	ConfFile *string `statekit:"name=conf_file"`
}

type SetFunc struct{}

func (SetFunc) Name() string { return "logrotate.set" }
func (SetFunc) Args() any    { return SetArgs{} }

func (SetFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetArgs)
	confFile := orDefault(a.ConfFile, defaultConf)
	conf := parseConf(rt, confFile)

	newLine := ""
	patternIsStanza := false

	if a.Setting == nil {
		currentValue, exists := conf[a.Key]
		if exists {
			if _, isMap := currentValue.(map[string]any); isMap {
				return false, fmt.Errorf(
					"Error: %s includes a dict, and a specific setting inside "+
						"the dict was not declared", a.Key)
			}
		}
		if equalAny(a.Value, currentValue) && exists {
			return true, nil
		}
		switch v := a.Value.(type) {
		case bool:
			if v {
				newLine = a.Key
			} else {
				newLine = "#" + a.Key
			}
		case string:
			if v == "" {
				newLine = a.Key
			} else {
				newLine = fmt.Sprintf("%s %s", a.Key, v)
			}
		default:
			newLine = fmt.Sprintf("%s %v", a.Key, v)
		}
	} else {
		stanzaRaw, hasStanza := conf[a.Key]
		if hasStanza {
			if _, isMap := stanzaRaw.(map[string]any); !isMap {
				return false, fmt.Errorf(
					"Error: A setting for a dict was declared, but the " +
						"configuration line given is not a dict")
			}
		}
		stanza, _ := stanzaRaw.(map[string]any)
		valueKey, _ := a.Value.(string)
		current := false
		if stanza != nil {
			if v, has := stanza[valueKey]; has {
				current = v == true
			}
		}
		settingBool := *a.Setting == "true"
		if settingBool == current {
			return true, nil
		}
		if stanza == nil {
			stanza = map[string]any{}
		}
		if *a.Setting != "" {
			stanza[valueKey] = *a.Setting
		} else {
			delete(stanza, valueKey)
		}
		newLine = dictToStanza(a.Key, stanza)
		patternIsStanza = true
	}

	return replaceConfLine(rt, confFile, a.Key, newLine, patternIsStanza)
}

// replaceConfLine mirrors file.replace with pattern="^{key}.*" and
// prepend_if_not_found=True (or the whole-stanza pattern for blocks).
func replaceConfLine(rt *runtime.Runtime, confFile, key, newLine string, stanzaMode bool) (bool, error) {
	data, rerr := rt.FS.ReadFile(confFile)
	if rerr != nil {
		data = nil
	}
	lines := splitLinesKeep(string(data))
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if stanzaMode {
			if strings.HasPrefix(trimmed, key) && strings.Contains(trimmed, "{") {
				lines[i] = newLine + "\n"
				found = true
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, key) &&
			!strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = newLine + "\n"
			found = true
			break
		}
	}
	if !found {
		prepended := []string{newLine + "\n"}
		lines = append(prepended, lines...)
	}
	if werr := rt.FS.WriteFile(confFile, []byte(strings.Join(lines, "\n")), 0o644); werr != nil {
		return false, werr
	}
	return true, nil
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

func splitLinesKeep(content string) []string {
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	// Preserve the trailing-newline invariant: "a\nb\n" splits into
	// ["a\n", "b\n", ""], and the final empty element must be dropped
	// so Join("\n") reconstructs the exact original bytes.
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
		for i := range lines {
			lines[i] += "\n"
		}
		return lines
	}
	for i := range lines {
		if i < len(lines)-1 {
			lines[i] += "\n"
		}
	}
	return lines
}

func equalAny(a, b any) bool {
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	ab, abok := a.(bool)
	bb, bbok := b.(bool)
	if abok && bbok {
		return ab == bb
	}
	an, anok := a.(int)
	bn, bnok := b.(int)
	if anok && bnok {
		return an == bn
	}
	return scalarString(a) == scalarString(b)
}

func orDefault(s *string, def string) string {
	if s != nil && *s != "" {
		return *s
	}
	return def
}

// Register installs all logrotate-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		ShowConfFunc{},
		GetFunc{},
		SetFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
