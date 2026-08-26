// Package pam implements Salt's PAM config parser (R5.3), mirroring
// saltstack/salt/modules/pam.py @ pinned revision. File access goes through
// the FileSystem abstraction so the bracketed control-flag grammar is
// testable hermetically.
package pam

import (
	"context"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type readFileArgs struct {
	FileName string `statekit:"required,name=file_name"`
}

type readFileFunc struct{}

func (readFileFunc) Name() string { return "pam.read_file" }
func (readFileFunc) Args() any    { return readFileArgs{} }
func (readFileFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPAM(&res, &err)
	a := args.(*readFileArgs)
	return parseFile(rt, a.FileName), nil
}

func recoverPAM(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

// parseFile ports _parse(contents=None, file_name=...): a missing file
// yields the literal False reply.
func parseFile(rt *runtime.Runtime, fileName string) any {
	data, rerr := rt.FS.ReadFile(fileName)
	if rerr != nil {
		return false
	}
	return parseContents(string(data))
}

// parseContents ports the _parse rule grammar, including the bracketed
// multi-word control-flag continuation.
func parseContents(contents string) []map[string]any {
	var rules []map[string]any
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		comps := strings.Fields(line)
		if len(comps) < 2 {
			continue
		}
		controlFlag := ""
		module := ""
		var arguments []string
		interfaceName := comps[0]
		position := 1
		if strings.HasPrefix(comps[1], "[") {
			controlFlag = strings.Replace(comps[1], "[", "", 1)
			for _, part := range comps[2:] {
				position++
				if strings.HasSuffix(part, "]") {
					controlFlag += " " + strings.Replace(part, "]", "", 1)
					position++
					break
				}
				controlFlag += " " + part
			}
		} else {
			controlFlag = comps[1]
			position++
		}
		if position < len(comps) {
			module = comps[position]
			if len(comps) > position {
				position++
				if position <= len(comps) {
					arguments = comps[position:]
				}
			}
		}
		rules = append(rules, map[string]any{
			"interface":    interfaceName,
			"control_flag": controlFlag,
			"module":       module,
			"arguments":    arguments,
		})
	}
	if rules == nil {
		rules = []map[string]any{}
	}
	return rules
}

// Register installs the R5.3 pam surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		readFileFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
