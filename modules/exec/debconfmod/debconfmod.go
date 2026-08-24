// Package debconfmod implements Salt's debconf surface: selections
// querying plus the set/set_file/set_template writers, over the central
// Runner and the injectable filesystem.
//
// Reference: saltstack/salt/modules/debconfmod.py @ pinned revision
// (references/salt.lock). Behavioral tests mapped from
// saltstack/tests/pytests/unit/modules/test_debconfmod.py.
//
// Contract notes (init.md section 28):
//
//   - The module loads only on Debian-family hosts with the debconf-utils
//     toolchain present; both __virtual__ guards are checked per call with
//     the verbatim load-failure messages.
//   - set_ registers under its CLI-facing alias debconf.set.
//   - set_template requires cp.get_template; templating stays excluded, so
//     the delegate absence surfaces UnsupportedError (documented).
package debconfmod

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

var whichBin = func(name string) string { return lookPathBin(name) }

func lookPathBin(exe string) string {
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + exe); err == nil {
			return dir + "/" + exe
		}
	}
	return ""
}

func backendErr(rt *runtime.Runtime) error {
	if rt.Facts == nil || rt.Facts.OS().Family != facts.FamilyDebian {
		return fmt.Errorf("The debconfmod module could not be loaded: unsupported OS family")
	}
	if whichBin("debconf-get-selections") == "" {
		return fmt.Errorf("The debconfmod module could not be loaded: debconf-utils is not installed.")
	}
	return nil
}

// unpackLines mirrors _unpack_lines over the (?ms) record regex.
var unpackLineRe = regexp.MustCompile(
	`(?m)^([^#]\S+)[\t ]+(\S+)[\t ]+(\S+)[\t ]+([^\n]*)$`)

type selection struct{ pkg, question, typ, value string }

func unpackLines(out string) []selection {
	matches := unpackLineRe.FindAllStringSubmatch(out, -1)
	lines := make([]selection, 0, len(matches))
	for _, m := range matches {
		lines = append(lines, selection{pkg: m[1], question: m[2], typ: m[3], value: m[4]})
	}
	return lines
}

type GetSelectionsArgs struct {
	FetchEmpty *bool `statekit:"name=fetchempty"`
}

type getSelectionsFunc struct{}

func (getSelectionsFunc) Name() string { return "debconf.get_selections" }
func (getSelectionsFunc) Args() any    { return GetSelectionsArgs{} }
func (getSelectionsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*GetSelectionsArgs)
	if err := backendErr(rt); err != nil {
		return nil, err
	}
	fetchEmpty := true
	if a.FetchEmpty != nil {
		fetchEmpty = *a.FetchEmpty
	}
	res := rt.Runner.Run(ctx, runtime.Command("debconf-get-selections"))
	stdout := ""
	if res.Err == nil {
		stdout = string(res.Stdout)
	}
	selections := map[string][][]string{}
	for _, line := range unpackLines(stdout) {
		if !fetchEmpty && line.value == "" {
			continue
		}
		selections[line.pkg] = append(selections[line.pkg], []string{line.question, line.typ, line.value})
	}
	return selections, nil
}

type ShowArgs struct {
	Name string `statekit:"required"`
}

type showFunc struct{}

func (showFunc) Name() string { return "debconf.show" }
func (showFunc) Args() any    { return ShowArgs{} }
func (showFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowArgs)
	sel, err := getSelectionsFunc{}.Execute(ctx, rt, &GetSelectionsArgs{})
	if err != nil {
		return nil, err
	}
	selections := sel.(map[string][][]string)
	result, ok := selections[a.Name]
	if !ok {
		return nil, nil
	}
	return result, nil
}

// setFileRun mirrors _set_file: `debconf-set-selections <path>`.
func setFileRun(ctx context.Context, rt *runtime.Runtime, path string) {
	rt.Runner.Run(ctx, runtime.Command("debconf-set-selections", path))
}

type SetArgs struct {
	Package  string   `statekit:"required,name=package"`
	Question string   `statekit:"required,name=question"`
	Type     string   `statekit:"required,name=type"`
	Value    string   `statekit:"required,name=value"`
	Extra    []string `statekit:"name=extra"`
}

type setFunc struct{}

// Name resolves through Salt's __func_alias__ ("set_" -> "set").
func (setFunc) Name() string { return "debconf.set" }
func (setFunc) Args() any    { return SetArgs{} }

func (setFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetArgs)
	if err := backendErr(rt); err != nil {
		return nil, err
	}
	value := a.Value
	if len(a.Extra) > 0 {
		value = strings.Join(append([]string{a.Value}, a.Extra...), " ")
	}
	fname, err := rt.FS.MkdirTemp("", "salt-")
	if err != nil {
		return nil, err
	}
	tmpFile := fname + "/selections"
	line := fmt.Sprintf("%s %s %s %s", a.Package, a.Question, a.Type, value)
	if werr := rt.FS.WriteFile(tmpFile, []byte(line), 0o600); werr != nil {
		return nil, werr
	}
	setFileRun(ctx, rt, tmpFile)
	rt.FS.RemoveAll(fname)
	return true, nil
}

type SetTemplateArgs struct {
	Path     string         `statekit:"required"`
	Template string         `statekit:"required,name=template"`
	Context  map[string]any `statekit:"name=context"`
	Defaults map[string]any `statekit:"name=defaults"`
	Saltenv  string         `statekit:"name=saltenv"`
}

type setTemplateFunc struct{}

func (setTemplateFunc) Name() string { return "debconf.set_template" }
func (setTemplateFunc) Args() any    { return SetTemplateArgs{} }
func (setTemplateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	// cp.get_template is unavailable until templating is scoped; upstream
	// delegates rendering entirely to it.
	_ = ctx
	_ = rt
	return nil, &runtime.UnsupportedError{Kind: "function", Name: "cp.get_template"}
}

type SetFileArgs struct {
	Path    string `statekit:"required"`
	Saltenv string `statekit:"name=saltenv"`
}

type setFileFunc struct{}

func (setFileFunc) Name() string { return "debconf.set_file" }
func (setFileFunc) Args() any    { return SetFileArgs{} }
func (setFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetFileArgs)
	if err := backendErr(rt); err != nil {
		return nil, err
	}
	if validProtoRe.MatchString(a.Path) {
		return false, &runtime.UnsupportedError{Kind: "function", Name: "cp.cache_file"}
	}
	setFileRun(ctx, rt, a.Path)
	return true, nil
}

var validProtoRe = regexp.MustCompile(`^(?:salt|https?|ftp|file)://`)

// Register installs all debconf execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getSelectionsFunc{},
		showFunc{},
		setFunc{},
		setTemplateFunc{},
		setFileFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ExportWhichBin returns the current toolchain-resolution hook (for test
// save/restore).
func ExportWhichBin() func(string) string { return whichBin }

// SetWhichBin overrides the binary-resolution hook (for tests).
func SetWhichBin(fn func(string) string) { whichBin = fn }
