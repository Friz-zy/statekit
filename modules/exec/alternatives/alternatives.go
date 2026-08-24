// Package alternatives implements Salt's alternatives-system module:
// display/install/remove/auto/set plus the link-inspection helpers, over
// the central Runner and the injectable filesystem.
//
// Reference: saltstack/salt/modules/alternatives.py @ pinned revision
// (references/salt.lock). Behavioral tests mapped from
// saltstack/tests/pytests/unit/modules/test_alternatives.py.
//
// Contract notes (init.md section 28):
//
//   - The command selection mirrors _get_cmd: `alternatives` on RedHat,
//     `update-alternatives` everywhere else.
//   - set_ registers under its CLI-facing alias alternatives.set like the
//     __func_alias__ mapping upstream (bridge.list precedent).
package alternatives

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

// System paths are package variables for hermetic redirection, mirroring
// the patched locations in the upstream tests.
var (
	etcAlternativesDir = "/etc/alternatives"
	redHatAltDir       = "/var/lib/alternatives"
	suseAltDir         = "/var/lib/rpm/alternatives"
)

// getCmd mirrors _get_cmd across distributions.
func getCmd(rt *runtime.Runtime) string {
	if rt.Facts != nil && rt.Facts.OS().Family == facts.FamilyRedHat {
		return "alternatives"
	}
	return "update-alternatives"
}

func runAll(ctx context.Context, rt *runtime.Runtime, argv []string) map[string]any {
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return map[string]any{
		"retcode": exitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

// outputFor picks stderr on failure with content, stdout otherwise —
// the shared return shape of display/install/remove/auto/set_
func outputFor(out map[string]any) string {
	retcode := out["retcode"].(int)
	stdout, _ := out["stdout"].(string)
	stderr, _ := out["stderr"].(string)
	if retcode > 0 && stderr != "" {
		return stderr
	}
	return stdout
}

type DisplayArgs struct {
	Name string `statekit:"required"`
}

type displayFunc struct{}

func (displayFunc) Name() string { return "alternatives.display" }
func (displayFunc) Args() any    { return DisplayArgs{} }

func (displayFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*DisplayArgs)
	out := runAll(ctx, rt, []string{getCmd(rt), "--display", a.Name})
	return outputFor(out), nil
}

// readAlternativeLinkDirectly mirrors _read_alternative_link_directly:
// the second physical line of the alternative's metadata file.
func readAlternativeLinkDirectly(rt *runtime.Runtime, dir, name string) (string, bool) {
	data, err := rt.FS.ReadFile(filepathJoin(dir, name))
	if err != nil {
		return "", false
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) < 2 {
		return "", false
	}
	return strings.TrimRight(lines[1], "\n"), true
}

// readAlternativeLinkWithCommand mirrors _read_alternative_link_with_command:
// the Link: field of the first --query block.
func readAlternativeLinkWithCommand(ctx context.Context, rt *runtime.Runtime, name string) (string, bool) {
	out := runAll(ctx, rt, []string{getCmd(rt), "--query", name})
	retcode := out["retcode"].(int)
	stderr, _ := out["stderr"].(string)
	stdout, _ := out["stdout"].(string)
	if retcode > 0 && stderr != "" {
		return "", false
	}
	firstBlock := stdout
	if idx := strings.Index(stdout, "\n\n"); idx >= 0 {
		firstBlock = stdout[:idx]
	}
	for _, line := range strings.Split(firstBlock, "\n") {
		if strings.HasPrefix(line, "Link:") {
			value := ""
			if _, after, found := strings.Cut(line, ":"); found {
				value = strings.TrimSpace(after)
			} else if _, after2, found2 := strings.Cut(line, "Link: "); found2 {
				value = strings.TrimSpace(after2)
			}
			return value, true
		}
	}
	return "", false
}

func filepathJoin(parts ...string) string {
	out := strings.TrimSuffix(parts[0], "/")
	for _, p := range parts[1:] {
		out += "/" + strings.TrimPrefix(p, "/")
	}
	return out
}

type ShowLinkArgs struct {
	Name string `statekit:"required"`
}

type showLinkFunc struct{}

func (showLinkFunc) Name() string { return "alternatives.show_link" }
func (showLinkFunc) Args() any    { return ShowLinkArgs{} }

func (showLinkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowLinkArgs)
	family := ""
	if rt.Facts != nil {
		family = rt.Facts.OS().Family
	}
	switch family {
	case facts.FamilyRedHat:
		v, ok := readAlternativeLinkDirectly(rt, redHatAltDir, a.Name)
		if !ok {
			return false, nil
		}
		return v, nil
	case facts.FamilySuse:
		v, ok := readAlternativeLinkDirectly(rt, suseAltDir, a.Name)
		if !ok {
			return false, nil
		}
		return v, nil
	default:
		v, ok := readAlternativeLinkWithCommand(ctx, rt, a.Name)
		if !ok {
			return false, nil
		}
		return v, nil
	}
}

type ShowCurrentArgs struct {
	Name string `statekit:"required"`
}

type showCurrentFunc struct{}

func (showCurrentFunc) Name() string { return "alternatives.show_current" }
func (showCurrentFunc) Args() any    { return ShowCurrentArgs{} }
func (showCurrentFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ShowCurrentArgs)
	link, err := rt.FS.Readlink(filepathJoin(etcAlternativesDir, a.Name))
	if err != nil {
		return false, nil
	}
	return link, nil
}

type CheckExistsArgs struct {
	Name string `statekit:"required,name=name"`
	Path string `statekit:"required,name=path"`
}

type checkExistsFunc struct{}

func (checkExistsFunc) Name() string { return "alternatives.check_exists" }
func (checkExistsFunc) Args() any    { return CheckExistsArgs{} }
func (checkExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckExistsArgs)
	out := runAll(ctx, rt, []string{getCmd(rt), "--display", a.Name})
	retcode := out["retcode"].(int)
	stderr, _ := out["stderr"].(string)
	stdout, _ := out["stdout"].(string)
	if retcode > 0 && stderr != "" {
		return false, nil
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, a.Path) {
			return true, nil
		}
	}
	return false, nil
}

type CheckInstalledArgs struct {
	Name string `statekit:"required,name=name"`
	Path string `statekit:"required,name=path"`
}

type checkInstalledFunc struct{}

func (checkInstalledFunc) Name() string { return "alternatives.check_installed" }
func (checkInstalledFunc) Args() any    { return CheckInstalledArgs{} }
func (checkInstalledFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CheckInstalledArgs)
	link, err := rt.FS.Readlink(filepathJoin(etcAlternativesDir, a.Name))
	if err != nil {
		return false, nil
	}
	return link == a.Path, nil
}

type InstallArgs struct {
	Name     string `statekit:"required,name=name"`
	Link     string `statekit:"required,name=link"`
	Path     string `statekit:"required,name=path"`
	Priority int    `statekit:"name=priority"`
}

type installFunc struct{}

func (installFunc) Name() string { return "alternatives.install" }
func (installFunc) Args() any    { return InstallArgs{} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InstallArgs)
	out := runAll(ctx, rt, []string{
		getCmd(rt), "--install", a.Link, a.Name, a.Path, fmt.Sprintf("%d", a.Priority),
	})
	return outputFor(out), nil
}

type RemoveArgs struct {
	Name string `statekit:"required,name=name"`
	Path string `statekit:"required,name=path"`
}

type removeFunc struct{}

func (removeFunc) Name() string { return "alternatives.remove" }
func (removeFunc) Args() any    { return RemoveArgs{} }
func (removeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RemoveArgs)
	out := runAll(ctx, rt, []string{getCmd(rt), "--remove", a.Name, a.Path})
	retcode := out["retcode"].(int)
	stdout, _ := out["stdout"].(string)
	stderr, _ := out["stderr"].(string)
	if retcode > 0 {
		return stderr, nil
	}
	return stdout, nil
}

type AutoArgs struct {
	Name string `statekit:"required"`
}

type autoFunc struct{}

func (autoFunc) Name() string { return "alternatives.auto" }
func (autoFunc) Args() any    { return AutoArgs{} }
func (autoFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AutoArgs)
	out := runAll(ctx, rt, []string{getCmd(rt), "--auto", a.Name})
	retcode := out["retcode"].(int)
	stdout, _ := out["stdout"].(string)
	stderr, _ := out["stderr"].(string)
	if retcode > 0 {
		return stderr, nil
	}
	return stdout, nil
}

type SetArgs struct {
	Name string `statekit:"required,name=name"`
	Path string `statekit:"required,name=path"`
}

type setFunc struct{}

// Name resolves through Salt's __func_alias__ ("set_" -> "set").
func (setFunc) Name() string { return "alternatives.set" }
func (setFunc) Args() any    { return SetArgs{} }
func (setFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetArgs)
	out := runAll(ctx, rt, []string{getCmd(rt), "--set", a.Name, a.Path})
	retcode := out["retcode"].(int)
	stdout, _ := out["stdout"].(string)
	stderr, _ := out["stderr"].(string)
	if retcode > 0 {
		return stderr, nil
	}
	return stdout, nil
}

// Register installs all alternatives execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		displayFunc{},
		showLinkFunc{},
		showCurrentFunc{},
		checkExistsFunc{},
		checkInstalledFunc{},
		installFunc{},
		removeFunc{},
		autoFunc{},
		setFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

// ensure os stays referenced for future path helpers.
var _ = os.Getenv
