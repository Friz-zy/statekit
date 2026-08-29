package file

// File long-tail part 3 (R4.6): sed/sed_contains/patch — thin wrappers
// over the sed and patch binaries through the central Runner, mirroring
// saltstack/salt/modules/file.py @ pinned revision.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// sedEsc mirrors _sed_esc: single quotes and forward slashes always
// escape; regex metacharacters only when escape_all is set.
func sedEsc(s string, escapeAll bool) string {
	const specialChars = "^.[$()|*+?{"
	s = strings.ReplaceAll(s, "'", "'\"'\"'")
	s = strings.ReplaceAll(s, "/", `\/`)
	if escapeAll {
		for _, char := range specialChars {
			s = strings.ReplaceAll(s, string(char), `\`+string(char))
		}
	}
	return s
}

type sedArgs struct {
	Path        string  `statekit:"required,name=path"`
	Before      string  `statekit:"required,name=before"`
	After       string  `statekit:"required,name=after"`
	Limit       *string `statekit:"name=limit"`
	Backup      *string `statekit:"name=backup"`
	Options     *string `statekit:"name=options"`
	Flags       *string `statekit:"name=flags"`
	EscapeAll   bool    `statekit:"name=escape_all"`
	NegateMatch bool    `statekit:"name=negate_match"`
}

type sedFunc struct{}

func (sedFunc) Name() string { return "file.sed" }
func (sedFunc) Args() any    { return sedArgs{} }

// Sed mirrors sed(): missing files return False; options are shlex-split
// into argv exactly like upstream passing them to cmd.run_all.
func (sedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sedArgs)
	path := expandUser(a.Path)
	if _, serr := os.Stat(path); serr != nil {
		return false, nil
	}

	limit := strOrPtr(a.Limit)
	backup := strOrPtr2(a.Backup, ".bak")
	options := strOrPtr2(a.Options, "-r -e")
	flags := strOrPtr2(a.Flags, "g")

	before := sedEsc(a.Before, a.EscapeAll)
	after := sedEsc(a.After, a.EscapeAll)
	limit = sedEsc(limit, a.EscapeAll)

	cmd := []string{"sed", "-i" + backup}
	cmd = append(cmd, shellSplitFile(options)...)
	pattern := fmt.Sprintf("%s%s s/%s/%s/%s",
		limit, negateMark(a.NegateMatch), before, after, flags)
	cmd = append(cmd, pattern, path)

	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("Error applying sed: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return "", nil
}

type sedContainsArgs struct {
	Path  string `statekit:"required,name=path"`
	Text  string `statekit:"required,name=text"`
	Limit string `statekit:"name=limit"`
	Flags string `statekit:"name=flags"`
}

type sedContainsFunc struct{}

func (sedContainsFunc) Name() string { return "file.sed_contains" }
func (sedContainsFunc) Args() any    { return sedContainsArgs{} }

// SedContains mirrors sed_contains: missing files return False; the `p`
// flag appends to any caller flags.
func (sedContainsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*sedContainsArgs)
	path := expandUser(a.Path)
	if _, serr := os.Stat(path); serr != nil {
		return false, nil
	}
	before := sedEsc(a.Text, false)
	limit := sedEsc(a.Limit, false)
	flags := a.Flags
	if flags == "" {
		flags = "g"
	}
	flags += "p"

	cmd := []string{"sed", "-n", "-r", "-e"}
	pattern := fmt.Sprintf("%ss/%s/%s/%s", limit, before, before, flags)
	cmd = append(cmd, pattern, path)

	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	return len(res.Stdout) > 0, nil
}

type patchArgs struct {
	OriginalFile string  `statekit:"required,name=originalfile"`
	PatchFile    string  `statekit:"required,name=patchfile"`
	Options      *string `statekit:"name=options"`
	DryRun       bool    `statekit:"name=dry_run"`
}

type patchFunc struct{}

func (patchFunc) Name() string { return "file.patch" }
func (patchFunc) Args() any    { return patchArgs{} }

// Patch mirrors patch(): which-guard on the patch binary, BSD -C dry-run,
// --forward by default, --reject-file=- unless supplied, -d/--strip=0 for
// directory targets.
func (patchFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*patchArgs)
	originalfile := expandUser(a.OriginalFile)
	patchfile := expandUser(a.PatchFile)

	patchPath := lookPathBin("patch")
	if patchPath == "" {
		return nil, fmt.Errorf(
			"patch executable not found. Is the distribution's patch package installed?")
	}

	cmd := []string{patchPath}
	cmd = append(cmd, shellSplitFile(strOrPtr(a.Options))...)
	dryFlag := "--dry-run"
	switch goosIdent() {
	case "freebsd", "openbsd":
		dryFlag = "-C"
	}
	if a.DryRun {
		cmd = append(cmd, dryFlag)
	}
	if !containsPrefixOption(cmd, "-N") && !containsPrefixOption(cmd, "--forward") {
		cmd = append(cmd, "--forward")
	}
	if !hasRejectFileOption(cmd) {
		cmd = append(cmd, "--reject-file=-")
	}
	cmd = append(cmd, "-i", patchfile)

	if info, err := os.Stat(originalfile); err == nil && info.IsDir() {
		cmd = append(cmd, "-d", originalfile)
		if !hasStripOption(cmd) {
			cmd = append(cmd, "--strip=0")
		}
	} else {
		cmd = append(cmd, originalfile)
	}

	res := rt.Runner.Run(ctx, runtime.Command(cmd...))
	exitCode := res.ExitCode
	if res.Err != nil {
		exitCode = -1
	}
	return map[string]any{
		"pid":     nil,
		"retcode": exitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}, nil
}

func containsPrefixOption(argv []string, opt string) bool {
	for _, arg := range argv {
		if arg == opt || strings.HasPrefix(arg, opt+" ") {
			return true
		}
	}
	return false
}

func hasRejectFileOption(argv []string) bool {
	for _, arg := range argv {
		if arg == "-r" || strings.HasPrefix(arg, "-r ") || strings.HasPrefix(arg, "--reject-file") {
			return true
		}
	}
	return false
}

func hasStripOption(argv []string) bool {
	for _, arg := range argv {
		if strings.HasPrefix(arg, "-p") || strings.HasPrefix(arg, "--strip=") {
			return true
		}
	}
	return false
}

func strOrPtr2(s *string, def string) string {
	if s != nil && *s != "" {
		return *s
	}
	return def
}

func negateMark(negate bool) string {
	if negate {
		return "!"
	}
	return ""
}

// shellSplitFile mirrors salt.utils.args.shlex_split for option strings.
func shellSplitFile(cmd string) []string {
	var args []string
	var cur strings.Builder
	has := false
	inDouble := false
	inSingle := false
	escaped := false
	for _, c := range cmd {
		switch {
		case escaped:
			cur.WriteRune(c)
			escaped = false
		case c == '\\' && !inSingle && !inDouble:
			escaped = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			has = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			has = true
		case (c == ' ' || c == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 || has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 || has {
		args = append(args, cur.String())
	}
	return args
}

// RegisterPatch installs the R4.6 sed/patch functions alongside the base.
func RegisterPatch(reg *runtime.ExecRegistry) error {
	if runtime.CurrentGOOS() == "windows" {
		return nil
	}
	for _, fn := range []runtime.ExecFunction{
		sedFunc{},
		sedContainsFunc{},
		patchFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
