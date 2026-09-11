package selinux

// File-context policy port: saltstack/salt/modules/selinux.py @ pinned
// revision. Upstream pipes `semanage fcontext --list` through grep -E; the
// shell-free Runner returns the listing and the ERE filtering happens
// in-process, line-oriented exactly like grep. restorecon -n -v provides
// the would-change preview (fcontext_policy_is_applied) and restorecon
// -v -F applies it (fcontext_apply_policy).

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// contextValidRe mirrors _context_string_to_dict's validation
// "[^:]+:[^:]+:[^:]+:[^:]+$" including Python's $ (end, or just before a
// single trailing newline).
var contextValidRe = regexp.MustCompile(`^[^:]+:[^:]+:[^:]+:[^:]+\n?$`)

// wouldRelabelRe and restoreconResetRe mirror the re.M findall patterns of
// fcontext_apply_policy.
var (
	wouldRelabelRe    = regexp.MustCompile(`(?m)Would relabel (.*) from (.*) to (.*)$`)
	restoreconResetRe = regexp.MustCompile(`(?m)restorecon reset (.*) context (.*)->(.*)$`)
)

// contextStringToDict mirrors _context_string_to_dict: validate the
// four-component context, then split into sel_user/sel_role/sel_type/
// sel_level with the verbatim SaltInvocationError text.
func contextStringToDict(context string) (map[string]any, error) {
	if !contextValidRe.MatchString(context) {
		return nil, fmt.Errorf(
			`Invalid SELinux context string: %s. Expected "sel_user:sel_role:sel_type:sel_level"`, context)
	}
	parts := strings.SplitN(context, ":", 4)
	return map[string]any{
		"sel_user":  parts[0],
		"sel_role":  parts[1],
		"sel_type":  parts[2],
		"sel_level": parts[3],
	}, nil
}

// grepOutput emulates upstream's `cmd.shell("semanage ... | grep -E 'pat'")`:
// every stdout line matching the ERE (unanchored per grep) is kept and the
// matches are joined with newlines like grep's own output would be. An
// empty result means grep found nothing (ignore_retcode).
func grepOutput(stdout string, pattern string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid filter pattern: %w", err)
	}
	var matched []string
	for _, line := range strings.Split(stdout, "\n") {
		if re.MatchString(line) {
			matched = append(matched, line)
		}
	}
	return strings.Join(matched, "\n"), nil
}

// runAllResult maps a CommandResult onto Salt's cmd.run_all dict
// {retcode, stdout, stderr}; pid is not tracked by the central Runner
// (documented boundary).
func runAllResult(res process.CommandResult) map[string]any {
	return map[string]any{
		"retcode": res.ExitCode,
		"stdout":  string(res.Stdout),
		"stderr":  string(res.Stderr),
	}
}

// FcontextPolicyArgs carries the shared name/filetype/context parameters of
// fcontext_get_policy, fcontext_add_policy, and fcontext_delete_policy.
type FcontextPolicyArgs struct {
	Name     string  `statekit:"required"`
	Filetype *string `statekit:"name=filetype"`
	SelType  *string `statekit:"name=sel_type"`
	SelUser  *string `statekit:"name=sel_user"`
	SelLevel *string `statekit:"name=sel_level"`
}

type fcontextGetPolicyFunc struct {
	linuxOnly
}

func (fcontextGetPolicyFunc) Name() string { return "selinux.fcontext_get_policy" }
func (fcontextGetPolicyFunc) Args() any    { return FcontextPolicyArgs{} }
func (fcontextGetPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FcontextPolicyArgs)
	if err := whichGuard("semanage"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", a.Name); err != nil {
		return nil, err
	}
	// `sel_user or "[^:]+"`: empty strings fall back to the permissive
	// pattern, and a provided value interpolates as a raw regex like the
	// pinned source (RE2 keeps that safe from backtracking blowups).
	selUser, selType, selLevel := `[^:]+`, `[^:]+`, `[^:]+`
	if a.SelUser != nil && *a.SelUser != "" {
		selUser = *a.SelUser
	}
	if a.SelType != nil && *a.SelType != "" {
		selType = *a.SelType
	}
	if a.SelLevel != nil && *a.SelLevel != "" {
		selLevel = *a.SelLevel
	}
	// se_role for file contexts is always object_r.
	fileTypePat := `[[:alpha:] ]+`
	if a.Filetype != nil && *a.Filetype != "" {
		desc, err := fileTypeFromCode(*a.Filetype)
		if err != nil {
			return nil, err
		}
		fileTypePat = desc
	}
	res := rt.Runner.Run(ctx, runtime.Command("semanage", "fcontext", "--list"))
	if res.Err != nil {
		return nil, res.Err
	}
	pattern := "^" + regexp.QuoteMeta(a.Name) + `[ ]+` + fileTypePat + `[ ]+` +
		selUser + `:[^:]+:` + selType + `:` + selLevel + "[ |\t]*$"
	entry, err := grepOutput(string(res.Stdout), pattern)
	if err != nil {
		return nil, err
	}
	if entry == "" {
		return nil, nil // Python None: no exact match
	}
	// Python re.match over grep's joined output: the first line must parse
	// and a trailing newline is tolerated, while a second matching line
	// makes the match fail exactly like upstream.
	parseRe, perr := regexp.Compile(`^(` + regexp.QuoteMeta(a.Name) + `) +([a-z ]+) (.*)\n?$`)
	if perr != nil {
		return nil, perr
	}
	parts := parseRe.FindStringSubmatch(entry)
	if parts == nil {
		return nil, fmt.Errorf("Output from the fcontext command did not match the expected format")
	}
	ret := map[string]any{
		"filespec": strings.TrimSpace(parts[1]),
		"filetype": strings.TrimSpace(parts[2]),
	}
	context, cerr := contextStringToDict(strings.TrimSpace(parts[3]))
	if cerr != nil {
		return nil, cerr
	}
	for key, value := range context {
		ret[key] = value
	}
	return ret, nil
}

type fcontextAddPolicyFunc struct {
	linuxOnly
}

func (fcontextAddPolicyFunc) Name() string { return "selinux.fcontext_add_policy" }
func (fcontextAddPolicyFunc) Args() any    { return FcontextPolicyArgs{} }
func (fcontextAddPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fcontextAddOrDeletePolicy(ctx, rt, "add", args.(*FcontextPolicyArgs))
}

type fcontextDeletePolicyFunc struct {
	linuxOnly
}

func (fcontextDeletePolicyFunc) Name() string { return "selinux.fcontext_delete_policy" }
func (fcontextDeletePolicyFunc) Args() any    { return FcontextPolicyArgs{} }
func (fcontextDeletePolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	return fcontextAddOrDeletePolicy(ctx, rt, "delete", args.(*FcontextPolicyArgs))
}

// fcontextAddOrDeletePolicy mirrors _fcontext_add_or_delete_policy: an add
// for a filespec with an existing entry flips to --modify (semanage raises
// ValueError otherwise), --ftype stays off for the "a" default, and the
// result is the cmd.run_all dict.
func fcontextAddOrDeletePolicy(ctx context.Context, rt *runtime.Runtime, action string, a *FcontextPolicyArgs) (map[string]any, error) {
	if err := whichGuard("semanage"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", a.Name); err != nil {
		return nil, err
	}
	if action == "add" {
		res := rt.Runner.Run(ctx, runtime.Command("semanage", "fcontext", "--list"))
		if res.Err != nil {
			return nil, res.Err
		}
		// grep -E '{re.escape(name)} ': the filespec followed by one space,
		// anywhere in a line.
		existing, err := grepOutput(string(res.Stdout), regexp.QuoteMeta(a.Name)+" ")
		if err != nil {
			return nil, err
		}
		if existing != "" {
			action = "modify"
		}
	}
	argv := []string{"semanage", "fcontext", "--" + action}
	// "semanage --ftype a" isn't valid on Centos 6; "a" is the default
	// filetype, so the flag stays off for it.
	if a.Filetype != nil && *a.Filetype != "a" {
		if _, err := fileTypeFromCode(*a.Filetype); err != nil {
			return nil, err
		}
		argv = append(argv, "--ftype", *a.Filetype)
	}
	if a.SelType != nil {
		if err := validateArgRunes("sel_type", *a.SelType); err != nil {
			return nil, err
		}
		argv = append(argv, "--type", *a.SelType)
	}
	if a.SelUser != nil {
		if err := validateArgRunes("sel_user", *a.SelUser); err != nil {
			return nil, err
		}
		argv = append(argv, "--seuser", *a.SelUser)
	}
	if a.SelLevel != nil {
		if err := validateArgRunes("sel_level", *a.SelLevel); err != nil {
			return nil, err
		}
		argv = append(argv, "--range", *a.SelLevel)
	}
	argv = append(argv, a.Name)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	ret := runAllResult(res)
	if res.Err != nil {
		return ret, res.Err
	}
	return ret, nil
}

type FcontextPolicyIsAppliedArgs struct {
	Name      string `statekit:"required"`
	Recursive bool   `statekit:"name=recursive"`
}

type fcontextPolicyIsAppliedFunc struct {
	linuxOnly
}

func (fcontextPolicyIsAppliedFunc) Name() string { return "selinux.fcontext_policy_is_applied" }
func (fcontextPolicyIsAppliedFunc) Args() any    { return FcontextPolicyIsAppliedArgs{} }
func (fcontextPolicyIsAppliedFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FcontextPolicyIsAppliedArgs)
	if err := whichGuard("restorecon"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", a.Name); err != nil {
		return nil, err
	}
	argv := []string{"restorecon", "-n", "-v"}
	if a.Recursive {
		argv = append(argv, "-R")
	}
	res := rt.Runner.Run(ctx, runtime.Command(append(argv, a.Name)...))
	if res.Err != nil {
		return nil, res.Err
	}
	return string(res.Stdout), nil // run_all().get("stdout")
}

type FcontextApplyPolicyArgs struct {
	Name      string `statekit:"required"`
	Recursive bool   `statekit:"name=recursive"`
}

type fcontextApplyPolicyFunc struct {
	linuxOnly
}

func (fcontextApplyPolicyFunc) Name() string { return "selinux.fcontext_apply_policy" }
func (fcontextApplyPolicyFunc) Args() any    { return FcontextApplyPolicyArgs{} }
func (fcontextApplyPolicyFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FcontextApplyPolicyArgs)
	if err := whichGuard("restorecon"); err != nil {
		return nil, err
	}
	if err := validateArgRunes("name", a.Name); err != nil {
		return nil, err
	}
	// Preview through restorecon -n -v (fcontext_policy_is_applied).
	previewArgv := []string{"restorecon", "-n", "-v"}
	if a.Recursive {
		previewArgv = append(previewArgv, "-R")
	}
	preview := rt.Runner.Run(ctx, runtime.Command(append(previewArgv, a.Name)...))
	if preview.Err != nil {
		return nil, preview.Err
	}
	changesText := string(preview.Stdout)

	applyArgv := []string{"restorecon", "-v", "-F"}
	if a.Recursive {
		applyArgv = append(applyArgv, "-R")
	}
	apply := rt.Runner.Run(ctx, runtime.Command(append(applyArgv, a.Name)...))
	ret := runAllResult(apply)
	if apply.Err != nil {
		return ret, apply.Err
	}
	if apply.ExitCode == 0 {
		var changes [][]string
		switch {
		case strings.HasPrefix(changesText, "Would relabel"):
			changes = wouldRelabelRe.FindAllStringSubmatch(changesText, -1)
		case strings.HasPrefix(changesText, "restorecon reset"):
			changes = restoreconResetRe.FindAllStringSubmatch(changesText, -1)
		default:
			// Faithful quirk: empty or unrecognized preview output (e.g. an
			// already-conformant tree) reports the unrecognized response.
			ret["retcode"] = 1
			ret["error"] = "Unrecognized response from restorecon command."
			return ret, nil
		}
		if len(changes) > 0 {
			ret["changes"] = map[string]any{}
		}
		for _, item := range changes {
			// Go submatch slices carry the full match at [0]; upstream's
			// findall tuples are item[1:] (filespec, old, new).
			old, err := contextStringToDict(item[2])
			if err != nil {
				return nil, err
			}
			newCtx, err := contextStringToDict(item[3])
			if err != nil {
				return nil, err
			}
			intersect := map[string]any{}
			for key, value := range old {
				if nv, ok := newCtx[key]; ok && nv == value {
					intersect[key] = value
				}
			}
			for key := range intersect {
				delete(old, key)
				delete(newCtx, key)
			}
			ret["changes"].(map[string]any)[item[1]] = map[string]any{"old": old, "new": newCtx}
		}
	}
	return ret, nil
}
