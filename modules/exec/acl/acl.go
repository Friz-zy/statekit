// Package acl implements Salt's Linux file-ACL surface (R5.3), mirroring
// saltstack/salt/modules/linux_acl.py @ pinned revision. The getfacl and
// setfacl binaries run through the central Runner with which-guards
// carrying upstream's __virtual__ message verbatim.
//
// Documented divergence: upstream assembles a quoted shell string; StateKit
// builds argv directly (equivalent for paths without spaces and safer
// overall).
package acl

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func execLookPathAcl(exe string) (string, error) { return exec.LookPath(exe) }

var whichBin = func(exe string) string {
	p, err := execLookPathAcl(exe)
	if err != nil {
		return ""
	}
	return p
}

func requireGetfacl() error {
	if whichBin("getfacl") == "" {
		return fmt.Errorf(
			"The linux_acl execution module cannot be loaded: the getfacl binary is not in" +
				" the path.")
	}
	return nil
}

func requireSetfacl() error {
	if whichBin("setfacl") == "" {
		return fmt.Errorf(
			"The linux_acl execution module cannot be loaded: the getfacl binary is not in" +
				" the path.")
	}
	return nil
}

type cmdExecErr struct{ msg string }

func (e *cmdExecErr) Error() string { return e.msg }

func recoverACL(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

func run(rt *runtime.Runtime, argv []string) string {
	res := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	return strings.TrimRight(string(res.Stdout), "\n")
}

func raiseOnNoFiles(files []string) {
	if len(files) == 0 {
		panic(&cmdExecErr{msg: "You need to specify at least one file or directory to work with!"})
	}
}

// ---------------------------------------------------------------------------
// acl.version

type versionArgs struct{}

type versionFunc struct{}

func (versionFunc) Name() string { return "acl.version" }
func (versionFunc) Args() any    { return versionArgs{} }
func (versionFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverACL(&res, &err)
	if gerr := requireGetfacl(); gerr != nil {
		return nil, gerr
	}
	out := run(rt, []string{"getfacl", "--version"})
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if len(fields) < 2 {
		return "", nil
	}
	return strings.TrimSpace(fields[1]), nil
}

// ---------------------------------------------------------------------------
// acl.getfacl

type getfaclArgs struct {
	Files     []string `statekit:"required,name=files"`
	Recursive *bool    `statekit:"name=recursive"`
}

type getfaclFunc struct{}

func (getfaclFunc) Name() string { return "acl.getfacl" }
func (getfaclFunc) Args() any    { return getfaclArgs{} }
func (getfaclFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverACL(&res, &err)
	a := args.(*getfaclArgs)
	raiseOnNoFiles(a.Files)
	if gerr := requireGetfacl(); gerr != nil {
		return nil, gerr
	}
	argv := []string{"getfacl", "--absolute-names"}
	if a.Recursive != nil && *a.Recursive {
		argv = append(argv, "-R")
	}
	argv = append(argv, a.Files...)
	out := run(rt, argv)

	ret := map[string]any{}
	dentry := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "getfacl") {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			entry, ok := ret[dentry].(map[string]any)
			if !ok {
				continue
			}
			owner, _ := entry["comment"].(map[string]any)["owner"].(string)
			group, _ := entry["comment"].(map[string]any)["group"].(string)
			vals := parseACL(line, owner, group)
			aclType := vals["type"]
			delete(vals, "type")
			for _, entity := range []string{"user", "group"} {
				usergroup, has := vals[entity]
				if !has {
					continue
				}
				delete(vals, entity)
				if aclType == "acl" {
					list, _ := entry[entity].([]map[string]any)
					entry[entity] = append(list, map[string]any{
						fmt.Sprintf("%v", usergroup): cloneWithout(vals, nil),
					})
				} else if aclType == "default" {
					defaults, _ := entry["defaults"].(map[string]any)
					if defaults == nil {
						defaults = map[string]any{}
						entry["defaults"] = defaults
					}
					list, _ := defaults[entity].([]map[string]any)
					defaults[entity] = append(list, map[string]any{
						fmt.Sprintf("%v", usergroup): cloneWithout(vals, nil),
					})
				}
			}
			for _, entity := range []string{"other", "mask"} {
				if _, has := vals[entity]; !has {
					continue
				}
				delete(vals, entity)
				wrapped := map[string]any{"": vals}
				if aclType == "acl" {
					entry[entity] = []map[string]any{wrapped}
				} else if aclType == "default" {
					defaults, _ := entry["defaults"].(map[string]any)
					if defaults == nil {
						defaults = map[string]any{}
						entry["defaults"] = defaults
					}
					defaults[entity] = []map[string]any{wrapped}
				}
			}
			continue
		}
		comps := strings.Split(strings.Replace(line, "# ", "", 1), ": ")
		if len(comps) < 2 {
			continue
		}
		if comps[0] == "file" {
			dentry = comps[1]
			ret[dentry] = map[string]any{
				"comment": map[string]any{},
				"user":    []map[string]any{},
				"group":   []map[string]any{},
			}
		}
		entry, ok := ret[dentry].(map[string]any)
		if !ok {
			continue
		}
		comment := entry["comment"].(map[string]any)
		comment[comps[0]] = comps[1]
		if comps[0] == "flags" {
			flags := strings.Split(comps[1], "")
			if len(flags) >= 1 && flags[0] == "s" {
				entry["suid"] = true
			}
			if len(flags) >= 2 && flags[1] == "s" {
				entry["sgid"] = true
			}
			if len(flags) >= 3 && flags[2] == "t" {
				entry["sticky"] = true
			}
		}
	}
	return ret, nil
}

func cloneWithout(vals map[string]any, _ any) map[string]any {
	out := map[string]any{}
	for k, v := range vals {
		out[k] = v
	}
	return out
}

// parseACL ports _parse_acl.
func parseACL(aclLine, user, group string) map[string]any {
	comps := strings.Split(aclLine, ":")
	vals := map[string]any{}

	vals["type"] = "acl"
	if comps[0] == "default" {
		vals["type"] = "default"
		comps = comps[1:]
	}
	if len(comps) < 2 {
		return vals
	}
	if comps[0] == "user" && comps[1] == "" {
		comps[1] = user
	} else if comps[0] == "group" && comps[1] == "" {
		comps[1] = group
	}
	vals[comps[0]] = comps[1]

	octal := 0
	perms := map[string]any{}
	last := comps[len(comps)-1]
	if strings.Contains(last, "r") {
		octal += 4
		perms["read"] = true
	} else {
		perms["read"] = false
	}
	if strings.Contains(last, "w") {
		octal += 2
		perms["write"] = true
	} else {
		perms["write"] = false
	}
	if strings.Contains(last, "x") {
		octal++
		perms["execute"] = true
	} else {
		perms["execute"] = false
	}
	vals["permissions"] = perms
	vals["octal"] = octal
	return vals
}

// ---------------------------------------------------------------------------
// acl.wipefacls / modfacl / delfacl

type wipefaclsArgs struct {
	Files     []string `statekit:"required,name=files"`
	Recursive *bool    `statekit:"name=recursive"`
}

type wipefaclsFunc struct{}

func (wipefaclsFunc) Name() string { return "acl.wipefacls" }
func (wipefaclsFunc) Args() any    { return wipefaclsArgs{} }
func (wipefaclsFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverACL(&res, &err)
	a := args.(*wipefaclsArgs)
	raiseOnNoFiles(a.Files)
	if gerr := requireSetfacl(); gerr != nil {
		return nil, gerr
	}
	argv := []string{"setfacl", "-b"}
	if a.Recursive != nil && *a.Recursive {
		argv = append(argv, "-R")
	}
	argv = append(argv, a.Files...)
	run(rt, argv)
	return true, nil
}

// aclPrefix ports _acl_prefix.
func aclPrefix(aclType string) string {
	prefix := ""
	if strings.HasPrefix(aclType, "d") {
		prefix = "d:"
		aclType = strings.ReplaceAll(aclType, "default:", "")
		aclType = strings.ReplaceAll(aclType, "d:", "")
	}
	switch aclType {
	case "user", "u":
		prefix += "u"
	case "group", "g":
		prefix += "g"
	case "mask", "m":
		prefix += "m"
	}
	return prefix
}

type modfaclArgs struct {
	AclType   string   `statekit:"required,name=acl_type"`
	AclName   *string  `statekit:"name=acl_name"`
	Perms     *string  `statekit:"name=perms"`
	Files     []string `statekit:"required,name=files"`
	Recursive *bool    `statekit:"name=recursive"`
	RaiseErr  *bool    `statekit:"name=raise_err"`
}

type modfaclFunc struct{}

func (modfaclFunc) Name() string { return "acl.modfacl" }
func (modfaclFunc) Args() any    { return modfaclArgs{} }
func (modfaclFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverACL(&res, &err)
	a := args.(*modfaclArgs)
	raiseOnNoFiles(a.Files)
	if gerr := requireSetfacl(); gerr != nil {
		return nil, gerr
	}
	aclName := strDeref(a.AclName)
	perms := strDeref(a.Perms)
	argv := []string{"setfacl"}
	if a.Recursive != nil && *a.Recursive {
		// -R must come first as -m needs the acl_* arguments that come later
		argv = append(argv, "-R")
	}
	argv = append(argv, "-m",
		fmt.Sprintf("%s:%s:%s", aclPrefix(a.AclType), aclName, perms))
	argv = append(argv, a.Files...)
	res2 := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	if (a.RaiseErr != nil && *a.RaiseErr) && res2.ExitCode != 0 {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(res2.Stderr)))
	}
	_ = strconv.Itoa // keep strconv import parity with future extensions
	return true, nil
}

type delfaclArgs struct {
	AclType   string   `statekit:"required,name=acl_type"`
	AclName   *string  `statekit:"name=acl_name"`
	Files     []string `statekit:"required,name=files"`
	Recursive *bool    `statekit:"name=recursive"`
}

type delfaclFunc struct{}

func (delfaclFunc) Name() string { return "acl.delfacl" }
func (delfaclFunc) Args() any    { return delfaclArgs{} }
func (delfaclFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverACL(&res, &err)
	a := args.(*delfaclArgs)
	raiseOnNoFiles(a.Files)
	if gerr := requireSetfacl(); gerr != nil {
		return nil, gerr
	}
	argv := []string{"setfacl"}
	if a.Recursive != nil && *a.Recursive {
		argv = append(argv, "-R")
	}
	argv = append(argv, "-x",
		fmt.Sprintf("%s:%s", aclPrefix(a.AclType), strDeref(a.AclName)))
	argv = append(argv, a.Files...)
	run(rt, argv)
	return true, nil
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Register installs the R5.3 ACL surface under Salt's virtual name "acl".
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		versionFunc{},
		getfaclFunc{},
		wipefaclsFunc{},
		modfaclFunc{},
		delfaclFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
