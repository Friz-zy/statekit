//go:build windows

// Package win_dacl implements the public win_dacl execution wrapper through
// icacls. File/directory ACLs are supported natively; registry/printer/service
// object types remain explicit boundaries because icacls cannot address their
// Win32 security descriptors.
package win_dacl

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func objectType(value string) error {
	switch strings.ToLower(value) {
	case "file", "directory":
		return nil
	default:
		return fmt.Errorf("object type %s is not supported by the icacls port", value)
	}
}

func icacls(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(append([]string{"icacls"}, argv...)...))
}

func aclFailure(result process.CommandResult) error {
	if result.Err != nil && result.ExitCode == -1 {
		return result.Err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("icacls failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

func aclLines(output string) []string {
	var lines []string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(strings.ToLower(line), "processed file") || strings.HasPrefix(strings.ToLower(line), "successfully") {
			continue
		}
		if !strings.Contains(line, ":(") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func permissionText(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fullcontrol", "full_control", "full control":
		return "F"
	case "modify":
		return "M"
	case "read", "read_execute", "read and execute":
		return "RX"
	case "write":
		return "W"
	default:
		return value
	}
}

func propagationText(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "FOLDER&SUBFOLDERS&FILES", "THIS_FOLDER_SUBFOLDERS_FILES", "THIS FOLDER, SUBFOLDERS AND FILES":
		return "(OI)(CI)"
	case "FOLDER&SUBFOLDERS", "THIS_FOLDER_SUBFOLDERS":
		return "(CI)"
	case "FOLDER&FILES", "THIS_FOLDER_FILES":
		return "(OI)"
	default:
		return ""
	}
}

func principalMatch(line, principal string) bool {
	return strings.HasPrefix(strings.ToLower(line), strings.ToLower(principal)+":") || strings.Contains(strings.ToLower(line), "\\"+strings.ToLower(principal)+":")
}

func aceMatch(line, principal, permission, aceType string, exact bool) bool {
	if !principalMatch(line, principal) {
		return false
	}
	lower := strings.ToLower(line)
	if aceType == "deny" && !strings.Contains(lower, ":(d") && !strings.Contains(lower, ":(deny") {
		return false
	}
	if aceType == "allow" && (strings.Contains(lower, ":(d") || strings.Contains(lower, ":(deny")) {
		return false
	}
	if permission == "" {
		return true
	}
	right := strings.ToLower(permissionText(permission))
	if exact {
		return strings.Contains(lower, ":("+right+")") || strings.Contains(lower, ")("+right+")")
	}
	return strings.Contains(lower, right)
}

func aclResult(result bool, comment string, changes any) map[string]any {
	return map[string]any{"result": result, "changes": changes, "comment": comment}
}

// ---------------------------------------------------------------------------
// get/add/remove ACEs

type getArgs struct {
	Path       string  `statekit:"required"`
	ObjectType string  `statekit:"required,name=objectType"`
	User       *string `statekit:"name=user"`
}
type getFunc struct{}

func (getFunc) Name() string        { return "win_dacl.get" }
func (getFunc) Args() any           { return getArgs{} }
func (getFunc) Platforms() []string { return []string{"windows"} }
func (getFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*getArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	r := icacls(ctx, rt, a.Path)
	if e := aclFailure(r); e != nil {
		return nil, e
	}
	acls := []string{}
	for _, line := range aclLines(string(r.Stdout)) {
		if a.User == nil || *a.User == "" || principalMatch(line, *a.User) {
			acls = append(acls, line)
		}
	}
	return map[string]any{"Path": a.Path, "ACLs": acls}, nil
}

type addAceArgs struct {
	Path        string `statekit:"required"`
	ObjectType  string `statekit:"required,name=objectType"`
	User        string `statekit:"required,name=user"`
	Permission  string `statekit:"required,name=permission"`
	AceType     string `statekit:"required,name=acetype"`
	Propagation string `statekit:"required,name=propagation"`
}
type addAceFunc struct{}

func (addAceFunc) Name() string        { return "win_dacl.add_ace" }
func (addAceFunc) Args() any           { return addAceArgs{} }
func (addAceFunc) Platforms() []string { return []string{"windows"} }
func (addAceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*addAceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	ace := strings.ToLower(a.AceType)
	if ace != "allow" && ace != "deny" {
		return aclResult(false, "Invalid ace type: "+a.AceType, map[string]any{}), nil
	}
	verb := "/grant"
	if ace == "deny" {
		verb = "/deny"
	}
	rule := a.User + ":" + propagationText(a.Propagation) + permissionText(a.Permission)
	r := icacls(ctx, rt, a.Path, verb, rule)
	if e := aclFailure(r); e != nil {
		return aclResult(false, "An error occurred attempting to add the ace.  The error was "+e.Error(), map[string]any{}), nil
	}
	text := fmt.Sprintf("%s %s %s on %s", a.User, ace, a.Permission, a.Propagation)
	return aclResult(true, "", map[string]any{"Added ACEs": []string{text}}), nil
}

type rmAceArgs struct {
	Path        string  `statekit:"required"`
	ObjectType  string  `statekit:"required,name=objectType"`
	User        string  `statekit:"required,name=user"`
	Permission  *string `statekit:"name=permission"`
	AceType     *string `statekit:"name=acetype"`
	Propagation *string `statekit:"name=propagation"`
}
type rmAceFunc struct{}

func (rmAceFunc) Name() string        { return "win_dacl.rm_ace" }
func (rmAceFunc) Args() any           { return rmAceArgs{} }
func (rmAceFunc) Platforms() []string { return []string{"windows"} }
func (rmAceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*rmAceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	removeFlag := "/remove"
	if a.AceType != nil {
		switch strings.ToLower(*a.AceType) {
		case "grant", "allow":
			removeFlag = "/remove:g"
		case "deny":
			removeFlag = "/remove:d"
		}
	}
	r := icacls(ctx, rt, a.Path, removeFlag, a.User)
	if e := aclFailure(r); e != nil {
		return aclResult(false, "Error removing ACE.  The error was "+e.Error(), map[string]any{}), nil
	}
	return aclResult(true, "", map[string]any{"Removed ACEs": []string{a.User}}), nil
}

// ---------------------------------------------------------------------------
// inheritance/checks

type inheritanceArgs struct {
	Path       string `statekit:"required"`
	ObjectType string `statekit:"required,name=objectType"`
	Clear      bool   `statekit:"name=clear"`
	Copy       *bool  `statekit:"name=copy"`
}
type enableInheritanceFunc struct{}

func (enableInheritanceFunc) Name() string        { return "win_dacl.enable_inheritance" }
func (enableInheritanceFunc) Args() any           { return inheritanceArgs{} }
func (enableInheritanceFunc) Platforms() []string { return []string{"windows"} }
func (enableInheritanceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*inheritanceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	flag := "/inheritance:e"
	if a.Clear {
		flag = "/inheritance:e"
	}
	r := icacls(ctx, rt, a.Path, flag)
	if e := aclFailure(r); e != nil {
		return aclResult(false, "Error attempting to set the inheritance.  The error was "+e.Error(), map[string]any{}), nil
	}
	changes := map[string]any{"Inheritance": "Enabled"}
	if a.Clear {
		changes["Removed ACEs"] = []string{}
	}
	return aclResult(true, "", changes), nil
}

type disableInheritanceFunc struct{}

func (disableInheritanceFunc) Name() string        { return "win_dacl.disable_inheritance" }
func (disableInheritanceFunc) Args() any           { return inheritanceArgs{} }
func (disableInheritanceFunc) Platforms() []string { return []string{"windows"} }
func (disableInheritanceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*inheritanceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	flag := "/inheritance:d"
	if a.Copy != nil && !(*a.Copy) {
		flag = "/inheritance:r"
	}
	r := icacls(ctx, rt, a.Path, flag)
	if e := aclFailure(r); e != nil {
		return aclResult(false, "Error attempting to set the inheritance.  The error was "+e.Error(), map[string]any{}), nil
	}
	return aclResult(true, "", map[string]any{"Inheritance": "Disabled"}), nil
}

type checkInheritanceArgs struct {
	Path       string  `statekit:"required"`
	ObjectType string  `statekit:"required,name=objectType"`
	User       *string `statekit:"name=user"`
}
type checkInheritanceFunc struct{}

func (checkInheritanceFunc) Name() string        { return "win_dacl.check_inheritance" }
func (checkInheritanceFunc) Args() any           { return checkInheritanceArgs{} }
func (checkInheritanceFunc) Platforms() []string { return []string{"windows"} }
func (checkInheritanceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*checkInheritanceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	r := icacls(ctx, rt, a.Path)
	if e := aclFailure(r); e != nil {
		return aclResult(false, "Error obtaining the Security Descriptor or DACL of the path: "+e.Error()+".", map[string]any{}), nil
	}
	inherited := false
	for _, line := range aclLines(string(r.Stdout)) {
		if !strings.Contains(line, "(I)") {
			continue
		}
		if a.User == nil || *a.User == "" || principalMatch(line, *a.User) {
			inherited = true
			break
		}
	}
	return map[string]any{"result": true, "Inheritance": inherited, "comment": ""}, nil
}

type checkAceArgs struct {
	Path                 string  `statekit:"required"`
	ObjectType           string  `statekit:"required,name=objectType"`
	User                 string  `statekit:"required,name=user"`
	Permission           *string `statekit:"name=permission"`
	AceType              *string `statekit:"name=acetype"`
	Propagation          *string `statekit:"name=propagation"`
	ExactPermissionMatch bool    `statekit:"name=exactPermissionMatch"`
}
type checkAceFunc struct{}

func (checkAceFunc) Name() string        { return "win_dacl.check_ace" }
func (checkAceFunc) Args() any           { return checkAceArgs{} }
func (checkAceFunc) Platforms() []string { return []string{"windows"} }
func (checkAceFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverDACL(&res, &err)
	a := args.(*checkAceArgs)
	if e := objectType(a.ObjectType); e != nil {
		return nil, e
	}
	r := icacls(ctx, rt, a.Path)
	if e := aclFailure(r); e != nil {
		return map[string]any{"Exists": false, "Error": e.Error()}, nil
	}
	permission := ""
	if a.Permission != nil {
		permission = *a.Permission
	}
	aceType := ""
	if a.AceType != nil {
		aceType = strings.ToLower(*a.AceType)
	}
	exists := false
	for _, line := range aclLines(string(r.Stdout)) {
		if aceMatch(line, a.User, permission, aceType, a.ExactPermissionMatch) {
			exists = true
			break
		}
	}
	return map[string]any{"Exists": exists}, nil
}

func recoverDACL(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Windows DACL wrapper functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getFunc{}, addAceFunc{}, rmAceFunc{}, enableInheritanceFunc{}, disableInheritanceFunc{}, checkInheritanceFunc{}, checkAceFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
