package acl

// R5.3 tests for the ACL surface, mapped onto the source-derived contracts
// of saltstack/salt/modules/linux_acl.py @ pinned revision.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type aclRunner struct {
	calls []process.Command
	resp  func(process.Command) process.CommandResult
}

func (r *aclRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.calls = append(r.calls, c)
	if r.resp != nil {
		return r.resp(c)
	}
	return process.CommandResult{}
}

func aclRT(t *testing.T) (*runtime.Runtime, *aclRunner) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &aclRunner{}
	rt := &runtime.Runtime{
		Exec:    reg,
		States:  runtime.NewStateRegistry(),
		FS:      runtime.NewMemoryFS(),
		Runner:  runner,
		Options: runtime.RuntimeOptions{},
	}
	orig := whichBin
	whichBin = func(exe string) string { return "/usr/bin/" + exe }
	t.Cleanup(func() { whichBin = orig })
	return rt, runner
}

const getfaclSample = `# file: /tmp/house/kitchen
# owner: root
# group: root
# flags: -st
user::rwx
user:myuser:r-x
group::rwx
group:guests:r--
mask::rwx
other::---
default:user::rwx
default:group::r-x
`

func TestGetfaclParsesCommentAndRules(t *testing.T) {
	rt, runner := aclRT(t)
	runner.resp = func(c process.Command) process.CommandResult {
		if filepath.Base(c.Name) == "getfacl" {
			return process.CommandResult{Stdout: []byte(getfaclSample)}
		}
		return process.CommandResult{}
	}

	res := mustACL(t, rt, "acl.getfacl", &getfaclArgs{Files: []string{"/tmp/house/kitchen"}})
	m := res.(map[string]any)
	entry, ok := m["/tmp/house/kitchen"].(map[string]any)
	if !ok {
		t.Fatalf("entry missing: %#v", m)
	}
	comment := entry["comment"].(map[string]any)
	if comment["owner"] != "root" || comment["group"] != "root" || comment["file"] != "/tmp/house/kitchen" {
		t.Fatalf("comment = %#v", comment)
	}
	// "-st": position 0 is '-' (no suid), 's' at 1 sets sgid, 't' sticky.
	if _, has := entry["suid"]; has {
		t.Fatalf("suid misdecoded: %#v", entry)
	}
	if entry["sgid"] != true || entry["sticky"] != true {
		t.Fatalf("flags decode = %#v", entry)
	}
	users := entry["user"].([]map[string]any)
	if len(users) != 2 {
		t.Fatalf("users = %#v", users)
	}
	ownerEntry := users[0]["root"].(map[string]any)
	if ownerEntry["octal"] != 7 {
		t.Fatalf("owner perms = %#v", ownerEntry)
	}
	namedEntry := users[1]["myuser"].(map[string]any)
	if namedEntry["octal"] != 5 {
		t.Fatalf("named user perms = %#v", namedEntry)
	}
	defaults := entry["defaults"].(map[string]any)
	if len(defaults["user"].([]map[string]any)) != 1 || len(defaults["group"].([]map[string]any)) != 1 {
		t.Fatalf("defaults = %#v", defaults)
	}

	// recursive flag reaches argv.
	recursive := true
	mustACL(t, rt, "acl.getfacl", &getfaclArgs{
		Files: []string{"/tmp/house"}, Recursive: &recursive,
	})
	last := runner.calls[len(runner.calls)-1]
	if argvString(last) != "getfacl --absolute-names -R /tmp/house" {
		t.Fatalf("argv = %v", last.Args)
	}
}

func mustACL(t *testing.T, rt *runtime.Runtime, name string, args any) any {
	t.Helper()
	res, err := rt.Exec.Call(context.Background(), rt, name, args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func TestACLLifecycleArgvsAndGuards(t *testing.T) {
	rt, runner := aclRT(t)

	runner.resp = func(c process.Command) process.CommandResult {
		if filepath.Base(c.Name) == "getfacl" {
			return process.CommandResult{Stdout: []byte("getfacl 2.3.1\n")}
		}
		return process.CommandResult{}
	}
	res := mustACL(t, rt, "acl.version", &versionArgs{})
	if res != "2.3.1" {
		t.Fatalf("version = %#v", res)
	}

	// modfacl default:group prefix + recursive ordering (-R before -m).
	recursive := true
	mustACL(t, rt, "acl.modfacl", &modfaclArgs{
		AclType: "default:group", AclName: strPtrA("mygroup"), Perms: strPtrA("rx"),
		Files: []string{"/tmp/house/kitchen"}, Recursive: &recursive,
	})
	last := runner.calls[len(runner.calls)-1]
	if argvString(last) != "setfacl -R -m d:g:mygroup:rx /tmp/house/kitchen" {
		t.Fatalf("modfacl argv = %v %v", last.Name, last.Args)
	}

	// d:u shorthand and multiple files.
	mustACL(t, rt, "acl.delfacl", &delfaclArgs{
		AclType: "d:u", AclName: strPtrA("myuser"),
		Files: []string{"/a", "/b"},
	})
	last = runner.calls[len(runner.calls)-1]
	if argvString(last) != "setfacl -x d:u:myuser /a /b" {
		t.Fatalf("delfacl argv = %v", last.Args)
	}

	mustACL(t, rt, "acl.wipefacls", &wipefaclsArgs{Files: []string{"/a"}})
	last = runner.calls[len(runner.calls)-1]
	if argvString(last) != "setfacl -b /a" {
		t.Fatalf("wipefacls argv = %v", last.Args)
	}

	// No files -> verbatim error text.
	_, err := wipefaclsFunc{}.Execute(context.Background(), rt, &wipefaclsArgs{})
	if err == nil ||
		err.Error() != "You need to specify at least one file or directory to work with!" {
		t.Fatalf("no-files guard = %v", err)
	}

	// Missing binary -> the __virtual__ message.
	orig := whichBin
	whichBin = func(string) string { return "" }
	t.Cleanup(func() { whichBin = orig })
	_, err = modfaclFunc{}.Execute(context.Background(), rt, &modfaclArgs{
		AclType: "u", Files: []string{"/a"},
	})
	if err == nil || !strings.Contains(err.Error(), "the getfacl binary is not in") {
		t.Fatalf("which-guard = %v", err)
	}
}

func strPtrA(s string) *string { return &s }

func argvString(c process.Command) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}
