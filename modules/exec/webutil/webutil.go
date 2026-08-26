// Package webutil implements Salt's htpasswd surface (R5.3), mirroring
// saltstack/salt/modules/webutil.py @ pinned revision. htpasswd runs through
// the central Runner with upstream's which-guard message.
//
// Documented boundary: runas follows the StateKit single-user model (see
// cmd/npm) — accepted in signatures and degraded to explicit env handling.
package webutil

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

func execLookPathWU(exe string) (string, error) { return exec.LookPath(exe) }

var whichBin = func(exe string) string {
	p, err := execLookPathWU(exe)
	if err != nil {
		return ""
	}
	return p
}

func requireHtpasswd() error {
	if whichBin("htpasswd") == "" {
		return fmt.Errorf(
			"The htpasswd execution mdule cannot be loaded: htpasswd binary not in path.")
	}
	return nil
}

func recoverWU(res *any, errPtr *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case error:
			*errPtr = e
		default:
			panic(r)
		}
	}
}

func runAll(rt *runtime.Runtime, argv []string) map[string]any {
	res := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	stdout := strings.TrimRight(string(res.Stdout), "\n")
	stderr := strings.TrimRight(string(res.Stderr), "\n")
	retcode := res.ExitCode
	if res.Err != nil {
		retcode = -1
	}
	return map[string]any{
		"stdout":  stdout,
		"stderr":  stderr,
		"retcode": retcode,
	}
}

func fileExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ---------------------------------------------------------------------------
// webutil.useradd

type useraddArgs struct {
	Pwfile   string  `statekit:"required,name=pwfile"`
	User     string  `statekit:"required,name=user"`
	Password string  `statekit:"required,name=password"`
	Opts     *string `statekit:"name=opts"`
	Runas    *string `statekit:"name=runas"`
}

type useraddFunc struct{}

func (useraddFunc) Name() string { return "webutil.useradd" }
func (useraddFunc) Args() any    { return useraddArgs{} }
func (useraddFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWU(&res, &err)
	a := args.(*useraddArgs)
	if gerr := requireHtpasswd(); gerr != nil {
		return nil, gerr
	}
	opts := strDeref(a.Opts)
	if !fileExists(rt, a.Pwfile) {
		opts += "c"
	}
	argv := []string{"htpasswd", fmt.Sprintf("-b%s", opts), a.Pwfile, a.User, a.Password}
	return runAll(rt, argv), nil
}

// ---------------------------------------------------------------------------
// webutil.userdel

type userdelArgs struct {
	Pwfile     string  `statekit:"required,name=pwfile"`
	User       string  `statekit:"required,name=user"`
	Runas      *string `statekit:"name=runas"`
	AllResults *bool   `statekit:"name=all_results"`
}

type userdelFunc struct{}

func (userdelFunc) Name() string { return "webutil.userdel" }
func (userdelFunc) Args() any    { return userdelArgs{} }
func (userdelFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWU(&res, &err)
	a := args.(*userdelArgs)
	if gerr := requireHtpasswd(); gerr != nil {
		return nil, gerr
	}
	if !fileExists(rt, a.Pwfile) {
		return "Error: The specified htpasswd file does not exist", nil
	}
	argv := []string{"htpasswd", "-D", a.Pwfile, a.User}
	if a.AllResults != nil && *a.AllResults {
		return runAll(rt, argv), nil
	}
	out := strings.TrimRight(string(rt.Runner.Run(context.Background(), runtime.Command(argv...)).Stdout), "\n")
	lines := strings.Split(out, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []any{}, nil
	}
	list := make([]any, 0, len(lines))
	for _, l := range lines {
		list = append(list, l)
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// webutil.verify

type verifyArgs struct {
	Pwfile   string  `statekit:"required,name=pwfile"`
	User     string  `statekit:"required,name=user"`
	Password string  `statekit:"required,name=password"`
	Opts     *string `statekit:"name=opts"`
	Runas    *string `statekit:"name=runas"`
}

type verifyFunc struct{}

func (verifyFunc) Name() string { return "webutil.verify" }
func (verifyFunc) Args() any    { return verifyArgs{} }
func (verifyFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverWU(&res, &err)
	a := args.(*verifyArgs)
	if gerr := requireHtpasswd(); gerr != nil {
		return nil, gerr
	}
	if !fileExists(rt, a.Pwfile) {
		return false, nil
	}
	argv := []string{"htpasswd", fmt.Sprintf("-bv%s", strDeref(a.Opts)), a.Pwfile, a.User, a.Password}
	result := rt.Runner.Run(context.Background(), runtime.Command(argv...))
	return result.OK(), nil
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Register installs the R5.3 webutil surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		useraddFunc{},
		userdelFunc{},
		verifyFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
