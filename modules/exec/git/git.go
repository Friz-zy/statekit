// Package git implements a Salt-compatible subset of git operations through
// the central Runner.
//
// Reference: saltstack/salt/modules/git.py @ pinned revision (reduced to the
// core revision-control surface).
package git

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func runOut(ctx context.Context, rt *runtime.Runtime, cwd string, argv ...string) (string, error) {
	cmd := runtime.Command(argv...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	res := rt.Runner.Run(ctx, cmd)
	if res.Err != nil {
		return "", res.Err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("git exited with code %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

type CurrentRevisionArgs struct {
	Cwd   string `statekit:"required,name=cwd"`
	Rev   string `statekit:"name=rev"`
	Short bool   `statekit:"name=short"`
}

type currentRevisionFunc struct{}

func (currentRevisionFunc) Name() string { return "git.current_revision" }
func (currentRevisionFunc) Args() any    { return CurrentRevisionArgs{} }
func (currentRevisionFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CurrentRevisionArgs)
	rev := a.Rev
	if rev == "" {
		rev = "HEAD"
	}
	argv := []string{"git", "rev-parse"}
	if a.Short {
		argv = append(argv, "--short")
	}
	argv = append(argv, rev)
	return runOut(ctx, rt, a.Cwd, argv...)
}

type CloneArgs struct {
	URL    string `statekit:"required,name=url"`
	Path   string `statekit:"required,name=path"`
	Depth  int    `statekit:"name=depth"`
	Branch string `statekit:"name=branch"`
}

type cloneFunc struct{}

func (cloneFunc) Name() string { return "git.clone" }
func (cloneFunc) Args() any    { return CloneArgs{} }
func (cloneFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CloneArgs)
	argv := []string{"git", "clone"}
	if a.Depth > 0 {
		argv = append(argv, "--depth", fmt.Sprintf("%d", a.Depth))
	}
	if a.Branch != "" {
		argv = append(argv, "--branch", a.Branch)
	}
	argv = append(argv, a.URL, a.Path)
	out, err := runOut(ctx, rt, "", argv...)
	if err != nil {
		return nil, err
	}
	return map[string]any{"path": a.Path, "output": out}, nil
}

type InitArgs struct {
	Path string `statekit:"required,name=path"`
	Bare bool   `statekit:"name=bare"`
}

type initFunc struct{}

func (initFunc) Name() string { return "git.init" }
func (initFunc) Args() any    { return InitArgs{} }
func (initFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*InitArgs)
	argv := []string{"git", "init"}
	if a.Bare {
		argv = append(argv, "--bare")
	}
	argv = append(argv, a.Path)
	out, err := runOut(ctx, rt, "", argv...)
	if err != nil {
		return nil, err
	}
	return map[string]any{"path": a.Path, "output": out}, nil
}

type FetchArgs struct {
	Cwd    string `statekit:"required,name=cwd"`
	Remote string `statekit:"name=remote"`
}

type fetchFunc struct{}

func (fetchFunc) Name() string { return "git.fetch" }
func (fetchFunc) Args() any    { return FetchArgs{} }
func (fetchFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*FetchArgs)
	remote := a.Remote
	if remote == "" {
		remote = "origin"
	}
	out, err := runOut(ctx, rt, a.Cwd, "git", "fetch", remote)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type PullArgs struct {
	Cwd string `statekit:"required,name=cwd"`
}

type pullFunc struct{}

func (pullFunc) Name() string { return "git.pull" }
func (pullFunc) Args() any    { return PullArgs{} }
func (pullFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*PullArgs)
	out, err := runOut(ctx, rt, a.Cwd, "git", "pull")
	if err != nil {
		return nil, err
	}
	return out, nil
}

type AddArgs struct {
	Cwd   string   `statekit:"required,name=cwd"`
	Files []string `statekit:"name=files"`
}

type addFunc struct{}

func (addFunc) Name() string { return "git.add" }
func (addFunc) Args() any    { return AddArgs{} }
func (addFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddArgs)
	files := a.Files
	if len(files) == 0 {
		files = []string{"."}
	}
	_, err := runOut(ctx, rt, a.Cwd, append([]string{"git", "add"}, files...)...)
	if err != nil {
		return nil, err
	}
	return true, nil
}

type CommitArgs struct {
	Cwd     string `statekit:"required,name=cwd"`
	Message string `statekit:"required,name=message"`
}

type commitFunc struct{}

func (commitFunc) Name() string { return "git.commit" }
func (commitFunc) Args() any    { return CommitArgs{} }
func (commitFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*CommitArgs)
	res := rt.Runner.Run(ctx, process.Command{
		Name: "git", Args: []string{"commit", "-m", a.Message}, Dir: a.Cwd,
	})
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		if strings.Contains(strings.ToLower(string(res.Stderr)), "nothing to commit") {
			return false, nil
		}
		return nil, fmt.Errorf("git commit exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return true, nil
}

// Register installs all git-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		currentRevisionFunc{}, cloneFunc{}, initFunc{}, fetchFunc{},
		pullFunc{}, addFunc{}, commitFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
