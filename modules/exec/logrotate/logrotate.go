// Package logrotate implements Salt-compatible logrotate configuration
// reading and forced rotation.
//
// Reference: saltstack/salt/modules/logrotate.py @ pinned revision.
package logrotate

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

const mainConfig = "/etc/logrotate.conf"

type ShowConfigArgs struct{}

type showConfigFunc struct{}

func (showConfigFunc) Name() string { return "logrotate.show_config" }
func (showConfigFunc) Args() any    { return ShowConfigArgs{} }
func (showConfigFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(mainConfig)
	if err != nil {
		return nil, err
	}
	conf := map[string]any{"main": strings.TrimRight(string(data), "\n")}
	snippets := map[string]string{}
	if entries, listErr := rt.FS.ReadDir("/etc/logrotate.d"); listErr == nil {
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".conf") && entry.IsDir() {
				continue
			}
			if snippet, readErr := rt.FS.ReadFile("/etc/logrotate.d/" + entry.Name()); readErr == nil {
				snippets[entry.Name()] = strings.TrimRight(string(snippet), "\n")
			}
		}
	}
	conf["includes"] = snippets
	return conf, nil
}

type RotateArgs struct {
	ConfFile string `statekit:"name=conf_file"`
	Force    bool   `statekit:"name=force"`
}

type rotateFunc struct{}

func (rotateFunc) Name() string { return "logrotate.rotate" }
func (rotateFunc) Args() any    { return RotateArgs{} }
func (rotateFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RotateArgs)
	conf := a.ConfFile
	if conf == "" {
		conf = mainConfig
	}
	argv := []string{"logrotate"}
	if a.Force {
		argv = append(argv, "-f")
	}
	argv = append(argv, conf)
	res := rt.Runner.Run(ctx, runtime.Command(argv...))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("logrotate exited with code %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return true, nil
}

// Register installs all logrotate-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{showConfigFunc{}, rotateFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
