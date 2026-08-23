// Package cron implements Salt-compatible crontab management.
//
// Reference: saltstack/salt/modules/cron.py @ pinned revision. Tabs are read
// and written through the runtime FileSystem at the Linux spool location
// (/var/spool/cron/crontabs/<user>) instead of shelling out to crontab(1).
package cron

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// linuxOnly restricts every function of this module to linux.
type linuxOnly struct{}

func (linuxOnly) Platforms() []string { return []string{"linux"} }

var envLineRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func spoolPath(user string) string {
	return "/var/spool/cron/crontabs/" + user
}

func readTab(rt *runtime.Runtime, user string) []string {
	data, err := rt.FS.ReadFile(spoolPath(user))
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

func writeTab(rt *runtime.Runtime, user string, lines []string) error {
	out := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	mode := fs.FileMode(0o600)
	if info, err := rt.FS.Stat(spoolPath(user)); err == nil {
		mode = info.Mode().Perm()
	}
	return rt.FS.WriteFile(spoolPath(user), []byte(out), mode)
}

type ListTabArgs struct {
	User string `statekit:"required,name=user"`
}

type listTabFunc struct {
	linuxOnly
}

func (listTabFunc) Name() string { return "cron.list_tab" }
func (listTabFunc) Args() any    { return ListTabArgs{} }
func (listTabFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListTabArgs)
	lines := readTab(rt, a.User)
	if lines == nil {
		return map[string]any{"crons": []any{}, "special": []any{}, "env": []any{}}, nil
	}
	crons := []any{}
	special := []any{}
	env := []any{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "@"):
			special = append(special, line)
		case envLineRe.MatchString(line):
			env = append(env, line)
		default:
			crons = append(crons, line)
		}
	}
	return map[string]any{"crons": crons, "special": special, "env": env}, nil
}

// jobLine renders one crontab job line from its fields.
func jobLine(minute, hour, daymonth, month, dayweek, command string) string {
	fields := []string{minute, hour, daymonth, month, dayweek}
	for i, field := range fields {
		if field == "" {
			fields[i] = "*"
		}
	}
	return strings.Join(fields, " ") + " " + command
}

type AddJobArgs struct {
	User     string `statekit:"required,name=user"`
	Minute   string `statekit:"name=minute"`
	Hour     string `statekit:"name=hour"`
	Daymonth string `statekit:"name=daymonth"`
	Month    string `statekit:"name=month"`
	Dayweek  string `statekit:"name=dayweek"`
	Command  string `statekit:"required,name=command"`
	Comment  string `statekit:"name=comment"`
}

type addJobFunc struct {
	linuxOnly
}

func (addJobFunc) Name() string { return "cron.add_job" }
func (addJobFunc) Args() any    { return AddJobArgs{} }
func (addJobFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*AddJobArgs)
	lines := readTab(rt, a.User)
	job := jobLine(a.Minute, a.Hour, a.Daymonth, a.Month, a.Dayweek, a.Command)
	for _, line := range lines {
		if strings.TrimSpace(line) == job {
			return fmt.Sprintf("new"), nil
		}
	}
	out := append(lines, "")
	if a.Comment != "" {
		out = append(out, "# "+a.Comment)
	}
	out = append(out, job)
	if err := writeTab(rt, a.User, out); err != nil {
		return nil, err
	}
	return "new", nil
}

type RmJobArgs struct {
	User     string `statekit:"required,name=user"`
	Minute   string `statekit:"name=minute"`
	Hour     string `statekit:"name=hour"`
	Daymonth string `statekit:"name=daymonth"`
	Month    string `statekit:"name=month"`
	Dayweek  string `statekit:"name=dayweek"`
	Command  string `statekit:"required,name=name"`
}

type rmJobFunc struct {
	linuxOnly
}

func (rmJobFunc) Name() string { return "cron.rm_job" }
func (rmJobFunc) Args() any    { return RmJobArgs{} }
func (rmJobFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmJobArgs)
	lines := readTab(rt, a.User)
	target := jobLine(a.Minute, a.Hour, a.Daymonth, a.Month, a.Dayweek, a.Command)
	found := false
	out := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) == target {
			found = true
			continue
		}
		out = append(out, line)
	}
	if !found {
		return false, nil
	}
	if err := writeTab(rt, a.User, out); err != nil {
		return nil, err
	}
	return "removed", nil
}

type RawArgs struct {
	User string `statekit:"required,name=user"`
}

type rawFunc struct {
	linuxOnly
}

func (rawFunc) Name() string { return "cron.raw_tab" }
func (rawFunc) Args() any    { return RawArgs{} }
func (rawFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RawArgs)
	data, err := rt.FS.ReadFile(spoolPath(a.User))
	if err != nil {
		return "", nil
	}
	return string(data), nil
}

// Register installs all cron-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{listTabFunc{}, addJobFunc{}, rmJobFunc{}, rawFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
