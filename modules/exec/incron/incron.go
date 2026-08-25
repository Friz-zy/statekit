// Package incron manages inotify cron tabs over the injectable filesystem,
// mirroring saltstack/salt/modules/incron.py @ pinned revision.
//
// Contract notes (init.md section 28): user-tab writes go through the
// `incrontab` binary via the central Runner exactly like upstream's
// cmd.retcode/cmd.run_all calls; the system tab writes directly to
// /etc/incron.d/salt. Paths are injectable for hermetic suites.
package incron

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

var (
	incronSystemTab = "/etc/incron.d/"
	incronSpoolDir  = "/var/spool/incron/"
)

var maskTypes = []string{
	"IN_ACCESS", "IN_ATTRIB", "IN_CLOSE_WRITE", "IN_CLOSE_NOWRITE",
	"IN_CREATE", "IN_DELETE", "IN_DELETE_SELF", "IN_MODIFY", "IN_MOVE_SELF",
	"IN_MOVED_FROM", "IN_MOVED_TO", "IN_OPEN", "IN_ALL_EVENTS", "IN_MOVE",
	"IN_CLOSE", "IN_DONT_FOLLOW", "IN_ONESHOT", "ONLYDIR", "DONDFOLLOW",
}

func validMask(mask string) (string, bool) {
	for _, item := range strings.Split(mask, ",") {
		if !containsStr(maskTypes, item) {
			return item, false
		}
	}
	return "", true
}

func containsStr(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func systemTabFile() string { return incronSystemTab + "salt" }

func userTabFile(user string) string { return incronSpoolDir + user }

type rawSystemIncronArgs struct{}

type RawSystemIncronFunc struct{}

func (RawSystemIncronFunc) Name() string { return "incron.raw_system_incron" }
func (RawSystemIncronFunc) Args() any    { return rawSystemIncronArgs{} }
func (RawSystemIncronFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile(systemTabFile())
	if err != nil {
		return "", nil
	}
	return string(data), nil
}

type RawIncronArgs struct {
	User string `statekit:"required,name=user"`
}

type rawIncronFunc struct{}

func (rawIncronFunc) Name() string { return "incron.raw_incron" }
func (rawIncronFunc) Args() any    { return RawIncronArgs{} }
func (rawIncronFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RawIncronArgs)
	data, err := rt.FS.ReadFile(userTabFile(a.User))
	if err != nil {
		return "", nil
	}
	return string(data), nil
}

type ListTabArgs struct {
	User string `statekit:"required,name=user"`
}

type ListTabFunc struct{}

func (ListTabFunc) Name() string { return "incron.list_tab" }
func (ListTabFunc) Args() any    { return ListTabArgs{} }

type cronEntry struct {
	path, mask, cmd string
}

type tabList struct {
	crons []cronEntry
	pre   []string
}

func readTab(rt *runtime.Runtime, user string) string {
	if user == "system" {
		data, err := rt.FS.ReadFile(systemTabFile())
		if err != nil {
			return ""
		}
		return string(data)
	}
	data, err := rt.FS.ReadFile(userTabFile(user))
	if err != nil {
		return ""
	}
	return string(data)
}

func parseTab(data string) tabList {
	ret := tabList{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 3 {
			ret.crons = append(ret.crons, cronEntry{
				path: fields[0], mask: fields[1], cmd: strings.Join(fields[2:], " "),
			})
		} else if line != "" {
			ret.pre = append(ret.pre, line)
		}
	}
	return ret
}

func (ListTabFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*ListTabArgs)
	lst := parseTab(readTab(rt, a.User))
	crons := make([]map[string]string, 0, len(lst.crons))
	for _, c := range lst.crons {
		crons = append(crons, map[string]string{
			"path": c.path, "mask": c.mask, "cmd": c.cmd,
		})
	}
	pre := append([]string{}, lst.pre...)
	sort.Strings(pre)
	return map[string]any{"crons": crons, "pre": pre}, nil
}

// renderTab mirrors _render_tab: pre lines first, then crons.
func renderTab(lst tabList) []string {
	var ret []string
	for _, pre := range lst.pre {
		ret = append(ret, pre+"\n")
	}
	for _, c := range lst.crons {
		ret = append(ret, fmt.Sprintf("%s %s %s\n", c.path, c.mask, c.cmd))
	}
	return ret
}

// writeIncronLines mirrors _write_incron_lines: the system tab is written
// directly; user tabs go through `incrontab <file>` via the Runner.
func writeIncronLines(ctx context.Context, rt *runtime.Runtime, user string, lines []string) envResult {
	if user == "system" {
		rt.FS.MkdirAll(incronSystemTab, 0o755)
		err := rt.FS.WriteFile(systemTabFile(), []byte(strings.Join(lines, "")), 0o644)
		if err != nil {
			return envResult{retcode: 1, stderr: err.Error()}
		}
		return envResult{retcode: 0}
	}
	tmpPath := fmt.Sprintf("/tmp/incron-%s.tab", user)
	content := strings.Join(lines, "")
	rt.FS.WriteFile(tmpPath, []byte(content), 0o644)
	defer rt.FS.Remove(tmpPath)

	res := rt.Runner.Run(ctx, runtime.Command("incrontab", tmpPath))
	exitCode := res.ExitCode
	stderr := string(res.Stderr)
	if res.Err != nil {
		exitCode = -1
		stderr = res.Err.Error()
	}
	return envResult{retcode: exitCode, stderr: stderr}
}

type envResult struct {
	retcode int
	stdout  string
	stderr  string
}

type SetJobArgs struct {
	User string `statekit:"required,name=user"`
	Path string `statekit:"required,name=path"`
	Mask string `statekit:"required,name=mask"`
	Cmd  string `statekit:"required,name=cmd"`
}

type SetJobFunc struct{}

func (SetJobFunc) Name() string { return "incron.set_job" }
func (SetJobFunc) Args() any    { return SetJobArgs{} }

func (SetJobFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*SetJobArgs)
	mask := strings.ToUpper(a.Mask)
	if invalid, ok := validMask(mask); !ok {
		return fmt.Sprintf("Invalid mask type: %s", invalid), nil
	}

	lst := parseTab(readTab(rt, a.User))
	argMask := append([]string{}, strings.Split(mask, ",")...)
	sort.Strings(argMask)

	updated := false
	var updatedCrons []cronEntry
	for _, cron := range lst.crons {
		if a.Path == cron.path && a.Cmd == cron.cmd {
			cronMask := append([]string{}, strings.Split(cron.mask, ",")...)
			sort.Strings(cronMask)
			if equalSlice(cronMask, argMask) {
				return "present", nil
			}
			overlap := false
			for _, m := range argMask {
				if containsStr(strings.Split(cron.mask, ","), m) {
					overlap = true
					break
				}
			}
			if overlap {
				updated = true // replaced below by the new entry
			} else {
				updatedCrons = append(updatedCrons, cron)
			}
			continue
		}
		updatedCrons = append(updatedCrons, cron)
	}
	updatedCrons = append(updatedCrons, cronEntry{path: a.Path, mask: mask, cmd: a.Cmd})
	lst.crons = updatedCrons

	comdat := writeIncronLines(ctx, rt, a.User, renderTab(lst))
	if comdat.retcode != 0 {
		return comdat.stderr, nil
	}
	if updated {
		return "updated", nil
	}
	return "new", nil
}

type RmJobArgs struct {
	User string `statekit:"required,name=user"`
	Path string `statekit:"required,name=path"`
	Mask string `statekit:"required,name=mask"`
	Cmd  string `statekit:"required,name=cmd"`
}

type RmJobFunc struct{}

func (RmJobFunc) Name() string { return "incron.rm_job" }
func (RmJobFunc) Args() any    { return RmJobArgs{} }

func (RmJobFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*RmJobArgs)
	mask := strings.ToUpper(a.Mask)
	if invalid, ok := validMask(mask); !ok {
		return fmt.Sprintf("Invalid mask type: %s", invalid), nil
	}

	lst := parseTab(readTab(rt, a.User))
	ret := "absent"
	rmIdx := -1
	for ind, val := range lst.crons {
		if rmIdx >= 0 {
			break
		}
		if a.Path == val.path && a.Cmd == val.cmd && mask == val.mask {
			rmIdx = ind
		}
	}
	if rmIdx >= 0 {
		lst.crons = append(lst.crons[:rmIdx], lst.crons[rmIdx+1:]...)
		ret = "removed"
	}
	comdat := writeIncronLines(ctx, rt, a.User, renderTab(lst))
	if comdat.retcode != 0 {
		return comdat.stderr, nil
	}
	return ret, nil
}

type WriteIncronFileArgs struct {
	User string `statekit:"required,name=user"`
	Path string `statekit:"required,name=path"`
}

type writeIncronFileFunc struct{}

func (writeIncronFileFunc) Name() string { return "incron.write_incron_file" }
func (writeIncronFileFunc) Args() any    { return WriteIncronFileArgs{} }
func (writeIncronFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*WriteIncronFileArgs)
	res := rt.Runner.Run(ctx, runtime.Command("incrontab", expandUser(a.Path)))
	return res.ExitCode == 0 && res.Err == nil, nil
}

type WriteIncronFileVerboseFunc struct{}

func (WriteIncronFileVerboseFunc) Name() string { return "incron.write_incron_file_verbose" }
func (WriteIncronFileVerboseFunc) Args() any    { return WriteIncronFileArgs{} }
func (WriteIncronFileVerboseFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*WriteIncronFileArgs)
	res := rt.Runner.Run(ctx, runtime.Command("incrontab", expandUser(a.Path)))
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

func expandUser(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return "/root/" + rest
	}
	return path
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SetPaths overrides the incron tab locations (for tests).
func SetPaths(systemTab, spoolDir string) {
	incronSystemTab = systemTab
	incronSpoolDir = spoolDir
}

// Register installs all incron-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		ListTabFunc{},
		rawIncronFunc{},
		RawSystemIncronFunc{},
		RmJobFunc{},
		SetJobFunc{},
		writeIncronFileFunc{},
		WriteIncronFileVerboseFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
