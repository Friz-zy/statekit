// Package cron implements the Salt-compatible cron.present/cron.absent
// states on top of the cron execution module.
//
// Reference: saltstack/salt/states/cron.py @ pinned revision.
package cron

import (
	"context"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execcron "github.com/friz-zy/statekit/modules/exec/cron"
)

type presentArgs struct {
	User     string `statekit:"required,name=user"`
	Job      string `statekit:"required,name=job"`
	Minute   string `statekit:"name=minute"`
	Hour     string `statekit:"name=hour"`
	Daymonth string `statekit:"name=daymonth"`
	Month    string `statekit:"name=month"`
	Dayweek  string `statekit:"name=dayweek"`
	Comment  string `statekit:"name=comment"`
	Test     bool   `statekit:"name=test"`
}

type presentFunc struct{}

func (presentFunc) Name() string { return "cron.present" }
func (presentFunc) Args() any    { return presentArgs{} }
func (presentFunc) Apply(ctx context.Context, rt *runtime.Runtime, args any) result.StateResult {
	a := args.(*presentArgs)
	value, err := rt.Exec.Call(ctx, rt, "cron.list_tab", &execcron.ListTabArgs{User: a.User})
	if err != nil {
		return result.Failure(a.Job, err.Error())
	}
	grouped, _ := value.(map[string]any)
	for _, entry := range toStrings(grouped["crons"]) {
		if endsWithCommand(entry, a.Job) {
			fields := strings.Fields(strings.TrimSuffix(entry, a.Job))
			if fieldsMatch(fields, a.Minute, a.Hour, a.Daymonth, a.Month, a.Dayweek) {
				return result.Success(a.Job, fmt.Sprintf("Cron job %s for user %s already present", a.Job, a.User))
			}
		}
	}

	if a.Test {
		return result.TestPending(a.Job,
			fmt.Sprintf("Cron job %s would be added for user %s", a.Job, a.User),
			map[string]any{"job": a.Job})
	}
	if _, err := rt.Exec.Call(ctx, rt, "cron.add_job", &execcron.AddJobArgs{
		User: a.User, Minute: a.Minute, Hour: a.Hour, Daymonth: a.Daymonth,
		Month: a.Month, Dayweek: a.Dayweek, Command: a.Job, Comment: a.Comment,
	}); err != nil {
		return result.Failure(a.Job, err.Error())
	}
	return result.New(a.Job, "", result.Bool(true), map[string]any{"added": a.Job})
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, len(list))
	for i, item := range list {
		s, _ := item.(string)
		out[i] = s
	}
	return out
}

func endsWithCommand(entry, command string) bool {
	return len(entry) > len(command) && entry[len(entry)-len(command):] == command
}

func fieldsMatch(fields []string, want ...string) bool {
	if len(fields) != len(want) {
		return false
	}
	for i := range want {
		got := fields[i]
		expected := want[i]
		if expected == "" {
			expected = "*"
		}
		if got != expected {
			return false
		}
	}
	return true
}

// Register installs all cron-module state functions.
func Register(reg *runtime.StateRegistry) error {
	return reg.Register(presentFunc{})
}
