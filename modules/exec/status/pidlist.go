// Additional status inspection via /proc scanning.
//
// Reference: saltstack/salt/modules/status.py @ pinned revision (pid_list).
package status

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

type pidListArgs struct {
	Name string `statekit:"required,name=name"`
}

type pidListFunc struct {
	procOnly
}

func (pidListFunc) Name() string { return "status.pid_list" }
func (pidListFunc) Args() any    { return pidListArgs{} }
func (pidListFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*pidListArgs)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// /proc is a live kernel filesystem; the FS abstraction cannot
		// substitute it here.
		return nil, fmt.Errorf("could not scan /proc: %w", err)
	}
	pids := []int{}
	for _, entry := range entries {
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil {
			continue
		}
		if comm, readErr := os.ReadFile("/proc/" + entry.Name() + "/comm"); readErr == nil &&
			strings.TrimSpace(string(comm)) == a.Name {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}
