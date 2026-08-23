// Package status implements Salt-compatible local system inspection.
//
// Reference: saltstack/salt/modules/status.py @ pinned revision, reduced to
// cheap local reads (load average, uptime, filesystem usage).
package status

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/runtime"
)

// procOnly marks functions reading /proc directly; they are linux contracts.
type procOnly struct{}

func (procOnly) Platforms() []string { return []string{"linux"} }

type loadavgArgs struct{}

type loadavgFunc struct {
	procOnly
}

func (loadavgFunc) Name() string { return "status.loadavg" }
func (loadavgFunc) Args() any    { return loadavgArgs{} }
func (loadavgFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected /proc/loadavg contents")
	}
	return map[string]any{
		"1-min":  parseFloat(fields[0]),
		"5-min":  parseFloat(fields[1]),
		"15-min": parseFloat(fields[2]),
	}, nil
}

type uptimeArgs struct{}

type uptimeFunc struct {
	procOnly
}

func (uptimeFunc) Name() string { return "status.uptime" }
func (uptimeFunc) Args() any    { return uptimeArgs{} }
func (uptimeFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile("/proc/uptime")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return nil, fmt.Errorf("unexpected /proc/uptime contents")
	}
	return map[string]any{"seconds": parseFloat(fields[0])}, nil
}

type diskusageArgs struct {
	Path string `statekit:"name=path"`
}

type diskusageFunc struct{}

func (diskusageFunc) Name() string { return "status.diskusage" }
func (diskusageFunc) Args() any    { return diskusageArgs{} }
func (diskusageFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*diskusageArgs)
	path := a.Path
	if path == "" {
		path = "/"
	}
	usage, err := readDiskUsage(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{path: usage}, nil
}

// Register installs all status-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	fns := []runtime.ExecFunction{loadavgFunc{}, uptimeFunc{}, diskusageFunc{}, meminfoFunc{}, pidListFunc{}}
	for _, fn := range fns {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}

type meminfoArgs struct{}

type meminfoFunc struct {
	procOnly
}

func (meminfoFunc) Name() string { return "status.meminfo" }
func (meminfoFunc) Args() any    { return meminfoArgs{} }
func (meminfoFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	data, err := rt.FS.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			out[strings.TrimSpace(key)] = strings.TrimSpace(rest)
			continue
		}
		entry := map[string]any{"value": value}
		if len(fields) > 1 {
			entry["unit"] = fields[1]
		}
		out[strings.TrimSpace(key)] = entry
	}
	return out, nil
}

func parseFloat(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}
