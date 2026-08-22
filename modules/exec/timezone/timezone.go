// Package timezone implements Salt-compatible timezone inspection and
// management.
//
// Reference: saltstack/salt/modules/timezone.py @ pinned revision.
package timezone

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

func fsPerm(mode uint32) fs.FileMode { return fs.FileMode(mode) }

// rtcValue maps a clock name onto timedatectl's set-local-rtc boolean.
func rtcValue(clock string) string {
	if clock == "UTC" {
		return "0"
	}
	return "1"
}

const (
	timezoneFile   = "/etc/timezone"
	localtimePath  = "/etc/localtime"
	zoneinfoPrefix = "/usr/share/zoneinfo/"
)

type getZoneArgs struct{}

type getZoneFunc struct{}

func (getZoneFunc) Name() string { return "timezone.get_zone" }
func (getZoneFunc) Args() any    { return getZoneArgs{} }
func (getZoneFunc) Execute(_ context.Context, rt *runtime.Runtime, _ any) (any, error) {
	if data, err := rt.FS.ReadFile(timezoneFile); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	target, err := rt.FS.Readlink(localtimePath)
	if err != nil {
		return nil, fmt.Errorf("could not determine timezone: %w", err)
	}
	return strings.TrimPrefix(target, zoneinfoPrefix), nil
}

type setZoneArgs struct {
	TimeZone string `statekit:"required,name=time_zone"`
}

type setZoneFunc struct{}

func (setZoneFunc) Name() string { return "timezone.set_zone" }
func (setZoneFunc) Args() any    { return setZoneArgs{} }
func (setZoneFunc) Execute(_ context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setZoneArgs)
	zone := strings.TrimPrefix(a.TimeZone, zoneinfoPrefix)
	source := zoneinfoPrefix + zone
	if _, err := rt.FS.Stat(source); err != nil {
		return nil, fmt.Errorf("unknown time zone %q", zone)
	}
	mode := fs.FileMode(0o644)
	if info, err := rt.FS.Stat(timezoneFile); err == nil {
		mode = info.Mode().Perm()
	}
	rt.FS.Remove(localtimePath)
	if err := rt.FS.Symlink(source, localtimePath); err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(timezoneFile, []byte(zone+"\n"), mode); err != nil {
		return nil, err
	}
	return true, nil
}

type getOffsetArgs struct{}

type getOffsetFunc struct{}

func (getOffsetFunc) Name() string { return "timezone.get_offset" }
func (getOffsetFunc) Args() any    { return getOffsetArgs{} }
func (getOffsetFunc) Execute(_ context.Context, _ *runtime.Runtime, _ any) (any, error) {
	return time.Now().Format("-0700"), nil
}

type getHwclockArgs struct{}

type getHwclockFunc struct{}

func (getHwclockFunc) Name() string { return "timezone.get_hwclock" }
func (getHwclockFunc) Args() any    { return getHwclockArgs{} }
func (getHwclockFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	res := rt.Runner.Run(ctx, runtime.Command("timedatectl", "show", "-p", "Clock"))
	if res.Err == nil && res.ExitCode == 0 {
		line := strings.TrimSpace(string(res.Stdout))
		if _, value, ok := strings.Cut(line, "="); ok {
			return value, nil
		}
	}
	data, err := rt.FS.ReadFile("/etc/adjtime")
	if err != nil {
		return nil, fmt.Errorf("could not determine hwclock: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) >= 3 {
		return strings.TrimSpace(lines[2]), nil
	}
	return "", fmt.Errorf("could not determine hwclock")
}

type setHwclockArgs struct {
	Clock string `statekit:"required,name=clock"`
}

type setHwclockFunc struct{}

func (setHwclockFunc) Name() string { return "timezone.set_hwclock" }
func (setHwclockFunc) Args() any    { return setHwclockArgs{} }
func (setHwclockFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (any, error) {
	a := args.(*setHwclockArgs)
	clock := a.Clock
	switch clock {
	case "UTC":
	case "localtime", "local":
		clock = "localtime"
	default:
		return nil, fmt.Errorf("clock must be UTC or localtime, got %q", a.Clock)
	}
	res := rt.Runner.Run(ctx, runtime.Command("timedatectl", "set-local-rtc", rtcValue(clock)))
	if res.Err != nil {
		return nil, res.Err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("timedatectl exited with code %d: %s", res.ExitCode, res.Stderr)
	}
	return true, nil
}

// Register installs all timezone-module execution functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getZoneFunc{}, setZoneFunc{}, getOffsetFunc{}, getHwclockFunc{}, setHwclockFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
