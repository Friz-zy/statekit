package timezone

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type scriptRunner struct {
	script []process.CommandResult
	calls  [][]string
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	if len(s.script) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next
}

func TestGetZoneFromFile(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/timezone", []byte("Europe/Berlin\n"), 0o644)
	value, err := (getZoneFunc{}).Execute(context.Background(), rt, &getZoneArgs{})
	if err != nil || value != "Europe/Berlin" {
		t.Fatalf("zone = %v, %v", value, err)
	}
}

func TestGetZoneFromLocaltimeSymlink(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.MkdirAll("/usr/share/zoneinfo", 0o755)
	rt.FS.Symlink("/usr/share/zoneinfo/Asia/Tokyo", "/etc/localtime")
	value, err := (getZoneFunc{}).Execute(context.Background(), rt, &getZoneArgs{})
	if err != nil || value != "Asia/Tokyo" {
		t.Fatalf("zone from symlink = %v, %v", value, err)
	}
}

func TestSetZone(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.MkdirAll("/usr/share/zoneinfo/Europe", 0o755)
	rt.FS.WriteFile("/usr/share/zoneinfo/Europe/Paris", []byte{0x1}, 0o644)

	if _, err := (setZoneFunc{}).Execute(context.Background(), rt, &setZoneArgs{TimeZone: "Europe/Paris"}); err != nil {
		t.Fatalf("set_zone: %v", err)
	}
	target, err := rt.FS.Readlink("/etc/localtime")
	if err != nil || target != "/usr/share/zoneinfo/Europe/Paris" {
		t.Fatalf("localtime link = %q, %v", target, err)
	}
	data, _ := rt.FS.ReadFile("/etc/timezone")
	if strings.TrimSpace(string(data)) != "Europe/Paris" {
		t.Fatalf("/etc/timezone = %q", data)
	}
	if _, err := (setZoneFunc{}).Execute(context.Background(), rt, &setZoneArgs{TimeZone: "Nowhere/Never"}); err == nil {
		t.Fatal("unknown zone must fail")
	}
}

func TestHwclockViaTimedatectlAndAdjtime(t *testing.T) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), FS: runtime.NewMemoryFS(), Runner: runner}
	runner.script = []process.CommandResult{{Stdout: []byte("Clock=UTC\n"), ExitCode: 0}}
	value, err := (getHwclockFunc{}).Execute(context.Background(), rt, &getHwclockArgs{})
	if err != nil || value != "UTC" {
		t.Fatalf("hwclock = %v, %v", value, err)
	}

	runner.script = nil
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/adjtime", []byte("0.0\n0\nLOCAL\n"), 0o644)
	value, err = (getHwclockFunc{}).Execute(context.Background(), rt, &getHwclockArgs{})
	if err != nil || value != "LOCAL" {
		t.Fatalf("adjtime hwclock = %v, %v", value, err)
	}
}
