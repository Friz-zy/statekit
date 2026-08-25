package mount

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const mountsFixture = `/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid 0 0
`

const fstabFixture = `# <fs> <mountpoint> <type> <opts> <dump> <pass>
/dev/sda1  /  ext4  defaults  1  1
tmpfs /tmp tmpfs rw,size=512m 0 0
`

type scriptRunner struct {
	calls [][]string
	code  int
}

func (s *scriptRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	s.calls = append(s.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: s.code}
}

func newRT() (*runtime.Runtime, *scriptRunner) {
	runner := &scriptRunner{}
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: runner,
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/proc", 0o755)
	rt.FS.WriteFile("/proc/mounts", []byte(mountsFixture), 0o644)
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/fstab", []byte(fstabFixture), 0o644)
	return rt, runner
}

func TestActive(t *testing.T) {
	rt, _ := newRT()
	value, err := (activeFunc{}).Execute(context.Background(), rt, &activeArgs{})
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	m := value.(map[string]any)
	root := m["/"].(map[string]any)
	if root["fstype"] != "ext4" || root["device"] != "/dev/sda1" {
		t.Fatalf("root mount wrong: %+v", root)
	}
	if strings.Join(root["opts"].([]string), ",") != "rw,relatime" {
		t.Fatalf("opts = %v", root["opts"])
	}
}

func TestIsMounted(t *testing.T) {
	rt, _ := newRT()
	value, _ := (isMountedFunc{}).Execute(context.Background(), rt, &isMountedArgs{Path: "/proc"})
	if value != true {
		t.Fatal("/proc must be mounted")
	}
	value, _ = (isMountedFunc{}).Execute(context.Background(), rt, &isMountedArgs{Path: "/nope"})
	if value != false {
		t.Fatal("unmounted path must report false")
	}
}

func TestFstabParsing(t *testing.T) {
	rt, _ := newRT()
	value, err := (fstabFunc{}).Execute(context.Background(), rt, &fstabArgs{})
	if err != nil {
		t.Fatalf("fstab: %v", err)
	}
	m := value.(map[string]any)
	tmp := m["/tmp"].(map[string]any)
	if tmp["fstype"] != "tmpfs" || tmp["device"] != "tmpfs" {
		t.Fatalf("tmp entry wrong: %+v", tmp)
	}
	if strings.Join(tmp["opts"].([]string), ",") != "rw,size=512m" {
		t.Fatalf("tmp opts = %v", tmp["opts"])
	}
	root := m["/"].(map[string]any)
	if strings.Join(root["opts"].([]string), ",") != "defaults" {
		t.Fatalf("root opts = %v", root["opts"])
	}
}

func TestMountUmountArgv(t *testing.T) {
	rt, runner := newRT()
	(mountFunc{}).Execute(context.Background(), rt, &mountArgs{
		Name: "/mnt/x", Device: "/dev/sdb1", FsType: "ext4", Opts: "rw,noatime",
	})
	got := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "mount -t ext4 -o rw,noatime /dev/sdb1 /mnt/x" {
		t.Fatalf("mount argv = %q", got)
	}
	(umountFunc{}).Execute(context.Background(), rt, &umountArgs{Name: "/mnt/x"})
	got = strings.Join(runner.calls[len(runner.calls)-1], " ")
	if got != "umount /mnt/x" {
		t.Fatalf("umount argv = %q", got)
	}
	runner.code = 32
	if _, err := (umountFunc{}).Execute(context.Background(), rt, &umountArgs{Name: "/mnt/x"}); err == nil {
		t.Fatal("failed umount must error")
	}
}
