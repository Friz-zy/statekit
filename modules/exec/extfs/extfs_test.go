package extfs

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	result process.CommandResult
	calls  [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return f.result
}

// TestMkfs mirrors Salt's test_mkfs including the full_return shape.
func TestMkfs(t *testing.T) {
	runner := &fakeRunner{result: process.CommandResult{}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}

	got, err := mkfsFunc{}.Execute(context.Background(), rt,
		&MkfsArgs{Device: "/dev/sda1", FsType: "ext4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.([]string)) != 0 {
		t.Fatalf("mkfs = %v", got)
	}
	wantArgv := []string{"mke2fs", "-F", "-t", "ext4", "/dev/sda1"}
	if !reflect.DeepEqual(runner.calls[0], wantArgv) {
		t.Fatalf("argv = %v", runner.calls[0])
	}

	full, err := mkfsFunc{}.Execute(context.Background(), rt,
		&MkfsArgs{Device: "/dev/sda1", FsType: "ext4", FullReturn: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"retcode": 0, "stdout": "", "stderr": "", "comment": []string{},
	}
	if !reflect.DeepEqual(full, want) {
		t.Fatalf("full = %v", full)
	}
}

// TestMkfsOptions pins flag translation and bare-flag booleans.
func TestMkfsOptions(t *testing.T) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	fn := mkfsFunc{}
	if _, err := fn.Execute(context.Background(), rt, &MkfsArgs{
		Device: "/dev/sda1", FsType: "ext4",
		Option: map[string]string{"label": "data", "force": "true", "unknown": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"mke2fs", "-F", "-t", "ext4",
		"-F", "-L", "data", "/dev/sda1"}
	if !reflect.DeepEqual(runner.calls[0], want) {
		t.Fatalf("options argv = %v", runner.calls[0])
	}
}

// TestTune mirrors Salt's test_tune line collection.
func TestTune(t *testing.T) {
	runner := &fakeRunner{result: process.CommandResult{
		ExitCode: 1,
		Stdout:   []byte("tune2fs 1.44.5 (15-Dec-2018)\n"),
		Stderr: []byte("tune2fs: No such file or directory while trying to open /dev/donkey\n" +
			"Couldn't find valid filesystem superblock.\n"),
	}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}

	got, err := tuneFunc{}.Execute(context.Background(), rt, &TuneArgs{Device: "/dev/sda1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tune2fs 1.44.5 (15-Dec-2018)",
		"tune2fs: No such file or directory while trying to open /dev/donkey",
		"Couldn't find valid filesystem superblock.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tune = %v", got)
	}

	full, err := tuneFunc{}.Execute(context.Background(), rt,
		&TuneArgs{Device: "/dev/sda1", FullReturn: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(full.(map[string]any)["comment"], want) {
		t.Fatalf("tune full = %v", full)
	}
}

const dumpe2fsFixture = `dumpe2fs 1.46.2 (28-Feb-2021)
Filesystem volume name:   <none>
Filesystem features:      has_journal ext_attr resize_inode
Filesystem state:         clean
Inode count:              2560
Block count:              5120
Group 0: (Blocks 0-4096) csum 0x1234
 Primary superblock at 0, Group descriptors at 1-1
 Free blocks: 2048-4096
 Free inodes: 11-2560
Group 1: (Blocks 4097-5119)
 Free blocks: 5000-5119
 Free inodes: 2500-2560
`

// TestDump covers both parse modes end to end.
func TestDump(t *testing.T) {
	runner := &fakeRunner{result: process.CommandResult{Stdout: []byte(dumpe2fsFixture)}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}

	gotRaw, err := dumpFunc{}.Execute(context.Background(), rt, &DumpArgs{Device: "/dev/sda1"})
	if err != nil {
		t.Fatal(err)
	}
	dump := gotRaw.(*fsDump)

	if dump.Attributes["Filesystem volume name"] != "<none>" ||
		dump.Attributes["Filesystem state"] != "clean" {
		t.Fatalf("attributes = %v", dump.Attributes)
	}
	features := dump.Attributes["Filesystem features"].([]string)
	if len(features) != 3 || features[0] != "has_journal" {
		t.Fatalf("features = %v", features)
	}

	if _, ok := dump.Blocks["Group 0"]; !ok {
		t.Fatalf("group 0 missing: %v", dump.Blocks)
	}
	g0 := dump.Blocks["Group 0"].(map[string]any)
	if g0["range"] != "0-4096" {
		t.Fatalf("range = %v", g0["range"])
	}
	if !reflect.DeepEqual(g0["free blocks"], []string{"2048-4096"}) {
		t.Fatalf("free blocks = %v", g0["free blocks"])
	}
	if !reflect.DeepEqual(g0["free inodes"], []string{"11-2560"}) {
		t.Fatalf("free inodes = %v", g0["free inodes"])
	}
	extra := g0["extra"].([]string)
	if len(extra) != 1 || !strings.Contains(extra[0], "Primary superblock") {
		t.Fatalf("extra = %v", extra)
	}
	g1 := dump.Blocks["Group 1"].(map[string]any)
	if !reflect.DeepEqual(g1["free blocks"], []string{"5000-5119"}) {
		t.Fatalf("g1 blocks = %v", g1["free blocks"])
	}

	if !reflect.DeepEqual(runner.calls[0], []string{"dumpe2fs", "/dev/sda1"}) {
		t.Fatalf("dump argv = %v", runner.calls[0])
	}

	attrs, err := attributesFunc{}.Execute(context.Background(), rt,
		&AttributesArgs{Device: "/dev/sda1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := attrs.(map[string]any)["Inode count"]; !ok {
		t.Fatalf("attributes view = %v", attrs)
	}

	blocks, err := blocksFunc{}.Execute(context.Background(), rt,
		&BlocksArgs{Device: "/dev/sda1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks.(map[string]any)) == 0 {
		t.Fatalf("blocks view empty")
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 5 {
		t.Fatalf("registered %d functions", len(reg.Names()))
	}
	for _, name := range reg.Names() {
		fn, _ := reg.Get(name)
		if c, ok := fn.(interface{ Platforms() []string }); !ok ||
			strings.Join(c.Platforms(), ",") != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}
