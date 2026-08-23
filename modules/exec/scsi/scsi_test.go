package scsi

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeDelegate struct {
	name string
	res  any
}

func (f *fakeDelegate) Name() string { return f.name }
func (f *fakeDelegate) Args() any    { return struct{}{} }
func (f *fakeDelegate) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return f.res, nil
}

func newRT(t *testing.T, lsscsi string, runAllRes any) *runtime.Runtime {
	t.Helper()
	saved := lsscsiBin
	lsscsiBin = func() string { return lsscsi }
	t.Cleanup(func() { lsscsiBin = saved })
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
	}
	// Only the cmd.run_all delegate is registered, as a fake - matching
	// Salt's __salt__ patching style.
	if runAllRes != nil {
		if err := rt.Exec.Register(&fakeDelegate{name: "cmd.run_all", res: runAllRes}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt
}

// Mirrors test_ls_.
func TestLs(t *testing.T) {
	rt := newRT(t, "/usr/bin/lsscsi", map[string]any{
		"retcode": 0,
		"stdout":  "[0:0:0:0] disk HP LOGICAL VOLUME 6.68 /dev/sda [8:0] 1.20TB",
		"stderr":  "",
	})

	gotRaw, err := lsFunc{}.Execute(context.Background(), rt, &LsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"[0:0:0:0]": map[string]any{
			"lun":    "0:0:0:0",
			"size":   "1.20TB",
			"major":  "8",
			"minor":  "0",
			"device": "/dev/sda",
			"model":  "LOGICAL VOLUME 6.68",
		},
	}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("ls with size = %#v", gotRaw)
	}

	// get_size=False drops the -s switch and the size column.
	rt2 := newRT(t, "/usr/bin/lsscsi", map[string]any{
		"retcode": 0,
		"stdout":  "[0:0:0:0] disk HP LOGICAL VOLUME 6.68 /dev/sda [8:0]",
		"stderr":  "",
	})
	gotRaw, err = lsFunc{}.Execute(context.Background(), rt2, &LsArgs{GetSize: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	entry := gotRaw.(map[string]any)["[0:0:0:0]"].(map[string]any)
	if entry["size"] != nil || entry["model"] != "LOGICAL VOLUME 6.68" {
		t.Fatalf("no-size entry = %#v", entry)
	}
}

// Mirrors test_ls_ error paths: first stderr line, and the invalid-option
// hint when the -s probe fails on old lsscsi builds.
func TestLsErrors(t *testing.T) {
	rt := newRT(t, "/usr/bin/lsscsi", map[string]any{
		"retcode": 1,
		"stdout":  "",
		"stderr":  "An error occurred\nmore detail",
	})
	got, err := lsFunc{}.Execute(context.Background(), rt, &LsArgs{})
	if err != nil || got != "An error occurred" {
		t.Fatalf("error passthrough = %#v, %v", got, err)
	}

	rt2 := newRT(t, "/usr/bin/lsscsi", map[string]any{
		"retcode": 1,
		"stdout":  "",
		"stderr":  "lsscsi: invalid option -- 's'\nUsage: lsscsi [options]",
	})
	got, err = lsFunc{}.Execute(context.Background(), rt2, &LsArgs{})
	if err != nil || got != "lsscsi: invalid option -- 's' - try get_size=False" {
		t.Fatalf("invalid-option hint = %#v, %v", got, err)
	}

	rt3 := newRT(t, "", nil)
	got, err = lsFunc{}.Execute(context.Background(), rt3, &LsArgs{})
	if err != nil || got != "scsi.ls not available - lsscsi command not found" {
		t.Fatalf("missing binary = %#v, %v", got, err)
	}
}

// Mirrors test_rescan_all.
func TestRescanAll(t *testing.T) {
	rt := newRT(t, "", "scan triggered\n")
	if err := rt.FS.MkdirAll("/sys/class/scsi_host/host0", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.Exec.Register(&fakeDelegate{
		name: "cmd.run",
		res:  "scan triggered\n",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := rescanAllFunc{}.Execute(context.Background(), rt, &RescanAllArgs{Host: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []any{"scan triggered"}) {
		t.Fatalf("rescan output = %#v", got)
	}

	got, err = rescanAllFunc{}.Execute(context.Background(), rt, &RescanAllArgs{Host: "9"})
	if err != nil || got != "Host 9 does not exist" {
		t.Fatalf("missing host = %#v, %v", got, err)
	}
}

func boolPtr(b bool) *bool { return &b }
