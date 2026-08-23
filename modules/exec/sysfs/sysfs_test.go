package sysfs

import (
	"context"
	"io/fs"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

// newTree builds the hermetic SysFS fixture used across the suite.
func newTree(t *testing.T) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec: runtime.NewExecRegistry(),
		FS:   runtime.NewMemoryFS(),
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}

	mustDir := func(p string) {
		if err := rt.FS.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustFile := func(p, data string, mode uint32) {
		if err := rt.FS.WriteFile(p, []byte(data), fs.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
	}

	// A queue directory like /sys/block/sda/queue.
	mustDir("/sys/block/sda/queue")
	mustDir("/sys/block/sda/queue/iosched")
	mustFile("/sys/block/sda/queue/logical_block_size", "512\n", 0o444)       // r
	mustFile("/sys/block/sda/queue/scheduler", "[none] mq-deadline\n", 0o644) // rw
	mustFile("/sys/block/sda/queue/iosched/quantum", "32\n", 0o644)           // rw nested
	mustDir("/sys/block/sda")
	mustFile("/sys/block/sda/size", "488386584\n", 0o444) // r
	mustFile("/sys/block/sda/dev", "8:0\n", 0o444)        // r
	// An action file: write-only.
	mustFile("/sys/block/sda/queue/tune_action", "", 0o200) // w
	// Empty readable attribute reads as false.
	mustFile("/sys/block/sda/empty", "", 0o444)
	return rt
}

func TestTarget(t *testing.T) {
	rt := newTree(t)
	tf := targetFunc{}

	// Relative keys get the /sys prefix.
	got, err := tf.Execute(context.Background(), rt, &TargetArgs{Key: "block/sda"})
	if err != nil || got != "/sys/block/sda" {
		t.Fatalf("target relative = %v, %v", got, err)
	}

	// Absolute keys pass through; full=false yields the basename.
	got, err = tf.Execute(context.Background(), rt, &TargetArgs{Key: "/sys/block/sda", Full: boolPtr(false)})
	if err != nil || got != "sda" {
		t.Fatalf("target basename = %v, %v", got, err)
	}

	// Unknown keys are boolean false.
	got, err = tf.Execute(context.Background(), rt, &TargetArgs{Key: "block/nope"})
	if err != nil || got != false {
		t.Fatalf("target missing = %v, %v", got, err)
	}

	// Symlinked keys resolve to their destination (realpath contract).
	if err := rt.FS.Symlink("/sys/block/sda", "/sys/block/sdlink"); err != nil {
		t.Fatal(err)
	}
	got, err = tf.Execute(context.Background(), rt, &TargetArgs{Key: "block/sdlink"})
	if err != nil || got != "/sys/block/sda" {
		t.Fatalf("symlink target = %v, %v", got, err)
	}
}

func TestReadWrite(t *testing.T) {
	rt := newTree(t)
	wf := writeFunc{}
	rf := readFunc{}

	got, err := wf.Execute(context.Background(), rt, &WriteArgs{Key: "block/sda/queue/scheduler", Value: "none"})
	if err != nil || got != true {
		t.Fatalf("write ok = %#v, %v", got, err)
	}
	data, _ := rt.FS.ReadFile("/sys/block/sda/queue/scheduler")
	if string(data) != "none\n" {
		t.Fatalf("written data = %q", data)
	}

	// Failed writes stay boolean false.
	got, err = wf.Execute(context.Background(), rt, &WriteArgs{Key: "block/missing/x", Value: "y"})
	if err != nil || got != false {
		t.Fatalf("write missing = %#v, %v", got, err)
	}

	// Scalar reads coerce ints then floats then keep strings.
	got, err = rf.Execute(context.Background(), rt, &ReadArgs{Key: []any{"block/sda/queue/logical_block_size"}})
	if err != nil || got != int64(512) {
		t.Fatalf("int read = %#v (%T), %v", got, got, err)
	}
	if err := rt.FS.WriteFile("/sys/block/sda/ratio", []byte("1.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ = rf.Execute(context.Background(), rt, &ReadArgs{Key: []any{"block/sda/ratio"}})
	if f, ok := got.(float64); !ok || f != 1.5 {
		t.Fatalf("float read = %#v (%T)", got, got)
	}

	// Empty values and unknown keys read as false.
	for _, key := range []string{"block/sda/empty", "block/sda/absent"} {
		got, err = rf.Execute(context.Background(), rt, &ReadArgs{Key: []any{key}})
		if err != nil || got != false {
			t.Fatalf("read %s = %#v, %v", key, got, err)
		}
	}

	// The root parameter prefixes each listed key; misses are skipped.
	got, err = rf.Execute(context.Background(), rt, &ReadArgs{
		Key:  []any{"logical_block_size", "missing"},
		Root: "/sys/block/sda/queue",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"logical_block_size": int64(512)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rooted list read = %#v, want %#v", got, want)
	}

	// Directory reads expand into a nested tree over readable interfaces.
	got, err = rf.Execute(context.Background(), rt, &ReadArgs{Key: []any{"block/sda/queue"}})
	if err != nil {
		t.Fatal(err)
	}
	tree := map[string]any{
		"logical_block_size": int64(512),
		// The earlier write in this test changed the live attribute.
		"scheduler": "none",
		"iosched":   map[string]any{"quantum": int64(32)},
	}
	if !reflect.DeepEqual(got, tree) {
		t.Fatalf("tree read = %#v, want %#v", got, tree)
	}
}

func TestAttr(t *testing.T) {
	rt := newTree(t)
	af := attrFunc{}

	// Read branch.
	got, err := af.Execute(context.Background(), rt, &AttrArgs{Key: "block/sda/size"})
	if err != nil || got != int64(488386584) {
		t.Fatalf("attr read = %#v, %v", got, err)
	}

	// Directory branch returns the resolved path itself.
	got, err = af.Execute(context.Background(), rt, &AttrArgs{Key: "block/sda"})
	if err != nil || got != "/sys/block/sda" {
		t.Fatalf("attr dir = %#v, %v", got, err)
	}

	// Write branch forwards the value.
	val := "performance"
	got, err = af.Execute(context.Background(), rt, &AttrArgs{Key: "block/sda/queue/scheduler", Value: &val})
	if err != nil || got != true {
		t.Fatalf("attr write = %#v, %v", got, err)
	}

	// Missing keys are false.
	got, err = af.Execute(context.Background(), rt, &AttrArgs{Key: "block/gone"})
	if err != nil || got != false {
		t.Fatalf("attr missing = %#v, %v", got, err)
	}
}

func TestInterfaces(t *testing.T) {
	rt := newTree(t)
	if_ := interfacesFunc{}

	gotRaw, err := if_.Execute(context.Background(), rt, &InterfacesArgs{Root: "block/sda"})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)

	assertSet(t, got["r"], "size", "dev", "empty", "queue/logical_block_size")
	assertSet(t, got["rw"], "queue/scheduler", "queue/iosched/quantum")
	assertSet(t, got["w"], "queue/tune_action")

	// Non-directories yield false.
	gotRaw, err = if_.Execute(context.Background(), rt, &InterfacesArgs{Root: "block/sda/size"})
	if err != nil || gotRaw != false {
		t.Fatalf("interfaces on file = %#v, %v", gotRaw, err)
	}
}

func assertSet(t *testing.T, got any, want ...string) {
	t.Helper()
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("expected list, got %#v", got)
	}
	have := map[string]bool{}
	for _, item := range list {
		have[item.(string)] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Fatalf("missing %q in %v", w, have)
		}
		delete(have, w)
	}
	if len(have) > 0 {
		t.Fatalf("unexpected extras %v", have)
	}
}

func boolPtr(b bool) *bool { return &b }
