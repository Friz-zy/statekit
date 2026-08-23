package sysfs

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execsysfs "github.com/friz-zy/statekit/modules/exec/sysfs"
)

// The suite drives the real exec sysfs functions over a MemoryFS so the
// state contract is tested end-to-end through the registry.
func newRT(t *testing.T) *runtime.Runtime {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
	}
	if err := execsysfs.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.MkdirAll("/sys/block/sda/queue", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/sys/block/sda/queue/scheduler", []byte("[none] mq-deadline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/sys/block/sda/queue/frozen", []byte("0\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	return rt
}

func apply(t *testing.T, rt *runtime.Runtime, args PresentArgs) result.StateResult {
	t.Helper()
	return presentFunc{}.Apply(context.Background(), rt, &args)
}

// fakeDelegate stands in for a __salt__ function like Salt's own unit
// tests do with MagicMock.
type fakeDelegate struct {
	name string
	res  any
}

func (f *fakeDelegate) Name() string { return f.name }
func (f *fakeDelegate) Args() any    { return struct{}{} }
func (f *fakeDelegate) Execute(context.Context, *runtime.Runtime, any) (any, error) {
	return f.res, nil
}

// Mirrors test_if_the_sysfs_attribute_exists.
func TestPresentMissingAttribute(t *testing.T) {
	rt := newRT(t)
	ret := apply(t, rt, PresentArgs{Name: "block/sda/queue/this_does_not_exist", Value: "none"})
	if ret.Result == nil || *ret.Result != false || ret.Comment != "SysFS attribute block/sda/queue/this_does_not_exist doesn't exist." {
		t.Fatalf("ret = %+v", ret)
	}
	if len(ret.Changes) != 0 {
		t.Fatalf("changes = %v", ret.Changes)
	}
}

// Mirrors test_name_is_an_object_and_not_an_attribute.
func TestPresentObjectNotAttribute(t *testing.T) {
	rt := newRT(t)
	ret := apply(t, rt, PresentArgs{Name: "block/sda/queue", Value: "none"})
	if ret.Result == nil || *ret.Result != false || ret.Comment != "block/sda/queue is not a SysFS attribute." {
		t.Fatalf("ret = %+v", ret)
	}
}

// Mirrors test_already_set: choice lists compare against the selection.
func TestPresentAlreadySet(t *testing.T) {
	rt := newRT(t)
	ret := apply(t, rt, PresentArgs{Name: "block/sda/queue/scheduler", Value: "none"})
	if ret.Result == nil || *ret.Result != true || ret.Comment != "SysFS attribute block/sda/queue/scheduler is already set." {
		t.Fatalf("ret = %+v", ret)
	}
	if !reflect.DeepEqual(ret.Changes, map[string]any{}) {
		t.Fatalf("changes = %v", ret.Changes)
	}
}

// Mirrors test_set_new_value_with_test_equals_true.
func TestPresentTestModeNoMutation(t *testing.T) {
	rt := newRT(t)
	ret := apply(t, rt, PresentArgs{Name: "block/sda/queue/scheduler", Value: "mq-deadline", Test: true})
	if ret.Result != nil {
		t.Fatalf("test mode result = %v, want null", ret.Result)
	}
	if ret.Comment != "SysFS attribute block/sda/queue/scheduler set to be changed." {
		t.Fatalf("comment = %q", ret.Comment)
	}
	data, _ := rt.FS.ReadFile("/sys/block/sda/queue/scheduler")
	if string(data) != "[none] mq-deadline\n" {
		t.Fatalf("test mode mutated the attribute: %q", data)
	}
}

func TestPresentAppliesChange(t *testing.T) {
	rt := newRT(t)
	ret := apply(t, rt, PresentArgs{Name: "block/sda/queue/scheduler", Value: "mq-deadline"})
	if ret.Result == nil || *ret.Result != true {
		t.Fatalf("result = %v", ret.Result)
	}
	if !reflect.DeepEqual(ret.Changes, map[string]any{"block/sda/queue/scheduler": "mq-deadline"}) {
		t.Fatalf("changes = %v", ret.Changes)
	}
	if ret.Comment != "Updated SysFS attribute block/sda/queue/scheduler to mq-deadline" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	data, _ := rt.FS.ReadFile("/sys/block/sda/queue/scheduler")
	if string(data) != "mq-deadline\n" {
		t.Fatalf("written data = %q", data)
	}

	// Idempotent second run reports no changes.
	second := apply(t, rt, PresentArgs{Name: "block/sda/queue/scheduler", Value: "mq-deadline"})
	if second.Result == nil || *second.Result != true || len(second.Changes) != 0 {
		t.Fatalf("second run = %+v", second)
	}
}

func TestPresentWriteFailure(t *testing.T) {
	// Mirror Salt's mocked __salt__ style: sysfs.write reporting false
	// must land in the failure branch without mutating anything.
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
	}
	fakes := []struct {
		name string
		res  any
	}{
		{"sysfs.read", "performance"},
		{"sysfs.write", false},
	}
	for _, fake := range fakes {
		fake := fake
		if err := rt.Exec.Register(&fakeDelegate{name: fake.name, res: fake.res}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Register(rt.States); err != nil {
		t.Fatal(err)
	}

	ret := presentFunc{}.Apply(context.Background(), rt, &PresentArgs{
		Name: "devices/system/cpu/cpufreq/policy0", Value: "powersave",
	})
	if ret.Result == nil || *ret.Result != false {
		t.Fatalf("result = %v", ret.Result)
	}
	if ret.Comment != "Failed to set devices/system/cpu/cpufreq/policy0 to powersave" {
		t.Fatalf("comment = %q", ret.Comment)
	}
	if len(ret.Changes) != 0 {
		t.Fatalf("changes = %v", ret.Changes)
	}
}
