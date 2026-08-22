package file

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"

	"github.com/friz-zy/statekit/internal/runtime"
)

func testRT() *runtime.Runtime {
	return &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
}

func TestManagedCreatesAndIsIdempotent(t *testing.T) {
	rt := testRT()

	first := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name: "/opt/app.conf", Contents: "key=value\n", Mode: "0640",
	})
	if !first.Succeeded() || !first.Changed() {
		t.Fatalf("create result wrong: %+v", first)
	}
	if first.Changes["newfile"] != "/opt/app.conf" {
		t.Fatalf("newfile change missing: %+v", first.Changes)
	}
	data, _ := rt.FS.ReadFile("/opt/app.conf")
	if string(data) != "key=value\n" {
		t.Fatalf("content = %q", data)
	}
	info, _ := rt.FS.Stat("/opt/app.conf")
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}

	second := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name: "/opt/app.conf", Contents: "key=value\n", Mode: "0640",
	})
	if !second.Succeeded() || second.Changed() {
		t.Fatalf("no-op must be success without changes: %+v", second)
	}
	if second.Comment != "File /opt/app.conf is in the correct state" {
		t.Fatalf("no-op comment = %q", second.Comment)
	}
}

func TestManagedTestModeCausesNoMutation(t *testing.T) {
	rt := testRT()
	pending := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name: "/etc/new.conf", Contents: "x", Test: true,
	})
	if pending.Result != nil {
		t.Fatalf("test mode must carry nil result, got %v", *pending.Result)
	}
	if pending.Changes["newfile"] != "/etc/new.conf" {
		t.Fatalf("changes = %+v", pending.Changes)
	}
	if _, err := rt.FS.Stat("/etc/new.conf"); err == nil {
		t.Fatal("test mode must not create the file")
	}

	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/existing", []byte("old"), 0o644)
	updatePending := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name: "/etc/existing", Contents: "new", Test: true,
	})
	if updatePending.Result != nil {
		t.Fatal("update test mode must be pending")
	}
	contentChange := updatePending.Changes["contents"].(map[string]any)
	if contentChange["old"] != "old" || contentChange["new"] != "new" {
		t.Fatalf("content delta wrong: %+v", contentChange)
	}
	stillOld, _ := rt.FS.ReadFile("/etc/existing")
	if string(stillOld) != "old" {
		t.Fatal("test mode mutated the file")
	}
}

func TestManagedFailureOnUnreadableSource(t *testing.T) {
	rt := testRT()
	res := managedFunc{}.Apply(context.Background(), rt, &managedArgs{
		Name: "/out", Source: "/missing/source",
	})
	if res.Succeeded() {
		t.Fatal("unreadable source must fail")
	}
}

func TestAbsentSemantics(t *testing.T) {
	rt := testRT()
	gone := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "/nothing"})
	if !gone.Succeeded() || gone.Changed() {
		t.Fatalf("already-absent must succeed without changes: %+v", gone)
	}

	rt.FS.MkdirAll("/tmp/x", 0o755)
	rt.FS.WriteFile("/tmp/x/f", []byte("d"), 0o644)

	testRes := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "/tmp/x", Test: true})
	if testRes.Result != nil || testRes.Changes["removed"] != "/tmp/x" {
		t.Fatalf("test removal wrong: %+v", testRes)
	}
	if testRes.Comment != "File /tmp/x is set for removal" {
		t.Fatalf("Salt comment mismatch: %q", testRes.Comment)
	}
	if _, err := rt.FS.Stat("/tmp/x"); err != nil {
		t.Fatal("test mode removed the tree")
	}

	applied := absentFunc{}.Apply(context.Background(), rt, &absentArgs{Name: "/tmp/x"})
	if !applied.Succeeded() || applied.Changes["removed"] != "/tmp/x" {
		t.Fatalf("removal wrong: %+v", applied)
	}
	if _, err := rt.FS.Stat("/tmp/x"); err == nil {
		t.Fatal("tree still present after removal")
	}
}

func TestDirectoryStates(t *testing.T) {
	rt := testRT()
	pending := directoryFunc{}.Apply(context.Background(), rt, &directoryArgs{Name: "/data", Test: true})
	if pending.Result != nil {
		t.Fatal("missing directory in test mode must pend")
	}
	if _, err := rt.FS.Stat("/data"); err == nil {
		t.Fatal("test mode created the directory")
	}

	applied := directoryFunc{}.Apply(context.Background(), rt, &directoryArgs{Name: "/data"})
	if !applied.Succeeded() {
		t.Fatalf("create failed: %+v", applied)
	}
	idempotent := directoryFunc{}.Apply(context.Background(), rt, &directoryArgs{Name: "/data"})
	if idempotent.Comment != "The directory /data is in the correct state" {
		t.Fatalf("Salt parity comment missing: %q", idempotent.Comment)
	}
}

func TestSymlinkLifecycle(t *testing.T) {
	rt := testRT()
	rt.FS.MkdirAll("/srv", 0o755)
	rt.FS.WriteFile("/srv/release-1", []byte("v1"), 0o644)

	applied := symlinkFunc{}.Apply(context.Background(), rt, &symlinkArgs{Name: "/srv/current", Target: "/srv/release-1"})
	if !applied.Succeeded() {
		t.Fatalf("symlink create failed: %+v", applied)
	}
	target, _ := rt.FS.Readlink("/srv/current")
	if target != "/srv/release-1" {
		t.Fatalf("link target = %q", target)
	}

	same := symlinkFunc{}.Apply(context.Background(), rt, &symlinkArgs{Name: "/srv/current", Target: "/srv/release-1"})
	if !same.Succeeded() || same.Changed() {
		t.Fatalf("idempotent symlink wrong: %+v", same)
	}

	switchPending := symlinkFunc{}.Apply(context.Background(), rt, &symlinkArgs{
		Name: "/srv/current", Target: "/srv/release-2", Force: true, Test: true,
	})
	if switchPending.Result != nil {
		t.Fatal("switch test mode must pend")
	}
	if switchPending.Comment != "Link /srv/current target is set to be changed to /srv/release-2" {
		t.Fatalf("Salt switch comment mismatch: %q", switchPending.Comment)
	}

	switched := symlinkFunc{}.Apply(context.Background(), rt, &symlinkArgs{
		Name: "/srv/current", Target: "/srv/release-2", Force: true,
	})
	if !switched.Succeeded() {
		t.Fatalf("force switch failed: %+v", switched)
	}
	target, _ = rt.FS.Readlink("/srv/current")
	if target != "/srv/release-2" {
		t.Fatalf("target after switch = %q", target)
	}
}
