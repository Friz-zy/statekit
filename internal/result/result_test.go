package result

import (
	"encoding/json"
	"testing"
)

func TestTriStateResult(t *testing.T) {
	if Bool(true) == Bool(false) {
		t.Fatal("distinct pointers expected")
	}
	pending := TestPending("curl", "would install", map[string]any{
		"curl": map[string]any{"old": "", "new": "latest"},
	})
	if pending.Result != nil {
		t.Fatalf("test mode must carry nil result, got %v", *pending.Result)
	}
	if !pending.Changed() {
		t.Fatal("pending changes lost")
	}
}

func TestNewNormalizesNilChanges(t *testing.T) {
	res := Success("nginx", "ok")
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	changes, ok := back["changes"].(map[string]any)
	if !ok {
		t.Fatalf("changes must be an object, got %T (%s)", back["changes"], data)
	}
	if len(changes) != 0 {
		t.Fatalf("expected empty changes, got %v", changes)
	}
}

func TestSucceeded(t *testing.T) {
	if !Success("x", "").Succeeded() {
		t.Fatal("success must report succeeded")
	}
	if Failure("x", "").Succeeded() {
		t.Fatal("failure must not report succeeded")
	}
	if TestPending("x", "", nil).Succeeded() {
		t.Fatal("test-pending must not report succeeded")
	}
}
