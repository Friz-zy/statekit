package shadow

import (
	"context"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestShadowInfo(t *testing.T) {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/shadow", []byte("alice:$6$h$xyz:20000:5:60:7:14:21000:\n"), 0o600)

	value, err := infoFunc{}.Execute(context.Background(), rt, &infoArgs{Name: "alice"})
	if err != nil {
		t.Fatalf("shadow.info: %v", err)
	}
	info := value.(map[string]any)
	if info["passwd"] != "$6$h$xyz" || info["lstchg"].(int64) != 20000 || info["max"].(int64) != 60 {
		t.Fatalf("shadow info wrong: %+v", info)
	}

	if _, err := (infoFunc{}).Execute(context.Background(), rt, &infoArgs{Name: "ghost"}); err == nil {
		t.Fatal("missing user must error")
	}
}
