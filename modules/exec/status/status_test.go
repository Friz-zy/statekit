package status

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func testRT() *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{}),
		Runner: process.NewRunner(),
		FS:     runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/proc", 0o755)
	rt.FS.WriteFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/100 1234\n"), 0o644)
	rt.FS.WriteFile("/proc/uptime", []byte("12345.67 23456.78\n"), 0o644)
	rt.FS.WriteFile("/proc/meminfo", []byte("MemTotal:       16384 kB\nMemFree:         1024 kB\n"), 0o644)
	return rt
}

func TestLoadavg(t *testing.T) {
	value, err := loadavgFunc{}.Execute(context.Background(), testRT(), &loadavgArgs{})
	if err != nil {
		t.Fatalf("loadavg: %v", err)
	}
	m := value.(map[string]any)
	if m["1-min"].(float64) != 0.10 || m["5-min"].(float64) != 0.20 || m["15-min"].(float64) != 0.30 {
		t.Fatalf("loadavg wrong: %+v", m)
	}
}

func TestUptime(t *testing.T) {
	value, err := uptimeFunc{}.Execute(context.Background(), testRT(), &uptimeArgs{})
	if err != nil {
		t.Fatalf("uptime: %v", err)
	}
	if value.(map[string]any)["seconds"].(float64) != 12345.67 {
		t.Fatalf("uptime = %v", value)
	}
}

func TestDiskusageRealFS(t *testing.T) {
	value, err := diskusageFunc{}.Execute(context.Background(), testRT(), &diskusageArgs{Path: "/tmp"})
	if err != nil {
		t.Fatalf("diskusage on real fs: %v", err)
	}
	entry := value.(map[string]any)["/tmp"].(map[string]any)
	if entry["filesystem"] != "/tmp" {
		t.Fatalf("filesystem = %v", entry["filesystem"])
	}
	if !strings.HasSuffix(entry["capacity"].(string), "%") {
		t.Fatalf("capacity = %v", entry["capacity"])
	}
}

func TestMeminfo(t *testing.T) {
	value, err := meminfoFunc{}.Execute(context.Background(), testRT(), &meminfoArgs{})
	if err != nil {
		t.Fatalf("meminfo: %v", err)
	}
	m := value.(map[string]any)
	memTotal, ok := m["MemTotal"].(map[string]any)
	if !ok {
		t.Fatalf("MemTotal entry wrong: %v", m["MemTotal"])
	}
	if _, hasUnit := memTotal["unit"]; !hasUnit {
		t.Fatal("MemTotal must carry a unit")
	}
}
