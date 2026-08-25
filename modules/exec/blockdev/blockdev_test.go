package blockdev

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct{}

func (fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	flag := ""
	if len(cmd.Args) > 1 {
		flag = cmd.Args[1]
	}
	_ = flag
	switch {
	case strings.HasSuffix(strings.Join(cmd.Args, " "), "--getsize64 /dev/sda"):
		return process.CommandResult{Stdout: []byte("512110190592\n"), ExitCode: 0}
	case strings.Contains(strings.Join(cmd.Args, " "), "--getsz"):
		return process.CommandResult{Stdout: []byte("1000215208\n"), ExitCode: 0}
	case strings.Contains(strings.Join(cmd.Args, " "), "--ssz"):
		return process.CommandResult{Stdout: []byte("512\n"), ExitCode: 0}
	}
	fmt.Println(strings.Join(append([]string{cmd.Name}, cmd.Args...), " "))
	return process.CommandResult{ExitCode: 1, Stderr: []byte("unknown flag")}
}

func TestBlockdevInfo(t *testing.T) {
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{}), Runner: fakeRunner{}, FS: runtime.NewMemoryFS()}
	value, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Device: "/dev/sda"})
	if err != nil {
		t.Fatal(err)
	}
	info := value.(map[string]any)
	if info["size_bytes"].(int64) != 512110190592 || info["sector_size"].(int64) != 512 {
		t.Fatalf("info wrong: %+v", info)
	}
	if info["device"] != "/dev/sda" {
		t.Fatalf("device = %v", info["device"])
	}
}
