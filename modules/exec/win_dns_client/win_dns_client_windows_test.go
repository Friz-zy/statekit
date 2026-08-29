//go:build windows

package win_dns_client

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type dnsRunner struct {
	calls []process.Command
	mode  string
}

func (r *dnsRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "powershell.exe" {
		if r.mode == "config" {
			return process.CommandResult{ExitCode: 0, Stdout: []byte("true")}
		}
		if r.calls[len(r.calls)-1].Args != nil {
			data, _ := json.Marshal([]string{"8.8.8.8", "1.1.1.1"})
			return process.CommandResult{ExitCode: 0, Stdout: data}
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsDNSCommandsAndNormalization(t *testing.T) {
	runner := &dnsRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getDNSServersFunc{}.Execute(context.Background(), rt, &getDNSServersArgs{Interface: `Local\\Area\\Connection`})
	if err != nil {
		t.Fatal(err)
	}
	servers := res.([]string)
	if len(servers) != 2 || servers[0] != "8.8.8.8" {
		t.Fatalf("servers = %v", servers)
	}
	res, err = addDNSFunc{}.Execute(context.Background(), rt, &addDNSArgs{IP: "8.8.8.8", Interface: "Ethernet", Index: piDNS(1)})
	if err != nil || res != true {
		t.Fatalf("idempotent add = %v %v", res, err)
	}
	res, err = rmDNSFunc{}.Execute(context.Background(), rt, &rmDNSArgs{IP: "8.8.8.8", Interface: "Ethernet"})
	if err != nil || res != true {
		t.Fatalf("remove = %v %v", res, err)
	}
	res, err = dnsDHCPFunc{}.Execute(context.Background(), rt, &dnsDHCPArgs{Interface: "Ethernet"})
	if err != nil || res != true {
		t.Fatalf("dhcp = %v %v", res, err)
	}
	if len(runner.calls) < 4 || !strings.Contains(strings.Join(runner.calls[len(runner.calls)-1].Args, " "), "source=dhcp") {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func piDNS(value int) *int { return &value }

func TestWindowsDNSConfigAndPlatform(t *testing.T) {
	rt := &runtime.Runtime{Runner: &dnsRunner{mode: "config"}, FS: runtime.NewMemoryFS()}
	res, err := getDNSConfigFunc{}.Execute(context.Background(), rt, &getDNSConfigArgs{Interface: "Ethernet"})
	if err != nil || res != true {
		t.Fatalf("config = %v %v", res, err)
	}
	platforms := (getDNSServersFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
