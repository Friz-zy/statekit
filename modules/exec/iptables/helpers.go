package iptables

import (
	"context"
	"net"
	"os"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func osGetenv(key string) string { return os.Getenv(key) }

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// primaryMAC returns the first non-loopback hardware address as hex text.
func primaryMAC() (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		out := ""
		for i, b := range iface.HardwareAddr {
			if i > 0 {
				out += ":"
			}
			const hexdigits = "0123456789abcdef"
			out += string([]byte{hexdigits[b>>4], hexdigits[b&0xf]})
		}
		return out, true
	}
	return "", false
}

// probeCommand builds the shell command used by existence probes.
func probeCommand(cmd string) process.Command {
	return process.Command{Name: cmd, Shell: true}
}

func ctx0() context.Context { return context.Background() }

// runIgnore mirrors __salt__["cmd.run"] calls whose failures upstream
// swallows implicitly (temporary chain setup/teardown).
func runIgnore(ctx context.Context, rt *runtime.Runtime, cmd string) {
	rt.Runner.Run(ctx, process.Command{Name: cmd, Shell: true})
}
