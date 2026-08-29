//go:build windows

package service

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type windowsServiceRunner struct{ calls [][]string }

func (r *windowsServiceRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, append([]string{command.Name}, command.Args...))
	if len(command.Args) >= 1 && command.Args[0] == "query" && len(command.Args) >= 2 && command.Args[1] == "type=" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("SERVICE_NAME: Demo\nSERVICE_NAME: Other\n")}
	}
	if len(command.Args) >= 1 && command.Args[0] == "queryex" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("SERVICE_NAME: Demo\n        STATE              : 4  RUNNING\n        WIN32_EXIT_CODE    : 0  (0x0)\n        WAIT_HINT           : 0\n        CHECKPOINT          : 0\n")}
	}
	if len(command.Args) >= 1 && command.Args[0] == "qc" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("SERVICE_NAME: Demo\n        START_TYPE         : 2   AUTO_START\n        ERROR_CONTROL      : 1   NORMAL\n        BINARY_PATH_NAME    : C:\\Demo\\demo.exe\n        DISPLAY_NAME        : Demo Service\n        DEPENDENCIES        : Tcpip\n        SERVICE_START_NAME  : LocalSystem\n")}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsServiceParsers(t *testing.T) {
	if parseState("4 RUNNING") != "Running" || parseState("1 STOPPED") != "Stopped" {
		t.Fatal("state parser")
	}
	if parseStartType("2 AUTO_START") != "Auto" || parseStartType("3 DEMAND_START") != "Manual" || parseStartType("4 DISABLED") != "Disabled" {
		t.Fatal("start parser")
	}
	if got := cmdQuote(`'C:\Program Files\demo.exe'`); got != `"C:\Program Files\demo.exe"` {
		t.Fatalf("quote = %q", got)
	}
	if got := splitDependencies("Tcpip  RpcSs"); len(got) != 2 || got[1] != "RpcSs" {
		t.Fatalf("dependencies = %v", got)
	}
}

func TestWindowsServiceInfoStatusAndNames(t *testing.T) {
	runner := &windowsServiceRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	info, err := serviceInfo(context.Background(), rt, "Demo")
	if err != nil {
		t.Fatal(err)
	}
	if info["Status"] != "Running" || info["StartType"] != "Auto" || info["DisplayName"] != "Demo Service" {
		t.Fatalf("info = %#v", info)
	}
	res, err := winStatusFunc{}.Execute(context.Background(), rt, &winStatusArgs{Name: "Demo"})
	if err != nil || res != true {
		t.Fatalf("status = %v %v", res, err)
	}
	res, err = winStatusFunc{}.Execute(context.Background(), rt, &winStatusArgs{Name: "D*"})
	if err != nil || res.(map[string]any)["Demo"] != true {
		t.Fatalf("glob status = %v %v", res, err)
	}
	res, err = winGetServiceNameFunc{}.Execute(context.Background(), rt, &winGetServiceNameArgs{})
	if err != nil || res.(map[string]string)["Demo Service"] != "Demo" {
		t.Fatalf("service names = %v %v", res, err)
	}
	if len(runner.calls) == 0 || !strings.Contains(strings.Join(runner.calls[0], " "), "sc.exe") {
		t.Fatalf("SCM calls = %v", runner.calls)
	}
}
