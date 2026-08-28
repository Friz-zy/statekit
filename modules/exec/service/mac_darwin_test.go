//go:build darwin

package service

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type darwinServiceRunner struct {
	calls []process.Command
}

func (r *darwinServiceRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "launchctl" || len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	switch command.Args[0] {
	case "list":
		if len(command.Args) > 1 {
			return process.CommandResult{ExitCode: 0, Stdout: []byte(`"PID" = 123\n`)}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte("PID\tStatus\tLabel\n123\t0\tcom.example.demo\n")}
	case "print-disabled":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("disabled services = {\n\t\"com.example.demo\" => true\n}\n")}
	case "print":
		return process.CommandResult{ExitCode: 0}
	default:
		return process.CommandResult{ExitCode: 0}
	}
}

func darwinServiceRuntime(t *testing.T) (*runtime.Runtime, *darwinServiceRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/Library/LaunchDaemons", 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.example.demo</string><key>KeepAlive</key><true/><key>ProgramArguments</key><array><string>/usr/bin/demo</string></array></dict></plist>`
	if err := fs.WriteFile("/Library/LaunchDaemons/com.example.demo.plist", []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &darwinServiceRunner{}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func TestDarwinServiceDiscoveryAndLifecycle(t *testing.T) {
	rt, runner := darwinServiceRuntime(t)
	res, err := macShowFunc{}.Execute(context.Background(), rt, &macShowArgs{Name: "com.example.demo"})
	if err != nil {
		t.Fatal(err)
	}
	service := res.(map[string]any)
	if service["file_path"] != "/Library/LaunchDaemons/com.example.demo.plist" {
		t.Fatalf("service = %#v", service)
	}
	res, err = macAvailableFunc{}.Execute(context.Background(), rt, &macAvailableArgs{Name: "com.example.demo.plist"})
	if err != nil || res != true {
		t.Fatalf("available = %v %v", res, err)
	}
	res, err = macListFunc{}.Execute(context.Background(), rt, &macListArgs{Name: stringPtr("com.example.demo")})
	if err != nil || res != `"PID" = 123\n` {
		t.Fatalf("list = %q %v", res, err)
	}
	res, err = macStatusFunc{}.Execute(context.Background(), rt, &macStatusArgs{Name: "com.example.demo"})
	if err != nil || res != true {
		t.Fatalf("status = %v %v", res, err)
	}
	res, err = macDisabledFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.demo"})
	if err != nil || res != true {
		t.Fatalf("disabled = %v %v", res, err)
	}
	res, err = macEnabledFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.demo"})
	if err != nil || res != false {
		t.Fatalf("enabled = %v %v", res, err)
	}
	for _, fn := range []runtime.ExecFunction{macEnableFunc{}, macDisableFunc{}, macStartFunc{}, macStopFunc{}, macRestartFunc{}} {
		value, err := fn.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.demo"})
		if err != nil || value != true {
			t.Fatalf("%s = %v %v", fn.Name(), value, err)
		}
	}
	res, err = macGetEnabledFunc{}.Execute(context.Background(), rt, &macGetEnabledArgs{})
	if err != nil || !strings.Contains(strings.Join(res.([]string), ","), "com.example.demo") {
		t.Fatalf("get enabled = %v %v", res, err)
	}
	res, err = macGetAllFunc{}.Execute(context.Background(), rt, &macGetAllArgs{})
	if err != nil || !strings.Contains(strings.Join(res.([]string), ","), "com.example.demo") {
		t.Fatalf("get all = %v %v", res, err)
	}
	res, err = macLoadedFunc{}.Execute(context.Background(), rt, &macNameRunasArgs{Name: "com.example.demo"})
	if err != nil || res != true {
		t.Fatalf("loaded = %v %v", res, err)
	}
	if len(runner.calls) == 0 {
		t.Fatal("launchctl was not called")
	}
}

func TestDarwinServiceErrorsAndAlias(t *testing.T) {
	rt, _ := darwinServiceRuntime(t)
	res, err := macMissingFunc{}.Execute(context.Background(), rt, &macAvailableArgs{Name: "missing"})
	if err != nil || res != true {
		t.Fatalf("missing = %v %v", res, err)
	}
	_, err = macShowFunc{}.Execute(context.Background(), rt, &macShowArgs{Name: "missing"})
	if err == nil || !strings.Contains(err.Error(), "Service not found: missing") {
		t.Fatalf("missing show = %v", err)
	}
	user := "alice"
	_, err = macLaunchctlFunc{}.Execute(context.Background(), rt, &macLaunchctlArgs{SubCmd: "list", Runas: &user})
	if err == nil || !strings.Contains(err.Error(), "runas is not supported") {
		t.Fatalf("runas = %v", err)
	}
	// Salt service aliases normalize to their macOS label.
	if mapped := saltMacServices["salt-minion"]; mapped != "com.saltstack.salt.minion" {
		t.Fatalf("salt alias = %q", mapped)
	}
}

func stringPtr(value string) *string { return &value }
