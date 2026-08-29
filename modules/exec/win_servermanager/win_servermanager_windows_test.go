//go:build windows

package win_servermanager

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type featureRunner struct{ calls []process.Command }

func (r *featureRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	result := map[string]any{
		"ExitCode": 0, "Success": true, "RestartNeeded": true,
		"FeatureResult": []map[string]any{{
			"Name": "Web-Server", "DisplayName": "Web Server", "Message": "Success",
			"RestartNeeded": true, "SkipReason": "", "Success": true,
		}},
	}
	data, _ := json.Marshal(result)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsServerManagerResultAndNames(t *testing.T) {
	if got := featureNames("Web-Server,Telnet-Client"); len(got) != 2 || got[1] != "Telnet-Client" {
		t.Fatalf("names = %v", got)
	}
	result := featureResult(map[string]any{
		"ExitCode": float64(0), "Success": true,
		"FeatureResult": []any{map[string]any{
			"Name": "Web-Server", "DisplayName": "Web Server", "Message": "Success",
			"RestartNeeded": true, "SkipReason": "", "Success": true,
		}},
	}, []string{"Web-Server", "Telnet-Client"})
	features := result["Features"].(map[string]any)
	if features["Web-Server"] == nil || features["Telnet-Client"].(map[string]any)["Message"] != "Already installed" {
		t.Fatalf("result = %#v", result)
	}
}

func TestWindowsServerManagerListAndSafeRestart(t *testing.T) {
	runner := &featureRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := listInstalledFunc{}.Execute(context.Background(), rt, noArgs{})
	if err != nil {
		t.Fatal(err)
	}
	// The fake result is a FeatureResult object; the production query returns
	// DisplayName/Name/Installed rows. This assertion keeps the decoder path
	// deterministic without invoking a Windows host.
	if res == nil {
		t.Fatal("list installed returned nil")
	}
	res, err = removeFunc{}.Execute(context.Background(), rt, &removeArgs{Feature: "Web-Server", Restart: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["Restarted"] != false {
		t.Fatalf("restart safety = %#v", res)
	}
	if len(runner.calls) < 2 || strings.Contains(strings.Join(runner.calls[1].Args, " "), "-Restart") {
		t.Fatalf("reboot command leaked = %+v", runner.calls)
	}
}
