//go:build windows

package win_smtp_server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type smtpRunner struct{ calls []process.Command }

func (r *smtpRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	var value any = []map[string]any{{
		"Name": "SmtpSvc/1", "LogPluginClsid": "{log-id}",
		"IPGrant":     []string{"127.0.0.1, 255.255.255.255"},
		"RelayIpList": []string{"127", "0", "0", "1"},
		"LogModuleId": "{log-id}",
	}}
	if len(r.calls) == 2 {
		value = []string{"127.0.0.1, 255.255.255.255"}
	}
	if len(r.calls) == 3 {
		value = []string{"127", "0", "0", "1"}
	}
	data, _ := json.Marshal(value)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsSMTPConversions(t *testing.T) {
	if got := normalizeSMTP(map[string]any{"MaxRecipients": "500"}); got != "{MaxRecipients}" {
		t.Fatalf("normalized dict = %v", got)
	}
	if got := smtpValue([]string{"127.0.0.1", "255.255.255.255"}); !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("array value = %q", got)
	}
	if got := smtpStringList([]any{"127", "0"}); len(got) != 2 || got[1] != "0" {
		t.Fatalf("string list = %v", got)
	}
	if smtpServer(nil) != defaultSMTPServer {
		t.Fatal("default server")
	}
}

func TestWindowsSMTPJSONAndSettings(t *testing.T) {
	runner := &smtpRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getServersFunc{}.Execute(context.Background(), rt, noArgs{})
	if err != nil || len(res.([]string)) != 1 || res.([]string)[0] != "SmtpSvc/1" {
		t.Fatalf("servers = %v %v", res, err)
	}
	res, err = getConnectionIPListFunc{}.Execute(context.Background(), rt, &connectionArgs{AsWMIFormat: boolPtrSMTP(true)})
	if err != nil || len(res.([]string)) != 1 || res.([]string)[0] != "127.0.0.1, 255.255.255.255" {
		t.Fatalf("IP grant = %v %v", res, err)
	}
	res, err = getRelayIPListFunc{}.Execute(context.Background(), rt, &serverArg{})
	if err != nil || res.([]string)[0] != "127.0.0.1" {
		t.Fatalf("relay = %v %v", res, err)
	}
	_, err = setLogFormatFunc{}.Execute(context.Background(), rt, &setLogFormatArgs{LogFormat: "missing"})
	if err == nil || !strings.Contains(err.Error(), "Invalid log format") {
		t.Fatalf("bad log format = %v", err)
	}
}

func boolPtrSMTP(value bool) *bool { return &value }
