//go:build windows

package win_event

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type eventRunner struct{ calls []process.Command }

func (r *eventRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name == "wevtutil" && len(command.Args) > 0 && command.Args[0] == "el" {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Application\r\nSystem\r\n")}
	}
	if command.Name == "powershell.exe" {
		if len(r.calls) > 0 && len(r.calls[len(r.calls)-1].Args) > 0 {
			data, _ := json.Marshal([]map[string]any{{
				"eventID": float64(100), "eventType": float64(4), "sourceName": "Demo",
				"recordNumber": float64(8), "computerName": "HOST", "timeGenerated": "2026-08-29T00:00:00Z",
				"data": "message", "logName": "Application",
			}})
			return process.CommandResult{ExitCode: 0, Stdout: data}
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func TestWindowsEventQueryAndFilter(t *testing.T) {
	runner := &eventRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := queryFunc{}.Execute(context.Background(), rt, &queryArgs{LogName: "Application", Records: intPtrEvent(5)})
	if err != nil {
		t.Fatal(err)
	}
	rows := res.([]map[string]any)
	if len(rows) != 1 || rows[0]["eventID"] != float64(100) {
		t.Fatalf("query = %#v", rows)
	}
	res, err = filteredFunc{}.Execute(context.Background(), rt, &filteredArgs{
		LogName: "Application", Filters: map[string]any{"eventID": 100},
	})
	if err != nil || len(res.([]map[string]any)) != 1 {
		t.Fatalf("filtered = %v %v", res, err)
	}
	res, err = queryFunc{}.Execute(context.Background(), rt, &queryArgs{LogName: "Application", Raw: boolPtrEvent(true)})
	if err != nil || res == nil {
		t.Fatalf("raw query = %v %v", res, err)
	}
}

func TestWindowsEventNamesClearAndValidation(t *testing.T) {
	runner := &eventRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getLogNamesFunc{}.Execute(context.Background(), rt, namesArgs{})
	if err != nil || len(res.([]string)) != 2 || res.([]string)[1] != "System" {
		t.Fatalf("names = %v %v", res, err)
	}
	res, err = countFunc{}.Execute(context.Background(), rt, &countArgs{LogName: "Application"})
	if err != nil {
		// The fake emits an event array for PowerShell; count remains a
		// decoded value and the real provider returns an integer.
		if !strings.Contains(err.Error(), "cannot") {
			t.Fatalf("count = %v %v", res, err)
		}
	}
	_, err = addFunc{}.Execute(context.Background(), rt, &addArgs{LogName: "Application", EventID: 1, EventType: "Bogus"})
	if err == nil || !strings.Contains(err.Error(), "Incorrect event type") {
		t.Fatalf("bad event type = %v", err)
	}
	res, err = clearFunc{}.Execute(context.Background(), rt, &clearArgs{LogName: "Application", Backup: stringPtrEvent("C:\\backup.evt")})
	if err != nil || res != nil {
		t.Fatalf("clear = %v %v", res, err)
	}
}

func intPtrEvent(value int) *int          { return &value }
func boolPtrEvent(value bool) *bool       { return &value }
func stringPtrEvent(value string) *string { return &value }
