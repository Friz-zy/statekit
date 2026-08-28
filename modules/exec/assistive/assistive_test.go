package assistive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type assistiveRunner struct {
	installed map[string]bool
	enabled   map[string]bool
	readonly  int
	calls     []process.Command
}

func (r *assistiveRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	query := strings.Join(command.Args, " ")
	if strings.Contains(query, "SELECT 1 AS present") {
		app := sqlTestApp(query)
		if r.installed[app] {
			return jsonResult([]map[string]any{{"present": float64(1)}})
		}
		return jsonResult([]map[string]any{})
	}
	if strings.Contains(query, "AS enabled") {
		app := sqlTestApp(query)
		if r.enabled[app] {
			return jsonResult([]map[string]any{{"enabled": float64(1)}})
		}
		return jsonResult([]map[string]any{{"enabled": float64(0)}})
	}
	if r.readonly > 0 && (strings.Contains(query, "INSERT OR REPLACE") ||
		strings.Contains(query, "UPDATE access") || strings.Contains(query, "DELETE FROM access")) {
		r.readonly--
		return process.CommandResult{ExitCode: 1, Stderr: []byte("attempt to write a readonly database")}
	}
	if strings.Contains(query, "INSERT OR REPLACE") {
		app := sqlInsertApp(query)
		r.installed[app] = true
		if strings.Contains(query, ",1,4,") || strings.Contains(query, ",1,4,1,") {
			r.enabled[app] = true
		}
		return process.CommandResult{ExitCode: 0}
	}
	if strings.Contains(query, "UPDATE access SET") {
		app := sqlTestApp(query)
		r.enabled[app] = strings.Contains(query, "=1")
		return process.CommandResult{ExitCode: 0}
	}
	if strings.Contains(query, "DELETE FROM access") {
		app := sqlTestApp(query)
		delete(r.installed, app)
		delete(r.enabled, app)
		return process.CommandResult{ExitCode: 0}
	}
	return process.CommandResult{ExitCode: 0}
}

func jsonResult(rows []map[string]any) process.CommandResult {
	data, _ := json.Marshal(rows)
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func sqlTestApp(query string) string {
	start := strings.Index(query, "client='")
	if start < 0 {
		return ""
	}
	start += len("client='")
	end := strings.Index(query[start:], "'")
	if end < 0 {
		return ""
	}
	return strings.ReplaceAll(query[start:start+end], "''", "'")
}

func sqlInsertApp(query string) string {
	needle := "kTCCServiceAccessibility','"
	start := strings.Index(query, needle)
	if start < 0 {
		return ""
	}
	start += len(needle)
	end := strings.Index(query[start:], "'")
	return query[start : start+end]
}

func assistiveRuntime(t *testing.T, schema schemaKind) (*runtime.Runtime, *assistiveRunner) {
	t.Helper()
	runner := &assistiveRunner{
		installed: map[string]bool{},
		enabled:   map[string]bool{},
	}
	oldDetector := schemaDetector
	schemaDetector = func(context.Context, *runtime.Runtime) (schemaKind, error) { return schema, nil }
	oldSleep := assistiveSleep
	assistiveSleep = func(time.Duration) {}
	t.Cleanup(func() {
		schemaDetector = oldDetector
		assistiveSleep = oldSleep
	})
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func TestAssistiveLifecycleAcrossSchemas(t *testing.T) {
	for _, schema := range []schemaKind{schemaMojaveCatalina, schemaBigSur, schemaSonoma} {
		t.Run(string(schema), func(t *testing.T) {
			rt, runner := assistiveRuntime(t, schema)
			app := "com.example.app"
			res, err := installedFunc{}.Execute(context.Background(), rt, &installedArgs{AppID: app})
			if err != nil || res != false {
				t.Fatalf("initial installed = %v %v", res, err)
			}
			res, err = installFunc{}.Execute(context.Background(), rt, &installArgs{AppID: app, Enable: pbAssistive(false)})
			if err != nil || res != true {
				t.Fatalf("install = %v %v", res, err)
			}
			res, err = installedFunc{}.Execute(context.Background(), rt, &installedArgs{AppID: app})
			if err != nil || res != true {
				t.Fatalf("installed = %v %v", res, err)
			}
			res, err = enabledFunc{}.Execute(context.Background(), rt, &enabledArgs{AppID: app})
			if err != nil || res != false {
				t.Fatalf("disabled = %v %v", res, err)
			}
			res, err = enableFunc{}.Execute(context.Background(), rt, &enableArgs{AppID: app})
			if err != nil || res != true {
				t.Fatalf("enable = %v %v", res, err)
			}
			res, err = enabledFunc{}.Execute(context.Background(), rt, &enabledArgs{AppID: app})
			if err != nil || res != true {
				t.Fatalf("enabled = %v %v", res, err)
			}
			res, err = removeFunc{}.Execute(context.Background(), rt, &removeArgs{AppID: app})
			if err != nil || res != true {
				t.Fatalf("remove = %v %v", res, err)
			}
			if len(runner.calls) < 7 {
				t.Fatalf("calls = %+v", runner.calls)
			}
		})
	}
}

func pbAssistive(value bool) *bool { return &value }

func TestAssistiveReadonlyRetryAndErrors(t *testing.T) {
	rt, runner := assistiveRuntime(t, schemaBigSur)
	runner.readonly = 1
	res, err := installFunc{}.Execute(context.Background(), rt, &installArgs{
		AppID: "com.example.retry", Tries: piAssistive(2), Wait: piAssistive(0),
	})
	if err != nil || res != true {
		t.Fatalf("readonly retry = %v %v", res, err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("retry calls = %d", len(runner.calls))
	}

	oldDetector := schemaDetector
	schemaDetector = func(context.Context, *runtime.Runtime) (schemaKind, error) {
		return "", fmt.Errorf("unknown TCC schema")
	}
	_, err = installedFunc{}.Execute(context.Background(), rt, &installedArgs{AppID: "broken"})
	if err == nil || !strings.Contains(err.Error(), "unknown TCC schema") {
		t.Fatalf("schema error = %v", err)
	}
	schemaDetector = oldDetector
}

func piAssistive(value int) *int { return &value }

func TestInstallQueriesAndPlatform(t *testing.T) {
	for _, schema := range []schemaKind{schemaMojaveCatalina, schemaBigSur, schemaSonoma} {
		query, err := installQuery(schema, "/usr/bin/osascript", true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(query, "kTCCServiceAccessibility") || !strings.Contains(query, "usr/bin/osascript") {
			t.Fatalf("%s query = %s", schema, query)
		}
	}
	if kind, err := clientType("/usr/bin/osascript"); err != nil || kind != 1 {
		t.Fatalf("command client type = %d %v", kind, err)
	}
	if kind, err := clientType("com.example.app"); err != nil || kind != 0 {
		t.Fatalf("bundle client type = %d %v", kind, err)
	}
	platforms := (installFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
