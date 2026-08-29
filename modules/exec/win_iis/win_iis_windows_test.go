//go:build windows

package win_iis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type iisRunner struct{ calls []process.Command }

func (r *iisRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	data, _ := json.Marshal([]map[string]any{{
		"name": "Default Web Site", "id": float64(1), "state": "Started",
		"apppool": "DefaultAppPool", "sourcepath": "C:\\inetpub\\wwwroot",
		"bindings": []map[string]any{{"bindingInformation": "*:80:", "protocol": "http"}},
	}})
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsIISSiteAndBindingProjection(t *testing.T) {
	runner := &iisRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := listSitesFunc{}.Execute(context.Background(), rt, noArgs{})
	if err != nil {
		t.Fatal(err)
	}
	sites := res.(map[string]any)
	if sites["Default Web Site"] == nil {
		t.Fatalf("sites = %#v", sites)
	}
	res, err = listBindingsFunc{}.Execute(context.Background(), rt, &bindingArgs{Site: "Default Web Site"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.(map[string]any)) != 1 {
		t.Fatalf("bindings = %#v", res)
	}
	res, err = createSiteFunc{}.Execute(context.Background(), rt, &siteArgs{Name: "Default Web Site", SourcePath: "C:\\inetpub\\wwwroot"})
	if err != nil || res != true {
		t.Fatalf("idempotent site = %v %v", res, err)
	}
	_, err = createSiteFunc{}.Execute(context.Background(), rt, &siteArgs{Name: "bad", SourcePath: "C:\\tmp", Protocol: stringPtrIIS("smtp")})
	if err == nil || !strings.Contains(err.Error(), "Invalid protocol") {
		t.Fatalf("bad protocol = %v", err)
	}
}

func TestWindowsIISBoundaryAndEncoding(t *testing.T) {
	runner := &iisRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	if got := iisLiteral("O'Reilly"); got != "'O''Reilly'" {
		t.Fatalf("literal = %q", got)
	}
	_, err := getWebConfigurationSettingsFunc{}.Execute(context.Background(), rt, &settingsArgs{Name: "x", Container: "y"})
	if err == nil || !strings.Contains(err.Error(), "explicit filter mapping") {
		t.Fatalf("settings boundary = %v", err)
	}
	platforms := (listSitesFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}
