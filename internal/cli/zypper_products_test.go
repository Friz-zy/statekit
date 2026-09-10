package cli

import (
	"encoding/json"
	"path"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperProductsCLIFS(t *testing.T, oemContent string) *cliLocksFS {
	t.Helper()
	memory := runtime.NewMemoryFS()
	if oemContent != "" {
		oemDir := "/target/var/lib/suseRegister/OEM"
		if err := memory.MkdirAll(oemDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := memory.WriteFile(path.Join(oemDir, "SLES"), []byte(oemContent), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &cliLocksFS{MemoryFS: memory}
}

func TestZypperListProductsCLIProviderAwareEndToEnd(t *testing.T) {
	fsys := zypperProductsCLIFS(t, "  OEM-15-SP4  \nignored\n")
	runner := &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><product-list><product name="SLES" version="15-SP4" release="0" isbase="true" installed="1" productline="SLES"><endoflife text="2028-07-31" time_t="1853904000"/><description>  SUSE Linux  ` + "\n" + ` Enterprise Server  </description></product></product-list></stream>`)},
	}}
	code, out, errS := captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_products", "--root", "/target", "-o", "json")
	var products []map[string]any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &products) != nil ||
		!reflect.DeepEqual(products, []map[string]any{{
			"name": "SLES", "version": "15-SP4", "release": "OEM-15-SP4",
			"isbase": true, "installed": true, "productline": "SLES",
			"eol": "2028-07-31", "eol_t": float64(1853904000), "description": "SUSE Linux Enterprise Server",
		}}) || len(runner.calls) != 1 || fsys.writes != 0 {
		t.Fatalf("code=%d out=%q err=%q products=%#v calls=%d writes=%d", code, out, errS, products, len(runner.calls), fsys.writes)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", "/target", "--disable-repositories", "products", "-i"}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, wantArgv) {
		t.Fatalf("argv=%v want=%v", got, wantArgv)
	}
	if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes == 0 || runner.calls[0].MaxStderrBytes == 0 {
		t.Fatalf("unsafe command=%#v", runner.calls[0])
	}

	// --all keeps the bare products query and skips the OEM file entirely.
	fsys = zypperProductsCLIFS(t, "")
	runner = &cliRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte(`<stream><product-list/></stream>`)},
	}}
	code, out, errS = captureCode(t, providerCLIAppWithFS(t, "zypper", runner, fsys), "exec", "pkg.list_products", "--all", "--refresh=false", "-o", "json")
	var empty []any
	if code != ExitOK || errS != "" || json.Unmarshal([]byte(out), &empty) != nil || len(empty) != 0 || len(runner.calls) != 1 {
		t.Fatalf("all code=%d out=%q err=%q empty=%#v calls=%d", code, out, errS, empty, len(runner.calls))
	}
	if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "products"}) {
		t.Fatalf("all argv=%v", got)
	}
}

func TestZypperListProductsCLIProviderBoundary(t *testing.T) {
	// APT and YUM keep the unsupported exit code without calling the Runner.
	for _, manager := range []string{"apt", "yum"} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.list_products")
		if code != ExitUnsupported || len(runner.calls) != 0 {
			t.Fatalf("manager=%s code=%d calls=%d", manager, code, len(runner.calls))
		}
	}

	// Unknown and mistyped flags are rejected before any zypper call.
	runner := &cliRecordingRunner{}
	code, _, _ := captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_products", "--repos", "repo")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("unknown flag code=%d calls=%d", code, len(runner.calls))
	}
	runner = &cliRecordingRunner{}
	code, _, _ = captureCode(t, providerCLIApp(t, "zypper", runner), "exec", "pkg.list_products", "--all=maybe")
	if code != ExitInvalidInput || len(runner.calls) != 0 {
		t.Fatalf("mistyped flag code=%d calls=%d", code, len(runner.calls))
	}
}
