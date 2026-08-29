//go:build windows

package win_pki

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type pkiRunner struct{ calls []process.Command }

func (r *pkiRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "powershell.exe" {
		return process.CommandResult{ExitCode: 0}
	}
	data, _ := json.Marshal([]map[string]any{{
		"LocationName": "LocalMachine", "StoreNames": []string{"My", "Root"},
	}})
	return process.CommandResult{ExitCode: 0, Stdout: data}
}

func TestWindowsPKIPowerShellEncodingAndStores(t *testing.T) {
	command := pkiPS("Get-ChildItem", []string{"secret"})
	if command.Name != "powershell.exe" || len(command.Args) != 4 || len(command.Redact) != 1 {
		t.Fatalf("PS command = %+v", command)
	}
	raw, err := base64.StdEncoding.DecodeString(command.Args[3])
	if err != nil || len(raw)%2 != 0 {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	if units[len(units)-1] != 0 || len(units) < 2 {
		t.Fatal("encoded command is not UTF-16LE terminated")
	}

	runner := &pkiRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getStoresFunc{}.Execute(context.Background(), rt, getStoresArgs{})
	if err != nil {
		t.Fatal(err)
	}
	stores := res.(map[string]any)
	if len(stores) != 1 {
		t.Fatalf("stores = %#v", stores)
	}
}

func TestWindowsPKIFormatAndPathGuards(t *testing.T) {
	if pkiFormat("cer") != nil || pkiFormat("pfx") != nil || pkiFormat("pem") == nil {
		t.Fatal("certificate format validation")
	}
	if certStorePathSafe("LocalMachine", "My") != `Cert:\LocalMachine\My` {
		t.Fatalf("store path = %q", certStorePathSafe("LocalMachine", "My"))
	}
	runner := &pkiRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := getCertFileFunc{}.Execute(context.Background(), rt, &getCertFileArgs{Name: "C:\\missing.cer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.(map[string]any)) != 0 {
		t.Fatalf("missing cert file = %#v", res)
	}
	_, err = getCertFileFunc{}.Execute(context.Background(), rt, &getCertFileArgs{Name: "x", CertFormat: stringPtrPKI("pem")})
	if err == nil || !strings.Contains(err.Error(), "Invalid certificate format") {
		t.Fatalf("bad format = %v", err)
	}
	platforms := (getStoresFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Fatalf("platforms = %v", platforms)
	}
}

func stringPtrPKI(value string) *string { return &value }
