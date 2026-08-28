package keychain

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type keychainRunner struct {
	calls []process.Command
}

func (r *keychainRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if strings.Contains(command.Name, "friendlyName") {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("friendlyName: Demo\n")}
	}
	if strings.Contains(command.Name, "find-certificate -c") {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("-----BEGIN CERTIFICATE-----\nBODY\n-----END CERTIFICATE-----")}
	}
	if strings.Contains(command.Name, "find-certificate -a") {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("alis \"Demo\"\nalis \"Other\"\n")}
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte("ok\n")}
}

func keychainRuntime(t *testing.T) (*runtime.Runtime, *keychainRunner) {
	t.Helper()
	runner := &keychainRunner{}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func TestKeychainCommandsAndParsing(t *testing.T) {
	rt, runner := keychainRuntime(t)
	keychain := "/tmp/login.keychain"
	pass := "secret"
	res, err := installFunc{}.Execute(context.Background(), rt, &installArgs{
		Cert: "cert.p12", Password: pass, Keychain: &keychain,
		AllowAny: true, KeychainPassword: &pass,
	})
	if err != nil || res != "ok\n" {
		t.Fatalf("install = %q %v", res, err)
	}
	if len(runner.calls) != 2 || len(runner.calls[0].Redact) != 1 || runner.calls[0].Redact[0] != pass {
		t.Fatalf("install calls = %+v", runner.calls)
	}
	res, err = listCertsFunc{}.Execute(context.Background(), rt, &listCertsArgs{Keychain: &keychain})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.([]string); len(got) != 3 || got[0] != "alis Demo" {
		// The shell pipeline's output is deliberately returned after quote
		// stripping, including its trailing empty split item.
		t.Fatalf("cert list = %#v", res)
	}
	res, err = friendlyNameFunc{}.Execute(context.Background(), rt, &friendlyNameArgs{Cert: "cert.p12", Password: pass})
	if err != nil || res != "Demo" {
		t.Fatalf("friendly = %q %v", res, err)
	}
	res, err = getHashFunc{}.Execute(context.Background(), rt, &getHashArgs{Name: "Demo"})
	if err != nil || res != "\nBODY\n" {
		t.Fatalf("hash = %q %v", res, err)
	}
}

func TestKeychainDefaultUnlockAndBoundaries(t *testing.T) {
	rt, runner := keychainRuntime(t)
	res, err := defaultKeychainFunc{}.Execute(context.Background(), rt, &defaultKeychainArgs{})
	if err != nil || res != "ok\n" {
		t.Fatalf("default = %q %v", res, err)
	}
	res, err = setDefaultKeychainFunc{}.Execute(context.Background(), rt, &setDefaultKeychainArgs{Keychain: "/tmp/login.keychain"})
	if err != nil || res != "ok\n" {
		t.Fatalf("set default = %q %v", res, err)
	}
	res, err = unlockFunc{}.Execute(context.Background(), rt, &unlockArgs{Keychain: "/tmp/login.keychain", Password: "secret"})
	if err != nil || res != nil {
		t.Fatalf("unlock = %v %v", res, err)
	}
	user := "alice"
	_, err = defaultKeychainFunc{}.Execute(context.Background(), rt, &defaultKeychainArgs{User: &user})
	if err == nil || !strings.Contains(err.Error(), "runas is not supported") {
		t.Fatalf("runas = %v", err)
	}
	if len(runner.calls) < 3 {
		t.Fatalf("calls = %+v", runner.calls)
	}
	platforms := (listCertsFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
