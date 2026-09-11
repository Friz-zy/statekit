package keychain

// R6.10 mock tests for the Darwin keychain surface, mapped onto
// saltstack/salt/modules/mac_keychain.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_keychain.py: exact security/
// openssl argv (the pytests pin the full command strings), default
// keychain handling, the -A/legacy flags, password redaction markers,
// Shell=false vs Shell=true command routing, get_hash certificate
// parsing and the registry matrix. All Runner output is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type keychainScriptRunner struct {
	script []process.CommandResult
	calls  []process.Command
}

func (r *keychainScriptRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.script) == 0 {
		return process.CommandResult{ExitCode: 0, Stdout: []byte("ok\n")}
	}
	next := r.script[0]
	r.script = r.script[1:]
	return next
}

func keychainRT(script ...process.CommandResult) (*runtime.Runtime, *keychainScriptRunner) {
	runner := &keychainScriptRunner{script: script}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func keyArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func strKeyPtr(value string) *string { return &value }

func TestInstallDefaultKeychainArgv(t *testing.T) {
	// pytest test_install_cert pins: security import <cert> -P <pw> -k
	// /Library/Keychains/System.keychain
	rt, runner := keychainRT()
	_, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{Cert: "/path/to/cert.p12", Password: "passw0rd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	if got := keyArgv(runner.calls[0]); got != "security import /path/to/cert.p12 -P passw0rd -k /Library/Keychains/System.keychain" {
		t.Fatalf("install argv = %q", got)
	}
	if runner.calls[0].Shell {
		t.Fatal("install must be a shell-free argv command")
	}
	if len(runner.calls[0].Redact) != 1 || runner.calls[0].Redact[0] != "passw0rd" {
		t.Fatalf("install redact = %v", runner.calls[0].Redact)
	}
}

func TestInstallExtrasUnlockAndAllowAny(t *testing.T) {
	// pytest test_install_cert_extras: unlock("/path/to/chain",
	// "passw0rd1") fires first, then security import ... -k ... -A.
	rt, runner := keychainRT()
	chain := "/path/to/chain"
	kpass := "passw0rd1"
	_, err := (installFunc{}).Execute(context.Background(), rt, &installArgs{
		Cert: "/path/to/cert.p12", Password: "passw0rd", Keychain: &chain,
		AllowAny: true, KeychainPassword: &kpass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	if got := keyArgv(runner.calls[0]); got != "security unlock-keychain -p passw0rd1 /path/to/chain" {
		t.Fatalf("unlock argv = %q", got)
	}
	if len(runner.calls[0].Redact) != 1 || runner.calls[0].Redact[0] != kpass {
		t.Fatalf("unlock redact = %v", runner.calls[0].Redact)
	}
	if got := keyArgv(runner.calls[1]); got != "security import /path/to/cert.p12 -P passw0rd -k /path/to/chain -A" {
		t.Fatalf("import argv = %q", got)
	}
}

func TestUninstallArgvAndUnlock(t *testing.T) {
	rt, runner := keychainRT()
	chain := "/path/to/chain"
	kpass := "passw0rd1"
	_, err := (uninstallFunc{}).Execute(context.Background(), rt, &uninstallArgs{
		CertName: "Demo", Keychain: &chain, KeychainPassword: &kpass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	if got := keyArgv(runner.calls[0]); got != "security unlock-keychain -p passw0rd1 /path/to/chain" {
		t.Fatalf("unlock argv = %q", got)
	}
	if got := keyArgv(runner.calls[1]); got != "security delete-certificate -c Demo /path/to/chain" {
		t.Fatalf("uninstall argv = %q", got)
	}
	if len(runner.calls[1].Redact) != 0 {
		t.Fatalf("uninstall redact = %v", runner.calls[1].Redact)
	}
	// default keychain applies to uninstall as well
	rt2, runner2 := keychainRT()
	if _, err := (uninstallFunc{}).Execute(context.Background(), rt2, &uninstallArgs{CertName: "Demo"}); err != nil {
		t.Fatal(err)
	}
	if got := keyArgv(runner2.calls[0]); got != "security delete-certificate -c Demo /Library/Keychains/System.keychain" {
		t.Fatalf("default uninstall argv = %q", got)
	}
}

func TestListCertsScriptAndParsing(t *testing.T) {
	// pytest test_list_certs: the pipeline string is shell-quoted and the
	// quoted "alis" names come back quote-stripped.
	rt, runner := keychainRT(process.CommandResult{
		ExitCode: 0, Stdout: []byte("\"com.apple.systemdefault\"\n\"com.apple.kerberos.kdc\""),
	})
	res, err := (listCertsFunc{}).Execute(context.Background(), rt, &listCertsArgs{Keychain: strKeyPtr("/path/to/cert.p12")})
	if err != nil {
		t.Fatal(err)
	}
	got := res.([]string)
	if !reflect.DeepEqual(got[:2], []string{"com.apple.systemdefault", "com.apple.kerberos.kdc"}) {
		t.Fatalf("list = %#v", got)
	}
	command := runner.calls[0]
	if !command.Shell {
		t.Fatal("list_certs pipeline must opt into the shell")
	}
	want := `security find-certificate -a '/path/to/cert.p12' | grep -o "alis.*" | grep -o '\"[-A-Za-z0-9.:() ]*\"'`
	if command.Name != want {
		t.Fatalf("script = %q; want %q", command.Name, want)
	}
	// default keychain when the argument is omitted
	rt2, runner2 := keychainRT(process.CommandResult{ExitCode: 0})
	if _, err := (listCertsFunc{}).Execute(context.Background(), rt2, &listCertsArgs{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(runner2.calls[0].Name, "/Library/Keychains/System.keychain") {
		t.Fatalf("default script = %q", runner2.calls[0].Name)
	}
}

func TestGetFriendlyNameScripts(t *testing.T) {
	// pytest test_get_friendly_name pins both the legacy and modern
	// openssl command strings.
	cases := []struct {
		legacy bool
		want   string
	}{
		{true, `openssl pkcs12 -legacy -in '/path/to/cert.p12' -passin pass:'passw0rd' -info -nodes -nokeys 2> /dev/null | grep friendlyName:`},
		{false, `openssl pkcs12 -in '/path/to/cert.p12' -passin pass:'passw0rd' -info -nodes -nokeys 2> /dev/null | grep friendlyName:`},
	}
	for _, tc := range cases {
		rt, runner := keychainRT(process.CommandResult{
			ExitCode: 0, Stdout: []byte("friendlyName: ID Installer Salt"),
		})
		res, err := (friendlyNameFunc{}).Execute(context.Background(), rt, &friendlyNameArgs{
			Cert: "/path/to/cert.p12", Password: "passw0rd", Legacy: tc.legacy,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res != "ID Installer Salt" {
			t.Fatalf("friendly name = %v", res)
		}
		if !runner.calls[0].Shell {
			t.Fatal("friendly-name pipeline must opt into the shell")
		}
		if runner.calls[0].Name != tc.want {
			t.Fatalf("script = %q; want %q", runner.calls[0].Name, tc.want)
		}
		if len(runner.calls[0].Redact) != 1 || runner.calls[0].Redact[0] != "passw0rd" {
			t.Fatalf("redact = %v", runner.calls[0].Redact)
		}
	}
}

func TestDefaultKeychainDomainRouting(t *testing.T) {
	rt, runner := keychainRT()
	domain := "system"
	if _, err := (defaultKeychainFunc{}).Execute(context.Background(), rt, &defaultKeychainArgs{Domain: &domain}); err != nil {
		t.Fatal(err)
	}
	if got := keyArgv(runner.calls[0]); got != "security default-keychain -d system" {
		t.Fatalf("domain argv = %q", got)
	}
	if _, err := (defaultKeychainFunc{}).Execute(context.Background(), rt, &defaultKeychainArgs{}); err != nil {
		t.Fatal(err)
	}
	if got := keyArgv(runner.calls[1]); got != "security default-keychain -d user" {
		t.Fatalf("default domain argv = %q", got)
	}
	if _, err := (setDefaultKeychainFunc{}).Execute(context.Background(), rt, &setDefaultKeychainArgs{
		Keychain: "/path/to/chain.keychain", Domain: &domain,
	}); err != nil {
		t.Fatal(err)
	}
	if got := keyArgv(runner.calls[2]); got != "security default-keychain -d system -s /path/to/chain.keychain" {
		t.Fatalf("set default argv = %q", got)
	}
	for _, command := range runner.calls {
		if command.Shell {
			t.Fatal("default-keychain commands must stay shell-free")
		}
	}
}

func TestGetHashPkcs12Branch(t *testing.T) {
	rt, runner := keychainRT(process.CommandResult{
		ExitCode: 0,
		Stdout:   []byte("-----BEGIN CERTIFICATE-----\nCERTBODY\n-----END CERTIFICATE-----\n"),
	})
	password := "passw0rd"
	res, err := (getHashFunc{}).Execute(context.Background(), rt, &getHashArgs{Name: "cert.p12", Password: &password})
	if err != nil {
		t.Fatal(err)
	}
	if res != "\nCERTBODY\n" {
		t.Fatalf("p12 hash body = %q", res)
	}
	command := runner.calls[0]
	if !command.Shell {
		t.Fatal("p12 hash pipeline must opt into the shell")
	}
	want := `openssl pkcs12 -in 'cert.p12' -passin pass:'passw0rd' -passout pass:'passw0rd'`
	if command.Name != want {
		t.Fatalf("script = %q; want %q", command.Name, want)
	}
	if len(command.Redact) != 1 || command.Redact[0] != password {
		t.Fatalf("redact = %v", command.Redact)
	}
	// a missing certificate marker returns False like Salt's regex miss
	rt2, runner2 := keychainRT(process.CommandResult{ExitCode: 0, Stdout: []byte("garbage")})
	res, err = (getHashFunc{}).Execute(context.Background(), rt2, &getHashArgs{Name: "cert.p12"})
	if err != nil || res != false {
		t.Fatalf("no-marker hash = %v %v", res, err)
	}
	if !strings.Contains(runner2.calls[0].Name, "-passin pass:''") {
		t.Fatalf("passwordless script = %q", runner2.calls[0].Name)
	}
	if len(runner2.calls[0].Redact) != 0 {
		t.Fatalf("passwordless redact = %v", runner2.calls[0].Redact)
	}
}

func TestKeychainRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"keychain.get_default_keychain",
		"keychain.get_friendly_name",
		"keychain.get_hash",
		"keychain.install",
		"keychain.list_certs",
		"keychain.set_default_keychain",
		"keychain.uninstall",
		"keychain.unlock_keychain",
	}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, _ := keychainRT(process.CommandResult{ExitCode: 0, Stdout: []byte("/Users/a/library/Keychains/login.keychain")})
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "keychain.get_default_keychain", &defaultKeychainArgs{})
		if err != nil || res != "/Users/a/library/Keychains/login.keychain" {
			t.Fatalf("dispatch = %v %v", res, err)
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "keychain.get_default_keychain", &defaultKeychainArgs{}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
