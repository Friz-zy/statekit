// Package keychain implements Salt's Darwin keychain execution surface.
// Native security/openssl pipelines run through Runtime.Runner; password
// arguments are marked for Runner redaction so the local port does not leak
// credentials into command logs.
package keychain

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultKeychain = "/Library/Keychains/System.keychain"

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func runArgv(ctx context.Context, rt *runtime.Runtime, secrets []string, argv ...string) string {
	result := rt.Runner.Run(ctx, process.Command{
		Name: argv[0], Args: argv[1:], Redact: secrets,
	})
	return string(result.Stdout)
}

func runShell(ctx context.Context, rt *runtime.Runtime, secrets []string, script string) string {
	result := rt.Runner.Run(ctx, process.Command{Name: script, Shell: true, Redact: secrets})
	return string(result.Stdout)
}

func rejectRunas(user *string) error {
	if user != nil && *user != "" {
		return fmt.Errorf("runas is not supported by statekit")
	}
	return nil
}

// ---------------------------------------------------------------------------
// install/uninstall/list

type installArgs struct {
	Cert             string  `statekit:"required,name=cert"`
	Password         string  `statekit:"required,name=password"`
	Keychain         *string `statekit:"name=keychain"`
	AllowAny         bool    `statekit:"name=allow_any"`
	KeychainPassword *string `statekit:"name=keychain_password"`
}
type installFunc struct{}

func (installFunc) Name() string        { return "keychain.install" }
func (installFunc) Args() any           { return installArgs{} }
func (installFunc) Platforms() []string { return []string{"darwin"} }
func (installFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*installArgs)
	keychain := defaultKeychain
	if a.Keychain != nil && *a.Keychain != "" {
		keychain = *a.Keychain
	}
	if a.KeychainPassword != nil {
		if _, err := unlockImpl(ctx, rt, keychain, *a.KeychainPassword); err != nil {
			return nil, err
		}
	}
	argv := []string{"security", "import", a.Cert, "-P", a.Password, "-k", keychain}
	if a.AllowAny {
		argv = append(argv, "-A")
	}
	return runArgv(ctx, rt, []string{a.Password}, argv...), nil
}

type uninstallArgs struct {
	CertName         string  `statekit:"required,name=cert_name"`
	Keychain         *string `statekit:"name=keychain"`
	KeychainPassword *string `statekit:"name=keychain_password"`
}
type uninstallFunc struct{}

func (uninstallFunc) Name() string        { return "keychain.uninstall" }
func (uninstallFunc) Args() any           { return uninstallArgs{} }
func (uninstallFunc) Platforms() []string { return []string{"darwin"} }
func (uninstallFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*uninstallArgs)
	keychain := defaultKeychain
	if a.Keychain != nil && *a.Keychain != "" {
		keychain = *a.Keychain
	}
	if a.KeychainPassword != nil {
		if _, err := unlockImpl(ctx, rt, keychain, *a.KeychainPassword); err != nil {
			return nil, err
		}
	}
	return runArgv(ctx, rt, nil, "security", "delete-certificate", "-c", a.CertName, keychain), nil
}

type listCertsArgs struct {
	Keychain *string `statekit:"name=keychain"`
}
type listCertsFunc struct{}

func (listCertsFunc) Name() string        { return "keychain.list_certs" }
func (listCertsFunc) Args() any           { return listCertsArgs{} }
func (listCertsFunc) Platforms() []string { return []string{"darwin"} }
func (listCertsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*listCertsArgs)
	keychain := defaultKeychain
	if a.Keychain != nil && *a.Keychain != "" {
		keychain = *a.Keychain
	}
	script := "security find-certificate -a " + shellQuote(keychain) +
		` | grep -o "alis.*" | grep -o '\"[-A-Za-z0-9.:() ]*\"'`
	out := runShell(ctx, rt, nil, script)
	out = strings.ReplaceAll(out, `"`, "")
	return strings.Split(out, "\n"), nil
}

// ---------------------------------------------------------------------------
// friendly name/default keychain

type friendlyNameArgs struct {
	Cert     string `statekit:"required,name=cert"`
	Password string `statekit:"required,name=password"`
	Legacy   bool   `statekit:"name=legacy"`
}
type friendlyNameFunc struct{}

func (friendlyNameFunc) Name() string        { return "keychain.get_friendly_name" }
func (friendlyNameFunc) Args() any           { return friendlyNameArgs{} }
func (friendlyNameFunc) Platforms() []string { return []string{"darwin"} }
func (friendlyNameFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*friendlyNameArgs)
	openssl := "openssl pkcs12"
	if a.Legacy {
		openssl += " -legacy"
	}
	script := openssl + " -in " + shellQuote(a.Cert) + " -passin pass:" +
		shellQuote(a.Password) + " -info -nodes -nokeys 2> /dev/null | grep friendlyName:"
	out := runShell(ctx, rt, []string{a.Password}, script)
	return strings.TrimSpace(strings.TrimPrefix(out, "friendlyName: ")), nil
}

type defaultKeychainArgs struct {
	User   *string `statekit:"name=user"`
	Domain *string `statekit:"name=domain"`
}
type defaultKeychainFunc struct{}

func (defaultKeychainFunc) Name() string        { return "keychain.get_default_keychain" }
func (defaultKeychainFunc) Args() any           { return defaultKeychainArgs{} }
func (defaultKeychainFunc) Platforms() []string { return []string{"darwin"} }
func (defaultKeychainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*defaultKeychainArgs)
	if err := rejectRunas(a.User); err != nil {
		return nil, err
	}
	domain := "user"
	if a.Domain != nil && *a.Domain != "" {
		domain = *a.Domain
	}
	return runArgv(ctx, rt, nil, "security", "default-keychain", "-d", domain), nil
}

type setDefaultKeychainArgs struct {
	Keychain string  `statekit:"required,name=keychain"`
	Domain   *string `statekit:"name=domain"`
	User     *string `statekit:"name=user"`
}
type setDefaultKeychainFunc struct{}

func (setDefaultKeychainFunc) Name() string        { return "keychain.set_default_keychain" }
func (setDefaultKeychainFunc) Args() any           { return setDefaultKeychainArgs{} }
func (setDefaultKeychainFunc) Platforms() []string { return []string{"darwin"} }
func (setDefaultKeychainFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*setDefaultKeychainArgs)
	if err := rejectRunas(a.User); err != nil {
		return nil, err
	}
	domain := "user"
	if a.Domain != nil && *a.Domain != "" {
		domain = *a.Domain
	}
	return runArgv(ctx, rt, nil, "security", "default-keychain", "-d", domain, "-s", a.Keychain), nil
}

// ---------------------------------------------------------------------------
// unlock/get_hash

type unlockArgs struct {
	Keychain string `statekit:"required,name=keychain"`
	Password string `statekit:"required,name=password"`
}
type unlockFunc struct{}

func (unlockFunc) Name() string        { return "keychain.unlock_keychain" }
func (unlockFunc) Args() any           { return unlockArgs{} }
func (unlockFunc) Platforms() []string { return []string{"darwin"} }
func (unlockFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*unlockArgs)
	_, err = unlockImpl(ctx, rt, a.Keychain, a.Password)
	return nil, err
}

func unlockImpl(ctx context.Context, rt *runtime.Runtime, keychain, password string) (string, error) {
	return runArgv(ctx, rt, []string{password}, "security", "unlock-keychain", "-p", password, keychain), nil
}

type getHashArgs struct {
	Name     string  `statekit:"required,name=name"`
	Password *string `statekit:"name=password"`
}
type getHashFunc struct{}

func (getHashFunc) Name() string        { return "keychain.get_hash" }
func (getHashFunc) Args() any           { return getHashArgs{} }
func (getHashFunc) Platforms() []string { return []string{"darwin"} }
func (getHashFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverKeychain(&res, &err)
	a := args.(*getHashArgs)
	var out string
	var secrets []string
	if len(a.Name) >= 4 && strings.HasSuffix(a.Name[len(a.Name)-4:], ".p12") {
		password := ""
		if a.Password != nil {
			password = *a.Password
			secrets = []string{password}
		}
		script := "openssl pkcs12 -in " + shellQuote(a.Name) + " -passin pass:" +
			shellQuote(password) + " -passout pass:" + shellQuote(password)
		out = runShell(ctx, rt, secrets, script)
	} else {
		script := "security find-certificate -c " + shellQuote(a.Name) + " -m -p"
		out = runShell(ctx, rt, nil, script)
	}
	matches := regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----`).FindStringSubmatch(out)
	if len(matches) == 2 {
		return matches[1], nil
	}
	return false, nil
}

func recoverKeychain(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs Darwin keychain functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		installFunc{}, uninstallFunc{}, listCertsFunc{}, friendlyNameFunc{},
		defaultKeychainFunc{}, setDefaultKeychainFunc{}, unlockFunc{}, getHashFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
