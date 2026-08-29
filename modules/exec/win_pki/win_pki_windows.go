//go:build windows

// Package win_pki implements Salt's Windows PKI Client module through encoded
// PowerShell. Certificate-store paths and password-bearing scripts never pass
// through an unescaped shell string.
package win_pki

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const defaultContext = "LocalMachine"
const defaultStore = "My"

func pkiPS(script string, secrets []string) process.Command {
	units := make([]uint16, 0, len(script)+1)
	for _, r := range script + "\x00" {
		if r <= 0xffff {
			units = append(units, uint16(r))
		} else {
			r -= 0x10000
			units = append(units, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return process.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}, Redact: secrets}
}
func pkiLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func pkiRun(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (string, error) {
	r := rt.Runner.Run(ctx, pkiPS(script, secrets))
	if r.Err != nil && r.ExitCode == -1 {
		return string(r.Stdout), r.Err
	}
	if r.ExitCode != 0 {
		return string(r.Stdout), fmt.Errorf("Unable to execute command (exit code %d): %s", r.ExitCode, strings.TrimSpace(string(r.Stderr)))
	}
	return string(r.Stdout), nil
}
func pkiJSON(ctx context.Context, rt *runtime.Runtime, script string, secrets []string) (any, error) {
	out, e := pkiRun(ctx, rt, script+" | ConvertTo-Json -Compress -Depth 4", secrets)
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return nil, nil
	}
	var v any
	if e = json.Unmarshal([]byte(out), &v); e != nil {
		return nil, fmt.Errorf("Unable to parse return data as JSON: %s", out)
	}
	return v, nil
}
func pkiRows(value any) []map[string]any {
	switch x := value.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		out := []map[string]any{}
		for _, item := range x {
			if row, ok := item.(map[string]any); ok {
				out = append(out, row)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}
func certStorePath(contextName, store string) string { return "Cert:\\" + contextName + "\\" + store }
func certStorePathSafe(contextName, store string) string {
	return "Cert:\\" + contextName + "\\" + store
}
func pkiFormat(value string) error {
	switch strings.ToLower(value) {
	case "cer", "pfx":
		return nil
	default:
		return fmt.Errorf("Invalid certificate format '%s' specified. Valid formats: [cer pfx]", value)
	}
}
func pkiPathExists(rt *runtime.Runtime, path string) bool {
	info, e := rt.FS.Stat(path)
	return e == nil && !info.IsDir()
}

// ---------------------------------------------------------------------------
// stores/certs

type getStoresArgs struct{}
type getStoresFunc struct{}

func (getStoresFunc) Name() string        { return "win_pki.get_stores" }
func (getStoresFunc) Args() any           { return getStoresArgs{} }
func (getStoresFunc) Platforms() []string { return []string{"windows"} }
func (getStoresFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPKI(&res, &err)
	value, e := pkiJSON(ctx, rt, "Get-ChildItem -Path 'Cert:\\' | Select-Object LocationName,StoreNames", nil)
	if e != nil {
		return nil, e
	}
	out := map[string]any{}
	for _, row := range pkiRows(value) {
		location := fmt.Sprint(row["LocationName"])
		var stores []string
		switch x := row["StoreNames"].(type) {
		case []any:
			for _, item := range x {
				stores = append(stores, fmt.Sprint(item))
			}
		case string:
			if x != "" {
				stores = []string{x}
			}
		}
		out[location] = stores
	}
	return out, nil
}

type getCertsArgs struct {
	Context *string `statekit:"name=context"`
	Store   *string `statekit:"name=store"`
}
type getCertsFunc struct{}

func (getCertsFunc) Name() string        { return "win_pki.get_certs" }
func (getCertsFunc) Args() any           { return getCertsArgs{} }
func (getCertsFunc) Platforms() []string { return []string{"windows"} }
func (getCertsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*getCertsArgs)
	contextName, store := defaultContext, defaultStore
	if a.Context != nil && *a.Context != "" {
		contextName = *a.Context
	}
	if a.Store != nil && *a.Store != "" {
		store = *a.Store
	}
	path := certStorePathSafe(contextName, store)
	value, e := pkiJSON(ctx, rt, "Get-ChildItem -Path "+pkiLiteral(path)+" | Select-Object DnsNameList,SerialNumber,Subject,Thumbprint,Version", nil)
	if e != nil {
		return nil, e
	}
	out := map[string]any{}
	for _, row := range pkiRows(value) {
		thumb := fmt.Sprint(row["Thumbprint"])
		if thumb == "<nil>" || thumb == "" {
			continue
		}
		info := map[string]any{}
		for key, value := range row {
			if key != "DnsNameList" {
				info[strings.ToLower(key)] = value
			}
		}
		names := []string{}
		if raw, ok := row["DnsNameList"].([]any); ok {
			for _, item := range raw {
				if m, ok := item.(map[string]any); ok {
					if name, ok := m["Unicode"].(string); ok {
						names = append(names, name)
					}
				}
			}
		}
		info["dnsnames"] = names
		out[thumb] = info
	}
	return out, nil
}

type getCertFileArgs struct {
	Name       string  `statekit:"required"`
	CertFormat *string `statekit:"name=cert_format"`
	Password   string  `statekit:"name=password"`
}
type getCertFileFunc struct{}

func (getCertFileFunc) Name() string        { return "win_pki.get_cert_file" }
func (getCertFileFunc) Args() any           { return getCertFileArgs{} }
func (getCertFileFunc) Platforms() []string { return []string{"windows"} }
func (getCertFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*getCertFileArgs)
	format := "cer"
	if a.CertFormat != nil && *a.CertFormat != "" {
		format = strings.ToLower(*a.CertFormat)
	}
	if e := pkiFormat(format); e != nil {
		return nil, e
	}
	if !pkiPathExists(rt, a.Name) {
		return map[string]any{}, nil
	}
	script := "Get-PfxCertificate -FilePath " + pkiLiteral(a.Name)
	if format == "cer" {
		script = "[System.Security.Cryptography.X509Certificates.X509Certificate2]::new();$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;$c.Import(" + pkiLiteral(a.Name) + ");$c"
	}
	if format == "pfx" && a.Password != "" {
		script = "$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;$c.Import(" + pkiLiteral(a.Name) + "," + pkiLiteral(a.Password) + ",'DefaultKeySet');$c"
	}
	script += " | Select-Object DnsNameList,SerialNumber,Subject,Thumbprint,Version"
	value, e := pkiJSON(ctx, rt, script, []string{a.Password})
	if e != nil {
		return nil, e
	}
	rows := pkiRows(value)
	if len(rows) == 0 {
		return map[string]any{}, nil
	}
	row := rows[0]
	out := map[string]any{}
	for key, value := range row {
		if key != "DnsNameList" {
			out[strings.ToLower(key)] = value
		}
	}
	names := []string{}
	if raw, ok := row["DnsNameList"].([]any); ok {
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				if name, ok := m["Unicode"].(string); ok {
					names = append(names, name)
				}
			}
		}
	}
	out["dnsnames"] = names
	return out, nil
}

// ---------------------------------------------------------------------------
// import/export/test/remove

type importCertArgs struct {
	Name       string  `statekit:"required"`
	CertFormat *string `statekit:"name=cert_format"`
	Context    *string `statekit:"name=context"`
	Store      *string `statekit:"name=store"`
	Exportable *bool   `statekit:"name=exportable"`
	Password   string  `statekit:"name=password"`
	Saltenv    *string `statekit:"name=saltenv"`
}
type importCertFunc struct{}

func (importCertFunc) Name() string        { return "win_pki.import_cert" }
func (importCertFunc) Args() any           { return importCertArgs{} }
func (importCertFunc) Platforms() []string { return []string{"windows"} }
func (importCertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*importCertArgs)
	format := "cer"
	if a.CertFormat != nil && *a.CertFormat != "" {
		format = strings.ToLower(*a.CertFormat)
	}
	if e := pkiFormat(format); e != nil {
		return nil, e
	}
	if !pkiPathExists(rt, a.Name) {
		return false, nil
	}
	contextName, store := defaultContext, defaultStore
	if a.Context != nil && *a.Context != "" {
		contextName = *a.Context
	}
	if a.Store != nil && *a.Store != "" {
		store = *a.Store
	}
	before, e := getCertsFunc{}.Execute(ctx, rt, &getCertsArgs{Context: &contextName, Store: &store})
	if e != nil {
		return nil, e
	}
	beforeMap := before.(map[string]any)
	props, e := getCertFileFunc{}.Execute(ctx, rt, &getCertFileArgs{Name: a.Name, CertFormat: &format, Password: a.Password})
	if e != nil {
		return nil, e
	}
	propsMap := props.(map[string]any)
	thumb := fmt.Sprint(propsMap["thumbprint"])
	if _, ok := beforeMap[thumb]; ok {
		return true, nil
	}
	path := certStorePathSafe(contextName, store)
	script := "Import-Certificate -FilePath " + pkiLiteral(a.Name) + " -CertStoreLocation " + pkiLiteral(path)
	secrets := []string{}
	if format == "pfx" {
		script = "$p=New-Object System.Security.SecureString;"
		if a.Password != "" {
			script = "$p=ConvertTo-SecureString -String " + pkiLiteral(a.Password) + " -AsPlainText -Force;"
			secrets = []string{a.Password}
		}
		script += "Import-PfxCertificate -FilePath " + pkiLiteral(a.Name) + " -CertStoreLocation " + pkiLiteral(path) + " -Password $p"
		if a.Exportable == nil || *a.Exportable {
			script += " -Exportable"
		}
	}
	if _, e := pkiRun(ctx, rt, script, secrets); e != nil {
		return nil, e
	}
	after, e := getCertsFunc{}.Execute(ctx, rt, &getCertsArgs{Context: &contextName, Store: &store})
	if e != nil {
		return nil, e
	}
	for item := range after.(map[string]any) {
		if _, ok := beforeMap[item]; !ok {
			return true, nil
		}
	}
	return false, nil
}

type exportCertArgs struct {
	Name       string  `statekit:"required"`
	Thumbprint string  `statekit:"required,name=thumbprint"`
	CertFormat *string `statekit:"name=cert_format"`
	Context    *string `statekit:"name=context"`
	Store      *string `statekit:"name=store"`
	Password   string  `statekit:"name=password"`
}
type exportCertFunc struct{}

func (exportCertFunc) Name() string        { return "win_pki.export_cert" }
func (exportCertFunc) Args() any           { return exportCertArgs{} }
func (exportCertFunc) Platforms() []string { return []string{"windows"} }
func (exportCertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*exportCertArgs)
	format := "cer"
	if a.CertFormat != nil && *a.CertFormat != "" {
		format = strings.ToLower(*a.CertFormat)
	}
	if e := pkiFormat(format); e != nil {
		return nil, e
	}
	contextName, store := defaultContext, defaultStore
	if a.Context != nil && *a.Context != "" {
		contextName = *a.Context
	}
	if a.Store != nil && *a.Store != "" {
		store = *a.Store
	}
	certs, e := getCertsFunc{}.Execute(ctx, rt, &getCertsArgs{Context: &contextName, Store: &store})
	if e != nil {
		return nil, e
	}
	if _, ok := certs.(map[string]any)[strings.ToUpper(a.Thumbprint)]; !ok {
		return nil, fmt.Errorf("Invalid path specified: %s", certStorePathSafe(contextName, store)+"\\"+strings.ToUpper(a.Thumbprint))
	}
	storePath := certStorePathSafe(contextName, store)
	script := "Export-Certificate -Cert " + pkiLiteral(storePath+"\\"+strings.ToUpper(a.Thumbprint)) + " -FilePath " + pkiLiteral(a.Name) + " | Out-Null;Test-Path -Path " + pkiLiteral(a.Name)
	secrets := []string{}
	if format == "pfx" {
		script = "$p=New-Object System.Security.SecureString;"
		if a.Password != "" {
			script = "$p=ConvertTo-SecureString -String " + pkiLiteral(a.Password) + " -AsPlainText -Force;"
			secrets = []string{a.Password}
		}
		script += "Export-PfxCertificate -Cert " + pkiLiteral(storePath+"\\"+strings.ToUpper(a.Thumbprint)) + " -FilePath " + pkiLiteral(a.Name) + " -Password $p | Out-Null;Test-Path -Path " + pkiLiteral(a.Name)
	}
	out, e := pkiRun(ctx, rt, script, secrets)
	if e != nil {
		return nil, e
	}
	return strings.EqualFold(strings.TrimSpace(out), "true"), nil
}

type testCertArgs struct {
	Thumbprint    string  `statekit:"required,name=thumbprint"`
	Context       *string `statekit:"name=context"`
	Store         *string `statekit:"name=store"`
	UntrustedRoot bool    `statekit:"name=untrusted_root"`
	DNSName       string  `statekit:"name=dns_name"`
	EKU           string  `statekit:"name=eku"`
}
type testCertFunc struct{}

func (testCertFunc) Name() string        { return "win_pki.test_cert" }
func (testCertFunc) Args() any           { return testCertArgs{} }
func (testCertFunc) Platforms() []string { return []string{"windows"} }
func (testCertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*testCertArgs)
	contextName, store := defaultContext, defaultStore
	if a.Context != nil && *a.Context != "" {
		contextName = *a.Context
	}
	if a.Store != nil && *a.Store != "" {
		store = *a.Store
	}
	certPath := certStorePathSafe(contextName, store) + "\\" + strings.ToUpper(a.Thumbprint)
	opts := " -ErrorAction SilentlyContinue"
	if a.UntrustedRoot {
		opts += " -AllowUntrustedRoot"
	}
	if a.DNSName != "" {
		opts += " -DnsName " + pkiLiteral(a.DNSName)
	}
	if a.EKU != "" {
		opts += " -EKU " + pkiLiteral(a.EKU)
	}
	out, e := pkiRun(ctx, rt, "Test-Certificate -Cert "+pkiLiteral(certPath)+opts+"", nil)
	if e != nil {
		return false, nil
	}
	return strings.EqualFold(strings.TrimSpace(out), "true"), nil
}

type removeCertArgs struct {
	Thumbprint string  `statekit:"required,name=thumbprint"`
	Context    *string `statekit:"name=context"`
	Store      *string `statekit:"name=store"`
}
type removeCertFunc struct{}

func (removeCertFunc) Name() string        { return "win_pki.remove_cert" }
func (removeCertFunc) Args() any           { return removeCertArgs{} }
func (removeCertFunc) Platforms() []string { return []string{"windows"} }
func (removeCertFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPKI(&res, &err)
	a := args.(*removeCertArgs)
	contextName, store := defaultContext, defaultStore
	if a.Context != nil && *a.Context != "" {
		contextName = *a.Context
	}
	if a.Store != nil && *a.Store != "" {
		store = *a.Store
	}
	certs, e := getCertsFunc{}.Execute(ctx, rt, &getCertsArgs{Context: &contextName, Store: &store})
	if e != nil {
		return nil, e
	}
	thumb := strings.ToUpper(a.Thumbprint)
	if _, ok := certs.(map[string]any)[thumb]; !ok {
		return true, nil
	}
	path := certStorePathSafe(contextName, store) + "\\" + thumb
	if _, e := pkiRun(ctx, rt, "Remove-Item -Path "+pkiLiteral(path), nil); e != nil {
		return nil, e
	}
	after, e := getCertsFunc{}.Execute(ctx, rt, &getCertsArgs{Context: &contextName, Store: &store})
	if e != nil {
		return nil, e
	}
	_, exists := after.(map[string]any)[thumb]
	return !exists, nil
}

func recoverPKI(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Windows PKI functions.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{getStoresFunc{}, getCertsFunc{}, getCertFileFunc{}, importCertFunc{}, exportCertFunc{}, testCertFunc{}, removeCertFunc{}} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
