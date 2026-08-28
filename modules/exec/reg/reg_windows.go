//go:build windows

// Package reg implements Salt's Windows registry execution surface through
// reg.exe. Win32 registry operations are kept behind the Runner so Linux
// tests remain hermetic and Windows builds retain native command semantics.
package reg

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var validHives = map[string]bool{
	"HKEY_LOCAL_MACHINE": true, "HKLM": true,
	"HKEY_CURRENT_USER": true, "HKCU": true,
	"HKEY_USERS": true, "HKU": true,
	"HKEY_CLASSES_ROOT": true, "HKCR": true,
	"HKEY_CURRENT_CONFIG": true, "HKCC": true,
}

func validateHive(hive string) error {
	if !validHives[hive] {
		return fmt.Errorf("Invalid Hive: %s", hive)
	}
	return nil
}

func regPath(hive, key string) string {
	key = strings.Trim(key, `\`)
	if key == "" {
		return hive
	}
	return strings.TrimRight(hive, `\`) + `\` + key
}

func regSwitch(use32 bool) string {
	if use32 {
		return "/reg:32"
	}
	return "/reg:64"
}

func run(ctx context.Context, rt *runtime.Runtime, argv ...string) process.CommandResult {
	return rt.Runner.Run(ctx, runtime.Command(argv...))
}

func notFound(result process.CommandResult) bool {
	text := strings.ToLower(string(result.Stderr) + "\n" + string(result.Stdout))
	return strings.Contains(text, "unable to find") || strings.Contains(text, "cannot find") || strings.Contains(text, "not found")
}

func tupleNotFound(hive, key string) []any {
	return []any{false, fmt.Sprintf(`Cannot find key: %s\%s`, hive, key)}
}

func parseRegValueLine(line string) (map[string]any, bool) {
	line = strings.TrimRight(line, "\r")
	if len(line) == 0 || line[0] != ' ' && line[0] != '\t' {
		return nil, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, false
	}
	name, typ := fields[0], fields[1]
	data := ""
	if len(fields) > 2 {
		data = strings.Join(fields[2:], " ")
	}
	if name == "(Default)" {
		name = "(Default)"
	}
	value := convertRegData(data, typ)
	return map[string]any{
		"vname": name, "vtype": typ, "vdata": value, "success": true,
	}, true
}

func convertRegData(data, typ string) any {
	switch typ {
	case "REG_DWORD", "REG_QWORD":
		if strings.HasPrefix(strings.ToLower(data), "0x") {
			value, err := strconv.ParseUint(data[2:], 16, 64)
			if err == nil {
				return value
			}
		}
		if value, err := strconv.ParseUint(data, 10, 64); err == nil {
			return value
		}
	case "REG_BINARY":
		clean := strings.NewReplacer(" ", "", ",", "").Replace(data)
		if value, err := hex.DecodeString(clean); err == nil {
			return value
		}
	case "REG_MULTI_SZ":
		parts := strings.Split(data, `\0`)
		if len(parts) > 1 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		if len(parts) == 1 && strings.Contains(data, ";") {
			return strings.Split(data, ";")
		}
		return parts
	}
	return data
}

func queryValues(ctx context.Context, rt *runtime.Runtime, hive, key string, use32 bool) (string, process.CommandResult) {
	result := run(ctx, rt, "reg.exe", "query", regPath(hive, key), regSwitch(use32))
	return string(result.Stdout), result
}

// ---------------------------------------------------------------------------
// key/value existence and enumeration

type keyExistsArgs struct {
	Hive             string `statekit:"required"`
	Key              string `statekit:"required"`
	Use32BitRegistry bool   `statekit:"name=use_32bit_registry"`
}
type keyExistsFunc struct{}

func (keyExistsFunc) Name() string        { return "reg.key_exists" }
func (keyExistsFunc) Args() any           { return keyExistsArgs{} }
func (keyExistsFunc) Platforms() []string { return []string{"windows"} }
func (keyExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*keyExistsArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	_, result := queryValues(ctx, rt, a.Hive, a.Key, a.Use32BitRegistry)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode == 0 {
		return true, nil
	}
	if notFound(result) {
		return false, nil
	}
	return nil, fmt.Errorf("reg.exe query failed: %s", strings.TrimSpace(string(result.Stderr)))
}

type valueExistsArgs struct {
	Hive             string `statekit:"required"`
	Key              string `statekit:"required"`
	VName            string `statekit:"required,name=vname"`
	Use32BitRegistry bool   `statekit:"name=use_32bit_registry"`
}
type valueExistsFunc struct{}

func (valueExistsFunc) Name() string        { return "reg.value_exists" }
func (valueExistsFunc) Args() any           { return valueExistsArgs{} }
func (valueExistsFunc) Platforms() []string { return []string{"windows"} }
func (valueExistsFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*valueExistsArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	value, err := readValueImpl(ctx, rt, a.Hive, a.Key, &a.VName, a.Use32BitRegistry)
	if err != nil {
		return nil, err
	}
	m, ok := value.(map[string]any)
	return ok && m["success"] == true && m["vdata"] != nil, nil
}

type listKeysArgs struct {
	Hive             string  `statekit:"required"`
	Key              *string `statekit:"name=key"`
	Use32BitRegistry bool    `statekit:"name=use_32bit_registry"`
}
type listKeysFunc struct{}

func (listKeysFunc) Name() string        { return "reg.list_keys" }
func (listKeysFunc) Args() any           { return listKeysArgs{} }
func (listKeysFunc) Platforms() []string { return []string{"windows"} }
func (listKeysFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*listKeysArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	key := ""
	if a.Key != nil {
		key = *a.Key
	}
	out, result := queryValues(ctx, rt, a.Hive, key, a.Use32BitRegistry)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		if notFound(result) {
			return tupleNotFound(a.Hive, key), nil
		}
		return nil, fmt.Errorf("reg.exe query failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	root := regPath(a.Hive, key)
	prefix := strings.ToUpper(strings.TrimRight(root, `\`)) + `\`
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), prefix) {
			continue
		}
		rest := line[len(prefix):]
		if i := strings.IndexByte(rest, '\\'); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" && !seen[rest] {
			seen[rest] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys, nil
}

type listValuesArgs struct {
	Hive             string  `statekit:"required"`
	Key              *string `statekit:"name=key"`
	Use32BitRegistry bool    `statekit:"name=use_32bit_registry"`
}
type listValuesFunc struct{}

func (listValuesFunc) Name() string        { return "reg.list_values" }
func (listValuesFunc) Args() any           { return listValuesArgs{} }
func (listValuesFunc) Platforms() []string { return []string{"windows"} }
func (listValuesFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*listValuesArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	key := ""
	if a.Key != nil {
		key = *a.Key
	}
	out, result := queryValues(ctx, rt, a.Hive, key, a.Use32BitRegistry)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		if notFound(result) {
			return tupleNotFound(a.Hive, key), nil
		}
		return nil, fmt.Errorf("reg.exe query failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	var values []map[string]any
	for _, line := range strings.Split(out, "\n") {
		value, ok := parseRegValueLine(line)
		if !ok {
			continue
		}
		value["hive"] = a.Hive
		value["key"] = key
		values = append(values, value)
	}
	return values, nil
}

type readValueArgs struct {
	Hive             string  `statekit:"required"`
	Key              string  `statekit:"required"`
	VName            *string `statekit:"name=vname"`
	Use32BitRegistry bool    `statekit:"name=use_32bit_registry"`
}
type readValueFunc struct{}

func (readValueFunc) Name() string        { return "reg.read_value" }
func (readValueFunc) Args() any           { return readValueArgs{} }
func (readValueFunc) Platforms() []string { return []string{"windows"} }
func (readValueFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*readValueArgs)
	return readValueImpl(ctx, rt, a.Hive, a.Key, a.VName, a.Use32BitRegistry)
}

func readValueImpl(ctx context.Context, rt *runtime.Runtime, hive, key string, vname *string, use32 bool) (any, error) {
	if err := validateHive(hive); err != nil {
		return nil, err
	}
	name := ""
	if vname != nil {
		name = *vname
	}
	out, result := queryValues(ctx, rt, hive, key, use32)
	ret := map[string]any{"hive": hive, "key": key, "vname": name, "vdata": nil, "vtype": nil, "success": true}
	if name == "" {
		ret["vname"] = "(Default)"
	}
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		if notFound(result) {
			ret["comment"] = fmt.Sprintf(`Cannot find key: %s\%s`, hive, key)
			ret["success"] = false
			return ret, nil
		}
		return nil, fmt.Errorf("reg.exe query failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	for _, line := range strings.Split(out, "\n") {
		value, ok := parseRegValueLine(line)
		if !ok {
			continue
		}
		if name == "" && value["vname"] == "(Default)" || name != "" && value["vname"] == name {
			ret["vdata"] = value["vdata"]
			ret["vtype"] = value["vtype"]
			return ret, nil
		}
	}
	if name == "" {
		ret["vdata"] = "(value not set)"
		ret["vtype"] = "REG_SZ"
		return ret, nil
	}
	ret["comment"] = fmt.Sprintf(`Cannot find %s in %s\%s`, name, hive, key)
	ret["success"] = false
	return ret, nil
}

// ---------------------------------------------------------------------------
// set/delete/import/broadcast

type setValueArgs struct {
	Hive             string  `statekit:"required"`
	Key              string  `statekit:"required"`
	VName            *string `statekit:"name=vname"`
	VData            any     `statekit:"name=vdata"`
	VType            *string `statekit:"name=vtype"`
	Use32BitRegistry bool    `statekit:"name=use_32bit_registry"`
	Volatile         bool    `statekit:"name=volatile"`
}
type setValueFunc struct{}

func (setValueFunc) Name() string        { return "reg.set_value" }
func (setValueFunc) Args() any           { return setValueArgs{} }
func (setValueFunc) Platforms() []string { return []string{"windows"} }
func (setValueFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*setValueArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	if a.Volatile {
		return false, fmt.Errorf("volatile registry keys are not supported by reg.exe")
	}
	typ := "REG_SZ"
	if a.VType != nil && *a.VType != "" {
		typ = *a.VType
	}
	nameArg := []string{"reg.exe", "add", regPath(a.Hive, a.Key)}
	if a.VName == nil || *a.VName == "" {
		nameArg = append(nameArg, "/ve")
	} else {
		nameArg = append(nameArg, "/v", *a.VName)
	}
	if a.VData != nil {
		data, ok := regDataString(a.VData, typ)
		if !ok {
			return false, nil
		}
		nameArg = append(nameArg, "/t", typ, "/d", data)
	}
	nameArg = append(nameArg, "/f", regSwitch(a.Use32BitRegistry))
	result := run(ctx, rt, nameArg...)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	_, _ = broadcastImpl(ctx, rt)
	return true, nil
}

func regDataString(value any, typ string) (string, bool) {
	switch typ {
	case "REG_SZ", "REG_EXPAND_SZ":
		s, ok := value.(string)
		return s, ok
	case "REG_BINARY":
		switch v := value.(type) {
		case []byte:
			return strings.ToUpper(hex.EncodeToString(v)), true
		case string:
			return strings.ToUpper(hex.EncodeToString([]byte(v))), true
		}
	case "REG_MULTI_SZ":
		switch v := value.(type) {
		case []string:
			return strings.Join(v, `\0`), true
		case []any:
			out := make([]string, 0, len(v))
			for _, x := range v {
				s, ok := x.(string)
				if !ok {
					return "", false
				}
				out = append(out, s)
			}
			return strings.Join(out, `\0`), true
		}
	case "REG_DWORD", "REG_QWORD":
		switch v := value.(type) {
		case int:
			return strconv.FormatUint(uint64(v), 10), true
		case int64:
			return strconv.FormatUint(uint64(v), 10), true
		case uint64:
			return strconv.FormatUint(v, 10), true
		case string:
			return v, true
		}
	}
	return "", false
}

type deleteKeyRecursiveArgs struct {
	Hive             string `statekit:"required"`
	Key              string `statekit:"required"`
	Use32BitRegistry bool   `statekit:"name=use_32bit_registry"`
}
type deleteKeyRecursiveFunc struct{}

func (deleteKeyRecursiveFunc) Name() string        { return "reg.delete_key_recursive" }
func (deleteKeyRecursiveFunc) Args() any           { return deleteKeyRecursiveArgs{} }
func (deleteKeyRecursiveFunc) Platforms() []string { return []string{"windows"} }
func (deleteKeyRecursiveFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*deleteKeyRecursiveArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	if len(a.Key) > 1 && strings.Count(a.Key, `\`) < 1 && a.Hive != "HKCU" && a.Hive != "HKEY_CURRENT_USER" {
		return false, nil
	}
	exists, _ := keyExistsFunc{}.Execute(ctx, rt, &keyExistsArgs{Hive: a.Hive, Key: a.Key, Use32BitRegistry: a.Use32BitRegistry})
	if exists != true {
		return false, nil
	}
	result := run(ctx, rt, "reg.exe", "delete", regPath(a.Hive, a.Key), "/f", regSwitch(a.Use32BitRegistry))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	ret := map[string]any{"Deleted": []string{}, "Failed": []string{}}
	if result.ExitCode == 0 {
		ret["Deleted"] = []string{regPath(a.Hive, a.Key)}
		_, _ = broadcastImpl(ctx, rt)
	} else {
		ret["Failed"] = []string{fmt.Sprintf(`%s\%s %s`, a.Hive, a.Key, strings.TrimSpace(string(result.Stderr)))}
	}
	return ret, nil
}

type deleteValueArgs struct {
	Hive             string  `statekit:"required"`
	Key              string  `statekit:"required"`
	VName            *string `statekit:"name=vname"`
	Use32BitRegistry bool    `statekit:"name=use_32bit_registry"`
}
type deleteValueFunc struct{}

func (deleteValueFunc) Name() string        { return "reg.delete_value" }
func (deleteValueFunc) Args() any           { return deleteValueArgs{} }
func (deleteValueFunc) Platforms() []string { return []string{"windows"} }
func (deleteValueFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*deleteValueArgs)
	if err := validateHive(a.Hive); err != nil {
		return nil, err
	}
	argv := []string{"reg.exe", "delete", regPath(a.Hive, a.Key)}
	if a.VName == nil || *a.VName == "" {
		argv = append(argv, "/ve")
	} else {
		argv = append(argv, "/v", *a.VName)
	}
	argv = append(argv, "/f", regSwitch(a.Use32BitRegistry))
	result := run(ctx, rt, argv...)
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 && notFound(result) {
		return nil, nil
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("reg.exe delete failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	_, _ = broadcastImpl(ctx, rt)
	return true, nil
}

type broadcastChangeArgs struct{}
type broadcastChangeFunc struct{}

func (broadcastChangeFunc) Name() string        { return "reg.broadcast_change" }
func (broadcastChangeFunc) Args() any           { return broadcastChangeArgs{} }
func (broadcastChangeFunc) Platforms() []string { return []string{"windows"} }
func (broadcastChangeFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (any, error) {
	return broadcastImpl(ctx, rt)
}
func broadcastImpl(ctx context.Context, rt *runtime.Runtime) (bool, error) {
	result := run(ctx, rt, "rundll32.exe", "user32.dll,UpdatePerUserSystemParameters")
	if result.Err != nil && result.ExitCode == -1 {
		return false, result.Err
	}
	return result.ExitCode == 0, nil
}

type importFileArgs struct {
	Source           string `statekit:"required"`
	Use32BitRegistry bool   `statekit:"name=use_32bit_registry"`
}
type importFileFunc struct{}

func (importFileFunc) Name() string        { return "reg.import_file" }
func (importFileFunc) Args() any           { return importFileArgs{} }
func (importFileFunc) Platforms() []string { return []string{"windows"} }
func (importFileFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverReg(&res, &err)
	a := args.(*importFileArgs)
	if !fileExists(rt, a.Source) {
		return nil, fmt.Errorf("File/URL %q probably invalid.", a.Source)
	}
	result := run(ctx, rt, "reg.exe", "import", a.Source, regSwitch(a.Use32BitRegistry))
	if result.Err != nil && result.ExitCode == -1 {
		return nil, result.Err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("reg.exe import failed")
	}
	return true, nil
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
func fileExists(rt *runtime.Runtime, path string) bool {
	info, err := rt.FS.Stat(path)
	return err == nil && !info.IsDir()
}
func recoverReg(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Windows registry execution surface.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		keyExistsFunc{}, valueExistsFunc{}, broadcastChangeFunc{}, listKeysFunc{}, listValuesFunc{},
		readValueFunc{}, setValueFunc{}, deleteKeyRecursiveFunc{}, deleteValueFunc{}, importFileFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
