// Package macdefaults implements the portable core of Salt's macdefaults
// module. The public functions are Darwin-only and use macOS's defaults CLI
// through the central Runner; XML plist conversion is implemented with the Go
// standard library so tests do not require macOS or an extra plist package.
//
// Boundary: Salt's optional user/runas path relies on cmd.run_all privilege
// switching and file.chown. StateKit's Runner has no target-user field, so a
// non-empty user is rejected explicitly rather than silently writing another
// user's defaults. Binary plist export is likewise rejected; defaults export
// normally emits XML for this module's contract.
package macdefaults

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

var timestampPrefix = "2006-01-02 15:04:05"

// ---------------------------------------------------------------------------
// plist parsing and encoding

func loadPlist(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return nil, fmt.Errorf("binary plist export is not supported by statekit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("plist root value not found")
			}
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "dict" || start.Name.Local == "array" {
			return parsePlistElement(decoder, start)
		}
	}
}

func parsePlistElement(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		out := map[string]any{}
		var key string
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch item := token.(type) {
			case xml.StartElement:
				switch item.Name.Local {
				case "key":
					if err := decoder.DecodeElement(&key, &item); err != nil {
						return nil, err
					}
				default:
					if key == "" {
						return nil, fmt.Errorf("plist dictionary value has no key")
					}
					value, err := parsePlistElement(decoder, item)
					if err != nil {
						return nil, err
					}
					out[key] = value
					key = ""
				}
			case xml.EndElement:
				if item.Name.Local == "dict" {
					return out, nil
				}
			}
		}
	case "array":
		out := []any{}
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch item := token.(type) {
			case xml.StartElement:
				value, err := parsePlistElement(decoder, item)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			case xml.EndElement:
				if item.Name.Local == "array" {
					return out, nil
				}
			}
		}
	case "string":
		var value string
		return value, decoder.DecodeElement(&value, &start)
	case "integer":
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return nil, err
		}
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	case "real":
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return nil, err
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	case "true":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return true, nil
	case "false":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return false, nil
	case "date":
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
		if err != nil {
			parsed, err = time.Parse("2006-01-02T15:04:05Z", strings.TrimSpace(value))
		}
		if err != nil {
			return nil, err
		}
		return parsed, nil
	case "data":
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return nil, err
		}
		parsed, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
		if err != nil {
			return nil, err
		}
		return parsed, nil
	default:
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unsupported plist element <%s>", start.Name.Local)
	}
}

func encodePlist(value any) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	out.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	out.WriteString("<plist version=\"1.0\">\n")
	if err := encodePlistValue(&out, value); err != nil {
		return nil, err
	}
	out.WriteString("\n</plist>\n")
	return out.Bytes(), nil
}

func encodePlistValue(out *bytes.Buffer, value any) error {
	switch item := value.(type) {
	case nil:
		return fmt.Errorf("nil is not a plist value")
	case string:
		out.WriteString("<string>")
		xml.EscapeText(out, []byte(item))
		out.WriteString("</string>")
	case []byte:
		out.WriteString("<data>")
		out.WriteString(base64.StdEncoding.EncodeToString(item))
		out.WriteString("</data>")
	case bool:
		if item {
			out.WriteString("<true/>")
		} else {
			out.WriteString("<false/>")
		}
	case int:
		out.WriteString("<integer>" + strconv.Itoa(item) + "</integer>")
	case int8:
		out.WriteString("<integer>" + strconv.FormatInt(int64(item), 10) + "</integer>")
	case int16:
		out.WriteString("<integer>" + strconv.FormatInt(int64(item), 10) + "</integer>")
	case int32:
		out.WriteString("<integer>" + strconv.FormatInt(int64(item), 10) + "</integer>")
	case int64:
		out.WriteString("<integer>" + strconv.FormatInt(item, 10) + "</integer>")
	case uint:
		out.WriteString("<integer>" + strconv.FormatUint(uint64(item), 10) + "</integer>")
	case uint64:
		out.WriteString("<integer>" + strconv.FormatUint(item, 10) + "</integer>")
	case float32:
		out.WriteString("<real>" + strconv.FormatFloat(float64(item), 'g', -1, 32) + "</real>")
	case float64:
		out.WriteString("<real>" + strconv.FormatFloat(item, 'g', -1, 64) + "</real>")
	case time.Time:
		out.WriteString("<date>" + item.UTC().Format(time.RFC3339) + "</date>")
	case []string:
		out.WriteString("<array>")
		for _, item := range item {
			if err := encodePlistValue(out, item); err != nil {
				return err
			}
		}
		out.WriteString("</array>")
	case []any:
		out.WriteString("<array>")
		for _, item := range item {
			if err := encodePlistValue(out, item); err != nil {
				return err
			}
		}
		out.WriteString("</array>")
	case map[string]string:
		converted := map[string]any{}
		for key, value := range item {
			converted[key] = value
		}
		return encodePlistValue(out, converted)
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteString("<dict>")
		for _, key := range keys {
			out.WriteString("<key>")
			xml.EscapeText(out, []byte(key))
			out.WriteString("</key>")
			if err := encodePlistValue(out, item[key]); err != nil {
				return err
			}
		}
		out.WriteString("</dict>")
	default:
		return fmt.Errorf("unsupported plist value %T", value)
	}
	return nil
}

// ---------------------------------------------------------------------------
// defaults command and traversal

func runDefaults(ctx context.Context, rt *runtime.Runtime, action string, user *string) map[string]any {
	if user != nil && *user != "" {
		return map[string]any{
			"retcode": -1,
			"stdout":  "",
			"stderr":  "runas is not supported by statekit",
		}
	}
	result := rt.Runner.Run(ctx, process.Command{
		Name:  "defaults " + action,
		Shell: true,
	})
	retcode := result.ExitCode
	if result.Err != nil && retcode == 0 {
		retcode = -1
	}
	stderr := string(result.Stderr)
	if retcode != 0 {
		stderr = removeTimestamp(stderr)
	}
	return map[string]any{
		"retcode": retcode,
		"stdout":  string(result.Stdout),
		"stderr":  stderr,
	}
}

var defaultsTimestamp = regexpMust(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?\s+defaults\[\d+:\d+\]`)

func regexpMust(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

func removeTimestamp(text string) string {
	if !defaultsTimestamp.MatchString(text) {
		return text
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) <= 1 {
		return ""
	}
	return strings.Join(lines[1:], "\n")
}

func shellDoubleQuote(value string) string {
	value = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(value)
	return `"` + value + `"`
}

func loadDomainPlist(ctx context.Context, rt *runtime.Runtime, domain string, user *string) (map[string]any, error) {
	ret := runDefaults(ctx, rt, "export "+shellDoubleQuote(domain)+" -", user)
	if ret["retcode"] != int(0) {
		return nil, fmt.Errorf("Failed to export defaults: %s", ret["stderr"])
	}
	root, err := loadPlist([]byte(ret["stdout"].(string)))
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	plist, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("defaults export did not contain a plist dictionary")
	}
	if len(plist) == 0 {
		return nil, nil
	}
	return plist, nil
}

func saveDomainPlist(ctx context.Context, rt *runtime.Runtime, domain string, plist map[string]any, user *string) (map[string]any, error) {
	if user != nil && *user != "" {
		return nil, fmt.Errorf("runas is not supported by statekit")
	}
	tempDir, err := rt.FS.MkdirTemp("", "salt_macdefaults")
	if err != nil {
		return nil, err
	}
	defer rt.FS.RemoveAll(tempDir)
	fileName := filepath.Join(tempDir, domain+".plist")
	data, err := encodePlist(plist)
	if err != nil {
		return nil, err
	}
	if err := rt.FS.WriteFile(fileName, data, 0o600); err != nil {
		return nil, err
	}
	return runDefaults(ctx, rt, "import "+shellDoubleQuote(domain)+" "+shellDoubleQuote(fileName), nil), nil
}

func splitKeys(key string, separator *string) ([]string, error) {
	if separator == nil {
		return []string{key}, nil
	}
	if *separator == "" {
		return nil, fmt.Errorf("empty key separator")
	}
	return strings.Split(key, *separator), nil
}

func digitKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func listIndex(key string, length int) (int, bool) {
	if !digitKey(key) {
		return 0, false
	}
	index, err := strconv.Atoi(key)
	if err != nil || index < 0 || index >= length {
		return 0, false
	}
	return index, true
}

func traverse(value any, keys []string) (any, bool) {
	current := value
	for _, key := range keys {
		switch container := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = container[key]
			if !ok || current == nil {
				return nil, false
			}
		case []any:
			index, ok := listIndex(key, len(container))
			if !ok {
				return nil, false
			}
			current = container[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func parentAndLast(value any, keys []string) (any, string, bool) {
	if len(keys) == 0 {
		return nil, "", false
	}
	if len(keys) == 1 {
		return value, keys[0], true
	}
	parent, ok := traverse(value, keys[:len(keys)-1])
	return parent, keys[len(keys)-1], ok
}

// deletePath returns the updated subtree because removing an array element
// changes the slice header; mutating only a local []any copy would otherwise
// leave a nested plist unchanged.
func deletePath(value any, keys []string) (any, bool) {
	if len(keys) == 0 {
		return value, false
	}
	switch container := value.(type) {
	case map[string]any:
		if len(keys) == 1 {
			if _, ok := container[keys[0]]; !ok {
				return value, false
			}
			delete(container, keys[0])
			return value, true
		}
		child, ok := container[keys[0]]
		if !ok || child == nil {
			return value, false
		}
		updated, changed := deletePath(child, keys[1:])
		if changed {
			container[keys[0]] = updated
		}
		return value, changed
	case []any:
		index, ok := listIndex(keys[0], len(container))
		if !ok {
			return value, false
		}
		if len(keys) == 1 {
			return append(container[:index], container[index+1:]...), true
		}
		updated, changed := deletePath(container[index], keys[1:])
		if changed {
			container[index] = updated
		}
		return container, changed
	default:
		return value, false
	}
}

// ---------------------------------------------------------------------------
// cast_value_to_vtype

func castValueToVType(value any, vtype string) (any, error) {
	switch vtype {
	case "bool", "boolean":
		switch item := value.(type) {
		case string:
			switch strings.ToLower(item) {
			case "true", "yes", "1":
				return true, nil
			case "false", "no", "0":
				return false, nil
			default:
				return nil, fmt.Errorf("Invalid value for boolean: '%v'", value)
			}
		case bool:
			return item, nil
		case int:
			if item == 0 || item == 1 {
				return item == 1, nil
			}
		case int64:
			if item == 0 || item == 1 {
				return item == 1, nil
			}
		case float64:
			if item == 0 || item == 1 {
				return item == 1, nil
			}
		}
		return nil, fmt.Errorf("Invalid value for boolean: '%v'", value)
	case "string":
		switch item := value.(type) {
		case bool:
			if item {
				return "YES", nil
			}
			return "NO", nil
		case string:
			return item, nil
		case []byte:
			return string(item), nil
		case time.Time:
			return item.UTC().Format("2006-01-02T15:04:05Z"), nil
		case int:
			return strconv.Itoa(item), nil
		case int64:
			return strconv.FormatInt(item, 10), nil
		case float64:
			return strconv.FormatFloat(item, 'f', -1, 64), nil
		default:
			return fmt.Sprint(value), nil
		}
	case "int", "integer":
		return castInt(value)
	case "float":
		return castFloat(value)
	case "date":
		if item, ok := value.(time.Time); ok {
			return item, nil
		}
		if text, ok := value.(string); ok {
			if seconds, err := strconv.ParseFloat(text, 64); err == nil {
				return time.Unix(int64(seconds), int64((seconds-float64(int64(seconds)))*1e9)).UTC(), nil
			}
			if parsed, err := time.Parse("2006-01-02T15:04:05Z", text); err == nil {
				return parsed, nil
			}
		}
		return nil, fmt.Errorf("Invalid date format: '%v'", value)
	case "data":
		switch item := value.(type) {
		case string:
			return []byte(item), nil
		case []byte:
			return item, nil
		default:
			return nil, fmt.Errorf("Invalid value for data: '%v'", value)
		}
	case "dict", "dict-add":
		if item, ok := plistMap(value); ok {
			return item, nil
		}
		return nil, fmt.Errorf("Invalid value for dictionary: '%v'", value)
	case "array", "array-add":
		if item, ok := plistArray(value); ok {
			return item, nil
		}
		return nil, fmt.Errorf("Invalid value for array: '%v'", value)
	default:
		return nil, fmt.Errorf("Invalid type: '%s'", vtype)
	}
}

func castInt(value any) (int64, error) {
	switch item := value.(type) {
	case string:
		parsed, err := strconv.ParseInt(item, 10, 64)
		if err == nil {
			return parsed, nil
		}
	case bool:
		if item {
			return 1, nil
		}
		return 0, nil
	case int:
		return int64(item), nil
	case int64:
		return item, nil
	case float64:
		return int64(item), nil
	}
	return 0, fmt.Errorf("Invalid value for integer: '%v'", value)
}

func castFloat(value any) (float64, error) {
	switch item := value.(type) {
	case string:
		parsed, err := strconv.ParseFloat(item, 64)
		if err == nil {
			return parsed, nil
		}
	case bool:
		if item {
			return 1, nil
		}
		return 0, nil
	case int:
		return float64(item), nil
	case int64:
		return float64(item), nil
	case float64:
		return item, nil
	}
	return 0, fmt.Errorf("Invalid value for float: '%v'", value)
}

func plistMap(value any) (map[string]any, bool) {
	switch item := value.(type) {
	case map[string]any:
		return item, true
	case map[string]string:
		out := map[string]any{}
		for key, value := range item {
			out[key] = value
		}
		return out, true
	case map[any]any:
		out := map[string]any{}
		for key, value := range item {
			text, ok := key.(string)
			if !ok {
				return nil, false
			}
			out[text] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func plistArray(value any) ([]any, bool) {
	switch item := value.(type) {
	case []any:
		return item, true
	case []string:
		out := make([]any, len(item))
		for i, value := range item {
			out[i] = value
		}
		return out, true
	default:
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// public functions

type writeArgs struct {
	Domain       string  `statekit:"required,name=domain"`
	Key          string  `statekit:"required,name=key"`
	Value        any     `statekit:"required,name=value"`
	VType        *string `statekit:"name=vtype"`
	User         *string `statekit:"name=user"`
	KeySeparator *string `statekit:"name=key_separator"`
	DictMerge    bool    `statekit:"name=dict_merge"`
	ArrayAdd     bool    `statekit:"name=array_add"`
	Type         *string `statekit:"name=type"`
}

type writeFunc struct{}

func (writeFunc) Name() string        { return "macdefaults.write" }
func (writeFunc) Args() any           { return writeArgs{} }
func (writeFunc) Platforms() []string { return []string{"darwin"} }
func (writeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacDefaults(&res, &err)
	a := args.(*writeArgs)
	return writeImpl(ctx, rt, a)
}

func writeImpl(ctx context.Context, rt *runtime.Runtime, a *writeArgs) (any, error) {
	plist, err := loadDomainPlist(ctx, rt, a.Domain, a.User)
	if err != nil {
		return nil, err
	}
	if plist == nil {
		plist = map[string]any{}
	}
	keys, err := splitKeys(a.Key, a.KeySeparator)
	if err != nil {
		return nil, err
	}
	container, last, ok := parentAndLast(plist, keys)
	if !ok {
		return nil, fmt.Errorf("Key not found: %s for domain: %s", a.Key, a.Domain)
	}
	value := a.Value
	vtype := a.VType
	if a.Type != nil {
		if vtype == nil {
			vtype = a.Type
		}
	}
	if vtype != nil {
		if *vtype == "array-add" {
			a.ArrayAdd = true
		}
		if *vtype == "dict-add" {
			a.DictMerge = true
		}
		value, err = castValueToVType(value, *vtype)
		if err != nil {
			return nil, err
		}
	}

	switch target := container.(type) {
	case map[string]any:
		current := target[last]
		if oldMap, ok := plistMap(current); ok {
			if newMap, ok := plistMap(value); ok && a.DictMerge {
				for key, item := range newMap {
					oldMap[key] = item
				}
				value = oldMap
			}
		}
		if oldArray, ok := plistArray(current); ok && a.ArrayAdd {
			if newArray, ok := plistArray(value); ok {
				oldArray = append(oldArray, newArray...)
				value = oldArray
			} else {
				value = append(oldArray, value)
			}
		}
		target[last] = value
	case []any:
		index, ok := listIndex(last, len(target))
		if !ok {
			return nil, fmt.Errorf("Index %s is out of range for domain: %s", last, a.Domain)
		}
		if a.ArrayAdd {
			if newArray, ok := plistArray(value); ok {
				if oldArray, isArray := plistArray(target[index]); isArray {
					target[index] = append(oldArray, newArray...)
				} else {
					target[index] = newArray
				}
			} else if oldArray, ok := plistArray(target[index]); ok {
				target[index] = append(oldArray, value)
			} else {
				target[index] = value
			}
		} else {
			target[index] = value
		}
	default:
		return nil, fmt.Errorf("Key not found: %s for domain: %s", a.Key, a.Domain)
	}
	return saveDomainPlist(ctx, rt, a.Domain, plist, a.User)
}

type readArgs struct {
	Domain       string  `statekit:"required,name=domain"`
	Key          string  `statekit:"required,name=key"`
	User         *string `statekit:"name=user"`
	KeySeparator *string `statekit:"name=key_separator"`
}

type readFunc struct{}

func (readFunc) Name() string        { return "macdefaults.read" }
func (readFunc) Args() any           { return readArgs{} }
func (readFunc) Platforms() []string { return []string{"darwin"} }
func (readFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacDefaults(&res, &err)
	a := args.(*readArgs)
	plist, err := loadDomainPlist(ctx, rt, a.Domain, a.User)
	if err != nil || plist == nil {
		return nil, err
	}
	keys, err := splitKeys(a.Key, a.KeySeparator)
	if err != nil {
		return nil, err
	}
	value, _ := traverse(plist, keys)
	return value, nil
}

type deleteArgs struct {
	Domain       string  `statekit:"required,name=domain"`
	Key          string  `statekit:"required,name=key"`
	User         *string `statekit:"name=user"`
	KeySeparator *string `statekit:"name=key_separator"`
}

type deleteFunc struct{}

func (deleteFunc) Name() string        { return "macdefaults.delete" }
func (deleteFunc) Args() any           { return deleteArgs{} }
func (deleteFunc) Platforms() []string { return []string{"darwin"} }
func (deleteFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacDefaults(&res, &err)
	a := args.(*deleteArgs)
	plist, err := loadDomainPlist(ctx, rt, a.Domain, a.User)
	if err != nil || plist == nil {
		return nil, err
	}
	keys, err := splitKeys(a.Key, a.KeySeparator)
	if err != nil {
		return nil, err
	}
	if _, changed := deletePath(plist, keys); !changed {
		return nil, nil
	}
	return saveDomainPlist(ctx, rt, a.Domain, plist, a.User)
}

type castValueArgs struct {
	Value any    `statekit:"required,name=value"`
	VType string `statekit:"required,name=vtype"`
}

type castValueFunc struct{}

func (castValueFunc) Name() string        { return "macdefaults.cast_value_to_vtype" }
func (castValueFunc) Args() any           { return castValueArgs{} }
func (castValueFunc) Platforms() []string { return []string{"darwin"} }
func (castValueFunc) Execute(_ context.Context, _ *runtime.Runtime, args any) (res any, err error) {
	defer recoverMacDefaults(&res, &err)
	a := args.(*castValueArgs)
	return castValueToVType(a.Value, a.VType)
}

func recoverMacDefaults(res *any, errPtr *error) {
	if r := recover(); r != nil {
		if err, ok := r.(error); ok {
			*errPtr = err
			return
		}
		panic(r)
	}
}

// Register installs the four public macdefaults functions. The functions
// remain in the registry on every build, while Runtime.Names filters them
// to darwin through PlatformConstrained.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		writeFunc{}, readFunc{}, deleteFunc{}, castValueFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
