package macdefaults

// R6.10 mock tests for the macdefaults core, mapped onto
// saltstack/salt/modules/macdefaults.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_macdefaults.py: vtype casting
// through the write pipeline, the deprecated type= alias precedence,
// array-index boundaries, delete miss short-circuits, plist loader
// error branches, encoder coverage, shell quoting/timestamp helpers
// and the registry matrix. All defaults(1) output is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

func newExecRegistryMacDefaults(t *testing.T) *runtime.ExecRegistry {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestWriteCastsVTypeIntoPlist(t *testing.T) {
	vectors := []struct {
		name    string
		args    *writeArgs
		fixture string // substring expected in the imported plist
	}{
		{
			name:    "bool yes",
			args:    &writeArgs{Domain: "com.example", Key: "NewBool", Value: "yes", VType: strPtrD("bool")},
			fixture: "<true/>",
		},
		{
			name:    "int string",
			args:    &writeArgs{Domain: "com.example", Key: "NewInt", Value: "124", VType: strPtrD("int")},
			fixture: "<integer>124</integer>",
		},
		{
			name:    "float string",
			args:    &writeArgs{Domain: "com.example", Key: "NewFloat", Value: "14.35", VType: strPtrD("float")},
			fixture: "<real>14.35</real>",
		},
		{
			name:    "data string",
			args:    &writeArgs{Domain: "com.example", Key: "NewData", Value: "foo", VType: strPtrD("data")},
			fixture: "<data>Zm9v</data>",
		},
		{
			name:    "date epoch seconds",
			args:    &writeArgs{Domain: "com.example", Key: "NewDate", Value: "737720347", VType: strPtrD("date")},
			fixture: "<date>1993-05-18T10:19:07Z</date>",
		},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			rt, runner := macRuntime(t)
			res, err := callMac(t, rt, writeFunc{}, vector.args)
			if err != nil {
				t.Fatal(err)
			}
			if ret := res.(map[string]any)["retcode"]; ret != 0 {
				t.Fatalf("retcode = %v", ret)
			}
			if !strings.Contains(string(runner.importBytes), vector.fixture) {
				t.Fatalf("import plist missing %q:\n%s", vector.fixture, runner.importBytes)
			}
		})
	}
}

func strPtrD(value string) *string { return &value }

func TestWriteTypeAliasPrecedence(t *testing.T) {
	// Salt: the deprecated type= fills vtype only when vtype is None;
	// when both are given vtype wins (warn-and-precedence contract).
	rt, runner := macRuntime(t)
	_, err := callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NewKey", Value: "124", Type: strPtrD("int"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runner.importBytes), "<integer>124</integer>") {
		t.Fatalf("type alias import = %s", runner.importBytes)
	}
	runner.importBytes = nil
	_, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NewKey", Value: "124",
		Type: strPtrD("string"), VType: strPtrD("int"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(runner.importBytes)
	if !strings.Contains(body, "<integer>124</integer>") || strings.Contains(body, "<string>124</string>") {
		t.Fatalf("vtype precedence import = %s", body)
	}
}

func TestWriteVTypeAddFlagsAndIndexBounds(t *testing.T) {
	rt, runner := macRuntime(t)
	// vtype=array-add appends rather than replacing (pytest write
	// array-add contract).
	_, err := callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents", Value: []any{"Extra"}, VType: strPtrD("array-add"),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	items := parsed.(map[string]any)["NoSyncBFPRecents"].([]any)
	if len(items) != 4 || items[3] != "Extra" {
		t.Fatalf("array-add via vtype = %#v", items)
	}
	// out-of-range index on an array container is the Salt IndexError text
	sep := "."
	_, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.9", Value: "x", KeySeparator: &sep,
	})
	if err == nil || err.Error() != "Index 9 is out of range for domain: com.example" {
		t.Fatalf("index bound = %v", err)
	}
	// non-numeric last segment on an array container is also out of range
	_, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.first", Value: "x", KeySeparator: &sep,
	})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("non-numeric index = %v", err)
	}
	// array index write replaces the scalar in place
	runner.importBytes = nil
	_, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.0", Value: "Replaced", KeySeparator: &sep,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	items = parsed.(map[string]any)["NoSyncBFPRecents"].([]any)
	if items[0] != "Replaced" || len(items) != 3 {
		t.Fatalf("index write = %#v", items)
	}
}

func TestDeleteMissesNeverSave(t *testing.T) {
	rt, runner := macRuntime(t)
	sep := "."
	imports := func() int {
		count := 0
		for _, command := range runner.calls {
			if strings.Contains(command.Name, " import ") {
				count++
			}
		}
		return count
	}
	// key absent from the domain → None without an import (Salt returns
	// None before _save_plist); only the export read is performed.
	res, err := callMac(t, rt, deleteFunc{}, &deleteArgs{Domain: "com.example", Key: "Missing"})
	if err != nil || res != nil {
		t.Fatalf("missing key delete = %v %v", res, err)
	}
	// parent path missing
	res, err = callMac(t, rt, deleteFunc{}, &deleteArgs{Domain: "com.example", Key: "Missing.parent.child", KeySeparator: &sep})
	if err != nil || res != nil {
		t.Fatalf("missing parent delete = %v %v", res, err)
	}
	// array index out of range
	res, err = callMac(t, rt, deleteFunc{}, &deleteArgs{Domain: "com.example", Key: "NoSyncBFPRecents.9", KeySeparator: &sep})
	if err != nil || res != nil {
		t.Fatalf("out-of-range delete = %v %v", res, err)
	}
	if imports() != 0 {
		t.Fatalf("miss deletes issued %d imports", imports())
	}
	// empty domain short-circuits to None too
	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><dict/></plist>`
	res, err = callMac(t, rt, deleteFunc{}, &deleteArgs{Domain: "com.example", Key: "k"})
	if err != nil || res != nil {
		t.Fatalf("empty domain delete = %v %v", res, err)
	}
	if imports() != 0 {
		t.Fatalf("empty domain delete issued %d imports", imports())
	}
}

func TestDeleteNestedDictKey(t *testing.T) {
	rt, runner := macRuntime(t)
	sep := "."
	res, err := callMac(t, rt, deleteFunc{}, &deleteArgs{
		Domain: "com.example", Key: "NoSyncFrame_SharedPreferences.topLeft", KeySeparator: &sep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ret := res.(map[string]any)["retcode"]; ret != 0 {
		t.Fatalf("retcode = %v", ret)
	}
	parsed, err := loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	nested := parsed.(map[string]any)["NoSyncFrame_SharedPreferences"].(map[string]any)
	if _, exists := nested["topLeft"]; exists {
		t.Fatalf("key not deleted: %#v", nested)
	}
	if nested["screenFrame"] != "{{0, 0}, {1920, 1200}}" {
		t.Fatalf("sibling lost = %#v", nested)
	}
}

func TestReadMissingKeyReturnsNil(t *testing.T) {
	rt, _ := macRuntime(t)
	res, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "Nope"})
	if err != nil || res != nil {
		t.Fatalf("missing read = %v %v", res, err)
	}
	sep := "."
	res, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "NoSyncBFPRecents.9", KeySeparator: &sep})
	if err != nil || res != nil {
		t.Fatalf("out-of-range read = %v %v", res, err)
	}
	res, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "Missing.deep.path", KeySeparator: &sep})
	if err != nil || res != nil {
		t.Fatalf("deep missing read = %v %v", res, err)
	}
}

func TestLoadPlistErrorBranches(t *testing.T) {
	rt, _ := macRuntime(t)
	// binary plist exports are rejected by the stdlib port boundary
	runner := rt.Runner.(*defaultsTestRunner)
	runner.stdout = "bplist00\xd0\x11"
	_, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "k"})
	if err == nil || err.Error() != "binary plist export is not supported by statekit" {
		t.Fatalf("binary plist = %v", err)
	}
	// a non-dictionary root is rejected
	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><array><string>x</string></array></plist>`
	_, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "k"})
	if err == nil || err.Error() != "defaults export did not contain a plist dictionary" {
		t.Fatalf("array root = %v", err)
	}
	// a dict value without a preceding key is malformed
	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><dict><string>orphan</string></dict></plist>`
	_, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "k"})
	if err == nil || err.Error() != "plist dictionary value has no key" {
		t.Fatalf("orphan value = %v", err)
	}
	// unknown plist elements are unsupported
	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><dict><key>k</key><foo>bar</foo></dict></plist>`
	_, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "k"})
	if err == nil || err.Error() != "unsupported plist element <foo>" {
		t.Fatalf("unsupported element = %v", err)
	}
	// no root element at all
	runner.stdout = `<?xml version="1.0"?>`
	_, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "k"})
	if err == nil || err.Error() != "plist root value not found" {
		t.Fatalf("no root = %v", err)
	}
}

func TestLoadPlistDataAndReal(t *testing.T) {
	// <data> base64 and <real> float values round-trip through reads.
	rt, _ := macRuntime(t)
	runner := rt.Runner.(*defaultsTestRunner)
	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>blob</key><data>AAECAw==</data>` +
		`<key>ratio</key><real>0.25</real>` +
		`</dict></plist>`
	res, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "blob"})
	if err != nil || !reflect.DeepEqual(res, []byte{0, 1, 2, 3}) {
		t.Fatalf("data read = %#v %v", res, err)
	}
	res, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "ratio"})
	if err != nil || res != 0.25 {
		t.Fatalf("real read = %#v %v", res, err)
	}
}

func TestEncodePlistTypes(t *testing.T) {
	epoch := time.Date(2024, 6, 23, 9, 33, 44, 0, time.UTC)
	data, err := encodePlist(map[string]any{
		"s":   "<string & escape>",
		"b":   []byte{0, 1, 2},
		"d":   epoch,
		"f":   1.5,
		"i":   int64(-7),
		"bl":  false,
		"arr": []any{"x", int64(2)},
		"m":   map[string]string{"k": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"<string>&lt;string &amp; escape&gt;</string>",
		"<data>AAEC</data>",
		"<date>2024-06-23T09:33:44Z</date>",
		"<real>1.5</real>",
		"<integer>-7</integer>",
		"<false/>",
		"<array><string>x</string><integer>2</integer></array>",
		"<dict><key>k</key><string>v</string></dict>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("encode missing %q in:\n%s", want, body)
		}
	}
	if !strings.HasPrefix(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") ||
		!strings.HasSuffix(body, "</plist>\n") {
		t.Fatalf("envelope = %q", body[:40])
	}
	if _, err := encodePlist(map[string]any{"nil": nil}); err == nil ||
		err.Error() != "nil is not a plist value" {
		t.Fatalf("nil encode = %v", err)
	}
	if _, err := encodePlist(map[string]any{"bad": struct{ X int }{1}}); err == nil ||
		!strings.Contains(err.Error(), "unsupported plist value") {
		t.Fatalf("unsupported encode = %v", err)
	}
	// encoded output parses back (round-trip through loadPlist)
	parsed, err := loadPlist(data)
	if err != nil {
		t.Fatal(err)
	}
	root := parsed.(map[string]any)
	if root["f"] != 1.5 || root["i"] != int64(-7) || root["bl"] != false {
		t.Fatalf("round-trip = %#v", root)
	}
}

func TestShellDoubleQuoteEscaping(t *testing.T) {
	vectors := map[string]string{
		`plain`:           `"plain"`,
		`back\slash`:      `"back\\slash"`,
		`dou"ble`:         `"dou\"ble"`,
		`dollar$var`:      `"dollar\$var"`,
		"back`tick":       "\"back\\`tick\"",
		`com.example/sub`: `"com.example/sub"`,
	}
	for input, want := range vectors {
		if got := shellDoubleQuote(input); got != want {
			t.Fatalf("shellDoubleQuote(%q) = %q; want %q", input, got, want)
		}
	}
	// the export action embeds the quoted domain in the shell command
	rt, runner := macRuntime(t)
	if _, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example odd", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(runner.calls[0].Name, `defaults export "com.example odd" -`) {
		t.Fatalf("export command = %q", runner.calls[0].Name)
	}
}

func TestRemoveTimestampCases(t *testing.T) {
	vectors := []struct {
		in   string
		want string
	}{
		{"plain failure", "plain failure"},
		// single-line timestamped stderr collapses to empty (Salt drops
		// the only line: splitlines[1:] of a 1-line text)
		{"2024-06-23 09:33:44 defaults[123:456] real message", ""},
		// the whole timestamped first line is dropped, later lines stay
		{"2024-06-23 09:33:44.123 defaults[123:456] line one\nline two", "line two"},
	}
	for _, vector := range vectors {
		if got := removeTimestamp(vector.in); got != vector.want {
			t.Fatalf("removeTimestamp(%q) = %q; want %q", vector.in, got, vector.want)
		}
	}
	// a timestamp-only stderr collapses to empty
	if got := removeTimestamp("2024-06-23 09:33:44 defaults[1:2]"); got != "" {
		t.Fatalf("timestamp only = %q", got)
	}
	// mid-text timestamps are anchored to the start and kept
	embedded := "prefix 2024-06-23 09:33:44 defaults[1:2] suffix"
	if got := removeTimestamp(embedded); got != embedded {
		t.Fatalf("embedded timestamp = %q", got)
	}
}

func TestSplitKeysAndRunDefaultsShape(t *testing.T) {
	if got, err := splitKeys("a.b", nil); err != nil || !reflect.DeepEqual(got, []string{"a.b"}) {
		t.Fatalf("nil separator = %v %v", got, err)
	}
	sep := "."
	if got, err := splitKeys("a.b.c", &sep); err != nil || !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("separator split = %v %v", got, err)
	}
	empty := ""
	if _, err := splitKeys("a", &empty); err == nil || err.Error() != "empty key separator" {
		t.Fatalf("empty separator = %v", err)
	}
	// runDefaults returns the cmd.run_all shape on success
	rt, _ := macRuntime(t)
	ret := runDefaults(context.Background(), rt, `read "com.apple.CrashReporter" "DialogType"`, nil)
	if ret["retcode"] != 0 {
		t.Fatalf("retcode = %v", ret["retcode"])
	}
	if _, ok := ret["stdout"].(string); !ok {
		t.Fatalf("stdout type = %T", ret["stdout"])
	}
	if _, ok := ret["stderr"].(string); !ok {
		t.Fatalf("stderr type = %T", ret["stderr"])
	}
}

func TestSaveDomainPlistUserBoundary(t *testing.T) {
	rt, _ := macRuntime(t)
	user := "alice"
	// a delete whose path resolution succeeds still cannot save as
	// another user (runas boundary).
	_, err := callMac(t, rt, deleteFunc{}, &deleteArgs{
		Domain: "com.example", Key: "AllowClipboardAccess", User: &user,
	})
	// loadDomainPlist rejects the user before any traversal happens
	if err == nil || !strings.Contains(err.Error(), "runas is not supported by statekit") {
		t.Fatalf("save boundary = %v", err)
	}
}

func TestMacDefaultsRegisteredNamesAndDispatch(t *testing.T) {
	reg := newExecRegistryMacDefaults(t)
	want := []string{
		"macdefaults.cast_value_to_vtype",
		"macdefaults.delete",
		"macdefaults.read",
		"macdefaults.write",
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
	rt, _ := macRuntime(t)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "macdefaults.cast_value_to_vtype", &castValueArgs{Value: "yes", VType: "bool"})
		if err != nil || res != true {
			t.Fatalf("dispatch = %v %v", res, err)
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "macdefaults.cast_value_to_vtype", &castValueArgs{Value: "yes", VType: "bool"}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
