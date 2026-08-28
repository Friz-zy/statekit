package macdefaults

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const plistFixture = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AllowClipboardAccess</key>
	<true/>
	<key>AppleAntiAliasingThreshold</key>
	<integer>1024</integer>
	<key>NoSyncBFPRecents</key>
	<array>
		<string>MonoLisa Variable</string>
		<string>Menlo</string>
		<string>MonoLisa</string>
	</array>
	<key>NoSyncFrame_SharedPreferences</key>
	<dict>
		<key>screenFrame</key>
		<string>{{0, 0}, {1920, 1200}}</string>
		<key>topLeft</key>
		<string>{668, 1004}</string>
	</dict>
	<key>NoSyncNextAnnoyanceTime</key>
	<real>699041775.9120981</real>
	<key>SULastCheckTime</key>
	<date>2024-06-23T09:33:44Z</date>
</dict>
</plist>`

type defaultsTestRunner struct {
	fs          *runtime.MemoryFS
	stdout      string
	stderr      string
	retcode     int
	calls       []process.Command
	importBytes []byte
}

func (r *defaultsTestRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if strings.Contains(command.Name, " export ") {
		return process.CommandResult{ExitCode: r.retcode, Stdout: []byte(r.stdout), Stderr: []byte(r.stderr)}
	}
	if strings.Contains(command.Name, " import ") && r.fs != nil {
		last := strings.LastIndex(command.Name, `"`)
		if last > 0 {
			before := command.Name[:last]
			first := strings.LastIndex(before, `"`)
			if first >= 0 {
				path := before[first+1:]
				r.importBytes, _ = r.fs.ReadFile(path)
			}
		}
	}
	return process.CommandResult{ExitCode: r.retcode, Stdout: []byte(r.stdout), Stderr: []byte(r.stderr)}
}

func macRuntime(t *testing.T) (*runtime.Runtime, *defaultsTestRunner) {
	t.Helper()
	fs := runtime.NewMemoryFS()
	runner := &defaultsTestRunner{fs: fs, stdout: plistFixture}
	return &runtime.Runtime{FS: fs, Runner: runner}, runner
}

func callMac(t *testing.T, rt *runtime.Runtime, fn runtime.ExecFunction, args any) (any, error) {
	t.Helper()
	return fn.Execute(context.Background(), rt, args)
}

func TestCastValueToVType(t *testing.T) {
	tests := []struct {
		value any
		vtype string
		want  any
	}{
		{"TRUE", "bool", true},
		{"NO", "boolean", false},
		{"124", "int", int64(124)},
		{"14.350", "float", 14.35},
		{"2024-06-23T09:33:44Z", "date", time.Date(2024, 6, 23, 9, 33, 44, 0, time.UTC)},
		{"foo", "data", []byte("foo")},
		{true, "string", "YES"},
		{false, "string", "NO"},
	}
	for _, test := range tests {
		got, err := castValueToVType(test.value, test.vtype)
		if err != nil {
			t.Fatalf("cast %v/%s: %v", test.value, test.vtype, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("cast %v/%s = %#v, want %#v", test.value, test.vtype, got, test.want)
		}
	}
	if _, err := castValueToVType("nope", "bool"); err == nil ||
		!strings.Contains(err.Error(), "Invalid value for boolean") {
		t.Fatalf("invalid bool = %v", err)
	}
	if _, err := castValueToVType("x", "dict"); err == nil {
		t.Fatal("scalar accepted as dict")
	}
	if got, err := castValueToVType(map[string]any{"x": 1}, "dict"); err != nil || got == nil {
		t.Fatalf("map cast = %#v %v", got, err)
	}
}

func TestReadNestedTypesAndEmptyDomain(t *testing.T) {
	rt, runner := macRuntime(t)
	res, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "AllowClipboardAccess"})
	if err != nil || res != true {
		t.Fatalf("bool read = %#v %v", res, err)
	}
	res, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "AppleAntiAliasingThreshold"})
	if err != nil || res != int64(1024) {
		t.Fatalf("integer read = %#v %v", res, err)
	}
	separator := "."
	res, err = callMac(t, rt, readFunc{}, &readArgs{
		Domain: "com.example", Key: "NoSyncFrame_SharedPreferences.topLeft", KeySeparator: &separator,
	})
	if err != nil || res != "{668, 1004}" {
		t.Fatalf("nested read = %#v %v", res, err)
	}
	res, err = callMac(t, rt, readFunc{}, &readArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.1", KeySeparator: &separator,
	})
	if err != nil || res != "Menlo" {
		t.Fatalf("array read = %#v %v", res, err)
	}
	if len(runner.calls) != 4 || !strings.Contains(runner.calls[0].Name, "defaults export") {
		t.Fatalf("runner calls = %+v", runner.calls)
	}

	runner.stdout = `<?xml version="1.0"?><plist version="1.0"><dict/></plist>`
	res, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "missing", Key: "key"})
	if err != nil || res != nil {
		t.Fatalf("empty domain = %#v %v", res, err)
	}
}

func TestWriteMergeAndArrayAdd(t *testing.T) {
	rt, runner := macRuntime(t)
	separator := "."
	merge := true
	res, err := callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncFrame_SharedPreferences", Value: map[string]any{"new": true},
		DictMerge: merge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["retcode"] != 0 || len(runner.importBytes) == 0 {
		t.Fatalf("dict write = %#v import=%d", res, len(runner.importBytes))
	}
	parsed, err := loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	root := parsed.(map[string]any)
	nested := root["NoSyncFrame_SharedPreferences"].(map[string]any)
	if nested["new"] != true || nested["topLeft"] != "{668, 1004}" {
		t.Fatalf("merged dict = %#v", nested)
	}

	runner.importBytes = nil
	res, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents", Value: []any{"New"}, ArrayAdd: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	items := parsed.(map[string]any)["NoSyncBFPRecents"].([]any)
	if len(items) != 4 || items[3] != "New" {
		t.Fatalf("array add = %#v", items)
	}

	// An array-add request against a scalar list element replaces that
	// element with the supplied array rather than panicking on a type cast.
	runner.importBytes = nil
	res, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.0", Value: []any{"Nested"},
		ArrayAdd: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["retcode"] != 0 {
		t.Fatalf("scalar array-add = %#v", res)
	}

	_, err = callMac(t, rt, writeFunc{}, &writeArgs{
		Domain: "com.example", Key: "Missing.Container", Value: "x", KeySeparator: &separator,
	})
	if err == nil || !strings.Contains(err.Error(), "Key not found") {
		t.Fatalf("missing parent = %v", err)
	}
}

func TestDeleteNestedArrayAndTimestampError(t *testing.T) {
	rt, runner := macRuntime(t)
	separator := "."
	res, err := callMac(t, rt, deleteFunc{}, &deleteArgs{
		Domain: "com.example", Key: "NoSyncBFPRecents.1", KeySeparator: &separator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["retcode"] != 0 {
		t.Fatalf("delete result = %#v", res)
	}
	parsed, err := loadPlist(runner.importBytes)
	if err != nil {
		t.Fatal(err)
	}
	items := parsed.(map[string]any)["NoSyncBFPRecents"].([]any)
	if !reflect.DeepEqual(items, []any{"MonoLisa Variable", "MonoLisa"}) {
		t.Fatalf("deleted array = %#v", items)
	}

	runner.stdout = ""
	runner.stderr = "2024-06-23 09:33:44.123 defaults[123:456] domain error\nsecond line"
	runner.retcode = 1
	_, err = callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "x"})
	if err == nil || !strings.Contains(err.Error(), "Failed to export defaults: second line") ||
		strings.Contains(err.Error(), "defaults[123:456]") {
		t.Fatalf("timestamp error = %v", err)
	}
}

func TestUserBoundaryAndDarwinPlatform(t *testing.T) {
	rt, _ := macRuntime(t)
	user := "alice"
	_, err := callMac(t, rt, readFunc{}, &readArgs{Domain: "com.example", Key: "x", User: &user})
	if err == nil || !strings.Contains(err.Error(), "runas is not supported by statekit") {
		t.Fatalf("runas boundary = %v", err)
	}
	platforms := (writeFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
