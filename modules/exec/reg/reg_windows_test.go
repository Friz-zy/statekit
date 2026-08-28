//go:build windows

package reg

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type regTestRunner struct{ calls []process.Command }

func (r *regTestRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	return process.CommandResult{ExitCode: 0, Stdout: []byte("HKEY_LOCAL_MACHINE\\SOFTWARE\n    Version    REG_SZ    1.2.3\n")}
}

func TestRegistryParserAndConversions(t *testing.T) {
	value, ok := parseRegValueLine("    Count    REG_DWORD    0x2a\r")
	if !ok || value["vname"] != "Count" || value["vtype"] != "REG_DWORD" || value["vdata"] != uint64(42) {
		t.Fatalf("DWORD parse = %#v %v", value, ok)
	}
	value, ok = parseRegValueLine("    Names    REG_MULTI_SZ    one\\0two")
	if !ok || !reflect.DeepEqual(value["vdata"], []string{"one", "two"}) {
		t.Fatalf("MULTI_SZ parse = %#v %v", value, ok)
	}
	if got := convertRegData("0x10", "REG_QWORD"); got != uint64(16) {
		t.Fatalf("QWORD = %#v", got)
	}
	if got := convertRegData("0A FF", "REG_BINARY"); !reflect.DeepEqual(got, []byte{0x0a, 0xff}) {
		t.Fatalf("binary = %#v", got)
	}
	if got := regPath("HKLM", `SOFTWARE\\Salt`); got != `HKLM\\SOFTWARE\\Salt` {
		t.Fatalf("reg path = %q", got)
	}
	if regSwitch(true) != "/reg:32" || regSwitch(false) != "/reg:64" {
		t.Fatal("registry view switches incorrect")
	}
	if validateHive("HKLM") != nil || validateHive("NOPE") == nil {
		t.Fatal("hive validation incorrect")
	}
}

func TestRegistryDataStringAndCommand(t *testing.T) {
	if got, ok := regDataString([]byte{0, 0xff}, "REG_BINARY"); !ok || got != "00FF" {
		t.Fatalf("binary data string = %q %v", got, ok)
	}
	if got, ok := regDataString([]string{"one", "two"}, "REG_MULTI_SZ"); !ok || got != "one\\0two" {
		t.Fatalf("multi data string = %q %v", got, ok)
	}
	runner := &regTestRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := keyExistsFunc{}.Execute(context.Background(), rt, &keyExistsArgs{Hive: "HKLM", Key: `SOFTWARE\\Salt`})
	if err != nil || res != true {
		t.Fatalf("key exists = %v %v", res, err)
	}
	if len(runner.calls) != 1 || !strings.Contains(strings.Join(runner.calls[0].Args, " "), "/reg:64") {
		t.Fatalf("query command = %+v", runner.calls)
	}
}
