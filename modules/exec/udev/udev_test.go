package udev

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	results map[string]process.CommandResult
	calls   [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, " ")]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		panic(err)
	}
	return rt, runner
}

// Mirrors test_info's fixture: env extracts the E section with numeric
// coercion and single-element collapse for other sections.
func TestEnvNameQuery(t *testing.T) {
	stdout := "P: /devices/virtual/vc/vcsa7\n" +
		"N: vcsa7\n" +
		"E: DEVNAME=/dev/vcsa7\n" +
		"E: DEVPATH=/devices/virtual/vc/vcsa7\n" +
		"E: MAJOR=7\n" +
		"E: MINOR=135\n" +
		"E: SUBSYSTEM=vc\n" +
		"\n"
	rt, runner := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/vcsa7": {Stdout: []byte(stdout)},
	})

	gotRaw, err := envFunc{}.Execute(context.Background(), rt, &EnvArgs{Dev: "/dev/vcsa7"})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	want := map[string]any{
		"DEVNAME":   "/dev/vcsa7",
		"DEVPATH":   "/devices/virtual/vc/vcsa7",
		"MAJOR":     int64(7),
		"MINOR":     int64(135),
		"SUBSYSTEM": "vc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %#v, want %#v", got, want)
	}

	// /dev names query through --name=; no shell involved.
	argv := runner.calls[0]
	last := argv[len(argv)-1]
	if last != "--name=/dev/vcsa7" || argv[0] != "udevadm" || !reflect.DeepEqual(argv[:4],
		[]string{"udevadm", "info", "--export", "--query=all"}) {
		t.Fatalf("argv = %v", argv)
	}
}

// A dev containing "sys" switches udevadm to the path query.
func TestEnvPathQuery(t *testing.T) {
	rt, runner := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --path=/sys/class/net/eth0": {Stdout: []byte("")},
	})
	if _, err := (&envFunc{}).Execute(context.Background(), rt, &EnvArgs{Dev: "/sys/class/net/eth0"}); err == nil {
		t.Fatal("expected error for empty record")
	}
	if last := runner.calls[0][len(runner.calls[0])-1]; last != "--path=/sys/class/net/eth0" {
		t.Fatalf("query type argv = %v", runner.calls[0])
	}
}

// Multi-device exportdb-style output: env reports the first record only,
// lists collapse when they carry a single element.
func TestParseInfoMultiDevice(t *testing.T) {
	devices := parseInfo("" +
		"P: /devices/LNXSYSTM:00/LNXPWRBN:00\n" +
		"E: DEVPATH=/devices/LNXSYSTM:00/LNXPWRBN:00\n" +
		"E: DRIVER=button\n" +
		"E: ID_INPUT=1\n" +
		"\n" +
		"P: /devices/input/event2\n" +
		"N: input/event2\n" +
		"S: input/by-id/x\n" +
		"S: input/by-path/y\n" +
		"E: MAJOR=13\n" +
		"\n")
	if len(devices) != 2 {
		t.Fatalf("device count = %d", len(devices))
	}
	first := devices[0]
	// Single-element sections collapse to scalars; E stays a dict.
	if first["P"] != "/devices/LNXSYSTM:00/LNXPWRBN:00" {
		t.Fatalf("first P = %#v", first["P"])
	}
	env := first["E"].(map[string]any)
	if env["ID_INPUT"] != int64(1) {
		t.Fatalf("numeric coercion = %#v", env["ID_INPUT"])
	}
	if devices[1]["N"] != "input/event2" {
		t.Fatalf("collapsed N = %#v", devices[1]["N"])
	}
	links, ok := devices[1]["S"].([]any)
	if !ok || len(links) != 2 {
		t.Fatalf("multi-element S = %#v", devices[1]["S"])
	}
}

// Non-zero retcodes surface the stderr as an error (Salt raises
// CommandExecutionError).
func TestEnvRetcodeFailure(t *testing.T) {
	rt, _ := newRT(map[string]process.CommandResult{
		"udevadm info --export --query=all --name=/dev/gone": {ExitCode: 1, Stderr: []byte("Unknown device")},
	})
	_, err := envFunc{}.Execute(context.Background(), rt, &EnvArgs{Dev: "/dev/gone"})
	if err == nil || !strings.Contains(err.Error(), "Unknown device") {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	if !names["udev.env"] {
		t.Fatal("missing udev.env registration")
	}
	for _, unplanned := range []string{"udev.info", "udev.name", "udev.path", "udev.links", "udev.exportdb"} {
		if names[unplanned] {
			t.Fatalf("%s must stay unregistered this round", unplanned)
		}
	}
}
