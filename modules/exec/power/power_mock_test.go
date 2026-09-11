package power

// R6.11 mock tests for the mac_power surface, mapped onto
// saltstack/salt/modules/mac_power.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_power.py plus
// salt.utils.mac_utils confirm_updated semantics: exact
// systemsetup argv/order for every getter and setter, the Salt error
// texts of _validate_sleep/validate_enabled, retry-loop behavior and
// the registry matrix. All Runner output is scripted.

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// powerMockRunner keeps a live systemsetup state store so set/get flows
// observe their own writes like the real daemon.
type powerMockRunner struct {
	minutes map[string]string
	flags   map[string]bool
	failSet string // "-setsleep" etc. forced to retcode 1 when non-empty
	calls   []process.Command
}

func (r *powerMockRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "systemsetup" || len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	flag := command.Args[0]
	if len(command.Args) >= 2 && strings.HasPrefix(flag, "-set") {
		if flag == r.failSet {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("systemsetup: error")}
		}
		value := command.Args[1]
		switch flag {
		case "-setsleep":
			for key := range r.minutes {
				r.minutes[key] = value
			}
		case "-setcomputersleep":
			r.minutes["computer"] = value
		case "-setdisplaysleep":
			r.minutes["display"] = value
		case "-setharddisksleep":
			r.minutes["disk"] = value
		case "-setwakeonmodem":
			r.flags["modem"] = value == "on"
		case "-setwakeonnetworkaccess":
			r.flags["network"] = value == "on"
		case "-setrestartpowerfailure":
			r.flags["failure"] = value == "on"
		case "-setrestartfreeze":
			r.flags["freeze"] = value == "on"
		case "-setallowpowerbuttontosleepcomputer":
			r.flags["button"] = value == "on"
		}
		return process.CommandResult{ExitCode: 0}
	}
	switch flag {
	case "-getcomputersleep":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Computer Sleep: " + r.minutes["computer"])}
	case "-getdisplaysleep":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Display Sleep: " + r.minutes["display"])}
	case "-getharddisksleep":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("Hard Disk Sleep: " + r.minutes["disk"])}
	case "-getwakeonmodem":
		return powerMockBool(r.flags["modem"], "Wake On Modem")
	case "-getwakeonnetworkaccess":
		return powerMockBool(r.flags["network"], "Wake On Network")
	case "-getrestartpowerfailure":
		return powerMockBool(r.flags["failure"], "Restart Power Failure")
	case "-getrestartfreeze":
		return powerMockBool(r.flags["freeze"], "Restart Freeze")
	case "-getallowpowerbuttontosleepcomputer":
		return powerMockBool(r.flags["button"], "Allow Power Button To Sleep Computer")
	}
	return process.CommandResult{ExitCode: 0}
}

func powerMockBool(on bool, label string) process.CommandResult {
	state := "Off"
	if on {
		state = "On"
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte(label + ": " + state)}
}

func powerMockRuntime(t *testing.T) (*runtime.Runtime, *powerMockRunner) {
	t.Helper()
	runner := &powerMockRunner{
		minutes: map[string]string{"computer": "10 minutes", "display": "20 minutes", "disk": "30 minutes"},
		flags:   map[string]bool{"modem": false, "network": false, "failure": false, "freeze": false, "button": false},
	}
	oldSleep := sleepPower
	sleepPower = func(time.Duration) {}
	t.Cleanup(func() { sleepPower = oldSleep })
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func powerMockArgv(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestPowerValidateSleepExactErrorTexts(t *testing.T) {
	// Salt _validate_sleep error strings, verbatim per pytest
	// test_validate_sleep_invalid_number/_invalid_string/_bool_true/
	// _unexpected.
	cases := []struct {
		in   any
		want string
	}{
		{181, "Invalid Integer Value for Minutes.\nInteger values must be between 1 and 180.\nPassed: 181"},
		{0, "Invalid Integer Value for Minutes.\nInteger values must be between 1 and 180.\nPassed: 0"},
		{"bob", "Invalid String Value for Minutes.\nString values must be \"Never\" or \"Off\".\nPassed: bob"},
		{true, "Invalid Boolean Value for Minutes.\nBoolean value \"On\" or \"True\" is not allowed.\nSalt CLI converts \"On\" to boolean True.\nPassed: true"},
		{1.5, "Unknown Variable Type Passed for Minutes.\nPassed: 1.5"},
	}
	for _, tc := range cases {
		_, err := validateSleep(tc.in)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("validateSleep(%v) error = %v; want %q", tc.in, err, tc.want)
		}
	}
	// accepted values: pytest boundaries 1/179 plus both string spellings.
	for _, tc := range []struct {
		in   any
		want string
	}{
		{1, "1"}, {179, "179"}, {180, "180"},
		{"never", "Never"}, {"Never", "Never"}, {"off", "Never"}, {"OFF", "Never"}, {false, "Never"},
		{int64(30), "30"},
	} {
		got, err := validateSleep(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("validateSleep(%v) = %q %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestPowerValidateEnabledExactMatrix(t *testing.T) {
	// salt.utils.mac_utils.validate_enabled coercion table.
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"on", "on"}, {"ON", "on"}, {" yes ", "on"}, {"no", "off"}, {"Off", "off"},
		{true, "on"}, {false, "off"}, {1, "on"}, {0, "off"}, {int64(2), "on"}, {int64(0), "off"},
		{float64(0), "off"}, {float64(0.5), "on"}, {nil, "off"}, {struct{ X int }{}, "on"},
	} {
		got, err := validateEnabled(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("validateEnabled(%#v) = %q %v; want %q", tc.in, got, err, tc.want)
		}
	}
	_, err := validateEnabled("maybe")
	want := "\nMac Power: Invalid String Value for Enabled.\nString values must be 'on' or 'off'/'yes' or 'no'.\nPassed: maybe"
	if err == nil || err.Error() != want {
		t.Fatalf("invalid enabled error = %v; want %q", err, want)
	}
}

func TestPowerParseReturnForms(t *testing.T) {
	// mac_utils.parse_return: ": " split, ":\n" split, passthrough.
	if got := parseReturn("Computer Sleep: 10 minutes"); got != "10 minutes" {
		t.Fatalf("colon-space parse = %q", got)
	}
	if got := parseReturn("Table:\nvalue"); got != "value" {
		t.Fatalf("colon-newline parse = %q", got)
	}
	if got := parseReturn("plain value"); got != "plain value" {
		t.Fatalf("passthrough = %q", got)
	}
}

func TestPowerGetterArgvMatrix(t *testing.T) {
	rt, runner := powerMockRuntime(t)
	getters := []struct {
		fn    runtime.ExecFunction
		argv  string
		label string
		want  any
	}{
		{getComputerSleepFunc{}, "systemsetup -getcomputersleep", "Computer", "10 minutes"},
		{getDisplaySleepFunc{}, "systemsetup -getdisplaysleep", "Display", "20 minutes"},
		{getHarddiskSleepFunc{}, "systemsetup -getharddisksleep", "Hard Disk", "30 minutes"},
		{getWakeOnModemFunc{}, "systemsetup -getwakeonmodem", "modem", false},
		{getWakeOnNetworkFunc{}, "systemsetup -getwakeonnetworkaccess", "network", false},
		{getRestartPowerFailureFunc{}, "systemsetup -getrestartpowerfailure", "failure", false},
		{getRestartFreezeFunc{}, "systemsetup -getrestartfreeze", "freeze", false},
		{getSleepOnPowerButtonFunc{}, "systemsetup -getallowpowerbuttontosleepcomputer", "button", false},
	}
	for i, getter := range getters {
		res, err := getter.fn.Execute(context.Background(), rt, getter.fn.Args())
		if err != nil {
			t.Fatal(err)
		}
		if res != getter.want {
			t.Fatalf("%s = %v", getter.argv, res)
		}
		if got := powerMockArgv(runner.calls[i]); got != getter.argv {
			t.Fatalf("call %d = %q; want %q", i, got, getter.argv)
		}
		if runner.calls[i].Shell {
			t.Fatalf("%s must stay shell-free", getter.argv)
		}
	}
}

func TestPowerSetSleepArgvAndConfirmation(t *testing.T) {
	rt, runner := powerMockRuntime(t)
	res, err := setSleepFunc{}.Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: 60})
	if err != nil || res != true {
		t.Fatalf("set_sleep = %v %v", res, err)
	}
	// Salt set_sleep: -setsleep then confirm through each of the three
	// getters (first-try success here: 4 calls total).
	want := []string{
		"systemsetup -setsleep 60",
		"systemsetup -getcomputersleep",
		"systemsetup -getdisplaysleep",
		"systemsetup -getharddisksleep",
	}
	if len(runner.calls) != len(want) {
		t.Fatalf("calls = %+v", runner.calls)
	}
	for i, argv := range want {
		if got := powerMockArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}
	// read-back through get_sleep reflects the single value everywhere.
	res, err = getSleepFunc{}.Execute(context.Background(), rt, getSleepArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	wantMap := map[string]any{"Computer": "60", "Display": "60", "Hard Disk": "60"}
	if !reflect.DeepEqual(got, wantMap) {
		t.Fatalf("get_sleep after set = %#v", got)
	}

	// "never" maps onto the Never keyword on the command line.
	rt, runner = powerMockRuntime(t)
	res, err = setSleepFunc{}.Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: "never"})
	if err != nil || res != true {
		t.Fatalf("set_sleep never = %v %v", res, err)
	}
	if got := powerMockArgv(runner.calls[0]); got != "systemsetup -setsleep Never" {
		t.Fatalf("never argv = %q", got)
	}

	// each individual setter targets only its own flag.
	rt, runner = powerMockRuntime(t)
	if _, err := (setComputerSleepFunc{}).Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: 90}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setDisplaySleepFunc{}).Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: int64(5)}); err != nil {
		t.Fatal(err)
	}
	if _, err := (setHarddiskSleepFunc{}).Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: "off"}); err != nil {
		t.Fatal(err)
	}
	wantSets := []string{
		"systemsetup -setcomputersleep 90",
		"systemsetup -getcomputersleep",
		"systemsetup -setdisplaysleep 5",
		"systemsetup -getdisplaysleep",
		"systemsetup -setharddisksleep Never",
		"systemsetup -getharddisksleep",
	}
	if len(runner.calls) != len(wantSets) {
		t.Fatalf("individual calls = %+v", runner.calls)
	}
	for i, argv := range wantSets {
		if got := powerMockArgv(runner.calls[i]); got != argv {
			t.Fatalf("call %d = %q; want %q", i, got, argv)
		}
	}
}

func TestPowerSetSleepRetcodeFailure(t *testing.T) {
	rt, runner := powerMockRuntime(t)
	runner.failSet = "-setsleep"
	_, err := setSleepFunc{}.Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: 60})
	if err == nil {
		t.Fatal("failed set_sleep must error")
	}
	// Salt mac_utils.execute_return_success error shape.
	for _, want := range []string{
		"Command Failed: systemsetup -setsleep 60",
		"Return Code: 1",
		"Error: systemsetup: error",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
	// invalid minutes never reach the runner.
	rt, runner = powerMockRuntime(t)
	if _, err := (setSleepFunc{}).Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: 999}); err == nil {
		t.Fatal("out-of-range minutes must error")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("invalid minutes reached the runner: %+v", runner.calls)
	}
}

func TestPowerSetBooleanSettingsArgvMatrix(t *testing.T) {
	setters := []struct {
		fn   runtime.ExecFunction
		set  string
		get  string
		key  string
		want any
	}{
		{setWakeOnModemFunc{}, "-setwakeonmodem", "-getwakeonmodem", "modem", true},
		{setWakeOnNetworkFunc{}, "-setwakeonnetworkaccess", "-getwakeonnetworkaccess", "network", true},
		{setRestartPowerFailureFunc{}, "-setrestartpowerfailure", "-getrestartpowerfailure", "failure", true},
		{setRestartFreezeFunc{}, "-setrestartfreeze", "-getrestartfreeze", "freeze", true},
		{setSleepOnPowerButtonFunc{}, "-setallowpowerbuttontosleepcomputer", "-getallowpowerbuttontosleepcomputer", "button", false},
	}
	for _, setter := range setters {
		rt, runner := powerMockRuntime(t)
		enabled := any(true)
		if !setter.want.(bool) {
			enabled = "off"
		}
		res, err := setter.fn.Execute(context.Background(), rt, &enabledArgs{Enabled: enabled})
		if err != nil || res != true {
			t.Fatalf("%s = %v %v", setter.set, res, err)
		}
		wantArgv := []string{
			"systemsetup " + setter.set + " on",
			"systemsetup " + setter.get,
		}
		if !setter.want.(bool) {
			wantArgv[0] = "systemsetup " + setter.set + " off"
		}
		if len(runner.calls) != 2 {
			t.Fatalf("%s calls = %+v", setter.set, runner.calls)
		}
		for i, argv := range wantArgv {
			if got := powerMockArgv(runner.calls[i]); got != argv {
				t.Fatalf("%s call %d = %q; want %q", setter.set, i, got, argv)
			}
		}
	}
}

func TestPowerConfirmUpdatedRetryLoop(t *testing.T) {
	// a stale check that converges on the 5th poll still reports true.
	sleeps := 0
	oldSleep := sleepPower
	sleepPower = func(time.Duration) { sleeps++ }
	t.Cleanup(func() { sleepPower = oldSleep })
	attempts := 0
	converging := func() (string, error) {
		attempts++
		if attempts < 5 {
			return "stale", nil
		}
		return "on", nil
	}
	if !confirmUpdated("on", converging, false) {
		t.Fatal("converging check must confirm")
	}
	if attempts != 5 || sleeps != 4 {
		t.Fatalf("attempts = %d sleeps = %d; want 5/4", attempts, sleeps)
	}

	// a check that never converges reports false after 5 polls.
	attempts = 0
	sleeps = 0
	stale := func() (string, error) { attempts++; return "off", nil }
	if confirmUpdated("on", stale, false) {
		t.Fatal("stale check must not confirm")
	}
	if attempts != 5 || sleeps != 4 {
		t.Fatalf("stale attempts = %d sleeps = %d; want 5/4", attempts, sleeps)
	}

	// normalize path: "On" capitalization is coerced before comparing.
	casedAttempts := 0
	cased := func() (string, error) { casedAttempts++; return "On", nil }
	if !confirmUpdated("on", cased, true) {
		t.Fatal("normalized check must confirm")
	}
	if casedAttempts != 1 {
		t.Fatalf("normalized attempts = %d", casedAttempts)
	}

	// a check erroring every poll is tolerated and retried.
	errChecks := 0
	failing := func() (string, error) { errChecks++; return "", fmt.Errorf("boom") }
	if confirmUpdated("on", failing, false) {
		t.Fatal("failing check must not confirm")
	}
	if errChecks != 5 {
		t.Fatalf("failing attempts = %d", errChecks)
	}
}

func TestPowerRegistryMatrix(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"power.get_computer_sleep",
		"power.get_display_sleep",
		"power.get_harddisk_sleep",
		"power.get_restart_freeze",
		"power.get_restart_power_failure",
		"power.get_sleep",
		"power.get_sleep_on_power_button",
		"power.get_wake_on_modem",
		"power.get_wake_on_network",
		"power.set_computer_sleep",
		"power.set_display_sleep",
		"power.set_harddisk_sleep",
		"power.set_restart_freeze",
		"power.set_restart_power_failure",
		"power.set_sleep",
		"power.set_sleep_on_power_button",
		"power.set_wake_on_modem",
		"power.set_wake_on_network",
	}
	// _validate_sleep stays internal exactly like Salt; everything else
	// is darwin-constrained in the registry.
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
	rt, runner := powerMockRuntime(t)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "power.get_sleep", getSleepArgs{})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.(map[string]any); got["Computer"] != "10 minutes" {
			t.Fatalf("dispatch = %#v", got)
		}
		if len(runner.calls) != 3 {
			t.Fatalf("dispatch calls = %d", len(runner.calls))
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "power.get_sleep", getSleepArgs{}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
