package power

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type powerRunner struct {
	minutes map[string]string
	flags   map[string]bool
	calls   []process.Command
}

func (r *powerRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if command.Name != "systemsetup" || len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	flag := command.Args[0]
	if len(command.Args) >= 2 && strings.HasPrefix(flag, "-set") {
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
		return boolPowerResult(r.flags["modem"], "Wake On Modem")
	case "-getwakeonnetworkaccess":
		return boolPowerResult(r.flags["network"], "Wake On Network")
	case "-getrestartpowerfailure":
		return boolPowerResult(r.flags["failure"], "Restart Power Failure")
	case "-getrestartfreeze":
		return boolPowerResult(r.flags["freeze"], "Restart Freeze")
	case "-getallowpowerbuttontosleepcomputer":
		return boolPowerResult(r.flags["button"], "Allow Power Button")
	}
	return process.CommandResult{ExitCode: 0}
}

func boolPowerResult(on bool, label string) process.CommandResult {
	state := "Off"
	if on {
		state = "On"
	}
	return process.CommandResult{ExitCode: 0, Stdout: []byte(label + ": " + state)}
}

func powerRuntime(t *testing.T) (*runtime.Runtime, *powerRunner) {
	t.Helper()
	runner := &powerRunner{
		minutes: map[string]string{"computer": "10 minutes", "display": "20 minutes", "disk": "30 minutes"},
		flags:   map[string]bool{"modem": false, "network": false, "failure": false, "freeze": false, "button": false},
	}
	oldSleep := sleepPower
	sleepPower = func(time.Duration) {}
	t.Cleanup(func() { sleepPower = oldSleep })
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func TestValidateSleepAndEnabled(t *testing.T) {
	for _, test := range []struct {
		in   any
		want string
	}{
		{120, "120"}, {int64(30), "30"}, {"off", "Never"}, {"Never", "Never"}, {false, "Never"},
	} {
		got, err := validateSleep(test.in)
		if err != nil || got != test.want {
			t.Fatalf("validateSleep(%v) = %q %v", test.in, got, err)
		}
	}
	for _, bad := range []any{0, 181, true, "on", 1.5} {
		if _, err := validateSleep(bad); err == nil {
			t.Fatalf("validateSleep(%v) accepted", bad)
		}
	}
	for _, test := range []struct {
		in   any
		want string
	}{
		{true, "on"}, {false, "off"}, {1, "on"}, {0, "off"}, {"yes", "on"}, {"no", "off"},
	} {
		got, err := validateEnabled(test.in)
		if err != nil || got != test.want {
			t.Fatalf("validateEnabled(%v) = %q %v", test.in, got, err)
		}
	}
	if _, err := validateEnabled("maybe"); err == nil {
		t.Fatal("invalid enabled string accepted")
	}
	if got := parseReturn("Time Zone: America/Denver"); got != "America/Denver" {
		t.Fatalf("parseReturn = %q", got)
	}
}

func TestSleepLifecycle(t *testing.T) {
	rt, runner := powerRuntime(t)
	res, err := getSleepFunc{}.Execute(context.Background(), rt, getSleepArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["Computer"] != "10 minutes" || got["Display"] != "20 minutes" || got["Hard Disk"] != "30 minutes" {
		t.Fatalf("sleep = %#v", got)
	}
	res, err = setSleepFunc{}.Execute(context.Background(), rt, &sleepMinutesArgs{Minutes: 60})
	if err != nil || res != true {
		t.Fatalf("set sleep = %#v %v", res, err)
	}
	res, err = getComputerSleepFunc{}.Execute(context.Background(), rt, getComputerSleepArgs{})
	if err != nil || res != "60" {
		t.Fatalf("computer sleep after set = %#v %v", res, err)
	}
	if len(runner.calls) < 6 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestBooleanPowerLifecycle(t *testing.T) {
	rt, _ := powerRuntime(t)
	res, err := getWakeOnModemFunc{}.Execute(context.Background(), rt, getWakeOnModemArgs{})
	if err != nil || res != false {
		t.Fatalf("modem = %#v %v", res, err)
	}
	res, err = setWakeOnModemFunc{}.Execute(context.Background(), rt, &enabledArgs{Enabled: true})
	if err != nil || res != true {
		t.Fatalf("set modem = %#v %v", res, err)
	}
	res, err = getWakeOnModemFunc{}.Execute(context.Background(), rt, getWakeOnModemArgs{})
	if err != nil || res != true {
		t.Fatalf("modem after set = %#v %v", res, err)
	}
	res, err = setRestartFreezeFunc{}.Execute(context.Background(), rt, &enabledArgs{Enabled: "yes"})
	if err != nil || res != true {
		t.Fatalf("set freeze = %#v %v", res, err)
	}
}

func TestPowerPlatforms(t *testing.T) {
	platforms := (getSleepFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
