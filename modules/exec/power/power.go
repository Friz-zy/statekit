// Package power implements Salt's Darwin power execution family through the
// systemsetup command and the central Runner.
package power

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
)

var sleepPower = time.Sleep

func powerCommand(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, error) {
	result := rt.Runner.Run(ctx, runtime.Command(argv...))
	if result.Err != nil && result.ExitCode == -1 {
		return string(result.Stdout), result.Err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("Command Failed: %s\nReturn Code: %d\nOutput: %s\nError: %s\n",
			strings.Join(argv, " "), result.ExitCode, result.Stdout, result.Stderr)
	}
	return string(result.Stdout), nil
}

func validateSleep(minutes any) (string, error) {
	switch value := minutes.(type) {
	case string:
		switch strings.ToLower(value) {
		case "never", "off":
			return "Never", nil
		default:
			return "", fmt.Errorf("Invalid String Value for Minutes.\nString values must be \"Never\" or \"Off\".\nPassed: %v", minutes)
		}
	case bool:
		if value {
			return "", fmt.Errorf("Invalid Boolean Value for Minutes.\nBoolean value \"On\" or \"True\" is not allowed.\nSalt CLI converts \"On\" to boolean True.\nPassed: %v", minutes)
		}
		return "Never", nil
	case int:
		if value >= 1 && value <= 180 {
			return strconv.Itoa(value), nil
		}
		return "", fmt.Errorf("Invalid Integer Value for Minutes.\nInteger values must be between 1 and 180.\nPassed: %v", minutes)
	case int64:
		if value >= 1 && value <= 180 {
			return strconv.FormatInt(value, 10), nil
		}
		return "", fmt.Errorf("Invalid Integer Value for Minutes.\nInteger values must be between 1 and 180.\nPassed: %v", minutes)
	default:
		return "", fmt.Errorf("Unknown Variable Type Passed for Minutes.\nPassed: %v", minutes)
	}
}

func validateEnabled(enabled any) (string, error) {
	switch value := enabled.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "on", "yes":
			return "on", nil
		case "off", "no":
			return "off", nil
		default:
			return "", fmt.Errorf("\nMac Power: Invalid String Value for Enabled.\nString values must be 'on' or 'off'/'yes' or 'no'.\nPassed: %v", enabled)
		}
	case bool:
		if value {
			return "on", nil
		}
		return "off", nil
	case int:
		if value == 0 {
			return "off", nil
		}
		return "on", nil
	case int64:
		if value == 0 {
			return "off", nil
		}
		return "on", nil
	case float64:
		if value == 0 {
			return "off", nil
		}
		return "on", nil
	default:
		if enabled == nil {
			return "off", nil
		}
		return "on", nil
	}
}

func parseReturn(data string) string {
	if strings.Contains(data, ": ") {
		return strings.Split(data, ": ")[1]
	}
	if strings.Contains(data, ":\n") {
		return strings.Split(data, ":\n")[1]
	}
	return data
}

func getSetting(ctx context.Context, rt *runtime.Runtime, argv ...string) (string, error) {
	out, err := powerCommand(ctx, rt, argv...)
	if err != nil {
		return "", err
	}
	return parseReturn(out), nil
}

func confirmUpdated(value string, check func() (string, error), normalize bool) bool {
	for i := 0; i < 5; i++ {
		state, err := check()
		if err == nil {
			if normalize {
				if normalized, nerr := validateEnabled(state); nerr == nil {
					state = normalized
				}
			}
			if strings.Contains(state, value) {
				return true
			}
		}
		if i < 4 {
			sleepPower(time.Second)
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// sleep

type getSleepArgs struct{}
type getSleepFunc struct{}

func (getSleepFunc) Name() string        { return "power.get_sleep" }
func (getSleepFunc) Args() any           { return getSleepArgs{} }
func (getSleepFunc) Platforms() []string { return []string{"darwin"} }
func (getSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	computer, err := getComputerSleepFunc{}.Execute(ctx, rt, getComputerSleepArgs{})
	if err != nil {
		return nil, err
	}
	display, err := getDisplaySleepFunc{}.Execute(ctx, rt, getDisplaySleepArgs{})
	if err != nil {
		return nil, err
	}
	disk, err := getHarddiskSleepFunc{}.Execute(ctx, rt, getHarddiskSleepArgs{})
	if err != nil {
		return nil, err
	}
	return map[string]any{"Computer": computer, "Display": display, "Hard Disk": disk}, nil
}

type sleepMinutesArgs struct {
	Minutes any `statekit:"required,name=minutes"`
}

type setSleepFunc struct{}

func (setSleepFunc) Name() string        { return "power.set_sleep" }
func (setSleepFunc) Args() any           { return sleepMinutesArgs{} }
func (setSleepFunc) Platforms() []string { return []string{"darwin"} }
func (setSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	value, err := validateSleep(args.(*sleepMinutesArgs).Minutes)
	if err != nil {
		return nil, err
	}
	if _, err := powerCommand(ctx, rt, "systemsetup", "-setsleep", value); err != nil {
		return nil, err
	}
	checks := []func() (string, error){
		func() (string, error) { return getSetting(ctx, rt, "systemsetup", "-getcomputersleep") },
		func() (string, error) { return getSetting(ctx, rt, "systemsetup", "-getdisplaysleep") },
		func() (string, error) { return getSetting(ctx, rt, "systemsetup", "-getharddisksleep") },
	}
	for _, check := range checks {
		if !confirmUpdated(value, check, false) {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// individual sleep values

type getComputerSleepArgs struct{}
type getComputerSleepFunc struct{}

func (getComputerSleepFunc) Name() string        { return "power.get_computer_sleep" }
func (getComputerSleepFunc) Args() any           { return getComputerSleepArgs{} }
func (getComputerSleepFunc) Platforms() []string { return []string{"darwin"} }
func (getComputerSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return getSetting(ctx, rt, "systemsetup", "-getcomputersleep")
}

type setComputerSleepFunc struct{}

func (setComputerSleepFunc) Name() string        { return "power.set_computer_sleep" }
func (setComputerSleepFunc) Args() any           { return sleepMinutesArgs{} }
func (setComputerSleepFunc) Platforms() []string { return []string{"darwin"} }
func (setComputerSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	value, err := validateSleep(args.(*sleepMinutesArgs).Minutes)
	if err != nil {
		return nil, err
	}
	if _, err := powerCommand(ctx, rt, "systemsetup", "-setcomputersleep", value); err != nil {
		return nil, err
	}
	return confirmUpdated(value, func() (string, error) {
		result, err := getComputerSleepFunc{}.Execute(ctx, rt, getComputerSleepArgs{})
		text, _ := result.(string)
		return text, err
	}, false), nil
}

type getDisplaySleepArgs struct{}
type getDisplaySleepFunc struct{}

func (getDisplaySleepFunc) Name() string        { return "power.get_display_sleep" }
func (getDisplaySleepFunc) Args() any           { return getDisplaySleepArgs{} }
func (getDisplaySleepFunc) Platforms() []string { return []string{"darwin"} }
func (getDisplaySleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return getSetting(ctx, rt, "systemsetup", "-getdisplaysleep")
}

type setDisplaySleepFunc struct{}

func (setDisplaySleepFunc) Name() string        { return "power.set_display_sleep" }
func (setDisplaySleepFunc) Args() any           { return sleepMinutesArgs{} }
func (setDisplaySleepFunc) Platforms() []string { return []string{"darwin"} }
func (setDisplaySleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	value, err := validateSleep(args.(*sleepMinutesArgs).Minutes)
	if err != nil {
		return nil, err
	}
	if _, err := powerCommand(ctx, rt, "systemsetup", "-setdisplaysleep", value); err != nil {
		return nil, err
	}
	return confirmUpdated(value, func() (string, error) {
		result, err := getDisplaySleepFunc{}.Execute(ctx, rt, getDisplaySleepArgs{})
		text, _ := result.(string)
		return text, err
	}, false), nil
}

type getHarddiskSleepArgs struct{}
type getHarddiskSleepFunc struct{}

func (getHarddiskSleepFunc) Name() string        { return "power.get_harddisk_sleep" }
func (getHarddiskSleepFunc) Args() any           { return getHarddiskSleepArgs{} }
func (getHarddiskSleepFunc) Platforms() []string { return []string{"darwin"} }
func (getHarddiskSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return getSetting(ctx, rt, "systemsetup", "-getharddisksleep")
}

type setHarddiskSleepFunc struct{}

func (setHarddiskSleepFunc) Name() string        { return "power.set_harddisk_sleep" }
func (setHarddiskSleepFunc) Args() any           { return sleepMinutesArgs{} }
func (setHarddiskSleepFunc) Platforms() []string { return []string{"darwin"} }
func (setHarddiskSleepFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	value, err := validateSleep(args.(*sleepMinutesArgs).Minutes)
	if err != nil {
		return nil, err
	}
	if _, err := powerCommand(ctx, rt, "systemsetup", "-setharddisksleep", value); err != nil {
		return nil, err
	}
	return confirmUpdated(value, func() (string, error) {
		result, err := getHarddiskSleepFunc{}.Execute(ctx, rt, getHarddiskSleepArgs{})
		text, _ := result.(string)
		return text, err
	}, false), nil
}

// ---------------------------------------------------------------------------
// boolean systemsetup settings

func boolSetting(ctx context.Context, rt *runtime.Runtime, flag string) (bool, error) {
	value, err := getSetting(ctx, rt, "systemsetup", flag)
	if err != nil {
		return false, err
	}
	normalized, err := validateEnabled(value)
	if err != nil {
		return false, err
	}
	return normalized == "on", nil
}

func setBoolSetting(ctx context.Context, rt *runtime.Runtime, setFlag string, enabled any, getFlag string) (bool, error) {
	state, err := validateEnabled(enabled)
	if err != nil {
		return false, err
	}
	if _, err := powerCommand(ctx, rt, "systemsetup", setFlag, state); err != nil {
		return false, err
	}
	return confirmUpdated(state, func() (string, error) {
		return getSetting(ctx, rt, "systemsetup", getFlag)
	}, true), nil
}

type getWakeOnModemArgs struct{}
type getWakeOnModemFunc struct{}

func (getWakeOnModemFunc) Name() string        { return "power.get_wake_on_modem" }
func (getWakeOnModemFunc) Args() any           { return getWakeOnModemArgs{} }
func (getWakeOnModemFunc) Platforms() []string { return []string{"darwin"} }
func (getWakeOnModemFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return boolSetting(ctx, rt, "-getwakeonmodem")
}

type setWakeOnModemFunc struct{}

func (setWakeOnModemFunc) Name() string        { return "power.set_wake_on_modem" }
func (setWakeOnModemFunc) Args() any           { return enabledArgs{} }
func (setWakeOnModemFunc) Platforms() []string { return []string{"darwin"} }
func (setWakeOnModemFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	return setBoolSetting(ctx, rt, "-setwakeonmodem", args.(*enabledArgs).Enabled, "-getwakeonmodem")
}

type getWakeOnNetworkArgs struct{}
type getWakeOnNetworkFunc struct{}

func (getWakeOnNetworkFunc) Name() string        { return "power.get_wake_on_network" }
func (getWakeOnNetworkFunc) Args() any           { return getWakeOnNetworkArgs{} }
func (getWakeOnNetworkFunc) Platforms() []string { return []string{"darwin"} }
func (getWakeOnNetworkFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return boolSetting(ctx, rt, "-getwakeonnetworkaccess")
}

type setWakeOnNetworkFunc struct{}

func (setWakeOnNetworkFunc) Name() string        { return "power.set_wake_on_network" }
func (setWakeOnNetworkFunc) Args() any           { return enabledArgs{} }
func (setWakeOnNetworkFunc) Platforms() []string { return []string{"darwin"} }
func (setWakeOnNetworkFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	return setBoolSetting(ctx, rt, "-setwakeonnetworkaccess", args.(*enabledArgs).Enabled, "-getwakeonnetworkaccess")
}

type getRestartPowerFailureArgs struct{}
type getRestartPowerFailureFunc struct{}

func (getRestartPowerFailureFunc) Name() string        { return "power.get_restart_power_failure" }
func (getRestartPowerFailureFunc) Args() any           { return getRestartPowerFailureArgs{} }
func (getRestartPowerFailureFunc) Platforms() []string { return []string{"darwin"} }
func (getRestartPowerFailureFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return boolSetting(ctx, rt, "-getrestartpowerfailure")
}

type setRestartPowerFailureFunc struct{}

func (setRestartPowerFailureFunc) Name() string        { return "power.set_restart_power_failure" }
func (setRestartPowerFailureFunc) Args() any           { return enabledArgs{} }
func (setRestartPowerFailureFunc) Platforms() []string { return []string{"darwin"} }
func (setRestartPowerFailureFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	return setBoolSetting(ctx, rt, "-setrestartpowerfailure", args.(*enabledArgs).Enabled, "-getrestartpowerfailure")
}

type getRestartFreezeArgs struct{}
type getRestartFreezeFunc struct{}

func (getRestartFreezeFunc) Name() string        { return "power.get_restart_freeze" }
func (getRestartFreezeFunc) Args() any           { return getRestartFreezeArgs{} }
func (getRestartFreezeFunc) Platforms() []string { return []string{"darwin"} }
func (getRestartFreezeFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return boolSetting(ctx, rt, "-getrestartfreeze")
}

type setRestartFreezeFunc struct{}

func (setRestartFreezeFunc) Name() string        { return "power.set_restart_freeze" }
func (setRestartFreezeFunc) Args() any           { return enabledArgs{} }
func (setRestartFreezeFunc) Platforms() []string { return []string{"darwin"} }
func (setRestartFreezeFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	return setBoolSetting(ctx, rt, "-setrestartfreeze", args.(*enabledArgs).Enabled, "-getrestartfreeze")
}

type getSleepOnPowerButtonArgs struct{}
type getSleepOnPowerButtonFunc struct{}

func (getSleepOnPowerButtonFunc) Name() string        { return "power.get_sleep_on_power_button" }
func (getSleepOnPowerButtonFunc) Args() any           { return getSleepOnPowerButtonArgs{} }
func (getSleepOnPowerButtonFunc) Platforms() []string { return []string{"darwin"} }
func (getSleepOnPowerButtonFunc) Execute(ctx context.Context, rt *runtime.Runtime, _ any) (res any, err error) {
	defer recoverPower(&res, &err)
	return boolSetting(ctx, rt, "-getallowpowerbuttontosleepcomputer")
}

type setSleepOnPowerButtonFunc struct{}

func (setSleepOnPowerButtonFunc) Name() string        { return "power.set_sleep_on_power_button" }
func (setSleepOnPowerButtonFunc) Args() any           { return enabledArgs{} }
func (setSleepOnPowerButtonFunc) Platforms() []string { return []string{"darwin"} }
func (setSleepOnPowerButtonFunc) Execute(ctx context.Context, rt *runtime.Runtime, args any) (res any, err error) {
	defer recoverPower(&res, &err)
	return setBoolSetting(ctx, rt, "-setallowpowerbuttontosleepcomputer", args.(*enabledArgs).Enabled, "-getallowpowerbuttontosleepcomputer")
}

type enabledArgs struct {
	Enabled any `statekit:"required,name=enabled"`
}

func recoverPower(res *any, errPtr *error) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			*errPtr = err
			return
		}
		panic(value)
	}
}

// Register installs the Darwin power functions; _validate_sleep remains an
// internal helper just like in Salt.
func Register(reg *runtime.ExecRegistry) error {
	for _, fn := range []runtime.ExecFunction{
		getSleepFunc{}, setSleepFunc{}, getComputerSleepFunc{}, setComputerSleepFunc{},
		getDisplaySleepFunc{}, setDisplaySleepFunc{}, getHarddiskSleepFunc{}, setHarddiskSleepFunc{},
		getWakeOnModemFunc{}, setWakeOnModemFunc{}, getWakeOnNetworkFunc{}, setWakeOnNetworkFunc{},
		getRestartPowerFailureFunc{}, setRestartPowerFailureFunc{}, getRestartFreezeFunc{}, setRestartFreezeFunc{},
		getSleepOnPowerButtonFunc{}, setSleepOnPowerButtonFunc{},
	} {
		if err := reg.Register(fn); err != nil {
			return err
		}
	}
	return nil
}
