package ethtool

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
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, cmd.Name)
	if res, ok := f.results[cmd.Name]; ok {
		return res
	}
	return process.CommandResult{}
}

const pauseRet = "Pause parameters for eth0:\n" +
	"Autonegotiate:  on\n" +
	"RX:             on\n" +
	"TX:             on\n" +
	"RX negotiated:  off\n" +
	"TX negotiated:  off"

func newRT(t *testing.T, bin string, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := ethtoolBin
	ethtoolBin = func() string { return bin }
	t.Cleanup(func() { ethtoolBin = saved })
	runner := &fakeRunner{results: results}
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Runner: runner,
	}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}

// Mirrors test_ethtool__ethtool_command_which_fail.
func TestCommandWhichFail(t *testing.T) {
	rt, _ := newRT(t, "", nil)
	_, err := ethtoolCommand(context.Background(), rt, "eth0", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be found") {
		t.Fatalf("err = %v", err)
	}
}

// Mirrors test_ethtool__ethtool_command_operation_not_supported: a
// leading header line does NOT raise; only a bare "Cannot..." first line
// does (upstream inspects ret[0] alone).
func TestCommandCannotLineRaises(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -a eth0": {Stdout: []byte(
			"Pause parameters for eth0:\nCannot get device pause settings: Operation not supported")},
		"/sbin/ethtool -A eth0 autoneg off": {Stdout: []byte(
			"Cannot get device pause settings: Operation not supported")},
	})
	lines, err := ethtoolCommand(context.Background(), rt, "eth0", []string{"-a"}, nil)
	if err != nil || len(lines) != 2 {
		t.Fatalf("header line must pass through: %v, %v", lines, err)
	}
	_, err = ethtoolCommand(context.Background(), rt, "eth0", []string{"-A"},
		map[string]string{"autoneg": "off"})
	if err == nil || !strings.HasPrefix(err.Error(), "Cannot get device pause settings") {
		t.Fatalf("err = %v", err)
	}
}

// Mirrors test_ethtool__ethtool_command: shell string shape is pinned.
func TestCommandBuildsShellString(t *testing.T) {
	rt, runner := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -A eth0 autoneg off": {Stdout: []byte(pauseRet)},
	})
	ret, err := ethtoolCommand(context.Background(), rt, "eth0", []string{"-A"},
		map[string]string{"autoneg": "off"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ret, strings.Split(pauseRet, "\n")) {
		t.Fatalf("ret = %v", ret)
	}
	found := false
	for _, call := range runner.calls {
		if call == "/sbin/ethtool -A eth0 autoneg off" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shell command missing: %v", runner.calls)
	}
}

// Mirrors test_ethtool__validate_params.
func TestValidateParams(t *testing.T) {
	if _, err := validateParams([]string{"not_found"}, map[string]any{"eth": "tool"}); err == nil {
		t.Fatal("no valid params must raise")
	}
	got, err := validateParams([]string{"eth"}, map[string]any{"eth": "tool"})
	if err != nil || !reflect.DeepEqual(got, map[string]string{"eth": "tool"}) {
		t.Fatalf("filter = %v, %v", got, err)
	}
	got, err = validateParams([]string{"eth", "salt"}, map[string]any{"eth": true, "salt": false})
	if err != nil || !reflect.DeepEqual(got, map[string]string{"eth": "on", "salt": "off"}) {
		t.Fatalf("bool mapping = %v, %v", got, err)
	}
}

// Mirrors test_ethtool_show_pause.
func TestShowPause(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -a eth0": {Stdout: []byte(pauseRet)},
	})
	retRaw, err := showPauseFunc{}.Execute(context.Background(), rt, &DevnameArgs{Devname: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"Autonegotiate": true, "RX": true, "TX": true,
		"RX negotiated": false, "TX negotiated": false,
	}
	if !reflect.DeepEqual(retRaw, want) {
		t.Fatalf("pause = %#v", retRaw)
	}
}

// Mirrors the head of the features fixture from test_ethtool_show_features.
func TestShowFeatures(t *testing.T) {
	features := "Features for eth0:\n" +
		"rx-checksumming: on [fixed]\n" +
		"tx-checksumming: on\n" +
		"\ttx-checksum-ipv4: off [fixed]\n" +
		"\ttx-checksum-ip-generic: on\n" +
		"scatter-gather: on\n" +
		"tcp-segmentation-offload: on\n" +
		"udp-fragmentation-offload: off\n" +
		"large-receive-offload: off [fixed]\n"
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -k eth0": {Stdout: []byte(features)},
	})
	retRaw, err := showFeaturesFunc{}.Execute(context.Background(), rt, &DevnameArgs{Devname: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"rx-checksumming":           map[string]bool{"on": true, "fixed": true},
		"tx-checksumming":           map[string]bool{"on": true, "fixed": false},
		"tx-checksum-ipv4":          map[string]bool{"on": false, "fixed": true},
		"tx-checksum-ip-generic":    map[string]bool{"on": true, "fixed": false},
		"scatter-gather":            map[string]bool{"on": true, "fixed": false},
		"tcp-segmentation-offload":  map[string]bool{"on": true, "fixed": false},
		"udp-fragmentation-offload": map[string]bool{"on": false, "fixed": false},
		"large-receive-offload":     map[string]bool{"on": false, "fixed": true},
	}
	if !reflect.DeepEqual(retRaw, want) {
		t.Fatalf("features = %#v", retRaw)
	}
}

// Mirrors test_ethtool_set_pause / test_ethtool_set_feature.
func TestSetPauseAndFeature(t *testing.T) {
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -A eth0 autoneg off": {},
		"/sbin/ethtool -K eth0 sg off":      {},
	})

	sp := setPauseFunc{}
	if _, err := sp.Execute(context.Background(), rt,
		&KwargsArgs{Devname: "eth0", Kwargs: map[string]any{"not_there": false}}); err == nil {
		t.Fatal("invalid params must raise")
	}
	retRaw, err := sp.Execute(context.Background(), rt,
		&KwargsArgs{Devname: "eth0", Kwargs: map[string]any{"autoneg": false}})
	if err != nil || retRaw != true {
		t.Fatalf("set_pause = %#v, %v", retRaw, err)
	}

	sf := setFeatureFunc{}
	if _, err := sf.Execute(context.Background(), rt,
		&KwargsArgs{Devname: "eth0", Kwargs: map[string]any{"not_there": false}}); err == nil {
		t.Fatal("invalid params must raise")
	}
	retRaw, err = sf.Execute(context.Background(), rt,
		&KwargsArgs{Devname: "eth0", Kwargs: map[string]any{"sg": false}})
	if err != nil || retRaw != true {
		t.Fatalf("set_feature = %#v, %v", retRaw, err)
	}
}

func TestShowRingParsesBothSections(t *testing.T) {
	ringOut := "Pre-set maximums:\n" +
		"RX:\t\t4096\n" +
		"RX Mini:\t0\n" +
		"RX Jumbo:\t0\n" +
		"TX:\t\t4096\n" +
		"Current hardware settings:\n" +
		"RX:\t\t255\n" +
		"RX Mini:\t0\n" +
		"RX Jumbo:\t0\n" +
		"TX:\t\t186\n"
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -g eth0": {Stdout: []byte(ringOut)},
	})
	retRaw, err := showRingFunc{}.Execute(context.Background(), rt, &DevnameArgs{Devname: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"rx": int64(255), "rx_max": int64(4096),
		"rx_mini": int64(0), "rx_mini_max": int64(0),
		"rx_jumbo": int64(0), "rx_jumbo_max": int64(0),
		"tx": int64(186), "tx_max": int64(4096),
	}
	if !reflect.DeepEqual(retRaw, want) {
		t.Fatalf("ring = %#v", retRaw)
	}
}

func TestSetRingChangesAndShows(t *testing.T) {
	ringOut := "Pre-set maximums:\nRX:\t\t4096\nTX:\t\t4096\n" +
		"Current hardware settings:\nRX:\t\t255\nTX:\t\t186\n"
	rt, runner := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -g eth0":        {Stdout: []byte(ringOut)},
		"/sbin/ethtool -G eth0 tx 512": {Stdout: []byte("")},
	})
	retRaw, err := setRingFunc{}.Execute(context.Background(), rt, &KwargsArgs{
		Devname: "eth0",
		Kwargs:  map[string]any{"tx": int64(512), "bogus": int64(1), "rx": int64(255)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ret := retRaw.(map[string]any)
	if ret["tx"] != int64(186) || ret["rx"] != int64(255) {
		t.Fatalf("post-set ring = %#v", ret)
	}
	wrote := false
	for _, call := range runner.calls {
		if call == "/sbin/ethtool -G eth0 tx 512" {
			wrote = true
		}
	}
	if !wrote {
		t.Fatalf("changed tx must trigger exactly one -G write: %v", runner.calls)
	}
}

func TestShowDriver(t *testing.T) {
	driverOut := "driver: virtio_net\nversion: 1.0.0\nbus-info: 0000:00:03.0\n"
	rt, _ := newRT(t, "/sbin/ethtool", map[string]process.CommandResult{
		"/sbin/ethtool -i eth0": {Stdout: []byte(driverOut)},
	})
	retRaw, err := showDriverFunc{}.Execute(context.Background(), rt, &DevnameArgs{Devname: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"driver": "virtio_net", "bus_info": "0000:00:03.0"}
	if !reflect.DeepEqual(retRaw, want) {
		t.Fatalf("driver = %#v", retRaw)
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, "", nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"ethtool.show_ring", "ethtool.show_coalesce", "ethtool.show_driver",
		"ethtool.set_ring", "ethtool.set_coalesce", "ethtool.show_offload",
		"ethtool.set_offload", "ethtool.show_pause", "ethtool.set_pause",
		"ethtool.show_features", "ethtool.set_feature",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	if names["ethtool._ethtool_command"] || names["ethtool._validate_params"] {
		t.Error("helpers must stay private")
	}
}
