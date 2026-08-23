package iwtools

import (
	"context"
	"errors"
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

const iwconfigOut = `wlan0     IEEE 802.11  ESSID:"HomeNet"
          Mode:Managed  Frequency:5.18 GHz  Access Point: AA:BB:CC:DD:EE:FF
          Bit Rate=866.7 Mb/s   Tx-Power=30 dBm
eth0      no wireless extensions.

lo        no wireless extensions.
`

func newRT(t *testing.T, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	saved := iwconfigBin
	iwconfigBin = func() bool { return true }
	t.Cleanup(func() { iwconfigBin = saved })
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

func TestListInterfaces(t *testing.T) {
	rt, runner := newRT(t, map[string]process.CommandResult{
		"iwconfig": {Stdout: []byte(iwconfigOut)},
	})
	ret, err := listInterfaces(rt)
	if err != nil {
		t.Fatal(err)
	}
	wlan, ok := ret["wlan0"].(map[string]any)
	if !ok {
		t.Fatalf("wlan0 missing from %v", keysOf(ret))
	}
	if wlan["ESSID"] != "HomeNet" {
		t.Fatalf("quoted ESSID = %#v", wlan["ESSID"])
	}
	if wlan["Mode"] != "Managed" || wlan["Frequency"] != "5.18 GHz" {
		t.Fatalf("colon fields = %#v", wlan)
	}
	if wlan["Bit Rate"] != "866.7 Mb/s" || wlan["Tx-Power"] != "30 dBm" {
		t.Fatalf("equals fields = %#v", wlan)
	}
	// Interfaces without wireless extensions are skipped entirely.
	if _, has := ret["eth0"]; has {
		t.Fatalf("eth0 must be skipped: %v", keysOf(ret))
	}
	_ = runner
}

func TestScan(t *testing.T) {
	scanOut := `wlan0    Scan completed :
          Cell 01 - Address: AA:BB:CC:DD:EE:01
                    ESSID:"Guest"
                    Mode:Ad-Hoc
          Cell 02 - Address: AA:BB:CC:DD:EE:02
                    ESSID:"HomeNet"
                    Encryption key:on
`
	rt, runner := newRT(t, map[string]process.CommandResult{
		"iwconfig":          {Stdout: []byte(iwconfigOut)},
		"iwlist wlan0 scan": {Stdout: []byte(scanOut)},
	})

	sf := scanFunc{}
	gotRaw, err := sf.Execute(context.Background(), rt, &ScanArgs{Iface: "wlan0"})
	if err != nil {
		t.Fatal(err)
	}
	cells := gotRaw.(map[string]any)
	if len(cells) != 2 {
		t.Fatalf("cells = %v", keysOf(cells))
	}
	// Upstream strips quotes only from Address; ESSID keeps them in scan
	// output (list_interfaces is the one that unwraps ESSID).
	cell1 := cells["AA:BB:CC:DD:EE:01"].(map[string]any)
	if cell1["ESSID"] != "\"Guest\"" || cell1["Mode"] != "Ad-Hoc" {
		t.Fatalf("cell1 = %#v", cell1)
	}
	cell2 := cells["AA:BB:CC:DD:EE:02"].(map[string]any)
	if cell2["Encryption key"] != "on" {
		t.Fatalf("cell2 = %#v", cell2)
	}
	for _, call := range runner.calls {
		if call == "ip link set wlan0 up" {
			t.Fatal("interface must not be raised when scan succeeds")
		}
	}

	// style=list returns the addresses only.
	gotRaw, err = sf.Execute(context.Background(), rt, &ScanArgs{Iface: "wlan0", Style: strPtr("list")})
	if err != nil {
		t.Fatal(err)
	}
	keys := gotRaw.([]any)
	if len(keys) != 2 {
		t.Fatalf("list style = %#v", keys)
	}

	// Unknown interfaces raise like SaltInvocationError.
	if _, err := sf.Execute(context.Background(), rt, &ScanArgs{Iface: "enp5s0"}); err == nil ||
		err.Error() != "The interface specified is not valid" {
		t.Fatalf("invalid iface err = %v", err)
	}
}

func TestSetModeRequiresIpFamily(t *testing.T) {
	rt, runner := newRT(t, map[string]process.CommandResult{
		"iwconfig":                    {Stdout: []byte(iwconfigOut)},
		"iwconfig wlan0 mode Monitor": {Stdout: []byte("")},
	})

	// Invalid mode raises before anything runs.
	mf := setModeFunc{}
	if _, err := mf.Execute(context.Background(), rt, &SetModeArgs{Iface: "wlan0", Mode: "Turbo"}); err == nil ||
		err.Error() != "One of the following modes must be specified: Managed, Ad-Hoc, Master, Repeater, Secondary, Monitor, Auto" {
		t.Fatalf("mode validation err = %v", err)
	}

	// ip.down is not registered this round: UnsupportedError, no writes.
	_, err := mf.Execute(context.Background(), rt, &SetModeArgs{Iface: "wlan0", Mode: "Monitor"})
	unsupported := &runtime.UnsupportedError{}
	if err == nil || !asUnsupported(err, unsupported) || unsupported.Name != "ip.down" {
		t.Fatalf("expected ip.down unsupported error, got %v", err)
	}
	for _, call := range runner.calls {
		if call == "iwconfig wlan0 mode Monitor" {
			t.Fatal("iwconfig must not run when the delegate is unavailable")
		}
	}
}

func asUnsupported(err error, target *runtime.UnsupportedError) bool {
	var u *runtime.UnsupportedError
	if errors.As(err, &u) {
		target.Name = u.Name
		return true
	}
	return false
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{"iwtools.scan", "iwtools.set_mode", "iwtools.list_interfaces"} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
}

func strPtr(s string) *string { return &s }

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
