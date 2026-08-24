package bridge

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
	joined := cmd.Name + " " + strings.Join(cmd.Args, " ")
	f.calls = append(f.calls, joined)
	if res, ok := f.results[joined]; ok {
		return res
	}
	return process.CommandResult{}
}

func newRT(t *testing.T, kernel string, results map[string]process.CommandResult) (*runtime.Runtime, *fakeRunner) {
	t.Helper()
	savedKernel := kernelHook
	kernelHook = func(*runtime.Runtime) string { return kernel }
	t.Cleanup(func() { kernelHook = savedKernel })
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

func bindTools(t *testing.T, mapping map[string]string) {
	t.Helper()
	saved := toolPath
	toolPath = func(ostool string) string { return mapping[ostool] }
	t.Cleanup(func() { toolPath = saved })
}

func strPtr(s string) *string { return &s }

const brctlShow = `bridge name	bridge id		STP enabled	interfaces
br0		8000.e4115bac8ddc	no		eth0
							foo0
br1		8000.e4115bac8ddc	no		eth1
`

// Mirrors the _linux_brshow parser contract through brctl show output.
func TestLinuxBrShow(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rt, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show":     {Stdout: []byte(brctlShow)},
		"/usr/sbin/brctl show br0": {Stdout: []byte(strings.ReplaceAll(brctlShow, "br1\t\t8000.e4115bac8ddc\tno\t\teth1\n", ""))},
	})

	gotRaw, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{})
	if err != nil {
		t.Fatal(err)
	}
	brs := gotRaw.(map[string]any)

	br0 := brs["br0"].(map[string]any)
	if br0["id"] != "8000.e4115bac8ddc" || br0["stp"] != "no" {
		t.Fatalf("br0 header = %#v", br0)
	}
	wantIfaces := []any{"eth0", "foo0"}
	if !reflect.DeepEqual(br0["interfaces"], wantIfaces) {
		t.Fatalf("br0 interfaces = %#v", br0["interfaces"])
	}
	if _, has := brs["br1"]; !has {
		t.Fatalf("br1 missing: %v", keysOf(brs))
	}

	// A specific bridge returns only its entry.
	brName := "br0"
	singleRaw, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{Br: &brName})
	if err != nil {
		t.Fatal(err)
	}
	single := singleRaw.(map[string]any)
	if single["id"] != "8000.e4115bac8ddc" {
		t.Fatalf("single bridge = %#v", single)
	}
}

// The continuation-line crash path surfaces as an error.
func TestLinuxBrShowMalformed(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rt, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show": {Stdout: []byte("orphan0\n")},
	})
	_, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{})
	if err == nil || !strings.Contains(err.Error(), "malformed brctl output") {
		t.Fatalf("err = %v", err)
	}
}

// Mirrors test_list_ None/list pairing.
func TestList(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rtEmpty, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show": {},
	})
	gotRaw, err := listFunc{}.Execute(context.Background(), rtEmpty, &ListArgs{})
	if err != nil || gotRaw != nil {
		t.Fatalf("empty list = %#v, %v", gotRaw, err)
	}

	rt, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show": {Stdout: []byte(brctlShow)},
	})
	gotRaw, err = listFunc{}.Execute(context.Background(), rt, &ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, item := range gotRaw.([]any) {
		names[item.(string)] = true
	}
	if !names["br0"] || !names["br1"] {
		t.Fatalf("list = %#v", gotRaw)
	}
}

// Mirrors test_interfaces plus real extraction.
func TestInterfaces(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rt, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show br0": {Stdout: []byte(brctlShow)},
	})
	iff := interfacesFunc{}

	gotRaw, err := iff.Execute(context.Background(), rt, &InterfacesArgs{})
	if err != nil || gotRaw != nil {
		t.Fatalf("no bridge arg = %#v, %v", gotRaw, err)
	}

	br0 := "br0"
	gotRaw, err = iff.Execute(context.Background(), rt, &InterfacesArgs{Br: &br0})
	if err != nil {
		t.Fatal(err)
	}
	// The single-bridge fixture keeps br0's foo0 continuation line.
	if !reflect.DeepEqual(gotRaw, []any{"eth0", "foo0"}) {
		t.Fatalf("br0 interfaces = %#v", gotRaw)
	}
}

// Mirrors test_find_interfaces.
func TestFindInterfaces(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rtEmpty, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show": {},
	})
	fif := findInterfacesFunc{}

	gotRaw, err := fif.Execute(context.Background(), rtEmpty, &FindInterfacesArgs{})
	if err != nil || gotRaw != nil {
		t.Fatalf("no bridges = %#v, %v", gotRaw, err)
	}

	rt, _ := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl show": {Stdout: []byte(brctlShow)},
	})
	gotRaw, err = fif.Execute(context.Background(), rt, &FindInterfacesArgs{
		Names: []string{"eth0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"eth0": "br0"}
	if !reflect.DeepEqual(gotRaw, want) {
		t.Fatalf("find = %#v, want %v", gotRaw, want)
	}

	// No matches yield the empty dict (not None).
	gotRaw, err = fif.Execute(context.Background(), rt, &FindInterfacesArgs{
		Names: []string{"missing"},
	})
	if err != nil || !reflect.DeepEqual(gotRaw, map[string]any{}) {
		t.Fatalf("no match = %#v, %v", gotRaw, err)
	}
}

// Mirrors test_add/test_delete/test_addif/test_delif argv construction.
func TestMutatingCommandsLinux(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rt, runner := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl addbr br0":      {Stdout: []byte("")},
		"/usr/sbin/brctl delbr br0":      {Stdout: []byte("")},
		"/usr/sbin/brctl addif br0 eth0": {Stdout: []byte("")},
		"/usr/sbin/brctl delif br0 eth0": {Stdout: []byte("")},
		"/usr/sbin/brctl stp br0 on":     {Stdout: []byte("")},
	})

	br0 := "br0"
	eth0 := "eth0"

	gotRaw, err := addFunc{}.Execute(context.Background(), rt, &AddArgs{Br: &br0})
	if err != nil || gotRaw != "" {
		t.Fatalf("add = %#v, %v", gotRaw, err)
	}
	_, err = deleteFunc{}.Execute(context.Background(), rt, &DeleteArgs{Br: &br0})
	if err != nil {
		t.Fatal(err)
	}
	_, err = addIfFunc{}.Execute(context.Background(), rt, &AddIfArgs{Br: &br0, Iface: &eth0})
	if err != nil {
		t.Fatal(err)
	}
	_, err = delIfFunc{}.Execute(context.Background(), rt, &DelIfArgs{Br: &br0, Iface: &eth0})
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{
		"/usr/sbin/brctl addbr br0",
		"/usr/sbin/brctl delbr br0",
		"/usr/sbin/brctl addif br0 eth0",
		"/usr/sbin/brctl delif br0 eth0",
	}
	for i, want := range expected {
		if i >= len(runner.calls) || runner.calls[i] != want {
			t.Fatalf("call[%d] = %q, want %q (all: %v)", i, runner.calls[i], want, runner.calls)
		}
	}
}

// Mirrors test_stp including the Linux state mapping and None kernel.
func TestStp(t *testing.T) {
	bindTools(t, map[string]string{"brctl": "/usr/sbin/brctl"})
	rt, runner := newRT(t, "Linux", map[string]process.CommandResult{
		"/usr/sbin/brctl stp br0 on":  {},
		"/usr/sbin/brctl stp br0 off": {},
	})
	sf := stpFunc{}
	br0 := "br0"

	enable := "enable"
	gotRaw, err := sf.Execute(context.Background(), rt, &StpArgs{Br: &br0, State: &enable})
	if err != nil || gotRaw != "" {
		t.Fatalf("stp enable = %#v, %v", gotRaw, err)
	}
	disable := "disable"
	if _, err = sf.Execute(context.Background(), rt, &StpArgs{Br: &br0, State: &disable}); err != nil {
		t.Fatal(err)
	}
	foundOn, foundOff := false, false
	for _, call := range runner.calls {
		if call == "/usr/sbin/brctl stp br0 on" {
			foundOn = true
		}
		if call == "/usr/sbin/brctl stp br0 off" {
			foundOff = true
		}
	}
	if !foundOn || !foundOff {
		t.Fatalf("stp argv missing: %v", runner.calls)
	}

	// Unknown states raise like the uncaught KeyError (Linux scope).
	if _, err = sf.Execute(context.Background(), rt, &StpArgs{Br: &br0, State: strPtr("bogus")}); err == nil {
		t.Fatal("invalid state must raise")
	}

	// Unknown kernels return False.
	rtNone, _ := newRT(t, "", nil)
	gotRaw, err = sf.Execute(context.Background(), rtNone, &StpArgs{})
	if err != nil || gotRaw != false {
		t.Fatalf("unsupported kernel = %#v, %v", gotRaw, err)
	}
}

// BSD dispatch paths pin ifconfig/brconfig argv differences.
func TestBSDDispatch(t *testing.T) {
	bindTools(t, map[string]string{
		"ifconfig": "/sbin/ifconfig",
		"brconfig": "/sbin/brconfig",
	})
	rt, runner := newRT(t, "FreeBSD", map[string]process.CommandResult{
		"/sbin/ifconfig -g bridge":          {Stdout: []byte("bridge0\n")},
		"/sbin/ifconfig bridge0":            {Stdout: []byte("bridge0: flags=88<UP>\n\tmember: fxp0 flags=143<LEARNING,DISCOVER,STP>\n")},
		"/sbin/ifconfig bridge1 create up":  {ExitCode: 0},
		"/sbin/ifconfig bridge1 addem fxp0": {},
		"/sbin/ifconfig bridge0 stp fxp0":   {},
		"/sbin/ifconfig bridge1 destroy":    {},
	})

	showRaw, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{})
	if err != nil {
		t.Fatal(err)
	}
	brs := showRaw.(map[string]any)
	entry := brs["bridge0"].(map[string]any)
	if entry["stp"] != "yes" {
		t.Fatalf("member STP detection = %#v", entry)
	}
	if !reflect.DeepEqual(entry["interfaces"], []any{"fxp0"}) {
		t.Fatalf("members = %#v", entry["interfaces"])
	}

	addIf := "bridge1"
	fxp0 := "fxp0"
	_, err = addIfFunc{}.Execute(context.Background(), rt, &AddIfArgs{Br: &addIf, Iface: &fxp0})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stpFunc{}.Execute(context.Background(), rt, &StpArgs{
		Br: &addIf, State: strPtr("enable"), Iface: &fxp0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = deleteFunc{}.Execute(context.Background(), rt, &DeleteArgs{Br: &addIf})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, call := range runner.calls {
		switch call {
		case "/sbin/ifconfig bridge1 addem fxp0":
			found++
		case "/sbin/ifconfig bridge1 stp fxp0":
			found++
		case "/sbin/ifconfig bridge1 destroy":
			found++
		}
	}
	if found != 3 {
		t.Fatalf("bsd argv mismatch: %v", runner.calls)
	}
}

// NetBSD uses brconfig for both show and member management.
func TestNetBSDShow(t *testing.T) {
	bindTools(t, map[string]string{"brconfig": "/sbin/brconfig"})
	rt, _ := newRT(t, "NetBSD", map[string]process.CommandResult{
		"/sbin/brconfig -a": {Stdout: []byte(
			"bridge0: flags=41<UP,RUNNING>\n\tInterfaces:\n\tfxp0 flags=3<LEARNING,DISCOVER>\n\tSTP: enabled\n")},
	})
	gotRaw, err := showFunc{}.Execute(context.Background(), rt, &ShowArgs{})
	if err != nil {
		t.Fatal(err)
	}
	brs := gotRaw.(map[string]any)
	entry := brs["bridge0"].(map[string]any)
	if !reflect.DeepEqual(entry["interfaces"], []any{"fxp0"}) {
		t.Fatalf("netbsd members = %#v", entry["interfaces"])
	}
}

func TestRegisterNames(t *testing.T) {
	rt, _ := newRT(t, "Linux", nil)
	names := map[string]bool{}
	for _, name := range rt.Exec.Names() {
		names[name] = true
	}
	for _, want := range []string{
		"bridge.show", "bridge.list", "bridge.interfaces",
		"bridge.find_interfaces", "bridge.add", "bridge.delete",
		"bridge.addif", "bridge.delif", "bridge.stp",
	} {
		if !names[want] {
			t.Errorf("missing registration %s", want)
		}
	}
	for _, priv := range []string{"bridge._linux_brshow", "bridge._os_dispatch"} {
		if names[priv] {
			t.Errorf("%s must stay private", priv)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
