package cryptdev

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct {
	result process.CommandResult
	calls  [][]string
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return f.result
}

// TestActive mirrors Salt's test_active.
func TestActive(t *testing.T) {
	runner := &fakeRunner{result: process.CommandResult{
		Stdout: []byte("my-device       (253, 1)\n"),
	}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	got, err := activeFunc{}.Execute(context.Background(), rt, &ActiveArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"my-device": map[string]string{"devname": "my-device", "major": "253", "minor": "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active = %v", got)
	}

	for _, out := range []string{"", "No devices found"} {
		runner.result = process.CommandResult{Stdout: []byte(out)}
		got2, err := activeFunc{}.Execute(context.Background(), rt, &ActiveArgs{})
		if err != nil || len(got2.(map[string]any)) != 0 {
			t.Fatalf("empty output = %v %v", got2, err)
		}
	}
}

func writeCrypttab(t *testing.T, rt *runtime.Runtime, content string) {
	t.Helper()
	if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/etc/crypttab", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const crypttabFixture = `# a comment
data    /dev/sdz1       /dev/mapper/secret      swap,size=256
home    /dev/sdy1       none
`

func TestCrypttabListing(t *testing.T) {
	rt := &runtime.Runtime{Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	writeCrypttab(t, rt, crypttabFixture)

	gotRaw, err := crypttabFunc{}.Execute(context.Background(), rt, &CrypttabArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := gotRaw.(map[string]any)
	if len(got) != 2 {
		t.Fatalf("entries = %v", got)
	}
	data := got["data"].(map[string]any)
	if data["device"] != "/dev/sdz1" ||
		!reflect.DeepEqual(data["options"], []string{"swap", "size=256"}) {
		t.Fatalf("data entry = %v", data)
	}
	home := got["home"].(map[string]any)
	if home["password"] != "none" ||
		!reflect.DeepEqual(home["options"], []string{""}) {
		t.Fatalf("3-field entry = %v", home)
	}

	// Duplicate names get an appended underscore.
	writeCrypttab(t, rt, "x /dev/a none\nx /dev/b none\n")
	got2, _ := crypttabFunc{}.Execute(context.Background(), rt, &CrypttabArgs{})
	if _, ok := got2.(map[string]any)["x_"]; !ok {
		t.Fatalf("dup rename missing: %v", got2)
	}
}

func TestRmCrypttab(t *testing.T) {
	rt := &runtime.Runtime{Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	writeCrypttab(t, rt, crypttabFixture)

	got, err := rmCrypttabFunc{}.Execute(context.Background(), rt,
		&RmCrypttabArgs{Name: "missing"})
	if err != nil || got != "absent" {
		t.Fatalf("absent = %v %v", got, err)
	}

	got2, err := rmCrypttabFunc{}.Execute(context.Background(), rt,
		&RmCrypttabArgs{Name: "data"})
	if err != nil || got2 != "change" {
		t.Fatalf("change = %v %v", got2, err)
	}
	data, _ := rt.FS.ReadFile("/etc/crypttab")
	if strings.Contains(string(data), "sdz1") {
		t.Fatalf("entry not removed: %s", data)
	}
	if !strings.HasPrefix(string(data), "# a comment\n") {
		t.Fatalf("other lines must survive: %q", data)
	}
}

func TestSetCrypttabFlows(t *testing.T) {
	rt := &runtime.Runtime{Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	writeCrypttab(t, rt, "# only a comment\n")

	// new
	got, err := setCrypttabFunc{}.Execute(context.Background(), rt,
		&SetCrypttabArgs{Name: "foo", Device: "/dev/sdz1"})
	if err != nil || got != "new" {
		t.Fatalf("new = %v %v", got, err)
	}
	data, _ := rt.FS.ReadFile("/etc/crypttab")
	if !strings.Contains(string(data), "foo") {
		t.Fatal("new entry not written")
	}

	// present (identical re-run)
	got2, err := setCrypttabFunc{}.Execute(context.Background(), rt,
		&SetCrypttabArgs{Name: "foo", Device: "/dev/sdz1", Password: strPtr("none")})
	if err != nil || got2 != "present" {
		t.Fatalf("present = %v %v", got2, err)
	}

	// change
	got3, err := setCrypttabFunc{}.Execute(context.Background(), rt,
		&SetCrypttabArgs{Name: "foo", Device: "/dev/sdz2"})
	if err != nil || got3 != "change" {
		t.Fatalf("change = %v %v", got3, err)
	}
	data2, _ := rt.FS.ReadFile("/etc/crypttab")
	if strings.Contains(string(data2), "sdz1") {
		t.Fatalf("old device line survived: %s", data2)
	}

	// test mode never writes
	writeCrypttab(t, rt, "")
	got4, err := setCrypttabFunc{}.Execute(context.Background(), rt,
		&SetCrypttabArgs{Name: "bar", Device: "/dev/sdq1", Test: true})
	if err != nil || got4 != "new" {
		t.Fatalf("test new = %v %v", got4, err)
	}
	data3, _ := rt.FS.ReadFile("/etc/crypttab")
	if string(data3) != "" {
		t.Fatalf("test mode wrote the file: %q", data3)
	}

	// invalid match_on key errors like Salt
	_, err = setCrypttabFunc{}.Execute(context.Background(), rt,
		&SetCrypttabArgs{Name: "x", Device: "y", MatchOn: []string{"bogus"}})
	if err == nil || !strings.Contains(err.Error(), "Unrecognized keys in match_on") {
		t.Fatalf("match_on error = %v", err)
	}

	// missing config file errors
	noCfg := &runtime.Runtime{Runner: &fakeRunner{}, FS: runtime.NewMemoryFS()}
	_, err = setCrypttabFunc{}.Execute(context.Background(), noCfg,
		&SetCrypttabArgs{Name: "x", Device: "y"})
	if err == nil || !strings.Contains(err.Error(), "Bad config file") {
		t.Fatalf("bad config error = %v", err)
	}
}

func TestOpenCloseContracts(t *testing.T) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}

	_, err := openFunc{}.Execute(context.Background(), rt,
		&OpenArgs{Name: "foo", Device: "/dev/sdz1", Keyfile: "none"})
	if err == nil || !strings.Contains(err.Error(), "keyfile must not be none") {
		t.Fatalf("open guard = %v", err)
	}

	runner.result = process.CommandResult{ExitCode: 0}
	ok, err := openFunc{}.Execute(context.Background(), rt,
		&OpenArgs{Name: "foo", Device: "/dev/sdz1", Keyfile: "/keys/f"})
	if err != nil || ok != true {
		t.Fatalf("open = %v %v", ok, err)
	}
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-1],
		[]string{"cryptsetup", "open", "--key-file", "/keys/f", "/dev/sdz1", "foo"}) {
		t.Fatalf("open argv = %v", runner.calls)
	}

	runner.result = process.CommandResult{ExitCode: 4}
	closed, err := closeFunc{}.Execute(context.Background(), rt, &CloseArgs{Name: "foo"})
	if err != nil || closed != false {
		t.Fatalf("close = %v %v", closed, err)
	}
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-1],
		[]string{"cryptsetup", "close", "foo"}) {
		t.Fatalf("close argv = %v", runner.calls)
	}
}

func TestPlatformConstraint(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Names()) != 6 {
		t.Fatalf("registered %d functions", len(reg.Names()))
	}
	for _, name := range reg.Names() {
		fn, _ := reg.Get(name)
		if c, ok := fn.(interface{ Platforms() []string }); !ok ||
			strings.Join(c.Platforms(), ",") != "linux" {
			t.Fatalf("%s not linux-constrained", name)
		}
	}
}

func strPtr(s string) *string { return &s }
