package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type aptHoldTestRunner struct {
	results  []process.CommandResult
	commands []process.Command
	cancel   context.CancelFunc
}

func (r *aptHoldTestRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if r.cancel != nil && len(r.commands) == 1 {
		r.cancel()
	}
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestAPTHoldTestModeAndMutationGate(t *testing.T) {
	p := &commandProvider{spec: aptSpec}
	args := map[string]any{"name": "demo"}
	r := &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte("demo install\n")}}}
	rt := &runtime.Runtime{Runner: r, Options: runtime.RuntimeOptions{Test: true}}
	got, err := p.Apt(context.Background(), rt, "hold", args)
	want := map[string]any{"demo": map[string]any{"name": "demo", "changes": map[string]any{}, "result": nil, "comment": "Package demo is set to be held."}}
	if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != 1 || len(r.commands[0].Stdin) != 0 {
		t.Fatalf("got=%#v err=%v commands=%#v", got, err, r.commands)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r = &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte("demo install\n")}}, cancel: cancel}
	got, err = p.Apt(ctx, &runtime.Runtime{Runner: r}, "hold", args)
	if got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 1 {
		t.Fatalf("cancel gate got=%#v err=%v commands=%d", got, err, len(r.commands))
	}
}

func TestAPTHoldBoundedReadbackAndMutationFailures(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name    string
		results []process.CommandResult
		want    error
	}{
		{"readback", []process.CommandResult{{Err: sentinel}}, sentinel},
		{"mutation", []process.CommandResult{{Stdout: []byte("demo install\n")}, {Err: sentinel}}, sentinel},
		{"bounds", []process.CommandResult{{Err: process.ErrOutputLimit}}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptHoldTestRunner{results: tc.results}
			got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"name": "demo"})
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
			}
			for _, command := range r.commands {
				if command.Shell || command.MaxStdoutBytes != aptHoldOutputLimit || command.MaxStderrBytes != aptHoldOutputLimit {
					t.Fatalf("unbounded command=%#v", command)
				}
			}
		})
	}
}

func TestAPTHoldProcessesTargetsSequentiallyAndPreservesPartialResult(t *testing.T) {
	sentinel := errors.New("second readback failed")
	r := &aptHoldTestRunner{results: []process.CommandResult{
		{Stdout: []byte("first install\n")}, {},
		{Err: sentinel},
	}}
	args := map[string]any{"pkgs": []string{"first", "second"}}
	got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", args)
	want := map[string]any{"first": map[string]any{
		"name": "first", "changes": map[string]any{"old": "install", "new": "hold"},
		"result": true, "comment": "Package first is now being held.",
	}}
	if !errors.Is(err, sentinel) || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(r.commands) != 3 {
		t.Fatalf("commands=%#v", r.commands)
	}
	wantArgv := [][]string{{"dpkg", "--get-selections", "first"}, {"dpkg", "--set-selections"}, {"dpkg", "--get-selections", "second"}}
	for i, command := range r.commands {
		if !reflect.DeepEqual(append([]string{command.Name}, command.Args...), wantArgv[i]) || command.Shell || command.MaxStdoutBytes != aptHoldOutputLimit || command.MaxStderrBytes != aptHoldOutputLimit {
			t.Fatalf("command[%d]=%#v", i, command)
		}
	}
	if string(r.commands[1].Stdin) != "first hold\n" || !reflect.DeepEqual(args, map[string]any{"pkgs": []string{"first", "second"}}) {
		t.Fatalf("stdin/args mutated: stdin=%q args=%#v", r.commands[1].Stdin, args)
	}
}

func TestAPTHoldAlreadyHeldAndNotInstalled(t *testing.T) {
	r := &aptHoldTestRunner{results: []process.CommandResult{
		{Stdout: []byte("held hold\n")}, {Stdout: []byte{}}, {},
	}}
	got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"pkgs": []string{"held", "missing"}})
	want := map[string]any{
		"held":    map[string]any{"name": "held", "changes": map[string]any{}, "result": true, "comment": "Package held is already set to be held."},
		"missing": map[string]any{"name": "missing", "changes": map[string]any{}, "result": false, "comment": "Package missing not currently held."},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != 2 {
		t.Fatalf("got=%#v err=%v commands=%#v", got, err, r.commands)
	}
}

func TestAPTEmptyHoldReadbackReturnsNotHeldWithoutMutation(t *testing.T) {
	for _, testMode := range []bool{false, true} {
		r := &aptHoldTestRunner{results: []process.CommandResult{{Stdout: []byte{}}}}
		rt := &runtime.Runtime{Runner: r, Options: runtime.RuntimeOptions{Test: testMode}}
		got, err := (&commandProvider{spec: aptSpec}).Apt(context.Background(), rt, "hold", map[string]any{"name": "empty"})
		if err != nil {
			t.Fatal(err)
		}
		entry := got.(map[string]any)["empty"].(map[string]any)
		if entry["result"] != false || entry["comment"] != "Package empty not currently held." || !reflect.DeepEqual(entry["changes"], map[string]any{}) || len(r.commands) != 1 {
			t.Fatalf("test=%v entry=%#v commands=%#v", testMode, entry, r.commands)
		}
	}
}

func TestAPTNameAndArchitectureHelpers(t *testing.T) {
	for _, tc := range []struct {
		in, arch, name string
		parsed         map[string]any
	}{
		{"zsh:amd64", "amd64", "zsh", map[string]any{"name": "zsh", "arch": "amd64"}},
		{"zsh:i386", "amd64", "zsh:i386", map[string]any{"name": "zsh", "arch": "i386"}},
		{"zsh", "amd64", "zsh", map[string]any{"name": "zsh", "arch": nil}},
	} {
		if got := normalizeName(tc.in, tc.arch); got != tc.name {
			t.Errorf("normalizeName(%q)=%q", tc.in, got)
		}
		got := parseArch(tc.in)
		if got["name"] != tc.parsed["name"] || got["arch"] != tc.parsed["arch"] {
			t.Errorf("parseArch(%q)=%v", tc.in, got)
		}
	}
}

func TestDebianVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0~rc1", "1.0", -1}, {"1:1.0", "2.0", 1},
		{"1.0-1", "1.0-2", -1}, {"1.0+really", "1.0~really", 1},
		{"1.0-1", "1.0-1", 0}, {"1.0-1", "1.0-1~bpo", 1},
	} {
		if got := debVersionCmp(tc.a, tc.b, false); got != tc.want {
			t.Errorf("compare %q %q=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if debVersionCmp("9:1", "2:9", true) >= 0 {
		t.Error("ignore_epoch must remove epochs")
	}
}
