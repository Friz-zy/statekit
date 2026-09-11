//go:build darwin

package user

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type darwinUserRunner struct {
	calls []process.Command
}

func (r *darwinUserRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	name := command.Name
	joined := strings.Join(command.Args, " ")
	switch {
	case name == "dscacheutil" && strings.Contains(joined, "-q user -a name alice"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte("name: alice\nuid: 501\ngid: 20\ndir: /Users/alice\nshell: /bin/zsh\ngecos: Alice Example\n")}
	case name == "id" && len(command.Args) >= 2 && command.Args[0] == "-Gn":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("staff everyone\n")}
	case name == "id" && len(command.Args) >= 3 && command.Args[0] == "-g":
		return process.CommandResult{ExitCode: 0, Stdout: []byte("staff\n")}
	case name == "dscacheutil" && strings.Contains(joined, "-q user"):
		return process.CommandResult{ExitCode: 0, Stdout: []byte("name: alice\nuid: 501\ngid: 20\ndir: /Users/alice\nshell: /bin/zsh\ngecos: Alice Example\n\n")}
	default:
		return process.CommandResult{ExitCode: 0}
	}
}

func TestDarwinUserInfoAndDSCLPath(t *testing.T) {
	runner := &darwinUserRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := macInfoFunc{}.Execute(context.Background(), rt, &macInfoArgs{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	info := res.(map[string]any)
	if info["name"] != "alice" || info["uid"] != 501 || info["gid"] != 20 ||
		info["home"] != "/Users/alice" || info["shell"] != "/bin/zsh" {
		t.Fatalf("info = %#v", info)
	}
	if got := macUserGroups(context.Background(), rt, "alice"); len(got) != 2 || got[0] != "staff" {
		t.Fatalf("groups = %v", got)
	}
	result := dscl(context.Background(), rt, []string{"/Users/alice", "UniqueID", "501"}, "create")
	if result.ExitCode != 0 || len(runner.calls) == 0 {
		t.Fatalf("dscl result = %+v", result)
	}
	command := runner.calls[len(runner.calls)-1]
	if strings.Join(command.Args, " ") != "localhost -create /Local/Default/Users/alice UniqueID 501" {
		t.Fatalf("dscl argv = %v", command.Args)
	}
	legacyFacts := facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Version: "10.7.5"}})
	legacyRT := &runtime.Runtime{Runner: runner, Facts: legacyFacts, FS: runtime.NewMemoryFS()}
	dscl(context.Background(), legacyRT, []string{"/Users/alice", "UniqueID", "501"}, "create")
	legacyCommand := runner.calls[len(runner.calls)-1]
	if strings.Join(legacyCommand.Args, " ") != ". -create /Users/alice UniqueID 501" {
		t.Fatalf("legacy dscl argv = %v", legacyCommand.Args)
	}
}

func TestDarwinUserPureHelpers(t *testing.T) {
	if got := userWhitespace("alice name"); !got {
		t.Fatal("whitespace not detected")
	}
	got, err := kcpassword("password")
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic expectation for the Go port: the trailing null is
	// XORed with the first key byte and the zero padding with the key
	// (macOS randomizes that tail, so the pytest reference vectors pin
	// only the password-byte region; see mac_darwin_mock_test.go).
	want := []byte{0x0d, 0xe8, 0x21, 0x50, 0xa5, 0xd3, 0xaf, 0x8e, 0xa3, 0xb9, 0x1f, 0x7d}
	if !bytes.Equal(got, want) {
		t.Fatalf("kcpassword = % x, want % x", got, want)
	}
}
