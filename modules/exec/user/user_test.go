package user

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
`

const groupFixture = `root:x:0:
users:x:1000:
devs:x:2000:alice
wheel:x:10:alice,bob
`

// fakeRunner records argv and returns scripted results.
type fakeRunner struct {
	calls [][]string
	code  int
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: f.code}
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/passwd", []byte(passwdFixture), 0o644)
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/group", []byte(groupFixture), 0o644)
	return rt, runner
}

func TestUserInfo(t *testing.T) {
	rt, _ := newRT()
	value, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Name: "alice"})
	if err != nil {
		t.Fatalf("user.info: %v", err)
	}
	info := value.(map[string]any)
	if info["uid"] != "1000" || info["shell"] != "/bin/zsh" || info["home"] != "/home/alice" {
		t.Fatalf("info wrong: %+v", info)
	}
	groups := info["groups"].([]string)
	if len(groups) != 2 || groups[0] != "devs" || groups[1] != "wheel" {
		t.Fatalf("groups = %v", groups)
	}
	if _, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Name: "ghost"}); err == nil {
		t.Fatal("missing user must error like Salt")
	}
}

func TestListUsers(t *testing.T) {
	rt, _ := newRT()
	value, _ := (listUsersFunc{}).Execute(context.Background(), rt, &ListUsersArgs{})
	names := value.([]string)
	if strings.Join(names, ",") != "root,alice" {
		t.Fatalf("names = %v", names)
	}
}

func TestAddArgvAssembly(t *testing.T) {
	rt, runner := newRT()
	(addFunc{}).Execute(context.Background(), rt, &AddArgs{
		Name: "bob", UID: "1001", GID: "1001", Home: "/home/bob", Shell: "/bin/sh",
	})
	want := []string{"useradd", "-u", "1001", "-g", "1001", "-d", "/home/bob", "-s", "/bin/sh", "-M", "bob"}
	if strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v want %v", runner.calls[0], want)
	}
	runner.code = 9
	if _, err := (addFunc{}).Execute(context.Background(), rt, &AddArgs{Name: "bob"}); err == nil {
		t.Fatal("non-zero exit must surface as error")
	}
}

func TestDeleteAndChUID(t *testing.T) {
	rt, runner := newRT()
	(deleteFunc{}).Execute(context.Background(), rt, &DeleteArgs{Name: "bob", Remove: true, Force: true})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "userdel -r -f bob" {
		t.Fatalf("userdel argv = %q", got)
	}
	(chUIDFunc{}).Execute(context.Background(), rt, &ChUIDArgs{Name: "alice", UID: "1010"})
	last := runner.calls[len(runner.calls)-1]
	if strings.Join(last, " ") != "usermod -u 1010 alice" {
		t.Fatalf("chuid argv = %v", last)
	}
}

func TestChHomeMoves(t *testing.T) {
	rt, runner := newRT()
	(chHomeFunc{}).Execute(context.Background(), rt, &ChHomeArgs{Name: "alice", Home: "/newhome", Move: true})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "usermod -m -d /newhome alice" {
		t.Fatalf("chhome argv = %q", got)
	}
}
