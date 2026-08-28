package xattr

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type xattrRunner struct {
	attrs map[string]map[string]string
	calls []process.Command
}

func (r *xattrRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(command.Args) == 0 {
		return process.CommandResult{ExitCode: 1, Stderr: []byte("No such file")}
	}
	path := command.Args[len(command.Args)-1]
	attrs, exists := r.attrs[path]
	if !exists {
		return process.CommandResult{ExitCode: 1, Stderr: []byte("No such file")}
	}
	switch command.Args[0] {
	case "-p":
		attribute := command.Args[1]
		if command.Args[1] == "-x" {
			attribute = command.Args[2]
		}
		value, ok := attrs[attribute]
		if !ok {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("No such xattr")}
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(value)}
	case "-w":
		attribute := command.Args[1]
		value := command.Args[2]
		if attribute == "-x" {
			attribute, value = command.Args[2], command.Args[3]
		}
		attrs[attribute] = value
		return process.CommandResult{ExitCode: 0}
	case "-d":
		attribute := command.Args[1]
		if _, ok := attrs[attribute]; !ok {
			return process.CommandResult{ExitCode: 1, Stderr: []byte("No such xattr")}
		}
		delete(attrs, attribute)
		return process.CommandResult{ExitCode: 0}
	case "-c":
		for attribute := range attrs {
			delete(attrs, attribute)
		}
		return process.CommandResult{ExitCode: 0}
	default:
		var names []string
		for attribute := range attrs {
			names = append(names, attribute)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(names, "\n"))}
	}
}

func xattrRuntime(t *testing.T) (*runtime.Runtime, *xattrRunner) {
	t.Helper()
	runner := &xattrRunner{attrs: map[string]map[string]string{
		"/tmp/file": {"com.example.one": "one", "com.example.two": "two"},
	}}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func TestXattrLifecycle(t *testing.T) {
	rt, runner := xattrRuntime(t)
	res, err := listFunc{}.Execute(context.Background(), rt, &listArgs{Path: "/tmp/file"})
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := res.(map[string]any)
	if attrs["com.example.one"] != "one" || attrs["com.example.two"] != "two" {
		t.Fatalf("list = %#v", res)
	}
	res, err = readFunc{}.Execute(context.Background(), rt, &readArgs{Path: "/tmp/file", Attribute: "com.example.one"})
	if err != nil || res != "one" {
		t.Fatalf("read = %#v %v", res, err)
	}
	res, err = writeFunc{}.Execute(context.Background(), rt, &writeArgs{
		Path: "/tmp/file", Attribute: "com.example.three", Value: "three", Hex: true,
	})
	if err != nil || res != true {
		t.Fatalf("write = %#v %v", res, err)
	}
	res, err = deleteFunc{}.Execute(context.Background(), rt, &deleteArgs{Path: "/tmp/file", Attribute: "com.example.three"})
	if err != nil || res != true {
		t.Fatalf("delete = %#v %v", res, err)
	}
	res, err = clearFunc{}.Execute(context.Background(), rt, &clearArgs{Path: "/tmp/file"})
	if err != nil || res != true {
		t.Fatalf("clear = %#v %v", res, err)
	}
	if len(runner.calls) < 8 {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestXattrErrorsAndPlatform(t *testing.T) {
	rt, _ := xattrRuntime(t)
	_, err := readFunc{}.Execute(context.Background(), rt, &readArgs{Path: "/tmp/missing", Attribute: "x"})
	if err == nil || !strings.Contains(err.Error(), "File not found: /tmp/missing") {
		t.Fatalf("missing file = %v", err)
	}
	_, err = readFunc{}.Execute(context.Background(), rt, &readArgs{Path: "/tmp/file", Attribute: "missing"})
	if err == nil || !strings.Contains(err.Error(), "Attribute not found: missing") {
		t.Fatalf("missing attr = %v", err)
	}
	platforms := (listFunc{}).Platforms()
	if len(platforms) != 1 || platforms[0] != "darwin" {
		t.Fatalf("platforms = %v", platforms)
	}
}
