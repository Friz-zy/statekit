package xattr

// R6.10 mock tests for the Darwin xattr surface, mapped onto
// saltstack/salt/modules/mac_xattr.py @ pinned revision 8b63e700637e
// and tests/pytests/unit/modules/test_mac_xattr.py: exact xattr argv
// (the pytest test_read_hex pins ["xattr","-p","-x",attr,path]), the
// "File not found"/"Attribute not found"/"Unknown Error" shapes, the
// non-UTF-8 replacement contract from test_read_not_decodeable, the
// write read-back verification and the registry matrix. All Runner
// output is scripted.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// argvXattrRunner is a stateful in-memory xattr store recording argv.
type argvXattrRunner struct {
	attrs    map[string]map[string]string
	mutate   func(attribute, value string) string // optional write distortion
	failNext map[string]string                    // argv prefix → stderr
	calls    []process.Command
}

func (r *argvXattrRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	for prefix, stderr := range r.failNext {
		if strings.HasPrefix(joined, prefix) {
			return process.CommandResult{ExitCode: 1, Stderr: []byte(stderr)}
		}
	}
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
		attribute, value := command.Args[1], command.Args[2]
		if attribute == "-x" {
			attribute, value = command.Args[2], command.Args[3]
		}
		if r.mutate != nil {
			value = r.mutate(attribute, value)
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
		r.attrs[path] = map[string]string{}
		return process.CommandResult{ExitCode: 0}
	default:
		var names []string
		for attribute := range attrs {
			names = append(names, attribute)
		}
		return process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Join(names, "\n"))}
	}
}

func xattrArgvRT(t *testing.T) (*runtime.Runtime, *argvXattrRunner) {
	t.Helper()
	runner := &argvXattrRunner{attrs: map[string]map[string]string{
		"/tmp/file": {"com.example.one": "one", "com.example.two": "two"},
	}}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func xa(command process.Command) string {
	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}

func TestReadArgvWithAndWithoutHex(t *testing.T) {
	rt, runner := xattrArgvRT(t)
	res, err := (readFunc{}).Execute(context.Background(), rt, &readArgs{Path: "/tmp/file", Attribute: "com.example.one"})
	if err != nil || res != "one" {
		t.Fatalf("read = %v %v", res, err)
	}
	if got := xa(runner.calls[0]); got != "xattr -p com.example.one /tmp/file" {
		t.Fatalf("read argv = %q", got)
	}
	res, err = (readFunc{}).Execute(context.Background(), rt, &readArgs{Path: "/tmp/file", Attribute: "com.example.one", Hex: true})
	if err != nil || res != "one" {
		t.Fatalf("hex read = %v %v", res, err)
	}
	// pytest test_read_hex pins the -x position directly after -p.
	if got := xa(runner.calls[1]); got != "xattr -p -x com.example.one /tmp/file" {
		t.Fatalf("hex argv = %q", got)
	}
	if runner.calls[0].Shell || runner.calls[1].Shell {
		t.Fatal("xattr commands must stay shell-free")
	}
}

func TestReadNotDecodeable(t *testing.T) {
	// pytest test_read_not_decodeable: b"\xd1expected results" decodes
	// with a replacement rune, not an error.
	runner := &argvXattrRunner{attrs: map[string]map[string]string{
		"/tmp/file": {"com.attr": string([]byte{0xd1}) + "expected results"},
	}}
	rt := &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
	res, err := (readFunc{}).Execute(context.Background(), rt, &readArgs{Path: "/tmp/file", Attribute: "com.attr"})
	if err != nil {
		t.Fatal(err)
	}
	if res != "\ufffdexpected results" {
		t.Fatalf("replacement = %q", res)
	}
}

func TestWriteArgvHexAndReadBack(t *testing.T) {
	rt, runner := xattrArgvRT(t)
	res, err := (writeFunc{}).Execute(context.Background(), rt, &writeArgs{
		Path: "/tmp/file", Attribute: "com.example.three", Value: "three",
	})
	if err != nil || res != true {
		t.Fatalf("write = %v %v", res, err)
	}
	if got := xa(runner.calls[0]); got != "xattr -w com.example.three three /tmp/file" {
		t.Fatalf("write argv = %q", got)
	}
	res, err = (writeFunc{}).Execute(context.Background(), rt, &writeArgs{
		Path: "/tmp/file", Attribute: "com.example.hex", Value: "deadbeef", Hex: true,
	})
	if err != nil || res != true {
		t.Fatalf("hex write = %v %v", res, err)
	}
	if got := xa(runner.calls[2]); got != "xattr -w -x com.example.hex deadbeef /tmp/file" {
		t.Fatalf("hex write argv = %q", got)
	}
	// a distorted write-back fails verification with False, not an error
	runner.mutate = func(_, value string) string { return value + "!" }
	res, err = (writeFunc{}).Execute(context.Background(), rt, &writeArgs{
		Path: "/tmp/file", Attribute: "com.example.distort", Value: "plain",
	})
	if err != nil || res != false {
		t.Fatalf("distorted write = %v %v", res, err)
	}
}

func TestDeleteAndClearArgv(t *testing.T) {
	rt, runner := xattrArgvRT(t)
	res, err := (deleteFunc{}).Execute(context.Background(), rt, &deleteArgs{Path: "/tmp/file", Attribute: "com.example.one"})
	if err != nil || res != true {
		t.Fatalf("delete = %v %v", res, err)
	}
	if got := xa(runner.calls[0]); got != "xattr -d com.example.one /tmp/file" {
		t.Fatalf("delete argv = %q", got)
	}
	// delete verification re-lists attributes (Salt: attribute not in list_)
	if got := xa(runner.calls[1]); got != "xattr /tmp/file" {
		t.Fatalf("verify list argv = %q", got)
	}
	res, err = (clearFunc{}).Execute(context.Background(), rt, &clearArgs{Path: "/tmp/file"})
	if err != nil || res != true {
		t.Fatalf("clear = %v %v", res, err)
	}
	last := runner.calls[len(runner.calls)-2]
	if got := xa(last); got != "xattr -c /tmp/file" {
		t.Fatalf("clear argv = %q", got)
	}
}

func TestListArgvEmptyAndHexPropagation(t *testing.T) {
	rt, runner := xattrArgvRT(t)
	res, err := (listFunc{}).Execute(context.Background(), rt, &listArgs{Path: "/tmp/file", Hex: true})
	if err != nil {
		t.Fatal(err)
	}
	attrs := res.(map[string]any)
	if attrs["com.example.one"] != "one" || len(attrs) != 2 {
		t.Fatalf("list = %#v", attrs)
	}
	if got := xa(runner.calls[0]); got != "xattr /tmp/file" {
		t.Fatalf("list argv = %q", got)
	}
	if got := xa(runner.calls[1]); got != "xattr -p -x com.example.one /tmp/file" && got != "xattr -p -x com.example.two /tmp/file" {
		// map iteration order is unspecified; both reads must carry -x
		t.Fatalf("hex propagated read argv = %q", got)
	}
	for _, command := range runner.calls {
		if command.Shell {
			t.Fatal("xattr commands must stay shell-free")
		}
	}
	// empty attribute listing is an empty dict, not an error (Salt: not ret → {})
	runner.attrs["/tmp/clean"] = map[string]string{}
	res, err = (listFunc{}).Execute(context.Background(), rt, &listArgs{Path: "/tmp/clean"})
	if err != nil || len(res.(map[string]any)) != 0 {
		t.Fatalf("empty list = %#v %v", res, err)
	}
}

func TestXattrErrorShapes(t *testing.T) {
	rt, runner := xattrArgvRT(t)
	runner.failNext = map[string]string{
		"xattr -w": "No such file or directory",
	}
	_, err := (writeFunc{}).Execute(context.Background(), rt, &writeArgs{
		Path: "/tmp/ghost", Attribute: "a", Value: "v",
	})
	if err == nil || err.Error() != "File not found: /tmp/ghost" {
		t.Fatalf("write missing file = %v", err)
	}
	runner.failNext = map[string]string{
		"xattr -d": "No such xattr: a",
	}
	_, err = (deleteFunc{}).Execute(context.Background(), rt, &deleteArgs{Path: "/tmp/file", Attribute: "com.missing"})
	if err == nil || err.Error() != "Attribute not found: com.missing" {
		t.Fatalf("delete missing attr = %v", err)
	}
	runner.failNext = map[string]string{
		"xattr -c": "disk I/O failure",
	}
	_, err = (clearFunc{}).Execute(context.Background(), rt, &clearArgs{Path: "/tmp/file"})
	if err == nil || err.Error() != "Unknown Error: disk I/O failure" {
		t.Fatalf("unknown error = %v", err)
	}
}

func TestXattrRegisteredNamesAndDispatch(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{"xattr.clear", "xattr.delete", "xattr.list", "xattr.read", "xattr.write"}
	// Names() filters to the current GOOS: darwin-constrained functions
	// are present in the registry (Get) but only listed on darwin.
	names := reg.Names()
	if runtime.CurrentGOOS() == "darwin" {
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("darwin names = %v", names)
		}
	} else if len(names) != 0 {
		t.Fatalf("non-darwin names must be empty, got %v", names)
	}
	for _, name := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok {
			t.Fatalf("%s is not platform-constrained", name)
		}
		platforms := constrained.Platforms()
		if len(platforms) != 1 || platforms[0] != "darwin" {
			t.Fatalf("%s platforms = %v", name, platforms)
		}
	}
	rt, _ := xattrArgvRT(t)
	rt.Exec = reg
	if runtime.CurrentGOOS() == "darwin" {
		res, err := rt.Exec.Call(context.Background(), rt, "xattr.read", &readArgs{Path: "/tmp/file", Attribute: "com.example.two"})
		if err != nil || res != "two" {
			t.Fatalf("dispatch = %v %v", res, err)
		}
	} else if _, err := rt.Exec.Call(context.Background(), rt, "xattr.read", &readArgs{Path: "/tmp/file", Attribute: "com.example.two"}); err == nil {
		t.Fatal("darwin-only function must be rejected on non-darwin GOOS")
	}
}
