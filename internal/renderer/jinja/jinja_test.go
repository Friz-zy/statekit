package jinja

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
)

type recordingRunner struct {
	results []process.CommandResult
	cmds    []process.Command
}

func (r *recordingRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.cmds = append(r.cmds, cmd)
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestResolveCandidatesOrderDeduplicatesAndIgnoresRelativeVirtualEnv(t *testing.T) {
	looked := []string{}
	lookup := func(name string) (string, error) {
		looked = append(looked, name)
		if filepath.IsAbs(name) {
			return name, nil
		}
		return "/candidate/" + name, nil
	}
	got := resolveCandidates([]string{"VIRTUAL_ENV=relative"}, "/work", lookup, "linux")
	want := []string{"/work/venv/bin/python3", "/work/venv/bin/python", "/candidate/python3", "/candidate/python"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestResolveCandidatesPlatformVirtualEnvScripts(t *testing.T) {
	lookup := func(name string) (string, error) { return name, nil }
	for _, tc := range []struct {
		goos string
		want string
	}{
		{"darwin", "/venv/bin/python3"},
		{"windows", "/venv/Scripts/python.exe"},
	} {
		got := resolveCandidates([]string{"VIRTUAL_ENV=/venv", "PYTHONFLAGS=kept"}, "", lookup, tc.goos)
		if len(got) == 0 || got[0] != tc.want {
			t.Fatalf("%s candidates = %#v, want first %q", tc.goos, got, tc.want)
		}
	}
}

func TestBootstrapContainsBoundedSubsetPolicy(t *testing.T) {
	for _, required := range []string{"SandboxedEnvironment", "StrictUndefined", "loader=None", "TemplateRejected", "ResourceLimit", "template.generate()", "env.parse(source)", "make_module()", "node.name != \"tojson\"", "MAX_AST_NODES"} {
		if !strings.Contains(bootstrap, required) {
			t.Fatalf("bootstrap missing %q", required)
		}
	}
	for _, forbidden := range []string{"chunks=[]", "\"\".join(chunks)", "template.render("} {
		if strings.Contains(bootstrap, forbidden) {
			t.Fatalf("bootstrap retains unbounded rendering %q", forbidden)
		}
	}
	if !strings.Contains(bootstrap, "sys.stdout.write('{\"kind\":\"resource_limit\"}')") {
		t.Fatal("resource limits do not produce a complete response frame")
	}
}

func TestResourceLimitResponseIsTerminalAndSingleFrame(t *testing.T) {
	runner := &recordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(`{"kind":"resource_limit"}`)},
		{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"fallback"}`)},
	}}
	_, err := renderCandidates(context.Background(), runner, Request{Operation: "render"}, []string{"/a", "/b"}, nil, "/work")
	if err == nil || err.Error() != "jinja: template resource limit" || len(runner.cmds) != 1 {
		t.Fatalf("resource limit = %v, calls=%d", err, len(runner.cmds))
	}
}

func TestRenderCandidatesUsesStaticShellFreeCommandAndFallsBackOnlyMissingModule(t *testing.T) {
	runner := &recordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(`{"kind":"missing_jinja2"}`)},
		{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"yes"}`)},
	}}
	got, err := renderWithResolver(context.Background(), runner, Request{Operation: "render", Source: "{{ secret }}"}, func([]string, string) []string { return []string{"/a/python", "/b/python"} }, []string{"PYTHONPATH=secret", "PYTHONHOME=home", "X=y"}, "/work")
	if err != nil || got != "yes" {
		t.Fatalf("render = %q, %v", got, err)
	}
	if len(runner.cmds) != 2 {
		t.Fatalf("calls = %d", len(runner.cmds))
	}
	for _, cmd := range runner.cmds {
		if cmd.Shell || !reflect.DeepEqual(cmd.Args, []string{"-I", "-B", "-u", "-c", bootstrap, "statekit-jinja-v1"}) {
			t.Fatal("command was not static shell-free bootstrap")
		}
		if string(cmd.Stdin) == "" || string(cmd.Stdin) == "{{ secret }}" {
			t.Fatal("request was not JSON stdin")
		}
		if cmd.MaxStdoutBytes != bridgeStdoutBytes || cmd.MaxStderrBytes != MaxBytes || cmd.Timeout <= 0 {
			t.Fatal("command was not bounded")
		}
		for _, e := range cmd.Env {
			if len(e) >= len("PYTHON") && e[:len("PYTHON")] == "PYTHON" && e != "PYTHONNOUSERSITE=1" && e != "PYTHONDONTWRITEBYTECODE=1" && e != "PYTHONUTF8=1" {
				t.Fatal("scrubbed environment leaked")
			}
		}
	}
}

func TestRenderCandidatesUnavailableIsStableAndRedacted(t *testing.T) {
	runner := &recordingRunner{results: []process.CommandResult{{Err: os.ErrNotExist, ExitCode: -1}}}
	_, err := renderCandidates(context.Background(), runner, Request{Operation: "render", Source: "private"}, []string{"/missing/python"}, nil, "/work")
	if !errors.Is(err, ErrJinjaUnavailable) || err.Error() != ErrJinjaUnavailable.Error() {
		t.Fatalf("error = %v", err)
	}
}

func TestNonzeroMissingResponseIsTerminal(t *testing.T) {
	runner := &recordingRunner{results: []process.CommandResult{{ExitCode: 7, Stdout: []byte(`{"kind":"missing_jinja2"}`)}}}
	_, err := renderCandidates(context.Background(), runner, Request{Operation: "render"}, []string{"/a", "/b"}, nil, "/work")
	if err == nil || len(runner.cmds) != 1 || err.Error() != "jinja: Python bridge exited unsuccessfully" {
		t.Fatalf("result = %v, calls=%d", err, len(runner.cmds))
	}
}

func TestMalformedAndTruncatedResponsesAreTerminal(t *testing.T) {
	for _, result := range []process.CommandResult{
		{ExitCode: 0, Stdout: []byte(`{"kind":"ok"`)},
		{ExitCode: 0, Stdout: []byte(`{"kind":"ok"}`), StdoutTruncated: true},
	} {
		runner := &recordingRunner{results: []process.CommandResult{result}}
		_, err := renderCandidates(context.Background(), runner, Request{Operation: "render"}, []string{"/a"}, nil, "/work")
		if err == nil || !strings.Contains(err.Error(), "invalid Python bridge response") {
			t.Fatalf("result = %v", err)
		}
	}
}

func TestOKResponseRequiresPresentStringRendered(t *testing.T) {
	for _, rendered := range []string{"", "null", "7", "{}", "[]"} {
		frame := `{"kind":"ok"}`
		if rendered != "" {
			frame = `{"kind":"ok","rendered":` + rendered + `}`
		}
		runner := &recordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte(frame)}}}
		_, err := renderCandidates(context.Background(), runner, Request{Operation: "render"}, []string{"/a"}, nil, "/work")
		if err == nil || err.Error() != "jinja: invalid Python bridge response" {
			t.Fatalf("rendered=%q error=%v", rendered, err)
		}
	}
}

func TestMissingExecutableClassificationDoesNotInspectText(t *testing.T) {
	if !isMissingExecutable(process.CommandResult{ExitCode: -1, Err: os.ErrNotExist}) {
		t.Fatal("ENOENT start error was not classified as missing")
	}
	if isMissingExecutable(process.CommandResult{ExitCode: -1, Err: fmt.Errorf("runtime: no such file in template")}) {
		t.Fatal("runtime text was classified as missing")
	}
	if isMissingExecutable(process.CommandResult{ExitCode: 1, Err: os.ErrNotExist}) {
		t.Fatal("nonzero ENOENT result was classified as missing")
	}
}

func TestResolveCandidatesDeduplicatesSymlinkAliases(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bin, "python3")
	alias := filepath.Join(bin, "python")
	if err := os.WriteFile(target, []byte{}, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Skip("symlinks unavailable")
	}
	lookup := func(name string) (string, error) {
		if filepath.IsAbs(name) {
			return name, nil
		}
		return "", os.ErrNotExist
	}
	got := resolveCandidates([]string{"VIRTUAL_ENV=" + dir}, "", lookup, "linux")
	if !reflect.DeepEqual(got, []string{target}) {
		t.Fatalf("candidates = %#v, want only canonical duplicate winner %#v", got, []string{target})
	}
}
