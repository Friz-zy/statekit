package jinja

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	jinjarenderer "github.com/friz-zy/statekit/internal/renderer/jinja"
	"github.com/friz-zy/statekit/internal/runtime"
)

type fakeRunner struct{ result process.CommandResult }

func (r *fakeRunner) Run(_ context.Context, _ process.Command) process.CommandResult { return r.result }

type recordingBoundedFS struct {
	runtime.FileSystem
	data  []byte
	reads int
	err   error
}

func (f *recordingBoundedFS) ReadFileBounded(_ string, _ int64) ([]byte, error) {
	f.reads++
	return f.data, f.err
}

func TestFileBackedWrappersPreCancelledBeforeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(context.Context, *runtime.Runtime) (any, error)
	}{
		{"yaml", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (importYAMLFunc{}).Execute(ctx, rt, &importYAMLArgs{Path: "/x"})
		}},
		{"json", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (importJSONFunc{}).Execute(ctx, rt, &importJSONArgs{Path: "/x"})
		}},
		{"map", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (loadMapFunc{}).Execute(ctx, rt, &loadMapArgs{Path: "/x", Value: "answer"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := &recordingBoundedFS{FileSystem: runtime.NewMemoryFS(), data: []byte("unused")}
			rt := &runtime.Runtime{FS: fsys, Runner: &fakeRunner{}}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := tc.fn(ctx, rt)
			if !errors.Is(err, context.Canceled) || fsys.reads != 0 {
				t.Fatalf("result=%v reads=%d", err, fsys.reads)
			}
		})
	}
}

func TestImportWrappersUseCancellableBoundedDecoders(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		call func(context.Context, *runtime.Runtime) (any, error)
		want string
	}{
		{"yaml", []byte("answer: 7"), func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (importYAMLFunc{}).Execute(ctx, rt, &importYAMLArgs{Path: "/x"})
		}, `{"answer":7}`},
		{"json", []byte("{\"answer\":7}"), func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (importJSONFunc{}).Execute(ctx, rt, &importJSONArgs{Path: "/x"})
		}, `{"answer":7}`},
		{"map", []byte("answer = 7"), func(ctx context.Context, rt *runtime.Runtime) (any, error) {
			return (loadMapFunc{}).Execute(ctx, rt, &loadMapArgs{Path: "/x", Value: "answer"})
		}, "7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := &recordingBoundedFS{FileSystem: runtime.NewMemoryFS(), data: tc.data}
			rt := &runtime.Runtime{FS: fsys, Runner: &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"` + string(tc.data) + `"}`)}}}
			// The fake response is replaced below with the rendered document/value.
			if tc.name == "yaml" {
				rt.Runner = &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"answer: 7"}`)}}
			}
			if tc.name == "json" {
				rt.Runner = &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"{\"answer\":7}"}`)}}
			}
			if tc.name == "map" {
				rt.Runner = &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"7"}`)}}
			}
			got, err := tc.call(context.Background(), rt)
			if err != nil || fsys.reads != 1 {
				t.Fatalf("result=%#v err=%v reads=%d", got, err, fsys.reads)
			}
			b, _ := json.Marshal(got)
			if string(b) != tc.want {
				t.Fatalf("value=%s want=%s", b, tc.want)
			}
		})
	}
}

func TestPythonResourceErrorIsTerminal(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"resource_limit"}`)}}}
	if err := rt.FS.WriteFile("/x", []byte("value: 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (importJSONFunc{}).Execute(context.Background(), rt, &importJSONArgs{Path: "/x"})
	if err == nil || got != false {
		t.Fatalf("result = %#v, %v", got, err)
	}
}

func TestImportJSONMissingFileReturnsFalseWithoutBridge(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: &fakeRunner{result: process.CommandResult{ExitCode: 0}}}
	got, err := (importJSONFunc{}).Execute(context.Background(), rt, &importJSONArgs{Path: "/missing"})
	if err != nil || got != false {
		t.Fatalf("result = %#v, %v", got, err)
	}
}

func TestReadSourceRequiresBoundedFilesystem(t *testing.T) {
	_, err := readSource(&runtime.Runtime{FS: struct{ runtime.FileSystem }{}}, "/x")
	if err == nil {
		t.Fatal("unbounded filesystem was accepted")
	}
}

func TestLoadMapDecodesOnlySelectedJSONValue(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"42"}`)}}}
	if err := rt.FS.WriteFile("/map", []byte("answer = 42"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/map", Value: "answer"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(got)
	if err != nil || string(b) != "42" {
		t.Fatalf("value = %#v (%v), want 42", got, err)
	}
}

func TestJinjaErrorsNeverExposeControlledPath(t *testing.T) {
	secret := "jinja-path-secret-7f3a"
	path := "/missing/" + secret
	fsys := &recordingBoundedFS{FileSystem: runtime.NewMemoryFS(), err: fmt.Errorf("open %s: permission denied", path)}
	rt := &runtime.Runtime{FS: fsys, Runner: &fakeRunner{}}
	got, err := (importJSONFunc{}).Execute(context.Background(), rt, &importJSONArgs{Path: path})
	if got != false || err == nil || strings.Contains(err.Error(), secret) || !errors.Is(err, ErrRead) {
		t.Fatalf("result=%#v err=%v", got, err)
	}
}

func TestJinjaDecodeErrorsNeverExposeControlledPath(t *testing.T) {
	secret := "rendered-secret-91ab"
	path := "/data/" + secret
	fsys := &recordingBoundedFS{FileSystem: runtime.NewMemoryFS(), data: []byte("ignored")}
	rt := &runtime.Runtime{FS: fsys, Runner: &fakeRunner{result: process.CommandResult{ExitCode: 0, Stdout: []byte(`{"kind":"ok","rendered":"not-json"}`)}}}
	got, err := (importJSONFunc{}).Execute(context.Background(), rt, &importJSONArgs{Path: path})
	if got != false || err == nil || strings.Contains(err.Error(), secret) || !errors.Is(err, ErrInvalidRendered) {
		t.Fatalf("result=%#v err=%v", got, err)
	}
}

func TestJinjaRealPythonContractWhenAvailable(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	check := exec.Command(python, "-I", "-c", "import jinja2")
	if err := check.Run(); err != nil {
		t.Skip("python3 -I cannot import jinja2")
	}
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: process.NewRunner()}
	if err := rt.FS.WriteFile("/data.yaml", []byte("{% set value = 42 %}answer: {{ value }}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/data.json", []byte(`{% set value = 42 %}{"answer": {{ value }}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/map", []byte("answer = 42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/bad-map", []byte("{% set answer = 42 %}visible output"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The renderer's public contract supplies no host data; this verifies
	// variable and conditional evaluation without filesystem/network access.
	got, err := jinjarenderer.Render(context.Background(), rt.Runner, jinjarenderer.Request{Operation: "render", Source: "{% set value = 42 %}{{ value }} {% if value %}yes{% else %}no{% endif %}"})
	if err != nil || got != "42 yes" {
		t.Fatalf("render=%q err=%v", got, err)
	}
	for _, tc := range []struct {
		name string
		call func() (any, error)
		want string
	}{
		{"yaml", func() (any, error) {
			return (importYAMLFunc{}).Execute(context.Background(), rt, &importYAMLArgs{Path: "/data.yaml"})
		}, `{"answer":42}`},
		{"json", func() (any, error) {
			return (importJSONFunc{}).Execute(context.Background(), rt, &importJSONArgs{Path: "/data.json"})
		}, `{"answer":42}`},
		{"map", func() (any, error) {
			return (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/map", Value: "answer"})
		}, "42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(got)
			if string(encoded) != tc.want {
				t.Fatalf("value=%s want=%s", encoded, tc.want)
			}
		})
	}
	for _, source := range []string{"visible {{ value }}", "{% for x in value %}{{ x }}{% endfor %}", "{{ value() }}"} {
		if _, err := jinjarenderer.Render(context.Background(), rt.Runner, jinjarenderer.Request{Operation: "render", Source: source}); err == nil {
			t.Fatalf("source %q was accepted", source)
		}
	}
	if _, err := (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/bad-map", Value: "answer"}); err == nil {
		t.Fatal("load_map accepted non-whitespace source output")
	}
}
