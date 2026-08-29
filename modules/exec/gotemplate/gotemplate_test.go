package gotemplate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	renderer "github.com/friz-zy/statekit/internal/renderer/gotemplate"
	"github.com/friz-zy/statekit/internal/runtime"
)

type recordingBoundedFS struct {
	runtime.FileSystem
	reads int
}

func (f *recordingBoundedFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	f.reads++
	return runtime.ReadFileBounded(f.FileSystem, name, limit)
}

func TestFunctionsRenderAndImports(t *testing.T) {
	mem := runtime.NewMemoryFS()
	if err := mem.WriteFile("/data.yaml", []byte("name: {{.name}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/data.json", []byte(`{"name":"{{.name}}"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	got, err := (renderFunc{}).Execute(ctx, &runtime.Runtime{}, &renderArgs{Contents: "{{.name}}", Context: map[string]any{"name": "rendered"}})
	if err != nil || got != "rendered" {
		t.Fatalf("render = %#v, %v", got, err)
	}
	rt := &runtime.Runtime{FS: mem}
	got, err = (importYAMLFunc{}).Execute(ctx, rt, &importArgs{Path: "/data.yaml", Context: map[string]any{"name": "yaml"}})
	if err != nil || got.(map[string]any)["name"] != "yaml" {
		t.Fatalf("yaml = %#v, %v", got, err)
	}
	got, err = (importJSONFunc{}).Execute(ctx, rt, &importArgs{Path: "/data.json", Context: map[string]any{"name": "json"}})
	if err != nil || got.(map[string]any)["name"] != "json" {
		t.Fatalf("json = %#v, %v", got, err)
	}
	got, err = (importYAMLFunc{}).Execute(ctx, rt, &importArgs{Path: "/missing"})
	if err != nil || got != false {
		t.Fatalf("missing = %#v, %v", got, err)
	}
}

func TestFileBackedFunctionsRejectOversizedSource(t *testing.T) {
	mem := runtime.NewMemoryFS()
	if err := mem.WriteFile("/large", []byte(strings.Repeat("x", renderer.MaxBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: mem}
	checks := []struct {
		name string
		call func() (any, error)
	}{
		{"import_yaml", func() (any, error) {
			return (importYAMLFunc{}).Execute(context.Background(), rt, &importArgs{Path: "/large"})
		}},
		{"import_json", func() (any, error) {
			return (importJSONFunc{}).Execute(context.Background(), rt, &importArgs{Path: "/large"})
		}},
		{"load_map", func() (any, error) {
			return (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/large", Value: "selected"})
		}},
	}
	for _, check := range checks {
		if _, err := check.call(); !errors.Is(err, renderer.ErrSourceLimit) {
			t.Errorf("%s error = %v, want source limit", check.name, err)
		}
	}
}

func TestFileBackedFunctionsRejectPreCanceledContextBeforeReading(t *testing.T) {
	base := runtime.NewMemoryFS()
	if err := base.WriteFile("/data", []byte(`{"value":"ok"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys := &recordingBoundedFS{FileSystem: base}
	rt := &runtime.Runtime{FS: fsys}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		call func() (any, error)
	}{
		{"import_json", func() (any, error) {
			return (importJSONFunc{}).Execute(ctx, rt, &importArgs{Path: "/data"})
		}},
		{"import_yaml", func() (any, error) {
			return (importYAMLFunc{}).Execute(ctx, rt, &importArgs{Path: "/data"})
		}},
		{"load_map", func() (any, error) {
			return (loadMapFunc{}).Execute(ctx, rt, &loadMapArgs{Path: "/data", Value: "selected"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys.reads = 0
			if _, err := tc.call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
			if fsys.reads != 0 {
				t.Fatalf("bounded reads = %d, want 0", fsys.reads)
			}
		})
	}
}

func TestFileBackedFunctionsUseBoundedReadAndSanitizeDecoderErrors(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		contents string
		call     func(context.Context, *runtime.Runtime, string) (any, error)
		want     any
	}{
		{"import_json", "/valid.json", `{"value":"json"}`, func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (importJSONFunc{}).Execute(ctx, rt, &importArgs{Path: path})
		}, map[string]any{"value": "json"}},
		{"import_yaml", "/valid.yaml", "value: yaml\n", func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (importYAMLFunc{}).Execute(ctx, rt, &importArgs{Path: path})
		}, map[string]any{"value": "yaml"}},
		{"load_map", "/valid.tmpl", `{{define "selected"}}value: map{{end}}`, func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (loadMapFunc{}).Execute(ctx, rt, &loadMapArgs{Path: path, Value: "selected"})
		}, map[string]any{"value": "map"}},
	}
	for _, tc := range cases {
		t.Run(tc.name+" valid", func(t *testing.T) {
			base := runtime.NewMemoryFS()
			if err := base.WriteFile(tc.path, []byte(tc.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			fsys := &recordingBoundedFS{FileSystem: base}
			got, err := tc.call(context.Background(), &runtime.Runtime{FS: fsys}, tc.path)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("result = %#v, %v; want %#v", got, err, tc.want)
			}
			if fsys.reads != 1 {
				t.Fatalf("bounded reads = %d, want 1", fsys.reads)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		path     string
		contents string
		call     func(context.Context, *runtime.Runtime, string) (any, error)
	}{
		{"import_json", "/bad.json", "{", func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (importJSONFunc{}).Execute(ctx, rt, &importArgs{Path: path})
		}},
		{"import_yaml", "/bad.yaml", "[unterminated", func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (importYAMLFunc{}).Execute(ctx, rt, &importArgs{Path: path})
		}},
		{"load_map", "/bad.tmpl", `{{define "selected"}}[unterminated{{end}}`, func(ctx context.Context, rt *runtime.Runtime, path string) (any, error) {
			return (loadMapFunc{}).Execute(ctx, rt, &loadMapArgs{Path: path, Value: "selected"})
		}},
	} {
		t.Run(tc.name+" decoder error", func(t *testing.T) {
			base := runtime.NewMemoryFS()
			if err := base.WriteFile(tc.path, []byte(tc.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			fsys := &recordingBoundedFS{FileSystem: base}
			_, err := tc.call(context.Background(), &runtime.Runtime{FS: fsys}, tc.path)
			if err == nil || !strings.Contains(err.Error(), "gotemplate.") {
				t.Fatalf("error = %v, want sanitized wrapper error", err)
			}
			if fsys.reads != 1 {
				t.Fatalf("bounded reads = %d, want 1", fsys.reads)
			}
		})
	}
	// Bounded reads do not receive a context, and the wrapper has no exported
	// hook between reading and decoding. Mid-decode cancellation is covered by
	// the renderer's exported DecodeJSON/DecodeYAML tests instead.
}

func TestLoadMapExecutesSelectedNamedTemplate(t *testing.T) {
	mem := runtime.NewMemoryFS()
	if err := mem.WriteFile("/map.tmpl", []byte(`{{define "selected"}}key: {{.value}}{{end}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &runtime.Runtime{FS: mem}
	got, err := (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/map.tmpl", Value: "selected", Context: map[string]any{"value": "ok"}})
	if err != nil || got.(map[string]any)["key"] != "ok" {
		t.Fatalf("load_map = %#v, %v", got, err)
	}
	if _, err := (loadMapFunc{}).Execute(context.Background(), rt, &loadMapArgs{Path: "/map.tmpl", Value: "bad-name"}); err == nil {
		t.Fatal("unsafe name accepted")
	}
}

func TestRegisterExposesCanonicalNames(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gotemplate.render", "gotemplate.import_yaml", "gotemplate.import_json", "gotemplate.load_map"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("%s not registered", name)
		}
	}
}
