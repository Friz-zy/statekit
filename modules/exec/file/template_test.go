package file

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type panicRuntimeFS struct{ runtime.FileSystem }

type panicProcessRunner struct{}

func (panicProcessRunner) Run(context.Context, process.Command) process.CommandResult {
	panic("apply_template_on_contents invoked process runner")
}

func TestApplyTemplateOnContentsRegistrationAndArgs(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := RegisterMeta(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("file.apply_template_on_contents")
	if !ok {
		t.Fatal("file.apply_template_on_contents is not registered")
	}
	typ := reflect.TypeOf(fn.Args())
	for _, field := range []struct {
		name string
		tag  string
	}{
		{"Contents", `statekit:"required,name=contents"`},
		{"Template", `statekit:"required,name=template"`},
		{"Context", `statekit:"name=context"`},
		{"Defaults", `statekit:"name=defaults"`},
		{"Saltenv", `statekit:"required,name=saltenv"`},
	} {
		got, _ := typ.FieldByName(field.name)
		if string(got.Tag) != field.tag {
			t.Errorf("%s tag = %q, want %q", field.name, string(got.Tag), field.tag)
		}
	}
}

func TestApplyTemplateOnContentsGotemplate(t *testing.T) {
	contextValues := map[string]any{"name": "context", "nested": map[string]any{"value": "kept"}}
	defaults := map[string]any{"name": "default", "other": "fallback"}
	contextBefore := map[string]any{"name": "context", "nested": map[string]any{"value": "kept"}}
	defaultsBefore := map[string]any{"name": "default", "other": "fallback"}

	got, err := (applyTemplateOnContentsFunc{}).Execute(context.Background(), &runtime.Runtime{}, &applyTemplateOnContentsArgs{
		Contents: "{{.name}}/{{.other}}/{{.nested.value}}",
		Template: "gotemplate",
		Context:  contextValues,
		Defaults: defaults,
		Saltenv:  "ignored",
	})
	if err != nil || got != "context/fallback/kept" {
		t.Fatalf("render = %v, %v", got, err)
	}
	if !reflect.DeepEqual(contextValues, contextBefore) || !reflect.DeepEqual(defaults, defaultsBefore) {
		t.Fatal("renderer mutated context or defaults")
	}
}

func TestApplyTemplateOnContentsRuntimeIsolation(t *testing.T) {
	rt := &runtime.Runtime{
		FS:     panicRuntimeFS{},
		Runner: panicProcessRunner{},
	}

	got, err := (applyTemplateOnContentsFunc{}).Execute(context.Background(), rt, &applyTemplateOnContentsArgs{
		Contents: "hello {{.name}}",
		Template: "gotemplate",
		Context:  map[string]any{"name": "world"},
		Saltenv:  "base",
	})
	if err != nil || got != "hello world" {
		t.Fatalf("gotemplate = %#v, %v; want %q, nil", got, err, "hello world")
	}

	for _, name := range []string{"jinja", "mako", "wempy", "", "None", "unknown"} {
		got, err := (applyTemplateOnContentsFunc{}).Execute(context.Background(), rt, &applyTemplateOnContentsArgs{
			Contents: "ignored",
			Template: name,
			Saltenv:  "base",
		})
		want := map[string]any{"result": false, "comment": "Specified template format " + name + " is not supported"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("template %q = %#v, %v; want %#v", name, got, err, want)
		}
	}
}

func TestApplyTemplateOnContentsUnsupportedAndCancellation(t *testing.T) {
	for _, name := range []string{"jinja", "mako", "wempy", "", "None", "unknown"} {
		got, err := (applyTemplateOnContentsFunc{}).Execute(context.Background(), nil, &applyTemplateOnContentsArgs{
			Contents: "{{ invalid",
			Template: name,
			Saltenv:  "base",
		})
		want := map[string]any{"result": false, "comment": "Specified template format " + name + " is not supported"}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("template %q = %#v, %v; want %#v", name, got, err, want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (applyTemplateOnContentsFunc{}).Execute(ctx, nil, &applyTemplateOnContentsArgs{Template: "gotemplate"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled execution error = %v", err)
	}
}

func TestApplyTemplateOnContentsErrorDoesNotLeakValues(t *testing.T) {
	secret := "do-not-leak"
	_, err := (applyTemplateOnContentsFunc{}).Execute(context.Background(), nil, &applyTemplateOnContentsArgs{
		Contents: "{{.missing}}",
		Template: "gotemplate",
		Context:  map[string]any{"secret": secret},
		Saltenv:  "base",
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v, leaked secret or was absent", err)
	}
}
