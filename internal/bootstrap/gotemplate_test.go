package bootstrap

import "testing"

func TestBuildRuntimeRegistersNativeGoTemplateWithoutChangingJinja(t *testing.T) {
	rt, err := BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gotemplate.render", "gotemplate.import_yaml", "gotemplate.import_json", "gotemplate.load_map", "jinja.import_yaml", "jinja.import_json", "jinja.load_map"} {
		if _, ok := rt.Exec.Get(name); !ok {
			t.Errorf("%s not registered", name)
		}
	}
}
