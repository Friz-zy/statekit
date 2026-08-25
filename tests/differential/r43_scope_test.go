package differential_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/bootstrap"
	execcp "github.com/friz-zy/statekit/modules/exec/cp"
	execdata "github.com/friz-zy/statekit/modules/exec/datastore"
	execdefaults "github.com/friz-zy/statekit/modules/exec/defaults"
	exectemp "github.com/friz-zy/statekit/modules/exec/temp"
	execxml "github.com/friz-zy/statekit/modules/exec/xml"
)

// R4.3 scope-pass tests: every new family registers with its full public
// surface and the live registry answers calls through the bootstrap.

func TestR43FamiliesRegistered(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]int{
		"cp":       14,
		"temp":     2,
		"xml":      4,
		"jinja":    3,
		"data":     11,
		"defaults": 4,
	}
	yamlLintWant := 1
	counts := map[string]int{}
	for _, name := range rt.Exec.Names() {
		head := strings.SplitN(name, ".", 2)[0]
		if _, tracked := expected[head]; tracked {
			counts[head]++
		}
		if name == "yaml.lint" {
			counts["yaml"]++
		}
	}
	for prefix, want := range expected {
		if counts[prefix] != want {
			t.Fatalf("%s registered %d functions; want %d", prefix, counts[prefix], want)
		}
	}
	if counts["yaml"] != yamlLintWant {
		t.Fatalf("yaml.lint registered %d; want %d", counts["yaml"], yamlLintWant)
	}
}

func TestR43SmokeCalls(t *testing.T) {
	rt, err := bootstrap.BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Keep datastore and temp writes inside a per-test scratch directory.
	scratch := t.TempDir()
	savedDir := execdata.ExportDataDir()
	execdata.SetDataDir(scratch)
	t.Cleanup(func() { execdata.SetDataDir(savedDir) })

	// temp.dir round trip.
	dirRes, derr := exectemp.DirFunc{}.Execute(ctx, rt, &exectemp.DirArgs{})
	if derr != nil {
		t.Fatal(derr)
	}
	tempDir := dirRes.(string)
	rt.FS.WriteFile(tempDir+"/marker", []byte("x"), 0o644)
	defer func() { _ = rt.FS.RemoveAll(tempDir) }()

	// cp.get_file local copy into that directory. BuildRuntime uses the
	// OS filesystem, so the source lives beside the temp target.
	srcPath := tempDir + "/source/app.conf"
	if err := rt.FS.MkdirAll(tempDir+"/source", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile(srcPath, []byte("key=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := tempDir + "/"
	getFileFn := execcp.GetFileFunc{}
	cpRes, cerr := getFileFn.Execute(ctx, rt, &execcp.GetFileArgs{
		Path: srcPath, Dest: &dst,
	})
	if cerr != nil {
		t.Fatal(cerr)
	}
	target := cpRes.(string)
	data, rerr := rt.FS.ReadFile(target)
	if rerr != nil || string(data) != "key=value\n" {
		t.Fatalf("get_file target = %q err=%v", string(data), rerr)
	}

	// cp.hash_file over the same artifact.
	hashFn := execcp.HashFileFunc{}
	hashRes, herr := hashFn.Execute(ctx, rt, &execcp.HashFileArgs{Path: target})
	if herr != nil {
		t.Fatal(herr)
	}
	if h, ok := hashRes.(string); !ok || len(h) != 64 {
		t.Fatalf("hash_file = %#v", hashRes)
	}

	// data.update/get cycle.
	updateFn := execdata.UpdateFunc{}
	if _, uerr := updateFn.Execute(ctx, rt, &execdata.UpdateArgs{
		Key: "flavor", Value: "salty",
	}); uerr != nil {
		t.Fatal(uerr)
	}
	getDataFn := execdata.GetFunc{}
	getRes, gerr := getDataFn.Execute(ctx, rt, &execdata.GetArgs{Key: "flavor"})
	if gerr != nil || getRes != "salty" {
		t.Fatalf("data.get = %#v, %v", getRes, gerr)
	}

	// defaults.merge recursion.
	mergedRaw, merr := execdefaults.MergeFunc{}.Execute(ctx, rt, &execdefaults.MergeArgs{
		Dest: map[string]any{
			"a":    map[string]any{"x": 1},
			"keep": true,
		},
		Src: map[string]any{"a": map[string]any{"y": 2}},
	})
	if merr != nil {
		t.Fatal(merr)
	}
	merged := mergedRaw.(map[string]any)
	sub := merged["a"].(map[string]any)
	if sub["x"] != 1 || sub["y"] != 2 || merged["keep"] != true {
		t.Fatalf("merge = %#v", merged)
	}

	// xml set/get value cycle.
	xmlDir := filepath.Join(scratch, "xml")
	if err := rt.FS.MkdirAll(xmlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(xmlDir, "doc.xml")
	rt.FS.WriteFile(docPath, []byte("<root><item id=\"1\">old</item></root>"), 0o644)
	setValFn := execxml.SetValueFunc{}
	if _, serr := setValFn.Execute(ctx, rt, &execxml.SetValueArgs{
		File: docPath, Element: ".//item", Value: "new",
	}); serr != nil {
		t.Fatal(serr)
	}
	getValFn := execxml.GetValueFunc{}
	vRes, verr := getValFn.Execute(ctx, rt, &execxml.GetValueArgs{
		File: docPath, Element: ".//item",
	})
	if verr != nil || vRes != "new" {
		t.Fatalf("xml.get_value = %#v, %v", vRes, verr)
	}

	// yaml.lint is exercised in its own package suite; the registry name
	// presence is asserted in TestR43FamiliesRegistered.
}
