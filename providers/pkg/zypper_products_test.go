package pkg

import (
	"context"
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperProductsXML = `<stream><product-list>` +
	`<product name="SLES" version="15-SP4" release="0" arch="x86_64" isbase="true" installed="1" vendor="SUSE">` +
	`<endoflife text="2028-07-31" time_t="1853904000"/>` +
	`<description>  SUSE Linux  <b/> Enterprise Server  </description>` +
	`</product>` +
	`<product name="SLED" version="15-SP4" isbase="false" installed="no" eol=""></product>` +
	`</product-list></stream>`

func TestZypperProductsInstalledQueryArgvAndResult(t *testing.T) {
	root := "/target"
	args := map[string]any{"root": &root}
	before := map[string]any{"root": &root}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperProductsXML)})

	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", args)
	want := []any{
		map[string]any{
			"name": "SLES", "version": "15-SP4", "release": "0", "arch": "x86_64",
			"isbase": true, "installed": true, "vendor": "SUSE",
			"eol": "2028-07-31", "eol_t": int64(1853904000),
			"description": "SUSE Linux Enterprise Server",
		},
		map[string]any{
			"name": "SLED", "version": "15-SP4",
			"isbase":      false,
			"installed":   false,
			"description": "",
		},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "--disable-repositories", "products", "-i"}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%#v want=%v", runner.commands, wantArgv)
	}
	assertZypperProductsCommand(t, runner.commands[0])
}

func TestZypperProductsAllTrueDropsInstalledSelectors(t *testing.T) {
	all := true
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(`<stream><product-list><product name="SLES" isbase="1"/></product-list></stream>`)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"all": &all})
	if err != nil || !reflect.DeepEqual(got, []any{map[string]any{"name": "SLES", "isbase": true, "description": ""}}) || len(runner.commands) != 1 {
		t.Fatalf("all got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "products"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("argv=%v want=%v", zypperCommandArgs(runner.commands[0]), want)
	}
	assertZypperProductsCommand(t, runner.commands[0])
}

func TestZypperProductsRefreshRootPositionAndForce(t *testing.T) {
	root := "/target"
	refresh := true
	rt, runner := zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{Stdout: []byte(`<stream><product-list/></stream>`)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"refresh": &refresh, "root": &root})
	if err != nil || !reflect.DeepEqual(got, []any{}) || len(runner.commands) != 2 {
		t.Fatalf("refresh got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	want := [][]string{
		{"zypper", "--non-interactive", "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "--disable-repositories", "products", "-i"},
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), want[i])
		}
		if i == 0 && !reflect.DeepEqual(command.Env, []string{"LC_ALL=C"}) {
			t.Fatalf("refresh env=%v", command.Env)
		}
	}

	emptyRoot := ""
	rt, runner = zypperLowpkgRuntime(process.CommandResult{}, process.CommandResult{Stdout: []byte(`<stream><product-list/></stream>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"refresh": true, "root": &emptyRoot})
	if err != nil || !reflect.DeepEqual(got, []any{}) || len(runner.commands) != 2 {
		t.Fatalf("empty-root got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	if want := []string{"zypper", "--non-interactive", "refresh"}; !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), want) {
		t.Fatalf("empty-root refresh argv=%v want=%v", zypperCommandArgs(runner.commands[0]), want)
	}
}

func TestZypperProductsDescriptionMultilineCollapse(t *testing.T) {
	output := `<stream><product-list><product name="multi">` +
		`<description>` + "\n" + `  SUSE Linux  ` + "\n\n" + ` Enterprise Server  ` + "\n" + `</description>` +
		`</product></product-list></stream>`
	records, err := zypperParseProducts(context.Background(), output)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	if got := zypperProductDescription(records[0].descParts); got != " SUSE Linux  Enterprise Server " {
		t.Fatalf("description=%q", got)
	}
	// A second description element must never contribute.
	output = `<stream><product-list><product name="two"><description>first</description><description>second</description></product></product-list></stream>`
	records, err = zypperParseProducts(context.Background(), output)
	if err != nil || len(records) != 1 || zypperProductDescription(records[0].descParts) != "first" {
		t.Fatalf("second description records=%#v err=%v", records, err)
	}
}

func TestZypperProductsEOLEdgeValues(t *testing.T) {
	for _, tc := range []struct {
		time_t string
		want   int64
	}{
		{"", 0},
		{"0", 0},
		{" 42 ", 42},
		{"1_000", 1000},
	} {
		got, err := zypperProductEOLTime(tc.time_t)
		if err != nil || got != tc.want {
			t.Fatalf("time_t=%q got=%d err=%v want=%d", tc.time_t, got, err, tc.want)
		}
	}
	for _, raw := range []string{"x", "1.0", "  ", "+"} {
		if got, err := zypperProductEOLTime(raw); err == nil || got != 0 || strings.Contains(err.Error(), raw) {
			t.Fatalf("invalid time_t=%q got=%d err=%v", raw, got, err)
		}
	}

	// An endoflife without a time_t attribute keeps eol_t zero.
	output := `<stream><product-list><product name="p"><endoflife text="2031-01-01"/></product></product-list></stream>`
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{})
	want := []any{map[string]any{"name": "p", "eol": "2031-01-01", "eol_t": int64(0), "description": ""}}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 1 {
		t.Fatalf("no-time_t got=%#v err=%v", got, err)
	}
}

type zypperProductsCountingFS struct {
	*runtime.MemoryFS
	reads []string
}

func (f *zypperProductsCountingFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	f.reads = append(f.reads, name)
	return f.MemoryFS.ReadFileBounded(name, limit)
}

func zypperProductsRuntimeWithOEM(t *testing.T, root, productline, content string, present bool) (*runtime.Runtime, *zypperProductsCountingFS) {
	t.Helper()
	memory := runtime.NewMemoryFS()
	if present {
		oemDir := "/var/lib/suseRegister/OEM"
		if root != "" {
			oemDir = path.Join(root, "var/lib/suseRegister/OEM")
		}
		if err := memory.MkdirAll(oemDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := memory.WriteFile(path.Join(oemDir, productline), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fsys := &zypperProductsCountingFS{MemoryFS: memory}
	runner := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		`<stream><product-list><product name="SLES" release="0" productline="` + productline + `"/></product-list></stream>`,
	)}}}
	return &runtime.Runtime{Runner: runner, FS: fsys}, fsys
}

func TestZypperProductsProductlineOEMOverride(t *testing.T) {
	root := "/target"
	rt, fsys := zypperProductsRuntimeWithOEM(t, root, "SLES", "  OEM-15-SP4  \nsecond line\n", true)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"root": &root})
	want := []any{map[string]any{"name": "SLES", "release": "OEM-15-SP4", "productline": "SLES", "description": ""}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("override got=%#v err=%v", got, err)
	}
	if len(fsys.reads) != 1 || fsys.reads[0] != "/target/var/lib/suseRegister/OEM/SLES" {
		t.Fatalf("reads=%v", fsys.reads)
	}

	// A whitespace-only OEM file never overrides the release attribute.
	rt, fsys = zypperProductsRuntimeWithOEM(t, root, "SLES", "   \n", true)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"root": &root})
	want = []any{map[string]any{"name": "SLES", "release": "0", "productline": "SLES", "description": ""}}
	if err != nil || !reflect.DeepEqual(got, want) || len(fsys.reads) != 1 {
		t.Fatalf("blank oem got=%#v err=%v reads=%v", got, err, fsys.reads)
	}

	// A missing OEM file is silently skipped, like the isfile guard.
	rt, fsys = zypperProductsRuntimeWithOEM(t, root, "MISSING", "", false)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{"root": &root})
	want = []any{map[string]any{"name": "SLES", "release": "0", "productline": "MISSING", "description": ""}}
	if err != nil || !reflect.DeepEqual(got, want) || len(fsys.reads) != 1 {
		t.Fatalf("missing oem got=%#v err=%v reads=%v", got, err, fsys.reads)
	}
}

func TestZypperProductsUnsafeProductlineNeverEscapesOEMDirectory(t *testing.T) {
	if zypperProductSafeProductline("con\x01trol") {
		t.Fatal("control-character productline accepted")
	}
	for _, productline := range []string{"", ".", "..", "../evil", "/etc/passwd", "a/b", "a\\b"} {
		if zypperProductSafeProductline(productline) {
			t.Fatalf("productline=%q accepted", productline)
		}
	}
	if !zypperProductSafeProductline("SLES") || !zypperProductSafeProductline("open-SUSE.15") {
		t.Fatal("plain productline rejected")
	}
	for _, productline := range []string{"../evil", "/etc/passwd", "a/b"} {
		rt, fsys := zypperProductsRuntimeWithOEM(t, "", productline, "evil-release\n", false)
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{})
		if err != nil || len(fsys.reads) != 0 {
			t.Fatalf("productline=%q reads=%v err=%v", productline, fsys.reads, err)
		}
		products, _ := got.([]any)
		if len(products) != 1 {
			t.Fatalf("productline=%q products=%#v", productline, products)
		}
		if release := products[0].(map[string]any)["release"]; release != "0" {
			t.Fatalf("productline=%q release=%#v", productline, release)
		}
	}
}

func TestZypperProductsEmptyMissingAndRepeatedProductList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		want   []any
	}{
		{"empty-document", `<stream/>`, []any{}},
		{"empty-product-list", `<stream><product-list/></stream>`, []any{}},
		{"product-outside-list", `<stream><product name="orphan"/></stream>`, []any{}},
		{"prefixed-list-ignored", `<stream xmlns:ns="urn:x"><ns:product-list><product name="p"/></ns:product-list></stream>`, []any{}},
		{"prefixed-product-ignored", `<stream><product-list><ns:product name="p" xmlns:ns="urn:x"/></product-list></stream>`, []any{}},
		{"second-list-ignored", `<stream><product-list/><product-list><product name="p"/></product-list></stream>`, []any{}},
	} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(tc.output)})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{})
		if err != nil || !reflect.DeepEqual(got, tc.want) || len(runner.commands) != 1 {
			t.Fatalf("%s got=%#v err=%v calls=%d", tc.name, got, err, len(runner.commands))
		}
	}
}

func TestZypperProductsNestedProductsShareFirstDescendants(t *testing.T) {
	output := `<stream><product-list>` +
		`<product name="outer">` +
		`<product name="inner"><endoflife text="2030-01-01" time_t="1893456000"/><description>inner</description></product>` +
		`</product>` +
		`</product-list></stream>`
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{})
	want := []any{
		map[string]any{"name": "outer", "eol": "2030-01-01", "eol_t": int64(1893456000), "description": "inner"},
		map[string]any{"name": "inner", "eol": "2030-01-01", "eol_t": int64(1893456000), "description": "inner"},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 1 {
		t.Fatalf("nested got=%#v err=%v", got, err)
	}
}

func TestZypperProductsParserRejectsMalformedAndEnforcesBounds(t *testing.T) {
	for _, output := range []string{
		"",
		"not xml",
		"<a/><b/>",
		"<stream><product-list></wrong></product-list></stream>",
		"</stream>",
	} {
		if got, err := zypperParseProducts(context.Background(), output); got != nil || err != errZypperProductsInvalidXML {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}
	if got, err := zypperParseProducts(context.Background(), "<stream>"+strings.Repeat("<node>", zypperSearchMaxXMLDepth)+"</stream>"); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("depth got=%#v err=%v", got, err)
	}
	if got, err := zypperParseProducts(context.Background(), "<stream>"+strings.Repeat(`<product-list><product name="p"/>`, zypperLowpkgMaxItems+1)+"</stream>"); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("items got=%#v err=%v", got, err)
	}
	var attrs strings.Builder
	for i := 0; i <= zypperPatternsMaxAttributesPerElement; i++ {
		attrs.WriteString(` a="v"`)
	}
	if got, err := zypperParseProducts(context.Background(), `<stream`+attrs.String()+`/>`); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("attribute-count got=%#v err=%v", got, err)
	}
	if got, err := zypperParseProducts(context.Background(), strings.Repeat("x", zypperLowpkgOutputLimit+1)); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output-bytes got=%#v err=%v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := zypperParseProducts(ctx, "<stream/>"); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled got=%#v err=%v", got, err)
	}
}

func TestZypperProductsErrorsCancellationAndValidation(t *testing.T) {
	for _, tc := range []struct {
		function string
		args     map[string]any
	}{
		{"list_products", map[string]any{"all": "yes"}},
		{"list_products", map[string]any{"refresh": 1}},
		{"list_products", map[string]any{"root": false}},
		{"list_products", map[string]any{"options": []string{"--details"}}},
	} {
		rt, runner := zypperLowpkgRuntime()
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args); got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s args=%#v got=%#v err=%v calls=%d", tc.function, tc.args, got, err, len(runner.commands))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime()
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "list_products", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	sentinel := errors.New("zypper runner failure")
	rt, runner = zypperLowpkgRuntime(process.CommandResult{Err: sentinel})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{}); got != nil || !errors.Is(err, sentinel) || len(runner.commands) != 1 {
		t.Fatalf("runner error got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	for _, result := range []process.CommandResult{
		{ExitCode: 1, Stderr: []byte("secret zypper stderr")},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
	} {
		rt, runner = zypperLowpkgRuntime(result)
		if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_products", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 || strings.Contains(err.Error(), "secret zypper stderr") {
			t.Fatalf("result=%#v got=%#v err=%v calls=%d", result, got, err, len(runner.commands))
		}
	}
}

func assertZypperProductsCommand(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
		t.Fatalf("unsafe command=%#v", command)
	}
	if want := []string{"LC_ALL=C", "ZYPP_READONLY_HACK=1"}; !reflect.DeepEqual(command.Env, want) {
		t.Fatalf("env=%v want=%v", command.Env, want)
	}
}
