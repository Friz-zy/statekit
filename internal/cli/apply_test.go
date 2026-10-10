package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	execuser "github.com/friz-zy/statekit/modules/exec/user"
)

func writeOps(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyDocumentParsing(t *testing.T) {
	ops, err := loadOperations([]byte("operations:\n  - state: test.nop\n    args: {name: a}\n"))
	if err != nil || len(ops) != 1 || ops[0].State != "test.nop" || ops[0].Args["name"] != "a" {
		t.Fatalf("object form wrong: %+v %v", ops, err)
	}
	ops, err = loadOperations([]byte("- state: file.managed\n"))
	if err != nil || len(ops) != 1 || ops[0].State != "file.managed" {
		t.Fatalf("bare list form wrong: %+v %v", ops, err)
	}
	if _, err := loadOperations(nil); err == nil {
		t.Fatal("empty document must fail")
	}
	if _, err := loadOperations([]byte("just: text\n")); err == nil {
		t.Fatal("non-operation document must fail")
	}
}

func TestApplyOtherRawTypeMatrixForYAMLAndJSONShapedDocuments(t *testing.T) {
	type row struct {
		name  string
		token string
		want  any
	}
	rows := []row{
		{"null", "null", nil}, {"empty string", `""`, ""}, {"quoted digits", `"0007"`, "0007"},
		{"zero", "0", int(0)}, {"negative one", "-1", int(-1)},
		{"minimum signed 64", "-9223372036854775808", int64(-9223372036854775808)},
		{"maximum signed 64", "9223372036854775807", int64(9223372036854775807)},
		{"signed maximum plus one", "9223372036854775808", uint64(9223372036854775808)},
		{"uint64 maximum", "18446744073709551615", uint64(18446744073709551615)},
		{"below signed minimum", "-9223372036854775809", float64(-9223372036854775809)},
		{"above uint64 maximum", "18446744073709551616", float64(18446744073709551616)},
		{"fraction", "1.5", float64(1.5)}, {"decimal point", "1.0", float64(1)},
		{"true", "true", true}, {"false", "false", false},
		{"array", "[0]", []any{int(0)}}, {"object", `{"x":0}`, map[string]any{"x": int(0)}},
	}
	if reflect.TypeOf(int(0)).Bits() == 64 {
		min64, max64 := int64(-9223372036854775808), int64(9223372036854775807)
		rows[5].want = int(min64)
		rows[6].want = int(max64)
	}
	formats := []struct {
		name string
		json bool
		obj  bool
	}{
		{"YAML list", false, false}, {"YAML operations object", false, true},
		{"JSON-shaped list", true, false}, {"JSON-shaped operations object", true, true},
	}
	for _, row := range rows {
		for _, format := range formats {
			t.Run(row.name+"/"+format.name, func(t *testing.T) {
				var document string
				if format.json {
					if format.obj {
						document = `{"operations":[{"state":"user.present","args":{"name":"synthetic","other":` + row.token + `}}]}`
					} else {
						document = `[{"state":"user.present","args":{"name":"synthetic","other":` + row.token + `}}]`
					}
				} else if format.obj {
					document = "operations:\n  - state: user.present\n    args:\n      name: synthetic\n      other: " + row.token + "\n"
				} else {
					document = "- state: user.present\n  args:\n    name: synthetic\n    other: " + row.token + "\n"
				}
				ops, err := loadOperations([]byte(document))
				if err != nil || len(ops) != 1 {
					t.Fatalf("load operations = %#v, %v", ops, err)
				}
				got, present := ops[0].Args["other"]
				if !present || reflect.TypeOf(got) != reflect.TypeOf(row.want) || !reflect.DeepEqual(got, row.want) {
					t.Fatalf("Apply raw other = %#v (%T), present=%v; want %#v (%T)", got, got, present, row.want, row.want)
				}
				execBound, code := decodeStructured("user.chother", execuser.ChOtherArgs{}, ops[0].Args)
				if code != ExitOK {
					t.Fatalf("parsed map did not bind required exec template: %d", code)
				}
				execOther := execBound.(*execuser.ChOtherArgs).Other
				if execOther == nil || !reflect.DeepEqual(*execOther, row.want) {
					t.Fatalf("parsed map exec *any = %#v, want %#v", execOther, row.want)
				}
				stateBound, code := decodeStructured("user.present", statePresentArgsForTest{}, ops[0].Args)
				if code != ExitOK {
					t.Fatalf("parsed map did not bind optional state template: %d", code)
				}
				stateOther := stateBound.(*statePresentArgsForTest).Other
				if stateOther == nil || !reflect.DeepEqual(*stateOther, row.want) {
					t.Fatalf("parsed map state *any = %#v, want %#v", stateOther, row.want)
				}
			})
		}
	}

	for _, format := range formats {
		t.Run("omitted/"+format.name, func(t *testing.T) {
			var document string
			if format.json {
				if format.obj {
					document = `{"operations":[{"state":"user.present","args":{"name":"synthetic"}}]}`
				} else {
					document = `[{"state":"user.present","args":{"name":"synthetic"}}]`
				}
			} else if format.obj {
				document = "operations:\n  - state: user.present\n    args: {name: synthetic}\n"
			} else {
				document = "- state: user.present\n  args: {name: synthetic}\n"
			}
			ops, err := loadOperations([]byte(document))
			if err != nil || len(ops) != 1 {
				t.Fatalf("load operations = %#v, %v", ops, err)
			}
			if _, present := ops[0].Args["other"]; present {
				t.Fatal("omitted Apply other key was manufactured")
			}
			if _, code := decodeStructured("user.chother", execuser.ChOtherArgs{}, ops[0].Args); code != ExitInvalidInput {
				t.Fatalf("omitted Apply exec other binding code = %d, want invalid input", code)
			}
			stateBound, code := decodeStructured("user.present", statePresentArgsForTest{}, ops[0].Args)
			if code != ExitOK || stateBound.(*statePresentArgsForTest).Other != nil {
				t.Fatalf("omitted Apply state Other = %#v code=%d", stateBound, code)
			}
		})
	}
}

func TestApplyOtherStructuredBindingAndStatePresence(t *testing.T) {
	missing := map[string]any{"name": "synthetic"}
	args, code := decodeStructured("user.chother", execuser.ChOtherArgs{}, missing)
	if args != nil || code != ExitInvalidInput {
		t.Fatalf("missing required exec other bound as %#v with code %d", args, code)
	}

	for _, tc := range []struct {
		name      string
		args      map[string]any
		wantOuter bool
		wantInner any
	}{
		{"null", map[string]any{"name": "synthetic", "other": nil}, true, nil},
		{"empty", map[string]any{"name": "synthetic", "other": ""}, true, ""},
		{"integer", map[string]any{"name": "synthetic", "other": int(0)}, true, int(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound, code := decodeStructured("user.chother", execuser.ChOtherArgs{}, tc.args)
			if code != ExitOK {
				t.Fatalf("required exec binding code = %d", code)
			}
			value := bound.(*execuser.ChOtherArgs).Other
			if (value != nil) != tc.wantOuter || (value != nil && !reflect.DeepEqual(*value, tc.wantInner)) {
				t.Fatalf("bound Other = %#v, want outer=%v inner=%#v", value, tc.wantOuter, tc.wantInner)
			}
			stateArgs, stateCode := decodeStructured("user.present", statePresentArgsForTest{}, tc.args)
			if stateCode != ExitOK {
				t.Fatalf("optional state binding code = %d", stateCode)
			}
			stateValue := reflect.ValueOf(stateArgs).Elem().FieldByName("Other")
			if stateValue.IsNil() {
				t.Fatalf("state Other outer pointer is nil for explicit %s", tc.name)
			}
			if tc.name == "null" && !stateValue.Elem().IsNil() {
				t.Fatalf("state null inner interface = %#v", stateValue.Elem().Interface())
			}
		})
	}

	// Apply itself uses YAML parsing for JSON-shaped operation files. Null
	// stays unmanaged, while explicit empty is managed clear.
	for _, tc := range []struct {
		name    string
		args    string
		changed bool
	}{
		{"omitted", `{"name":"synthetic"}`, false},
		{"null", `{"name":"synthetic","other":null}`, false},
		{"empty", `{"name":"synthetic","other":""}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, runner, fsys := newCLIUserApp(t)
			path := writeOps(t, `[{"state":"user.present","args":`+tc.args+`}]`)
			code, output, errText := captureCode(t, app, "apply", path, "-o", "json")
			if code != ExitOK || errText != "" {
				t.Fatalf("apply code=%d err=%q output=%q", code, errText, output)
			}
			if tc.changed {
				if len(runner.commands) != 1 || fsys.boundedReads != 3 || fsys.unboundedRead != 0 {
					t.Fatalf("explicit empty Apply state = output %q commands=%v reads=%d/%d", output, runner.commands, fsys.boundedReads, fsys.unboundedRead)
				}
				var results []map[string]any
				if err := json.Unmarshal([]byte(output), &results); err != nil || len(results) != 1 {
					t.Fatalf("decode Apply output %q: results=%#v err=%v", output, results, err)
				}
				changes, changesOK := results[0]["changes"].(map[string]any)
				otherChange, otherOK := changes["other"].(map[string]any)
				if !changesOK || !otherOK || !reflect.DeepEqual(otherChange, map[string]any{"changed": true}) {
					t.Fatalf("Apply metadata changes = %#v", results[0]["changes"])
				}
			} else if len(runner.commands) != 0 || fsys.boundedReads != 0 || fsys.unboundedRead != 2 || strings.Contains(output, `"other"`) {
				t.Fatalf("omitted/null Apply state = output %q commands=%v reads=%d/%d", output, runner.commands, fsys.boundedReads, fsys.unboundedRead)
			}
		})
	}
}

// Test-only state prototype used to exercise decodeStructured's optional
// pointer-to-any presence in the Apply argument path.
type statePresentArgsForTest struct {
	Name  string `statekit:"required"`
	Other *any   `statekit:"name=other"`
}

func TestApplyEndToEndViaApp(t *testing.T) {
	path := writeOps(t, `operations:
  - state: file.managed
    args: {name: /stage/a.conf, contents: A}
  - state: test.nop
    args: {name: mid}
`)
	code, out, _ := runApp(t, "apply", path)
	_ = out
	if code != ExitOK {
		t.Fatalf("apply exit = %d", code)
	}
}

func TestApplyStopsOnFailureByDefault(t *testing.T) {
	path := writeOps(t, `operations:
  - state: nosuch.state
    args: {name: x}
  - state: test.nop
    args: {name: never}
`)
	code, _, _ := runApp(t, "apply", path)
	if code != ExitUnsupported {
		t.Fatalf("unsupported operation exit = %d", code)
	}
}

func TestApplyTestModeGlobal(t *testing.T) {
	path := writeOps(t, "operations:\n  - state: test.nop\n    args: {name: a}\n")
	code, out, _ := runApp(t, "apply", path, "--test", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"result": true`) {
		t.Fatalf("global test mode: code=%d out=%q", code, out)
	}
}
