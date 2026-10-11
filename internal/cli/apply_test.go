package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/output"
	"github.com/friz-zy/statekit/internal/result"
	"github.com/friz-zy/statekit/internal/runtime"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	"gopkg.in/yaml.v3"
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

func TestApplyRoomnumberUnknownKeyEchoBoundary(t *testing.T) {
	app, runner, fsys := newCLIUserApp(t)
	path := writeOps(t, `[{"state":"user.present","args":{"name":"synthetic","roomnumber":"42","ROOM_ECHO_MARKER":"DIFFERENT_VALUE_MARKER"}}]`)
	code, output, errText := captureCode(t, app, "apply", path)
	if code != ExitInvalidInput || !strings.Contains(errText, "ROOM_ECHO_MARKER") || strings.Contains(errText, "DIFFERENT_VALUE_MARKER") ||
		strings.Contains(output, "DIFFERENT_VALUE_MARKER") || fsys.boundedReads != 0 || fsys.unboundedRead != 0 || len(runner.commands) != 0 || len(runner.resolveCalls) != 0 {
		t.Fatal("Apply roomnumber unknown-key echo/effect boundary mismatch")
	}
}

func TestApplyRoomnumberStructuredBindingAndStatePresence(t *testing.T) {
	missing := map[string]any{"name": "synthetic"}
	args, code := decodeStructured("user.chroomnumber", execuser.ChRoomNumberArgs{}, missing)
	if args != nil || code != ExitInvalidInput {
		t.Fatal("missing required exec roomnumber binding mismatch")
	}
	for _, tc := range []struct {
		name      string
		value     any
		wantInner any
	}{
		{"null", nil, nil},
		{"empty", "", ""},
		{"integer", int(7), int(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound, code := decodeStructured("user.chroomnumber", execuser.ChRoomNumberArgs{}, map[string]any{
				"name": "synthetic", "roomnumber": tc.value,
			})
			if code != ExitOK {
				t.Fatal("explicit exec roomnumber binding failed")
			}
			value := bound.(*execuser.ChRoomNumberArgs).RoomNumber
			if value == nil || !reflect.DeepEqual(*value, tc.wantInner) {
				t.Fatal("explicit exec roomnumber presence mismatch")
			}
			stateArgs, stateCode := decodeStructured("user.present", statePresentArgsForTest{}, map[string]any{
				"name": "synthetic", "roomnumber": tc.value,
			})
			if stateCode != ExitOK {
				t.Fatal("explicit state roomnumber binding failed")
			}
			stateValue := reflect.ValueOf(stateArgs).Elem().FieldByName("RoomNumber")
			if stateValue.IsNil() || !reflect.DeepEqual(stateValue.Elem().Interface(), tc.wantInner) {
				t.Fatal("explicit state roomnumber presence mismatch")
			}
		})
	}

	// Apply accepts JSON-shaped documents through its YAML decoder. Null stays
	// unmanaged, while empty is a managed clear reported as metadata only.
	app, runner, fsys := newCLIUserApp(t)
	path := writeOps(t, `[{"state":"user.present","args":{"name":"synthetic","roomnumber":null}}]`)
	code, _, errText := captureCode(t, app, "apply", path, "-o", "json")
	if code != ExitOK || errText != "" || len(runner.commands) != 0 || len(runner.resolveCalls) != 0 || fsys.boundedReads != 0 || fsys.unboundedRead != 2 {
		t.Fatal("Apply null roomnumber did not remain unmanaged")
	}

	app, runner, fsys = newCLIUserApp(t)
	path = writeOps(t, `[{"state":"user.present","args":{"name":"synthetic","roomnumber":""}}]`)
	code, output, errText := captureCode(t, app, "apply", path, "-o", "json")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || len(runner.resolveCalls) != 1 || fsys.boundedReads != 3 || fsys.unboundedRead != 0 {
		t.Fatal("Apply empty roomnumber did not dispatch one managed clear")
	}
	if !reflect.DeepEqual(runner.commands[0].Args, []string{"-c", "first,,room,work,old", "synthetic"}) ||
		strings.Contains(output, "first,last,room,work") || strings.Contains(output, "old") {
		t.Fatal("Apply roomnumber output or command was not metadata-only")
	}
	var results []map[string]any
	if err := json.Unmarshal([]byte(output), &results); err != nil || len(results) != 1 {
		t.Fatal("Apply roomnumber result was not valid JSON")
	}
	changes, ok := results[0]["changes"].(map[string]any)
	if !ok || !reflect.DeepEqual(changes["roomnumber"], map[string]any{"changed": true}) {
		t.Fatal("Apply roomnumber Changes contract mismatch")
	}

	app, runner, fsys = newCLIUserApp(t)
	path = writeOps(t, `[{"state":"user.present","args":{"name":"synthetic","roomnumber":0}}]`)
	code, _, errText = captureCode(t, app, "apply", path, "-o", "json")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || len(runner.resolveCalls) != 1 ||
		fsys.boundedReads != 3 || fsys.unboundedRead != 0 || runner.commands[0].Args[1] != "first,0,room,work,old" {
		t.Fatal("Apply YAML-decoded integer roomnumber transport mismatch")
	}
}

// Test-only state prototype used to exercise decodeStructured's optional
// pointer-to-any presence in the Apply argument path.
type statePresentArgsForTest struct {
	Name       string `statekit:"required"`
	Other      *any   `statekit:"name=other"`
	RoomNumber *any   `statekit:"name=roomnumber"`
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

type applyOutcomeArgs struct {
	Name string `statekit:"required"`
	Test bool   `statekit:"name=test"`
}

type applyOutcomeCall struct {
	State string
	Name  string
	Test  bool
}

type applyOutcomeState struct {
	state  string
	result result.StateResult
	calls  *[]applyOutcomeCall
}

func (s *applyOutcomeState) Name() string { return s.state }

func (s *applyOutcomeState) Args() any { return applyOutcomeArgs{} }

func (s *applyOutcomeState) Apply(_ context.Context, _ *runtime.Runtime, args any) result.StateResult {
	a := args.(*applyOutcomeArgs)
	*s.calls = append(*s.calls, applyOutcomeCall{State: s.state, Name: a.Name, Test: a.Test})
	res := s.result
	res.Name = a.Name
	return res
}

type applyOutcomeStep struct {
	state  string
	result result.StateResult
}

func newApplyOutcomeStep(state, name string, value *bool) applyOutcomeStep {
	return applyOutcomeStep{
		state: state,
		result: result.New(name, "comment:"+name, value, map[string]any{
			"marker": map[string]any{"step": name},
		}),
	}
}

func newApplyOutcomeApp(t *testing.T, steps []applyOutcomeStep) (*App, *[]applyOutcomeCall) {
	t.Helper()
	states := runtime.NewStateRegistry()
	calls := []applyOutcomeCall{}
	for _, step := range steps {
		state := &applyOutcomeState{state: step.state, result: step.result, calls: &calls}
		if err := states.Register(state); err != nil {
			t.Fatal("register synthetic Apply state failed")
		}
	}
	rt := &runtime.Runtime{States: states}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil }), &calls
}

func applyOutcomeDocument(steps []applyOutcomeStep) string {
	var document strings.Builder
	for _, step := range steps {
		fmt.Fprintf(&document, "- state: %q\n  args: {name: %q}\n", step.state, step.result.Name)
	}
	return document.String()
}

func assertApplyOutcomeResults(t *testing.T, format, rendered string, want []result.StateResult) {
	t.Helper()
	if format == "text" {
		var expected strings.Builder
		for _, res := range want {
			expected.WriteString(output.StateResultText(res))
			expected.WriteString("---\n")
		}
		if rendered != expected.String() {
			t.Fatalf("text result payload/order mismatch: got %q", rendered)
		}
		return
	}

	var got []result.StateResult
	var err error
	if format == "json" {
		err = json.Unmarshal([]byte(rendered), &got)
	} else {
		err = yaml.Unmarshal([]byte(rendered), &got)
	}
	if err != nil || len(got) != len(want) {
		t.Fatalf("%s result list decode/length mismatch: len=%d err=%v", format, len(got), err)
	}
	for i := range want {
		resultMatches := (got[i].Result == nil) == (want[i].Result == nil)
		if resultMatches && got[i].Result != nil {
			resultMatches = *got[i].Result == *want[i].Result
		}
		if got[i].Name != want[i].Name || !resultMatches || got[i].Comment != want[i].Comment ||
			!reflect.DeepEqual(got[i].Changes, want[i].Changes) {
			t.Fatalf("%s result %d payload/order mismatch", format, i)
		}
	}
}

func TestApplyOutcomeExitContract(t *testing.T) {
	trueResult := result.Bool(true)
	falseResult := result.Bool(false)
	cases := []struct {
		name      string
		format    string
		onFailure string
		testMode  bool
		steps     []applyOutcomeStep
		executed  []int
		wantExit  int
	}{
		{
			name: "single-true-json", format: "json", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", trueResult)}, executed: []int{0},
		},
		{
			name: "single-true-yaml", format: "yaml", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", trueResult)}, executed: []int{0},
		},
		{
			name: "single-true-text", format: "text", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", trueResult)}, executed: []int{0},
		},
		{
			name: "single-false-json", format: "json", wantExit: ExitFailed,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", falseResult)}, executed: []int{0},
		},
		{
			name: "single-false-yaml", format: "yaml", wantExit: ExitFailed,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", falseResult)}, executed: []int{0},
		},
		{
			name: "single-false-text", format: "text", wantExit: ExitFailed,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", falseResult)}, executed: []int{0},
		},
		{
			name: "pending-only", format: "json", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.pending", "pending", nil)}, executed: []int{0},
		},
		{
			name: "pending-only-yaml", format: "yaml", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.pending", "pending", nil)}, executed: []int{0},
		},
		{
			name: "pending-only-text", format: "text", wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.pending", "pending", nil)}, executed: []int{0},
		},
		{
			name: "pending-global-test-json", format: "json", testMode: true, wantExit: ExitOK,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.pending", "pending", nil)}, executed: []int{0},
		},
		{
			name: "continue-true-then-false", format: "json", onFailure: "continue", wantExit: ExitFailed,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.first", "first", trueResult),
				newApplyOutcomeStep("test.second", "second", falseResult),
			}, executed: []int{0, 1},
		},
		{
			name: "continue-false-then-true", format: "yaml", onFailure: "continue", wantExit: ExitFailed,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.first", "first", falseResult),
				newApplyOutcomeStep("test.second", "second", trueResult),
			}, executed: []int{0, 1},
		},
		{
			name: "continue-all-true", format: "json", onFailure: "continue", wantExit: ExitOK,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.first", "first", trueResult),
				newApplyOutcomeStep("test.second", "second", trueResult),
			}, executed: []int{0, 1},
		},
		{
			name: "continue-false-then-pending", format: "json", onFailure: "continue", wantExit: ExitFailed,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.first", "first", falseResult),
				newApplyOutcomeStep("test.pending", "pending", nil),
			}, executed: []int{0, 1},
		},
		{
			name: "continue-pending-then-true", format: "json", onFailure: "continue", wantExit: ExitOK,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.pending", "pending", nil),
				newApplyOutcomeStep("test.second", "second", trueResult),
			}, executed: []int{0, 1},
		},
		{
			name: "stop-false-then-true", format: "json", wantExit: ExitFailed,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.first", "first", falseResult),
				newApplyOutcomeStep("test.second", "second", trueResult),
			}, executed: []int{0},
		},
		{
			name: "stop-pending-then-true", format: "yaml", wantExit: ExitOK,
			steps: []applyOutcomeStep{
				newApplyOutcomeStep("test.pending", "pending", nil),
				newApplyOutcomeStep("test.second", "second", trueResult),
			}, executed: []int{0, 1},
		},
		{
			name: "test-mode-false", format: "json", testMode: true, wantExit: ExitFailed,
			steps: []applyOutcomeStep{newApplyOutcomeStep("test.first", "first", falseResult)}, executed: []int{0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, calls := newApplyOutcomeApp(t, tc.steps)
			path := writeOps(t, applyOutcomeDocument(tc.steps))
			argv := []string{"apply", path}
			if tc.onFailure != "" {
				argv = append(argv, "--on-failure="+tc.onFailure)
			}
			if tc.testMode {
				argv = append(argv, "--test")
			}
			argv = append(argv, "-o", tc.format)
			code, rendered, errText := captureCode(t, app, argv...)
			if code != tc.wantExit || errText != "" {
				t.Fatalf("Apply exit=%d stderr=%q, want exit=%d", code, errText, tc.wantExit)
			}

			wantCalls := make([]applyOutcomeCall, 0, len(tc.executed))
			wantResults := make([]result.StateResult, 0, len(tc.executed))
			for _, index := range tc.executed {
				step := tc.steps[index]
				wantCalls = append(wantCalls, applyOutcomeCall{
					State: step.state, Name: step.result.Name, Test: tc.testMode,
				})
				wantResults = append(wantResults, step.result)
			}
			if !reflect.DeepEqual(*calls, wantCalls) {
				t.Fatalf("Apply state calls/order = %#v, want %#v", *calls, wantCalls)
			}
			assertApplyOutcomeResults(t, tc.format, rendered, wantResults)
		})
	}
}

// TestApplyEncodingFailurePrecedesStateOutcome is intentionally non-parallel:
// it swaps os.Stdout for a read-only temporary file to force an actual write error.
func TestApplyEncodingFailurePrecedesStateOutcome(t *testing.T) {
	trueResult := result.Bool(true)
	falseResult := result.Bool(false)
	for _, tc := range []struct {
		format string
		name   string
		result *bool
	}{
		{format: "json", name: "true", result: trueResult},
		{format: "json", name: "false", result: falseResult},
		{format: "yaml", name: "true", result: trueResult},
		{format: "yaml", name: "false", result: falseResult},
	} {
		t.Run(tc.format+"/"+tc.name, func(t *testing.T) {
			step := newApplyOutcomeStep("test.first", "first", tc.result)
			app, calls := newApplyOutcomeApp(t, []applyOutcomeStep{step})
			path := writeOps(t, applyOutcomeDocument([]applyOutcomeStep{step}))

			sinkPath := filepath.Join(t.TempDir(), "read-only-output")
			if err := os.WriteFile(sinkPath, nil, 0o600); err != nil {
				t.Fatal("create output sink failed")
			}
			sink, err := os.Open(sinkPath)
			if err != nil {
				t.Fatal("open read-only output sink failed")
			}
			originalStdout := os.Stdout
			t.Cleanup(func() {
				os.Stdout = originalStdout
				_ = sink.Close()
			})
			var code int
			_, stderr := capture(t, func() {
				capturedStdout := os.Stdout
				os.Stdout = sink
				defer func() { os.Stdout = capturedStdout }()
				code = app.Run([]string{"apply", path, "-o", tc.format})
			})
			if code != ExitInternal || !strings.HasPrefix(stderr, "statekit: ") ||
				strings.TrimSpace(strings.TrimPrefix(stderr, "statekit:")) == "" || strings.Contains(stderr, "internal failure:") {
				t.Fatalf("Apply write error did not return through the encoder path (exit=%d)", code)
			}
			if !reflect.DeepEqual(*calls, []applyOutcomeCall{{State: step.state, Name: step.result.Name}}) {
				t.Fatalf("state calls after output failure = %#v, want one invocation", *calls)
			}
		})
	}
}

type applySyntheticEncodingError struct{}

func (applySyntheticEncodingError) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("synthetic JSON serialization failure")
}

func (applySyntheticEncodingError) MarshalYAML() (any, error) {
	return nil, fmt.Errorf("synthetic YAML serialization failure")
}

func TestApplySerializationFailurePrecedesStateOutcome(t *testing.T) {
	falseResult := result.Bool(false)
	for _, format := range []string{"json", "yaml"} {
		t.Run(format+"-false", func(t *testing.T) {
			step := newApplyOutcomeStep("test.first", "first", falseResult)
			step.result.Changes = map[string]any{"opaque": applySyntheticEncodingError{}}
			app, calls := newApplyOutcomeApp(t, []applyOutcomeStep{step})
			path := writeOps(t, applyOutcomeDocument([]applyOutcomeStep{step}))

			code, _, errText := captureCode(t, app, "apply", path, "-o", format)
			if code != ExitInternal || !strings.HasPrefix(errText, "statekit: ") || strings.Contains(errText, "internal failure:") {
				t.Fatalf("%s serialization error did not take precedence over false state result (exit=%d)", format, code)
			}
			if !reflect.DeepEqual(*calls, []applyOutcomeCall{{State: step.state, Name: step.result.Name}}) {
				t.Fatalf("state calls after serialization failure = %#v, want one invocation", *calls)
			}
		})
	}
}
