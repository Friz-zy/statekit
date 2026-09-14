package zonecfg

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zonecfgRecordingRunner struct {
	results []*process.CommandResult
	calls   []process.Command
	cancel  context.CancelFunc
}

func (r *zonecfgRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	r.calls = append(r.calls, command)
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := *r.results[0]
	r.results = r.results[1:]
	return result
}

func zonecfgRuntime(runner *zonecfgRecordingRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

type zonecfgCountingFS struct {
	*runtime.MemoryFS
	statErr      error
	statCalls    int
	mkdirCalls   int
	cancelOnStat context.CancelFunc
}

func (f *zonecfgCountingFS) Stat(name string) (fs.FileInfo, error) {
	f.statCalls++
	if f.cancelOnStat != nil {
		f.cancelOnStat()
		f.cancelOnStat = nil
	}
	if f.statErr != nil {
		return nil, f.statErr
	}
	return f.MemoryFS.Stat(name)
}

func (f *zonecfgCountingFS) MkdirAll(path string, perm fs.FileMode) error {
	f.mkdirCalls++
	return f.MemoryFS.MkdirAll(path, perm)
}

func zonecfgArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func stringPtr(value string) *string { return &value }

func assertZonecfgBounds(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != zonecfgCommandTimeout ||
		command.MaxStdoutBytes != zonecfgOutputLimit ||
		command.MaxStderrBytes != zonecfgOutputLimit ||
		len(command.Stdin) > runtime.MaxCommandInputBytes {
		t.Fatalf("unsafe zonecfg command: %#v", command)
	}
}

// Solaris-constrained functions cannot execute through ExecRegistry on the
// Linux test host.  This adapter keeps the production Execute method while
// making the registry boundary testable here; the real Register/platform gate
// remains covered by TestZonecfgRegistryArgumentsPlatformAndLinuxCLI.
type currentPlatformRemoveResourceFunc struct{ removeResourceFunc }

func (currentPlatformRemoveResourceFunc) Platforms() []string {
	return []string{runtime.CurrentGOOS()}
}

func zonecfgRemoveResourceRegistry(t *testing.T) *runtime.ExecRegistry {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if runtime.CurrentGOOS() == "solaris" {
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		return reg
	}
	if err := reg.Register(currentPlatformRemoveResourceFunc{}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestZonecfgDirectSurfaceAndExactCommandStreams(t *testing.T) {
	tests := []struct {
		name  string
		fn    runtime.ExecFunction
		args  any
		argv  []string
		stdin string
	}{
		{"create", createFunc{}, &CreateArgs{Zone: "web", Brand: "solaris", Zonepath: "/zones/web", Force: true}, []string{"zonecfg", "-z", "web"}, "create -b -F\nset brand=solaris\nset zonepath=/zones/web\n"},
		{"create_from_template", createFromTemplateFunc{}, &CreateFromTemplateArgs{Zone: "web", Template: "SUNWsolaris"}, []string{"zonecfg", "-z", "web"}, "create -t SUNWsolaris -F\n"},
		{"delete", deleteFunc{}, &DeleteArgs{Zone: "web"}, []string{"zonecfg", "-z", "web"}, "delete -F\n"},
		{"export", exportFunc{}, &ExportArgs{Zone: "web", Path: stringPtr("/zones/web.cfg")}, []string{"zonecfg", "-z", "web"}, "export -f /zones/web.cfg\n"},
		{"import", importFunc{}, &ImportArgs{Zone: "web", Path: "/zones/web.cfg"}, []string{"zonecfg", "-z", "web", "-f", "/zones/web.cfg"}, ""},
		{"set_property", setPropertyFunc{}, &SetPropertyArgs{Zone: "web", Key: "cpu-shares", Value: 100}, []string{"zonecfg", "-z", "web"}, "set cpu-shares=100\n"},
		{"clear_property", clearPropertyFunc{}, &ClearPropertyArgs{Zone: "web", Key: "cpu-shares"}, []string{"zonecfg", "-z", "web"}, "clear cpu-shares\n"},
		{"add_resource", addResourceFunc{}, &AddResourceArgs{Zone: "web", ResourceType: "rctl", Kwargs: map[string]any{"value": "(priv=privileged,limit=33554432,action=deny)", "name": "zone.max-locked-memory"}}, []string{"zonecfg", "-z", "web"}, "add rctl\nset name=zone.max-locked-memory\nset value=(priv=privileged,limit=33554432,action=deny)\nend\n"},
		{"update_resource", updateResourceFunc{}, &UpdateResourceArgs{Zone: "web", ResourceType: "rctl", ResourceSelector: "name", Kwargs: map[string]any{"name": "zone.max-locked-memory", "value": "(priv=privileged,limit=33554432,action=deny)"}}, []string{"zonecfg", "-z", "web"}, "select rctl name=zone.max-locked-memory\nset value=(priv=privileged,limit=33554432,action=deny)\nend\n"},
		{"remove_resource", removeResourceFunc{}, &RemoveResourceArgs{Zone: "web", ResourceType: "rctl", ResourceKey: stringPtr("name"), ResourceValue: stringPtr("zone.max-locked-memory")}, []string{"zonecfg", "-z", "web"}, "remove rctl name=zone.max-locked-memory\n"},
		{"info", infoFunc{}, &InfoArgs{Zone: "web"}, []string{"zonecfg", "-z", "web"}, "info\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zonecfgRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte("zonecfg: done")}}}
			got, err := tc.fn.Execute(context.Background(), zonecfgRuntime(runner), tc.args)
			if tc.name == "info" {
				if err != nil || !reflect.DeepEqual(got, map[string]any{"zonecfg": "done"}) {
					t.Fatalf("info result=%#v err=%v", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, map[string]any{"status": true, "message": "done"}) {
				t.Fatalf("result=%#v err=%v", got, err)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(zonecfgArgv(runner.calls[0]), tc.argv) ||
				string(runner.calls[0].Stdin) != tc.stdin {
				t.Fatalf("call argv=%#v stdin=%q want argv=%#v stdin=%q", zonecfgArgv(runner.calls[0]), runner.calls[0].Stdin, tc.argv, tc.stdin)
			}
			assertZonecfgBounds(t, runner.calls[0])
		})
	}
}

func TestZonecfgRemoveResourceDecodeAndRegistryContract(t *testing.T) {
	tests := []struct {
		name            string
		structured      map[string]any
		wantStdin       string
		wantDecodeError bool
		wantCallError   error
	}{
		{
			name: "explicit empty selector",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "", "resource_value": "",
			},
			wantStdin: "remove dedicated-cpu\n",
		},
		{
			name: "empty selector ignores safe value",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "", "resource_value": "2",
			},
			wantStdin: "remove dedicated-cpu\n",
		},
		{
			name: "nonempty selector",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "ncpus", "resource_value": "2",
			},
			wantStdin: "remove dedicated-cpu ncpus=2\n",
		},
		{
			name: "resource key omitted",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_value": "",
			},
			wantCallError: errZonecfgMissingSelector,
		},
		{
			name: "resource value omitted",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "ncpus",
			},
			wantCallError: errZonecfgMissingSelector,
		},
		{
			name: "selectors omitted",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
			},
			wantCallError: errZonecfgMissingSelector,
		},
		{
			name: "empty selector control value",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "", "resource_value": "2\nend",
			},
			wantCallError: errZonecfgInvalidArgument,
		},
		{
			name: "key control value",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": "ncpus", "resource_value": "2\nend",
			},
			wantCallError: errZonecfgInvalidArgument,
		},
		{
			name: "invalid resource type",
			structured: map[string]any{
				"zone": "web", "resource_type": "unknown",
				"resource_key": "", "resource_value": "",
			},
			wantCallError: errZonecfgInvalidArgument,
		},
		{
			name: "zone omitted",
			structured: map[string]any{
				"resource_type": "dedicated-cpu",
				"resource_key":  "", "resource_value": "",
			},
			wantDecodeError: true,
		},
		{
			name: "resource type omitted",
			structured: map[string]any{
				"zone": "web", "resource_key": "", "resource_value": "",
			},
			wantDecodeError: true,
		},
		{
			name: "malformed resource key",
			structured: map[string]any{
				"zone": "web", "resource_type": "dedicated-cpu",
				"resource_key": []any{"ncpus"}, "resource_value": "2",
			},
			wantDecodeError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zonecfgRecordingRunner{}
			rt := zonecfgRuntime(runner)
			decoded := &RemoveResourceArgs{}
			decodeErr := config.Decode(decoded, tc.structured, nil)
			if tc.wantDecodeError {
				if decodeErr == nil || len(runner.calls) != 0 {
					t.Fatalf("decode err=%v calls=%d, want decode failure without mutation", decodeErr, len(runner.calls))
				}
				return
			}
			if decodeErr != nil {
				t.Fatalf("decode: %v", decodeErr)
			}
			before := *decoded
			reg := zonecfgRemoveResourceRegistry(t)
			got, callErr := reg.Call(context.Background(), rt, "zonecfg.remove_resource", decoded)
			if tc.wantCallError != nil {
				if got != nil || !errors.Is(callErr, tc.wantCallError) || len(runner.calls) != 0 {
					t.Fatalf("got=%#v err=%v calls=%d, want error without Runner", got, callErr, len(runner.calls))
				}
			} else {
				if callErr != nil || !reflect.DeepEqual(got, map[string]any{"status": true}) {
					t.Fatalf("got=%#v err=%v", got, callErr)
				}
				if len(runner.calls) != 1 || !reflect.DeepEqual(zonecfgArgv(runner.calls[0]), []string{"zonecfg", "-z", "web"}) ||
					string(runner.calls[0].Stdin) != tc.wantStdin {
					t.Fatalf("call argv=%#v stdin=%q want argv=%#v stdin=%q", zonecfgArgv(runner.calls[0]), runner.calls[0].Stdin, []string{"zonecfg", "-z", "web"}, tc.wantStdin)
				}
				assertZonecfgBounds(t, runner.calls[0])
				if tc.name == "explicit empty selector" &&
					(decoded.ResourceKey == nil || *decoded.ResourceKey != "" || decoded.ResourceValue == nil || *decoded.ResourceValue != "") {
					t.Fatalf("explicit empty values were not preserved: %#v", decoded)
				}
			}
			if !reflect.DeepEqual(*decoded, before) {
				t.Fatalf("registry call mutated decoded arguments: before=%#v after=%#v", before, *decoded)
			}
		})
	}
}

func TestZonecfgRemoveResourceDirectProviderContract(t *testing.T) {
	tests := []struct {
		name      string
		args      *RemoveResourceArgs
		wantStdin string
		wantError error
	}{
		{
			name: "empty key and empty value",
			args: &RemoveResourceArgs{
				Zone: "web", ResourceType: "dedicated-cpu",
				ResourceKey: stringPtr(""), ResourceValue: stringPtr(""),
			},
			wantStdin: "remove dedicated-cpu\n",
		},
		{
			name: "empty key and safe value",
			args: &RemoveResourceArgs{
				Zone: "web", ResourceType: "dedicated-cpu",
				ResourceKey: stringPtr(""), ResourceValue: stringPtr("2"),
			},
			wantStdin: "remove dedicated-cpu\n",
		},
		{
			name: "empty key and control value",
			args: &RemoveResourceArgs{
				Zone: "web", ResourceType: "dedicated-cpu",
				ResourceKey: stringPtr(""), ResourceValue: stringPtr("2\nend"),
			},
			wantError: errZonecfgInvalidArgument,
		},
		{
			name: "key and valid value",
			args: &RemoveResourceArgs{
				Zone: "web", ResourceType: "dedicated-cpu",
				ResourceKey: stringPtr("ncpus"), ResourceValue: stringPtr("2"),
			},
			wantStdin: "remove dedicated-cpu ncpus=2\n",
		},
		{
			name:      "omitted nil selectors",
			args:      &RemoveResourceArgs{Zone: "web", ResourceType: "dedicated-cpu"},
			wantError: errZonecfgMissingSelector,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zonecfgRecordingRunner{}
			got, err := (removeResourceFunc{}).Execute(context.Background(), zonecfgRuntime(runner), tc.args)
			if tc.wantError != nil {
				if got != nil || !errors.Is(err, tc.wantError) || len(runner.calls) != 0 {
					t.Fatalf("got=%#v err=%v calls=%d, want error without Runner", got, err, len(runner.calls))
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, map[string]any{"status": true}) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(zonecfgArgv(runner.calls[0]), []string{"zonecfg", "-z", "web"}) ||
				string(runner.calls[0].Stdin) != tc.wantStdin {
				t.Fatalf("call argv=%#v stdin=%q want argv=%#v stdin=%q", zonecfgArgv(runner.calls[0]), runner.calls[0].Stdin, []string{"zonecfg", "-z", "web"}, tc.wantStdin)
			}
			assertZonecfgBounds(t, runner.calls[0])
		})
	}
}

func TestZonecfgInfoParsingAndShowAll(t *testing.T) {
	output := strings.Join([]string{
		"zonepath: /zones/web",
		"autoboot: true",
		"property: (name=comment,value=\"web zone\")",
		"rctl:",
		"\tname: zone.max-locked-memory",
		"\tvalue: (priv=privileged,limit=33554432,action=deny)",
		"net:",
		"\taddress: 10.0.0.2",
		"\tphysical: e1000g0",
		"[cpu-shares: 10]",
		"[capped-cpu:",
		"\tncpus: 2",
		"]",
		"fs:",
		"\tdir: /zones/web/root",
	}, "\n")
	runner := &zonecfgRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
	got, err := (infoFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &InfoArgs{Zone: "web"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"zonepath": "/zones/web",
		"autoboot": true,
		"property": map[string]any{"comment": "web zone"},
		"rctl": []any{map[string]any{
			"name":  "zone.max-locked-memory",
			"value": map[string]any{"priv": "privileged", "limit": 33554432, "action": "deny"},
		}},
		"net": []any{map[string]any{"address": "10.0.0.2", "physical": "e1000g0"}},
		"fs":  []any{map[string]any{"dir": "/zones/web/root"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("info=%#v want=%#v", got, want)
	}

	runner = &zonecfgRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte(output)}}}
	got, err = (infoFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &InfoArgs{Zone: "web", ShowAll: true})
	if err != nil {
		t.Fatal(err)
	}
	all, ok := got.(map[string]any)
	if !ok || !reflect.DeepEqual(all["cpu-shares"], 10) ||
		!reflect.DeepEqual(all["capped-cpu"], []any{map[string]any{"ncpus": 2}}) ||
		!reflect.DeepEqual(all["fs"], []any{map[string]any{"dir": "/zones/web/root"}}) {
		t.Fatalf("show_all=%#v", got)
	}
}

func TestZonecfgParserAndBuilderHelpers(t *testing.T) {
	if got, err := sanitizeValue([]string{"one", "two words"}); err != nil || got != `"(one,two words)"` {
		t.Fatalf("list sanitize=%q err=%v", got, err)
	}
	if got, err := sanitizeValue(map[string]any{"z": 2, "a": true}); err != nil || got != "(a=True,z=2)" {
		t.Fatalf("map sanitize=%q err=%v", got, err)
	}
	for _, tc := range []struct {
		input string
		want  any
	}{
		{"true", true},
		{"42", 42},
		{`"text"`, "text"},
		{"[one,two]", []string{"one", "two"}},
		{"(name=demo,limit=2)", map[string]any{"name": "demo", "limit": 2}},
	} {
		got, err := parseZonecfgValue(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parse %q=%#v err=%v want=%#v", tc.input, got, err, tc.want)
		}
	}
	if got := cleanMessage("zonecfg: bad\nOn line 4\nzonecfg: detail\n"); got != "bad\ndetail" {
		t.Fatalf("clean message=%q", got)
	}
	commands, err := resourceCommands("update", "rctl", "name", map[string]any{
		"value": "deny",
		"name":  "zone.max-locked-memory",
	})
	if err != nil || !reflect.DeepEqual(commands, []string{
		"select rctl name=zone.max-locked-memory",
		"set value=deny",
		"end",
	}) {
		t.Fatalf("resource commands=%v err=%v", commands, err)
	}
	if _, err := resourceCommands("add", "rctl", nil, map[string]any{"name\n": "bad"}); !errors.Is(err, errZonecfgInvalidArgument) {
		t.Fatalf("unsafe resource key error=%v", err)
	}
}

func TestZonecfgCollectionValuesUseExactPublicStdin(t *testing.T) {
	tests := []struct {
		name string
		fn   runtime.ExecFunction
		args any
		want string
	}{
		{
			name: "set_property list",
			fn:   setPropertyFunc{},
			args: &SetPropertyArgs{
				Zone: "web", Key: "auths", Value: []string{"one", "two words"},
			},
			want: "set auths=\"(one,two words)\"\n",
		},
		{
			name: "add_resource list",
			fn:   addResourceFunc{},
			args: &AddResourceArgs{
				Zone: "web", ResourceType: "admin",
				Kwargs: map[string]any{"auths": []string{"one", "two words"}},
			},
			want: "add admin\nset auths=\"(one,two words)\"\nend\n",
		},
		{
			name: "update_resource dict",
			fn:   updateResourceFunc{},
			args: &UpdateResourceArgs{
				Zone: "web", ResourceType: "rctl", ResourceSelector: "name",
				Kwargs: map[string]any{
					"name":  "zone.max-locked-memory",
					"value": map[string]any{"z": 2, "a": true},
				},
			},
			want: "select rctl name=zone.max-locked-memory\nset value=(a=True,z=2)\nend\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zonecfgRecordingRunner{}
			got, err := tc.fn.Execute(context.Background(), zonecfgRuntime(runner), tc.args)
			if err != nil || !reflect.DeepEqual(got, map[string]any{"status": true}) {
				t.Fatalf("result=%#v err=%v", got, err)
			}
			if len(runner.calls) != 1 || string(runner.calls[0].Stdin) != tc.want {
				t.Fatalf("stdin=%q want=%q", runner.calls[0].Stdin, tc.want)
			}
		})
	}
}

func TestZonecfgRetcodesErrorsCancellationAndNoMutation(t *testing.T) {
	runner := &zonecfgRecordingRunner{results: []*process.CommandResult{{ExitCode: 2, Stderr: []byte("zonecfg: denied")}}}
	got, err := (deleteFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &DeleteArgs{Zone: "web"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"status": false, "message": "denied"}) {
		t.Fatalf("nonzero result=%#v err=%v", got, err)
	}

	runner = &zonecfgRecordingRunner{results: []*process.CommandResult{{Err: errors.New("runner failed"), ExitCode: -1}}}
	got, err = (deleteFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &DeleteArgs{Zone: "web"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "runner failed") {
		t.Fatalf("runner error result=%#v err=%v", got, err)
	}

	runner = &zonecfgRecordingRunner{results: []*process.CommandResult{{StdoutTruncated: true}}}
	got, err = (deleteFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &DeleteArgs{Zone: "web"})
	if got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit result=%#v err=%v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &zonecfgRecordingRunner{}
	got, err = (deleteFunc{}).Execute(ctx, zonecfgRuntime(runner), &DeleteArgs{Zone: "web"})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("pre-cancel result=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	ctx, cancel = context.WithCancel(context.Background())
	runner = &zonecfgRecordingRunner{cancel: cancel, results: []*process.CommandResult{{ExitCode: 0}}}
	got, err = (deleteFunc{}).Execute(ctx, zonecfgRuntime(runner), &DeleteArgs{Zone: "web"})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("post-cancel result=%#v err=%v", got, err)
	}

	runner = &zonecfgRecordingRunner{}
	got, err = (updateResourceFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &UpdateResourceArgs{
		Zone: "web", ResourceType: "rctl", ResourceSelector: "name", Kwargs: map[string]any{"value": "x"},
	})
	if !reflect.DeepEqual(got, map[string]any{"status": false, "message": "resource selector name not found in parameters"}) || err != nil || len(runner.calls) != 0 {
		t.Fatalf("selector miss result=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	runner = &zonecfgRecordingRunner{}
	rt := &runtime.Runtime{Runner: runner}
	got, err = (createFunc{}).Execute(context.Background(), rt, &CreateArgs{
		Zone: "web", Brand: "solaris", Zonepath: "/zones/web",
	})
	if got != nil || !errors.Is(err, errZonecfgFilesystemMissing) || len(runner.calls) != 0 {
		t.Fatalf("missing filesystem result=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestEnsureZonepathOnlyCreatesAfterNotExist(t *testing.T) {
	injectedIO := errors.New("injected I/O error")
	tests := []struct {
		name          string
		statErr       error
		preCancel     bool
		cancelOnStat  bool
		wantErr       error
		wantStatCalls int
		wantMkdir     int
		wantRunner    int
	}{
		{
			name:          "not exist",
			statErr:       fs.ErrNotExist,
			wantStatCalls: 1,
			wantMkdir:     1,
			wantRunner:    1,
		},
		{
			name:          "permission",
			statErr:       fs.ErrPermission,
			wantErr:       fs.ErrPermission,
			wantStatCalls: 1,
		},
		{
			name:          "I/O",
			statErr:       injectedIO,
			wantErr:       injectedIO,
			wantStatCalls: 1,
		},
		{
			name:      "pre-cancel",
			preCancel: true,
			wantErr:   context.Canceled,
		},
		{
			name:          "cancel during stat",
			statErr:       fs.ErrNotExist,
			cancelOnStat:  true,
			wantErr:       context.Canceled,
			wantStatCalls: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsys := &zonecfgCountingFS{
				MemoryFS: runtime.NewMemoryFS(),
				statErr:  tc.statErr,
			}
			runner := &zonecfgRecordingRunner{}
			rt := &runtime.Runtime{Runner: runner, FS: fsys}
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.preCancel || tc.cancelOnStat {
				ctx, cancel = context.WithCancel(context.Background())
				if tc.preCancel {
					cancel()
				} else {
					fsys.cancelOnStat = cancel
				}
			}
			got, err := (createFunc{}).Execute(ctx, rt, &CreateArgs{
				Zone: "web", Brand: "solaris", Zonepath: "/zones/web",
			})
			if tc.wantErr == nil {
				if err != nil || !reflect.DeepEqual(got, map[string]any{"status": true}) {
					t.Fatalf("result=%#v err=%v", got, err)
				}
			} else if got != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("result=%#v err=%v want=%v", got, err, tc.wantErr)
			}
			if fsys.statCalls != tc.wantStatCalls || fsys.mkdirCalls != tc.wantMkdir ||
				len(runner.calls) != tc.wantRunner {
				t.Fatalf("fs stat=%d mkdir=%d runner=%d want %d/%d/%d", fsys.statCalls, fsys.mkdirCalls, len(runner.calls), tc.wantStatCalls, tc.wantMkdir, tc.wantRunner)
			}
		})
	}
}

func TestZonecfgValidationAndMalformedInfoDoNotRun(t *testing.T) {
	cases := []struct {
		name string
		fn   runtime.ExecFunction
		args any
	}{
		{"zone injection", deleteFunc{}, &DeleteArgs{Zone: "web;touch"}},
		{"path injection", importFunc{}, &ImportArgs{Zone: "web", Path: "/tmp/a;touch"}},
		{"key injection", clearPropertyFunc{}, &ClearPropertyArgs{Zone: "web", Key: "x;touch"}},
		{"resource value injection", removeResourceFunc{}, &RemoveResourceArgs{Zone: "web", ResourceType: "rctl", ResourceKey: stringPtr("name"), ResourceValue: stringPtr("x\nend")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zonecfgRecordingRunner{}
			got, err := tc.fn.Execute(context.Background(), zonecfgRuntime(runner), tc.args)
			if got != nil || !errors.Is(err, errZonecfgInvalidArgument) || len(runner.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
		})
	}
	runner := &zonecfgRecordingRunner{results: []*process.CommandResult{{ExitCode: 0, Stdout: []byte("rctl:\n\tvalue: (broken)\n")}}}
	got, err := (infoFunc{}).Execute(context.Background(), zonecfgRuntime(runner), &InfoArgs{Zone: "web"})
	if got != nil || !errors.Is(err, errZonecfgMalformedInfo) || len(runner.calls) != 1 {
		t.Fatalf("malformed info=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestZonecfgRegistryArgumentsPlatformAndLinuxCLI(t *testing.T) {
	want := map[string]struct {
		prototype any
		arguments []string
	}{
		"zonecfg.create":               {CreateArgs{}, []string{"brand", "force", "zone", "zonepath"}},
		"zonecfg.create_from_template": {CreateFromTemplateArgs{}, []string{"template", "zone"}},
		"zonecfg.delete":               {DeleteArgs{}, []string{"zone"}},
		"zonecfg.export":               {ExportArgs{}, []string{"path", "zone"}},
		"zonecfg.import":               {ImportArgs{}, []string{"path", "zone"}},
		"zonecfg.set_property":         {SetPropertyArgs{}, []string{"key", "value", "zone"}},
		"zonecfg.clear_property":       {ClearPropertyArgs{}, []string{"key", "zone"}},
		"zonecfg.add_resource":         {AddResourceArgs{}, []string{"kwargs", "resource_type", "zone"}},
		"zonecfg.update_resource":      {UpdateResourceArgs{}, []string{"kwargs", "resource_selector", "resource_type", "zone"}},
		"zonecfg.remove_resource":      {RemoveResourceArgs{}, []string{"resource_key", "resource_type", "resource_value", "zone"}},
		"zonecfg.info":                 {InfoArgs{}, []string{"show_all", "zone"}},
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if reg.Len() != len(want) {
		t.Fatalf("registry len=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s args=%T want=%T", name, fn.Args(), row.prototype)
		}
		args, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(args, row.arguments) {
			t.Fatalf("%s arguments=%v err=%v want=%v", name, args, err, row.arguments)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) ||
			runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s platform constraint invalid", name)
		}
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if runtime.CurrentGOOS() == "solaris" {
		return
	}
	runner := &zonecfgRecordingRunner{}
	rt := zonecfgRuntime(runner)
	for name := range want {
		if _, err := reg.Call(context.Background(), rt, name, fnArgsForZonecfg(name)); err == nil {
			t.Fatalf("%s unexpectedly ran on Linux", name)
		} else {
			var unsupported *runtime.UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Kind != "function" || unsupported.Name != name {
				t.Fatalf("%s error=%v, want UnsupportedError", name, err)
			}
		}
	}
	if len(runner.calls) != 0 || len(reg.Names()) != 0 {
		t.Fatalf("Linux registry mutated calls=%#v names=%v", runner.calls, reg.Names())
	}
	app := cli.NewApp("zonecfg-test", func() (*runtime.Runtime, error) {
		rt.Exec = reg
		return rt, nil
	})
	for name := range want {
		if code := app.Run([]string{"exec", name}); code != cli.ExitUnsupported {
			t.Fatalf("CLI %s exit=%d want=%d", name, code, cli.ExitUnsupported)
		}
	}
}

func fnArgsForZonecfg(name string) any {
	switch name {
	case "zonecfg.create":
		return &CreateArgs{}
	case "zonecfg.create_from_template":
		return &CreateFromTemplateArgs{}
	case "zonecfg.delete":
		return &DeleteArgs{}
	case "zonecfg.export":
		return &ExportArgs{}
	case "zonecfg.import":
		return &ImportArgs{}
	case "zonecfg.set_property":
		return &SetPropertyArgs{}
	case "zonecfg.clear_property":
		return &ClearPropertyArgs{}
	case "zonecfg.add_resource":
		return &AddResourceArgs{}
	case "zonecfg.update_resource":
		return &UpdateResourceArgs{}
	case "zonecfg.remove_resource":
		return &RemoveResourceArgs{}
	case "zonecfg.info":
		return &InfoArgs{}
	default:
		panic("unknown zonecfg test function")
	}
}
