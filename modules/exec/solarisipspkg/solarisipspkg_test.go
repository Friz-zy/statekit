package solarisipspkg

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type solarisipspkgFakeRunner struct {
	results       []process.CommandResult
	defaultResult process.CommandResult
	available     bool
	availableLog  []string
	calls         []process.Command
}

func (r *solarisipspkgFakeRunner) CommandAvailable(name string) bool {
	r.availableLog = append(r.availableLog, name)
	return r.available
}

func (r *solarisipspkgFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return r.defaultResult
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func newSolarisipspkgRuntime(results ...process.CommandResult) (*runtime.Runtime, *solarisipspkgFakeRunner) {
	runner := &solarisipspkgFakeRunner{results: results, defaultResult: process.CommandResult{ExitCode: 0}, available: true}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func ipsArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertIPSCommand(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit ||
		len(command.Stdin) != 0 {
		t.Fatalf("unsafe IPS command: %#v", command)
	}
}

func stringPtr(value string) *string { return &value }
func boolPtr(value bool) *bool       { return &value }

const ipsFixture = "pkg://solaris/editor/vim@2.0 i--\n" +
	"pkg://solaris/library/foo@1.0 i--\n" +
	"pkg://solaris/editor/vim@1.0 i--\n"

func TestSolarisipspkgRegistrySurfaceAndArguments(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"pkg.refresh_db":        {RefreshDBArgs{}, []string{"full", "kwargs"}},
		"pkg.upgrade_available": {UpgradeAvailableArgs{}, []string{"kwargs", "name"}},
		"pkg.list_upgrades":     {ListUpgradesArgs{}, []string{"kwargs", "refresh"}},
		"pkg.upgrade":           {UpgradeArgs{}, []string{"kwargs", "refresh"}},
		"pkg.list_pkgs":         {ListPkgsArgs{}, []string{"kwargs", "versions_as_list"}},
		"pkg.version":           {VersionArgs{}, []string{"kwargs", "names"}},
		"pkg.latest_version":    {LatestVersionArgs{}, []string{"kwargs", "names"}},
		"pkg.get_fmri":          {NameArgs{}, []string{"kwargs", "name"}},
		"pkg.normalize_name":    {NameArgs{}, []string{"kwargs", "name"}},
		"pkg.is_installed":      {IsInstalledArgs{}, []string{"kwargs", "name"}},
		"pkg.search":            {SearchArgs{}, []string{"kwargs", "name", "versions_as_list"}},
		"pkg.install":           {InstallArgs{}, []string{"kwargs", "name", "pkgs", "refresh", "test", "version"}},
		"pkg.remove":            {RemoveArgs{}, []string{"kwargs", "name", "pkgs"}},
		"pkg.purge":             {PurgeArgs{}, []string{"kwargs", "name"}},
	}
	if reg.Len() != len(want) {
		t.Fatalf("registry length=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s prototype=%T want=%T", name, fn.Args(), row.prototype)
		}
		got, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(got, row.args) {
			t.Fatalf("%s args=%v err=%v want=%v", name, got, err, row.args)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) {
			t.Fatalf("%s platform=%v constrained=%t", name, constrained, ok)
		}
		if runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "solaris") {
			t.Fatalf("%s platform support incorrect", name)
		}
	}
	if _, ok := reg.Get("pkg.available_version"); ok {
		t.Fatal("deprecated available_version alias leaked into registry")
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestSolarisipspkgUnsupportedOnLinux(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux gating assertion does not apply on Solaris")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &solarisipspkgFakeRunner{available: true}
	_, err := reg.Call(context.Background(), &runtime.Runtime{Runner: runner}, "pkg.install", &InstallArgs{Name: stringPtr("vim")})
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Name != "pkg.install" || unsupported.Kind != "function" {
		t.Fatalf("error=%v, want UnsupportedError", err)
	}
	if len(runner.calls) != 0 || len(runner.availableLog) != 0 {
		t.Fatalf("unsupported call reached provider: calls=%d availability=%v", len(runner.calls), runner.availableLog)
	}
}

func TestSolarisipspkgListingAndReadOnlyFunctions(t *testing.T) {
	rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim":  "1.0,2.0",
		"pkg://solaris/library/foo": "1.0",
	}) {
		t.Fatalf("list=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hv"}) {
		t.Fatalf("list argv=%v", ipsArgv(runner.calls[0]))
	}
	assertIPSCommand(t, runner.calls[0])

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err = (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{VersionsAsList: true})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim":  []string{"1.0", "2.0"},
		"pkg://solaris/library/foo": []string{"1.0"},
	}) {
		t.Fatalf("list versions=%#v err=%v", got, err)
	}

	rt, runner = newSolarisipspkgRuntime()
	got, err = (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{Kwargs: map[string]any{"removed": true}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
		t.Fatalf("removed=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: []string{"vim"}})
	if err != nil || got != "1.0" {
		// The source delegates to pkg_resource.version, whose one-name
		// contract returns the first matched listing value even for a partial
		// name.
		t.Fatalf("partial version=%#v err=%v", got, err)
	}
	if !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hv", "vim"}) {
		t.Fatalf("version argv=%v", ipsArgv(runner.calls[0]))
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: []string{"pkg://solaris/editor/vim"}})
	if err != nil || got != "1.0" {
		t.Fatalf("full version=%#v err=%v", got, err)
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/editor/vim@2.0 u--\n")}, process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/editor/vim@1.0 i--\n")})
	got, err = (latestVersionFunc{}).Execute(context.Background(), rt, &LatestVersionArgs{Names: []string{"pkg://solaris/editor/vim"}})
	if err != nil || got != "2.0" {
		t.Fatalf("latest=%#v err=%v", got, err)
	}
	if len(runner.calls) != 2 || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hnv", "pkg://solaris/editor/vim"}) ||
		!reflect.DeepEqual(ipsArgv(runner.calls[1]), []string{ipsBinary, "list", "-Hv", "pkg://solaris/editor/vim"}) {
		t.Fatalf("latest argv=%v", runner.calls)
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/editor/vim@2.0 u--\n")})
	got, err = (getFMriFunc{}).Execute(context.Background(), rt, &NameArgs{Name: "vim"})
	if err != nil || !reflect.DeepEqual(got, []string{"pkg://solaris/editor/vim"}) {
		t.Fatalf("get fmri=%#v err=%v", got, err)
	}
	got, err = (getFMriFunc{}).Execute(context.Background(), rt, &NameArgs{Name: "pkg://solaris/editor/vim"})
	if err != nil || got != "pkg://solaris/editor/vim" || len(runner.calls) != 1 {
		t.Fatalf("full fmri=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/editor/vim@2.0 u--\n")})
	got, err = (normalizeNameFunc{}).Execute(context.Background(), rt, &NameArgs{Name: "vim"})
	if err != nil || got != "pkg://solaris/editor/vim" {
		t.Fatalf("normalize=%#v err=%v", got, err)
	}
	got, err = (normalizeNameFunc{}).Execute(context.Background(), rt, &NameArgs{Name: "pkg://solaris/editor/vim"})
	if err != nil || got != "pkg://solaris/editor/vim" || len(runner.calls) != 1 {
		t.Fatalf("full normalize=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 1})
	got, err = (isInstalledFunc{}).Execute(context.Background(), rt, &IsInstalledArgs{Name: "vim"})
	if err != nil || got != false {
		t.Fatalf("is installed=%#v err=%v", got, err)
	}
	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err = (searchFunc{}).Execute(context.Background(), rt, &SearchArgs{Name: "vim"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim":  "2.0,1.0",
		"pkg://solaris/library/foo": "1.0",
	}) {
		t.Fatalf("search=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("search calls=%d", len(runner.calls))
	}

	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
	got, err = (upgradeAvailableFunc{}).Execute(context.Background(), rt, &UpgradeAvailableArgs{Name: "vim"})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim":  "1.0",
		"pkg://solaris/library/foo": "1.0",
	}) || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsPathBinary, "list", "-Huv", "vim"}) {
		t.Fatalf("upgrade available=%#v err=%v calls=%v", got, err, runner.calls)
	}
}

func TestSolarisipspkgIsTrueStateFlagVectors(t *testing.T) {
	values := []struct {
		name     string
		value    any
		suppress bool
	}{
		{name: "bool true", value: true, suppress: true},
		{name: "string True", value: "True", suppress: true},
		{name: "string true", value: "true", suppress: true},
		{name: "numeric one", value: 1, suppress: true},
		{name: "numeric float one", value: 1.0, suppress: true},
		{name: "numeric fraction", value: 0.5},
		{name: "bool false", value: false},
		{name: "string False", value: "False"},
		{name: "string fraction", value: "0.5", suppress: true},
		{name: "string false", value: "false"},
		{name: "string zero", value: "0"},
		{name: "numeric zero", value: 0},
		{name: "numeric float zero", value: 0.0},
		{name: "nil", value: nil},
	}
	for _, flag := range []string{"removed", "purge_desired"} {
		for _, tc := range values {
			t.Run(flag+"/"+tc.name, func(t *testing.T) {
				reg := runtime.NewExecRegistry()
				if err := Register(reg); err != nil {
					t.Fatal(err)
				}
				fn, ok := reg.Get("pkg.list_pkgs")
				if !ok {
					t.Fatal("pkg.list_pkgs is not registered")
				}
				rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
				got, err := fn.Execute(context.Background(), rt, &ListPkgsArgs{
					Kwargs: map[string]any{flag: tc.value},
				})
				if err != nil {
					t.Fatal(err)
				}
				if tc.suppress {
					if reflect.TypeOf(got) != reflect.TypeOf(map[string]any{}) ||
						!reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 || len(runner.availableLog) != 0 {
						t.Fatalf("got=%#v (%T) calls=%d availability=%v, want empty map and no Runner call", got, got, len(runner.calls), runner.availableLog)
					}
					return
				}
				if !reflect.DeepEqual(got, map[string]any{
					"pkg://solaris/editor/vim":  "1.0,2.0",
					"pkg://solaris/library/foo": "1.0",
				}) || len(runner.calls) != 1 || !reflect.DeepEqual(runner.availableLog, []string{"pkg"}) {
					t.Fatalf("got=%#v (%T) calls=%d availability=%v, want listed map and one Runner call", got, got, len(runner.calls), runner.availableLog)
				}
				if !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hv"}) {
					t.Fatalf("argv=%v", ipsArgv(runner.calls[0]))
				}
			})
		}
	}
}

func TestSolarisipspkgVersionsAsListPreservesPythonTruthiness(t *testing.T) {
	values := []struct {
		name  string
		value any
		list  bool
	}{
		{name: "bool true", value: true, list: true},
		{name: "string False", value: "False", list: true},
		{name: "string zero", value: "0", list: true},
		{name: "numeric one", value: 1, list: true},
		{name: "numeric float one", value: 1.0, list: true},
		{name: "numeric fraction", value: 0.5, list: true},
		{name: "bool false", value: false},
		{name: "numeric zero", value: 0},
		{name: "numeric float zero", value: 0.0},
		{name: "string zero", value: "0", list: true},
		{name: "string fraction", value: "0.5", list: true},
		{name: "nil", value: nil},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
			got, err := listPackages(context.Background(), rt, tc.value, nil)
			if err != nil {
				t.Fatal(err)
			}
			var want any = map[string]any{
				"pkg://solaris/editor/vim":  "1.0,2.0",
				"pkg://solaris/library/foo": "1.0",
			}
			if tc.list {
				want = map[string]any{
					"pkg://solaris/editor/vim":  []string{"1.0", "2.0"},
					"pkg://solaris/library/foo": []string{"1.0"},
				}
			}
			if reflect.TypeOf(got) != reflect.TypeOf(want) || !reflect.DeepEqual(got, want) ||
				len(runner.calls) != 1 || !reflect.DeepEqual(runner.availableLog, []string{"pkg"}) {
				t.Fatalf("got=%#v (%T) want=%#v (%T) calls=%d availability=%v", got, got, want, want, len(runner.calls), runner.availableLog)
			}
			if !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hv"}) {
				t.Fatalf("argv=%v", ipsArgv(runner.calls[0]))
			}
		})
	}
}

func TestSolarisipspkgStructuredJSONVersionsAsListThroughRegistry(t *testing.T) {
	values := []struct {
		name        string
		jsonValue   string
		list        bool
		decodedType reflect.Type
	}{
		{name: "bool true", jsonValue: "true", list: true, decodedType: reflect.TypeOf(true)},
		{name: "bool false", jsonValue: "false", decodedType: reflect.TypeOf(false)},
		{name: "string False", jsonValue: `"False"`, list: true, decodedType: reflect.TypeOf("")},
		{name: "string zero", jsonValue: `"0"`, list: true, decodedType: reflect.TypeOf("")},
		{name: "numeric zero", jsonValue: "0", decodedType: reflect.TypeOf(float64(0))},
		{name: "numeric one", jsonValue: "1", list: true, decodedType: reflect.TypeOf(float64(0))},
		{name: "numeric float one", jsonValue: "1.0", list: true, decodedType: reflect.TypeOf(float64(0))},
	}
	functions := []struct {
		name       string
		jsonPrefix string
		argv       []string
		scalar     any
		list       any
		scalarJSON string
		listJSON   string
	}{
		{
			name:       "pkg.list_pkgs",
			jsonPrefix: `{"versions_as_list":`,
			argv:       []string{ipsBinary, "list", "-Hv"},
			scalar: map[string]any{
				"pkg://solaris/editor/vim":  "1.0,2.0",
				"pkg://solaris/library/foo": "1.0",
			},
			list: map[string]any{
				"pkg://solaris/editor/vim":  []string{"1.0", "2.0"},
				"pkg://solaris/library/foo": []string{"1.0"},
			},
			scalarJSON: `{"pkg://solaris/editor/vim":"1.0,2.0","pkg://solaris/library/foo":"1.0"}`,
			listJSON:   `{"pkg://solaris/editor/vim":["1.0","2.0"],"pkg://solaris/library/foo":["1.0"]}`,
		},
		{
			name:       "pkg.search",
			jsonPrefix: `{"name":"vim","versions_as_list":`,
			argv:       []string{ipsBinary, "list", "-aHv", "vim"},
			scalar: map[string]any{
				"pkg://solaris/editor/vim":  "2.0,1.0",
				"pkg://solaris/library/foo": "1.0",
			},
			list: map[string]any{
				"pkg://solaris/editor/vim":  []string{"2.0", "1.0"},
				"pkg://solaris/library/foo": []string{"1.0"},
			},
			scalarJSON: `{"pkg://solaris/editor/vim":"2.0,1.0","pkg://solaris/library/foo":"1.0"}`,
			listJSON:   `{"pkg://solaris/editor/vim":["2.0","1.0"],"pkg://solaris/library/foo":["1.0"]}`,
		},
	}

	for _, function := range functions {
		for _, tc := range values {
			t.Run(function.name+"/"+tc.name, func(t *testing.T) {
				reg := runtime.NewExecRegistry()
				if err := Register(reg); err != nil {
					t.Fatal(err)
				}
				fn, ok := reg.Get(function.name)
				if !ok {
					t.Fatalf("%s is not registered", function.name)
				}
				structured, err := config.ParseStructured([]byte(function.jsonPrefix + tc.jsonValue + `}`))
				if err != nil {
					t.Fatal(err)
				}
				args := reflect.New(reflect.TypeOf(fn.Args())).Interface()
				if err := config.Decode(args, structured, nil); err != nil {
					t.Fatal(err)
				}
				decoded := reflect.ValueOf(args).Elem().FieldByName("VersionsAsList").Interface()
				if gotType := reflect.TypeOf(decoded); gotType != tc.decodedType {
					t.Fatalf("decoded type=%v want=%v", gotType, tc.decodedType)
				}

				rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
				got, err := fn.Execute(context.Background(), rt, args)
				if err != nil {
					t.Fatal(err)
				}
				want, wantJSON := function.scalar, function.scalarJSON
				if tc.list {
					want, wantJSON = function.list, function.listJSON
				}
				payload, err := json.Marshal(got)
				if err != nil || string(payload) != wantJSON || reflect.TypeOf(got) != reflect.TypeOf(want) || !reflect.DeepEqual(got, want) {
					t.Fatalf("got=%#v (%T) JSON=%q err=%v want=%#v (%T) JSON=%q", got, got, payload, err, want, want, wantJSON)
				}
				if len(runner.calls) != 1 || !reflect.DeepEqual(runner.availableLog, []string{"pkg"}) ||
					!reflect.DeepEqual(ipsArgv(runner.calls[0]), function.argv) {
					t.Fatalf("calls=%d availability=%v argv=%v want=%v", len(runner.calls), runner.availableLog, ipsArgv(runner.calls[0]), function.argv)
				}
			})
		}
	}
}

func TestSolarisipspkgDecodedJSONIsTrueStateFlagVectors(t *testing.T) {
	values := []struct {
		name        string
		jsonValue   string
		suppress    bool
		decodedType reflect.Type
	}{
		{name: "numeric fraction", jsonValue: "0.5", decodedType: reflect.TypeOf(float64(0))},
		{name: "numeric float one", jsonValue: "1.0", suppress: true, decodedType: reflect.TypeOf(float64(0))},
		{name: "string fraction", jsonValue: `"0.5"`, suppress: true, decodedType: reflect.TypeOf("")},
		{name: "string zero", jsonValue: `"0"`, decodedType: reflect.TypeOf("")},
		{name: "string False", jsonValue: `"False"`, decodedType: reflect.TypeOf("")},
	}
	for _, flag := range []string{"removed", "purge_desired"} {
		for _, tc := range values {
			t.Run(flag+"/"+tc.name, func(t *testing.T) {
				reg := runtime.NewExecRegistry()
				if err := Register(reg); err != nil {
					t.Fatal(err)
				}
				fn, ok := reg.Get("pkg.list_pkgs")
				if !ok {
					t.Fatal("pkg.list_pkgs is not registered")
				}
				structured, err := config.ParseStructured([]byte(`{"kwargs":{"` + flag + `":` + tc.jsonValue + `}}`))
				if err != nil {
					t.Fatal(err)
				}
				args := &ListPkgsArgs{}
				if err := config.Decode(args, structured, nil); err != nil {
					t.Fatal(err)
				}
				if gotType := reflect.TypeOf(args.Kwargs[flag]); gotType != tc.decodedType {
					t.Fatalf("decoded %s type=%v want=%v", flag, gotType, tc.decodedType)
				}

				rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)})
				got, err := fn.Execute(context.Background(), rt, args)
				if err != nil {
					t.Fatal(err)
				}
				var want any = map[string]any{
					"pkg://solaris/editor/vim":  "1.0,2.0",
					"pkg://solaris/library/foo": "1.0",
				}
				wantJSON := `{"pkg://solaris/editor/vim":"1.0,2.0","pkg://solaris/library/foo":"1.0"}`
				wantCalls := 1
				if tc.suppress {
					want = map[string]any{}
					wantJSON = `{}`
					wantCalls = 0
				}
				payload, err := json.Marshal(got)
				if err != nil || string(payload) != wantJSON || reflect.TypeOf(got) != reflect.TypeOf(want) || !reflect.DeepEqual(got, want) {
					t.Fatalf("got=%#v (%T) JSON=%q err=%v want=%#v (%T) JSON=%q", got, got, payload, err, want, want, wantJSON)
				}
				if len(runner.calls) != wantCalls || len(runner.availableLog) != wantCalls {
					t.Fatalf("Runner calls=%d availability=%v want calls=%d", len(runner.calls), runner.availableLog, wantCalls)
				}
				if wantCalls == 1 && runner.availableLog[0] != "pkg" {
					t.Fatalf("availability=%v want [pkg]", runner.availableLog)
				}
				if wantCalls == 1 && !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Hv"}) {
					t.Fatalf("argv=%v", ipsArgv(runner.calls[0]))
				}
			})
		}
	}
}

func TestSolarisipspkgVersionNoNamesRegistryProvider(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("pkg.version")
	if !ok {
		t.Fatal("pkg.version is not registered")
	}
	rt, runner := newSolarisipspkgRuntime()
	got, err := fn.Execute(context.Background(), rt, &VersionArgs{})
	if err != nil || got != "" || reflect.TypeOf(got) != reflect.TypeOf("") ||
		len(runner.calls) != 0 || len(runner.availableLog) != 0 {
		t.Fatalf("registry pkg.version()=%#v (%T) err=%v calls=%d availability=%v", got, got, err, len(runner.calls), runner.availableLog)
	}
}

func TestSolarisipspkgRefreshUpgradeAndMutations(t *testing.T) {
	got, err := func() (any, error) {
		rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0})
		value, callErr := (refreshDBFunc{}).Execute(context.Background(), rt, &RefreshDBArgs{Full: true})
		if len(runner.calls) != 1 || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "refresh", "--full"}) {
			t.Fatalf("refresh argv=%v", runner.calls)
		}
		assertIPSCommand(t, runner.calls[0])
		return value, callErr
	}()
	if err != nil || got != true {
		t.Fatalf("refresh=%#v err=%v", got, err)
	}

	refreshFalse := false
	rt, runner := newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
	)
	got, err = (listUpgradesFunc{}).Execute(context.Background(), rt, &ListUpgradesArgs{Refresh: &refreshFalse})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim":  "1.0",
		"pkg://solaris/library/foo": "1.0",
	}) {
		t.Fatalf("list upgrades=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "list", "-Huv"}) {
		t.Fatalf("list upgrades argv=%v", runner.calls)
	}

	rt, runner = newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
	)
	got, err = (listUpgradesFunc{}).Execute(context.Background(), rt, &ListUpgradesArgs{})
	if err != nil || len(runner.calls) != 2 || !reflect.DeepEqual(ipsArgv(runner.calls[0]), []string{ipsBinary, "refresh", "--full"}) {
		t.Fatalf("default refresh got=%#v err=%v calls=%v", got, err, runner.calls)
	}

	noRefresh := false
	rt, runner = newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
	)
	got, err = (upgradeFunc{}).Execute(context.Background(), rt, &UpgradeArgs{Refresh: &noRefresh})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 3 {
		t.Fatalf("upgrade=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	if !reflect.DeepEqual(ipsArgv(runner.calls[1]), []string{ipsPathBinary, "update", "-v", "--accept"}) {
		t.Fatalf("upgrade argv=%v", ipsArgv(runner.calls[1]))
	}

	rt, runner = newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 1},
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
		process.CommandResult{ExitCode: 7, Stderr: []byte("busy")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
	)
	got, err = (installFunc{}).Execute(context.Background(), rt, &InstallArgs{Name: stringPtr("vim"), Test: true})
	if err == nil || !strings.Contains(err.Error(), "busy") || len(runner.calls) != 4 {
		t.Fatalf("install failure=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	if !reflect.DeepEqual(ipsArgv(runner.calls[2]), []string{ipsPathBinary, "install", "-v", "--accept", "-n", "vim"}) {
		t.Fatalf("install argv=%v", ipsArgv(runner.calls[2]))
	}

	rt, runner = newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/library/foo@1.0 i--\n")},
	)
	got, err = (removeFunc{}).Execute(context.Background(), rt, &RemoveArgs{Name: stringPtr("vim")})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"pkg://solaris/editor/vim": map[string]any{"old": "1.0,2.0", "new": ""},
	}) {
		t.Fatalf("remove=%#v err=%v", got, err)
	}
	if !reflect.DeepEqual(ipsArgv(runner.calls[1]), []string{ipsBinary, "uninstall", "-v", "vim"}) {
		t.Fatalf("remove argv=%v", ipsArgv(runner.calls[1]))
	}

	rt, runner = newSolarisipspkgRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte(ipsFixture)},
		process.CommandResult{ExitCode: 0},
		process.CommandResult{ExitCode: 0, Stdout: []byte("pkg://solaris/library/foo@1.0 i--\n")},
	)
	got, err = (purgeFunc{}).Execute(context.Background(), rt, &PurgeArgs{Name: stringPtr("vim")})
	if err != nil || len(runner.calls) != 3 {
		t.Fatalf("purge=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
}

func TestSolarisipspkgFailuresCancellationAvailabilityAndBounds(t *testing.T) {
	if commandTimeout != 30*time.Second || outputLimit != 4<<20 {
		t.Fatalf("bounds changed: timeout=%s output=%d", commandTimeout, outputLimit)
	}
	for _, line := range []string{"", "pkg://solaris/x no-version", "pkg://solaris/x@"} {
		if _, err := parseIPSRecord(line); err == nil {
			t.Fatalf("malformed record accepted: %q", line)
		}
	}
	if err := commandError("upgrading", process.CommandResult{ExitCode: 5}, map[string]any{}); err == nil || !strings.Contains(err.Error(), "a  live image") {
		t.Fatalf("retcode 5 message=%v", err)
	}
	rt, runner := newSolarisipspkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("x"), StdoutTruncated: true})
	if _, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{}); !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("output limit err=%v calls=%d", err, len(runner.calls))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newSolarisipspkgRuntime()
	if _, err := (listPkgsFunc{}).Execute(ctx, rt, &ListPkgsArgs{}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 || len(runner.availableLog) != 0 {
		t.Fatalf("cancel err=%v calls=%d availability=%v", err, len(runner.calls), runner.availableLog)
	}
	rt, runner = newSolarisipspkgRuntime()
	runner.available = false
	if _, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{}); !errors.Is(err, errIPSUnavailable) || len(runner.calls) != 0 {
		t.Fatalf("unavailable err=%v calls=%d", err, len(runner.calls))
	}
	runnerErr := errors.New("runner failed")
	rt, runner = newSolarisipspkgRuntime(process.CommandResult{ExitCode: -1, Err: runnerErr})
	if _, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{}); !errors.Is(err, runnerErr) || len(runner.calls) != 1 {
		t.Fatalf("runner err=%v calls=%d", err, len(runner.calls))
	}
	tooMany := make([]any, maxTargets+1)
	for index := range tooMany {
		tooMany[index] = "pkg://solaris/x"
	}
	rt, runner = newSolarisipspkgRuntime()
	if _, err := (removeFunc{}).Execute(context.Background(), rt, &RemoveArgs{Pkgs: tooMany}); err == nil || len(runner.calls) != 0 {
		t.Fatalf("target bound err=%v calls=%d", err, len(runner.calls))
	}
}
