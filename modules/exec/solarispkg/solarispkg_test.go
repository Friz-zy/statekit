package solarispkg

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type solarispkgFakeRunner struct {
	results     []process.CommandResult
	defaultData process.CommandResult
	calls       []process.Command
	fs          *runtime.MemoryFS
	adminData   string
}

func (r *solarispkgFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	if r.fs != nil && (command.Name == "/usr/sbin/pkgadd" || command.Name == "/usr/sbin/pkgrm") && len(command.Args) >= 3 {
		if data, err := r.fs.ReadFile(command.Args[2]); err == nil {
			r.adminData = string(data)
		}
	}
	if len(r.results) == 0 {
		return r.defaultData
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func newSolarispkgRuntime(results ...process.CommandResult) (*runtime.Runtime, *solarispkgFakeRunner) {
	fsys := runtime.NewMemoryFS()
	runner := &solarispkgFakeRunner{results: results, defaultData: process.CommandResult{ExitCode: 0}, fs: fsys}
	return &runtime.Runtime{Runner: runner, FS: fsys}, runner
}

func solarispkgArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func stringPtr(value string) *string { return &value }

const pkginfoFixture = "SUNWbzip                          The bzip utility\n" +
	"                                  (i386) 11.10.0,REV=2005\n" +
	"SUNWgzip                          The gzip utility\n" +
	"                                  (i386) 12.0\n"

func assertSolarispkgCommand(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit ||
		len(command.Stdin) != 0 {
		t.Fatalf("unsafe command: %#v", command)
	}
}

func TestSolarispkgRegistrySurfaceAndArguments(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"pkg.list_pkgs":         {ListPkgsArgs{}, []string{"kwargs", "versions_as_list"}},
		"pkg.latest_version":    {LatestVersionArgs{}, []string{"kwargs", "names"}},
		"pkg.upgrade_available": {UpgradeAvailableArgs{}, []string{"kwargs", "name"}},
		"pkg.version":           {VersionArgs{}, []string{"kwargs", "names"}},
		"pkg.install":           {InstallArgs{}, []string{"kwargs", "name", "saltenv", "sources"}},
		"pkg.remove":            {RemoveArgs{}, []string{"kwargs", "name", "pkgs", "saltenv"}},
		"pkg.purge":             {PurgeArgs{}, []string{"kwargs", "name", "pkgs"}},
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
		t.Fatal("deprecated alias must not be a second registry name")
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestSolarispkgUnsupportedOnLinux(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux gating assertion does not apply on Solaris")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	runner := &solarispkgFakeRunner{}
	_, err := reg.Call(context.Background(), &runtime.Runtime{Runner: runner}, "pkg.list_pkgs", &ListPkgsArgs{})
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || unsupported.Name != "pkg.list_pkgs" || unsupported.Kind != "function" {
		t.Fatalf("error=%v, want UnsupportedError", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unsupported call reached Runner: %#v", runner.calls)
	}
}

func TestSolarispkgListVersionAndStateBranches(t *testing.T) {
	rt, runner := newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
	got, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"SUNWbzip": "11.10.0,REV=2005", "SUNWgzip": "12.0",
	}) {
		t.Fatalf("list=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(solarispkgArgv(runner.calls[0]), []string{"/usr/bin/pkginfo", "-x"}) {
		t.Fatalf("argv=%v", solarispkgArgv(runner.calls[0]))
	}
	assertSolarispkgCommand(t, runner.calls[0])

	rt, runner = newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
	got, err = (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{VersionsAsList: true})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"SUNWbzip": []string{"11.10.0,REV=2005"}, "SUNWgzip": []string{"12.0"},
	}) {
		t.Fatalf("list versions=%#v err=%v", got, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("version-list calls=%d", len(runner.calls))
	}

	rt, runner = newSolarispkgRuntime()
	got, err = (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{Kwargs: map[string]any{"removed": true}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
		t.Fatalf("removed branch got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	rt, runner = newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
	got, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: []string{"SUNWbzip"}})
	if err != nil || got != "11.10.0,REV=2005" {
		t.Fatalf("version=%#v err=%v", got, err)
	}
	emptyVersion, emptyErr := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{})
	if emptyErr != nil || !reflect.DeepEqual(emptyVersion, map[string]any{}) {
		t.Fatalf("empty version=%#v err=%v", emptyVersion, emptyErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("empty version unexpectedly ran Runner: %d", len(runner.calls))
	}

	for _, names := range [][]string{{"SUNWbzip", "missing"}, {"SUNW*"}} {
		rt, _ = newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
		got, err = (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{Names: names})
		if err != nil {
			t.Fatalf("names=%v err=%v", names, err)
		}
		if len(names) == 2 {
			if !reflect.DeepEqual(got, map[string]any{"SUNWbzip": "11.10.0,REV=2005", "missing": ""}) {
				t.Fatalf("multi version=%#v", got)
			}
		} else if !reflect.DeepEqual(got, map[string]any{"SUNWbzip": "11.10.0,REV=2005", "SUNWgzip": "12.0"}) {
			t.Fatalf("glob version=%#v", got)
		}
	}

	for _, names := range [][]string{{}, {"SUNWbzip"}, {"SUNWbzip", "SUNWgzip"}} {
		got, err = (latestVersionFunc{}).Execute(context.Background(), rt, &LatestVersionArgs{Names: names})
		if err != nil {
			t.Fatal(err)
		}
		if len(names) == 0 && got != "" {
			t.Fatalf("latest empty=%#v", got)
		}
		if len(names) == 1 && got != "" {
			t.Fatalf("latest single=%#v", got)
		}
	}
	got, err = (upgradeAvailableFunc{}).Execute(context.Background(), rt, &UpgradeAvailableArgs{Name: "SUNWbzip"})
	if err != nil || got != false {
		t.Fatalf("upgrade available=%#v err=%v", got, err)
	}
}

func TestSolarispkgIsTrueStateFlagVectors(t *testing.T) {
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
				result := process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)}
				rt, runner := newSolarispkgRuntime(result)
				got, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{
					Kwargs: map[string]any{flag: tc.value},
				})
				if err != nil {
					t.Fatal(err)
				}
				if tc.suppress {
					if reflect.TypeOf(got) != reflect.TypeOf(map[string]any{}) ||
						!reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
						t.Fatalf("got=%#v (%T) calls=%d, want empty map and no Runner call", got, got, len(runner.calls))
					}
					return
				}
				if !reflect.DeepEqual(got, map[string]any{
					"SUNWbzip": "11.10.0,REV=2005", "SUNWgzip": "12.0",
				}) || len(runner.calls) != 1 {
					t.Fatalf("got=%#v (%T) calls=%d, want listed map and one Runner call", got, got, len(runner.calls))
				}
				if !reflect.DeepEqual(solarispkgArgv(runner.calls[0]), []string{"/usr/bin/pkginfo", "-x"}) {
					t.Fatalf("argv=%v", solarispkgArgv(runner.calls[0]))
				}
			})
		}
	}
}

func TestSolarispkgVersionsAsListIsTrueVectors(t *testing.T) {
	values := []struct {
		name  string
		value any
		list  bool
	}{
		{name: "bool true", value: true, list: true},
		{name: "string True", value: "True", list: true},
		{name: "string true", value: "true", list: true},
		{name: "numeric one", value: 1, list: true},
		{name: "numeric float one", value: 1.0, list: true},
		{name: "bool false", value: false},
		{name: "string False", value: "False"},
		{name: "string zero", value: "0"},
		{name: "numeric zero", value: 0},
		{name: "numeric float zero", value: 0.0},
		{name: "nil", value: nil},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
			got, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{
				Names:  []string{"SUNWbzip"},
				Kwargs: map[string]any{"versions_as_list": tc.value},
			})
			if err != nil {
				t.Fatal(err)
			}
			var want any = "11.10.0,REV=2005"
			if tc.list {
				want = []string{"11.10.0,REV=2005"}
			}
			if reflect.TypeOf(got) != reflect.TypeOf(want) || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v (%T), want=%#v (%T)", got, got, want, want)
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(solarispkgArgv(runner.calls[0]), []string{"/usr/bin/pkginfo", "-x"}) {
				t.Fatalf("calls=%d argv=%v", len(runner.calls), solarispkgArgv(runner.calls[0]))
			}
		})
	}
}

func TestSolarispkgDecodedJSONIsTrueStateFlagVectors(t *testing.T) {
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

				rt, runner := newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
				got, err := fn.Execute(context.Background(), rt, args)
				if err != nil {
					t.Fatal(err)
				}
				var want any = map[string]any{
					"SUNWbzip": "11.10.0,REV=2005", "SUNWgzip": "12.0",
				}
				wantJSON := `{"SUNWbzip":"11.10.0,REV=2005","SUNWgzip":"12.0"}`
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
				if len(runner.calls) != wantCalls {
					t.Fatalf("Runner calls=%d want=%d", len(runner.calls), wantCalls)
				}
				if wantCalls == 1 && !reflect.DeepEqual(solarispkgArgv(runner.calls[0]), []string{"/usr/bin/pkginfo", "-x"}) {
					t.Fatalf("argv=%v", solarispkgArgv(runner.calls[0]))
				}
			})
		}
	}
}

func TestSolarispkgCurrentZoneOnlyArgvVectors(t *testing.T) {
	values := []struct {
		name  string
		value any
		zone  bool
	}{
		{name: "bool true", value: true, zone: true},
		{name: "string True", value: "True", zone: true},
		{name: "numeric one", value: 1, zone: true},
		{name: "bool false", value: false},
		{name: "string False", value: "False"},
		{name: "string zero", value: "0"},
		{name: "numeric zero", value: 0},
		{name: "nil", value: nil},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			old := process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)}
			newOut := process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture + "SUNWbashS                         Bash\n" + "                                  (i386) 1.0\n")}
			rt, runner := newSolarispkgRuntime(old, process.CommandResult{ExitCode: 0}, newOut)
			got, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
				Sources: []any{map[string]any{"SUNWbashS": "/var/spool/pkg/bashs"}},
				Kwargs:  map[string]any{"current_zone_only": tc.value},
			})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"SUNWbashS": map[string]any{"old": "", "new": "1.0"}}) {
				t.Fatalf("install=%#v err=%v", got, err)
			}
			if len(runner.calls) != 3 {
				t.Fatalf("calls=%d", len(runner.calls))
			}
			argv := solarispkgArgv(runner.calls[1])
			want := []string{"/usr/sbin/pkgadd", "-n", "-a", argv[3]}
			if tc.zone {
				want = append(want, "-G ")
			}
			want = append(want, "-d", "/var/spool/pkg/bashs", "all")
			if !reflect.DeepEqual(argv, want) {
				t.Fatalf("argv=%v want=%v", argv, want)
			}
		})
	}
}

func TestSolarispkgVersionNoNamesRegistryProvider(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("pkg.version")
	if !ok {
		t.Fatal("pkg.version is not registered")
	}
	rt, runner := newSolarispkgRuntime()
	got, err := fn.Execute(context.Background(), rt, &VersionArgs{})
	if err != nil || reflect.TypeOf(got) != reflect.TypeOf(map[string]any{}) ||
		!reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 0 {
		t.Fatalf("registry pkg.version()=%#v (%T) err=%v calls=%d", got, got, err, len(runner.calls))
	}
}

func TestSolarispkgVersionMissingListValuesSerializeAsEmptyArrays(t *testing.T) {
	for _, tc := range []struct {
		name      string
		names     []string
		wantJSON  string
		multiName bool
	}{
		{name: "single", names: []string{"missing"}, wantJSON: `[]`},
		{name: "multi", names: []string{"missing", "absent"}, wantJSON: `{"absent":[],"missing":[]}`, multiName: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
			got, err := (versionFunc{}).Execute(context.Background(), rt, &VersionArgs{
				Names:  tc.names,
				Kwargs: map[string]any{"versions_as_list": true},
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(got)
			if err != nil || string(payload) != tc.wantJSON {
				t.Fatalf("got=%#v (%T) JSON=%q err=%v want JSON=%q", got, got, payload, err, tc.wantJSON)
			}
			if tc.multiName {
				values, ok := got.(map[string]any)
				if !ok {
					t.Fatalf("multi result type=%T", got)
				}
				for _, name := range tc.names {
					versions, ok := values[name].([]string)
					if !ok || versions == nil || len(versions) != 0 {
						t.Fatalf("%s value=%#v (%T), want nonnil empty []string", name, values[name], values[name])
					}
				}
			} else {
				versions, ok := got.([]string)
				if !ok || versions == nil || len(versions) != 0 {
					t.Fatalf("single value=%#v (%T), want nonnil empty []string", got, got)
				}
			}
			if len(runner.calls) != 1 || !reflect.DeepEqual(solarispkgArgv(runner.calls[0]), []string{"/usr/bin/pkginfo", "-x"}) {
				t.Fatalf("Runner calls=%d argv=%v", len(runner.calls), solarispkgArgv(runner.calls[0]))
			}
		})
	}
}

func TestSolarispkgInstallRemoveAndAdminFile(t *testing.T) {
	old := process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)}
	newOut := process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture + "SUNWbashS                         Bash\n" + "                                  (i386) 1.0\n")}
	rt, runner := newSolarispkgRuntime(old, process.CommandResult{ExitCode: 0}, newOut)
	got, err := (installFunc{}).Execute(context.Background(), rt, &InstallArgs{
		Name:    stringPtr("SUNWbashS"),
		Sources: []any{map[string]any{"SUNWbashS": "/var/spool/pkg/bashs"}},
		// The pinned Python branch uses membership in (True, "True").
		Kwargs: map[string]any{"current_zone_only": "False", "instance": "overwrite"},
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"SUNWbashS": map[string]any{"old": "", "new": "1.0"}}) {
		t.Fatalf("install=%#v err=%v", got, err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("install calls=%d", len(runner.calls))
	}
	argv := solarispkgArgv(runner.calls[1])
	if len(argv) != 7 || !reflect.DeepEqual(argv, []string{
		"/usr/sbin/pkgadd", "-n", "-a", argv[3], "-d", "/var/spool/pkg/bashs", "all",
	}) {
		t.Fatalf("pkgadd argv=%v", argv)
	}
	assertSolarispkgCommand(t, runner.calls[1])
	if !strings.Contains(runner.adminData, "instance=overwrite\n") || !strings.Contains(runner.adminData, "basedir=default\n") {
		t.Fatalf("admin data=%q", runner.adminData)
	}
	if _, statErr := rt.FS.Stat(argv[3]); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("temporary admin file remains: %v", statErr)
	}

	rt, runner = newSolarispkgRuntime(old, process.CommandResult{ExitCode: 0}, process.CommandResult{ExitCode: 0, Stdout: []byte("SUNWgzip                          The gzip utility\n                                  (i386) 12.0\n")})
	got, err = (removeFunc{}).Execute(context.Background(), rt, &RemoveArgs{
		Name: stringPtr("SUNWbzip"), Kwargs: map[string]any{"admin_source": "/tmp/admin"},
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"SUNWbzip": map[string]any{"old": "11.10.0,REV=2005", "new": ""}}) {
		t.Fatalf("remove=%#v err=%v", got, err)
	}
	if len(runner.calls) != 3 || !reflect.DeepEqual(solarispkgArgv(runner.calls[1]), []string{"/usr/sbin/pkgrm", "-n", "-a", "/tmp/admin", "SUNWbzip"}) {
		t.Fatalf("pkgrm argv=%v", solarispkgArgv(runner.calls[1]))
	}
	assertSolarispkgCommand(t, runner.calls[1])

	rt, runner = newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte(pkginfoFixture)})
	got, err = (removeFunc{}).Execute(context.Background(), rt, &RemoveArgs{Name: stringPtr("not-installed")})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.calls) != 1 {
		t.Fatalf("remove no-op=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	got, err = (purgeFunc{}).Execute(context.Background(), rt, &PurgeArgs{Name: stringPtr("not-installed")})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("purge no-op=%#v err=%v", got, err)
	}
}

func TestSolarispkgFailuresCancellationAndBounds(t *testing.T) {
	if commandTimeout != 30*time.Second || outputLimit != 4<<20 || fileLimit != 1<<20 {
		t.Fatalf("bounds changed: timeout=%s output=%d file=%d", commandTimeout, outputLimit, fileLimit)
	}
	if _, err := parsePkginfo([]byte("SUNWbad only-one-row\n")); err == nil {
		t.Fatal("odd pkginfo rows accepted")
	}
	if _, err := parsePkginfo([]byte("\nversion 1\n")); err == nil {
		t.Fatal("malformed pkginfo name accepted")
	}
	rt, runner := newSolarispkgRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("x"), StdoutTruncated: true})
	if _, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{}); !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("output limit err=%v calls=%d", err, len(runner.calls))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newSolarispkgRuntime()
	if _, err := (listPkgsFunc{}).Execute(ctx, rt, &ListPkgsArgs{}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancel err=%v calls=%d", err, len(runner.calls))
	}
	runnerErr := errors.New("runner failed")
	rt, runner = newSolarispkgRuntime(process.CommandResult{ExitCode: -1, Err: runnerErr})
	if _, err := (listPkgsFunc{}).Execute(context.Background(), rt, &ListPkgsArgs{}); !errors.Is(err, runnerErr) || len(runner.calls) != 1 {
		t.Fatalf("runner error=%v calls=%d", err, len(runner.calls))
	}
	tooMany := make([]any, maxTargets+1)
	for i := range tooMany {
		tooMany[i] = "SUNWx"
	}
	rt, runner = newSolarispkgRuntime()
	if _, err := (removeFunc{}).Execute(context.Background(), rt, &RemoveArgs{Pkgs: tooMany}); err == nil || len(runner.calls) != 0 {
		t.Fatalf("target bound err=%v calls=%d", err, len(runner.calls))
	}
}
