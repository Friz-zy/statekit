package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type zypperLowpkgExecRunner struct {
	commands []process.Command
	results  []process.CommandResult
}

func (r *zypperLowpkgExecRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestZypperLowpkgRegistryPrototypeAndCallMatrix(t *testing.T) {
	name := "demo"
	root := "/target"
	rows := []struct {
		name       string
		prototype  any
		args       any
		results    []process.CommandResult
		wantArgv   [][]string
		wantResult any
		capability []string
	}{
		{
			name:       "pkg.file_list",
			prototype:  ZypperFilesArgs{},
			args:       &ZypperFilesArgs{Packages: []string{name}, Root: &root},
			results:    []process.CommandResult{{Stdout: []byte("/usr/bin/demo\n")}},
			wantArgv:   [][]string{{"rpm", "--root", root, "-ql", name}},
			wantResult: map[string]any{"errors": []string{}, "files": []string{"/usr/bin/demo"}},
			capability: []string{"aptpkg", "yumpkg", "zypperpkg"},
		},
		{
			name:      "pkg.file_dict",
			prototype: ZypperFilesArgs{},
			args:      &ZypperFilesArgs{Packages: []string{name}, Root: &root},
			results: []process.CommandResult{
				{Stdout: []byte("demo 1\n")},
				{Stdout: []byte("/usr/bin/demo\n")},
			},
			wantArgv:   [][]string{{"rpm", "--root", root, "-q", "--queryformat", "%{NAME} %{VERSION}\\n", name}, {"rpm", "-ql", name}},
			wantResult: map[string]any{"errors": []string{}, "packages": map[string]any{name: []string{"/usr/bin/demo"}}},
			capability: []string{"aptpkg", "yumpkg", "zypperpkg"},
		},
		{
			name:      "pkg.info_installed",
			prototype: ZypperInfoInstalledArgs{},
			args: &ZypperInfoInstalledArgs{
				Names: []string{name}, Root: &root, Attr: zypperInfoRegistryStringPtr("version"), AllVersions: zypperInfoRegistryBoolPtr(false), Errors: zypperInfoRegistryStringPtr("ignore"),
			},
			results: []process.CommandResult{
				{Stdout: []byte("SIZE\n")},
				{Stdout: []byte("name: demo\nversion: 1\nedition: 1-1\n-----\n")},
			},
			wantArgv:   [][]string{{"rpm", "--querytags"}}, // the metadata format is asserted below
			wantResult: map[string]any{"demo": map[string]any{"version": "1"}},
			capability: []string{"aptpkg", "yumpkg", "zypperpkg"},
		},
		{
			name:       "pkg.owner",
			prototype:  ZypperOwnerArgs{},
			args:       &ZypperOwnerArgs{Paths: []string{"/usr/bin/demo"}, Root: &root},
			results:    []process.CommandResult{{Stdout: []byte("demo")}},
			wantArgv:   [][]string{{"rpm", "--root", root, "-qf", "--queryformat", "%{name}", "/usr/bin/demo"}},
			wantResult: "demo",
			capability: []string{"aptpkg", "yumpkg", "zypperpkg"},
		},
		{
			name:       "pkg.modified",
			prototype:  ZypperModifiedArgs{},
			args:       &ZypperModifiedArgs{Packages: []string{name}, Root: &root},
			results:    []process.CommandResult{{ExitCode: 0}},
			wantArgv:   [][]string{{"rpm", "--root", root, "--noscripts", "-Va", name}},
			wantResult: map[string]any{},
			capability: []string{"yumpkg", "zypperpkg"},
		},
		{
			name:       "pkg.verify",
			prototype:  ZypperVerifyArgs{},
			args:       &ZypperVerifyArgs{Names: []string{name}, Root: &root, VerifyOptions: "nodigest", IgnoreTypes: []string{"doc"}},
			results:    []process.CommandResult{{ExitCode: 0}},
			wantArgv:   [][]string{{"rpm", "--root", root, "--nodigest", "--noscripts", "-V", name}},
			wantResult: map[string]any{},
			capability: []string{"yumpkg", "zypperpkg"},
		},
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			runner := &zypperLowpkgExecRunner{results: append([]process.CommandResult(nil), row.results...)}
			rt := zypperRegistryRuntime("zypper", runner)
			prototype, err := reg.ResolveArgs(rt, row.name)
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(row.prototype) {
				t.Fatalf("prototype=%T err=%v want=%T", prototype, err, row.prototype)
			}
			argumentNames, err := config.ArgumentNames(prototype)
			if err != nil {
				t.Fatal(err)
			}
			wantNames := map[string][]string{
				"pkg.file_list":      {"packages", "root"},
				"pkg.file_dict":      {"packages", "root"},
				"pkg.info_installed": {"all_versions", "attr", "errors", "names", "root"},
				"pkg.owner":          {"paths", "root"},
				"pkg.modified":       {"capabilities", "checksum", "device", "group", "mode", "owner", "packages", "root", "size", "symlink", "time"},
				"pkg.verify":         {"ignore_types", "names", "root", "verify_options"},
			}[row.name]
			if !reflect.DeepEqual(argumentNames, wantNames) {
				t.Fatalf("argument names=%v want=%v", argumentNames, wantNames)
			}
			if got := reg.ProviderCapabilities(row.name); !reflect.DeepEqual(got, row.capability) {
				t.Fatalf("capabilities=%v want=%v", got, row.capability)
			}
			before := reflect.ValueOf(row.args).Elem().Interface()
			got, err := reg.Call(context.Background(), rt, row.name, row.args)
			if err != nil || !reflect.DeepEqual(got, row.wantResult) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, row.wantResult)
			}
			if !reflect.DeepEqual(reflect.ValueOf(row.args).Elem().Interface(), before) {
				t.Fatal("registry call mutated arguments")
			}
			gotArgv := make([][]string, len(runner.commands))
			for i, command := range runner.commands {
				if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
					t.Fatalf("unsafe command=%#v", command)
				}
				gotArgv[i] = append([]string{command.Name}, command.Args...)
			}
			if row.name != "pkg.info_installed" && !reflect.DeepEqual(gotArgv, row.wantArgv) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, row.wantArgv)
			}
			if row.name == "pkg.info_installed" && (len(gotArgv) != 2 || !reflect.DeepEqual(gotArgv[0], row.wantArgv[0]) || len(gotArgv[1]) != 7 || gotArgv[1][0] != "rpm" || gotArgv[1][1] != "--root" || gotArgv[1][2] != root || gotArgv[1][3] != "-q" || gotArgv[1][4] != name || gotArgv[1][5] != "--queryformat") {
				t.Fatalf("info argv=%#v", gotArgv)
			}
			wrongRunner := &zypperLowpkgExecRunner{}
			rt.Runner = wrongRunner
			var wrong any
			switch row.name {
			case "pkg.file_list", "pkg.file_dict":
				wrong = &FilePackagesArgs{}
			case "pkg.info_installed":
				wrong = &InfoArgs{}
			case "pkg.owner":
				wrong = &OwnerArgs{}
			case "pkg.modified":
				wrong = &ModifiedArgs{}
			case "pkg.verify":
				wrong = &VerifyArgs{}
			}
			if got, err := reg.Call(context.Background(), rt, row.name, wrong); got != nil || err == nil || len(wrongRunner.commands) != 0 {
				t.Fatalf("wrong pointer got=%#v err=%v calls=%d", got, err, len(wrongRunner.commands))
			}
		})
	}

	for _, name := range []string{"pkg.file_list", "pkg.file_dict", "pkg.info_installed", "pkg.modified", "pkg.owner", "pkg.verify"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registrations=%d", name, count)
		}
	}
}

func TestZypperLowpkgRegistryVerificationArgvMatrix(t *testing.T) {
	root := "/target"
	cases := []struct {
		name     string
		function string
		args     any
		wantArgv []string
	}{
		{
			name:     "verify default",
			function: "pkg.verify",
			args:     &ZypperVerifyArgs{},
			wantArgv: []string{"rpm", "--noscripts", "-Va"},
		},
		{
			name:     "verify named",
			function: "pkg.verify",
			args:     &ZypperVerifyArgs{Names: []string{"demo"}},
			wantArgv: []string{"rpm", "--noscripts", "-V", "demo"},
		},
		{
			name:     "verify root",
			function: "pkg.verify",
			args:     &ZypperVerifyArgs{Root: &root},
			wantArgv: []string{"rpm", "--root", root, "--noscripts", "-Va"},
		},
		{
			name:     "verify options",
			function: "pkg.verify",
			args:     &ZypperVerifyArgs{Names: []string{"demo"}, VerifyOptions: "nodigest,noscripts"},
			wantArgv: []string{"rpm", "--nodigest", "--noscripts", "-V", "demo"},
		},
		{
			name:     "modified default",
			function: "pkg.modified",
			args:     &ZypperModifiedArgs{},
			wantArgv: []string{"rpm", "--noscripts", "-Va"},
		},
		{
			name:     "modified named",
			function: "pkg.modified",
			args:     &ZypperModifiedArgs{Packages: []string{"demo"}},
			wantArgv: []string{"rpm", "--noscripts", "-Va", "demo"},
		},
		{
			name:     "modified root",
			function: "pkg.modified",
			args:     &ZypperModifiedArgs{Packages: []string{"demo"}, Root: &root},
			wantArgv: []string{"rpm", "--root", root, "--noscripts", "-Va", "demo"},
		},
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &zypperLowpkgExecRunner{results: []process.CommandResult{{ExitCode: 0}}}
			rt := zypperRegistryRuntime("zypper", runner)
			got, err := reg.Call(context.Background(), rt, tc.function, tc.args)
			if err != nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.commands) != 1 {
				t.Fatalf("calls=%d commands=%#v", len(runner.commands), runner.commands)
			}
			command := runner.commands[0]
			if command.Shell || command.MaxStdoutBytes != 1<<20 || command.MaxStderrBytes != 1<<20 {
				t.Fatalf("unsafe command=%#v", command)
			}
			if gotArgv := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(gotArgv, tc.wantArgv) {
				t.Fatalf("argv=%#v want=%#v", gotArgv, tc.wantArgv)
			}
		})
	}
}

func zypperInfoRegistryStringPtr(value string) *string { return &value }

func zypperInfoRegistryBoolPtr(value bool) *bool { return &value }

func TestZypperLowpkgRegistryRejectsUnsupportedProviderBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt", "unsupported"} {
		runner := &zypperLowpkgExecRunner{}
		rt := zypperRegistryRuntime(manager, runner)
		for _, row := range []struct {
			name string
			args any
		}{
			{"pkg.modified", &ModifiedArgs{}},
			{"pkg.verify", &VerifyArgs{}},
		} {
			if _, err := reg.ResolveArgs(rt, row.name); err == nil || !errors.As(err, new(*runtime.UnsupportedError)) {
				t.Fatalf("%s/%s resolved err=%v", manager, row.name, err)
			}
			if got, err := reg.Call(context.Background(), rt, row.name, row.args); got != nil || err == nil || len(runner.commands) != 0 {
				t.Fatalf("%s/%s got=%#v err=%v calls=%d", manager, row.name, got, err, len(runner.commands))
			}
		}
	}
}
