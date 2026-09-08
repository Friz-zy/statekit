package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func zypperLowpkgProvider() *commandProvider {
	return &commandProvider{spec: rpmSpec("zypper")}
}

func zypperLowpkgRuntime(results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
	runner := &yumRecordingRunner{results: results}
	return &runtime.Runtime{Runner: runner}, runner
}

func zypperStringPtr(value string) *string { return &value }

func zypperBoolPtr(value bool) *bool { return &value }

func zypperCommandArgs(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

type zypperCancelRunner struct {
	calls  []process.Command
	cancel context.CancelFunc
}

func (r *zypperCancelRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.calls) == 1 {
		r.cancel()
	}
	return process.CommandResult{Stdout: []byte("demo 1\n")}
}

func TestZypperFileListAndDictMatchRPMLowpkgContract(t *testing.T) {
	root := "/image root"
	rt, runner := zypperLowpkgRuntime(process.CommandResult{
		ExitCode: 7,
		Stdout:   []byte("alpha 1\nbeta 2\nalpha 3\nmissing is not installed\n"),
	}, process.CommandResult{Stdout: []byte("/usr/bin/alpha\n/usr/share/alpha\n")}, process.CommandResult{Stdout: []byte("/usr/bin/beta\n")})
	args := map[string]any{"packages": []string{"alpha", "beta"}, "root": &root}
	before := map[string]any{"packages": append([]string(nil), args["packages"].([]string)...), "root": &root}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", args)
	want := map[string]any{
		"errors":   []string{"missing is not installed"},
		"packages": map[string]any{"alpha": []string{"/usr/bin/alpha", "/usr/share/alpha"}, "beta": []string{"/usr/bin/beta"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("file_dict got=%#v err=%v args=%#v", got, err, args)
	}
	if len(runner.commands) != 3 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--root", root, "-q", "--queryformat", "%{NAME} %{VERSION}\\n", "alpha", "beta"}) || !reflect.DeepEqual(zypperCommandArgs(runner.commands[1]), []string{"rpm", "-ql", "alpha"}) || !reflect.DeepEqual(zypperCommandArgs(runner.commands[2]), []string{"rpm", "-ql", "beta"}) {
		t.Fatalf("file_dict commands=%#v", runner.commands)
	}
	for _, command := range runner.commands {
		if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
			t.Fatalf("unbounded or shell command=%#v", command)
		}
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("/z\n/z\n/x\n")})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "file_list", map[string]any{"root": &root})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{"/z", "/z", "/x"}}) {
		t.Fatalf("file_list got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--root", root, "-qla"}) {
		t.Fatalf("file_list command=%#v", runner.commands)
	}
}

func TestZypperFileDictMalformedAndEmptyOutput(t *testing.T) {
	for _, output := range []string{"bad\n", "good\n\nnext 1\n", " \n"} {
		rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(output)})
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("output=%q got=%#v err=%v calls=%d", output, got, err, len(runner.commands))
		}
	}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "packages": map[string]any{}}) || len(runner.commands) != 1 {
		t.Fatalf("empty output got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperFileDictRejectsUntrustedResponsePackageNamesBeforeSecondCall(t *testing.T) {
	outputs := []string{
		"--querytags 1\nregular 2\n",
		"bad\x00name 1\n",
		string([]byte{'b', 'a', 'd', 0xff, ' ', '1', '\n'}),
		strings.Repeat("a", maxZypperTokenRunes+1) + " 1\n",
	}
	for index, output := range outputs {
		rt, runner := zypperLowpkgRuntime(
			process.CommandResult{Stdout: []byte(output)},
			process.CommandResult{Stdout: []byte("must-not-run\n")},
		)
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("case=%d got=%#v err=%v calls=%d", index, got, err, len(runner.commands))
		}
	}
}

func TestZypperFileDictCompletedNonzeroOutputKeepsSourceDataShape(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(
		process.CommandResult{ExitCode: 9, Stdout: []byte("alpha 1\nmissing is not installed\nbeta 2\n")},
		process.CommandResult{ExitCode: 4, Stdout: []byte("/usr/bin/alpha\n")},
		process.CommandResult{ExitCode: 5, Stdout: []byte("/usr/bin/beta\n")},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
	want := map[string]any{
		"errors":   []string{"missing is not installed"},
		"packages": map[string]any{"alpha": []string{"/usr/bin/alpha"}, "beta": []string{"/usr/bin/beta"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(runner.commands) != 3 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	rt, runner = zypperLowpkgRuntime(process.CommandResult{ExitCode: 7, Stdout: []byte("/missing\n")})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "file_list", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{"/missing"}}) || len(runner.commands) != 1 {
		t.Fatalf("file_list got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperInfoInstalledMetadataAndVersions(t *testing.T) {
	attr := "name,version,release,arch,size,source_rpm,build_date,install_date,signature,description"
	metadata := "name: demo\nversion: 2.0\nrelease: 4\narch: x86_64\nsource_rpm: (none)\nbuild_date: 0\ninstall_date: 1700000000\nsignature: RSA/SHA256\ndescription:\nfirst line\nsecond line\n-----\n"
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("SIZE\nLONGSIZE\n")}, process.CommandResult{Stdout: []byte(metadata), ExitCode: 3})
	args := map[string]any{"names": []string{"demo"}, "root": zypperStringPtr("/root"), "attr": &attr, "errors": zypperStringPtr("ignore")}
	before := map[string]any{"names": append([]string(nil), args["names"].([]string)...), "root": zypperStringPtr("/root"), "attr": zypperStringPtr(attr), "errors": zypperStringPtr("ignore")}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", args)
	want := map[string]any{"demo": map[string]any{
		"version":      "2.0",
		"release":      "4",
		"arch":         "x86_64",
		"source":       "(none)",
		"build_date":   "1970-01-01T00:00:00Z",
		"install_date": "2023-11-14T22:13:20Z",
		"signature":    "RSA/SHA256",
		"description":  "first line\nsecond line",
	}}
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("info got=%#v err=%v args=%#v", got, err, args)
	}
	if len(runner.commands) != 2 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--querytags"}) {
		t.Fatalf("info querytags commands=%#v", runner.commands)
	}
	query := runner.commands[1]
	if query.Shell || !reflect.DeepEqual(query.Env, []string{"TZ=UTC"}) || query.MaxStdoutBytes != zypperLowpkgOutputLimit || query.MaxStderrBytes != zypperLowpkgOutputLimit || len(query.Args) != 6 || query.Args[0] != "--root" || query.Args[1] != "/root" || query.Args[2] != "-q" || query.Args[3] != "demo" || query.Args[4] != "--queryformat" || query.Args[5] == "" || !strings.Contains(query.Args[5], "%{LONGSIZE}") {
		t.Fatalf("info query command=%#v", query)
	}

	versions := "name: demo\nedition: 1:1.0-1\nversion: 1.0\nrelease: 1\n-----\nname: demo\nedition: 2:1.0-1\nversion: 1.0\nrelease: 1\n-----\nname: gpg-pubkey\nedition: 9\n-----\n"
	rt, _ = zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("SIZE\n")}, process.CommandResult{Stdout: []byte(versions)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", map[string]any{"all_versions": zypperBoolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	all, ok := got.(map[string]any)["demo"].([]any)
	if !ok || len(all) != 2 || all[0].(map[string]any)["edition"] != "2:1.0-1" || all[1].(map[string]any)["edition"] != "1:1.0-1" {
		t.Fatalf("all_versions=%#v", got)
	}
}

func TestZypperInfoErrorsAndMissingMetadata(t *testing.T) {
	for _, mode := range []string{"ignore", "report"} {
		t.Run(mode, func(t *testing.T) {
			output := "name: demo\nbuild_date: invalid\ninstall_date_time_t: invalid\n-----\n"
			rt, _ := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("SIZE\n")}, process.CommandResult{Stdout: []byte(output)})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", map[string]any{"errors": mode})
			if err != nil {
				t.Fatal(err)
			}
			fields := got.(map[string]any)["demo"].(map[string]any)
			if _, exists := fields["build_date"]; exists {
				t.Fatalf("broken date was retained for errors=%s: %#v", mode, fields)
			}
			if _, exists := fields["install_date_time_t"]; exists {
				t.Fatalf("broken timestamp was retained for errors=%s: %#v", mode, fields)
			}
			if _, exists := fields["name"]; exists {
				t.Fatalf("lowpkg name leaked into metadata for errors=%s: %#v", mode, fields)
			}
		})
	}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("SIZE\n")}, process.CommandResult{Stdout: []byte("not metadata\n")})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", map[string]any{"attr": "not-an-attribute"})
	if got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("invalid attr got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperInfoInstalledUsesLooseVersionOrderingAndSourceMetadataShape(t *testing.T) {
	metadata := "" +
		"name: demo\nedition: 2\nsummary: tie-first\n-----\n" +
		"name: demo\nedition: 2\nsummary: tie-second\n-----\n" +
		"name: demo\nedition: 1.0\nsummary: rpm-later\n-----\n" +
		"name: demo\nedition: 1.0~rc1\nsummary: loose-later\n-----\n"
	rt, _ := zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte("SIZE\n")},
		process.CommandResult{Stdout: []byte(metadata)},
	)
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", map[string]any{"all_versions": true})
	if err != nil {
		t.Fatal(err)
	}
	versions := got.(map[string]any)["demo"].([]any)
	if len(versions) != 4 {
		t.Fatalf("versions=%#v", got)
	}
	wantSummaries := []string{"tie-second", "tie-first", "loose-later", "rpm-later"}
	for index, want := range wantSummaries {
		fields := versions[index].(map[string]any)
		if fields["summary"] != want {
			t.Fatalf("version[%d]=%#v want summary %q", index, fields, want)
		}
		if _, exists := fields["name"]; exists {
			t.Fatalf("version[%d] leaked name: %#v", index, fields)
		}
	}

	rt, _ = zypperLowpkgRuntime(
		process.CommandResult{Stdout: []byte("SIZE\n")},
		process.CommandResult{Stdout: []byte("name: demo\nedition: 1\nsource_rpm: source.rpm\nbuild_date: broken\nbuild_date_time_t: broken\nversion: 1\n-----\n")},
	)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "info_installed", map[string]any{"attr": "version,source_rpm,build_date,build_date_time_t", "errors": "report"})
	if err != nil {
		t.Fatal(err)
	}
	fields := got.(map[string]any)["demo"].(map[string]any)
	if !reflect.DeepEqual(fields, map[string]any{"version": "1", "source": "source.rpm"}) {
		t.Fatalf("attr/report fields=%#v", fields)
	}
}

func TestZypperModifiedAndVerifyUseSourceFlagsAndFilters(t *testing.T) {
	modifiedOutput := "SM5DLUGTP c /etc/demo\n......... /etc/clean\n"
	modifiedArgs := map[string]any{
		"packages":     []string{"demo"},
		"root":         zypperStringPtr("/target"),
		"size":         zypperBoolPtr(true),
		"mode":         zypperBoolPtr(true),
		"checksum":     zypperBoolPtr(true),
		"device":       zypperBoolPtr(true),
		"symlink":      zypperBoolPtr(true),
		"owner":        zypperBoolPtr(true),
		"group":        zypperBoolPtr(true),
		"time":         zypperBoolPtr(true),
		"capabilities": zypperBoolPtr(true),
	}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 1, Stdout: []byte(modifiedOutput)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "modified", modifiedArgs)
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/demo": []string{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities", "config"}}) {
		t.Fatalf("modified got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--root", "/target", "--noscripts", "-Va", "demo"}) {
		t.Fatalf("modified command=%#v", runner.commands)
	}

	verifyOutput := "SM5DLUGTP  c /etc/demo\n.........  d /usr/share/doc/demo\n"
	rt, runner = zypperLowpkgRuntime(process.CommandResult{ExitCode: 1, Stdout: []byte(verifyOutput)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "verify", map[string]any{
		"names":          []string{"demo"},
		"root":           zypperStringPtr("/target"),
		"verify_options": "nodigest,nosignature",
		"ignore_types":   []string{"doc"},
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/demo": map[string]any{"type": "config", "mismatch": []string{"size", "mode", "md5sum", "device major/minor number", "readlink path", "user", "group", "mtime", "capabilities"}}}) {
		t.Fatalf("verify got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--root", "/target", "--nodigest", "--nosignature", "--noscripts", "-V", "demo"}) {
		t.Fatalf("verify command=%#v", runner.commands)
	}
}

func TestZypperVerificationAlwaysUsesNoScripts(t *testing.T) {
	root := "/target"
	cases := []struct {
		name     string
		function string
		args     map[string]any
		wantArgv []string
	}{
		{
			name:     "verify default",
			function: "verify",
			args:     map[string]any{},
			wantArgv: []string{"rpm", "--noscripts", "-Va"},
		},
		{
			name:     "verify named",
			function: "verify",
			args:     map[string]any{"names": []string{"demo"}},
			wantArgv: []string{"rpm", "--noscripts", "-V", "demo"},
		},
		{
			name:     "verify root",
			function: "verify",
			args:     map[string]any{"root": &root},
			wantArgv: []string{"rpm", "--root", root, "--noscripts", "-Va"},
		},
		{
			name:     "verify options",
			function: "verify",
			args: map[string]any{
				"names": []string{"demo"}, "verify_options": "nodigest,noscripts,nosignature",
			},
			wantArgv: []string{"rpm", "--nodigest", "--noscripts", "--nosignature", "-V", "demo"},
		},
		{
			name:     "verify duplicate option",
			function: "verify",
			args:     map[string]any{"verify_options": []string{"noscripts", "noscripts"}},
			wantArgv: []string{"rpm", "--noscripts", "-Va"},
		},
		{
			name:     "modified default",
			function: "modified",
			args:     map[string]any{},
			wantArgv: []string{"rpm", "--noscripts", "-Va"},
		},
		{
			name:     "modified named",
			function: "modified",
			args:     map[string]any{"packages": []string{"demo"}},
			wantArgv: []string{"rpm", "--noscripts", "-Va", "demo"},
		},
		{
			name:     "modified root",
			function: "modified",
			args:     map[string]any{"packages": []string{"demo"}, "root": &root},
			wantArgv: []string{"rpm", "--root", root, "--noscripts", "-Va", "demo"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 0})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, tc.function, tc.args)
			if err != nil || got == nil && tc.function == "verify" {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if len(runner.commands) != 1 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), tc.wantArgv) {
				t.Fatalf("argv=%#v want=%#v", runner.commands, tc.wantArgv)
			}
		})
	}
}

func TestZypperVerifyRejectsNonVerificationOptionsBeforeRunner(t *testing.T) {
	for _, option := range []string{
		"pipe=touch /tmp/unsafe",
		"eval=system('unsafe')",
		"--querytags",
		"define=macro value",
		"nodigest=%{NAME}",
		"unknown-verification-option",
	} {
		runner := &yumNoCallRunner{}
		rt := &runtime.Runtime{Runner: runner}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "verify", map[string]any{"verify_options": option})
		var unsupported *runtime.UnsupportedError
		if got != nil || err == nil || !errors.As(err, &unsupported) || runner.calls != 0 {
			t.Fatalf("option=%q got=%#v err=%v calls=%d", option, got, err, runner.calls)
		}
	}
}

func TestZypperOwnerShapeAndMissingFiles(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{ExitCode: 7, Stdout: []byte("demo")}, process.CommandResult{ExitCode: 1, Stdout: []byte("file is not owned by any package")})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "owner", map[string]any{"paths": []string{"/one", "/two"}, "root": zypperStringPtr("/target")})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/one": "demo", "/two": ""}) {
		t.Fatalf("owner got=%#v err=%v", got, err)
	}
	if len(runner.commands) != 2 || !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), []string{"rpm", "--root", "/target", "-qf", "--queryformat", "%{name}", "/one"}) || !reflect.DeepEqual(zypperCommandArgs(runner.commands[1]), []string{"rpm", "--root", "/target", "-qf", "--queryformat", "%{name}", "/two"}) {
		t.Fatalf("owner commands=%#v", runner.commands)
	}
	rt, _ = zypperLowpkgRuntime()
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "owner", map[string]any{})
	if err != nil || got != "" {
		t.Fatalf("owner empty got=%#v err=%v", got, err)
	}
}

func TestZypperLowpkgAggregateBudgetsStopBeforeFurtherQueries(t *testing.T) {
	var discovery strings.Builder
	for index := 0; index <= zypperLowpkgMaxResultItems; index++ {
		_, _ = fmt.Fprintf(&discovery, "pkg%d 1\n", index)
	}
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(discovery.String())})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
	if got != nil || !errors.Is(err, errZypperLowpkgResultBudget) || len(runner.commands) != 1 {
		t.Fatalf("discovery got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	packageNames := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	packageDiscovery := strings.Join(packageNames, " 1\n") + " 1\n"
	large := []byte(strings.Repeat("x", zypperLowpkgOutputLimit))
	results := []process.CommandResult{{Stdout: []byte(packageDiscovery)}}
	for range packageNames {
		results = append(results, process.CommandResult{Stdout: large})
	}
	rt, runner = zypperLowpkgRuntime(results...)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "file_dict", map[string]any{})
	if got != nil || !errors.Is(err, errZypperLowpkgResultBudget) || len(runner.commands) >= len(packageNames)+1 {
		t.Fatalf("file_dict bytes got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	paths := make([]string, len(packageNames))
	for index := range paths {
		paths[index] = fmt.Sprintf("/path/%d", index)
	}
	results = nil
	for range paths {
		results = append(results, process.CommandResult{Stdout: large})
	}
	rt, runner = zypperLowpkgRuntime(results...)
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "owner", map[string]any{"paths": paths})
	if got != nil || !errors.Is(err, errZypperLowpkgResultBudget) || len(runner.commands) >= len(paths) {
		t.Fatalf("owner bytes got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperLowpkgErrorsBoundsAndNoCallValidation(t *testing.T) {
	runnerErr := errors.New("runner")
	cases := []struct {
		name   string
		result process.CommandResult
		want   error
	}{
		{"runner", process.CommandResult{Err: runnerErr}, runnerErr},
		{"stdout-limit", process.CommandResult{StdoutTruncated: true}, process.ErrOutputLimit},
		{"stderr-limit", process.CommandResult{StderrTruncated: true}, process.ErrOutputLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := zypperLowpkgRuntime(tc.result)
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "file_list", map[string]any{})
			if got != nil || !errors.Is(err, tc.want) || len(runner.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"unknown", map[string]any{"not_supported": true}},
		{"bad-verify-option", map[string]any{"verify_options": []any{"ok", 1}}},
		{"bad-errors", map[string]any{"errors": "return"}},
		{"bad-root", map[string]any{"root": "bad\x00root"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &yumNoCallRunner{}
			rt := &runtime.Runtime{Runner: runner}
			function := "file_list"
			if tc.name == "bad-verify-option" {
				function = "verify"
			}
			if tc.name == "bad-errors" {
				function = "info_installed"
			}
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, function, tc.args)
			var unsupported *runtime.UnsupportedError
			if got != nil || err == nil || (tc.name != "bad-errors" && !errors.As(err, &unsupported)) || runner.calls != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, runner.calls)
			}
		})
	}
	wrong := &commandProvider{spec: rpmSpec("yum")}
	runner := &yumNoCallRunner{}
	got, err := wrong.Zypper(context.Background(), &runtime.Runtime{Runner: runner}, "file_list", map[string]any{})
	if got != nil || !errors.Is(err, ErrUnsupportedZypper) || runner.calls != 0 {
		t.Fatalf("wrong provider got=%#v err=%v calls=%d", got, err, runner.calls)
	}
}

func TestZypperLowpkgCancellationStopsTheBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte("/usr/bin/demo\n")})
	got, err := zypperLowpkgProvider().Zypper(ctx, rt, "file_dict", map[string]any{"packages": []string{"demo"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 1 {
		t.Fatalf("pre-canceled batch got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt.Runner = cancelRunner
	got, err = zypperLowpkgProvider().Zypper(ctx, rt, "file_dict", map[string]any{"packages": []string{"demo"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("mid-batch cancellation got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}
}
