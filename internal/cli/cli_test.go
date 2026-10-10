package cli

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgs "github.com/friz-zy/statekit/modules/exec/pkg"
	exectest "github.com/friz-zy/statekit/modules/exec/test"
	execuser "github.com/friz-zy/statekit/modules/exec/user"
	statefile "github.com/friz-zy/statekit/modules/state/file"
	statetest "github.com/friz-zy/statekit/modules/state/test"
	stateuser "github.com/friz-zy/statekit/modules/state/user"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func capture(t *testing.T, fn func()) (string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()
	fn()
	outW.Close()
	errW.Close()
	outData, _ := io.ReadAll(outR)
	errData, _ := io.ReadAll(errR)
	return string(outData), string(errData)
}

type cliRecordingRunner struct {
	calls   []process.Command
	results []process.CommandResult
}

func (r *cliRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.calls = append(r.calls, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

type cliCountingFS struct{ calls int }

func (f *cliCountingFS) fail()                                       { f.calls++; panic("pure Zypper CLI call touched filesystem") }
func (f *cliCountingFS) Stat(string) (fs.FileInfo, error)            { f.fail(); return nil, nil }
func (f *cliCountingFS) Lstat(string) (fs.FileInfo, error)           { f.fail(); return nil, nil }
func (f *cliCountingFS) ReadFile(string) ([]byte, error)             { f.fail(); return nil, nil }
func (f *cliCountingFS) WriteFile(string, []byte, fs.FileMode) error { f.fail(); return nil }
func (f *cliCountingFS) MkdirAll(string, fs.FileMode) error          { f.fail(); return nil }
func (f *cliCountingFS) MkdirTemp(string, string) (string, error)    { f.fail(); return "", nil }
func (f *cliCountingFS) Remove(string) error                         { f.fail(); return nil }
func (f *cliCountingFS) RemoveAll(string) error                      { f.fail(); return nil }
func (f *cliCountingFS) Rename(string, string) error                 { f.fail(); return nil }
func (f *cliCountingFS) Symlink(string, string) error                { f.fail(); return nil }
func (f *cliCountingFS) Link(string, string) error                   { f.fail(); return nil }
func (f *cliCountingFS) Glob(string) ([]string, error)               { f.fail(); return nil, nil }
func (f *cliCountingFS) Readlink(string) (string, error)             { f.fail(); return "", nil }
func (f *cliCountingFS) ReadDir(string) ([]fs.DirEntry, error)       { f.fail(); return nil, nil }
func (f *cliCountingFS) Chmod(string, fs.FileMode) error             { f.fail(); return nil }
func (f *cliCountingFS) Chown(string, int, int) error                { f.fail(); return nil }
func (f *cliCountingFS) Lchown(string, int, int) error               { f.fail(); return nil }

func providerCLIApp(t *testing.T, manager string, runner *cliRecordingRunner) *App {
	return providerCLIAppWithFS(t, manager, runner, runtime.NewMemoryFS())
}

func providerCLIAppWithFS(t *testing.T, manager string, runner *cliRecordingRunner, fsys runtime.FileSystem) *App {
	t.Helper()
	build := func() (*runtime.Runtime, error) {
		rt := &runtime.Runtime{
			Exec: runtime.NewExecRegistry(), Providers: runtime.NewProviderRegistry(), Runner: runner,
			Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}),
			FS:    fsys,
		}
		if err := pkgs.Register(rt.Exec); err != nil {
			return nil, err
		}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			return nil, err
		}
		return rt, nil
	}
	return NewApp("test-version", build)
}

func TestProviderAwareCLIValidation(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "zypper"} {
		runner := &cliRecordingRunner{results: []process.CommandResult{
			{ExitCode: 0, Stdout: []byte("LONGSIZE\n")},
			{ExitCode: 0, Stdout: []byte("name: foo\nversion: 1\nrelease: 1\nedition: 1-1\n-----\n")},
		}}
		code, _, errS := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.info_installed", "--all-versions", "--root", "/image", "--attr", "version")
		if code != ExitOK || errS != "" || len(runner.calls) != 2 {
			t.Fatalf("%s valid fields: code=%d err=%q calls=%d", manager, code, errS, len(runner.calls))
		}
		if runner.calls[1].Args[0] != "--root" || runner.calls[1].Args[1] != "/image" {
			t.Fatalf("%s root not decoded: %#v", manager, runner.calls[1])
		}

		runner = &cliRecordingRunner{}
		code, _, _ = captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.info_installed", "--failhard")
		if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("%s accepted apt-only flag: code=%d calls=%d", manager, code, len(runner.calls))
		}
	}
	for _, manager := range []string{"apt"} {
		runner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0}}}
		code, _, _ := captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.info_installed", "--failhard")
		if code == ExitInvalidInput || len(runner.calls) == 0 {
			t.Fatalf("apt failhard validation: code=%d calls=%d", code, len(runner.calls))
		}
		runner = &cliRecordingRunner{}
		code, _, _ = captureCode(t, providerCLIApp(t, manager, runner), "exec", "pkg.info_installed", "--all-versions")
		if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("apt accepted yum-only flag: code=%d calls=%d", code, len(runner.calls))
		}
	}
	for _, tc := range []struct {
		manager string
		command string
		valid   bool
	}{
		{"yum", "pkg.file_list", true}, {"dnf", "pkg.owner", true},
		{"zypper", "pkg.file_list", true}, {"zypper", "pkg.owner", true},
		{"apt", "pkg.file_list", false}, {"apt", "pkg.owner", false},
	} {
		runner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0, Stdout: []byte("/x\n")}}}
		flag := "--packages"
		if tc.command == "pkg.owner" {
			flag = "--paths"
		}
		code, _, _ := captureCode(t, providerCLIApp(t, tc.manager, runner), "exec", tc.command, "--root", "/image", flag, "/x")
		if tc.valid {
			if code == ExitInvalidInput || len(runner.calls) == 0 {
				t.Fatalf("%s %s root rejected: code=%d calls=%d", tc.manager, tc.command, code, len(runner.calls))
			}
		} else if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("%s %s accepted root: code=%d calls=%d", tc.manager, tc.command, code, len(runner.calls))
		}
	}
}

func TestZypperLowpkgCLIUsesProviderPrototypesBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		results  []process.CommandResult
		calls    int
		wantArgv []string
	}{
		{
			name:     "pkg.modified",
			args:     []string{"exec", "pkg.modified", "--packages", "demo"},
			results:  []process.CommandResult{{ExitCode: 1, Stdout: []byte("......... /clean\n")}},
			calls:    1,
			wantArgv: []string{"rpm", "--noscripts", "-Va", "demo"},
		},
		{
			name:     "pkg.verify",
			args:     []string{"exec", "pkg.verify", "--names", "demo", "--verify-options", "nodigest"},
			results:  []process.CommandResult{{ExitCode: 0}},
			calls:    1,
			wantArgv: []string{"rpm", "--nodigest", "--noscripts", "-V", "demo"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: tc.results}
			code, _, errS := captureCode(t, providerCLIApp(t, "zypper", runner), append(tc.args, "-o", "json")...)
			if code != ExitOK || errS != "" || len(runner.calls) != tc.calls {
				t.Fatalf("code=%d err=%q calls=%d", code, errS, len(runner.calls))
			}
			if runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes != 1<<20 || runner.calls[0].MaxStderrBytes != 1<<20 {
				t.Fatalf("command=%#v", runner.calls[0])
			}
			if got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(got, tc.wantArgv) {
				t.Fatalf("argv=%#v want=%#v", got, tc.wantArgv)
			}
		})
	}
	for _, args := range [][]string{
		{"exec", "pkg.modified", "--names", "demo"},
		{"exec", "pkg.verify", "--failhard"},
	} {
		runner := &cliRecordingRunner{}
		code, _, _ := captureCode(t, providerCLIApp(t, "zypper", runner), append(args, "-o", "json")...)
		if code != ExitInvalidInput || len(runner.calls) != 0 {
			t.Fatalf("args=%v code=%d calls=%d", args, code, len(runner.calls))
		}
	}
}

func TestZypperLowpkgCLIVerificationDefaultsUseNoScripts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		function string
		wantArgv []string
	}{
		{name: "modified default", function: "pkg.modified", wantArgv: []string{"rpm", "--noscripts", "-Va"}},
		{name: "verify default", function: "pkg.verify", wantArgv: []string{"rpm", "--noscripts", "-Va"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &cliRecordingRunner{results: []process.CommandResult{{ExitCode: 0}}}
			app := providerCLIAppWithFS(t, "zypper", runner, runtime.NewMemoryFS())
			code, out, errS := captureCode(t, app, "exec", tc.function, "-o", "json")
			if code != ExitOK || errS != "" || out != "{}\n" || len(runner.calls) != 1 {
				t.Fatalf("code=%d out=%q err=%q calls=%d", code, out, errS, len(runner.calls))
			}
			got := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
			if !reflect.DeepEqual(got, tc.wantArgv) || runner.calls[0].Shell || runner.calls[0].MaxStdoutBytes != 1<<20 || runner.calls[0].MaxStderrBytes != 1<<20 {
				t.Fatalf("command=%#v argv=%#v want=%#v", runner.calls[0], got, tc.wantArgv)
			}
		})
	}
}

func TestZypperLowpkgCLIOutputMatrix(t *testing.T) {
	const outputLimit = 1 << 20
	const fileDictFormat = "%{NAME} %{VERSION}\\n"
	const infoFormat = "version: %{VERSION}\\nname: %{NAME}\\nedition: %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n-----\\n"

	cases := []struct {
		name     string
		argv     []string
		results  []process.CommandResult
		want     any
		wantArgv [][]string
		wantEnv  [][]string
	}{
		{
			name: "file_list",
			argv: []string{"exec", "pkg.file_list", "--packages", "demo", "--root", "/target"},
			results: []process.CommandResult{{
				Stdout: []byte("/usr/bin/demo\n/usr/share/doc/demo\n"),
			}},
			want: map[string]any{
				"errors": []any{}, "files": []any{"/usr/bin/demo", "/usr/share/doc/demo"},
			},
			wantArgv: [][]string{{"rpm", "--root", "/target", "-ql", "demo"}},
			wantEnv:  [][]string{nil},
		},
		{
			name: "file_dict",
			argv: []string{"exec", "pkg.file_dict", "--packages", "demo", "--root", "/target"},
			results: []process.CommandResult{
				{Stdout: []byte("demo 1\n")},
				{Stdout: []byte("/usr/bin/demo\n/usr/share/demo\n")},
			},
			want: map[string]any{
				"errors": []any{},
				"packages": map[string]any{
					"demo": []any{"/usr/bin/demo", "/usr/share/demo"},
				},
			},
			wantArgv: [][]string{
				{"rpm", "--root", "/target", "-q", "--queryformat", fileDictFormat, "demo"},
				{"rpm", "-ql", "demo"},
			},
			wantEnv: [][]string{nil, nil},
		},
		{
			name: "info_installed",
			argv: []string{
				"exec", "pkg.info_installed", "--names", "demo", "--root", "/target",
				"--attr", "version", "--errors", "report",
			},
			results: []process.CommandResult{
				{Stdout: []byte("LONGSIZE\n")},
				{Stdout: []byte("name: demo\nversion: 2\nedition: 2-1\n-----\n")},
			},
			want: map[string]any{
				"demo": map[string]any{"version": "2"},
			},
			wantArgv: [][]string{
				{"rpm", "--querytags"},
				{"rpm", "--root", "/target", "-q", "demo", "--queryformat", infoFormat},
			},
			wantEnv: [][]string{nil, {"TZ=UTC"}},
		},
		{
			name:     "owner",
			argv:     []string{"exec", "pkg.owner", "--paths", "/usr/bin/demo", "--root", "/target"},
			results:  []process.CommandResult{{Stdout: []byte("demo")}},
			want:     "demo",
			wantArgv: [][]string{{"rpm", "--root", "/target", "-qf", "--queryformat", "%{name}", "/usr/bin/demo"}},
			wantEnv:  [][]string{nil},
		},
		{
			name: "modified",
			argv: []string{
				"exec", "pkg.modified", "--packages", "demo", "--root", "/target",
				"--size", "--mode", "--checksum", "--device", "--symlink", "--owner",
				"--group", "--time", "--capabilities",
			},
			results: []process.CommandResult{{
				ExitCode: 1,
				Stdout:   []byte("SM5DLUGTP c /etc/demo\n......... /etc/clean\n"),
			}},
			want: map[string]any{
				"/etc/demo": []any{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities", "config"},
			},
			wantArgv: [][]string{{"rpm", "--root", "/target", "--noscripts", "-Va", "demo"}},
			wantEnv:  [][]string{nil},
		},
		{
			name: "verify",
			argv: []string{
				"exec", "pkg.verify", "--names", "demo", "--root", "/target",
				"--verify-options", "nodigest,noscripts,nosignature", "--ignore-types", "doc",
			},
			results: []process.CommandResult{{
				ExitCode: 1,
				Stdout:   []byte("SM5DLUGTP  c /etc/demo\n.........  d /usr/share/doc/demo\n"),
			}},
			want: map[string]any{
				"/etc/demo": map[string]any{
					"type": "config",
					"mismatch": []any{
						"size", "mode", "md5sum", "device major/minor number", "readlink path",
						"user", "group", "mtime", "capabilities",
					},
				},
			},
			wantArgv: [][]string{{
				"rpm", "--root", "/target", "--nodigest", "--noscripts", "--nosignature", "-V", "demo",
			}},
			wantEnv: [][]string{nil},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := runtime.NewMemoryFS()
			runner := &cliRecordingRunner{results: append([]process.CommandResult(nil), tc.results...)}
			app := providerCLIAppWithFS(t, "zypper", runner, fsys)
			code, out, errS := captureCode(t, app, append(tc.argv, "-o", "json")...)
			if code != ExitOK || errS != "" {
				t.Fatalf("code=%d out=%q err=%q", code, out, errS)
			}
			var got any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("JSON: %v (%q)", err, out)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("result=%#v want=%#v", got, tc.want)
			}
			if len(runner.calls) != len(tc.wantArgv) || len(runner.results) != 0 {
				t.Fatalf("calls=%d remaining results=%d", len(runner.calls), len(runner.results))
			}
			for index, command := range runner.calls {
				gotArgv := append([]string{command.Name}, command.Args...)
				if !reflect.DeepEqual(gotArgv, tc.wantArgv[index]) {
					t.Fatalf("call[%d] argv=%#v want=%#v", index, gotArgv, tc.wantArgv[index])
				}
				if command.Shell || command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit {
					t.Fatalf("call[%d] unsafe bounds/runner mode: %#v", index, command)
				}
				if !reflect.DeepEqual(command.Env, tc.wantEnv[index]) {
					t.Fatalf("call[%d] env=%#v want=%#v", index, command.Env, tc.wantEnv[index])
				}
			}
		})
	}
}

func TestZypperVersionCmpCLIUsesSourceArgumentNames(t *testing.T) {
	fsys := &cliCountingFS{}
	runner := &cliRecordingRunner{}
	app := providerCLIAppWithFS(t, "zypper", runner, fsys)
	for _, tc := range []struct {
		name string
		argv []string
		want any
	}{
		{"normalize_name", []string{"exec", "pkg.normalize_name", "--name", "pkg.x86_64", "-o", "json"}, "pkg"},
		{"parse_arch", []string{"exec", "pkg.parse_arch", "--name", "pkg.x86_64", "-o", "json"}, map[string]any{"name": "pkg", "arch": "x86_64"}},
		{"version_cmp", []string{"exec", "pkg.version_cmp", "--ver1", "1_0:1", "--ver2", "2:1", "-o", "json"}, float64(1)},
	} {
		code, out, errS := captureCode(t, app, tc.argv...)
		if code != ExitOK || errS != "" || len(runner.calls) != 0 || fsys.calls != 0 {
			t.Fatalf("%s: code=%d out=%q err=%q runner=%d fs=%d", tc.name, code, out, errS, len(runner.calls), fsys.calls)
		}
		var got any
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%s JSON: %v (%q)", tc.name, err, out)
		}
		switch want := tc.want.(type) {
		case string:
			if got != want {
				t.Fatalf("%s result=%#v want=%#v", tc.name, got, want)
			}
		case float64:
			if got != want {
				t.Fatalf("%s result=%#v want=%#v", tc.name, got, want)
			}
		case map[string]any:
			actual, ok := got.(map[string]any)
			if !ok || len(actual) != len(want) {
				t.Fatalf("%s result=%#v want=%#v", tc.name, got, want)
			}
			for key, value := range want {
				if actual[key] != value {
					t.Fatalf("%s result=%#v want=%#v", tc.name, got, want)
				}
			}
		}
	}

	code, _, errS := captureCode(t, app, "exec", "pkg.version_cmp", "--config", `{"pkg1":"1","pkg2":"2"}`)
	if code != ExitInvalidInput || errS == "" || len(runner.calls) != 0 || fsys.calls != 0 {
		t.Fatalf("zypper rejected pkg1/pkg2: code=%d err=%q runner=%d fs=%d", code, errS, len(runner.calls), fsys.calls)
	}
}

func TestZypperCLIRejectsUnsafeTokensWithoutSideEffects(t *testing.T) {
	fsys := &cliCountingFS{}
	runner := &cliRecordingRunner{}
	app := providerCLIAppWithFS(t, "zypper", runner, fsys)
	badName := "pkg.\x00secret"
	code, _, errS := captureCode(t, app, "exec", "pkg.normalize_name", "--name", badName)
	if code != ExitFailed || errS != "statekit: invalid package name\n" || strings.Contains(errS, "secret") || len(runner.calls) != 0 || fsys.calls != 0 {
		t.Fatalf("name rejection: code=%d err=%q runner=%d fs=%d", code, errS, len(runner.calls), fsys.calls)
	}

	badVersion := strings.Repeat("v", 4097)
	code, _, errS = captureCode(t, app, "exec", "pkg.version_cmp", "--ver1", badVersion, "--ver2", "1")
	if code != ExitFailed || errS != "statekit: invalid package version\n" || strings.Contains(errS, badVersion) || len(runner.calls) != 0 || fsys.calls != 0 {
		t.Fatalf("version rejection: code=%d err=%q runner=%d fs=%d", code, errS, len(runner.calls), fsys.calls)
	}
}

func captureCode(t *testing.T, app *App, argv ...string) (int, string, string) {
	t.Helper()
	var code int
	out, errS := capture(t, func() { code = app.Run(argv) })
	return code, out, errS
}

func testRuntime() (*runtime.Runtime, error) {
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		Facts: facts.ForTesting(facts.Overrides{
			OS: &facts.OSFacts{ID: "alpine", Family: facts.FamilyAlpine},
		}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    process.NewRunner(),
		FS:        runtime.NewMemoryFS(),
	}
	if err := exectest.Register(rt.Exec); err != nil {
		return nil, err
	}
	if err := statetest.Register(rt.States); err != nil {
		return nil, err
	}
	if err := statefile.Register(rt.States); err != nil {
		return nil, err
	}
	return rt, nil
}

func runApp(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	var code int
	var out, errS string
	app := NewApp("test-version", testRuntime)
	out, errS = capture(t, func() { code = app.Run(argv) })
	return code, out, errS
}

func TestVersionCommand(t *testing.T) {
	code, out, _ := runApp(t, "version")
	if code != ExitOK || !strings.Contains(out, "test-version") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	code, out, _ = runApp(t, "version", "-o", "json")
	var parsed map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &parsed) != nil || parsed["version"] != "test-version" {
		t.Fatalf("version json: code=%d out=%q", code, out)
	}
}

func TestExecEchoChannels(t *testing.T) {
	code, out, _ := runApp(t, "exec", "test.echo", "--text", "hello")
	if code != ExitOK || strings.TrimSpace(out) != "hello" {
		t.Fatalf("flag channel: code=%d out=%q", code, out)
	}

	code, out, _ = runApp(t, "exec", "test.echo", "--config", `{"text":"hi"}`)
	if code != ExitOK || strings.TrimSpace(out) != "hi" {
		t.Fatalf("config channel: code=%d out=%q", code, out)
	}

	code, _, _ = runApp(t, "exec", "test.echo", "--stdin", "--file", "x.yaml")
	if code != ExitInvalidInput {
		t.Fatalf("stdin+file must conflict, got %d", code)
	}

	dir := t.TempDir()
	path := dir + "/req.json"
	os.WriteFile(path, []byte(`{"text":"from-file"}`), 0o600)
	code, out, _ = runApp(t, "exec", "test.echo", "--file", path)
	if code != ExitOK || strings.TrimSpace(out) != "from-file" {
		t.Fatalf("file channel: code=%d out=%q", code, out)
	}

	code, out, _ = runApp(t, "exec", "test.echo", "--config", `{"text":"x"}`, "--text", "override")
	if code != ExitOK || strings.TrimSpace(out) != "override" {
		t.Fatalf("flag precedence over config broken: code=%d out=%q", code, out)
	}

	code, _, errS := runApp(t, "exec", "test.echo")
	if code != ExitInvalidInput || !strings.Contains(errS, "required") {
		t.Fatalf("missing required text: code=%d err=%q", code, errS)
	}
}

type cliUserFS struct {
	runtime.FileSystem
	boundedReads  int
	unboundedRead int
}

func (f *cliUserFS) ReadFile(name string) ([]byte, error) {
	f.unboundedRead++
	return f.FileSystem.ReadFile(name)
}

func (f *cliUserFS) ReadFileBounded(name string, limit int64) ([]byte, error) {
	f.boundedReads++
	return runtime.ReadFileBounded(f.FileSystem, name, limit)
}

type cliUserRunner struct {
	commands     []process.Command
	resolveCalls []string
	fs           runtime.FileSystem
}

func (r *cliUserRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.commands = append(r.commands, cmd)
	if cmd.Name == "/usr/sbin/usermod" && len(cmd.Args) == 3 && cmd.Args[0] == "-c" {
		data, err := r.fs.ReadFile("/etc/passwd")
		if err == nil {
			lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			for i, line := range lines {
				fields := strings.SplitN(line, ":", 7)
				if len(fields) == 7 && fields[0] == cmd.Args[2] {
					fields[4] = cmd.Args[1]
					lines[i] = strings.Join(fields, ":")
				}
			}
			_ = r.fs.WriteFile("/etc/passwd", []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		}
	}
	return process.CommandResult{ExitCode: 0}
}

func (r *cliUserRunner) ResolveTrustedCommand(name string) (string, error) {
	r.resolveCalls = append(r.resolveCalls, name)
	if name != "usermod" {
		return "", process.ErrTrustedCommandUnsupported
	}
	return "/usr/sbin/usermod", nil
}

func newCLIUserApp(t *testing.T) (*App, *cliUserRunner, *cliUserFS) {
	t.Helper()
	mem := runtime.NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile("/etc/passwd", []byte("synthetic:x:1000:1000:first,last,room,work,old:/home/synthetic:/bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys := &cliUserFS{FileSystem: mem}
	runner := &cliUserRunner{fs: mem}
	rt := &runtime.Runtime{
		Exec: runtime.NewExecRegistry(), States: runtime.NewStateRegistry(),
		Facts: facts.ForTesting(facts.Overrides{}), Providers: runtime.NewProviderRegistry(),
		Runner: runner, FS: fsys,
	}
	if err := execuser.Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	if err := stateuser.Register(rt.States); err != nil {
		t.Fatal(err)
	}
	return NewApp("test-version", func() (*runtime.Runtime, error) { return rt, nil }), runner, fsys
}

func TestChotherOrdinaryCLIJSONYAMLAndFlagTransport(t *testing.T) {
	app, runner, fsys := newCLIUserApp(t)
	code, _, errText := captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic"}`)
	if code != ExitInvalidInput || !strings.Contains(errText, `missing required argument "other"`) || len(runner.commands) != 0 || fsys.boundedReads != 0 || fsys.unboundedRead != 0 {
		t.Fatalf("missing other binding effects: code=%d err=%q commands=%v reads=%d/%d", code, errText, runner.commands, fsys.boundedReads, fsys.unboundedRead)
	}

	app, runner, fsys = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic","other":0}`)
	if code != ExitFailed || !strings.Contains(errText, "user.chother: invalid other type") || len(runner.commands) != 0 || fsys.boundedReads != 0 {
		t.Fatalf("JSON-first float64 must fail before effects: code=%d err=%q commands=%v reads=%d", code, errText, runner.commands, fsys.boundedReads)
	}

	app, runner, fsys = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", "name: synthetic\nother: 0\n")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || !strings.HasSuffix(runner.commands[0].Args[1], ",0") {
		t.Fatalf("YAML integer transport: code=%d err=%q commands=%+v", code, errText, runner.commands)
	}
	if fsys.boundedReads != 2 || fsys.unboundedRead != 0 {
		t.Fatalf("YAML integer reads=%d/%d", fsys.boundedReads, fsys.unboundedRead)
	}

	app, runner, fsys = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic","other":-1}`)
	if code != ExitFailed || !strings.Contains(errText, "user.chother: invalid other type") || len(runner.commands) != 0 || fsys.boundedReads != 0 {
		t.Fatalf("JSON negative integer must remain float64 and fail: code=%d err=%q commands=%v reads=%d", code, errText, runner.commands, fsys.boundedReads)
	}

	app, runner, _ = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic","other":null}`)
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || runner.commands[0].Args[1] != "first,last,room,work" {
		t.Fatalf("JSON null must clear other: code=%d err=%q commands=%+v", code, errText, runner.commands)
	}

	for _, structured := range []string{
		`{"name":"synthetic","other":null}`,
		`{"name":"synthetic","other":7}`,
	} {
		app, runner, _ = newCLIUserApp(t)
		code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", structured, "--other=0007")
		if code != ExitOK || errText != "" || len(runner.commands) != 1 || !strings.HasSuffix(runner.commands[0].Args[1], ",0007") {
			t.Fatalf("flag override config=%s: code=%d err=%q commands=%+v", structured, code, errText, runner.commands)
		}
	}

	app, runner, _ = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic","other":"old"}`, "--other=null")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || !strings.HasSuffix(runner.commands[0].Args[1], ",null") {
		t.Fatalf("--other=null must be literal text: code=%d err=%q commands=%+v", code, errText, runner.commands)
	}

	app, runner, _ = newCLIUserApp(t)
	code, _, errText = captureCode(t, app, "exec", "user.chother", "--config", `{"name":"synthetic","other":"old"}`, "--other=")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || strings.HasSuffix(runner.commands[0].Args[1], ",") {
		t.Fatalf("empty flag must override with clear: code=%d err=%q commands=%+v", code, errText, runner.commands)
	}
}

func TestUserPresentOtherOrdinaryCLIStateTransport(t *testing.T) {
	app, runner, fsys := newCLIUserApp(t)
	code, out, errText := captureCode(t, app, "state", "user.present", "--config", `{"name":"synthetic","other":null}`, "-o", "json")
	if code != ExitOK || errText != "" || len(runner.commands) != 0 || fsys.boundedReads != 0 || fsys.unboundedRead != 2 {
		t.Fatalf("state null must remain unmanaged: code=%d out=%q err=%q commands=%v reads=%d/%d", code, out, errText, runner.commands, fsys.boundedReads, fsys.unboundedRead)
	}

	app, runner, fsys = newCLIUserApp(t)
	code, out, errText = captureCode(t, app, "state", "user.present", "--config", `{"name":"synthetic","other":""}`, "-o", "json")
	if code != ExitOK || errText != "" || len(runner.commands) != 1 || fsys.boundedReads != 3 || fsys.unboundedRead != 0 {
		t.Fatalf("state empty must clear: code=%d out=%q err=%q commands=%v reads=%d/%d", code, out, errText, runner.commands, fsys.boundedReads, fsys.unboundedRead)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode state output: %v", err)
	}
	changes, ok := result["changes"].(map[string]any)
	if !ok || !reflect.DeepEqual(changes["other"], map[string]any{"changed": true}) || strings.Contains(out, "first,last,room,work") {
		t.Fatalf("state output is not metadata-only: %s", out)
	}
}

func TestExecUnknownFunctionExitThree(t *testing.T) {
	code, _, errS := runApp(t, "exec", "nosuchmod.nofun", "--name", "curl")
	if code != ExitUnsupported || !strings.Contains(errS, "unsupported") {
		t.Fatalf("unknown function: code=%d err=%q", code, errS)
	}
}

func TestStateNopJSONShape(t *testing.T) {
	code, out, _ := runApp(t, "state", "test.nop", "--name", "example", "-o", "json")
	var res map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil {
		t.Fatalf("state nop json: code=%d out=%q", code, out)
	}
	if res["name"] != "example" || res["result"] != true || res["comment"] != "Success!" {
		t.Fatalf("salt-compatible fields wrong: %v", res)
	}
	changes, ok := res["changes"].(map[string]any)
	if !ok || len(changes) != 0 {
		t.Fatalf("changes must be empty object: %v", res["changes"])
	}
	meta, ok := res["meta"].(map[string]any)
	if !ok || meta["type"] != "state" || meta["module"] != "test" || meta["function"] != "nop" {
		t.Fatalf("meta missing or wrong: %v", res["meta"])
	}
}

func TestStateSingle(t *testing.T) {
	code, out, _ := runApp(t, "state", "single", "test.nop", "--name", "example", "-o", "json")
	var res map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || res["result"] != true {
		t.Fatalf("single positional form: code=%d out=%q", code, out)
	}
	meta := res["meta"].(map[string]any)
	if meta["module"] != "test" || meta["function"] != "nop" {
		t.Fatalf("meta wrong: %v", meta)
	}

	code, out, _ = runApp(t, "state", "single", "--config",
		`{"fun":"test.nop","name":"via-fun-key"}`, "-o", "json")
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || res["name"] != "via-fun-key" {
		t.Fatalf("single fun-key form: code=%d out=%q", code, out)
	}

	code, _, errS := runApp(t, "state", "single")
	if code != ExitInvalidInput {
		t.Fatalf("bare single must fail, got %d (%q)", code, errS)
	}

	code, _, errS = runApp(t, "exec", "single", "test.echo")
	if code != ExitInvalidInput && code != ExitUnsupported {
		t.Fatalf("single is state-only, got %d (%q)", code, errS)
	}
}

func TestListCommands(t *testing.T) {
	code, out, _ := runApp(t, "exec", "--list")
	if code != ExitOK || !strings.Contains(out, "test.echo") || !strings.Contains(out, "test.ping") {
		t.Fatalf("exec --list: %q", out)
	}
	code, out, _ = runApp(t, "state", "--list")
	if code != ExitOK || !strings.Contains(out, "test.nop") {
		t.Fatalf("state --list: %q", out)
	}
	code, out, _ = runApp(t, "exec", "--list", "nomodule")
	if code != ExitOK || strings.TrimSpace(out) != "" {
		t.Fatalf("filtered list must be empty for unknown prefix: %q", out)
	}
	code, out, _ = runApp(t, "state", "--list", "test")
	if code != ExitOK || !strings.Contains(out, "test.nop") {
		t.Fatalf("module-filtered state list: %q", out)
	}
}

func TestFactsCommand(t *testing.T) {
	code, out, _ := runApp(t, "facts", "-o", "json")
	var parsed map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &parsed) != nil {
		t.Fatalf("facts: code=%d out=%q", code, out)
	}
	osMap, ok := parsed["os"].(map[string]any)
	if !ok || osMap["id"] != "alpine" {
		t.Fatalf("facts payload wrong: %v", parsed["os"])
	}
}

func TestErrorPathsAndCodes(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"no args", nil, ExitInvalidInput},
		{"unknown command", []string{"bogus"}, ExitInvalidInput},
		{"bad target form", []string{"exec", "noDot"}, ExitInvalidInput},
		{"unknown flag", []string{"exec", "test.echo", "--bogus", "x"}, ExitInvalidInput},
		{"missing required", []string{"exec", "test.echo"}, ExitInvalidInput},
		{"unknown arg structured", []string{"exec", "test.echo", "--config", `{"nmae":"x"}`}, ExitInvalidInput},
		{"invalid format", []string{"exec", "test.echo", "--text", "x", "-o", "xml"}, ExitInvalidInput},
		{"unknown state", []string{"state", "pkg.installed", "--name", "x"}, ExitUnsupported},
	}
	for _, tc := range cases {
		code, _, errS := runApp(t, tc.argv...)
		if code != tc.want {
			t.Fatalf("%s: exit=%d want=%d err=%q", tc.name, code, tc.want, errS)
		}
	}
}

func TestHelpExitsZero(t *testing.T) {
	for _, h := range []string{"help", "-h", "--help"} {
		code, out, _ := runApp(t, h)
		if code != ExitOK || !strings.Contains(out, "Usage:") {
			t.Fatalf("%s: code=%d", h, code)
		}
	}
}

func TestStdinDashChannel(t *testing.T) {
	// "-" positional is validated at parse level; full stdin piping covered by
	// the integration harness which spawns the real binary.
	code, _, _ := runApp(t, "exec", "test.echo", "-", "extra-positional")
	if code != ExitInvalidInput {
		t.Fatalf("unexpected positionals must fail, got %d", code)
	}
}
