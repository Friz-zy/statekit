package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type yumExecNoCallRunner struct{ calls int }

func (r *yumExecNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	panic("runner invoked")
}

func TestYumLongtailRegistryAndPureCalls(t *testing.T) {
	for _, manager := range []string{"yum", "dnf"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecNoCallRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Runner: runner, Providers: runtime.NewProviderRegistry()}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			name string
			args any
			want any
		}{
			{"pkg.normalize_name", &NormalizeNameArgs{Name: "zsh.x86_64"}, "zsh"},
			{"pkg.parse_arch", &ParseArchArgs{Name: "zsh.x86_64"}, map[string]any{"name": "zsh", "arch": "x86_64"}},
			{"pkg.version_cmp", &VersionCmpArgs{Pkg1: "1.0~rc1", Pkg2: "1.0"}, -1},
		} {
			fn, ok := reg.Get(tt.name)
			if !ok {
				t.Fatalf("missing %s", tt.name)
			}
			if got := fn.Args(); reflect.TypeOf(got) != reflect.TypeOf(tt.args).Elem() {
				t.Fatalf("%s Args type=%T", tt.name, got)
			}
			if got := reg.ProviderCapabilities(tt.name); !reflect.DeepEqual(got, []string{"aptpkg", "yumpkg"}) {
				t.Fatalf("%s caps=%v", tt.name, got)
			}
			got, err := reg.Call(context.Background(), rt, tt.name, tt.args)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s got=%#v err=%v", tt.name, got, err)
			}
		}
		for _, args := range []any{nil, &NormalizeNameArgs{}, map[string]any{"pkg1": "1", "pkg2": 2}} {
			if _, err := reg.Call(context.Background(), rt, "pkg.version_cmp", args); err == nil {
				t.Errorf("version_cmp accepted malformed args %#v", args)
			}
		}
		for _, tt := range []struct {
			left, right string
			ignore      *bool
			want        any
		}{
			{"", "1.0", nil, -1},
			{"wat:1.0", "1.0", nil, 0},
			{"1.0", "1.0", nil, 0},
			{"1.1", "1.0", nil, 1},
			{"0:1.0", "1:1.0", func() *bool { v := true; return &v }(), 0},
		} {
			got, err := reg.Call(context.Background(), rt, "pkg.version_cmp", &VersionCmpArgs{Pkg1: tt.left, Pkg2: tt.right, IgnoreEpoch: tt.ignore})
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("version_cmp %q/%q got=%#v err=%v want=%#v", tt.left, tt.right, got, err, tt.want)
			}
		}
		for _, tt := range []struct {
			name string
			args any
		}{
			{"pkg.normalize_name", nil},
			{"pkg.normalize_name", "zsh.x86_64"},
			{"pkg.normalize_name", map[string]any{"name": "zsh.x86_64"}},
			{"pkg.normalize_name", (*NormalizeNameArgs)(nil)},
			{"pkg.normalize_name", &AutoremoveArgs{}},
			{"pkg.parse_arch", nil},
			{"pkg.parse_arch", 1},
			{"pkg.parse_arch", map[string]any{"name": "zsh.x86_64"}},
			{"pkg.parse_arch", (*ParseArchArgs)(nil)},
			{"pkg.parse_arch", &AutoremoveArgs{}},
		} {
			if got, err := reg.Call(context.Background(), rt, tt.name, tt.args); got != nil || err == nil || err.Error() != tt.name+": malformed arguments" {
				t.Errorf("%s malformed args got=%#v err=%v", tt.name, got, err)
			}
		}
		for _, fn := range longtailFunctions() {
			name := fn.Name()
			if reflect.DeepEqual(reg.ProviderCapabilities(name), []string{"aptpkg"}) {
				if _, err := reg.Call(context.Background(), rt, name, fn.Args()); !errors.As(err, new(*runtime.UnsupportedError)) {
					t.Fatalf("%s on %s: error=%v", name, manager, err)
				}
			}
		}
		if runner.calls != 0 {
			t.Fatalf("%s runner calls=%d", manager, runner.calls)
		}
	}
}

func TestLongtailResolveArgsProviderMatrix(t *testing.T) {
	for _, manager := range []string{"apt", "yum", "dnf"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		if manager == "apt" {
			// The provider selector uses the package fact, while the OS family is
			// only used by the normal provider registration path.
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}}), Providers: runtime.NewProviderRegistry()}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name       string
			wantType   reflect.Type
			wantNames  []string
			args       any
			results    []process.CommandResult
			wantArgv   [][]string
			wantResult func(any) bool
		}{
			{"pkg.file_list", reflect.TypeOf(FilePackagesArgs{}), []string{"packages"},
				&YumFilesArgs{Packages: []string{"foo"}},
				[]process.CommandResult{{Stdout: []byte("/usr/bin/foo\n")}},
				[][]string{{"rpm", "-ql", "foo"}},
				func(v any) bool {
					return reflect.DeepEqual(v, map[string]any{"errors": []string{}, "files": []string{"/usr/bin/foo"}})
				}},
			{"pkg.file_dict", reflect.TypeOf(FilePackagesArgs{}), []string{"packages"},
				&YumFilesArgs{Packages: []string{"foo"}},
				[]process.CommandResult{{Stdout: []byte("foo 1\n")}, {Stdout: []byte("/usr/bin/foo\n")}},
				[][]string{{"rpm", "-q", "--queryformat", "%{NAME} %{VERSION}\\n", "foo"}, {"rpm", "-ql", "foo"}},
				func(v any) bool {
					return reflect.DeepEqual(v, map[string]any{"errors": []string{}, "packages": map[string]any{"foo": []string{"/usr/bin/foo"}}})
				}},
			{"pkg.info_installed", reflect.TypeOf(InfoArgs{}), []string{"failhard", "names"},
				&YumInfoInstalledArgs{Names: []string{"foo"}},
				[]process.CommandResult{{Stdout: []byte("Package\n")}, {Stdout: []byte("name: foo\nversion: 1\nrelease: 0\nedition: 1-0\n-----\n")}},
				[][]string{{"rpm", "--querytags"}, {"rpm", "-q", "foo", "--queryformat", "name: %{NAME}\\n" + "edition: %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n"}},
				func(v any) bool { m, ok := v.(map[string]any); return ok && m["foo"] != nil }},
			{"pkg.owner", reflect.TypeOf(OwnerArgs{}), []string{"paths"},
				&YumOwnerArgs{Paths: []string{"/usr/bin/foo"}},
				[]process.CommandResult{{Stdout: []byte("foo")}},
				[][]string{{"rpm", "-qf", "--queryformat", "%{name}", "/usr/bin/foo"}},
				func(v any) bool { return v == "foo" }},
		} {
			name := tc.name
			prototype, err := reg.ResolveArgs(rt, name)
			if err != nil {
				t.Fatalf("%s/%s resolve: %v", manager, name, err)
			}
			wantType := tc.wantType
			if manager != "apt" {
				switch name {
				case "pkg.file_list", "pkg.file_dict":
					wantType = reflect.TypeOf(YumFilesArgs{})
				case "pkg.info_installed":
					wantType = reflect.TypeOf(YumInfoInstalledArgs{})
				case "pkg.owner":
					wantType = reflect.TypeOf(YumOwnerArgs{})
				}
			}
			if reflect.TypeOf(prototype) != wantType {
				t.Fatalf("%s/%s prototype=%T want %v", manager, name, prototype, wantType)
			}
			argumentNames, err := config.ArgumentNames(prototype)
			wantNames := tc.wantNames
			if manager != "apt" {
				switch name {
				case "pkg.file_list", "pkg.file_dict":
					wantNames = []string{"packages", "root"}
				case "pkg.info_installed":
					wantNames = []string{"all_versions", "attr", "names", "root"}
				case "pkg.owner":
					wantNames = []string{"paths", "root"}
				}
			}
			if err != nil || !reflect.DeepEqual(argumentNames, wantNames) {
				t.Fatalf("%s/%s argument names=%v err=%v want=%v", manager, name, argumentNames, err, wantNames)
			}

			results := tc.results
			wantArgv := tc.wantArgv
			wantResult := tc.wantResult
			if manager == "apt" {
				switch name {
				case "pkg.file_list", "pkg.file_dict":
					results = []process.CommandResult{{Stdout: []byte("installed\tfoo\n")}, {Stdout: []byte("/usr/bin/foo\n")}}
					wantArgv = [][]string{{"dpkg-query", "-f=${db:Status-Status}\t${binary:Package}\n", "-W", "foo"}, {"dpkg", "-L", "foo"}}
					if name == "pkg.file_list" {
						wantResult = func(v any) bool {
							return reflect.DeepEqual(v, map[string]any{"errors": []string{}, "files": []string{"/usr/bin/foo"}})
						}
					} else {
						wantResult = func(v any) bool {
							return reflect.DeepEqual(v, map[string]any{"errors": []string{}, "packages": map[string]any{"foo": []string{"/usr/bin/foo"}}})
						}
					}
				case "pkg.info_installed":
					results = []process.CommandResult{{Stdout: []byte("package:foo\nversion:1\nstatus:ii \n\n*/~^*\n")}}
					wantArgv = [][]string{{"dpkg-query", "-W", "-f=" + "package:${Package}\nrevision:${binary:Revision}\narchitecture:${Architecture}\nmaintainer:${Maintainer}\nsummary:${Summary}\nsource:${source:Package}\nversion:${Version}\nsection:${Section}\ninstalled_size:${Installed-size}\nsize:${Size}\nMD5:${MD5sum}\nSHA1:${SHA1}\nSHA256:${SHA256}\norigin:${Origin}\nhomepage:${Homepage}\nstatus:${db:Status-Abbrev}\ninstall_date:${db-fsys:Last-Modified}\ndescription:${Description}\n\n*/~^\\*\n", "foo"}}
					wantResult = func(v any) bool { m, ok := v.(map[string]any); return ok && m["foo"] != nil }
				case "pkg.owner":
					results = []process.CommandResult{{Stdout: []byte("foo: /usr/bin/foo\n")}}
					wantArgv = [][]string{{"dpkg", "-S", "/usr/bin/foo"}}
					wantResult = func(v any) bool { return v == "foo" }
				}
			}
			runner := &yumExecRecordingRunner{results: results}
			rt.Runner = runner
			args := tc.args
			if manager == "apt" {
				switch name {
				case "pkg.file_list", "pkg.file_dict":
					args = &FilePackagesArgs{Packages: []string{"foo"}}
				case "pkg.info_installed":
					args = &InfoArgs{Names: []string{"foo"}}
				case "pkg.owner":
					args = &OwnerArgs{Paths: []string{"/usr/bin/foo"}}
				}
			}
			got, err := reg.Call(context.Background(), rt, name, args)
			argv := commandArgv(runner.commands)
			argvOK := reflect.DeepEqual(argv, wantArgv)
			if manager != "apt" && name == "pkg.info_installed" {
				argvOK = len(argv) == 2 && reflect.DeepEqual(argv[0], []string{"rpm", "--querytags"}) &&
					len(argv[1]) == 5 && argv[1][0] == "rpm" && argv[1][1] == "-q" && argv[1][2] == "foo" && argv[1][3] == "--queryformat" &&
					strings.HasPrefix(argv[1][4], "name: %{NAME}\\n") && strings.HasSuffix(argv[1][4], "description:\\n%{DESCRIPTION}\\n-----\\n")
			}
			if err != nil || !wantResult(got) || !argvOK {
				t.Fatalf("%s/%s result=%#v err=%v argv=%#v want=%#v", manager, name, got, err, commandArgv(runner.commands), wantArgv)
			}

			badRunner := &yumExecRecordingRunner{}
			rt.Runner = badRunner
			if got, err := reg.Call(context.Background(), rt, name, &AutoremoveArgs{}); got != nil || err == nil || err.Error() != name+": expected arguments of type *"+wantType.String()+", got *pkg.AutoremoveArgs" {
				t.Fatalf("%s/%s wrong prototype got=%#v err=%v", manager, name, got, err)
			}
			if len(badRunner.commands) != 0 {
				t.Fatalf("%s/%s wrong prototype runner calls=%d", manager, name, len(badRunner.commands))
			}
		}
	}
}

type yumExecRecordingRunner struct {
	commands []process.Command
	results  []process.CommandResult
}

func (r *yumExecRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func commandArgv(commands []process.Command) [][]string {
	argv := make([][]string, 0, len(commands))
	for _, command := range commands {
		argv = append(argv, append([]string{command.Name}, command.Args...))
	}
	return argv
}
