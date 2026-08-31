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

func TestYumGroupListRegistryProviderMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte("Installed Groups:\nCore\nDone\n")}}}
		rt := &runtime.Runtime{
			Facts:     facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}}),
			Providers: providers, Runner: runner,
		}
		prototype, err := reg.ResolveArgs(rt, "pkg.group_list")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(struct{}{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || len(names) != 0 {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		if caps := reg.ProviderCapabilities("pkg.group_list"); !reflect.DeepEqual(caps, []string{"yumpkg"}) {
			t.Fatalf("%s capabilities=%v", manager, caps)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.group_list", &struct{}{})
		want := map[string]any{
			"installed": []string{"Core"}, "available": []string{},
			"installed environments": []string{}, "available environments": []string{},
			"available languages": map[string]any{},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s got=%#v err=%v", manager, got, err)
		}
		if argv := commandArgv(runner.commands); !reflect.DeepEqual(argv, [][]string{{manager, "grouplist", "hidden"}}) || runner.commands[0].Shell {
			t.Fatalf("%s argv=%#v commands=%#v", manager, argv, runner.commands)
		}
	}

	for _, manager := range []string{"apt", "zypper", "unsupported"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		if _, err := reg.ResolveArgs(rt, "pkg.group_list"); err == nil {
			t.Fatalf("%s unexpectedly resolved", manager)
		}
		if got, err := reg.Call(context.Background(), rt, "pkg.group_list", &struct{}{}); got != nil || err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s got=%#v err=%v commands=%d", manager, got, err, len(runner.commands))
		}
	}
}

func TestYumLongtailRegistryAndPureCalls(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
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

func TestYumUpgradeFunctionsRegistryMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		r := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte("foo.x86_64 2:2.0-1 @repo\n")}}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Providers: providers, Runner: r}
		for _, tc := range []struct {
			name string
			arg  any
			want reflect.Type
		}{
			{"pkg.list_upgrades", &YumListUpgradesArgs{}, reflect.TypeOf(YumListUpgradesArgs{})},
			{"pkg.upgrade_available", &YumUpgradeAvailableArgs{Name: "foo"}, reflect.TypeOf(YumUpgradeAvailableArgs{})},
		} {
			prototype, err := reg.ResolveArgs(rt, tc.name)
			if err != nil || reflect.TypeOf(prototype) != tc.want {
				t.Fatalf("%s prototype=%T err=%v", tc.name, prototype, err)
			}
			if caps := reg.ProviderCapabilities(tc.name); !reflect.DeepEqual(caps, []string{"aptpkg", "yumpkg"}) {
				t.Fatalf("%s capabilities=%v", tc.name, caps)
			}
			if tc.name == "pkg.list_upgrades" {
				refresh := false
				r.results = []process.CommandResult{{Stdout: []byte("foo.x86_64 2:2.0-1 @repo\n")}}
				got, err := reg.Call(context.Background(), rt, tc.name, &YumListUpgradesArgs{Refresh: &refresh})
				if err != nil || !reflect.DeepEqual(got, map[string]string{"foo": "2:2.0-1"}) {
					t.Fatalf("%s got=%#v err=%v", tc.name, got, err)
				}
			} else {
				refresh := false
				r.results = []process.CommandResult{{Stdout: []byte("foo_|-0_|-1.0_|-1_|-x86_64_|-(none)_|-0\n")}, {Stdout: []byte("foo.x86_64 2.0-1 @repo\n")}}
				got, err := reg.Call(context.Background(), rt, tc.name, &YumUpgradeAvailableArgs{Name: "foo", Refresh: &refresh})
				if err != nil || got != true {
					t.Fatalf("%s got=%#v err=%v", tc.name, got, err)
				}
			}
		}
	}
}

func TestYumUpgradeFunctionsRejectNonYumProvidersBeforeRunner(t *testing.T) {
	for _, manager := range []string{"zypper", "unsupported"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{
			Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner,
		}
		for _, tc := range []struct {
			name string
			args any
		}{
			{"pkg.list_upgrades", &YumListUpgradesArgs{}},
			{"pkg.upgrade_available", &YumUpgradeAvailableArgs{Name: "foo"}},
		} {
			if _, err := reg.ResolveArgs(rt, tc.name); err == nil {
				t.Fatalf("%s/%s unexpectedly resolved", manager, tc.name)
			}
			if got, err := reg.Call(context.Background(), rt, tc.name, tc.args); got != nil || err == nil {
				t.Fatalf("%s/%s got=%#v err=%v", manager, tc.name, got, err)
			}
		}
		if len(runner.commands) != 0 {
			t.Fatalf("%s runner calls=%d", manager, len(runner.commands))
		}
	}
}

func TestLongtailResolveArgsProviderMatrix(t *testing.T) {
	for _, manager := range []string{"apt", "yum", "dnf", "dnf5"} {
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

func TestYumGroupInfoRegistryProviderMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		fromrepo := "base"
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte("Group: Demo\nGroup-Id: demo.id\nDescription: desc\nMandatory Packages:\n z\n")}}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}}), Providers: providers, Runner: runner}
		prototype, err := reg.ResolveArgs(rt, "pkg.group_info")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumGroupInfoArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		names, err := config.ArgumentNames(prototype)
		if err != nil || !reflect.DeepEqual(names, []string{"disablerepo", "enablerepo", "expand", "fromrepo", "ignore_groups", "name"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		if caps := reg.ProviderCapabilities("pkg.group_info"); !reflect.DeepEqual(caps, []string{"yumpkg"}) {
			t.Fatalf("%s capabilities=%v", manager, caps)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.group_info", &YumGroupInfoArgs{Name: "Demo", Fromrepo: &fromrepo})
		want := map[string]any{"type": "package group", "group": "Demo", "id": "demo.id", "description": "desc", "mandatory": []string{"z"}, "optional": []string{}, "default": []string{}, "conditional": []string{}}
		if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(commandArgv(runner.commands), [][]string{{manager, "--quiet", "--disablerepo=*", "--enablerepo=base", "groupinfo", "Demo"}}) {
			t.Fatalf("%s got=%#v err=%v argv=%#v", manager, got, err, commandArgv(runner.commands))
		}
		bad := &yumExecNoCallRunner{}
		rt.Runner = bad
		if got, err := reg.Call(context.Background(), rt, "pkg.group_info", &AutoremoveArgs{}); got != nil || err == nil || bad.calls != 0 {
			t.Fatalf("%s wrong args got=%#v err=%v calls=%d", manager, got, err, bad.calls)
		}
	}
	for _, manager := range []string{"apt", "zypper", "unsupported"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecNoCallRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: runtime.NewProviderRegistry(), Runner: runner}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.ResolveArgs(rt, "pkg.group_info"); err == nil {
			t.Fatalf("%s unexpectedly resolved", manager)
		}
		if got, err := reg.Call(context.Background(), rt, "pkg.group_info", &YumGroupInfoArgs{Name: "x"}); got != nil || err == nil || runner.calls != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", manager, got, err, runner.calls)
		}
	}
}

func TestYumGroupDiffRegistryProviderMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{results: []process.CommandResult{
			{Stdout: []byte("alpha 1\ngamma 1\n")},
			{Stdout: []byte("Group: Demo\nMandatory Packages:\n zeta\n alpha\nDefault Packages:\n gamma\n")},
		}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		prototype, err := reg.ResolveArgs(rt, "pkg.group_diff")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumGroupDiffArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"disablerepo", "enablerepo", "fromrepo", "name"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		if caps := reg.ProviderCapabilities("pkg.group_diff"); !reflect.DeepEqual(caps, []string{"yumpkg"}) {
			t.Fatalf("%s capabilities=%v", manager, caps)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.group_diff", &YumGroupDiffArgs{Name: "Demo"})
		want := map[string]any{
			"mandatory":   map[string]any{"installed": []string{"alpha"}, "not installed": []string{"zeta"}},
			"optional":    map[string]any{"installed": []string{}, "not installed": []string{}},
			"default":     map[string]any{"installed": []string{"gamma"}, "not installed": []string{}},
			"conditional": map[string]any{"installed": []string{}, "not installed": []string{}},
		}
		if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(commandArgv(runner.commands), [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {manager, "--quiet", "groupinfo", "Demo"}}) {
			t.Fatalf("%s got=%#v err=%v argv=%#v", manager, got, err, commandArgv(runner.commands))
		}
		bad := &yumExecNoCallRunner{}
		rt.Runner = bad
		if got, err := reg.Call(context.Background(), rt, "pkg.group_diff", &YumGroupInfoArgs{}); got != nil || err == nil || bad.calls != 0 {
			t.Fatalf("%s wrong pointer got=%#v err=%v calls=%d", manager, got, err, bad.calls)
		}
	}
	for _, manager := range []string{"apt", "zypper"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecNoCallRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Runner: runner, Providers: runtime.NewProviderRegistry()}
		if err := pkgprovider.Register(rt.Providers); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.ResolveArgs(rt, "pkg.group_diff"); err == nil {
			t.Fatalf("%s unexpectedly resolved", manager)
		}
		if got, err := reg.Call(context.Background(), rt, "pkg.group_diff", &YumGroupDiffArgs{Name: "Demo"}); got != nil || err == nil || runner.calls != 0 {
			t.Fatalf("%s got=%#v err=%v calls=%d", manager, got, err, runner.calls)
		}
	}
}

func TestCleanMetadataProviderAwareRegistry(t *testing.T) {
	for _, manager := range []string{"yum", "dnf"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{ExitCode: 0}, {ExitCode: 100}}}
		rt := &runtime.Runtime{
			Facts:     facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}}),
			Providers: providers, Runner: runner,
		}
		prototype, err := reg.ResolveArgs(rt, "pkg.clean_metadata")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumCleanMetadataArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if got, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(got, []string{"branch", "check_update", "disableexcludes", "disablerepo", "enablerepo", "fromrepo", "repo", "setopt"}) {
			t.Fatalf("%s args=%v err=%v", manager, got, err)
		}
		if got := reg.ProviderCapabilities("pkg.clean_metadata"); !reflect.DeepEqual(got, []string{"yumpkg"}) {
			t.Fatalf("%s capabilities=%v", manager, got)
		}
		fromrepo := "base"
		got, err := reg.Call(context.Background(), rt, "pkg.clean_metadata", &YumCleanMetadataArgs{Fromrepo: &fromrepo, Enablerepo: []string{"ignored"}})
		if err != nil || got != true {
			t.Fatalf("%s got=%#v err=%v", manager, got, err)
		}
		want := [][]string{{manager, "--quiet", "--assumeyes", "clean", "expire-cache", "--disablerepo=*", "--enablerepo=base"}, {manager, "--quiet", "--assumeyes", "check-update", "--disablerepo=*", "--enablerepo=base"}}
		if got := commandArgv(runner.commands); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv=%v want=%v", manager, got, want)
		}
	}

	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	runner := &yumExecRecordingRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "apt"}), Providers: providers, Runner: runner}
	if _, err := reg.ResolveArgs(rt, "pkg.clean_metadata"); err == nil || len(runner.commands) != 0 {
		t.Fatalf("apt resolve err=%v calls=%d", err, len(runner.commands))
	}
}

func TestServicesNeedRestartProviderAwareRegistryMapsEveryPIDToken(t *testing.T) {
	for _, manager := range []string{"dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{results: []process.CommandResult{
			{Stdout: []byte("123: one\n0: zero\nnot-a-pid: text\n: empty\nno delimiter\n")},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"sshd.service"}`)},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"cron.service"}`)},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"sshd.service"}`)},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"not-a-service"}`)},
		}}
		rt := &runtime.Runtime{
			Facts:     facts.ForTesting(facts.Overrides{Package: manager, Init: "systemd", OS: &facts.OSFacts{Family: facts.FamilyRedHat}}),
			Providers: providers,
			Runner:    runner,
		}
		prototype, err := reg.ResolveArgs(rt, "pkg.services_need_restart")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(struct{}{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || len(names) != 0 {
			t.Fatalf("%s argument names=%v err=%v", manager, names, err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.services_need_restart", &struct{}{})
		if err != nil || !reflect.DeepEqual(got, []string{"cron", "sshd"}) {
			t.Fatalf("%s got=%#v err=%v", manager, got, err)
		}
		want := [][]string{
			{manager, "--quiet", "needs-restarting"},
			{"systemctl", "--output", "json", "status", "123"},
			{"systemctl", "--output", "json", "status", "0"},
			{"systemctl", "--output", "json", "status", "not-a-pid"},
			{"systemctl", "--output", "json", "status", ""},
		}
		if !reflect.DeepEqual(commandArgv(runner.commands), want) {
			t.Fatalf("%s argv=%#v want=%#v", manager, commandArgv(runner.commands), want)
		}
		for _, command := range runner.commands {
			if command.Shell {
				t.Fatalf("%s used shell command=%#v", manager, command)
			}
		}
	}
}

func TestServicesNeedRestartRegistryRejectsUnsupportedProvidersBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"yum", "zypper"} {
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		if manager != "yum" {
			if _, err := reg.ResolveArgs(rt, "pkg.services_need_restart"); err == nil {
				t.Fatalf("%s unexpectedly resolved", manager)
			}
		}
		if _, err := reg.Call(context.Background(), rt, "pkg.services_need_restart", &struct{}{}); err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s call err=%v commands=%d", manager, err, len(runner.commands))
		}
	}
	for _, manager := range []string{"dnf", "dnf5"} {
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager, Init: "openrc", OS: &facts.OSFacts{Family: facts.FamilyRedHat}}), Providers: providers, Runner: runner}
		if _, err := reg.Call(context.Background(), rt, "pkg.services_need_restart", &struct{}{}); err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s non-systemd err=%v commands=%d", manager, err, len(runner.commands))
		}
	}
}

func TestServicesNeedRestartRegistryPropagatesCancelAndRunnerError(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, wantErr := range []error{context.Canceled, errors.New("runner failed")} {
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Err: wantErr}}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "dnf", Init: "systemd", OS: &facts.OSFacts{Family: facts.FamilyRedHat}}), Providers: providers, Runner: runner}
		ctx := context.Background()
		if wantErr == context.Canceled {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		got, err := reg.Call(ctx, rt, "pkg.services_need_restart", &struct{}{})
		if got != nil || !errors.Is(err, wantErr) || len(runner.commands) != 1 {
			t.Fatalf("want=%v got=%#v err=%v commands=%d", wantErr, got, err, len(runner.commands))
		}
	}
}

func TestCleanMetadataRegistryRejectsNULBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	runner := &yumExecNoCallRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum", OS: &facts.OSFacts{Family: facts.FamilyRedHat}}), Providers: providers, Runner: runner}
	for _, args := range []any{
		&YumCleanMetadataArgs{Enablerepo: "bad\x00repo"},
		&YumCleanMetadataArgs{Setopt: []any{"ok=1", "bad\nvalue"}},
	} {
		if _, err := reg.Call(context.Background(), rt, "pkg.clean_metadata", args); err == nil || runner.calls != 0 {
			t.Fatalf("args=%#v err=%v calls=%d", args, err, runner.calls)
		}
	}
}

func TestListHoldsProviderAwareRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if got := reg.ProviderCapabilities("pkg.list_holds"); !reflect.DeepEqual(got, []string{"yumpkg"}) {
		t.Fatalf("capabilities=%v", got)
	}
	for _, manager := range []string{"yum", "dnf"} {
		plugin := "yum-plugin-versionlock"
		if manager == "dnf" {
			plugin = "python2-dnf-plugin-versionlock"
		}
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte("\n")}}}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		prototype, err := reg.ResolveArgs(rt, "pkg.list_holds")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumListHoldsArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"full", "pattern"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		full := false
		pattern := "foo"
		got, err := reg.Call(context.Background(), rt, "pkg.list_holds", &YumListHoldsArgs{Pattern: &pattern, Full: &full})
		if err != nil || !reflect.DeepEqual(got, []string{}) || len(runner.commands) != 2 {
			t.Fatalf("%s call got=%#v err=%v commands=%d", manager, got, err, len(runner.commands))
		}
		if got := commandArgv(runner.commands); !reflect.DeepEqual(got, [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {manager, "versionlock", "list"}}) {
			t.Fatalf("%s argv=%#v", manager, got)
		}
	}
	for _, manager := range []string{"apt", "zypper"} {
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		if _, err := reg.ResolveArgs(rt, "pkg.list_holds"); err == nil {
			t.Fatalf("%s unexpectedly resolved list_holds", manager)
		}
		if _, err := reg.Call(context.Background(), rt, "pkg.list_holds", &YumListHoldsArgs{}); err == nil || len(runner.commands) != 0 {
			t.Fatalf("%s call err=%v commands=%d", manager, err, len(runner.commands))
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

func TestListPatchesProviderAwareRegistry(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"yum", "dnf"} {
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte("\ni RHSA-1 Important foo-1\n  RHSA-1 Important bar-2\ni RHSA-2 Moderate baz-3\nmalformed\n")}}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		for _, name := range []string{"pkg.list_patches", "pkg.list_installed_patches"} {
			runner.results = []process.CommandResult{{Stdout: []byte("\ni RHSA-1 Important foo-1\n  RHSA-1 Important bar-2\ni RHSA-2 Moderate baz-3\nmalformed\n")}}
			prototype, err := reg.ResolveArgs(rt, name)
			wantPrototype := reflect.TypeOf(YumListPatchesArgs{})
			wantNames := []string{"refresh"}
			if name == "pkg.list_installed_patches" {
				wantPrototype = reflect.TypeOf(YumListInstalledPatchesArgs{})
				wantNames = []string{}
			}
			if err != nil || reflect.TypeOf(prototype) != wantPrototype {
				t.Fatalf("%s/%s prototype=%T err=%v", manager, name, prototype, err)
			}
			if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, wantNames) {
				t.Fatalf("%s/%s names=%v err=%v", manager, name, names, err)
			}
			if got := reg.ProviderCapabilities(name); !reflect.DeepEqual(got, []string{"yumpkg"}) {
				t.Fatalf("%s/%s capabilities=%v", manager, name, got)
			}
			var args any = &YumListPatchesArgs{Refresh: func() *bool { v := false; return &v }()}
			if name == "pkg.list_installed_patches" {
				args = &YumListInstalledPatchesArgs{}
			}
			got, err := reg.Call(context.Background(), rt, name, args)
			want := map[string]any{"RHSA-1": map[string]any{"installed": false, "summary": []string{"foo-1", "bar-2"}}, "RHSA-2": map[string]any{"installed": true, "summary": []string{"baz-3"}}}
			if name == "pkg.list_installed_patches" {
				want = map[string]any{"RHSA-2": map[string]any{"installed": true, "summary": []string{"baz-3"}}}
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s/%s got=%#v err=%v", manager, name, got, err)
			}
			if got := commandArgv(runner.commands); len(got) != 1 || !reflect.DeepEqual(got[0], []string{manager, "--quiet", "updateinfo", "list", "all"}) {
				t.Fatalf("%s/%s argv=%#v", manager, name, got)
			}
			runner.commands = nil
		}
	}
	for _, manager := range []string{"apt", "zypper"} {
		runner := &yumExecRecordingRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		for _, name := range []string{"pkg.list_patches", "pkg.list_installed_patches"} {
			if _, err := reg.ResolveArgs(rt, name); err == nil {
				t.Fatalf("%s unexpectedly resolved %s", manager, name)
			}
			if _, err := reg.Call(context.Background(), rt, name, &YumListPatchesArgs{}); err == nil || len(runner.commands) != 0 {
				t.Fatalf("%s call %s err=%v commands=%d", manager, name, err, len(runner.commands))
			}
		}
	}
}

func TestListPatchesRefreshAndInstalledFiltering(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	refresh := true
	runner := &yumExecRecordingRunner{results: []process.CommandResult{{ExitCode: 7}, {ExitCode: 100}, {Stdout: []byte("i RHSA-1 Important foo\n  RHSA-1 Important bar\ni RHSA-2 Moderate baz\n")}}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: runner}
	got, err := reg.Call(context.Background(), rt, "pkg.list_patches", &YumListPatchesArgs{Refresh: &refresh})
	if err != nil || got == nil {
		t.Fatalf("refresh got=%#v err=%v", got, err)
	}
	if want := [][]string{{"yum", "--quiet", "--assumeyes", "clean", "expire-cache"}, {"yum", "--quiet", "--assumeyes", "check-update"}, {"yum", "--quiet", "updateinfo", "list", "all"}}; !reflect.DeepEqual(commandArgv(runner.commands), want) {
		t.Fatalf("argv=%#v", commandArgv(runner.commands))
	}
	runner = &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte(" RHSA-1 Important foo\ni RHSA-2 Moderate bar\n")}}}
	rt.Runner = runner
	got, err = reg.Call(context.Background(), rt, "pkg.list_installed_patches", &YumListInstalledPatchesArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"RHSA-2": map[string]any{"installed": true, "summary": []string{"bar"}}}) {
		t.Fatalf("installed got=%#v err=%v", got, err)
	}
}

func TestListInstalledPatchesRefreshUsesSharedContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"yum", "dnf"} {
		runner := &yumExecRecordingRunner{results: []process.CommandResult{{Stdout: []byte("i RHSA-1 Important foo\n")}}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: runner}
		prototype, err := reg.ResolveArgs(rt, "pkg.list_installed_patches")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumListInstalledPatchesArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.list_installed_patches", &YumListInstalledPatchesArgs{})
		want := map[string]any{"RHSA-1": map[string]any{"installed": true, "summary": []string{"foo"}}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s got=%#v err=%v", manager, got, err)
		}
		wantArgv := [][]string{{manager, "--quiet", "updateinfo", "list", "all"}}
		if !reflect.DeepEqual(commandArgv(runner.commands), wantArgv) {
			t.Fatalf("%s argv=%#v want=%#v", manager, commandArgv(runner.commands), wantArgv)
		}
	}
}

func TestListPatchesPropagatesRunnerFailuresAndRejectsOptions(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, result := range []process.CommandResult{{Err: errors.New("runner failed")}, {Err: context.Canceled}, {ExitCode: 1, Stderr: []byte("failed")}} {
		runner := &yumExecRecordingRunner{results: []process.CommandResult{result}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: runner}
		got, err := reg.Call(context.Background(), rt, "pkg.list_patches", &YumListPatchesArgs{})
		if result.ExitCode == 1 {
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 1 {
				t.Fatalf("nonzero empty got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		} else if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
		}
	}
	runner := &yumExecRecordingRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: runner}
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		t.Fatal(err)
	}
	yp := p.(pkgprovider.YumProvider)
	if _, err := yp.Yum(context.Background(), rt, "list_patches", map[string]any{"other": true}); err == nil || len(runner.commands) != 0 {
		t.Fatalf("unsupported option err=%v calls=%d", err, len(runner.commands))
	}
}

func TestListPatchesNonzeroParseableStdoutAndInstalledRejectsRefresh(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	runner := &yumExecRecordingRunner{results: []process.CommandResult{{ExitCode: 100, Stdout: []byte("i RHSA-1 Important foo\n")}}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: runner}
	got, err := reg.Call(context.Background(), rt, "pkg.list_patches", &YumListPatchesArgs{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"RHSA-1": map[string]any{"installed": true, "summary": []string{"foo"}}}) {
		t.Fatalf("nonzero stdout got=%#v err=%v", got, err)
	}
	runner.commands = nil
	refresh := true
	if got, err := reg.Call(context.Background(), rt, "pkg.list_installed_patches", &YumListInstalledPatchesArgs{}); err != nil || got == nil {
		t.Fatalf("installed call got=%#v err=%v", got, err)
	}
	if _, err := pkgprovider.Resolve(rt); err != nil {
		t.Fatal(err)
	}
	provider, _ := pkgprovider.Resolve(rt)
	if _, err := provider.(pkgprovider.YumProvider).Yum(context.Background(), rt, "list_installed_patches", map[string]any{"refresh": &refresh}); err == nil || len(runner.commands) != 1 {
		t.Fatalf("installed refresh accepted err=%v calls=%d", err, len(runner.commands))
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &yumExecRecordingRunner{}
	rt.Runner = runner
	if got, err := reg.Call(canceled, rt, "pkg.list_patches", &YumListPatchesArgs{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 1 {
		t.Fatalf("canceled got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}
