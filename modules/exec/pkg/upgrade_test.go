package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

type registryUpgradeRunner struct {
	commands []process.Command
	results  []process.CommandResult
}

const registryYumInstalledQueryFormat = "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-(none)_|-%{INSTALLTIME}\n"

func (r *registryUpgradeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func registryUpgradeRecord(name, epoch, version, release, arch string) string {
	return fmt.Sprintf("%s_|-%s_|-%s_|-%s_|-%s_|-(none)_|-0\n", name, epoch, version, release, arch)
}

func registryUpgradeArgv(commands []process.Command) [][]string {
	argv := make([][]string, 0, len(commands))
	for _, command := range commands {
		argv = append(argv, append([]string{command.Name}, command.Args...))
	}
	return argv
}

func registryUpgradeRuntime(t *testing.T, manager string, runner process.Runner) (*runtime.Runtime, *runtime.ExecRegistry) {
	t.Helper()
	registry := runtime.NewExecRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	family := facts.FamilyRedHat
	if manager == "apt" {
		family = facts.FamilyDebian
	}
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{
			Package: manager,
			OS:      &facts.OSFacts{Family: family},
			CPU:     &facts.CPUFacts{Arch: "x86_64"},
		}),
		Providers: providers,
		Runner:    runner,
	}, registry
}

func boolPointer(v bool) *bool { return &v }

func TestUpgradeRegistryProviderMatrix(t *testing.T) {
	yumArgs := []string{"branch", "check_update", "diff_attr", "disableexcludes", "disablerepo", "enablerepo", "fromrepo", "kwargs", "minimal", "name", "normalize", "obsoletes", "pkgs", "refresh", "repo", "setopt", "skip_verify"}
	for _, manager := range []string{"apt", "yum", "dnf", "dnf5"} {
		t.Run(manager+"/upgrade", func(t *testing.T) {
			refresh := false
			runner := &registryUpgradeRunner{}
			rt, registry := registryUpgradeRuntime(t, manager, runner)
			prototype, err := registry.ResolveArgs(rt, "pkg.upgrade")
			if err != nil {
				t.Fatal(err)
			}
			if manager == "apt" {
				if reflect.TypeOf(prototype) != reflect.TypeOf(UpgradeArgs{}) {
					t.Fatalf("prototype=%T", prototype)
				}
				if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"allow_downgrades", "cache_valid_time", "dist_upgrade", "download_only", "downloadonly", "force_conf_new", "force_yes", "refresh", "skip_verify"}) {
					t.Fatalf("argument names=%v err=%v", names, err)
				}
				runner.results = []process.CommandResult{{Stdout: []byte("foo 1\n")}, {}, {Stdout: []byte("foo 2\n")}}
				got, err := registry.Call(context.Background(), rt, "pkg.upgrade", &UpgradeArgs{Refresh: &refresh})
				want := map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}
				wantArgv := [][]string{{"dpkg-query", "-W", "-f=${Package} ${Version}\\n"}, {"apt-get", "-q", "-y", "-o", "DPkg::Options::=--force-confold", "-o", "DPkg::Options::=--force-confdef", "upgrade"}, {"dpkg-query", "-W", "-f=${Package} ${Version}\\n"}}
				if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(registryUpgradeArgv(runner.commands), wantArgv) {
					t.Fatalf("got=%#v err=%v argv=%#v", got, err, registryUpgradeArgv(runner.commands))
				}
			} else {
				if reflect.TypeOf(prototype) != reflect.TypeOf(YumUpgradeArgs{}) {
					t.Fatalf("prototype=%T", prototype)
				}
				if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, yumArgs) {
					t.Fatalf("argument names=%v err=%v", names, err)
				}
				runner.results = []process.CommandResult{{Stdout: []byte(registryUpgradeRecord("foo", "0", "1", "", "x86_64"))}, {}, {Stdout: []byte(registryUpgradeRecord("foo", "0", "2", "", "x86_64"))}}
				got, err := registry.Call(context.Background(), rt, "pkg.upgrade", &YumUpgradeArgs{Refresh: &refresh})
				want := map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}
				wantArgv := [][]string{{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat}, {manager, "--quiet", "-y", "upgrade"}, {"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat}}
				if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(registryUpgradeArgv(runner.commands), wantArgv) {
					t.Fatalf("got=%#v err=%v argv=%#v", got, err, registryUpgradeArgv(runner.commands))
				}
			}
			if capabilities := registry.ProviderCapabilities("pkg.upgrade"); !reflect.DeepEqual(capabilities, []string{"aptpkg", "yumpkg"}) {
				t.Fatalf("capabilities=%v", capabilities)
			}
			bad := &registryUpgradeRunner{}
			rt.Runner = bad
			wrong := any(&YumUpgradeArgs{})
			if manager != "apt" {
				wrong = &UpgradeArgs{}
			}
			if got, err := registry.Call(context.Background(), rt, "pkg.upgrade", wrong); got != nil || err == nil || len(bad.commands) != 0 {
				t.Fatalf("wrong pointer got=%#v err=%v commands=%d", got, err, len(bad.commands))
			}
		})
	}
}

func TestAPTUpgradeRegistryFailsClosedWithoutRunner(t *testing.T) {
	var typedNil *registryUpgradeRunner
	for _, tc := range []struct {
		name   string
		runner process.Runner
	}{
		{"nil runner", nil},
		{"typed nil runner", typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, registry := registryUpgradeRuntime(t, "apt", tc.runner)
			got, err := registry.Call(context.Background(), rt, "pkg.upgrade", &UpgradeArgs{Refresh: boolPointer(false)})
			if got != nil || err == nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
}

func TestAPTUpgradeDirectFailsClosedWithoutRunner(t *testing.T) {
	var typedNil *aptFakeRunner
	for _, tc := range []struct {
		name   string
		runner process.Runner
	}{
		{"nil runner", nil},
		{"typed nil runner", typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &aptFakeRunner{}
			rt := aptExecRuntime("apt", runner)
			rt.Runner = tc.runner
			got, err := (aptLongtailFunc{"upgrade", UpgradeArgs{}}).Execute(context.Background(), rt, &UpgradeArgs{Refresh: boolPointer(false)})
			if got != nil || err == nil || len(runner.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
			}
		})
	}
}

func TestUpdateRegistryYumOnlyProviderMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			refresh := false
			runner := &registryUpgradeRunner{results: []process.CommandResult{{Stdout: []byte(registryUpgradeRecord("foo", "0", "1", "", "x86_64"))}, {}, {Stdout: []byte(registryUpgradeRecord("foo", "0", "2", "", "x86_64"))}}}
			rt, registry := registryUpgradeRuntime(t, manager, runner)
			prototype, err := registry.ResolveArgs(rt, "pkg.update")
			if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(YumUpgradeArgs{}) {
				t.Fatalf("prototype=%T err=%v", prototype, err)
			}
			if capabilities := registry.ProviderCapabilities("pkg.update"); !reflect.DeepEqual(capabilities, []string{"yumpkg"}) {
				t.Fatalf("capabilities=%v", capabilities)
			}
			got, err := registry.Call(context.Background(), rt, "pkg.update", &YumUpgradeArgs{Refresh: &refresh})
			want := map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}
			transaction := []string{manager, "--quiet", "-y"}
			if manager != "yum" {
				transaction = append(transaction, "--setopt=obsoletes=False")
			}
			transaction = append(transaction, "update")
			if manager != "yum" {
				transaction[len(transaction)-1] = "upgrade"
			}
			wantArgv := [][]string{{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat}, transaction, {"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(registryUpgradeArgv(runner.commands), wantArgv) {
				t.Fatalf("got=%#v err=%v argv=%#v", got, err, registryUpgradeArgv(runner.commands))
			}
			bad := &registryUpgradeRunner{}
			rt.Runner = bad
			if got, err := registry.Call(context.Background(), rt, "pkg.update", &UpgradeArgs{}); got != nil || err == nil || len(bad.commands) != 0 {
				t.Fatalf("wrong pointer got=%#v err=%v commands=%d", got, err, len(bad.commands))
			}
		})
	}

	for _, manager := range []string{"zypper"} {
		t.Run(manager+"/unsupported", func(t *testing.T) {
			runner := &registryUpgradeRunner{}
			rt, registry := registryUpgradeRuntime(t, manager, runner)
			for _, name := range []string{"pkg.update", "pkg.upgrade"} {
				if _, err := registry.ResolveArgs(rt, name); !errors.As(err, new(*runtime.UnsupportedError)) {
					t.Fatalf("%s resolve err=%v", name, err)
				}
				if got, err := registry.Call(context.Background(), rt, name, &YumUpgradeArgs{}); got != nil || !errors.As(err, new(*runtime.UnsupportedError)) || len(runner.commands) != 0 {
					t.Fatalf("%s got=%#v err=%v commands=%d", name, got, err, len(runner.commands))
				}
			}
		})
	}
	{
		runner := &registryUpgradeRunner{}
		rt, registry := registryUpgradeRuntime(t, "apt", runner)
		if _, err := registry.ResolveArgs(rt, "pkg.update"); !errors.As(err, new(*runtime.UnsupportedError)) {
			t.Fatalf("apt update resolve err=%v", err)
		}
		if got, err := registry.Call(context.Background(), rt, "pkg.update", &YumUpgradeArgs{}); got != nil || !errors.As(err, new(*runtime.UnsupportedError)) || len(runner.commands) != 0 {
			t.Fatalf("apt update got=%#v err=%v commands=%d", got, err, len(runner.commands))
		}
	}
}

func TestYumUpgradePointerOmissionAndExplicitFalsePreserved(t *testing.T) {
	omitted, err := mapArgs("pkg.upgrade", &YumUpgradeArgs{}, YumUpgradeArgs{})
	if err != nil || len(omitted) != 0 {
		t.Fatalf("omitted=%#v err=%v", omitted, err)
	}
	falseValue := false
	zeroValue := false
	explicit, err := mapArgs("pkg.upgrade", &YumUpgradeArgs{
		Refresh: &falseValue, CheckUpdate: &falseValue, SkipVerify: &falseValue, Normalize: &falseValue,
		Minimal: &zeroValue, Obsoletes: &zeroValue,
	}, YumUpgradeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"refresh", "check_update", "skip_verify", "normalize", "minimal", "obsoletes"} {
		value, present := explicit[key].(*bool)
		if !present || value == nil || *value {
			t.Fatalf("%s=%#v", key, explicit[key])
		}
	}
}

func TestUpgradeRegistryCheckUpdateRefreshOnly(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, name := range []string{"pkg.upgrade", "pkg.update"} {
			t.Run(manager+"/"+name, func(t *testing.T) {
				refresh, checkUpdate := true, false
				runner := &registryUpgradeRunner{results: []process.CommandResult{
					{},
					{Stdout: []byte(registryUpgradeRecord("foo", "0", "1", "", "x86_64"))},
					{},
					{Stdout: []byte(registryUpgradeRecord("foo", "0", "2", "", "x86_64"))},
				}}
				rt, registry := registryUpgradeRuntime(t, manager, runner)
				args := &YumUpgradeArgs{Refresh: &refresh, CheckUpdate: &checkUpdate}
				got, err := registry.Call(context.Background(), rt, name, args)
				if err != nil || !reflect.DeepEqual(got, map[string]any{"foo": map[string]any{"old": "1", "new": "2"}}) {
					t.Fatalf("got=%#v err=%v", got, err)
				}
				transaction := []string{manager, "--quiet", "-y"}
				if name == "pkg.update" && manager != "yum" {
					transaction = append(transaction, "--setopt=obsoletes=False")
				}
				if name == "pkg.update" && manager == "yum" {
					transaction = append(transaction, "update")
				} else {
					transaction = append(transaction, "upgrade")
				}
				refreshOptions := []string{}
				if name == "pkg.update" && manager != "yum" {
					refreshOptions = []string{"--setopt=obsoletes=False"}
				}
				want := [][]string{
					append([]string{manager, "--quiet", "--assumeyes", "clean", "expire-cache"}, refreshOptions...),
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat},
					transaction,
					{"rpm", "-qa", "--nodigest", "--nosignature", "--queryformat", registryYumInstalledQueryFormat},
				}
				if actual := registryUpgradeArgv(runner.commands); !reflect.DeepEqual(actual, want) {
					t.Fatalf("argv=%#v want=%#v", actual, want)
				}
			})
		}
	}
}

func TestUpgradeRegistryRejectsNilFactsBeforeRunner(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		for _, name := range []string{"pkg.upgrade", "pkg.update"} {
			t.Run(manager+"/"+name, func(t *testing.T) {
				runner := &registryUpgradeRunner{}
				rt, registry := registryUpgradeRuntime(t, manager, runner)
				rt.Facts = nil
				got, err := registry.Call(context.Background(), rt, name, &YumUpgradeArgs{})
				if got != nil || err == nil || len(runner.commands) != 0 {
					t.Fatalf("got=%#v err=%v commands=%d", got, err, len(runner.commands))
				}
			})
		}
	}
}
