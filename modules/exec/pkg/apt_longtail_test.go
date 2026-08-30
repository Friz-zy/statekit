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

type aptFakeRunner struct {
	results []process.CommandResult
	calls   []process.Command
}

func strptr(s string) *string { return &s }

func (r *aptFakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.calls = append(r.calls, cmd)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func aptExecRuntime(manager string, runner *aptFakeRunner) *runtime.Runtime {
	rt := &runtime.Runtime{
		Facts:  facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyDebian}}),
		Runner: runner, FS: runtime.NewMemoryFS(), Providers: runtime.NewProviderRegistry(),
	}
	if err := pkgprovider.Register(rt.Providers); err != nil {
		panic(err)
	}
	return rt
}

func TestLongtailCanonicalPackagesAndDispatch(t *testing.T) {
	runner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: a\nVersion: 1\n\n"), ExitCode: 0}}}
	rt := aptExecRuntime("apt", runner)
	fn := aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}
	got, err := fn.Execute(context.Background(), rt, &FilePackagesArgs{Packages: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls[0].Args, []string{"show", "a", "b"}) || runner.calls[0].Name != "apt-cache" {
		t.Fatalf("argv = %#v", runner.calls[0])
	}
	if got == nil {
		t.Fatal("expected result")
	}
}

func TestLongtailCapabilityGateBeforeRunner(t *testing.T) {
	runner := &aptFakeRunner{}
	rt := aptExecRuntime("dnf", runner)
	fn := aptLongtailFunc{"purge", PackagesArgs{}}
	_, err := fn.Execute(context.Background(), rt, &PackagesArgs{Pkgs: []string{"pkg"}})
	if !errors.Is(err, pkgprovider.ErrUnsupportedAPT) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("non-APT capability constructed a command")
	}
}

func TestLongtailMalformedAndEmptyPackages(t *testing.T) {
	for _, args := range []any{map[string]any{"packages": "not-a-list"}} {
		runner := &aptFakeRunner{}
		rt := aptExecRuntime("apt", runner)
		fn := aptLongtailFunc{"purge", PackagesArgs{}}
		if _, err := fn.Execute(context.Background(), rt, args); err == nil {
			t.Fatal("malformed/empty package input must fail")
		}
		if len(runner.calls) != 0 {
			t.Fatal("invalid input reached Runner")
		}
	}
	r := &aptFakeRunner{}
	if got, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{}); err != nil || !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("empty purge: got=%#v err=%v", got, err)
	}
}

func TestLongtailProviderPreservesRunnerFailures(t *testing.T) {
	for _, result := range []process.CommandResult{
		{ExitCode: 7, Stderr: []byte("apt failed")},
		{ExitCode: -1, Err: context.Canceled},
	} {
		runner := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed safe-name 1\n")}, result}}
		rt := aptExecRuntime("apt", runner)
		fn := aptLongtailFunc{"purge", PackagesArgs{}}
		if _, err := fn.Execute(context.Background(), rt, &PackagesArgs{Pkgs: []string{"safe-name"}}); err == nil {
			t.Fatal("runner failure must be returned")
		} else if len(runner.calls) == 0 {
			t.Fatalf("runner failure before command: %v", err)
		}
		if got, want := runner.calls[1].Name, "apt-get"; got != want || !reflect.DeepEqual(runner.calls[1].Args, []string{"-q", "-y", "purge", "safe-name"}) {
			t.Fatalf("command = %#v", runner.calls[1])
		}
	}
}

func TestLongtailSelectionValidationAndDeterministicInput(t *testing.T) {
	runner := &aptFakeRunner{}
	rt := aptExecRuntime("apt", runner)
	fn := aptLongtailFunc{"set_selections", SetSelectionsArgs{}}
	_, err := fn.Execute(context.Background(), rt, &SetSelectionsArgs{Selection: map[string][]string{
		"hold": {"z"}, "install": {"a"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(runner.calls[1].Stdin), "z hold\n"; got != want {
		t.Fatalf("stdin = %q, want %q", got, want)
	}
	before := len(runner.calls)
	_, err = fn.Execute(context.Background(), rt, &SetSelectionsArgs{Selection: map[string][]string{"hold": {"bad\nname"}}})
	if err == nil || len(runner.calls) != before {
		t.Fatal("control input must be rejected before Runner")
	}
}

// The expected argv and result shapes below are pinned to Salt's aptpkg
// execution contracts (saltstack/salt/modules/aptpkg.py and
// saltstack/salt/tests/unit/modules/test_aptpkg.py @ pinned revision).
// and deliberately use only the fake Runner; no package manager is invoked.
func TestAPTLongtailNamedRunnerContractMatrix(t *testing.T) {
	type matrixCase struct {
		name     string
		positive func(*testing.T)
		negative func(*testing.T)
	}
	boolptr := func(v bool) *bool { return &v }
	cases := []matrixCase{
		{"normalize_name", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 0}, {ExitCode: 1}, {ExitCode: 1}}}
			got, err := (aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "curl:all"})
			if err != nil || got != "curl" || len(r.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 1}, {ExitCode: 1}}}
			_, err := (aptLongtailFunc{"normalize_name", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "bad name"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed normalize_name: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"parse_arch", func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"parse_arch", ParseArchArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ParseArchArgs{Name: "curl:arm64"})
			want := map[string]any{"name": "curl", "arch": "arm64"}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"parse_arch", ParseArchArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ParseArchArgs{Name: "bad\nname"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed parse_arch: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"version_cmp", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 0}}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1.0~rc1", Pkg2: "1.0"})
			if err != nil || got != -1 || len(r.calls) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}, {ExitCode: 1}, {ExitCode: 1}}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "bad version", Pkg2: "1"})
			if err != nil || got != nil || len(r.calls) != 3 {
				t.Fatalf("malformed version_cmp: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"get_selections", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("z hold\na install\na install\n")}}}
			got, err := (aptLongtailFunc{"get_selections", SelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SelectionsArgs{})
			want := map[string][]string{"hold": {"z"}, "install": {"a", "a"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "*"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9}}}
			_, err := (aptLongtailFunc{"get_selections", SelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SelectionsArgs{Pattern: strptr("bad pattern")})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid get_selections: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"set_selections", func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {"z", "a"}, "install": {"b"}}, Clear: boolptr(true)})
			if err != nil || len(r.calls) != 5 || !reflect.DeepEqual(r.calls[2].Stdin, []byte("a hold\n")) || !reflect.DeepEqual(got.(map[string]any)["a"], map[string]any{"old": "", "new": "hold"}) {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {"x\ty"}}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid set_selections: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"hold", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p install\n")}, {}}}
			got, err := (aptLongtailFunc{"hold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Name: strptr("p")})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"p": map[string]any{"name": "p", "changes": map[string]any{"old": "install", "new": "hold"}, "result": true, "comment": "Package p is now being held."}}) || len(r.calls) != 2 || string(r.calls[1].Stdin) != "p hold\n" {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"hold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Pkgs: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid hold: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"unhold", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p hold\n")}}}
			got, err := (aptLongtailFunc{"unhold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{Pkgs: []string{"p"}})
			if err != nil || len(r.calls) != 2 || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "p"}) {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}}}
			_, err := (aptLongtailFunc{"unhold", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PackagesArgs{})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("empty unhold: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"autoremove", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}}}
			got, err := (aptLongtailFunc{"autoremove", AutoremoveArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &AutoremoveArgs{})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || !reflect.DeepEqual(r.calls[1].Args, []string{"--assume-yes", "autoremove"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 2}}}
			_, err := (aptLongtailFunc{"autoremove", AutoremoveArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &AutoremoveArgs{ListOnly: boolptr(true)})
			if err != nil || len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0].Args, []string{"--assume-no", "autoremove"}) {
				t.Fatalf("autoremove failure: err=%v calls=%#v", err, r.calls)
			}
		}},
		{"purge", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed a 1\ninstall ok installed b 1\n")}, {}, {Stdout: []byte("deinstall ok config-files a 1\ndeinstall ok config-files b 1\n")}}}
			got, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{Pkgs: []string{"a", "b"}})
			want := map[string]any{"removed": map[string]any{"a": map[string]any{"old": "", "new": "1"}, "b": map[string]any{"old": "", "new": "1"}}, "installed": map[string]any{"a": map[string]any{"old": "1", "new": ""}, "b": map[string]any{"old": "1", "new": ""}}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "purge", "a", "b"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"purge", PurgeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PurgeArgs{})
			if err != nil || len(r.calls) != 1 {
				t.Fatalf("empty purge: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"upgrade", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{}, {}, {}, {}}}
			got, err := (aptLongtailFunc{"upgrade", UpgradeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &UpgradeArgs{Refresh: boolptr(false), DownloadOnly: boolptr(true), DistUpgrade: boolptr(true)})
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "-o", "DPkg::Options::=--force-confold", "-o", "DPkg::Options::=--force-confdef", "--download-only", "dist-upgrade"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"upgrade", UpgradeArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &UpgradeArgs{Refresh: boolptr(false)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("upgrade failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_upgrades", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Conf z (2.0 Ubuntu:1)\nConf a (1.2 Ubuntu:2)\n")}}}
			got, err := (aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ListUpgradesArgs{Refresh: boolptr(false), DistUpgrade: boolptr(false)})
			want := map[string]string{"z": "2.0", "a": "1.2"}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"--just-print", "upgrade"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 3}}}
			_, err := (aptLongtailFunc{"list_upgrades", ListUpgradesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ListUpgradesArgs{Refresh: boolptr(false)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("list_upgrades failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"upgrade_available", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("1.0\n")}, {Stdout: []byte("Candidate: 2.0\n")}, {ExitCode: 1}, {ExitCode: 1}, {ExitCode: 0}}}
			got, err := (aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "p"})
			if err != nil || got != true || !reflect.DeepEqual(r.calls[1].Args, []string{"policy", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"upgrade_available", NormalizeNameArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &NormalizeNameArgs{Name: "bad name"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid upgrade_available: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"show", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: p\nVersion: 1\nDescription: d\n\n")}}}
			got, err := (aptLongtailFunc{"show", ShowArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ShowArgs{Names: []string{"p"}})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"p": map[string]any{"1": map[string]string{"Description": "d"}}}) || !reflect.DeepEqual(r.calls[0].Args, []string{"show", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"show", ShowArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &ShowArgs{Names: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid show: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_repo_pkgs", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("Package: p\nVersion: 1\n\nPackage: p\nVersion: 1\n\nPackage: q\nVersion: 2\n")}}}
			got, err := (aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"p"}})
			want := map[string][]string{"p": {"1", "1"}, "q": {"2"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[0].Args, []string{"show", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"list_repo_pkgs", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid list_repo_pkgs: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"owner", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("pkg: /x\n")}}}
			got, err := (aptLongtailFunc{"owner", struct {
				Paths []string `statekit:"name=paths"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), &struct {
				Paths []string `statekit:"name=paths"`
			}{Paths: []string{"/x"}})
			if err != nil || got != "pkg" || !reflect.DeepEqual(r.calls[0].Args, []string{"-S", "/x"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"owner", struct {
				Paths []string `statekit:"name=paths"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"paths": "bad"})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed owner: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"which", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("pkg: /x\n")}}}
			rt := aptExecRuntime("apt", r)
			if err := rt.FS.WriteFile("/x", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := (aptLongtailFunc{"which", PathArgs{}}).Execute(context.Background(), rt, &PathArgs{Path: "/x"})
			if err != nil || got != "pkg" || !reflect.DeepEqual(r.calls[0].Args, []string{"-S", "/x"}) {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			got, err := (aptLongtailFunc{"which", PathArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &PathArgs{Path: "relative"})
			if err != nil || got != false || len(r.calls) != 0 {
				t.Fatalf("invalid which: got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}},
		{"file_list", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\tp\n")}, {Stdout: []byte("/a\n\n/a\n")}}}
			got, err := (aptLongtailFunc{"file_list", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"p"}})
			want := map[string]any{"errors": []string{}, "files": []string{"/a"}}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(r.calls[1].Args, []string{"-L", "p"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\tp\n")}, {Stdout: []byte("/a\n")}}}
			got, err := (aptLongtailFunc{"file_list", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{})
			if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{"/a"}}) || len(r.calls) != 2 {
				t.Fatalf("empty file_list: got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}},
		{"file_dict", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("installed\ta\ninstalled\tb\n")}, {Stdout: []byte("/a\n")}, {Stdout: []byte("/b\n")}}}
			got, err := (aptLongtailFunc{"file_dict", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"a", "b"}})
			want := map[string]any{"errors": []string{}, "packages": map[string]any{"a": []string{"/a"}, "b": []string{"/b"}}}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.calls) != 3 {
				t.Fatalf("got=%#v err=%v calls=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"file_dict", FilePackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &FilePackagesArgs{Packages: []string{"bad name"}})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("invalid file_dict: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"info_installed", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p\t1\tinstall ok installed\n")}}}
			got, err := (aptLongtailFunc{"info_installed", InfoArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &InfoArgs{Failhard: boolptr(false)})
			want := map[string]any{"p": map[string]any{"name": "p", "version": "1"}}
			if err != nil || !reflect.DeepEqual(got, want) || r.calls[0].Name != "dpkg-query" {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 1}}}
			_, err := (aptLongtailFunc{"info_installed", InfoArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &InfoArgs{Failhard: boolptr(true)})
			if err == nil || len(r.calls) != 1 {
				t.Fatalf("failhard info_installed: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"list_downloaded", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("a 1\n")}}}
			rt := aptExecRuntime("apt", r)
			if err := rt.FS.MkdirAll("/root/var/cache/apt/archives", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := rt.FS.WriteFile("/root/var/cache/apt/archives/a.deb", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := (aptLongtailFunc{"list_downloaded", struct {
				Root string `statekit:"name=root"`
			}{}}).Execute(context.Background(), rt, &struct {
				Root string `statekit:"name=root"`
			}{Root: "/root"})
			meta := got.(map[string]any)["a"].(map[string]any)["1"].(map[string]any)
			if err != nil || !reflect.DeepEqual(meta["path"], "/root/var/cache/apt/archives/a.deb") || !reflect.DeepEqual(meta["size"], int64(1)) || meta["creation_date_time_t"] == nil || meta["creation_date_time"] == nil || len(r.calls) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.calls))
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{"list_downloaded", struct {
				Root string `statekit:"name=root"`
			}{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"root": 7})
			if err == nil || len(r.calls) != 0 {
				t.Fatalf("malformed list_downloaded: err=%v calls=%d", err, len(r.calls))
			}
		}},
		{"services_need_restart", func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("SERVICE:sshd,123\nSERVICE:cron,4\n")}}}
			got, err := (aptLongtailFunc{"services_need_restart", struct{}{}}).Execute(context.Background(), aptExecRuntime("apt", r), struct{}{})
			if err != nil || !reflect.DeepEqual(got, []string{"sshd", "cron"}) || !reflect.DeepEqual(r.calls[0].Args, []string{"--machine", "--package"}) {
				t.Fatalf("got=%#v err=%v cmd=%#v", got, err, r.calls)
			}
		}, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{{Err: context.Canceled, ExitCode: -1}}}
			_, err := (aptLongtailFunc{"services_need_restart", struct{}{}}).Execute(context.Background(), aptExecRuntime("apt", r), struct{}{})
			if !errors.Is(err, context.Canceled) || len(r.calls) != 1 {
				t.Fatalf("services failure: err=%v calls=%d", err, len(r.calls))
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.positive(t); tc.negative(t) })
	}
	if len(cases) != 21 {
		t.Fatalf("contract matrix has %d functions, want 21", len(cases))
	}
}

func TestAPTLongtailCapabilityRejectsEveryNamedFunctionBeforeRunner(t *testing.T) {
	cases := []struct {
		name string
		args any
	}{
		{"normalize_name", &NormalizeNameArgs{}}, {"parse_arch", &ParseArchArgs{}}, {"version_cmp", &VersionCmpArgs{}},
		{"get_selections", &SelectionsArgs{}}, {"set_selections", &SetSelectionsArgs{}}, {"hold", &PackagesArgs{}}, {"unhold", &PackagesArgs{}},
		{"autoremove", &AutoremoveArgs{}}, {"purge", &PackagesArgs{}}, {"upgrade", &UpgradeArgs{}}, {"list_upgrades", &ListUpgradesArgs{}},
		{"upgrade_available", &NormalizeNameArgs{}}, {"show", &ShowArgs{}}, {"list_repo_pkgs", &FilePackagesArgs{}},
		{"owner", &struct {
			Paths []string `statekit:"name=paths"`
		}{}}, {"which", &PathArgs{}}, {"file_list", &FilePackagesArgs{}},
		{"file_dict", &FilePackagesArgs{}}, {"info_installed", &InfoArgs{}}, {"list_downloaded", &struct {
			Root string `statekit:"name=root"`
		}{}},
		{"services_need_restart", &struct{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptFakeRunner{}
			_, err := (aptLongtailFunc{tc.name, tc.args}).Execute(context.Background(), aptExecRuntime("dnf", r), tc.args)
			if !errors.Is(err, pkgprovider.ErrUnsupportedAPT) || len(r.calls) != 0 {
				t.Fatalf("err=%v calls=%d", err, len(r.calls))
			}
		})
	}
}

func TestAPTSetSelectionsBoundedInputRejectsBeforeRunner(t *testing.T) {
	r := &aptFakeRunner{}
	name := strings.Repeat("x", 1<<20)
	_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{Selection: map[string][]string{"hold": {name}}})
	if err == nil || len(r.calls) != 0 {
		t.Fatalf("oversized selection: err=%v calls=%d", err, len(r.calls))
	}
}

func TestAPTArgsExposeSaltNamesAndRejectLegacyPackages(t *testing.T) {
	for _, tc := range []struct {
		name string
		args any
		want []string
	}{
		{"hold", PackagesArgs{}, []string{"name", "pkgs", "sources"}},
		{"unhold", PackagesArgs{}, []string{"name", "pkgs", "sources"}},
		{"purge", PurgeArgs{}, []string{"name", "pkgs"}},
	} {
		got, err := config.ArgumentNames(tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s args = %#v, %v; want %#v", tc.name, got, err, tc.want)
		}
	}
	r := &aptFakeRunner{}
	_, err := (aptLongtailFunc{"purge", PackagesArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), map[string]any{"packages": []string{"legacy"}})
	if err == nil || len(r.calls) != 0 {
		t.Fatalf("legacy packages must be rejected before Runner: %v, calls=%d", err, len(r.calls))
	}
}

func TestAPTFileFunctionsUseRegisteredPackagesPrototype(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pkg.file_list", "pkg.file_dict", "pkg.list_repo_pkgs"} {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if _, ok := fn.Args().(FilePackagesArgs); !ok {
			t.Fatalf("%s prototype = %T, want FilePackagesArgs", name, fn.Args())
		}
		keys, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(keys, []string{"packages"}) {
			t.Fatalf("%s prototype keys = %#v, %v", name, keys, err)
		}
	}
	for _, name := range []string{"file_list", "file_dict", "list_repo_pkgs"} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				label string
				args  any
			}{
				{"malformed", map[string]any{"packages": "not-a-list"}},
				{"legacy", map[string]any{"pkgs": []string{"p"}}},
				{"conflict", map[string]any{"packages": []string{"p"}, "pkgs": []string{"q"}}},
			} {
				r := &aptFakeRunner{}
				_, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), name, tc.args)
				if err == nil || len(r.calls) != 0 {
					t.Fatalf("%s %s: err=%v calls=%d", name, tc.label, err, len(r.calls))
				}
			}
		})
	}
}

func TestAPTVersionCmpPropagatesRunnerErrorsAndInvalidStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want error
	}{
		{"cancel", process.CommandResult{Err: context.Canceled, ExitCode: -1}, context.Canceled},
		{"output-limit", process.CommandResult{Err: process.ErrOutputLimit, ExitCode: -1}, process.ErrOutputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &aptFakeRunner{results: []process.CommandResult{tc.res}}
			got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1", Pkg2: "2"})
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
	r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 2}}}
	got, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "bad", Pkg2: "also-bad"})
	if err != nil || got != nil {
		t.Fatalf("invalid comparison status: got=%#v err=%v", got, err)
	}
	r = &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9, Stderr: []byte("failed")}}}
	if _, err := (aptLongtailFunc{"version_cmp", VersionCmpArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &VersionCmpArgs{Pkg1: "1", Pkg2: "2"}); err == nil {
		t.Fatal("unexpected child status must be returned")
	}
}

func TestAPTExplicitEmptyAndConflictingPkgsAreNotIgnored(t *testing.T) {
	for _, args := range []any{
		map[string]any{"name": "one", "pkgs": []string{}},
		map[string]any{"name": "one", "pkgs": []string{"two"}},
	} {
		r := &aptFakeRunner{}
		_, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "purge", args)
		if err != nil {
			t.Fatalf("package selection: err=%v calls=%d", err, len(r.calls))
		}
	}
}

// pkgproviderTestAPT keeps this test focused on the public execution boundary.
type pkgproviderTestAPT struct{}

func (*pkgproviderTestAPT) execute(ctx context.Context, rt *runtime.Runtime, name string, args any) (any, error) {
	p, err := pkgprovider.Resolve(rt)
	if err != nil {
		return nil, err
	}
	return p.(pkgprovider.AptProvider).Apt(ctx, rt, name, args.(map[string]any))
}

func TestAPTSetSelectionsFailedQueryNeverClears(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{ExitCode: 9}}}
	_, err := (aptLongtailFunc{"set_selections", SetSelectionsArgs{}}).Execute(context.Background(), aptExecRuntime("apt", r), &SetSelectionsArgs{
		Selection: map[string][]string{"hold": {"pkg"}}, Clear: func() *bool { v := true; return &v }(),
	})
	if err == nil || len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0].Args, []string{"--get-selections", "*"}) {
		t.Fatalf("failed prerequisite mutated selections: err=%v calls=%#v", err, r.calls)
	}
}

func TestAPTTargetPrecedenceAndSources(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("install ok installed two 1\n")}, {}, {Stdout: []byte("install ok installed two 1\n")}}}
	got, err := (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "purge", map[string]any{"name": "one", "pkgs": []string{"two"}})
	if err != nil || got == nil || len(r.calls) != 3 || !reflect.DeepEqual(r.calls[1].Args, []string{"-q", "-y", "purge", "two"}) {
		t.Fatalf("pkgs precedence: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
	r = &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("p install\n")}, {}}}
	got, err = (&pkgproviderTestAPT{}).execute(context.Background(), aptExecRuntime("apt", r), "hold", map[string]any{"sources": []any{map[string]any{"p": "file.deb"}}})
	if err != nil || got == nil || len(r.calls) != 2 || string(r.calls[1].Stdin) != "p hold\n" {
		t.Fatalf("source target extraction: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
}

func TestAPTDownloadedRecursiveAndNilFS(t *testing.T) {
	r := &aptFakeRunner{results: []process.CommandResult{{Stdout: []byte("a 1\n")}, {Stdout: []byte("b 2\n")}}}
	rt := aptExecRuntime("apt", r)
	if err := rt.FS.MkdirAll("/root/var/cache/apt/archives/nested", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/root/var/cache/apt/archives/nested/b.deb", []byte("bb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.WriteFile("/root/var/cache/apt/archives/a.deb", []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (aptLongtailFunc{"list_downloaded", DownloadedArgs{}}).Execute(context.Background(), rt, &DownloadedArgs{Root: strptr("/root")})
	if err != nil || len(got.(map[string]any)) != 2 || !reflect.DeepEqual(r.calls[0].Args, []string{"-f", "/root/var/cache/apt/archives/a.deb", "Package", "Version"}) {
		t.Fatalf("recursive downloaded: got=%#v err=%v calls=%#v", got, err, r.calls)
	}
	rt = aptExecRuntime("apt", &aptFakeRunner{})
	rt.FS = nil
	_, err = (aptLongtailFunc{"list_downloaded", DownloadedArgs{}}).Execute(context.Background(), rt, &DownloadedArgs{})
	if err == nil {
		t.Fatal("nil filesystem must be unsupported")
	}
}
