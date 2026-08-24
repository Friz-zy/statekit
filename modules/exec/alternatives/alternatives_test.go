package alternatives

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests mapped onto saltstack/tests/pytests/unit/modules/test_alternatives.py.

type fakeRunner struct {
	calls   [][]string
	results map[string]process.CommandResult
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	f.calls = append(f.calls, argv)
	if res, ok := f.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{}
}

func altRT(t *testing.T, family string, runner *fakeRunner, files map[string]string) *runtime.Runtime {
	t.Helper()
	saved := etcAlternativesDir
	etcAlternativesDir = "/testbed/etc/alternatives"
	t.Cleanup(func() { etcAlternativesDir = saved })

	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{
			ID: family, Name: family, Family: family,
		}}),
		Runner: runner,
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func parentOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "/"
}

// Mirrors test_display including the per-family command selection and the
// stderr-on-failure return shape.
func TestDisplay(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"alternatives\x00--display\x00better-world":        {Stdout: []byte("salt")},
		"update-alternatives\x00--display\x00better-world": {Stdout: []byte("undoubtedly-salt")},
	}}
	rt := altRT(t, "redhat", runner, nil)
	got, _ := displayFunc{}.Execute(context.Background(), rt, &DisplayArgs{Name: "better-world"})
	if got != "salt" || len(runner.calls) != 1 || runner.calls[0][0] != "alternatives" {
		t.Fatalf("redhat display = %#v calls=%#v", got, runner.calls)
	}

	rt = altRT(t, "suse", runner, nil)
	got, _ = displayFunc{}.Execute(context.Background(), rt, &DisplayArgs{Name: "better-world"})
	if got != "undoubtedly-salt" || runner.calls[len(runner.calls)-1][0] != "update-alternatives" {
		t.Fatalf("suse display = %#v", got)
	}

	runner.results["alternatives\x00--display\x00better-world"] =
		process.CommandResult{ExitCode: 1, Stdout: []byte("salt-out"), Stderr: []byte("salt-err")}
	rt = altRT(t, "redhat", runner, nil)
	got, _ = displayFunc{}.Execute(context.Background(), rt, &DisplayArgs{Name: "better-world"})
	if got != "salt-err" {
		t.Fatalf("failure display = %#v; want stderr", got)
	}
}

// Mirrors test_show_current with a real symlink in the memory FS.
func TestShowCurrent(t *testing.T) {
	rt := altRT(t, "debian", &fakeRunner{}, nil)
	if err := rt.FS.MkdirAll("/testbed/etc/alternatives", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.Symlink("/etc/alternatives/salt", "/testbed/etc/alternatives/better-world"); err != nil {
		t.Fatal(err)
	}
	got, _ := showCurrentFunc{}.Execute(context.Background(), rt, &ShowCurrentArgs{Name: "better-world"})
	if got != "/etc/alternatives/salt" {
		t.Fatalf("show_current = %#v", got)
	}

	got, _ = showCurrentFunc{}.Execute(context.Background(), rt, &ShowCurrentArgs{Name: "hell"})
	if got != false {
		t.Fatalf("missing link = %#v; want false", got)
	}
}

// Mirrors test_check_installed.
func TestCheckInstalled(t *testing.T) {
	rt := altRT(t, "debian", &fakeRunner{}, nil)
	if err := rt.FS.MkdirAll("/testbed/etc/alternatives", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rt.FS.Symlink("/etc/alternatives/salt", "/testbed/etc/alternatives/better-world"); err != nil {
		t.Fatal(err)
	}
	got, _ := checkInstalledFunc{}.Execute(context.Background(), rt, &CheckInstalledArgs{
		Name: "better-world", Path: "/etc/alternatives/salt",
	})
	if got != true {
		t.Fatalf("check_installed = %#v", got)
	}
	got, _ = checkInstalledFunc{}.Execute(context.Background(), rt, &CheckInstalledArgs{
		Name: "help", Path: "/etc/alternatives/salt",
	})
	if got != false {
		t.Fatalf("missing check_installed = %#v", got)
	}
}

// Mirrors test_install across families and the failure return shape.
func TestInstall(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	key := func(bin string) string {
		return strings.Join([]string{bin, "--install", "/usr/bin/better-world",
			"better-world", "/usr/bin/salt", "100"}, "\x00")
	}

	rt := altRT(t, "redhat", runner, nil)
	runner.results[key("alternatives")] = process.CommandResult{Stdout: []byte("salt")}
	got, _ := installFunc{}.Execute(context.Background(), rt, &InstallArgs{
		Name: "better-world", Link: "/usr/bin/better-world", Path: "/usr/bin/salt", Priority: 100,
	})
	if got != "salt" {
		t.Fatalf("redhat install = %#v", got)
	}

	rt = altRT(t, "debian", runner, nil)
	runner.results[key("update-alternatives")] = process.CommandResult{Stdout: []byte("salt")}
	got, _ = installFunc{}.Execute(context.Background(), rt, &InstallArgs{
		Name: "better-world", Link: "/usr/bin/better-world", Path: "/usr/bin/salt", Priority: 100,
	})
	if got != "salt" {
		t.Fatalf("debian install = %#v", got)
	}

	runner.results[key("alternatives")] = process.CommandResult{ExitCode: 1,
		Stdout: []byte("salt-out"), Stderr: []byte("salt-err")}
	rt = altRT(t, "redhat", runner, nil)
	got, _ = installFunc{}.Execute(context.Background(), rt, &InstallArgs{
		Name: "better-world", Link: "/usr/bin/better-world", Path: "/usr/bin/salt", Priority: 100,
	})
	if got != "salt-err" {
		t.Fatalf("failed install = %#v", got)
	}
}

// Mirrors test_remove across families.
func TestRemove(t *testing.T) {
	runner := &fakeRunner{results: map[string]process.CommandResult{}}
	removeKey := func(bin string) string {
		return strings.Join([]string{bin, "--remove", "better-world", "/usr/bin/better-world"}, "\x00")
	}

	rt := altRT(t, "redhat", runner, nil)
	runner.results[removeKey("alternatives")] = process.CommandResult{Stdout: []byte("salt")}
	got, _ := removeFunc{}.Execute(context.Background(), rt, &RemoveArgs{
		Name: "better-world", Path: "/usr/bin/better-world",
	})
	if got != "salt" {
		t.Fatalf("redhat remove = %#v", got)
	}

	rt = altRT(t, "debian", runner, nil)
	runner.results[removeKey("update-alternatives")] = process.CommandResult{Stdout: []byte("salt")}
	got, _ = removeFunc{}.Execute(context.Background(), rt, &RemoveArgs{
		Name: "better-world", Path: "/usr/bin/better-world",
	})
	if got != "salt" {
		t.Fatalf("debian remove = %#v", got)
	}

	runner.results[removeKey("alternatives")] = process.CommandResult{ExitCode: 1,
		Stdout: []byte("salt-out"), Stderr: []byte("salt-err")}
	rt = altRT(t, "redhat", runner, nil)
	got, _ = removeFunc{}.Execute(context.Background(), rt, &RemoveArgs{
		Name: "better-world", Path: "/usr/bin/better-world",
	})
	if got != "salt-err" {
		t.Fatalf("failed remove = %#v", got)
	}
}

// Mirrors test_show_link_debian with the upstream query fixture.
func TestShowLinkDebian(t *testing.T) {
	queryOut := `Name: editor
Link: /usr/bin/editor
Slaves:
 editor.1.gz /usr/share/man/man1/editor.1.gz
Status: manual
Best: /bin/nano
Value: /usr/bin/vim.basic

Alternative: /bin/nano
Priority: 40
`
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"update-alternatives\x00--query\x00editor": {Stdout: []byte(queryOut)},
	}}
	rt := altRT(t, "debian", runner, nil)
	got, _ := showLinkFunc{}.Execute(context.Background(), rt, &ShowLinkArgs{Name: "editor"})
	if got != "/usr/bin/editor" {
		t.Fatalf("debian show_link = %#v", got)
	}
}

// Mirrors test_show_link_redhat: second line of the metadata file.
func TestShowLinkRedHat(t *testing.T) {
	savedRedHat := redHatAltDir
	redHatAltDir = "/testbed/var/lib/alternatives"
	t.Cleanup(func() { redHatAltDir = savedRedHat })
	ldData := "auto\n/usr/bin/ld\n\n/usr/bin/ld.bfd\n50\n/usr/bin/ld.gold\n30\n"
	runner := &fakeRunner{}
	rt := altRT(t, "redhat", runner, map[string]string{
		"/testbed/var/lib/alternatives/ld": ldData,
	})
	got, _ := showLinkFunc{}.Execute(context.Background(), rt, &ShowLinkArgs{Name: "ld"})
	if got != "/usr/bin/ld" {
		t.Fatalf("redhat show_link = %#v", got)
	}
}

// Mirrors test_show_link_suse with the rpm alternatives directory.
func TestShowLinkSuse(t *testing.T) {
	saved := suseAltDir
	suseAltDir = "/testbed/var/lib/rpm/alternatives"
	t.Cleanup(func() { suseAltDir = saved })
	ldData := "auto\n/usr/bin/ld\n\n/usr/bin/ld.bfd\n2\n\n"
	rt := altRT(t, "suse", &fakeRunner{}, map[string]string{
		"/testbed/var/lib/rpm/alternatives/ld": ldData,
	})
	got, _ := showLinkFunc{}.Execute(context.Background(), rt, &ShowLinkArgs{Name: "ld"})
	if got != "/usr/bin/ld" {
		t.Fatalf("suse show_link = %#v", got)
	}
}

// Pins the CLI-facing alias: set_ registers as alternatives.set.
func TestSetAliasRegistration(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("alternatives.set"); !ok {
		t.Fatalf("alternatives.set not registered")
	}
	if _, ok := reg.Get("alternatives.set_"); ok {
		t.Fatalf("raw set_ leaked into the registry")
	}
}
