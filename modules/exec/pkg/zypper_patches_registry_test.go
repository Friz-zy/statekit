package pkg

import (
	"context"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// zypperFinalBatchRow describes one registry contract row for the final
// Zypper batch: the canonical registration, the zypper prototype resolved
// from facts, its exact argument names, and the capability list.
type zypperFinalBatchRow struct {
	name  string
	proto any
	args  []string
	caps  []string
}

func zypperFinalBatchRows() []zypperFinalBatchRow {
	return []zypperFinalBatchRow{
		{"pkg.list_patches", ZypperListPatchesArgs{}, []string{"refresh", "root"}, []string{"yumpkg", "zypperpkg"}},
		{"pkg.list_installed_patches", ZypperListInstalledPatchesArgs{}, []string{"root"}, []string{"yumpkg", "zypperpkg"}},
		{"pkg.services_need_restart", ZypperServicesNeedRestartArgs{}, []string{"root"}, []string{"aptpkg", "yumpkg", "zypperpkg"}},
		{"pkg.list_repo_pkgs", ZypperListRepoPkgsArgs{}, []string{"byrepo", "fromrepo", "pkgs", "root"}, []string{"aptpkg", "yumpkg", "zypperpkg"}},
		{"pkg.download", ZypperDownloadArgs{}, []string{"packages", "refresh", "root"}, []string{"yumpkg", "zypperpkg"}},
		{"pkg.list_downloaded", ZypperListDownloadedArgs{}, []string{"root"}, []string{"aptpkg", "yumpkg", "zypperpkg"}},
		{"pkg.diff", ZypperDiffArgs{}, []string{"paths", "root"}, []string{"yumpkg", "zypperpkg"}},
	}
}

func TestZypperFinalBatchRegistryContract(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, row := range zypperFinalBatchRows() {
		count := 0
		for _, registered := range reg.Names() {
			if registered == row.name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s registration count=%d", row.name, count)
		}
		fn, ok := reg.Get(row.name)
		if !ok {
			t.Fatalf("missing %s", row.name)
		}
		strict, ok := fn.(runtime.ProviderArgsStrict)
		if !ok || !strict.ProviderArgsStrict() {
			t.Fatalf("%s is not strict", row.name)
		}
		if got := reg.ProviderCapabilities(row.name); !reflect.DeepEqual(got, row.caps) {
			t.Fatalf("%s capabilities=%v", row.name, got)
		}
		if names, err := config.ArgumentNames(row.proto); err != nil || !reflect.DeepEqual(names, row.args) {
			t.Fatalf("%s argument names=%v err=%v", row.name, names, err)
		}
	}

	runner := &zypperResolveRegistryRunner{}
	rt := zypperRegistryRuntime("zypper", runner)
	for _, row := range zypperFinalBatchRows() {
		prototype, err := reg.ResolveArgs(rt, row.name)
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(row.proto) {
			t.Fatalf("%s prototype=%T err=%v", row.name, prototype, err)
		}
	}
}

func TestZypperFinalBatchRegistryCallFlows(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	patchesXML := []byte(`<stream><solvable-list><solvable name="SUSE-1" summary="sec" status="installed" kind="patch"/><solvable name="SUSE-2" summary="rec" status="not-installed" kind="patch"/></solvable-list></stream>`)
	root := "/target"

	t.Run("list_patches", func(t *testing.T) {
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{{Stdout: patchesXML}}}
		rt := zypperRegistryRuntime("zypper", runner)
		refresh := false
		got, err := reg.Call(context.Background(), rt, "pkg.list_patches", &ZypperListPatchesArgs{Refresh: &refresh, Root: &root})
		want := map[string]any{
			"SUSE-1": map[string]any{"installed": true, "summary": "sec"},
			"SUSE-2": map[string]any{"installed": false, "summary": "rec"},
		}
		if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
		if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "se", "-t", "patch"}) {
			t.Fatalf("argv=%v", argv)
		}
	})

	t.Run("list_installed_patches", func(t *testing.T) {
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{{Stdout: patchesXML}}}
		rt := zypperRegistryRuntime("zypper", runner)
		got, err := reg.Call(context.Background(), rt, "pkg.list_installed_patches", &ZypperListInstalledPatchesArgs{Root: &root})
		want := map[string]any{"SUSE-1": map[string]any{"installed": true, "summary": "sec"}}
		if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
	})

	t.Run("services_need_restart", func(t *testing.T) {
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{{Stdout: []byte("sshd.service cron.service\n")}}}
		rt := zypperRegistryRuntime("zypper", runner)
		got, err := reg.Call(context.Background(), rt, "pkg.services_need_restart", &ZypperServicesNeedRestartArgs{})
		if err != nil || !reflect.DeepEqual(got, []string{"sshd.service", "cron.service"}) || len(runner.calls) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
		if argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...); !reflect.DeepEqual(argv, []string{"zypper", "--non-interactive", "--no-refresh", "ps", "-sss"}) {
			t.Fatalf("argv=%v", argv)
		}
	})

	t.Run("list_repo_pkgs", func(t *testing.T) {
		repoXML := `<stream><solvable-list>` +
			`<solvable name="bash" edition="4.3-83.3.1" repository="OSS Update" kind="package"/>` +
			`<solvable name="bash" edition="4.3-82.6" repository="OSS" kind="package"/>` +
			`</solvable-list></stream>`
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{{Stdout: []byte(repoXML)}}}
		rt := zypperRegistryRuntime("zypper", runner)
		byrepo := false
		fromrepo := ""
		got, err := reg.Call(context.Background(), rt, "pkg.list_repo_pkgs", &ZypperListRepoPkgsArgs{Pkgs: []string{"bash"}, Byrepo: &byrepo, Fromrepo: &fromrepo})
		want := map[string]any{"bash": []string{"4.3-83.3.1", "4.3-82.6"}}
		if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
	})

	t.Run("list_downloaded", func(t *testing.T) {
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{{Stdout: []byte("bash_|-0_|-4.3_|-83.3.1_|-x86_64_|-none_|-0\n")}}}
		rt := zypperRegistryRuntime("zypper", runner)
		rt.FS = runtime.NewMemoryFS()
		if err := rt.FS.MkdirAll("/target/var/cache/zypp/packages", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile("/target/var/cache/zypp/packages/bash-4.3.rpm", []byte("rpm"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.list_downloaded", &ZypperListDownloadedArgs{Root: &root})
		meta := got.(map[string]any)["bash"].(map[string]any)["4.3-83.3.1"].(map[string]any)
		if err != nil || meta["path"] != "/target/var/cache/zypp/packages/bash-4.3.rpm" || len(runner.calls) != 1 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
	})

	t.Run("download", func(t *testing.T) {
		xml := `<stream><download-result><repository name="OSS" alias="repo-oss"/><localfile path="/var/cache/zypp/packages/bash-4.3.rpm"/><name>bash</name></download-result></stream>`
		runner := &zypperResolveRegistryRunner{results: []process.CommandResult{
			{Stdout: []byte(xml)},
			{ExitCode: 0},
		}}
		rt := zypperRegistryRuntime("zypper", runner)
		rt.FS = runtime.NewMemoryFS()
		if err := rt.FS.MkdirAll("/var/cache/zypp/packages", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile("/var/cache/zypp/packages/bash-4.3.rpm", []byte("rpm"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.download", &ZypperDownloadArgs{Packages: []string{"bash"}})
		want := map[string]any{
			"bash": map[string]any{"repository-name": "OSS", "repository-alias": "repo-oss", "path": "/var/cache/zypp/packages/bash-4.3.rpm"},
		}
		if err != nil || !reflect.DeepEqual(got, want) || len(runner.calls) != 2 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
		argv := append([]string{runner.calls[0].Name}, runner.calls[0].Args...)
		if !reflect.DeepEqual(argv, []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "download", "bash"}) {
			t.Fatalf("argv=%v", argv)
		}
	})

	t.Run("diff", func(t *testing.T) {
		xml := `<stream><download-result><repository name="OSS" alias="repo-oss"/><localfile path="/var/cache/zypp/packages/alpha.rpm"/><name>alpha</name></download-result></stream>`
		runner := &zypperFinalAvailabilityRunner{zypperResolveRegistryRunner{results: []process.CommandResult{
			{Stdout: []byte("alpha")},
			{Stdout: []byte(xml)},
			{ExitCode: 0},
			{Stdout: []byte("ARCHIVE")},
			{Stdout: []byte("original one")},
			{ExitCode: 1, Stdout: []byte("--- a\n+++ b\n")},
		}}}
		rt := zypperRegistryRuntime("zypper", runner)
		rt.FS = runtime.NewMemoryFS()
		if err := rt.FS.MkdirAll("/etc", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile("/etc/one", []byte("current one"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.MkdirAll("/var/cache/zypp/packages", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile("/var/cache/zypp/packages/alpha.rpm", []byte("rpm"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.diff", &ZypperDiffArgs{Paths: []string{"/etc/one"}})
		if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/one": "--- a\n+++ b\n"}) || len(runner.calls) != 6 {
			t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.calls))
		}
	})
}

// zypperFinalAvailabilityRunner extends the canned-results runner with the
// command availability signal the rpm-diff helpers gate requires.
type zypperFinalAvailabilityRunner struct {
	zypperResolveRegistryRunner
}

func (r *zypperFinalAvailabilityRunner) CommandAvailable(string) bool { return true }

func TestZypperFinalBatchRegistryNegativeAndNoCall(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}

	// Negative: empty packages raises the ported SaltInvocationError, and
	// malformed arguments never reach the runner.
	runner := &zypperResolveRegistryRunner{}
	rt := zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(context.Background(), rt, "pkg.download", &ZypperDownloadArgs{}); got != nil || err == nil || len(runner.calls) != 0 {
		t.Fatalf("empty download got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}
	runner = &zypperResolveRegistryRunner{}
	rt = zypperRegistryRuntime("zypper", runner)
	if got, err := reg.Call(context.Background(), rt, "pkg.download", &ZypperDownloadArgs{Packages: []string{"bad name"}}); got != nil || err == nil || len(runner.calls) != 0 {
		t.Fatalf("unsafe download got=%#v err=%v calls=%d", got, err, len(runner.calls))
	}

	// apt/yum keep their own shapes: every zypper pointer is rejected
	// before the provider or runner is touched.
	for _, manager := range []string{"apt", "yum"} {
		for _, call := range []struct {
			name string
			args any
		}{
			{"pkg.list_patches", &ZypperListPatchesArgs{}},
			{"pkg.list_installed_patches", &ZypperListInstalledPatchesArgs{}},
			{"pkg.services_need_restart", &ZypperServicesNeedRestartArgs{}},
			{"pkg.list_repo_pkgs", &ZypperListRepoPkgsArgs{}},
			{"pkg.download", &ZypperDownloadArgs{}},
			{"pkg.list_downloaded", &ZypperListDownloadedArgs{}},
			{"pkg.diff", &ZypperDiffArgs{}},
		} {
			otherRunner := &zypperResolveRegistryRunner{}
			otherRT := zypperRegistryRuntime(manager, otherRunner)
			got, err := reg.Call(context.Background(), otherRT, call.name, call.args)
			if got != nil || err == nil || len(otherRunner.calls) != 0 {
				t.Fatalf("%s %s got=%#v err=%v calls=%d", manager, call.name, got, err, len(otherRunner.calls))
			}
		}
	}
}

func TestZypperFinalBatchCLIFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		proto  any
		flags  []string
		wanted []string
	}{
		{"list_patches", ZypperListPatchesArgs{}, []string{"--refresh", "--root", "/target"}, []string{"refresh", "root"}},
		{"list_installed_patches", ZypperListInstalledPatchesArgs{}, []string{"--root", "/target"}, []string{"root"}},
		{"services_need_restart", ZypperServicesNeedRestartArgs{}, []string{"--root", "/target"}, []string{"root"}},
		{"list_repo_pkgs", ZypperListRepoPkgsArgs{}, []string{"--byrepo", "--fromrepo", "OSS Update", "--pkgs", "bash,vim", "--root", "/target"}, []string{"byrepo", "fromrepo", "pkgs", "root"}},
		{"download", ZypperDownloadArgs{}, []string{"--packages", "bash,vim", "--refresh", "--root", "/target"}, []string{"packages", "refresh", "root"}},
		{"list_downloaded", ZypperListDownloadedArgs{}, []string{"--root", "/target"}, []string{"root"}},
		{"diff", ZypperDiffArgs{}, []string{"--paths", "/etc/one,/etc/two", "--root", "/target"}, []string{"paths", "root"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags, err := config.NewFlagSet(tc.name, tc.proto)
			if err != nil {
				t.Fatal(err)
			}
			if err := flags.Parse(tc.flags); err != nil {
				t.Fatalf("%s flags: %v", tc.name, err)
			}
			for _, name := range tc.wanted {
				if flags.Lookup(name) == nil {
					t.Fatalf("%s flag %q missing", tc.name, name)
				}
			}
		})
	}
}
