package pkg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const zypperDownloadXML = `<stream>` +
	`<download-result repository-alias="ignored-attr">` +
	`<repository name="OSS Update" alias="repo-oss-update"/>` +
	`<localfile path="/var/cache/zypp/packages/OSS Update/bash-4.3-83.3.1.x86_64.rpm"/>` +
	`<name>bash</name>` +
	`</download-result>` +
	`<download-result>` +
	`<localfile path="/var/cache/zypp/packages/vim-7.4.x86_64.rpm"/>` +
	`<repository name="OSS" alias="repo-oss"/>` +
	`<name>vim</name>` +
	`</download-result>` +
	`</stream>`

// zypperDownloadSplitNameXML separates the name element's text into two
// character-data chunks with a comment so the aggregate join with "\n" is
// observable, exactly like _get_first_aggregate_text over split DOM text
// nodes.
const zypperDownloadSplitNameXML = `<stream><download-result>` +
	`<repository name="OSS" alias="repo-oss"/>` +
	`<localfile path="/var/cache/zypp/packages/bash.rpm"/>` +
	`<name>ba<!--split-->sh</name>` +
	`</download-result></stream>`

func TestZypperDownloadNameAggregateJoinsTextChildren(t *testing.T) {
	rt, _, _ := zypperDownloadRuntime(process.CommandResult{Stdout: []byte(zypperDownloadSplitNameXML)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash"}})
	if err != nil {
		t.Fatal(err)
	}
	ret := got.(map[string]any)
	if _, exists := ret["ba\nsh"]; !exists {
		t.Fatalf("aggregate key missing: %#v", ret)
	}
	if _, failed := ret["_error"]; !failed {
		t.Fatalf("source package name mismatch must surface as _error: %#v", ret)
	}
	if ret["_error"] != "The following package(s) failed to download: bash" {
		t.Fatalf("_error=%v", ret["_error"])
	}
}

func zypperDownloadRuntime(results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner, *runtime.MemoryFS) {
	runner := &yumRecordingRunner{results: results}
	fsys := runtime.NewMemoryFS()
	return &runtime.Runtime{Runner: runner, FS: fsys}, runner, fsys
}

func TestZypperDownloadParsesResultsAndRunsChecksum(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result process.CommandResult
	}{
		{"checksum ok", process.CommandResult{ExitCode: 0}},
		{"checksum failed but dict stays truthy", process.CommandResult{ExitCode: 1, Stderr: []byte("digest mismatch")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := "/target"
			args := map[string]any{"packages": []string{"bash", "vim"}, "root": &root}
			before := map[string]any{"packages": []string{"bash", "vim"}, "root": &root}
			rt, runner, fsys := zypperDownloadRuntime(
				process.CommandResult{Stdout: []byte(zypperDownloadXML)},
				tc.result,
				tc.result,
			)
			if err := fsys.MkdirAll("/var/cache/zypp/packages/OSS Update", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/cache/zypp/packages/OSS Update/bash-4.3-83.3.1.x86_64.rpm", []byte("rpm"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := fsys.WriteFile("/var/cache/zypp/packages/vim-7.4.x86_64.rpm", []byte("rpm"), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", args)
			want := map[string]any{
				"bash": map[string]any{
					"repository-name":  "OSS Update",
					"repository-alias": "repo-oss-update",
					"path":             "/var/cache/zypp/packages/OSS Update/bash-4.3-83.3.1.x86_64.rpm",
				},
				"vim": map[string]any{
					"repository-name":  "OSS",
					"repository-alias": "repo-oss",
					"path":             "/var/cache/zypp/packages/vim-7.4.x86_64.rpm",
				},
			}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
				t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
			}
			wantArgv := [][]string{
				{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "download", "bash", "vim"},
				{"rpm", "--root", root, "-K", "--quiet", "/var/cache/zypp/packages/OSS Update/bash-4.3-83.3.1.x86_64.rpm"},
				{"rpm", "--root", root, "-K", "--quiet", "/var/cache/zypp/packages/vim-7.4.x86_64.rpm"},
			}
			if len(runner.commands) != len(wantArgv) {
				t.Fatalf("commands=%#v", runner.commands)
			}
			for i, command := range runner.commands {
				if !reflect.DeepEqual(zypperCommandArgs(command), wantArgv[i]) {
					t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), wantArgv[i])
				}
				if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit {
					t.Fatalf("unsafe command[%d]=%#v", i, command)
				}
			}
			assertZypperPatternsCommand(t, runner.commands[0], true)
		})
	}
}

func TestZypperDownloadMissingLocalFileSkipsRPMButIncludesRecord(t *testing.T) {
	rt, runner, _ := zypperDownloadRuntime(process.CommandResult{Stdout: []byte(zypperDownloadXML)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash", "vim"}})
	if err != nil {
		t.Fatal(err)
	}
	ret := got.(map[string]any)
	if len(ret) != 2 {
		t.Fatalf("got=%#v", ret)
	}
	if len(runner.commands) != 1 {
		// file.file_exists was false, so no rpm -K ran at all.
		t.Fatalf("commands=%#v", runner.commands)
	}
}

func TestZypperDownloadPartialFailureAndFullFailure(t *testing.T) {
	xml := `<stream><download-result><repository name="r" alias="a"/><localfile path="/var/cache/zypp/packages/bash.rpm"/><name>bash</name></download-result></stream>`
	rt, _, _ := zypperDownloadRuntime(process.CommandResult{Stdout: []byte(xml)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash", "b"}})
	want := map[string]any{
		"bash":   map[string]any{"repository-name": "r", "repository-alias": "a", "path": "/var/cache/zypp/packages/bash.rpm"},
		"_error": "The following package(s) failed to download: b",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("partial got=%#v err=%v", got, err)
	}

	rt, runner, _ := zypperDownloadRuntime(process.CommandResult{Stdout: []byte(`<stream/>`)})
	got, err = zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"a", "b"}})
	if got != nil || err == nil || err.Error() != "Unable to download packages: a, b" || len(runner.commands) != 1 {
		t.Fatalf("full got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperDownloadEmptyPackagesRaisesBeforeAnything(t *testing.T) {
	for _, args := range []map[string]any{
		{},
		{"packages": []string{}},
		{"refresh": true, "packages": []string{}, "root": zypperStringPtr("/target")},
	} {
		rt, runner, _ := zypperDownloadRuntime()
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", args)
		if got != nil || err != errZypperDownloadPackagesRequired || len(runner.commands) != 0 {
			t.Fatalf("args=%#v got=%#v err=%v calls=%d", args, got, err, len(runner.commands))
		}
	}
}

func TestZypperDownloadRefreshRootPosition(t *testing.T) {
	root := "/target"
	refresh := true
	rt, runner, fsys := zypperDownloadRuntime(
		process.CommandResult{},
		process.CommandResult{Stdout: []byte(zypperDownloadXML)},
		process.CommandResult{ExitCode: 0},
	)
	if err := fsys.MkdirAll("/var/cache/zypp/packages", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/var/cache/zypp/packages/vim-7.4.x86_64.rpm", []byte("rpm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash", "vim"}, "refresh": &refresh, "root": &root}); err != nil {
		t.Fatal(err)
	}
	// The bash localfile does not exist in this runtime, so its checksum
	// short-circuits on file.file_exists and never reaches rpm.
	want := [][]string{
		{"zypper", "--non-interactive", "refresh", "--force"},
		{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "download", "bash", "vim"},
		{"rpm", "--root", root, "-K", "--quiet", "/var/cache/zypp/packages/vim-7.4.x86_64.rpm"},
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands=%#v", runner.commands)
	}
	for i, command := range runner.commands {
		if !reflect.DeepEqual(zypperCommandArgs(command), want[i]) {
			t.Fatalf("argv[%d]=%v want=%v", i, zypperCommandArgs(command), want[i])
		}
	}
}

func TestZypperDownloadRejectsBadArgumentsBeforeRunner(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"packages wrong type", map[string]any{"packages": "bash"}},
		{"packages unsafe token", map[string]any{"packages": []string{"bad name"}}},
		{"packages dash token", map[string]any{"packages": []string{"-x"}}},
		{"refresh not bool", map[string]any{"packages": []string{"bash"}, "refresh": "yes"}},
		{"unknown kwarg", map[string]any{"packages": []string{"bash"}, "enablerepo": "x"}},
		{"bad root", map[string]any{"packages": []string{"bash"}, "root": 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner, _ := zypperDownloadRuntime()
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", tc.args)
			if got != nil || err == nil || err == errZypperDownloadPackagesRequired || len(runner.commands) != 0 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
}

func TestZypperDownloadMalformedAndUnsafeResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		xml    string
		want   error
		unused int
	}{
		{"not xml", "not xml", errZypperDownloadInvalidXML, 1},
		{"two roots", "<a/><b/>", errZypperDownloadInvalidXML, 1},
		{"missing repository", `<stream><download-result><localfile path="/var/cache/zypp/packages/x.rpm"/><name>x</name></download-result></stream>`, errZypperDownloadIncompleteResult, 1},
		{"missing localfile", `<stream><download-result><repository name="r" alias="a"/><name>x</name></download-result></stream>`, errZypperDownloadIncompleteResult, 1},
		{"unsafe localfile", `<stream><download-result><repository name="r" alias="a"/><localfile path="/bad&#10;path.rpm"/><name>x</name></download-result></stream>`, errZypperDownloadUnsafePath, 1},
		{"element cap", `<stream>` + strings.Repeat(`<download-result/>`, zypperLowpkgMaxItems+1) + `</stream>`, process.ErrOutputLimit, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner, _ := zypperDownloadRuntime(process.CommandResult{Stdout: []byte(tc.xml)})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"x"}})
			if got != nil || !errors.Is(err, tc.want) || len(runner.commands) != tc.unused {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
			}
		})
	}
}

func TestZypperDownloadCancelAndRunnerFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancelRunner := &zypperCancelRunner{cancel: cancel}
	rt := &runtime.Runtime{Runner: cancelRunner, FS: runtime.NewMemoryFS()}
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "download", map[string]any{"packages": []string{"bash"}}); got != nil || !errors.Is(err, context.Canceled) || len(cancelRunner.calls) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(cancelRunner.calls))
	}

	rt, runner, _ := zypperDownloadRuntime(process.CommandResult{Err: process.ErrOutputLimit})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash"}}); got != nil || !errors.Is(err, process.ErrOutputLimit) || len(runner.commands) != 1 {
		t.Fatalf("output limit got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperDownloadTestModeReturnsEmptyBeforeRunner(t *testing.T) {
	rt, runner, _ := zypperDownloadRuntime()
	rt.Options.Test = true
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(runner.commands) != 0 {
		t.Fatalf("test got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}

func TestZypperDownloadRequiresFilesystem(t *testing.T) {
	rt, runner := zypperLowpkgRuntime(process.CommandResult{Stdout: []byte(zypperDownloadXML)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "download", map[string]any{"packages": []string{"bash"}})
	if got != nil || err == nil || len(runner.commands) != 0 {
		t.Fatalf("nil fs got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
}
