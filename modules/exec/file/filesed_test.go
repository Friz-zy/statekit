package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// The patch targets use the OS filesystem (patch binary runs against real
// paths), so fixtures write real files.
func writeFileP(_ *runtime.Runtime, path, content string) error {
	if err := os.MkdirAll(parentOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func osMkdir(dir string) error { return os.MkdirAll(dir, 0o755) }

// R4.6 tests pinning the sed/patch argv contracts read from
// saltstack/salt/modules/file.py @ pinned revision.

type sedFakeRunner struct {
	calls   [][]string
	code    int
	results map[string]process.CommandResult
}

func (s *sedFakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	argv := append([]string{cmd.Name}, cmd.Args...)
	s.calls = append(s.calls, argv)
	if res, ok := s.results[strings.Join(argv, "\x00")]; ok {
		return res
	}
	return process.CommandResult{ExitCode: s.code}
}

func sedRT(t *testing.T, files map[string]string, code int) (*runtime.Runtime, *sedFakeRunner) {
	t.Helper()
	rt := &runtime.Runtime{
		Exec:   runtime.NewExecRegistry(),
		States: runtime.NewStateRegistry(),
		FS:     runtime.NewMemoryFS(),
		Facts:  facts.ForTesting(facts.Overrides{}),
	}
	for path, content := range files {
		if err := rt.FS.MkdirAll(parentOf(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := rt.FS.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &sedFakeRunner{code: code}
	rt.Runner = runner
	return rt, runner
}

func TestSedArgvAndMissing(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(confPath, []byte("LogLevel warn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, runner := sedRT(t, map[string]string{}, 0)

	sedFn := sedFunc{}
	ret, err := sedFn.Execute(context.Background(), rt, &sedArgs{
		Path:   confPath,
		Before: "warn",
		After:  "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ret != "" {
		t.Fatalf("ret = %#v", ret)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	wantHead := []string{"sed", "-i.bak", "-r", "-e"}
	if !equalSlice(call[:4], wantHead) || call[len(call)-1] != confPath {
		t.Fatalf("argv = %#v", call)
	}
	if call[4] != " s/warn/info/g" && call[4] != "s/warn/info/g" &&
		!strings.Contains(call[4], "warn") {
		t.Fatalf("pattern = %q", call[4])
	}

	// Missing file → False without a call.
	before := len(runner.calls)
	ret, err = sedFn.Execute(context.Background(), rt, &sedArgs{
		Path: confPath + ".missing", Before: "a", After: "b",
	})
	if err != nil || ret != false {
		t.Fatalf("missing file = %#v, %v", ret, err)
	}
	if len(runner.calls) != before {
		t.Fatalf("unexpected call for missing file")
	}

	// escape_all escapes regex metacharacters in the pattern token.
	_, err = sedFn.Execute(context.Background(), rt, &sedArgs{
		Path: confPath, Before: "a.b(c)", After: "x", EscapeAll: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pattern := runner.calls[len(runner.calls)-1][len(runner.calls[len(runner.calls)-1])-2]
	if !strings.Contains(pattern, `a\.b\(c\)`) {
		t.Fatalf("escape_all pattern = %q", pattern)
	}
}

func TestSedContains(t *testing.T) {
	cronPath := filepath.Join(t.TempDir(), "crontab")
	if err := os.WriteFile(cronPath, []byte("mymaintenance.sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, runner := sedRT(t, map[string]string{}, 0)

	// Seed the exact argv key: sed -n -r -e 'limit's/text/text/p path.
	pattern := "s/mymaintenance.sh/mymaintenance.sh/gp"
	key := strings.Join([]string{
		"sed", "-n", "-r", "-e", pattern, cronPath,
	}, "\x00")
	runner.results = map[string]process.CommandResult{
		key: {Stdout: []byte("mymaintenance.sh\n")},
	}

	fn := sedContainsFunc{}
	got, err := fn.Execute(context.Background(), rt, &sedContainsArgs{
		Path: cronPath, Text: "mymaintenance.sh",
	})
	if err != nil || got != true {
		t.Fatalf("contains = %#v, %v", got, err)
	}
	call := strings.Join(runner.calls[0], " ")
	if !strings.Contains(call, "-n -r -e") {
		t.Fatalf("argv malformed: %s", call)
	}

	// Missing file returns False without a call.
	before := len(runner.calls)
	got, err = fn.Execute(context.Background(), rt, &sedContainsArgs{
		Path: filepath.Join(cronPath, ".missing"), Text: "x",
	})
	if err != nil || got != false {
		t.Fatalf("missing contains = %#v, %v", got, err)
	}
	if len(runner.calls) != before {
		t.Fatalf("unexpected call for missing file")
	}
}

func TestPatchArgv(t *testing.T) {
	savedWhich := lookPathBin
	lookPathBin = func(name string) string {
		if name == "patch" {
			return "/usr/bin/patch"
		}
		return ""
	}
	t.Cleanup(func() { lookPathBin = savedWhich })

	tmpDir := t.TempDir()
	origFile := filepath.Join(tmpDir, "file.txt")
	patchFile := filepath.Join(tmpDir, "f.patch")
	dirTarget := filepath.Join(tmpDir, "dir")
	if err := os.WriteFile(origFile, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchFile, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirTarget, 0o755); err != nil {
		t.Fatal(err)
	}

	rt, runner := sedRT(t, map[string]string{}, 0)

	resRaw, perr := patchFunc{}.Execute(context.Background(), rt, &patchArgs{
		OriginalFile: origFile, PatchFile: patchFile,
	})
	if perr != nil {
		t.Fatal(perr)
	}
	res := resRaw.(map[string]any)
	if res["retcode"] != 0 {
		t.Fatalf("result = %#v", res)
	}
	call := strings.Join(runner.calls[0], " ")
	for _, piece := range []string{
		"/usr/bin/patch --forward --reject-file=- -i " + patchFile + " " + origFile,
	} {
		if !strings.Contains(call, piece) {
			t.Fatalf("argv missing %q: %s", piece, call)
		}
	}

	// Directory target adds -d and --strip=0.
	_, perr = patchFunc{}.Execute(context.Background(), rt, &patchArgs{
		OriginalFile: dirTarget, PatchFile: patchFile,
	})
	if perr != nil {
		t.Fatal(perr)
	}
	last := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if !strings.Contains(last, "-d "+dirTarget+" --strip=0") {
		t.Fatalf("directory flags missing: %s", last)
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
