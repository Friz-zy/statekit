package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	"gopkg.in/yaml.v3"
)

func zypperLocksPlain(value any) any {
	if ordered, ok := value.(zypperOrderedMap); ok {
		return ordered.asMap()
	}
	return value
}

func zypperLocksRuntime(t *testing.T, root, content string, result process.CommandResult) (*runtime.Runtime, *yumRecordingRunner, *zypperLocksWriteFS) {
	t.Helper()
	memory := runtime.NewMemoryFS()
	lockPath := zypperLocksPath(root)
	if err := memory.MkdirAll(path.Dir(lockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile(lockPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys := &zypperLocksWriteFS{MemoryFS: memory}
	runner := &yumRecordingRunner{results: []process.CommandResult{result}}
	return &runtime.Runtime{Runner: runner, FS: fsys}, runner, fsys
}

type zypperLocksWriteFS struct {
	*runtime.MemoryFS
	writes int
}

func (f *zypperLocksWriteFS) WriteFile(name string, data []byte, perm fs.FileMode) error {
	f.writes++
	return f.MemoryFS.WriteFile(name, data, perm)
}

type zypperLocksReadErrorFS struct {
	*runtime.MemoryFS
	err    error
	cancel context.CancelFunc
	reads  int
}

func (f *zypperLocksReadErrorFS) ReadFileBounded(string, int64) ([]byte, error) {
	f.reads++
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	return nil, f.err
}

func TestZypperListLocksSourceParsingAndSafeFilesystemBoundary(t *testing.T) {
	root := "/target"
	content := "solvable_name: alpha\nCaseSensitive: yes\nmatch_type: exact\nmatch_type: first\n\n" +
		"solvable_name: beta\nsource: repo:updates\ntype: package\n\n" +
		"malformed line\nsolvable_name: alpha\nCaseSensitive: no\nnew_attr: last\n\n" +
		"solvable_name:\nignored: empty-name\n"
	rt, runner, fsys := zypperLocksRuntime(t, root, content, process.CommandResult{})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_locks", map[string]any{"root": root})
	want := map[string]any{
		"alpha": map[string]any{"CaseSensitive": "no", "new_attr": "last"},
		"beta":  map[string]any{"source": "repo:updates", "type": "package"},
	}
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), want) || len(runner.commands) != 0 || fsys.writes != 0 {
		t.Fatalf("got=%#v err=%v runner=%d writes=%d want=%#v", got, err, len(runner.commands), fsys.writes, want)
	}
	if _, err := fsys.ReadFileBounded(zypperLocksPath(root), zypperLowpkgOutputLimit); err != nil {
		t.Fatal(err)
	}

	missing := runtime.NewMemoryFS()
	missingRT := &runtime.Runtime{Runner: &zypperNoCallRunner{}, FS: missing}
	got, err = zypperLowpkgProvider().Zypper(context.Background(), missingRT, "list_locks", map[string]any{"root": root})
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), map[string]any{}) || missingRT.Runner.(*zypperNoCallRunner).calls != 0 {
		t.Fatalf("missing got=%#v err=%v runner=%d", got, err, missingRT.Runner.(*zypperNoCallRunner).calls)
	}

	if err := missing.MkdirAll(path.Dir(zypperLocksPath(root)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := missing.Symlink("/outside", zypperLocksPath(root)); err != nil {
		t.Fatal(err)
	}
	got, err = zypperLowpkgProvider().Zypper(context.Background(), missingRT, "list_locks", map[string]any{"root": root})
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), map[string]any{}) {
		t.Fatalf("unreadable got=%#v err=%v", got, err)
	}
}

func TestZypperParseLocksNormalizesTextModeNewlines(t *testing.T) {
	lf := "solvable_name: alpha\nkind: first\n\nsolvable_name: beta\nkind: second\n"
	want := map[string]any{
		"alpha": map[string]any{"kind": "first"},
		"beta":  map[string]any{"kind": "second"},
	}
	for _, tc := range []struct {
		name    string
		content string
	}{
		{name: "LF", content: lf},
		{name: "CRLF", content: strings.ReplaceAll(lf, "\n", "\r\n")},
		{name: "CR", content: strings.ReplaceAll(lf, "\n", "\r")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := zypperParseLocks(context.Background(), tc.content)
			if err != nil || !reflect.DeepEqual(got.asMap(), want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
		})
	}
}

func TestZypperParseLocksPreservesPythonDictOrderAtSerializationBoundary(t *testing.T) {
	content := "solvable_name: beta\nfirst: old\nsecond: two\nfirst: last\n\n" +
		"solvable_name: alpha\nfirst: a\n\n" +
		"solvable_name: beta\nfirst: replaced\n"
	got, err := zypperParseLocks(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"beta":{"first":"replaced"},"alpha":{"first":"a"}}`
	if string(encoded) != wantJSON {
		t.Fatalf("json=%s want=%s", encoded, wantJSON)
	}
	var shape map[string]map[string]string
	if err := json.Unmarshal(encoded, &shape); err != nil || !reflect.DeepEqual(shape, map[string]map[string]string{
		"alpha": {"first": "a"},
		"beta":  {"first": "replaced"},
	}) {
		t.Fatalf("shape=%#v err=%v", shape, err)
	}
	yamlEncoded, err := yaml.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if beta, alpha := strings.Index(string(yamlEncoded), "beta:"), strings.Index(string(yamlEncoded), "alpha:"); beta < 0 || alpha < 0 || beta > alpha {
		t.Fatalf("yaml=%s", yamlEncoded)
	}
}

func TestZypperListLocksBoundsRootAndProviderGates(t *testing.T) {
	root := "/target"
	fsys := runtime.NewMemoryFS()
	lockPath := zypperLocksPath(root)
	if err := fsys.MkdirAll(path.Dir(lockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(lockPath, []byte(strings.Repeat("x\n", zypperLowpkgMaxItems+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &zypperNoCallRunner{}
	rt := &runtime.Runtime{Runner: runner, FS: fsys}
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "list_locks", map[string]any{"root": root})
	if err != nil || !reflect.DeepEqual(zypperLocksPlain(got), map[string]any{}) || runner.calls != 0 {
		t.Fatalf("bounded got=%#v err=%v runner=%d", got, err, runner.calls)
	}

	for _, unsafeRoot := range []string{"../escape", "/target/../escape", "/target\\..\\escape"} {
		runner := &zypperNoCallRunner{}
		got, err := zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: runner, FS: fsys}, "list_locks", map[string]any{"root": unsafeRoot})
		if got != nil || err == nil || strings.Contains(err.Error(), unsafeRoot) || runner.calls != 0 {
			t.Fatalf("root=%q got=%#v err=%v runner=%d", unsafeRoot, got, err, runner.calls)
		}
	}

	for _, manager := range []string{"apt", "yum"} {
		runner := &zypperNoCallRunner{}
		got, err := (&commandProvider{spec: spec{manager: manager}}).Zypper(context.Background(), &runtime.Runtime{Runner: runner, FS: fsys}, "list_locks", map[string]any{})
		if got != nil || !errors.Is(err, ErrUnsupportedZypper) || runner.calls != 0 {
			t.Fatalf("manager=%s got=%#v err=%v runner=%d", manager, got, err, runner.calls)
		}
	}
}

func TestZypperCleanLocksMissingAndExactMutationBoundary(t *testing.T) {
	root := "/target"
	rt, runner, fsys := zypperLocksRuntime(t, root, "", process.CommandResult{
		Stdout: []byte(`<stream><message type="info">Removed Demo</message><message>removed ignored</message></stream>`),
	})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "clean_locks", map[string]any{"root": root})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"removed": "demo"}) || len(runner.commands) != 1 {
		t.Fatalf("got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	wantArgv := []string{"zypper", "--non-interactive", "--xmlout", "--no-refresh", "--root", root, "cl"}
	if !reflect.DeepEqual(zypperCommandArgs(runner.commands[0]), wantArgv) {
		t.Fatalf("argv=%v want=%v", zypperCommandArgs(runner.commands[0]), wantArgv)
	}
	command := runner.commands[0]
	if command.Shell || command.MaxStdoutBytes != zypperLowpkgOutputLimit || command.MaxStderrBytes != zypperLowpkgOutputLimit || !reflect.DeepEqual(command.Env, []string{"LC_ALL=C"}) {
		t.Fatalf("unsafe mutation command=%#v", command)
	}
	if fsys.writes != 0 {
		t.Fatalf("clean_locks wrote through FS: %d", fsys.writes)
	}

	missing := runtime.NewMemoryFS()
	noCall := &zypperNoCallRunner{}
	got, err = zypperLowpkgProvider().Zypper(context.Background(), &runtime.Runtime{Runner: noCall, FS: missing}, "clean_locks", map[string]any{"root": root})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"removed": 0}) || noCall.calls != 0 {
		t.Fatalf("missing got=%#v err=%v calls=%d", got, err, noCall.calls)
	}
}

func TestZypperCleanLocksCancellationPrecedesReadErrorClassification(t *testing.T) {
	root := "/target"
	for _, tc := range []struct {
		name       string
		readErr    error
		cancelRead bool
	}{
		{name: "missing", readErr: fs.ErrNotExist},
		{name: "access", readErr: errors.New("permission denied")},
		{name: "cancel-missing", readErr: fs.ErrNotExist, cancelRead: true},
		{name: "cancel-access", readErr: errors.New("permission denied"), cancelRead: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.cancelRead {
				ctx, cancel = context.WithCancel(ctx)
			}
			fsys := &zypperLocksReadErrorFS{MemoryFS: runtime.NewMemoryFS(), err: tc.readErr, cancel: cancel}
			runner := &zypperNoCallRunner{}
			rt := &runtime.Runtime{Runner: runner, FS: fsys}
			got, err := zypperLowpkgProvider().Zypper(ctx, rt, "clean_locks", map[string]any{"root": root})
			if tc.cancelRead {
				if got != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("got=%#v err=%v, want context.Canceled", got, err)
				}
			} else if errors.Is(tc.readErr, fs.ErrNotExist) {
				if err != nil || !reflect.DeepEqual(got, map[string]any{"removed": 0}) {
					t.Fatalf("missing got=%#v err=%v", got, err)
				}
			} else if got != nil || err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("access got=%#v err=%v", got, err)
			}
			if fsys.reads != 1 || runner.calls != 0 {
				t.Fatalf("reads=%d runner calls=%d", fsys.reads, runner.calls)
			}
		})
	}
}

func TestZypperCleanLocksMessagesErrorsCancellationAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output string
		want   any
	}{
		{"empty-stream", `<stream/>`, map[string]any{"removed": 0}},
		{"count-token", `<stream><message>removed 3 locks</message></stream>`, map[string]any{"removed": "3"}},
		{"non-removed", `<stream><message>Nothing changed</message></stream>`, map[string]any{"removed": 0}},
		{"first-removed-wins", `<stream><message>Removed first</message><message>removed second</message><message>removed</message></stream>`, map[string]any{"removed": "first"}},
		{"later-message-is-not-inspected", `<stream><message>Removed first</message><message/></stream>`, map[string]any{"removed": "first"}},
		{"later-missing-token-is-not-inspected", `<stream><message>Removed first</message><message>Removed</message></stream>`, map[string]any{"removed": "first"}},
		{"prefixed-message-is-ignored", `<stream xmlns:p="urn:probe"><p:message>Removed prefixed</p:message><message>Removed plain</message></stream>`, map[string]any{"removed": "plain"}},
		{"processing-instruction-first-child", `<stream><message><?probe Removed 3?></message></stream>`, map[string]any{"removed": "3"}},
		{"cdata-first-child", `<stream><message><![CDATA[Removed cdata]]></message></stream>`, map[string]any{"removed": "cdata"}},
		{"text-before-cdata-stays-first", `<stream><message>Removed <![CDATA[cdata]]></message></stream>`, map[string]any{"removed": ""}},
		{"comment-first-child", `<stream><message><!--Removed comment-->Removed later</message></stream>`, map[string]any{"removed": "comment"}},
		{"comment-prevents-later-text", `<stream><message><!--not removed-->Removed later</message></stream>`, map[string]any{"removed": 0}},
		{"repeated-space-empty-token", `<stream><message>Removed  demo</message></stream>`, map[string]any{"removed": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner, _ := zypperLocksRuntime(t, "", "present", process.CommandResult{Stdout: []byte(tc.output)})
			got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "clean_locks", map[string]any{})
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(runner.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d want=%#v", got, err, len(runner.commands), tc.want)
			}
		})
	}
	splitRT, splitRunner, _ := zypperLocksRuntime(t, "", "present", process.CommandResult{Stdout: []byte(`<stream><message>Removed</message></stream>`)})
	got, err := zypperLowpkgProvider().Zypper(context.Background(), splitRT, "clean_locks", map[string]any{})
	if got != nil || err == nil || len(splitRunner.commands) != 1 {
		t.Fatalf("missing split token got=%#v err=%v calls=%d", got, err, len(splitRunner.commands))
	}

	for _, result := range []process.CommandResult{
		{Err: errors.New("runner failed")},
		{ExitCode: 7, Stdout: []byte(`<stream><message>removed fake</message></stream>`)},
		{StdoutTruncated: true},
		{StderrTruncated: true},
		{Stdout: make([]byte, zypperLowpkgOutputLimit+1)},
	} {
		rt, runner, _ := zypperLocksRuntime(t, "", "present", result)
		got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "clean_locks", map[string]any{})
		if got != nil || err == nil || len(runner.commands) != 1 {
			t.Fatalf("result=%#v got=%#v err=%v calls=%d", result, got, err, len(runner.commands))
		}
	}

	rt, runner, _ := zypperLocksRuntime(t, "", "present", process.CommandResult{Stdout: []byte(`<stream>`)})
	if got, err := zypperLowpkgProvider().Zypper(context.Background(), rt, "clean_locks", map[string]any{}); got != nil || err == nil || len(runner.commands) != 1 {
		t.Fatalf("malformed XML got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}
	mismatch := `<stream><message>Removed first</message><broken></stream>`
	if got, err := zypperParseCleanLocks(context.Background(), mismatch); got != nil || err == nil || strings.Contains(err.Error(), mismatch) || strings.Contains(err.Error(), "Removed demo") {
		t.Fatalf("mismatched XML got=%#v err=%v", got, err)
	}

	deep := `<stream>` + strings.Repeat(`<node>`, zypperSearchMaxXMLDepth) + strings.Repeat(`</node>`, zypperSearchMaxXMLDepth) + `</stream>`
	if got, err := zypperParseCleanLocks(context.Background(), deep); got != nil || !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("depth-bounded XML got=%#v err=%v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner, _ = zypperLocksRuntime(t, "", "present", process.CommandResult{})
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "clean_locks", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(runner.commands) != 0 {
		t.Fatalf("pre-cancel got=%#v err=%v calls=%d", got, err, len(runner.commands))
	}

	ctx, cancel = context.WithCancel(context.Background())
	canceling := &zypperLocksCancelRunner{cancel: cancel}
	rt, _, _ = zypperLocksRuntime(t, "", "present", process.CommandResult{})
	rt.Runner = canceling
	if got, err := zypperLowpkgProvider().Zypper(ctx, rt, "clean_locks", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(canceling.commands) != 1 {
		t.Fatalf("post-cancel got=%#v err=%v calls=%d", got, err, len(canceling.commands))
	}
}

func TestZypperParseCleanLocksCancellationIsCheckedBeforeTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := zypperParseCleanLocks(ctx, `<stream><message>Removed demo</message></stream>`); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got=%#v err=%v, want context.Canceled", got, err)
	}
}

type zypperLocksCancelRunner struct {
	commands []process.Command
	cancel   context.CancelFunc
}

func (r *zypperLocksCancelRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	r.cancel()
	return process.CommandResult{Stdout: []byte(`<stream><message>removed fake</message></stream>`)}
}
