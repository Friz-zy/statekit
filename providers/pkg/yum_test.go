package pkg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type yumFixtureDirEntry struct {
	name     string
	typeBits fs.FileMode
}

func (e yumFixtureDirEntry) Name() string      { return e.name }
func (e yumFixtureDirEntry) IsDir() bool       { return e.typeBits&fs.ModeDir != 0 }
func (e yumFixtureDirEntry) Type() fs.FileMode { return e.typeBits }
func (e yumFixtureDirEntry) Info() (fs.FileInfo, error) {
	return yumFixtureInfo{name: e.name, mode: e.typeBits}, nil
}

type yumFixtureInfo struct {
	name string
	mode fs.FileMode
}

func (i yumFixtureInfo) Name() string       { return i.name }
func (i yumFixtureInfo) Size() int64        { return 7 }
func (i yumFixtureInfo) Mode() fs.FileMode  { return i.mode }
func (i yumFixtureInfo) ModTime() time.Time { return time.Unix(123, 0) }
func (i yumFixtureInfo) IsDir() bool        { return i.mode.IsDir() }
func (i yumFixtureInfo) Sys() any           { return nil }

type yumFixtureFS struct {
	*runtime.MemoryFS
	entries []fs.DirEntry
	info    map[string]fs.FileInfo
	lstats  []string
	stats   []string
	root    string
}

func (f *yumFixtureFS) ReadDirBounded(name string, _ int) ([]fs.DirEntry, error) {
	if name == f.root {
		return f.entries, nil
	}
	return nil, nil
}
func (f *yumFixtureFS) Lstat(name string) (fs.FileInfo, error) {
	f.lstats = append(f.lstats, name)
	if info, ok := f.info[name]; ok {
		return info, nil
	}
	return nil, fs.ErrNotExist
}
func (f *yumFixtureFS) Stat(name string) (fs.FileInfo, error) {
	f.stats = append(f.stats, name)
	return f.MemoryFS.Stat(name)
}

func TestYumDownloadedRejectsDirEntryNonregularAndLstatNonregular(t *testing.T) {
	root := "/var/cache/yum"
	names := []struct {
		name string
		mode fs.FileMode
	}{
		{"pipe.rpm", fs.ModeNamedPipe}, {"device.rpm", fs.ModeDevice},
		{"socket.rpm", fs.ModeSocket}, {"char.rpm", fs.ModeCharDevice},
		{"symlink.rpm", fs.ModeSymlink}, {"directory.rpm", fs.ModeDir},
	}
	entries := make([]fs.DirEntry, 0, len(names)+2)
	for _, tc := range names {
		entries = append(entries, yumFixtureDirEntry{name: tc.name, typeBits: tc.mode})
	}
	lateSymlink := root + "/late-symlink.rpm"
	regular := root + "/regular.rpm"
	entries = append(entries, yumFixtureDirEntry{name: "late-symlink.rpm"}, yumFixtureDirEntry{name: "regular.rpm"})
	fsys := &yumFixtureFS{MemoryFS: runtime.NewMemoryFS(), root: root, entries: entries, info: map[string]fs.FileInfo{
		lateSymlink: yumFixtureInfo{name: "late-symlink.rpm", mode: fs.ModeSymlink},
	}}
	if err := fsys.MemoryFS.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.MemoryFS.WriteFile(regular, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	fsys.info[regular], _ = fsys.MemoryFS.Lstat(regular)
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("demo_|-0_|-1_|-(none)_|-x86_64_|-none_|-0")}}}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{FS: fsys, Runner: r, Facts: factsForYUMTest()}, "list_downloaded", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fsys.lstats) != 2 || len(fsys.stats) != 0 || len(r.commands) != 1 || r.commands[0].Args[len(r.commands[0].Args)-1] != regular {
		t.Fatalf("lstat/stat/query candidates: lstats=%v stats=%v commands=%v", fsys.lstats, fsys.stats, r.commands)
	}
	if _, ok := got.(map[string]any)["demo"]; !ok {
		t.Fatalf("regular candidate missing: %#v", got)
	}
}

func TestYumGroupListMatchesPinnedRawLineParsing(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"plugin comment\n" +
			" Installed Groups: \n" +
			"INSTALLED GROUPS:\n" +
			"  Base  \n" +
			"Base\n" +
			"Available Groups:\n" +
			" Tools \n" +
			"Installed Environment Groups:\n" +
			" Server \n" +
			"Available Environment Groups:\n" +
			" Desktop \n" +
			"Available Language Groups:\n" +
			" English [en] \n" +
			"French [fr]\n" +
			"malformed [\n" +
			" Done \n" +
			"after-whitespace-done\n" +
			"DONE\n" +
			"ignored after done\n",
	)}}}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"installed":              []string{"Base", "Base"},
		"available":              []string{"Tools"},
		"installed environments": []string{"Server"},
		"available environments": []string{"Desktop"},
		"available languages": map[string]any{
			"English [en]": map[string]any{"name": "English", "language": "en"},
			"French [fr]":  map[string]any{"name": "French", "language": "fr"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
	if len(r.commands) != 1 || r.commands[0].Name != "yum" ||
		!reflect.DeepEqual(r.commands[0].Args, []string{"grouplist", "hidden"}) || r.commands[0].Shell ||
		r.commands[0].MaxStdoutBytes != yumGroupsOutputLimit || r.commands[0].MaxStderrBytes != yumGroupsOutputLimit {
		t.Fatalf("commands=%#v", r.commands)
	}
}

func TestYumListDownloadedUsesCacheAndRPMQuery(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/var/cache/dnf/nested", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/var/cache/dnf/nested/pkg.rpm", []byte("rpm"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/var/cache/dnf/nested/ignored.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("demo_|-1_|-2.3_|-1_|-x86_64_|-none_|-0")}}}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r}, "list_downloaded", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	meta := got.(map[string]any)["demo"].(map[string]any)["1:2.3-1"].(map[string]any)
	info, statErr := fs.Stat("/var/cache/dnf/nested/pkg.rpm")
	ctime, ctimeOK := fileCTime(info)
	if statErr != nil || !ctimeOK || meta["path"] != "/var/cache/dnf/nested/pkg.rpm" || meta["size"] != int64(3) || meta["creation_date_time_t"] != ctime.Unix() {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
	if len(r.commands) != 1 || !reflect.DeepEqual(r.commands[0].Args, []string{"-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}", "/var/cache/dnf/nested/pkg.rpm"}) {
		t.Fatalf("unexpected query: %#v", r.commands)
	}
}

func TestYumListDownloadedIgnoresAllKwargsWithoutChangingBehavior(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			makeRuntime := func(args map[string]any) (any, *yumRecordingRunner, map[string]any, error) {
				fs := runtime.NewMemoryFS()
				if err := fs.MkdirAll("/var/cache/"+manager+"/nested", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := fs.WriteFile("/var/cache/"+manager+"/nested/pkg.rpm", []byte("payload"), 0o640); err != nil {
					t.Fatal(err)
				}
				r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("demo_|-0_|-1_|-(none)_|-x86_64_|-none_|-0")}}}
				before := map[string]any{}
				for k, v := range args {
					before[k] = v
				}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r, Facts: factsForYUMTest()}, "list_downloaded", args)
				return got, r, before, err
			}
			plain, plainRunner, _, err := makeRuntime(map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			kwargs := map[string]any{"root": "/wrong", "unknown": map[string]any{"nested": true}}
			withKwargs, kwargsRunner, before, err := makeRuntime(kwargs)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plain, withKwargs) || !reflect.DeepEqual(plainRunner.commands, kwargsRunner.commands) || !reflect.DeepEqual(kwargs, before) {
				t.Fatalf("kwargs changed behavior: plain=%#v kwargs=%#v plainCommands=%#v kwargsCommands=%#v args=%#v", plain, withKwargs, plainRunner.commands, kwargsRunner.commands, kwargs)
			}
		})
	}
}

func factsForYUMTest() *facts.Facts {
	return facts.ForTesting(facts.Overrides{CPU: &facts.CPUFacts{Arch: "x86_64"}})
}

func TestYumListDownloadedTraversalMetadataAndBounds(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			fs := runtime.NewMemoryFS()
			root := "/var/cache/" + manager
			if err := fs.MkdirAll(root+"/nested", 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				root + "/a.rpm":        "first",
				root + "/nested/z.rpm": "last",
				root + "/noarch.rpm":   "third",
				root + "/ignored.txt":  "ignored",
			}
			for name, body := range files {
				if err := fs.WriteFile(name, []byte(body), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if err := fs.MkdirAll(root+"/directory.rpm", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fs.Symlink(root+"/nested", root+"/symlink.rpm"); err != nil {
				t.Fatal(err)
			}
			if err := fs.Symlink(root+"/a.rpm", root+"/final-symlink.rpm"); err != nil {
				t.Fatal(err)
			}
			r := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("demo_|-2_|-2.0_|-3_|-x86_64_|-none_|-0")},
				{Stdout: []byte("other_|-(none)_|-1.0_|-(none)_|-noarch_|-none_|-0")},
				{Stdout: []byte("demo_|-2_|-2.0_|-3_|-x86_64_|-none_|-0")},
			}}
			before := map[string]any{"root": "/not-used", "unknown": "ignored"}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r, Facts: factsForYUMTest()}, "list_downloaded", before)
			if err != nil {
				t.Fatal(err)
			}
			demo := got.(map[string]any)["demo"].(map[string]any)["2:2.0-3"].(map[string]any)
			info, err := fs.Stat(root + "/nested/z.rpm")
			if err != nil {
				t.Fatal(err)
			}
			ctime, ok := fileCTime(info)
			if !ok {
				t.Fatal("memory filesystem did not expose ctime")
			}
			wantTime := time.Unix(ctime.Unix(), 0).Local().Format("2006-01-02T15:04:05")
			if !reflect.DeepEqual(demo, map[string]any{"path": root + "/nested/z.rpm", "size": int64(4), "creation_date_time_t": ctime.Unix(), "creation_date_time": wantTime}) {
				t.Fatalf("duplicate/metadata result=%#v", demo)
			}
			other := got.(map[string]any)["other"].(map[string]any)["1.0"].(map[string]any)
			if other["path"] != root+"/noarch.rpm" || other["size"] != int64(5) {
				t.Fatalf("noarch result=%#v", other)
			}
			if len(r.commands) != 3 {
				t.Fatalf("queried non-RPM or nonregular entries: %#v", r.commands)
			}
			for _, command := range r.commands {
				if command.MaxStdoutBytes != yumDownloadedMetadataLimit || command.MaxStderrBytes != yumDownloadedMetadataLimit || !reflect.DeepEqual(command.Args[:3], []string{"-qp", "--queryformat", "%{NAME}_|-%{EPOCH}_|-%{VERSION}_|-%{RELEASE}_|-%{ARCH}_|-none_|-%{INSTALLTIME}"}) {
					t.Fatalf("unbounded or incorrect query=%#v", command)
				}
			}
			if !reflect.DeepEqual(before, map[string]any{"root": "/not-used", "unknown": "ignored"}) {
				t.Fatal("kwargs mutated")
			}
		})
	}
}

func TestYumListDownloadedQueryFailuresAndMalformedMetadata(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/var/cache/yum", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/var/cache/yum/a.rpm", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want error
	}{
		{"nonzero", process.CommandResult{ExitCode: 9, Stderr: []byte("query failed")}, errors.New("rpm exited with code 9: query failed")},
		{"runner", process.CommandResult{Err: context.Canceled}, context.Canceled},
		{"output-limit", process.CommandResult{Err: process.ErrOutputLimit}, process.ErrOutputLimit},
		{"malformed", process.CommandResult{Stdout: []byte("None")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{tc.res}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r, Facts: factsForYUMTest()}, "list_downloaded", map[string]any{})
			if tc.want != nil {
				matches := errors.Is(err, tc.want)
				if tc.name == "nonzero" {
					matches = err != nil && err.Error() == tc.want.Error()
				}
				if got != nil || !matches {
					t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
				}
			} else if err != nil || !reflect.DeepEqual(got, map[string]any{}) {
				t.Fatalf("malformed metadata got=%#v err=%v", got, err)
			}
		})
	}
}

func TestYumVerifySourceCompatibleArgvAndParsing(t *testing.T) {
	// Source reference: saltstack/salt/modules/rpm_lowpkg.py:159-253.
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("SM5DLUGTP  c /etc/demo\n"), ExitCode: 0}}}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", map[string]any{
		"root": "/target", "verify_options": "foo,bar", "ignore_types": []string{"doc"}, "names": []string{"demo"},
	})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"/etc/demo": map[string]any{"type": "config", "mismatch": []string{"size", "mode", "md5sum", "device major/minor number", "readlink path", "user", "group", "mtime", "capabilities"}}}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(r.commands) != 1 || !reflect.DeepEqual(append([]string{r.commands[0].Name}, r.commands[0].Args...), []string{"rpm", "--root", "/target", "--foo", "--bar", "-V", "demo"}) || r.commands[0].Shell {
		t.Fatalf("command=%#v", r.commands)
	}
}

func TestYumVerifyRejectsUnsafeOrWrongTypesBeforeRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	p := &commandProvider{spec: yumSpec}
	for _, args := range []map[string]any{
		{"verify_options": 1}, {"ignore_types": []any{"doc"}}, {"verify_options": ""},
		{"verify_options": "bad value"}, {"verify_options": "-x"}, {"names": ""}, {"root": "bad root"},
	} {
		if got, err := p.Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", args); got != nil || err == nil {
			t.Errorf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumVerifyRetcodeAndMalformedOutputHandling(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want any
		err  string
	}{
		{"empty success", process.CommandResult{}, map[string]any{}, ""},
		{"empty failure", process.CommandResult{ExitCode: 1}, nil, "Failed to verify package(s)"},
		{"parseable failure", process.CommandResult{ExitCode: 1, Stdout: []byte("SM5DLUGTP  c /etc/demo\n")}, map[string]any{"/etc/demo": map[string]any{"type": "config", "mismatch": []string{"size", "mode", "md5sum", "device major/minor number", "readlink path", "user", "group", "mtime", "capabilities"}}}, ""},
		{"short", process.CommandResult{Stdout: []byte("x\n")}, map[string]any{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{tc.res}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", map[string]any{})
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
		})
	}
}

func TestYumVerifyMapsEveryPinnedMismatchAndTypeMarker(t *testing.T) {
	flags := []struct{ flag, name string }{
		{"S", "size"}, {"M", "mode"}, {"5", "md5sum"}, {"D", "device major/minor number"},
		{"L", "readlink path"}, {"U", "user"}, {"G", "group"}, {"T", "mtime"}, {"P", "capabilities"},
	}
	for _, flag := range flags {
		for _, marker := range []struct{ raw, mapped string }{{"c", "config"}, {"d", "doc"}, {"g", "ghost"}, {"l", "license"}, {"r", "readme"}} {
			status := "         "
			for i, candidate := range []string{"S", "M", "5", "D", "L", "U", "G", "T", "P"} {
				if candidate == flag.flag {
					status = status[:i] + flag.flag + status[i+1:]
					break
				}
			}
			output := status + "  " + marker.raw + " /etc/demo"
			r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(output)}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", map[string]any{})
			want := map[string]any{"/etc/demo": map[string]any{"type": marker.mapped, "mismatch": []string{flag.name}}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s/%s got=%#v err=%v want=%#v", flag.flag, marker.raw, got, err, want)
			}
		}
	}
}

func TestYumVerifyIgnoreTypesScalarListAndCommaForms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ignore any
		want   map[string]any
	}{
		{"scalar", "doc", map[string]any{"/etc/config": map[string]any{"type": "config", "mismatch": []string{"size"}}, "/etc/ghost": map[string]any{"type": "ghost", "mismatch": []string{"size"}}}},
		{"list", []string{"doc", "ghost"}, map[string]any{"/etc/config": map[string]any{"type": "config", "mismatch": []string{"size"}}}},
		{"comma", "doc,ghost", map[string]any{"/etc/config": map[string]any{"type": "config", "mismatch": []string{"size"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := "S          c /etc/config\nS          d /etc/doc\nS          g /etc/ghost\n"
			r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(out)}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", map[string]any{"ignore_types": tc.ignore})
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
		})
	}
}

func TestYumVerifyMissingMalformedAndRetcodeCasesDoNotPanic(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name    string
		result  process.CommandResult
		want    any
		wantErr string
	}{
		{name: "missing", result: process.CommandResult{Stdout: []byte("missing     /etc/demo\n")}, want: map[string]any{"/etc/demo": map[string]any{"missing": true}}},
		{name: "malformed", result: process.CommandResult{Stdout: []byte("x\nshort\n123456789012\n")}, want: map[string]any{}},
		{name: "empty success", result: process.CommandResult{ExitCode: 0}, want: map[string]any{}},
		{name: "empty failure", result: process.CommandResult{ExitCode: 3}, wantErr: "Failed to verify package(s)"},
		{name: "parseable failure", result: process.CommandResult{ExitCode: 3, Stdout: []byte("S          c /etc/demo\n")}, want: map[string]any{"/etc/demo": map[string]any{"type": "config", "mismatch": []string{"size"}}}},
		{name: "runner", result: process.CommandResult{Err: sentinel}, wantErr: "runner failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{tc.result}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", map[string]any{})
			if tc.wantErr != "" {
				if got != nil || err == nil || err.Error() != tc.wantErr {
					t.Fatalf("got=%#v err=%v", got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
		})
	}
}

func TestYumVerifyForwardsSafeOptionsAndDoesNotMutateInputs(t *testing.T) {
	options := []string{"color", "nodigest"}
	ignore := []string{"doc"}
	args := map[string]any{"names": []string{"demo"}, "root": "/target", "verify_options": options, "ignore_types": ignore}
	before := map[string]any{"names": []string{"demo"}, "root": "/target", "verify_options": []string{"color", "nodigest"}, "ignore_types": []string{"doc"}}
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("S          c /etc/demo\n")}}}
	got, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", args)
	if err != nil || got == nil || !reflect.DeepEqual(args, before) {
		t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
	}
	if len(r.commands) != 1 || !reflect.DeepEqual(append([]string{r.commands[0].Name}, r.commands[0].Args...), []string{"rpm", "--root", "/target", "--color", "--nodigest", "-V", "demo"}) || r.commands[0].Shell {
		t.Fatalf("command=%#v", r.commands)
	}
}

func TestYumVerifyRejectsInvalidValuesBeforeRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	for _, args := range []map[string]any{
		{"verify_options": ""}, {"verify_options": "a,,b"}, {"verify_options": "a b"}, {"verify_options": "-x"},
		{"verify_options": []string{"a", "\t"}}, {"ignore_types": 1}, {"ignore_types": []any{"doc"}}, {"names": []any{"x"}},
	} {
		if got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "verify", args); got != nil || err == nil {
			t.Fatalf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumGroupInfoMatchesPinnedMetadataAndSections(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(
		"Group : Demo\nGroup-Id : demo.id\nDescription : desc\n" +
			"Mandatory Packages:\n zeta \n!alpha\n" +
			"Optional Packages:\n beta\nDefault Packages:\n gamma\nConditional Packages:\n delta\n",
	)}}}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{
		"name": "Demo", "fromrepo": "base", "expand": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"type": "package group", "group": "Demo", "id": "demo.id", "description": "desc",
		"mandatory": []string{"alpha", "zeta"}, "optional": []string{"beta"},
		"default": []string{"gamma"}, "conditional": []string{"delta"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
	if len(r.commands) != 1 || !reflect.DeepEqual(append([]string{r.commands[0].Name}, r.commands[0].Args...), []string{
		"dnf", "--quiet", "--disablerepo=*", "--enablerepo=base", "groupinfo", "Demo",
	}) || r.commands[0].Shell || r.commands[0].MaxStdoutBytes != yumGroupInfoOutputLimit {
		t.Fatalf("commands=%#v", r.commands)
	}
}

func TestYumGroupDiffUsesListAndExpandedGroupInfoWithoutMutatingSource(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("alpha 1\ngamma 1\n")},
		{Stdout: []byte("Group: Demo\nMandatory Packages:\n zeta\n alpha\nOptional Packages:\n beta\nDefault Packages:\n gamma\nConditional Packages:\n delta\n")},
	}}
	args := map[string]any{"name": "Demo", "fromrepo": "base", "enablerepo": []string{"extras"}, "disablerepo": "old"}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_diff", args)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"mandatory":   map[string]any{"installed": []string{"alpha"}, "not installed": []string{"zeta"}},
		"optional":    map[string]any{"installed": []string{}, "not installed": []string{"beta"}},
		"default":     map[string]any{"installed": []string{"gamma"}, "not installed": []string{}},
		"conditional": map[string]any{"installed": []string{}, "not installed": []string{"delta"}},
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, map[string]any{"name": "Demo", "fromrepo": "base", "enablerepo": []string{"extras"}, "disablerepo": "old"}) {
		t.Fatalf("got=%#v want=%#v args=%#v", got, want, args)
	}
	if len(r.commands) != 2 || !reflect.DeepEqual(r.commands[0].Args, []string{"-qa", "--qf", "%{NAME} %{VERSION}\n"}) ||
		!reflect.DeepEqual(append([]string{r.commands[1].Name}, r.commands[1].Args...), []string{"dnf", "--quiet", "--disablerepo=*", "--enablerepo=base", "groupinfo", "Demo"}) {
		t.Fatalf("commands=%#v", r.commands)
	}
}

func TestYumGroupDiffRejectsUnknownAndMalformedArgumentsBeforeRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	provider := &commandProvider{spec: yumSpec}
	for _, args := range []map[string]any{
		{"name": "Demo", "expand": true},
		{"name": 1},
		{"name": "Demo", "enablerepo": 1},
	} {
		if got, err := provider.Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_diff", args); got != nil || err == nil {
			t.Errorf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumGroupInfoSplitsOnlyLFAndOmitsTerminalEmptyLine(t *testing.T) {
	for _, tc := range []struct {
		output string
		want   []string
	}{
		{output: "", want: []string{}},
		{output: "a", want: []string{"a"}},
		{output: "a\n", want: []string{"a"}},
		{output: "a\n\n", want: []string{"a", ""}},
	} {
		if got := yumGroupInfoLines(tc.output); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("output=%q got=%#v want=%#v", tc.output, got, tc.want)
		}
	}

	for _, tc := range []struct {
		name, output          string
		wantMeta, wantPackage string
	}{
		{name: "lf", output: "Group : Demo\nDescription : desc\nMandatory Packages:\n pkg\n", wantMeta: "desc", wantPackage: "pkg"},
		{name: "cr", output: "Group : Demo\rvalue\nDescription : desc\rvalue\nMandatory Packages:\n pkg\rvalue\n", wantMeta: "desc\rvalue", wantPackage: "pkg\rvalue"},
		{name: "crlf", output: "Group : Demo\r\nDescription : desc\r\nMandatory Packages:\r\n pkg\r\n", wantMeta: "desc", wantPackage: "pkg"},
		{name: "vt", output: "Group : Demo\vvalue\nDescription : desc\vvalue\nMandatory Packages:\n pkg\vvalue\n", wantMeta: "desc\vvalue", wantPackage: "pkg\vvalue"},
		{name: "ff", output: "Group : Demo\fvalue\nDescription : desc\fvalue\nMandatory Packages:\n pkg\fvalue\n", wantMeta: "desc\fvalue", wantPackage: "pkg\fvalue"},
		{name: "nel", output: "Group : Demo\u0085value\nDescription : desc\u0085value\nMandatory Packages:\n pkg\u0085value\n", wantMeta: "desc\u0085value", wantPackage: "pkg\u0085value"},
		{name: "record separators", output: "Group : Demo\x1cvalue\nDescription : desc\x1dvalue\nMandatory Packages:\n pkg\x1evalue\n", wantMeta: "desc\x1dvalue", wantPackage: "pkg\x1evalue"},
		{name: "unicode separators", output: "Group : Demo\u2028value\nDescription : desc\u2029value\nMandatory Packages:\n pkg\u2028value\n", wantMeta: "desc\u2029value", wantPackage: "pkg\u2028value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(tc.output)}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Demo"})
			if err != nil {
				t.Fatal(err)
			}
			info := got.(map[string]any)
			if info["description"] != tc.wantMeta || !reflect.DeepEqual(info["mandatory"], []string{tc.wantPackage}) {
				t.Fatalf("got description=%q mandatory=%#v", info["description"], info["mandatory"])
			}
		})
	}

	// Provider parsing must be identical with and without the terminal LF.
	for _, output := range []string{"Group : Demo\nMandatory Packages:\n pkg\n", "Group : Demo\nMandatory Packages:\n pkg"} {
		r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(output)}}}
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Demo"})
		if err != nil || !reflect.DeepEqual(got.(map[string]any)["mandatory"], []string{"pkg"}) {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}
}

func TestYumGroupInfoExpansionUsesSharedSetsAndBareFallback(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("Environment Group : Demo\nEnvironment-ID : demo.id\nDescription : has: a colon\nMandatory Groups:\n Child\n Child\nOptional Groups:\n Bare\n")},
		{Stdout: []byte("Group : Child\nGroup-Id : child.id\nMandatory Packages:\n zeta\n alpha\n alpha\n")}, // @Child: not found is supplied below by the runner order
		{Stdout: []byte("Group : Child\nGroup-Id : child.id\nMandatory Packages:\n zeta\n alpha\n alpha\n")},
		{Stdout: []byte("Group : Bare\nMandatory Packages:\n beta\n")},
	}}
	// The first Child lookup must fail so the provider exercises @group then
	// bare fallback. The recording runner is replaced with an explicit queue.
	r.results[1] = process.CommandResult{}
	r.results[1].ExitCode = 1
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Demo", "expand": true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"type": "environment group", "group": "Demo", "id": "demo.id", "description": "",
		"mandatory": []string{"alpha", "zeta"}, "optional": []string{"beta"}, "default": []string{}, "conditional": []string{}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
	if len(r.commands) != 4 || r.commands[1].Args[len(r.commands[1].Args)-2] != "groupinfo" || r.commands[1].Args[len(r.commands[1].Args)-1] != "@Child" || r.commands[2].Args[len(r.commands[2].Args)-1] != "Child" {
		t.Fatalf("commands=%#v", r.commands)
	}
}

func TestYumGroupInfoExpansionCycleAndIgnoreGroupsAreFinite(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("Environment Group: Root\nMandatory Groups:\n A\nOptional Groups:\n B\n")},
		{Stdout: []byte("Environment Group: A\nMandatory Groups:\n B\n")},
		{Stdout: []byte("Environment Group: B\nMandatory Groups:\n A\n")},
	}}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Root", "expand": true})
	if err != nil || len(r.commands) != 3 || !reflect.DeepEqual(got.(map[string]any)["mandatory"], []string{}) {
		t.Fatalf("cycle got=%#v err=%v calls=%d", got, err, len(r.commands))
	}
	r = &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("Environment Group: Root\nMandatory Groups:\n A\n")}}}
	got, err = (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Root", "expand": true, "ignore_groups": []string{"A"}})
	if err != nil || len(r.commands) != 1 || !reflect.DeepEqual(got.(map[string]any)["mandatory"], []string{}) {
		t.Fatalf("ignored got=%#v err=%v calls=%d", got, err, len(r.commands))
	}
}

func TestYumGroupInfoRejectsMalformedEmptyRunnerAndCancellation(t *testing.T) {
	sentinel := errors.New("runner failure")
	cases := []struct {
		name string
		ctx  context.Context
		args map[string]any
		res  process.CommandResult
		want error
		text string
	}{
		{"empty", context.Background(), map[string]any{"name": "x"}, process.CommandResult{}, errYUMGroupNotFound, "Group 'x' not found"},
		{"malformed", context.Background(), map[string]any{"name": "x"}, process.CommandResult{Stdout: []byte("not group metadata")}, errYUMGroupNotFound, "Group 'x' not found"},
		{"runner", context.Background(), map[string]any{"name": "x"}, process.CommandResult{Err: sentinel}, sentinel, "runner failure"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cases = append(cases, struct {
		name string
		ctx  context.Context
		args map[string]any
		res  process.CommandResult
		want error
		text string
	}{"cancel", ctx, map[string]any{"name": "x"}, process.CommandResult{}, context.Canceled, "context canceled"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumContextRecordingRunner{results: []process.CommandResult{tc.res}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(tc.ctx, &runtime.Runtime{Runner: r}, "group_info", tc.args)
			if got != nil || !errors.Is(err, tc.want) || err.Error() != tc.text || len(r.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
		})
	}
}

func TestYumGroupInfoExpansionHasGlobalNodeAndDepthLimits(t *testing.T) {
	results := []process.CommandResult{}
	// Use distinct source names for a deterministic breadth of fallback calls.
	root := "Environment Group: Root\nMandatory Groups:\n"
	for i := 0; i < 300; i++ {
		root += fmt.Sprintf(" G%d\n", i)
		results = append(results, process.CommandResult{ExitCode: 1}, process.CommandResult{Stdout: []byte(fmt.Sprintf("Group: G%d\n", i))})
	}
	results[0] = process.CommandResult{Stdout: []byte(root)}
	r := &yumRecordingRunner{results: results}
	_, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Root", "expand": true})
	if err == nil || err.Error() != "YUM group_info recursion limit exceeded" || len(r.commands) != yumGroupMaxNodes {
		t.Fatalf("node limit err=%v calls=%d", err, len(r.commands))
	}

	results = []process.CommandResult{{Stdout: []byte("Environment Group: Root\nMandatory Groups:\n G0\n")}}
	for i := 0; i < 40; i++ {
		next := ""
		if i < 39 {
			next = fmt.Sprintf("Mandatory Groups:\n G%d\n", i+1)
		}
		results = append(results, process.CommandResult{Stdout: []byte("Environment Group: G" + fmt.Sprint(i) + "\n" + next)})
	}
	r = &yumRecordingRunner{results: results}
	_, err = (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_info", map[string]any{"name": "Root", "expand": true})
	if err == nil || err.Error() != "YUM group_info recursion limit exceeded" {
		t.Fatalf("depth limit err=%v calls=%d", err, len(r.commands))
	}
}

func TestYumGroupListEmptyNonzeroRunnerErrorAndCancellation(t *testing.T) {
	empty := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 19}}}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{Runner: empty}, "group_list", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, map[string]any{
		"installed": []string{}, "available": []string{}, "installed environments": []string{},
		"available environments": []string{}, "available languages": map[string]any{},
	}) {
		t.Fatalf("empty/nonzero got=%#v err=%v", got, err)
	}
	sentinel := errors.New("runner failure")
	failed := &yumRecordingRunner{results: []process.CommandResult{{Err: sentinel}}}
	got, err = (&commandProvider{spec: dnfSpec}).Yum(context.Background(), &runtime.Runtime{Runner: failed}, "group_list", map[string]any{})
	if got != nil || !errors.Is(err, sentinel) {
		t.Fatalf("runner error got=%#v err=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := &yumContextRecordingRunner{}
	got, err = (&commandProvider{spec: dnfSpec}).Yum(ctx, &runtime.Runtime{Runner: called}, "group_list", map[string]any{})
	if got != nil || !errors.Is(err, context.Canceled) || len(called.commands) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(called.commands))
	}
}

func TestYumGroupListSplitsOnlyTerminalSeparator(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         []string
	}{
		{
			name:   "lf",
			output: "Installed Groups:\nAlpha\n\nBeta\n",
			want:   []string{"Alpha", "", "Beta"},
		},
		{
			name:   "crlf",
			output: "Installed Groups:\r\nAlpha\r\n\r\nBeta\r\n",
			want:   []string{},
		},
		{
			name:   "no trailing separator",
			output: "Installed Groups:\nAlpha\n\nBeta",
			want:   []string{"Alpha", "", "Beta"},
		},
		{
			name:   "done",
			output: "Installed Groups:\nAlpha\nDone\n",
			want:   []string{"Alpha"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(tc.output)}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_list", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			groups := got.(map[string]any)["installed"].([]string)
			if !reflect.DeepEqual(groups, tc.want) {
				t.Fatalf("installed=%#v want=%#v", groups, tc.want)
			}
		})
	}
}

func TestYumGroupListKeepsRawCRLFMarkersUnrecognized(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         []string
	}{
		{
			name:   "crlf header",
			output: "Installed Groups:\r\nAlpha\n",
			want:   []string{},
		},
		{
			name:   "crlf done",
			output: "Installed Groups:\nBefore\r\nDone\r\nAfter\n",
			want:   []string{"Before", "Done", "After"},
		},
		{
			name:   "lf markers",
			output: "Installed Groups:\nBefore\nDone\nAfter\n",
			want:   []string{"Before"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte(tc.output)}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "group_list", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			groups := got.(map[string]any)["installed"].([]string)
			if !reflect.DeepEqual(groups, tc.want) {
				t.Fatalf("installed=%#v want %#v", groups, tc.want)
			}
		})
	}
}

func TestYumListHoldsPinnedParsing(t *testing.T) {
	for _, tc := range []struct {
		manager string
		output  string
		full    bool
		pattern string
		want    []string
	}{
		{"yum", "Loaded\n0:vim-enhanced-7.4.629-5.el6.x86_64.*\n0:vim-enhanced-7.4.629-5.el6.x86_64.*\n", true, "", []string{"0:vim-enhanced-7.4.629-5.el6.x86_64.*", "0:vim-enhanced-7.4.629-5.el6.x86_64.*"}},
		{"yum", "0:vim-enhanced-7.4.629-5.el6.x86_64.*\n", false, "", []string{"vim-enhanced"}},
		{"dnf", "vim-enhanced-2:7.4.827-1.fc22.x86_64.*\nother-1:2-3.x86_64.*\n", true, "vim", []string{"vim-enhanced-2:7.4.827-1.fc22.x86_64.*"}},
		{"dnf", "vim-enhanced-2:7.4.827-1.fc22.x86_64.*\n", false, "vim", []string{"vim-enhanced"}},
	} {
		t.Run(tc.manager+fmt.Sprint(tc.full)+tc.pattern, func(t *testing.T) {
			plugin := "yum-plugin-versionlock"
			if tc.manager == "dnf" {
				plugin = "python2-dnf-plugin-versionlock"
			}
			r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(tc.output)}}}
			a := map[string]any{"full": tc.full}
			if tc.pattern != "" {
				a["pattern"] = tc.pattern
			}
			got, err := (&commandProvider{spec: rpmSpec(tc.manager)}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", a)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			if len(r.commands) != 2 || r.commands[1].Shell || !reflect.DeepEqual(append([]string{r.commands[1].Name}, r.commands[1].Args...), []string{tc.manager, "versionlock", "list"}) {
				t.Fatalf("command=%#v", r.commands)
			}
		})
	}
}

func TestYumServicesNeedRestartUsesDNFAndSystemctlMapping(t *testing.T) {
	for _, manager := range []string{"dnf", "dnf5"} {
		r := &yumRecordingRunner{results: []process.CommandResult{
			{Stdout: []byte("123: one\n456: two\n123: duplicate\ninvalid: no\n")},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"sshd.service"}`), ExitCode: 0},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"cron.service"}`), ExitCode: 0},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"sshd.service"}`), ExitCode: 0},
			{Stdout: []byte(`{"_SYSTEMD_UNIT":"ignored.service"}`), ExitCode: 1},
		}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Init: "systemd"}), Runner: r}
		got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "services_need_restart", map[string]any{})
		if err != nil || !reflect.DeepEqual(got, []string{"cron", "sshd"}) {
			t.Fatalf("%s got=%#v err=%v", manager, got, err)
		}
		if len(r.commands) != 5 || r.commands[0].Name != manager || r.commands[0].Shell || r.commands[1].Name != "systemctl" {
			t.Fatalf("%s commands=%#v", manager, r.commands)
		}
	}
}

func TestYumServicesNeedRestartRejectsYumAndNonSystemdBeforeRunner(t *testing.T) {
	for _, tc := range []struct{ manager, init, want string }{
		{"yum", "systemd", "dnf or dnf5 is required to list outdated services."},
		{"apt", "systemd", "YUM capability is not supported by this package provider"},
		{"zypper", "systemd", "YUM capability is not supported by this package provider"},
		{"dnf", "openrc", "systemd is required to list outdated services."},
	} {
		r := &yumNoCallRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Init: tc.init}), Runner: r}
		_, err := (&commandProvider{spec: rpmSpec(tc.manager)}).Yum(context.Background(), rt, "services_need_restart", map[string]any{})
		if err == nil || err.Error() != tc.want || r.calls != 0 {
			t.Fatalf("%s/%s err=%v calls=%d", tc.manager, tc.init, err, r.calls)
		}
	}
}

func TestYumServicesNeedRestartSkipsBadMappingsAndPropagatesRunnerErrors(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("1: bad\n2: no-unit\n3: failed\n4: unsafe\n")},
		{Stdout: []byte("not json"), ExitCode: 0},
		{Stdout: []byte(`{"_SYSTEMD_UNIT":"target"}`), ExitCode: 0},
		{Stdout: []byte(`{"_SYSTEMD_UNIT":"bad.service"}`), ExitCode: 5},
		{Stdout: []byte(`{"_SYSTEMD_UNIT":"bad/name.service"}`), ExitCode: 0},
	}}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Init: "systemd"}), Runner: r}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), rt, "services_need_restart", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{"bad/name"}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	sentinel := errors.New("runner failed")
	r = &yumRecordingRunner{results: []process.CommandResult{{Err: sentinel}}}
	rt.Runner = r
	_, err = (&commandProvider{spec: dnfSpec}).Yum(context.Background(), rt, "services_need_restart", map[string]any{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runner error=%v", err)
	}
}

func TestYumListHoldsDefaultsValidationAndDNF5TOMLReadback(t *testing.T) {
	r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("yum-plugin-versionlock 1\n")}, {Stdout: []byte("0:vim-enhanced-7.4-1.x86_64.*\n")}}}
	p := &commandProvider{spec: rpmSpec("yum")}
	got, err := p.Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", map[string]any{})
	if err != nil || !reflect.DeepEqual(got, []string{"0:vim-enhanced-7.4-1.x86_64.*"}) {
		t.Fatalf("defaults got=%#v err=%v", got, err)
	}
	for _, bad := range []map[string]any{{"full": "yes"}, {"pattern": 1}, {"pattern": "["}} {
		before := len(r.commands)
		if _, err := p.Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", bad); err == nil || len(r.commands) != before {
			t.Fatalf("bad=%#v err=%v calls=%d", bad, err, len(r.commands))
		}
	}
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/etc/dnf/versionlock.toml", []byte("[[packages]]\nname = \"vim\"\n[[packages.conditions]]\nkey = \"evr\"\ncomparator = \"=\"\nvalue = \"7.4-1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dnfRunner := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
	got, err = (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: dnfRunner}, "list_holds", map[string]any{"full": false})
	if err != nil || !reflect.DeepEqual(got, []string{"vim"}) || len(dnfRunner.commands) != 1 {
		t.Fatalf("dnf5 got=%#v err=%v commands=%#v", got, err, dnfRunner.commands)
	}
}

func TestYumListHoldsDNF5IgnoresPatternAndSelectsFirstEqualityEVR(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
		t.Fatal(err)
	}
	valid := []byte(`[[packages]]
name = "alpha"
[[packages.conditions]]
key = "arch"
comparator = "="
value = "x86_64"
[[packages.conditions]]
key = "evr"
comparator = "="
value = "1-2"
[[packages.conditions]]
key = "evr"
comparator = "="
value = "9-9"
[[packages]]
name = "beta"
[[packages.conditions]]
key = "evr"
comparator = "!="
value = "2-3"
[[packages]]
name = "alpha"
[[packages.conditions]]
key = "repo"
comparator = "="
value = "base"
`)
	if err := fs.WriteFile("/etc/dnf/versionlock.toml", valid, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		full bool
		args map[string]any
		want []string
	}{
		{false, map[string]any{"full": false}, []string{"alpha", "beta"}},
		{true, map[string]any{"full": true}, []string{"alpha-0:1-2.*"}},
		{false, map[string]any{"full": false, "pattern": "^does-not-match$"}, []string{"alpha", "beta"}},
		{true, map[string]any{"full": true, "pattern": "["}, []string{"alpha-0:1-2.*"}},
	} {
		r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
		got, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r}, "list_holds", tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) || len(r.commands) != 1 {
			t.Fatalf("full=%v got=%#v err=%v calls=%d", tc.full, got, err, len(r.commands))
		}
	}
}

func TestYumDNF5VersionlockTOMLCompatibility(t *testing.T) {
	fs := runtime.NewMemoryFS()
	if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
		t.Fatal(err)
	}
	data := `# comments may not consume quoted hashes
[[packages]] # package header comment
"name" = "foo#bar"
[[packages.conditions]] # condition header comment
"key" = "other" # key/value comment
'comparator' = '='
'value' = 'ignored#value'
[[packages.conditions]]
"key" = 'evr'
'comparator' = "="
"value" = '1-2'
[[packages]]
"name" = "escaped \"quote\" and \\slash"
[[packages.conditions]]
"key" = "evr"
'comparator' = "="
"value" = "3-4"
`
	if err := fs.WriteFile(yumDNF5VersionlockPath, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		full bool
		want []string
	}{
		{false, []string{"foo#bar", `escaped "quote" and \slash`}},
		{true, []string{"foo#bar-0:1-2.*", `escaped "quote" and \slash-0:3-4.*`}},
	} {
		r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
		got, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r}, "list_holds", map[string]any{"full": tc.full, "pattern": "["})
		if err != nil || !reflect.DeepEqual(got, tc.want) || len(r.commands) != 1 || r.commands[0].Name != "rpm" {
			t.Fatalf("full=%v got=%#v err=%v commands=%#v", tc.full, got, err, r.commands)
		}
	}
	for _, malformed := range []string{"", "[[packages]]\nname = \"unterminated\n", "[[packages.conditions]]\nkey = \"evr\"\n"} {
		if err := fs.WriteFile(yumDNF5VersionlockPath, []byte(malformed), 0o644); err != nil {
			t.Fatal(err)
		}
		r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
		got, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r}, "list_holds", map[string]any{"full": false})
		if err != nil || !reflect.DeepEqual(got, []string{}) || len(r.commands) != 1 {
			t.Fatalf("malformed=%q got=%#v err=%v commands=%#v", malformed, got, err, r.commands)
		}
	}
}

func TestDNF5TOMLBasicStringPinnedEscapeMatrix(t *testing.T) {
	tests := []struct {
		name, token, want string
		valid             bool
	}{
		{"backslash", `"a\\b"`, "a\\b", true},
		{"quote", `"a\"b"`, `a"b`, true},
		{"backspace", `"a\bb"`, "a\bb", true},
		{"tab", `"a\tb"`, "a\tb", true},
		{"newline", `"a\nb"`, "a\nb", true},
		{"formfeed", `"a\fb"`, "a\fb", true},
		{"return", `"a\rb"`, "a\rb", true},
		{"unicode", `"\u03bb"`, "λ", true},
		{"unicode-wide", `"\U0001F642"`, "🙂", true},
		{"go-x", `"\x41"`, "", false},
		{"go-octal", `"\101"`, "", false},
		{"go-a", `"\a"`, "", false},
		{"go-v", `"\v"`, "", false},
		{"nul", "\"a" + string([]byte{0}) + "b\"", "", false},
		{"raw-tab", "\"a\t b\"", "", false},
		{"raw-newline", "\"a\nb\"", "", false},
		{"bad-hex", `"\u12G4"`, "", false},
		{"short-hex", `"\u123"`, "", false},
		{"surrogate", `"\uD800"`, "", false},
		{"too-wide", `"\U00110000"`, "", false},
		{"unknown", `"\q"`, "", false},
		{"trailing", `"ok"x`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := dnf5TOMLString(tc.token)
			if ok != tc.valid || (ok && got != tc.want) {
				t.Fatalf("token=%q got=%q valid=%v want=%q/%v", tc.token, got, ok, tc.want, tc.valid)
			}
			key, keyOK := dnf5TOMLKey(tc.token)
			if keyOK != tc.valid || (keyOK && key != tc.want) {
				t.Fatalf("key token=%q got=%q valid=%v want=%q/%v", tc.token, key, keyOK, tc.want, tc.valid)
			}
		})
	}
	for _, tc := range []struct {
		token string
		valid bool
	}{
		{`'literal#value'`, true}, {`'literal\\value'`, true}, {`'bad'quote'`, false},
	} {
		if _, ok := dnf5TOMLString(tc.token); ok != tc.valid {
			t.Fatalf("literal token=%q valid=%v want=%v", tc.token, ok, tc.valid)
		}
	}
}

func TestYumListHoldsDNF5ActualRegistryEscapeFixturesFailClosed(t *testing.T) {
	fixtures := []struct {
		name  string
		valid bool
	}{
		{`"pkg\\name"`, true}, {`"pkg\"name"`, true}, {`"pkg\b"`, true},
		{`"pkg\t"`, true}, {`"pkg\n"`, true}, {`"pkg\f"`, true}, {`"pkg\r"`, true},
		{`"pkg\u03bb"`, true}, {`"pkg\U0001F642"`, true},
		{`"pkg\x41"`, false}, {`"pkg\101"`, false}, {`"pkg\a"`, false},
		{`"pkg\v"`, false}, {`"pkg\uD800"`, false}, {`"pkg\U00110000"`, false},
		{`"pkg\u12G4"`, false}, {`"pkg\q"`, false},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			fs := runtime.NewMemoryFS()
			if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
				t.Fatal(err)
			}
			data := "[[packages]]\nname = " + tc.name + "\n[[packages.conditions]]\nkey = \"evr\"\ncomparator = \"=\"\nvalue = \"1-2\"\n"
			if err := fs.WriteFile(yumDNF5VersionlockPath, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("python2-dnf-plugin-versionlock 1\n")}}}
			got, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: fs, Runner: r}, "list_holds", map[string]any{"full": false, "pattern": "["})
			if err != nil || !tc.valid && !reflect.DeepEqual(got, []string{}) || tc.valid && len(got.([]string)) != 1 || len(r.commands) != 1 || r.commands[0].Name != "rpm" {
				t.Fatalf("valid=%v got=%#v err=%v commands=%#v", tc.valid, got, err, r.commands)
			}
		})
	}
}

func TestYumHoldNonzeroAddContinuesButRunnerErrorStops(t *testing.T) {
	results := []process.CommandResult{
		{Stdout: []byte("yum-plugin-versionlock 1\n")},
		{Stdout: []byte("yum-plugin-versionlock 1\n")},
		{},
		{ExitCode: 7},
		{},
	}
	r := &yumRecordingRunner{results: results}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"pkgs": []any{"first", "second"}})
	want := map[string]any{
		"first":  map[string]any{"name": "first", "changes": map[string]any{}, "result": false, "comment": "Package first was unable to be held."},
		"second": map[string]any{"name": "second", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package second is now being held."},
	}
	if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != 5 || r.commands[3].Args[2] != "first" || r.commands[4].Args[2] != "second" {
		t.Fatalf("continuation got=%#v err=%v commands=%#v", got, err, r.commands)
	}
	sentinel := errors.New("add runner failure")
	r = &yumRecordingRunner{results: []process.CommandResult{{Stdout: []byte("yum-plugin-versionlock 1\n")}, {Stdout: []byte("yum-plugin-versionlock 1\n")}, {}, {Err: sentinel}, {}}}
	got, err = (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "hold", map[string]any{"pkgs": []any{"first", "second"}})
	if got != nil || !errors.Is(err, sentinel) || len(r.commands) != 4 {
		t.Fatalf("runner stop got=%#v err=%v commands=%#v", got, err, r.commands)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cr := &yumHoldCancelRunner{cancel: cancel, results: []process.CommandResult{
		{Stdout: []byte("yum-plugin-versionlock 1\n")}, {Stdout: []byte("yum-plugin-versionlock 1\n")}, {}, {},
	}}
	got, err = (&commandProvider{spec: yumSpec}).Yum(ctx, &runtime.Runtime{Runner: cr}, "hold", map[string]any{"pkgs": []any{"first", "second"}})
	if got != nil || !errors.Is(err, context.Canceled) || len(cr.commands) != 4 {
		t.Fatalf("cancel stop got=%#v err=%v commands=%#v", got, err, cr.commands)
	}
}

func TestYumListHoldsChecksVersionlockPluginBeforeListing(t *testing.T) {
	for _, tc := range []struct {
		name, manager, osID, version, plugin string
	}{
		{"yum", "yum", "", "", "yum-plugin-versionlock"},
		{"fedora-old", "dnf", "fedora", "25", "python3-dnf-plugins-extras-versionlock"},
		{"fedora-new", "dnf", "fedora", "40", "python3-dnf-plugin-versionlock"},
		{"rhel-old", "dnf", "rhel", "7.9", "python2-dnf-plugin-versionlock"},
		{"rhel-new", "dnf", "rhel", "9.4", "python3-dnf-plugin-versionlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &listHoldsRunner{results: []process.CommandResult{
				{Stdout: []byte(tc.plugin + " 1\n")},
				{Stdout: []byte("held-1-1.x86_64.*\n")},
			}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{ID: tc.osID, Family: facts.FamilyRedHat, Version: tc.version}})}
			if _, err := (&commandProvider{spec: rpmSpec(tc.manager)}).Yum(context.Background(), rt, "list_holds", map[string]any{}); err != nil {
				t.Fatal(err)
			}
			if len(r.commands) != 2 || r.commands[0].Name != "rpm" || r.commands[1].Name != tc.manager {
				t.Fatalf("command order=%#v", r.commands)
			}
			if got := append([]string{r.commands[0].Name}, r.commands[0].Args...); !reflect.DeepEqual(got, []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}) {
				t.Fatalf("plugin query=%v", got)
			}
		})
	}

	r := &listHoldsRunner{results: []process.CommandResult{{Stdout: []byte("other 1\n")}}}
	_, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", map[string]any{})
	if err == nil || err.Error() != "Cannot proceed, yum-plugin-versionlock is not installed." || len(r.commands) != 1 {
		t.Fatalf("absent plugin err=%v commands=%#v", err, r.commands)
	}
}

func TestYumListHoldsRetcodesAndMalformedLinesFollowSource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		listResult process.CommandResult
		full       bool
		want       []string
		wantErr    error
	}{
		{name: "zero full", listResult: process.CommandResult{Stdout: []byte("Loaded\n0:vim-enhanced-7.4-1.x86_64.*\nmalformed\n")}, full: true, want: []string{"0:vim-enhanced-7.4-1.x86_64.*"}},
		{name: "zero full false", listResult: process.CommandResult{Stdout: []byte("0:vim-enhanced-7.4-1.x86_64.*\n")}, want: []string{"vim-enhanced"}},
		{name: "nonzero still returns command stdout", listResult: process.CommandResult{ExitCode: 17, Stderr: []byte("versionlock unavailable"), Stdout: []byte("0:vim-enhanced-7.4-1.x86_64.*\n")}, want: []string{"vim-enhanced"}},
		{name: "empty", listResult: process.CommandResult{ExitCode: 0}, want: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &listHoldsRunner{results: []process.CommandResult{
				{ExitCode: 0, Stdout: []byte("yum-plugin-versionlock 1\n")},
				tc.listResult,
			}}
			a := map[string]any{"full": tc.full}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", a)
			if !reflect.DeepEqual(got, tc.want) || !errors.Is(err, tc.wantErr) {
				t.Fatalf("got=%#v err=%v want=%#v/%v", got, err, tc.want, tc.wantErr)
			}
			if len(r.commands) != 2 || r.commands[0].Name != "rpm" || r.commands[1].Name != "yum" ||
				!reflect.DeepEqual(r.commands[1].Args, []string{"versionlock", "list"}) || r.commands[1].Shell ||
				r.commands[1].MaxStdoutBytes != yumHoldOutputLimit || r.commands[1].MaxStderrBytes != yumHoldOutputLimit {
				t.Fatalf("commands=%#v", r.commands)
			}
		})
	}
}

func TestYumListHoldsStopsAfterPluginOrListRunnerFailure(t *testing.T) {
	sentinel := errors.New("runner failure")
	cases := []struct {
		name    string
		results []process.CommandResult
		wantErr error
		calls   int
		cancel  bool
	}{
		{name: "plugin runner error", results: []process.CommandResult{{Err: sentinel}}, wantErr: sentinel, calls: 1},
		{name: "plugin cancellation", results: []process.CommandResult{{}}, wantErr: context.Canceled, calls: 1, cancel: true},
		{name: "list runner error", results: []process.CommandResult{{Stdout: []byte("yum-plugin-versionlock 1\n")}, {Err: sentinel}}, wantErr: sentinel, calls: 2},
		{name: "list cancellation", results: []process.CommandResult{{Stdout: []byte("yum-plugin-versionlock 1\n")}, {}}, wantErr: context.Canceled, calls: 2, cancel: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &listHoldsRunner{results: tc.results}
			if tc.cancel {
				r.cancel = cancel
				if tc.calls == 1 {
					cancel()
				}
			}
			got, err := (&commandProvider{spec: yumSpec}).Yum(ctx, &runtime.Runtime{Runner: r}, "list_holds", map[string]any{})
			if got != nil || !errors.Is(err, tc.wantErr) || len(r.commands) != tc.calls {
				t.Fatalf("got=%#v err=%v calls=%d want err=%v calls=%d", got, err, len(r.commands), tc.wantErr, tc.calls)
			}
			if len(r.commands) > 0 && r.commands[0].Name != "rpm" {
				t.Fatalf("command order=%#v", r.commands)
			}
			if len(r.commands) == 2 && r.commands[1].Name != "yum" {
				t.Fatalf("command order=%#v", r.commands)
			}
		})
	}
}

func TestYumListHoldsRejectsTDNFBeforeRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	_, err := (&commandProvider{spec: rpmSpec("tdnf")}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "list_holds", map[string]any{})
	if err == nil || err.Error() != "Cannot proceed, no versionlock for tdnf" || r.calls != 0 {
		t.Fatalf("tdnf err=%v calls=%d", err, r.calls)
	}
}

func TestYumHoldUsesBoundedPreflightAndExactMutationContract(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			plugin := "yum-plugin-versionlock"
			if manager != "yum" {
				plugin = "python2-dnf-plugin-versionlock"
			}
			r := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte(plugin + " 1\nalpha 1\n")},
				{Stdout: []byte(plugin + " 1\nalpha 1\n")},
				{Stdout: []byte("0:alpha-1-1.x86_64.*\n")},
				{},
			}}
			rt := &runtime.Runtime{Runner: r}
			if manager == "dnf5" {
				fs := runtime.NewMemoryFS()
				if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := fs.WriteFile("/etc/dnf/versionlock.toml", []byte("[[packages]]\nname = \"alpha\"\n[[packages.conditions]]\nkey = \"evr\"\ncomparator = \"=\"\nvalue = \"1-1\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				rt.FS = fs
			}
			args := map[string]any{"name": "ignored", "pkgs": []any{"alpha", "beta"}, "normalize": true}
			before := map[string]any{"name": args["name"], "pkgs": append([]any(nil), args["pkgs"].([]any)...), "normalize": args["normalize"]}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "hold", args)
			want := map[string]any{
				"alpha": map[string]any{"name": "alpha", "changes": map[string]any{}, "result": true, "comment": "Package alpha is already set to be held."},
				"beta":  map[string]any{"name": "beta", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package beta is now being held."},
			}
			wantCalls := 4
			if manager == "dnf5" {
				wantCalls = 3
			}
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) || len(r.commands) != wantCalls {
				t.Fatalf("got=%#v err=%v args=%#v commands=%#v", got, err, args, r.commands)
			}
			wantArgv := [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {manager, "versionlock", "add", "beta"}}
			if manager != "dnf5" {
				wantArgv = [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {manager, "versionlock", "list"}, {manager, "versionlock", "add", "beta"}}
			} else {
				wantArgv = [][]string{{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}, {manager, "versionlock", "add", "beta"}}
			}
			for i, command := range r.commands {
				if !reflect.DeepEqual(append([]string{command.Name}, command.Args...), wantArgv[i]) || command.Shell || command.MaxStdoutBytes != yumHoldOutputLimit || command.MaxStderrBytes != yumHoldOutputLimit {
					t.Fatalf("command[%d]=%#v", i, command)
				}
			}
		})
	}
}

func TestYumHoldPreflightsBeforeRejectingConflictsAndMalformedTargets(t *testing.T) {
	for _, args := range []map[string]any{
		{"name": "x", "pkgs": []any{"x"}, "sources": []any{map[string]any{"y": "file"}}},
		{"pkgs": []any{1}}, {"sources": []any{"not-a-map"}}, {},
	} {
		r := &yumRecordingRunner{results: []process.CommandResult{
			{Stdout: []byte("yum-plugin-versionlock 1\n")},
			{Stdout: []byte{}},
		}}
		if _, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "hold", args); err == nil || len(r.commands) != 1 {
			t.Fatalf("args=%#v err=%v calls=%d", args, err, len(r.commands))
		}
		if r.commands[0].Name != "rpm" {
			t.Fatalf("preflight order=%#v", r.commands)
		}
	}
}

func TestYumHoldPinnedTestModeAndMappingShapes(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			plugin := "yum-plugin-versionlock"
			if manager != "yum" {
				plugin = "python2-dnf-plugin-versionlock"
			}
			newRuntime := func(results []process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
				r := &yumRecordingRunner{results: results}
				rt := &runtime.Runtime{Runner: r, Options: runtime.RuntimeOptions{Test: true}}
				if manager == "dnf5" {
					fs := runtime.NewMemoryFS()
					if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
						t.Fatal(err)
					}
					if err := fs.WriteFile(yumDNF5VersionlockPath, []byte("[[packages]]\nname = \"other\"\n"), 0o644); err != nil {
						t.Fatal(err)
					}
					rt.FS = fs
				}
				return rt, r
			}
			preflight := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}}
			rt, r := newRuntime(preflight)
			args := map[string]any{"pkgs": []any{"target"}}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "hold", args)
			want := map[string]any{"target": map[string]any{"name": "target", "changes": map[string]any{}, "result": nil, "comment": "Package target is set to be held."}}
			wantCalls := 3
			if manager == "dnf5" {
				wantCalls = 2
			}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != wantCalls {
				t.Fatalf("test mode got=%#v err=%v commands=%#v", got, err, r.commands)
			}
			for i, c := range r.commands {
				if c.Shell || c.MaxStdoutBytes != yumHoldOutputLimit || c.MaxStderrBytes != yumHoldOutputLimit {
					t.Fatalf("command[%d] unbounded=%#v", i, c)
				}
				want := []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
				if i == 2 {
					want = []string{manager, "versionlock", "list"}
				}
				if !reflect.DeepEqual(append([]string{c.Name}, c.Args...), want) {
					t.Fatalf("command[%d]=%v want %v", i, c, want)
				}
			}

			for _, tc := range []struct {
				name   string
				args   map[string]any
				target string
			}{
				{"pkgs-map", map[string]any{"pkgs": []any{map[string]any{"pkg-a": "1-1"}}}, "pkg-a"},
				{"sources-map", map[string]any{"sources": []any{map[string]string{"pkg-b": "file.rpm"}}}, "pkg-b"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := map[string]any{}
					for k, v := range tc.args {
						before[k] = v
					}
					rt, r := newRuntime([]process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}})
					got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "hold", tc.args)
					if err != nil || got.(map[string]any)[tc.target] == nil || !reflect.DeepEqual(tc.args, before) || len(r.commands) < 2 {
						t.Fatalf("accepted mapping got=%#v err=%v args=%#v commands=%d", got, err, tc.args, len(r.commands))
					}
				})
			}
			for _, tc := range []struct {
				name, key string
				args      map[string]any
			}{
				{"pkgs", "pkgs", map[string]any{"pkgs": []any{map[string]any{"a": "1", "b": "2"}}}},
				{"sources", "sources", map[string]any{"sources": []any{map[string]any{"a": "1", "b": "2"}}}},
			} {
				t.Run("reject-"+tc.name, func(t *testing.T) {
					before := map[string]any{tc.key: append([]any(nil), tc.args[tc.key].([]any)...)}
					rt, r := newRuntime([]process.CommandResult{{Stdout: []byte(plugin + " 1\n")}})
					got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "hold", tc.args)
					var unsupported *runtime.UnsupportedError
					if got != nil || !errors.As(err, &unsupported) || unsupported.Name != "pkg.hold "+tc.key+" multi-key mapping" || len(r.commands) != 1 || !reflect.DeepEqual(tc.args[tc.key], before[tc.key]) {
						t.Fatalf("rejection got=%#v err=%v commands=%#v args=%#v", got, err, r.commands, tc.args)
					}
				})
			}
		})
	}
}

func TestYumHoldPinnedAddRetcodeAndCancellationMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			plugin := "yum-plugin-versionlock"
			if manager != "yum" {
				plugin = "python2-dnf-plugin-versionlock"
			}
			results := []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}, {ExitCode: 9}, {}}
			if manager == "dnf5" {
				results = []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {ExitCode: 9}, {}}
			}
			r := &yumRecordingRunner{results: results}
			rt := &runtime.Runtime{Runner: r}
			if manager == "dnf5" {
				fs := runtime.NewMemoryFS()
				if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := fs.WriteFile(yumDNF5VersionlockPath, []byte("[[packages]]\nname = \"other\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				rt.FS = fs
			}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), rt, "hold", map[string]any{"pkgs": []any{"first", "second"}})
			want := map[string]any{
				"first":  map[string]any{"name": "first", "changes": map[string]any{}, "result": false, "comment": "Package first was unable to be held."},
				"second": map[string]any{"name": "second", "changes": map[string]any{"new": "hold", "old": ""}, "result": true, "comment": "Package second is now being held."},
			}
			wantCalls := 5
			if manager == "dnf5" {
				wantCalls = 4
			}
			if err != nil || !reflect.DeepEqual(got, want) || len(r.commands) != wantCalls {
				t.Fatalf("retcode got=%#v err=%v commands=%#v", got, err, r.commands)
			}
			for i, c := range r.commands {
				if c.Shell || c.MaxStdoutBytes != yumHoldOutputLimit || c.MaxStderrBytes != yumHoldOutputLimit {
					t.Fatalf("command[%d]=%#v", i, c)
				}
				want := []string{"rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"}
				if manager != "dnf5" && i == 2 {
					want = []string{manager, "versionlock", "list"}
				}
				if i == len(r.commands)-2 || i == len(r.commands)-1 {
					want = []string{manager, "versionlock", "add", []string{"first", "second"}[i-(len(r.commands)-2)]}
				}
				if !reflect.DeepEqual(append([]string{c.Name}, c.Args...), want) {
					t.Fatalf("command[%d]=%v want %v", i, c, want)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cr := &yumHoldCancelRunner{cancel: cancel, results: []process.CommandResult{{Stdout: []byte(plugin + " 1\n")}, {Stdout: []byte(plugin + " 1\n")}, {}, {}}}
			if manager == "dnf5" {
				fs := runtime.NewMemoryFS()
				if err := fs.MkdirAll("/etc/dnf", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := fs.WriteFile(yumDNF5VersionlockPath, []byte("[[packages]]\nname = \"other\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				rt = &runtime.Runtime{Runner: cr, FS: fs}
			} else {
				rt = &runtime.Runtime{Runner: cr}
			}
			got, err = (&commandProvider{spec: rpmSpec(manager)}).Yum(ctx, rt, "hold", map[string]any{"pkgs": []any{"first", "second"}})
			wantCalls = 4
			if manager == "dnf5" {
				wantCalls = 3
			}
			if got != nil || !errors.Is(err, context.Canceled) || len(cr.commands) != wantCalls || cr.commands[wantCalls-1].Args[2] != "first" {
				t.Fatalf("cancel got=%#v err=%v commands=%#v", got, err, cr.commands)
			}
			cancel()
		})
	}
}

type listHoldsRunner struct {
	results  []process.CommandResult
	commands []process.Command
	cancel   context.CancelFunc
}

func (r *listHoldsRunner) Run(ctx context.Context, c process.Command) process.CommandResult {
	r.commands = append(r.commands, c)
	if err := ctx.Err(); err != nil {
		return process.CommandResult{Err: err}
	}
	if r.cancel != nil && len(r.commands) == 1 {
		r.cancel()
	}
	if len(r.results) == 0 {
		return process.CommandResult{}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

type yumNoCallRunner struct{ calls int }

func (r *yumNoCallRunner) Run(context.Context, process.Command) process.CommandResult {
	r.calls++
	return process.CommandResult{}
}

type yumRecordingRunner struct {
	commands []process.Command
	results  []process.CommandResult
}

type yumHoldCancelRunner struct {
	commands []process.Command
	results  []process.CommandResult
	cancel   context.CancelFunc
}

func (r *yumHoldCancelRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	result := process.CommandResult{}
	if len(r.results) > 0 {
		result, r.results = r.results[0], r.results[1:]
	}
	if len(command.Args) >= 3 && command.Args[0] == "versionlock" && command.Args[1] == "add" {
		r.cancel()
	}
	return result
}

type yumBoundedErrorFS struct {
	*runtime.MemoryFS
	fail map[string]error
}

func (f *yumBoundedErrorFS) ReadDirBounded(name string, max int) ([]fs.DirEntry, error) {
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	return f.MemoryFS.ReadDirBounded(name, max)
}

type yumUnboundedFS struct{ runtime.FileSystem }

func TestYumListDownloadedFailureAndCapabilityMatrix(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			root := "/var/cache/" + manager
			base := runtime.NewMemoryFS()
			if err := base.MkdirAll(root+"/nested", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := base.WriteFile(root+"/nested/a.rpm", []byte("payload"), 0o640); err != nil {
				t.Fatal(err)
			}

			t.Run("missing-root", func(t *testing.T) {
				r := &yumNoCallRunner{}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: runtime.NewMemoryFS(), Runner: r}, "list_downloaded", map[string]any{})
				if err != nil || !reflect.DeepEqual(got, map[string]any{}) || r.calls != 0 {
					t.Fatalf("got=%#v err=%v calls=%d", got, err, r.calls)
				}
			})
			t.Run("nested-read-error-suppressed", func(t *testing.T) {
				fsys := &yumBoundedErrorFS{MemoryFS: base, fail: map[string]error{root + "/nested": fs.ErrPermission}}
				r := &yumNoCallRunner{}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: fsys, Runner: r}, "list_downloaded", map[string]any{})
				if err != nil || !reflect.DeepEqual(got, map[string]any{}) || r.calls != 0 {
					t.Fatalf("got=%#v err=%v calls=%d", got, err, r.calls)
				}
			})
			t.Run("overflow-no-partial", func(t *testing.T) {
				fsys := &yumBoundedErrorFS{MemoryFS: base, fail: map[string]error{root: runtime.ErrDirReadLimit}}
				r := &yumNoCallRunner{}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: fsys, Runner: r}, "list_downloaded", map[string]any{})
				if got != nil || err == nil || r.calls != 0 {
					t.Fatalf("got=%#v err=%v calls=%d", got, err, r.calls)
				}
			})
			t.Run("unsupported-no-runner", func(t *testing.T) {
				r := &yumNoCallRunner{}
				fsys := &yumUnboundedFS{FileSystem: base}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: fsys, Runner: r}, "list_downloaded", map[string]any{})
				if got != nil || !errors.Is(err, runtime.ErrBoundedDirUnsupported) || r.calls != 0 {
					t.Fatalf("got=%#v err=%v calls=%d", got, err, r.calls)
				}
			})
			t.Run("runner-error-stops", func(t *testing.T) {
				r := &yumRecordingRunner{results: []process.CommandResult{{Err: context.Canceled}}}
				got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{FS: base, Runner: r, Facts: factsForYUMTest()}, "list_downloaded", map[string]any{"root": "/ignored"})
				if got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 1 {
					t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
				}
			})
		})
	}
}

func TestYumUpgradeFunctionsUsePinnedQueriesAndEVRRules(t *testing.T) {
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			facts := facts.ForTesting(facts.Overrides{Package: manager, OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}})
			r := &yumRecordingRunner{results: []process.CommandResult{{}, {Stdout: []byte("foo.x86_64 2:2.0-2 @repo\nfoo.i686 9:9.0-9 @repo\n")}}}
			p := &commandProvider{spec: rpmSpec(manager)}
			got, err := p.Yum(context.Background(), &runtime.Runtime{Runner: r, Facts: facts}, "list_upgrades", map[string]any{})
			if err != nil || !reflect.DeepEqual(got, map[string]string{"foo": "2:2.0-2", "foo.i686": "9:9.0-9"}) {
				t.Fatalf("list_upgrades got=%#v err=%v", got, err)
			}
			action := "updates"
			if manager != "yum" {
				action = "--upgrades"
			}
			if len(r.commands) != 2 || !reflect.DeepEqual(r.commands[1].Args, append([]string{"--quiet", "list", action}, nil...)) {
				t.Fatalf("list_upgrades commands=%#v", r.commands)
			}

			installed := "foo_|-1_|-1.0_|-1_|-x86_64_|-(none)_|-0\nfoo_|-2_|-0.9_|-9_|-x86_64_|-(none)_|-0\n"
			r = &yumRecordingRunner{results: []process.CommandResult{{}, {}, {Stdout: []byte(installed)}, {Stdout: []byte("foo.x86_64 1:1.0-2 @repo\nfoo.x86_64 3:1.0-1 @repo\n")}}}
			got, err = p.Yum(context.Background(), &runtime.Runtime{Runner: r, Facts: facts}, "upgrade_available", map[string]any{"name": "foo"})
			if err != nil || got != true {
				t.Fatalf("upgrade_available got=%#v err=%v", got, err)
			}
			if len(r.commands) != 4 || r.commands[2].Args[0] != "-qa" || r.commands[3].Args[len(r.commands[3].Args)-1] != "foo" {
				t.Fatalf("upgrade_available commands=%#v", r.commands)
			}
		})
	}
}

func TestYumLooseVersionCandidateOrderingMatchesPinnedSaltVectors(t *testing.T) {
	// Derived from versions.LooseVersion.parse and _cmp in the pinned
	// salt/utils/versions.py:73-101 and distutils' component_re.split.
	// The RPM result is included to make the intentional comparator boundary
	// explicit; candidate ordering must use the LooseVersion result only.
	for _, tc := range []struct {
		left, right string
		loose, rpm  int
	}{
		{left: "1.0~rc1", right: "1.0", loose: 1, rpm: -1},
		{left: "1.0-foo", right: "1.0-1", loose: 1, rpm: -1},
		{left: "1.0+1", right: "1.0-1", loose: -1, rpm: 1},
		{left: "1.0-10", right: "1.0-2", loose: 1, rpm: 1},
		{left: "1.0-1.el10", right: "1.0-1.el9", loose: 1, rpm: 1},
	} {
		got := yumSign(yumLooseVersionCmp(tc.left, tc.right))
		if got != tc.loose {
			t.Errorf("LooseVersion(%q, %q)=%d, want %d", tc.left, tc.right, got, tc.loose)
		}
		if got := yumSign(yumVersionCmp(tc.left, tc.right, false)); got != tc.rpm {
			t.Errorf("RPM(%q, %q)=%d, want %d", tc.left, tc.right, got, tc.rpm)
		}
	}
}

func TestYumLooseVersionDoesNotTruncateCandidates(t *testing.T) {
	// Values beyond the former 4096-byte and 256-component cutoffs must still
	// participate in ordering; yumUpgradeOutputLimit bounds provider input.
	longNumeric := strings.Repeat("1", 4096)
	if got := yumSign(yumLooseVersionCmp(longNumeric+"0", longNumeric+"1")); got != -1 {
		t.Fatalf("long LooseVersion comparison = %d, want -1", got)
	}
	left := strings.Repeat("1.", 256) + "2"
	right := strings.Repeat("1.", 256) + "1"
	if got := yumSign(yumLooseVersionCmp(left, right)); got != 1 {
		t.Fatalf("long component LooseVersion comparison = %d, want 1", got)
	}
}

func TestYumUpgradeAvailableNonzeroAvailableListDiscardsCandidates(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{},
		{Stdout: []byte("foo.x86_64 9:9.0-1 @updates\n"), Stderr: []byte("metadata unavailable"), ExitCode: 1},
	}}
	rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}})}
	got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), rt, "upgrade_available", map[string]any{"name": "foo", "refresh": false})
	if err != nil || got != false {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if len(r.commands) != 2 || r.commands[1].Name != "dnf" {
		t.Fatalf("commands=%#v", r.commands)
	}
}

func TestYumListUpgradesRetcodeHandling(t *testing.T) {
	sentinel := errors.New("runner failed")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		result process.CommandResult
		want   map[string]string
		err    error
	}{
		{name: "nonzero parseable", result: process.CommandResult{ExitCode: 100, Stdout: []byte("foo.x86_64 1:2.0-1 @updates\n")}, want: map[string]string{"foo": "1:2.0-1"}},
		{name: "nonzero error marker in stdout", result: process.CommandResult{ExitCode: 1, Stdout: []byte("Error: metadata unavailable\nfoo.x86_64 1:2.0-1 @updates\n")}, want: map[string]string{"Error:": "metadata", "foo": "1:2.0-1"}},
		{name: "nonzero error marker in stderr", result: process.CommandResult{ExitCode: 1, Stdout: []byte("foo.x86_64 1:2.0-1 @updates\n"), Stderr: []byte("Error: metadata unavailable")}, want: map[string]string{"foo": "1:2.0-1"}},
		{name: "empty", result: process.CommandResult{ExitCode: 0}, want: map[string]string{}},
		{name: "malformed", result: process.CommandResult{ExitCode: 0, Stdout: []byte("not package\n")}, want: map[string]string{}},
		{name: "runner error", result: process.CommandResult{Err: sentinel}, err: sentinel},
		{name: "canceled", ctx: canceled, err: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			r := &yumContextRecordingRunner{results: []process.CommandResult{tc.result}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}})}
			got, err := (&commandProvider{spec: dnfSpec}).Yum(ctx, rt, "list_upgrades", map[string]any{"refresh": false})
			if tc.err != nil {
				if got != nil || err != tc.err {
					t.Fatalf("got=%#v err=%v want=%#v err=%v", got, err, tc.want, tc.err)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) || err != nil {
				t.Fatalf("got=%#v err=%v want=%#v err=%v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestYumUpgradeAvailableArchitectureFiltering(t *testing.T) {
	cases := []struct {
		request, candidate string
		want               bool
	}{
		{"foo", "foo.noarch", true},
		{"foo", "foo.x86_64", true},
		// yumpkg.py:592-600 compares candidate pkg.arch exactly with the
		// OS arch; its resolve_name normalization does not create an arch
		// interchange. ARCHES excludes SPARC (rpm.py:47-56).
		{"foo", "foo.x86_64_v2", false},
		{"foo", "foo.i686", false},
		{"foo.i686", "foo.i386", false},
		// An unknown requested/candidate suffix uses osarch for the arch
		// comparison, but remains part of the source package name.
		{"foo", "foo.unknown", false},
		// SPARC suffixes are not in rpm.ARCHES (salt/utils/pkg/rpm.py:47-56),
		// so they remain unknown requested architectures and are not made
		// eligible by inventing a public SPARC mapping.
		{"foo.sparc", "foo.sparc", false},
		{"foo.sparc", "foo.x86_64", false},
		{"foo.i686", "foo.i686", true},
		{"foo.i686", "foo.noarch", false},
		{"foo.i686", "foo.x86_64", false},
		// latest_version compares the normalized candidate to the exact
		// requested string; normalized foo does not equal foo.x86_64.
		{"foo.x86_64", "foo.x86_64", false},
		{"foo.x86_64", "foo.noarch", false},
		{"foo.noarch", "foo.noarch", false},
		{"foo.noarch", "foo.x86_64", false},
	}
	for _, tc := range cases {
		t.Run(tc.request+"/"+tc.candidate, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{
				{Stdout: []byte("installed packages\n")},
				{Stdout: []byte(tc.candidate + " 2:2.0-1 @updates\n")},
			}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}})}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "upgrade_available", map[string]any{"name": tc.request, "refresh": false})
			if err != nil || got != tc.want {
				t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}

func TestYumUpgradeAvailableNoarchRequestUsesOSArchAndResolvedName(t *testing.T) {
	// yumpkg.latest_version.py:578-583 checks the requested suffix only against
	// salt.utils.pkg.rpm.ARCHES, which excludes noarch.  The candidate parser
	// still sees raw foo.noarch, while rpm.resolve_name normalizes it to foo;
	// the source then compares that normalized name with the exact request.
	if got := yumRequestedArch("foo.noarch", "x86_64"); got != "x86_64" {
		t.Fatalf("yumRequestedArch(foo.noarch)=%q want x86_64", got)
	}
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("installed packages\n")},
		{Stdout: []byte("foo.noarch 2:2.0-1 @updates\n")},
	}}
	rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{
		OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"},
	})}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "upgrade_available", map[string]any{
		"name": "foo.noarch", "refresh": false,
	})
	if err != nil || got != false {
		t.Fatalf("newer foo.noarch got=%#v err=%v want false", got, err)
	}
	if records := yumPkgInfo("foo.noarch 2:2.0-1 @updates\n", "x86_64"); len(records) != 1 || records[0].name != "foo" || records[0].arch != "noarch" {
		t.Fatalf("resolved candidate=%#v want name foo arch noarch", records)
	}
}

func TestYumUpgradeAvailableUnknownSuffixUsesExactNameAndArch(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{Stdout: []byte("foo.unknown_|-2_|-2.0_|-1_|-x86_64_|-(none)_|-0\n")},
		{Stdout: []byte("foo.unknown 2:2.0-1 @updates\n")},
	}}
	rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{
		OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"},
	})}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "upgrade_available", map[string]any{
		"name": "foo.unknown", "refresh": false,
	})
	if err != nil || got != false {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestYumPackageRecordsUseRawFinalSuffixBeforeResolveName(t *testing.T) {
	for _, tc := range []struct {
		value, wantName, wantBase, wantArch string
	}{
		{"foo", "foo", "foo", "x86_64"},
		{"foo.x86_64", "foo", "foo", "x86_64"},
		{"foo.i686", "foo.i686", "foo", "i686"},
		{"foo.noarch", "foo", "foo", "noarch"},
		{"foo.unknown", "foo.unknown", "foo", "unknown"},
	} {
		got := yumPkgInfo(tc.value+" 2:1.0-1 @repo\n", "x86_64")
		if len(got) != 1 || got[0].name != tc.wantName || got[0].base != tc.wantBase || got[0].arch != tc.wantArch {
			t.Fatalf("%q: got=%#v want name=%q base=%q arch=%q", tc.value, got, tc.wantName, tc.wantBase, tc.wantArch)
		}
	}
	installed := yumInstalledPkgInfo("foo.unknown_|-0_|-1.0_|-1_|-x86_64_|-(none)_|-0\n", "x86_64")
	if len(installed) != 1 || installed[0].name != "foo.unknown" || installed[0].arch != "x86_64" {
		t.Fatalf("installed unknown record=%#v", installed)
	}
}

func (r *yumRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestYumModifiedDispatchAndPinnedRecords(t *testing.T) {
	output := "SM5DLUGTX c /all\n......... /clean\nX........ /unknown\n......... c /config\n"
	want := map[string]any{
		"/all":     []string{"size", "mode", "checksum", "device", "symlink", "owner", "group", "time", "capabilities", "config"},
		"/clean":   []string{},
		"/unknown": []string{"size"},
		"/config":  []string{"config"},
	}
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		t.Run(manager, func(t *testing.T) {
			names := []string{"alpha", "beta"}
			args := map[string]any{"names": names, "root": "/target"}
			before := map[string]any{"names": []string{"alpha", "beta"}, "root": "/target"}
			r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stdout: []byte(output)}}}
			got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "modified", args)
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) || !reflect.DeepEqual(names, before["names"]) {
				t.Fatalf("got=%#v err=%v args=%#v", got, err, args)
			}
			if len(r.commands) != 1 || !reflect.DeepEqual(append([]string{r.commands[0].Name}, r.commands[0].Args...), []string{"rpm", "--root", "/target", "-Va", "alpha", "beta"}) || r.commands[0].Shell || r.commands[0].MaxStdoutBytes != yumModifiedOutputLimit || r.commands[0].MaxStderrBytes != yumModifiedOutputLimit {
				t.Fatalf("command=%#v", r.commands)
			}

			noNames := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 0}}}
			if got, err := (&commandProvider{spec: rpmSpec(manager)}).Yum(context.Background(), &runtime.Runtime{Runner: noNames}, "modified", map[string]any{}); err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(noNames.commands) != 1 || !reflect.DeepEqual(noNames.commands[0].Args, []string{"-Va"}) {
				t.Fatalf("no names got=%#v err=%v commands=%#v", got, err, noNames.commands)
			}
		})
	}
}

func TestYumModifiedRetcodesErrorsCancellationAndMalformedLines(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name string
		res  process.CommandResult
		want any
		err  error
	}{
		{"success", process.CommandResult{}, map[string]any{}, nil},
		{"changes", process.CommandResult{ExitCode: 1, Stdout: []byte("S........ /file\n")}, map[string]any{"/file": []string{"size"}}, nil},
		{"failure", process.CommandResult{ExitCode: 2, Stderr: []byte("failed")}, map[string]any{"retcode": 2, "stderr": "failed"}, nil},
		{"runner", process.CommandResult{Err: sentinel}, nil, sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{tc.res}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "modified", map[string]any{})
			if tc.err != nil {
				if !errors.Is(err, tc.err) || got != nil {
					t.Fatalf("got=%#v err=%v", got, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
		})
	}
	for _, output := range []string{"malformed\n......... /ok\n", " ......... /leading\n", "......... /ok\n\n......... /later\n", "......... /ok\n\n"} {
		r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 1, Stdout: []byte(output)}}}
		if got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "modified", map[string]any{}); got != nil || err == nil {
			t.Fatalf("output=%q got=%#v err=%v", output, got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &yumContextRecordingRunner{}
	if got, err := (&commandProvider{spec: yumSpec}).Yum(ctx, &runtime.Runtime{Runner: r}, "modified", map[string]any{}); got != nil || !errors.Is(err, context.Canceled) || len(r.commands) != 1 {
		t.Fatalf("cancel got=%#v err=%v calls=%d", got, err, len(r.commands))
	}
}

type yumContextRecordingRunner struct {
	commands []process.Command
	results  []process.CommandResult
}

func (r *yumContextRecordingRunner) Run(ctx context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if err := ctx.Err(); err != nil {
		return process.CommandResult{Err: err}
	}
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func TestYumInfoInstalledQueryTagsFailureDoesNotQueryRPM(t *testing.T) {
	provider := &commandProvider{spec: yumSpec}
	sentinel := errors.New("querytags failed")
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		result process.CommandResult
		want   error
	}{
		{name: "runner error", ctx: context.Background(), result: process.CommandResult{Err: sentinel}, want: sentinel},
		{name: "nonzero", ctx: context.Background(), result: process.CommandResult{ExitCode: 7, Stderr: []byte("bad tags")}, want: errors.New("rpm exited with code 7: bad tags")},
		{name: "canceled", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(), result: process.CommandResult{}, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumContextRecordingRunner{results: []process.CommandResult{tc.result}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}
			got, err := provider.Yum(tc.ctx, rt, "info_installed", map[string]any{"names": []string{"foo"}})
			if tc.name == "nonzero" {
				if err == nil || err.Error() != tc.want.Error() || got != nil {
					t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
				}
			} else if err != tc.want || got != nil {
				t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
			}
			if len(r.commands) != 1 || !reflect.DeepEqual(r.commands[0].Args, []string{"--querytags"}) {
				t.Fatalf("commands=%#v", r.commands)
			}
		})
	}
}

func TestYumInfoInstalledMainQueryFailureDoesNotCreateMetadata(t *testing.T) {
	provider := &commandProvider{spec: yumSpec}
	for _, tc := range []struct {
		name string
		want error
	}{
		{name: "runner error", want: errors.New("rpm info failed")},
		{name: "canceled", want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{
				{ExitCode: 0, Stdout: []byte("LONGSIZE\n")},
				{Err: tc.want},
			}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}
			got, err := provider.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}})
			if err != tc.want || got != nil {
				t.Fatalf("got=%#v err=%v want=%v", got, err, tc.want)
			}
			if len(r.commands) != 2 {
				t.Fatalf("commands=%#v", r.commands)
			}
		})
	}
}

func TestYumInfoInstalledSelectsSizeQueryTagAndPreservesCommandModel(t *testing.T) {
	provider := &commandProvider{spec: yumSpec}
	for _, tc := range []struct {
		name, tags, sizeTag, size string
	}{
		{name: "long size", tags: "LONGSIZE\n", sizeTag: "%{LONGSIZE}", size: "123456789"},
		{name: "legacy size", tags: "SIZE\n", sizeTag: "%{SIZE}", size: "42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{
				{ExitCode: 0, Stdout: []byte(tc.tags)},
				{ExitCode: 0, Stdout: []byte("size: " + tc.size + "\nname: foo\nversion: 1\nedition: 1-0\n-----\n")},
			}}
			rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}
			got, err := provider.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}, "attr": "size,name,version"})
			want := map[string]any{"foo": map[string]any{"size": tc.size, "name": "foo", "version": "1"}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, want)
			}
			format := "size: " + tc.sizeTag + "\\nname: %{NAME}\\nversion: %{VERSION}\\nedition: %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n-----\\n"
			if !reflect.DeepEqual(r.commands[0], process.Command{Name: "rpm", Args: []string{"--querytags"}}) {
				t.Fatalf("querytags command=%#v", r.commands[0])
			}
			wantMain := process.Command{Name: "rpm", Args: []string{"-q", "foo", "--queryformat", format}, Env: []string{"TZ=UTC"}}
			if !reflect.DeepEqual(r.commands[1], wantMain) {
				t.Fatalf("main command=%#v want=%#v", r.commands[1], wantMain)
			}
		})
	}
}

func TestYumLongtailRootAndInfoQuery(t *testing.T) {
	r := &yumRecordingRunner{results: []process.CommandResult{
		{ExitCode: 0, Stdout: []byte("/a\n/a\n")},
		{ExitCode: 0, Stdout: []byte("foo 1\n")},
		{ExitCode: 0, Stdout: []byte("/usr/bin/foo\n")},
		{ExitCode: 0, Stdout: []byte("foo\n")},
		{ExitCode: 0, Stdout: []byte("LONGSIZE\n")},
		{ExitCode: 0, Stdout: []byte("name: foo\nversion: 1\nrelease: 2\nedition: 1-2\nrelocations: (not relocatable)\nsignature: sig\ndescription:\ntext\n-----\n")},
	}}
	rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}
	p := &commandProvider{spec: yumSpec}
	root := "/image"
	if _, err := p.Yum(context.Background(), rt, "file_list", map[string]any{"packages": []string{"foo"}, "root": &root}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Yum(context.Background(), rt, "file_dict", map[string]any{"packages": []string{"foo"}, "root": &root}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Yum(context.Background(), rt, "owner", map[string]any{"paths": []string{"/usr/bin/foo"}, "root": &root}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}, "root": &root, "attr": "relocations,signature,description"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"rpm", "--root", "/image", "-ql", "foo"},
		{"rpm", "--root", "/image", "-q", "--queryformat", "%{NAME} %{VERSION}\\n", "foo"},
		{"rpm", "-ql", "foo"}, // pinned rpm_lowpkg.py omits root in per-package call
		{"rpm", "--root", "/image", "-qf", "--queryformat", "%{name}", "/usr/bin/foo"},
		{"rpm", "--querytags"},
		{"rpm", "--root", "/image", "-q", "foo", "--queryformat", "relocations: %|PREFIXES?{[%{PREFIXES} ]}:{(not relocatable)}|\\n" +
			"signature: %|DSAHEADER?{%{DSAHEADER:pgpsig}}:{%|RSAHEADER?{%{RSAHEADER:pgpsig}}:{%|SIGGPG?{%{SIGGPG:pgpsig}}:{%|SIGPGP?{%{SIGPGP:pgpsig}}:{(none)}|}|}|}|\\n" +
			"name: %{NAME}\\n" + "edition: %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n" + "description:\\n%{DESCRIPTION}\\n-----\\n"},
	}
	for i, command := range r.commands {
		if i == 5 {
			if !reflect.DeepEqual(command.Args, want[i][1:]) || command.Env == nil || !reflect.DeepEqual(command.Env, []string{"TZ=UTC"}) {
				t.Fatalf("info argv/env=%#v/%#v want=%#v/TZ", command.Args, command.Env, want[i][1:])
			}
			continue
		}
		got := append([]string{command.Name}, command.Args...)
		if !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("command %d=%#v want=%#v", i, got, want[i])
		}
	}
}

func TestYumCleanMetadataMirrorsRefreshDB(t *testing.T) {
	trueValue := true
	args := map[string]any{
		"repo": "legacy", "fromrepo": "preferred",
		"disablerepo": []string{"one", "two"}, "enablerepo": []string{"three"},
		"disableexcludes": "main", "branch": "stable",
		"setopt": []string{"a=1", "b=2"}, "check_update": &trueValue,
	}
	r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 7}, {ExitCode: 100}}}
	rt := &runtime.Runtime{Runner: r}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "clean_metadata", args)
	if err != nil || got != true {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	want := [][]string{
		{"yum", "--quiet", "--assumeyes", "clean", "expire-cache", "--disablerepo=*", "--enablerepo=preferred", "--disableexcludes=main", "--branch=stable", "--setopt=a=1", "--setopt=b=2"},
		{"yum", "--quiet", "--assumeyes", "check-update", "--disablerepo=*", "--enablerepo=preferred", "--disableexcludes=main", "--branch=stable", "--setopt=a=1", "--setopt=b=2"},
	}
	if len(r.commands) != len(want) {
		t.Fatalf("commands=%#v", r.commands)
	}
	for i, command := range r.commands {
		if got := append([]string{command.Name}, command.Args...); !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("command %d=%v want %v", i, got, want[i])
		}
		if command.Shell || command.MaxStdoutBytes != yumMetadataOutputLimit || command.MaxStderrBytes != yumMetadataOutputLimit {
			t.Fatalf("command %d unsafe execution settings: %#v", i, command)
		}
	}
}

func TestYumCleanMetadataRetcodesAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want any
	}{
		{"no updates", 0, nil}, {"updates", 100, true}, {"error", 1, false}, {"other", 42, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 0}, {ExitCode: tc.code}}}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", map[string]any{})
			if err != nil || !reflect.DeepEqual(got, tc.want) || len(r.commands) != 2 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
		})
	}
	for _, args := range []map[string]any{
		{"unknown": true}, {"check_update": "yes"}, {"repo": 1}, {"enablerepo": []any{1}},
	} {
		r := &yumNoCallRunner{}
		_, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", args)
		if err == nil || r.calls != 0 {
			t.Fatalf("args=%#v err=%v calls=%d", args, err, r.calls)
		}
	}
}

func TestYumCleanMetadataStopsOnRunnerErrorOrCancellation(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, result := range []process.CommandResult{{Err: sentinel}, {Err: context.Canceled}} {
		r := &yumRecordingRunner{results: []process.CommandResult{result}}
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", map[string]any{})
		if !errors.Is(err, result.Err) || got != nil || len(r.commands) != 1 {
			t.Fatalf("got=%#v err=%v commands=%d", got, err, len(r.commands))
		}
	}
	falseValue := false
	r := &yumRecordingRunner{}
	got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", map[string]any{"check_update": &falseValue})
	if err != nil || got != true || len(r.commands) != 1 {
		t.Fatalf("check_update=false got=%#v err=%v commands=%d", got, err, len(r.commands))
	}
}

func TestYumCleanMetadataOptionShapesAndRHEL7(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
		want []string
	}{
		{"scalar", map[string]any{"disablerepo": "base", "enablerepo": "extras", "setopt": "a=1,b=2", "check_update": false}, []string{"--disablerepo=base", "--enablerepo=extras", "--setopt=a=1", "--setopt=b=2"}},
		{"list", map[string]any{"disablerepo": []string{"a", "b"}, "enablerepo": []any{"c"}, "setopt": []string{"x=1", "y=2"}, "check_update": false}, []string{"--disablerepo=a", "--disablerepo=b", "--enablerepo=c", "--setopt=x=1", "--setopt=y=2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &yumRecordingRunner{}
			_, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", tc.args)
			if err != nil || len(r.commands) != 1 || !reflect.DeepEqual(r.commands[0].Args[4:], tc.want) {
				t.Fatalf("err=%v argv=%v want=%v", err, r.commands, tc.want)
			}
		})
	}
	for _, version := range []string{"7.9", "8.0", ""} {
		r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 0}, {ExitCode: 100}}}
		rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat, Version: version}})}
		if _, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "clean_metadata", map[string]any{}); err != nil {
			t.Fatal(err)
		}
		got := append([]string{r.commands[1].Name}, r.commands[1].Args...)
		has := containsString(got, "--setopt=autocheck_running_kernel=false")
		if has != (version == "7.9") {
			t.Fatalf("version=%q argv=%v", version, got)
		}
		if has && got[4] != "--setopt=autocheck_running_kernel=false" {
			t.Fatalf("flag position=%v", got)
		}
	}
}

func TestYumCleanMetadataRejectsInvalidEffectiveOptionsWithoutRunner(t *testing.T) {
	for _, args := range []map[string]any{
		{"repo": "bad\x00repo"}, {"fromrepo": "bad\nrepo"}, {"enablerepo": ""},
		{"disablerepo": []any{"ok", 1}}, {"setopt": "ok=1,,bad=2"},
	} {
		r := &yumNoCallRunner{}
		_, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{Runner: r}, "clean_metadata", args)
		if err == nil || r.calls != 0 {
			t.Fatalf("args=%#v err=%v calls=%d", args, err, r.calls)
		}
	}
}

func TestYumCleanMetadataRHEL7ManagerArgv(t *testing.T) {
	for _, tc := range []struct {
		manager string
		spec    spec
	}{
		{"yum", yumSpec}, {"dnf", dnfSpec},
	} {
		r := &yumRecordingRunner{results: []process.CommandResult{{ExitCode: 0}, {ExitCode: 100}}}
		rt := &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat, Version: "7.9"}})}
		if _, err := (&commandProvider{spec: tc.spec}).Yum(context.Background(), rt, "clean_metadata", map[string]any{"setopt": "z=1"}); err != nil {
			t.Fatal(err)
		}
		want := []string{tc.manager, "--quiet", "--assumeyes", "check-update", "--setopt=autocheck_running_kernel=false", "--setopt=z=1"}
		if got := append([]string{r.commands[1].Name}, r.commands[1].Args...); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s argv=%v want=%v", tc.manager, got, want)
		}
	}
}

func TestYumLongtailReturnsProviderValues(t *testing.T) {
	newRuntime := func(results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
		r := &yumRecordingRunner{results: results}
		return &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}, r
	}
	p := &commandProvider{spec: yumSpec}

	rt, _ := newRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("/usr/bin/a\n/usr/bin/a\n")})
	got, err := p.Yum(context.Background(), rt, "file_list", map[string]any{"packages": []string{"a"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{"/usr/bin/a", "/usr/bin/a"}}) {
		t.Fatalf("file_list got=%#v err=%v", got, err)
	}

	rt, _ = newRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("a 1\nb 2\na 3\nb is not installed\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("/a\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte("/b\n")},
	)
	got, err = p.Yum(context.Background(), rt, "file_dict", map[string]any{"packages": []string{"a", "b"}})
	want := map[string]any{"errors": []string{"b is not installed"}, "packages": map[string]any{"a": []string{"/a"}, "b": []string{"/b"}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("file_dict got=%#v err=%v want=%#v", got, err, want)
	}

	rt, _ = newRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("a\n")})
	got, err = p.Yum(context.Background(), rt, "owner", map[string]any{"paths": []string{"/a"}})
	if err != nil || got != "a\n" {
		t.Fatalf("owner got=%#v err=%v", got, err)
	}

	metadata := "name: foo\nversion: 1\nrelease: 0\nsource_rpm: (none)\nbuild_date: 100\nbuild_date_time_t: 100\ninstall_date: (not installed)\ninstall_date_time_t: (not installed)\nedition: 1-0\n-----\n" +
		"name: foo\nversion: 2\nrelease: 0\nsource_rpm: (not installed)\nedition: 2-0\n-----\n" +
		"name: gpg-pubkey\nversion: 1\nedition: 1-0\n-----\n"
	rt, _ = newRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("LONGSIZE\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(metadata)},
	)
	got, err = p.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}})
	want = map[string]any{"foo": map[string]any{
		"name": "foo", "version": "2", "release": "0", "source": "(not installed)", "edition": "2-0", "description": "",
	}}
	// Latest mode follows yumpkg's wrapper and drops edition, while retaining
	// lowpkg's name and source translation; date values are checked separately
	// in all_versions mode below.
	delete(want["foo"].(map[string]any), "edition")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("info_installed latest got=%#v err=%v want=%#v", got, err, want)
	}

	all := true
	rt, _ = newRuntime(
		process.CommandResult{ExitCode: 0, Stdout: []byte("SIZE\n")},
		process.CommandResult{ExitCode: 0, Stdout: []byte(metadata)},
	)
	got, err = p.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}, "all_versions": all, "attr": "name,source_rpm,build_date,build_date_time_t"})
	want = map[string]any{"foo": []any{
		map[string]any{"name": "foo", "source": "(not installed)", "edition": "2-0"},
		map[string]any{"name": "foo", "source": "(none)", "build_date": "1970-01-01T00:01:40Z", "build_date_time_t": int64(100), "edition": "1-0"},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("info_installed all got=%#v err=%v want=%#v", got, err, want)
	}
}

// These cases pin the value shapes at the yumpkg/rpm_lowpkg boundary.  The
// source references are salt/modules/yumpkg.py and salt/modules/rpm_lowpkg.py
// at revision 8b63e700637e40d76f80a00d95c60471797c73b9; only the fake Runner is
// used here.
func TestYumSharedFunctionsReturnAllSourceShapes(t *testing.T) {
	provider := &commandProvider{spec: yumSpec}
	newRuntime := func(results ...process.CommandResult) (*runtime.Runtime, *yumRecordingRunner) {
		r := &yumRecordingRunner{results: results}
		return &runtime.Runtime{Runner: r, Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}})}, r
	}

	rt, r := newRuntime(process.CommandResult{ExitCode: 0})
	got, err := provider.Yum(context.Background(), rt, "file_list", map[string]any{"packages": []string{}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "files": []string{}}) || len(r.commands) != 1 {
		t.Fatalf("empty file_list got=%#v err=%v calls=%d", got, err, len(r.commands))
	}

	rt, r = newRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("x 1\nx 2\n")})
	got, err = provider.Yum(context.Background(), rt, "file_dict", map[string]any{"packages": []string{"x"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"errors": []string{}, "packages": map[string]any{"x": []string{}}}) || len(r.commands) != 2 {
		t.Fatalf("file_dict empty grouped value got=%#v err=%v calls=%d", got, err, len(r.commands))
	}

	metadata := "name: foo\nversion: 3\nrelease: 1\nsource_rpm: src-3.rpm\nrelocations: /opt\nsignature: sig\ninstall_date: 100\ninstall_date_time_t: 100\nedition: 3-1\ndescription:\nhello\n-----\n"
	rt, r = newRuntime(process.CommandResult{ExitCode: 0, Stdout: []byte("LONGSIZE\n")}, process.CommandResult{ExitCode: 0, Stdout: []byte(metadata)})
	got, err = provider.Yum(context.Background(), rt, "info_installed", map[string]any{"names": []string{"foo"}, "attr": "name,source_rpm,relocations,signature,install_date,install_date_time_t,description"})
	wantInfo := map[string]any{"foo": map[string]any{"name": "foo", "source": "src-3.rpm", "relocations": "/opt", "signature": "sig", "install_date": "1970-01-01T00:01:40Z", "install_date_time_t": int64(100), "description": "hello"}}
	if err != nil || !reflect.DeepEqual(got, wantInfo) || len(r.commands) != 2 {
		t.Fatalf("info attrs got=%#v err=%v calls=%d", got, err, len(r.commands))
	}

	for _, tc := range []struct {
		name      string
		args      map[string]any
		results   []process.CommandResult
		want      any
		wantCalls int
	}{
		{"owner zero", map[string]any{"paths": []string{}}, nil, "", 0},
		{"owner one", map[string]any{"paths": []string{"/a"}}, []process.CommandResult{{Stdout: []byte("pkg\n")}}, "pkg\n", 1},
		{"owner many", map[string]any{"paths": []string{"/a", "/b"}}, []process.CommandResult{{Stdout: []byte("a")}, {Stdout: []byte("b")}}, map[string]any{"/a": "a", "/b": "b"}, 2},
		{"owner unowned", map[string]any{"paths": []string{"/a"}}, []process.CommandResult{{ExitCode: 1, Stdout: []byte("file is not owned")}}, "", 1},
		{"owner error", map[string]any{"paths": []string{"/a"}}, []process.CommandResult{{Err: context.Canceled}}, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, r := newRuntime(tc.results...)
			got, err := provider.Yum(context.Background(), rt, "owner", tc.args)
			if tc.name == "owner error" {
				if !errors.Is(err, context.Canceled) || got != nil {
					t.Fatalf("got=%#v err=%v", got, err)
				}
			} else if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			if len(r.commands) != tc.wantCalls {
				t.Fatalf("calls=%d want=%d", len(r.commands), tc.wantCalls)
			}
		})
	}

	root := "/image"
	rt, r = newRuntime(process.CommandResult{Stdout: []byte("pkg")})
	if _, err := provider.Yum(context.Background(), rt, "owner", map[string]any{"paths": []string{"/a"}, "root": &root}); err != nil || !reflect.DeepEqual(r.commands[0].Args, []string{"--root", "/image", "-qf", "--queryformat", "%{name}", "/a"}) {
		t.Fatalf("root owner command=%#v err=%v", r.commands, err)
	}
}

func TestYumNormalizeNameSourceVectors(t *testing.T) {
	tests := []struct {
		name, osarch, want string
	}{
		{"pkg.x86_64", "x86_64", "pkg"},
		{"pkg.x86_64_v2", "x86_64", "pkg"},
		{"pkg.x86_64", "x86_64_v2", "pkg"},
		{"pkg.i686", "x86_64", "pkg.i686"},
		{"pkg.aarch64", "aarch64", "pkg"},
		{"pkg.noarch", "x86_64", "pkg"},
		{"pkg.sparc", "x86_64", "pkg.sparc"},
		{"pkg.sparcv8", "x86_64", "pkg.sparcv8"},
		{"pkg.sparcv9", "x86_64", "pkg.sparcv9"},
		{"pkg.sparcv9v", "x86_64", "pkg.sparcv9v"},
		{"pkg.sparc64", "x86_64", "pkg.sparc64"},
		{"pkg.sparc64v", "x86_64", "pkg.sparc64v"},
		{"pkg.custom", "x86_64", "pkg.custom"},
		{"pkg", "x86_64", "pkg"},
		{"pkg.x86_64", "i686", "pkg.x86_64"},
		{"pkg.noarch", "i686", "pkg"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.osarch, func(t *testing.T) {
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: tt.osarch}})}
			got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "normalize_name", map[string]any{"name": tt.name})
			if err != nil || got != tt.want {
				t.Fatalf("got=%#v err=%v want=%q", got, err, tt.want)
			}
		})
	}
}

func TestYumParseArchSourceVectors(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want map[string]any
	}{
		{"pkg.x86_64", map[string]any{"name": "pkg", "arch": "x86_64"}},
		{"pkg.i686", map[string]any{"name": "pkg", "arch": "i686"}},
		{"pkg.aarch64", map[string]any{"name": "pkg", "arch": "aarch64"}},
		{"pkg.noarch", map[string]any{"name": "pkg", "arch": "noarch"}},
		{"pkg.sparc", map[string]any{"name": "pkg.sparc", "arch": nil}},
		{"pkg.sparcv8", map[string]any{"name": "pkg.sparcv8", "arch": nil}},
		{"pkg.sparcv9", map[string]any{"name": "pkg.sparcv9", "arch": nil}},
		{"pkg.sparcv9v", map[string]any{"name": "pkg.sparcv9v", "arch": nil}},
		{"pkg.sparc64", map[string]any{"name": "pkg.sparc64", "arch": nil}},
		{"pkg.sparc64v", map[string]any{"name": "pkg.sparc64v", "arch": nil}},
		{"pkg.custom", map[string]any{"name": "pkg.custom", "arch": nil}},
		{"pkg", map[string]any{"name": "pkg", "arch": nil}},
		{"", map[string]any{"name": "", "arch": nil}},
	} {
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{}, "parse_arch", map[string]any{"name": tt.in})
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%q: got=%#v err=%v want=%#v", tt.in, got, err, tt.want)
		}
	}
}

func TestYumRejectsMalformedInputWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyRedHat}, CPU: &facts.CPUFacts{Arch: "x86_64"}}), Runner: r}
	for _, args := range []any{nil, map[string]any{}, map[string]any{"name": 42}} {
		if _, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "normalize_name", args); err == nil {
			t.Fatalf("args=%#v accepted", args)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumVersionCmpSourceVectors(t *testing.T) {
	// Vectors follow salt/utils/pkg/rpm.py:168-351
	// (_rpmvercmp, evr_compare, and version_to_evr).
	tests := []struct {
		name, left, right string
		ignore            bool
		want              int
	}{
		{"equal", "1.2-3", "1.2-3", false, 0},
		{"epoch", "1:1.0-1", "0:9.9-9", false, 1},
		{"signed epoch", "-1:1.0", "0:1.0", false, -1},
		{"ignore epoch", "1:1.0-1", "0:1.0-1", true, 0},
		{"version", "1.10", "1.9", false, 1},
		{"release", "1.0-2", "1.0-1", false, 1},
		{"leading zeros", "1.01", "1.1", false, 0},
		{"numeric alpha", "1.0", "1.a", false, 1},
		{"punctuation", "1.0.1", "1_0_1", false, 0},
		{"tilde", "1.0~rc1", "1.0", false, -1},
		{"caret", "1.0", "1.0^git1", false, -1},
		{"missing release lower", "1.0", "1.0-99", false, -1},
		{"missing release upper", "1.0-99", "1.0", false, 1},
		{"missing release equal", "1.0", "1.0-", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), &runtime.Runtime{}, "version_cmp", map[string]any{
				"pkg1": tt.left, "pkg2": tt.right, "ignore_epoch": tt.ignore,
			})
			if err != nil || value != tt.want {
				t.Fatalf("got=%#v err=%v want=%d", value, err, tt.want)
			}
		})
	}
}

func TestYumVersionToEVRSourceEpochVectors(t *testing.T) {
	// Python int(epoch) vectors from salt/utils/pkg/rpm.py:168-351.
	for _, tt := range []struct {
		name, input, want string
	}{
		{"arabic-indic", "١٢:1.0", "12"},
		{"devanagari", "१२:1.0", "12"},
		{"signed whitespace", "  +१२  :1.0", "12"},
		{"negative", "-१२:1.0", "-12"},
		{"negative zero canonical", "-٠:1.0", "0"},
		{"huge", "999999999999999999999999999999999999999999999999999999:1.0", "999999999999999999999999999999999999999999999999999999"},
		{"roman rejected fallback", "Ⅻ:1.0", "0"},
		{"fraction rejected fallback", "½:1.0", "0"},
		{"superscript rejected fallback", "²:1.0", "0"},
		{"invalid rejected fallback", "12x:1.0", "0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			epoch, _, _ := yumVersionToEVR(tt.input)
			if epoch != tt.want {
				t.Fatalf("yumVersionToEVR(%q) epoch=%q want=%q", tt.input, epoch, tt.want)
			}
		})
	}
}

func TestYumVersionCmpAcceptsSourceValuesWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Runner: r}
	for _, tt := range []struct {
		left, right string
		want        int
	}{
		{"", "1.0", -1}, {"1.0", "", 1}, {"wat:1.0", "1.0", 0},
		{"1:", "1.0", 1}, {"-1", "1.0", -1}, {"1.0-", "1.0", 0},
		{"1.0 bad", "1.0", 1}, {"1:2:1.0", "1.0", 1},
	} {
		got, err := (&commandProvider{spec: yumSpec}).Yum(context.Background(), rt, "version_cmp", map[string]any{
			"pkg1": tt.left, "pkg2": tt.right,
		})
		if err != nil || got != tt.want {
			t.Errorf("%q/%q got=%#v err=%v want=%d", tt.left, tt.right, got, err, tt.want)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestYumVersionCmpUnicodeSourceVectors(t *testing.T) {
	for _, tt := range []struct {
		left, right string
		want        int
	}{
		{"1.0α", "1.0β", -1},
		{"1.0α", "1.0a", 1},
		{"1.٠", "1.2", 1},
		{"1.①", "1.1", 1},
		{"1.፩", "1.1", 1},
		{"1.⑴", "1.1", 1},
		{"1.²", "1.1", 1},
		{"1.½", "1.1", -1},
		{"1.Ⅻ", "1.1", -1},
		{"1.①", "1.②", -1},
		{"1.①①", "1.①", 1},
		{"1.１２", "1.２", 1},
		{"1.0~α", "1.0", -1},
		{"1.0^α", "1.0", 1},
		{"1.0+α", "1.0_β", -1},
		{"1+0", "1_0", 0},
		{"1/0", "1.0", 0},
	} {
		got := yumVersionCmp(tt.left, tt.right, false)
		if got != tt.want {
			t.Errorf("%q/%q got=%v want=%d", tt.left, tt.right, got, tt.want)
		}
	}
}

func TestPythonDigitPredicateSourceVectors(t *testing.T) {
	// These assertions mirror Python str.isdigit() on the pinned Unicode
	// version: Other_Digit values are true, while other numeric categories are
	// deliberately false.
	for _, tt := range []struct {
		name string
		r    rune
		want bool
	}{
		{"ascii digit", '7', true},
		{"circled digit", '①', true},
		{"ethiopic digit", '፩', true},
		{"parenthesized digit", '⑴', true},
		{"superscript digit", '²', true},
		{"fraction", '½', false},
		{"roman numeral", 'Ⅻ', false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := pythonDigit(tt.r); got != tt.want {
				t.Fatalf("pythonDigit(%U)=%v want=%v", tt.r, got, tt.want)
			}
		})
	}
}

func TestYumVersionCmpRejectsTypesWithoutRunner(t *testing.T) {
	r := &yumNoCallRunner{}
	rt := &runtime.Runtime{Runner: r}
	for _, args := range []map[string]any{
		{"pkg1": 1, "pkg2": "1"}, {"pkg1": "1", "pkg2": nil}, {"pkg1": "1", "pkg2": "1", "ignore_epoch": "no"},
	} {
		if got, err := (&commandProvider{spec: dnfSpec}).Yum(context.Background(), rt, "version_cmp", args); got != nil || err == nil {
			t.Errorf("args=%#v got=%#v err=%v", args, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("runner calls=%d", r.calls)
	}
}

func TestSourceSplitLinesMatchesPythonBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        []string
	}{
		{"lf", "a\nb", []string{"a", "b"}},
		{"cr", "a\rb", []string{"a", "b"}},
		{"crlf", "a\r\nb", []string{"a", "b"}},
		{"vertical tab", "a\vb", []string{"a", "b"}},
		{"form feed", "a\fb", []string{"a", "b"}},
		{"file separator", "a\x1cb", []string{"a", "b"}},
		{"group separator", "a\x1db", []string{"a", "b"}},
		{"record separator", "a\x1eb", []string{"a", "b"}},
		{"nel", "a\u0085b", []string{"a", "b"}},
		{"line separator", "a\u2028b", []string{"a", "b"}},
		{"paragraph separator", "a\u2029b", []string{"a", "b"}},
		{"consecutive empty lines", "a\n\nb", []string{"a", "", "b"}},
		{"trailing boundary", "a\n", []string{"a"}},
		{"no boundary", "ab", []string{"ab"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceSplitLines(tc.input); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("sourceSplitLines(%q)=%#v want %#v", tc.input, got, tc.want)
			}
		})
	}
}
