package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

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

func TestYumListHoldsDefaultsValidationAndDNF5FailClosed(t *testing.T) {
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
	r.commands = nil
	if _, err := (&commandProvider{spec: rpmSpec("dnf5")}).Yum(context.Background(), &runtime.Runtime{FS: runtime.NewMemoryFS()}, "list_holds", map[string]any{}); !errors.As(err, new(*runtime.UnsupportedError)) || len(r.commands) != 0 {
		t.Fatalf("dnf5 err=%v", err)
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

func (r *yumRecordingRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	r.commands = append(r.commands, command)
	if len(r.results) == 0 {
		return process.CommandResult{ExitCode: 0}
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
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
