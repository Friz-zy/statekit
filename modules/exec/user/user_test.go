package user

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
`

const groupFixture = `root:x:0:
users:x:1000:
devs:x:2000:alice
wheel:x:10:alice,bob
`

// fakeRunner records argv and returns scripted results.
type fakeRunner struct {
	calls [][]string
	code  int
}

func (f *fakeRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	f.calls = append(f.calls, append([]string{cmd.Name}, cmd.Args...))
	return process.CommandResult{ExitCode: f.code}
}

func newRT() (*runtime.Runtime, *fakeRunner) {
	runner := &fakeRunner{}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        runtime.NewMemoryFS(),
	}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/passwd", []byte(passwdFixture), 0o644)
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/group", []byte(groupFixture), 0o644)
	return rt, runner
}

func TestUserInfo(t *testing.T) {
	rt, _ := newRT()
	value, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Name: "alice"})
	if err != nil {
		t.Fatalf("user.info: %v", err)
	}
	info := value.(map[string]any)
	if info["uid"] != "1000" || info["shell"] != "/bin/zsh" || info["home"] != "/home/alice" {
		t.Fatalf("info wrong: %+v", info)
	}
	groups := info["groups"].([]string)
	if len(groups) != 2 || groups[0] != "devs" || groups[1] != "wheel" {
		t.Fatalf("groups = %v", groups)
	}
	if _, err := (infoFunc{}).Execute(context.Background(), rt, &InfoArgs{Name: "ghost"}); err == nil {
		t.Fatal("missing user must error like Salt")
	}
}

func TestListUsers(t *testing.T) {
	rt, _ := newRT()
	value, _ := (listUsersFunc{}).Execute(context.Background(), rt, &ListUsersArgs{})
	names := value.([]string)
	if strings.Join(names, ",") != "root,alice" {
		t.Fatalf("names = %v", names)
	}
}

func TestAddArgvAssembly(t *testing.T) {
	rt, runner := newRT()
	(addFunc{}).Execute(context.Background(), rt, &AddArgs{
		Name: "bob", UID: "1001", GID: "1001", Home: "/home/bob", Shell: "/bin/sh",
	})
	want := []string{"useradd", "-u", "1001", "-g", "1001", "-d", "/home/bob", "-s", "/bin/sh", "-M", "bob"}
	if strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v want %v", runner.calls[0], want)
	}
	runner.code = 9
	if _, err := (addFunc{}).Execute(context.Background(), rt, &AddArgs{Name: "bob"}); err == nil {
		t.Fatal("non-zero exit must surface as error")
	}
}

func TestDeleteAndChUID(t *testing.T) {
	rt, runner := newRT()
	(deleteFunc{}).Execute(context.Background(), rt, &DeleteArgs{Name: "bob", Remove: true, Force: true})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "userdel -r -f bob" {
		t.Fatalf("userdel argv = %q", got)
	}
	(chUIDFunc{}).Execute(context.Background(), rt, &ChUIDArgs{Name: "alice", UID: "1010"})
	last := runner.calls[len(runner.calls)-1]
	if strings.Join(last, " ") != "usermod -u 1010 alice" {
		t.Fatalf("chuid argv = %v", last)
	}
}

func TestChHomeMoves(t *testing.T) {
	rt, runner := newRT()
	(chHomeFunc{}).Execute(context.Background(), rt, &ChHomeArgs{Name: "alice", Home: "/newhome", Move: true})
	if got := strings.Join(runner.calls[len(runner.calls)-1], " "); got != "usermod -m -d /newhome alice" {
		t.Fatalf("chhome argv = %q", got)
	}
}

const chotherPasswdFixture = "synthetic:x:123:456:first,last,room,work,old:/home/synthetic:/bin/false\n"

type trackedUserFS struct {
	runtime.FileSystem
	boundedReads  int
	boundedPaths  []string
	boundedLimits []int64
	unboundedRead int
	readErr       error
}

func (f *trackedUserFS) ReadFile(path string) ([]byte, error) {
	f.unboundedRead++
	return f.FileSystem.ReadFile(path)
}

func (f *trackedUserFS) ReadFileBounded(path string, limit int64) ([]byte, error) {
	f.boundedReads++
	f.boundedPaths = append(f.boundedPaths, path)
	f.boundedLimits = append(f.boundedLimits, limit)
	if f.readErr != nil {
		return nil, f.readErr
	}
	return runtime.ReadFileBounded(f.FileSystem, path, limit)
}

type unboundedOnlyUserFS struct{ runtime.FileSystem }

type usermodTestRunner struct {
	commands     []process.Command
	resolveCalls []string
	path         string
	resolveErr   error
	result       process.CommandResult
	onResolve    func(string)
	beforeRun    func(process.Command)
	afterRun     func(process.Command)
}

func (r *usermodTestRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	r.commands = append(r.commands, cmd)
	if r.beforeRun != nil {
		r.beforeRun(cmd)
	}
	if r.afterRun != nil {
		r.afterRun(cmd)
	}
	return r.result
}

func (r *usermodTestRunner) ResolveTrustedCommand(name string) (string, error) {
	r.resolveCalls = append(r.resolveCalls, name)
	if r.onResolve != nil {
		r.onResolve(name)
	}
	if r.resolveErr != nil {
		return "", r.resolveErr
	}
	return r.path, nil
}

func newChotherRuntime(t *testing.T) (*runtime.Runtime, *trackedUserFS, *usermodTestRunner) {
	t.Helper()
	mem := runtime.NewMemoryFS()
	if err := mem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteFile(passwdPath, []byte(chotherPasswdFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys := &trackedUserFS{FileSystem: mem}
	runner := &usermodTestRunner{path: "/usr/sbin/usermod", result: process.CommandResult{ExitCode: 0}}
	rt := &runtime.Runtime{
		Exec:      runtime.NewExecRegistry(),
		States:    runtime.NewStateRegistry(),
		Facts:     facts.ForTesting(facts.Overrides{}),
		Providers: runtime.NewProviderRegistry(),
		Runner:    runner,
		FS:        fsys,
	}
	runner.afterRun = func(cmd process.Command) {
		if len(cmd.Args) != 3 || cmd.Args[0] != "-c" {
			return
		}
		data, err := mem.ReadFile(passwdPath)
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		for i, line := range lines {
			fields := strings.SplitN(line, ":", 7)
			if len(fields) == 7 && fields[0] == cmd.Args[2] {
				fields[4] = cmd.Args[1]
				lines[i] = strings.Join(fields, ":")
			}
		}
		_ = mem.WriteFile(passwdPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}
	return rt, fsys, runner
}

func anyValue(value any) *any { return &value }

func setSyntheticGecos(t *testing.T, fsys *trackedUserFS, gecos string) {
	t.Helper()
	data, err := fsys.FileSystem.ReadFile(passwdPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, line := range lines {
		fields := strings.SplitN(line, ":", 7)
		if len(fields) == 7 && fields[0] == "synthetic" {
			fields[4] = gecos
			lines[i] = strings.Join(fields, ":")
		}
	}
	if err := fsys.FileSystem.WriteFile(passwdPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestChotherDirectGuardsRejectBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name string
		args any
		want string
	}{
		{"nil args", nil, "user.chother: invalid arguments"},
		{"typed nil args", (*ChOtherArgs)(nil), "user.chother: invalid arguments"},
		{"missing other", &ChOtherArgs{Name: "synthetic"}, "missing required argument \"other\""},
		{"missing name", &ChOtherArgs{Other: anyValue("new")}, "missing required argument \"name\""},
		{"empty name", &ChOtherArgs{Name: "", Other: anyValue("new")}, "missing required argument \"name\""},
		{"leading hyphen name", &ChOtherArgs{Name: "-synthetic", Other: anyValue("new")}, "user.chother: invalid name"},
		{"single hyphen name", &ChOtherArgs{Name: "-", Other: anyValue("new")}, "user.chother: invalid name"},
		{"double hyphen name", &ChOtherArgs{Name: "--", Other: anyValue("new")}, "user.chother: invalid name"},
		{"option-like root name", &ChOtherArgs{Name: "-R/tmp", Other: anyValue("new")}, "user.chother: invalid name"},
		{"option-like uid name", &ChOtherArgs{Name: "--uid=0", Other: anyValue("new")}, "user.chother: invalid name"},
		{"colon name", &ChOtherArgs{Name: "bad:name", Other: anyValue("new")}, "user.chother: invalid name"},
		{"NUL name", &ChOtherArgs{Name: "bad\x00name", Other: anyValue("new")}, "user.chother: invalid name"},
		{"control name", &ChOtherArgs{Name: "bad\nname", Other: anyValue("new")}, "user.chother: invalid name"},
		{"invalid UTF-8 name", &ChOtherArgs{Name: string([]byte{0xff}), Other: anyValue("new")}, "user.chother: invalid name"},
		{"oversized name", &ChOtherArgs{Name: strings.Repeat("n", 4097), Other: anyValue("new")}, "user.chother: invalid name"},
		{"empty root rejected", &ChOtherArgs{Name: "synthetic", Other: anyValue("new"), Root: ""}, "user.chother: unsupported root"},
		{"slash root rejected", &ChOtherArgs{Name: "synthetic", Other: anyValue("new"), Root: "/"}, "user.chother: unsupported root"},
		{"alternate root rejected", &ChOtherArgs{Name: "synthetic", Other: anyValue("new"), Root: "/image"}, "user.chother: unsupported root"},
		{"typed nil root rejected", func() any {
			var root any = (*int)(nil)
			return &ChOtherArgs{Name: "synthetic", Other: anyValue("new"), Root: root}
		}(), "user.chother: unsupported root"},
		{"unsupported type", &ChOtherArgs{Name: "synthetic", Other: anyValue(true)}, "user.chother: invalid other type"},
		{"typed nil inner", func() any { var value any = (*int)(nil); return &ChOtherArgs{Name: "synthetic", Other: &value} }(), "user.chother: invalid other type"},
		{"uint64 range", &ChOtherArgs{Name: "synthetic", Other: anyValue(uint64(math.MaxInt64) + 1)}, "user.chother: other integer out of range"},
		{"raw other too long", &ChOtherArgs{Name: "synthetic", Other: anyValue(strings.Repeat(",", 4097))}, "user.chother: other exceeds limit"},
		{"other control", &ChOtherArgs{Name: "synthetic", Other: anyValue("bad\x7f")}, "user.chother: invalid other"},
		{"other colon", &ChOtherArgs{Name: "synthetic", Other: anyValue("bad:value")}, "user.chother: invalid other"},
		{"other NUL", &ChOtherArgs{Name: "synthetic", Other: anyValue("bad\x00value")}, "user.chother: invalid other"},
		{"invalid UTF-8 other", &ChOtherArgs{Name: "synthetic", Other: anyValue(string([]byte{0xff}))}, "user.chother: invalid other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newChotherRuntime(t)
			_, err := (chOtherFunc{}).Execute(context.Background(), rt, tc.args)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("execute error = %v, want %q", err, tc.want)
			}
			if fsys.boundedReads != 0 || fsys.unboundedRead != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
				t.Fatalf("invalid input caused effects: bounded=%d unbounded=%d resolve=%v commands=%v", fsys.boundedReads, fsys.unboundedRead, runner.resolveCalls, runner.commands)
			}
		})
	}
}

func TestChotherRegistryGuardsAndLinuxDirectPlatformCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		args any
		want string
	}{
		{"nil arguments", nil, "user.chother: invalid arguments"},
		{"typed nil arguments", (*ChOtherArgs)(nil), "user.chother: invalid arguments"},
		{"missing other", &ChOtherArgs{Name: "synthetic"}, "missing required argument \"other\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newChotherRuntime(t)
			reg := runtime.NewExecRegistry()
			if err := registerUserForGOOS(reg, "linux"); err != nil {
				t.Fatal(err)
			}
			rt.Exec = reg
			_, err := reg.Call(context.Background(), rt, "user.chother", tc.args)
			if err == nil || err.Error() != tc.want || fsys.boundedReads != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
				t.Fatalf("registry guard error=%v reads=%d resolver=%v commands=%v", err, fsys.boundedReads, runner.resolveCalls, runner.commands)
			}
		})
	}

	rt, fsys, runner := newChotherRuntime(t)
	_, err := executeChotherForGOOS(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")}, "darwin")
	if err == nil || err.Error() != "user.chother: unsupported platform" || fsys.boundedReads != 0 || fsys.unboundedRead != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
		t.Fatalf("direct non-Linux Execute = %v reads=%d/%d resolver=%v commands=%v", err, fsys.boundedReads, fsys.unboundedRead, runner.resolveCalls, runner.commands)
	}
}

func TestChotherRootNullDefaultAndExplicitEmptyFlag(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	args := &ChOtherArgs{}
	if err := config.Decode(args, map[string]any{"name": "synthetic", "other": "old", "root": nil}, nil); err != nil {
		t.Fatalf("null root binding: %v", err)
	}
	if args.Root != nil {
		t.Fatalf("null root must mean omitted: %#v", args.Root)
	}
	if value, err := (chOtherFunc{}).Execute(context.Background(), rt, args); err != nil || value != true || fsys.boundedReads != 1 || len(runner.commands) != 0 {
		t.Fatalf("null root no-op = %#v, %v reads=%d commands=%v", value, err, fsys.boundedReads, runner.commands)
	}

	rt, fsys, runner = newChotherRuntime(t)
	args = &ChOtherArgs{}
	if err := config.Decode(args, map[string]any{"name": "synthetic", "other": "new", "root": nil}, map[string]string{"root": ""}); err != nil {
		t.Fatalf("empty root flag binding: %v", err)
	}
	root, ok := args.Root.(string)
	if !ok || root != "" {
		t.Fatalf("explicit empty root flag = %#v", args.Root)
	}
	_, err := (chOtherFunc{}).Execute(context.Background(), rt, args)
	if err == nil || err.Error() != "user.chother: unsupported root" || fsys.boundedReads != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
		t.Fatalf("explicit root flag effects: err=%v reads=%d resolver=%v commands=%v", err, fsys.boundedReads, runner.resolveCalls, runner.commands)
	}
}

func TestChotherExactIntegerAndStringNormalization(t *testing.T) {
	type CountAlias = int64
	type ByteAlias = byte
	type RuneAlias = rune
	type NamedCount int64
	type NamedText string
	values := []struct {
		name  string
		value any
		want  string
	}{
		{"int zero", int(0), "0"}, {"int8 zero", int8(0), "0"}, {"int16 zero", int16(0), "0"},
		{"int32 zero", int32(0), "0"}, {"int64 zero", int64(0), "0"}, {"uint zero", uint(0), "0"},
		{"uint8 zero", uint8(0), "0"}, {"uint16 zero", uint16(0), "0"}, {"uint32 zero", uint32(0), "0"},
		{"uint64 zero", uint64(0), "0"}, {"int negative one", int(-1), "-1"}, {"int8 min", int8(-128), "-128"},
		{"int16 min", int16(-32768), "-32768"}, {"int32 min", int32(-2147483648), "-2147483648"},
		{"int64 min", int64(math.MinInt64), "-9223372036854775808"},
		{"int64 max", int64(math.MaxInt64), "9223372036854775807"},
		{"uint64 max int64", uint64(math.MaxInt64), "9223372036854775807"},
		{"uint8 max", uint8(255), "255"}, {"uint16 max", uint16(65535), "65535"},
		{"uint32 max", uint32(4294967295), "4294967295"}, {"uint max 32", uint(4294967295), "4294967295"},
		{"alias count", CountAlias(-1), "-1"}, {"byte alias", ByteAlias(0), "0"}, {"rune alias", RuneAlias(0), "0"},
		{"leading zeros string", "0007", "0007"}, {"signed-looking string", "+7", "+7"},
		{"numeric-looking oversized string", "9223372036854775808", "9223372036854775808"},
		{"whitespace string", " 7 ", " 7 "}, {"unicode string", "é7", "é7"},
	}
	if reflect.TypeOf(uint(0)).Bits() == 64 {
		maxInt64 := uint64(9223372036854775807)
		values = append(values,
			struct {
				name  string
				value any
				want  string
			}{"uint signed maximum", uint(maxInt64), "9223372036854775807"},
		)
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeOther(tc.value)
			if err != nil || got != tc.want {
				t.Fatalf("normalize %#v (%T) = %q, %v; want %q", tc.value, tc.value, got, err, tc.want)
			}
		})
	}

	ranges := []struct {
		name  string
		value any
		want  string
	}{
		{"uint64 over signed max", uint64(math.MaxInt64) + 1, "user.chother: other integer out of range"},
		{"uint64 maximum", uint64(math.MaxUint64), "user.chother: other integer out of range"},
	}
	if reflect.TypeOf(uint(0)).Bits() == 64 {
		overRange := uint64(9223372036854775808)
		ranges = append(ranges, struct {
			name  string
			value any
			want  string
		}{"uint over signed max", uint(overRange), "user.chother: other integer out of range"})
	}
	for _, tc := range ranges {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeOther(tc.value)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("normalize range error = %v, want %q", err, tc.want)
			}
		})
	}
	var typedNil any = (*int)(nil)
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"named integer", NamedCount(0)}, {"named string", NamedText("x")}, {"uintptr", uintptr(0)},
		{"json.Number", json.Number("0")}, {"float32 zero", float32(0)}, {"float64 zero", float64(0)},
		{"float64 negative", float64(-1)}, {"NaN", math.NaN()}, {"positive infinity", math.Inf(1)},
		{"bool true", true}, {"bool false", false}, {"complex64", complex64(0)}, {"complex128", complex128(0)},
		{"typed nil pointer", typedNil}, {"byte slice", []byte("7")}, {"list", []any{1}},
		{"map", map[string]any{}}, {"struct", struct{}{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeOther(tc.value)
			if err == nil || err.Error() != "user.chother: invalid other type" {
				t.Fatalf("normalize unsupported %#v (%T) = %v", tc.value, tc.value, err)
			}
		})
	}
}

func TestChotherExecDirectRegistryAndBoundDecodeScalarMatrix(t *testing.T) {
	type CountAlias = int64
	type ByteAlias = byte
	type RuneAlias = rune
	type NamedCount int64
	type NamedText string
	values := []struct {
		name  string
		value any
		want  string
	}{
		{"nil interface clears", nil, ""}, {"int zero", int(0), "0"}, {"int8 zero", int8(0), "0"},
		{"int16 zero", int16(0), "0"}, {"int32 zero", int32(0), "0"}, {"int64 zero", int64(0), "0"},
		{"uint zero", uint(0), "0"}, {"uint8 zero", uint8(0), "0"}, {"uint16 zero", uint16(0), "0"},
		{"uint32 zero", uint32(0), "0"}, {"uint64 zero", uint64(0), "0"}, {"int negative", int(-1), "-1"},
		{"int8 minimum", int8(-128), "-128"}, {"int16 minimum", int16(-32768), "-32768"},
		{"int32 minimum", int32(-2147483648), "-2147483648"}, {"int64 minimum", int64(math.MinInt64), "-9223372036854775808"},
		{"int64 maximum", int64(math.MaxInt64), "9223372036854775807"},
		{"uint64 signed maximum", uint64(math.MaxInt64), "9223372036854775807"},
		{"uint8 maximum", uint8(255), "255"}, {"uint16 maximum", uint16(65535), "65535"},
		{"uint32 maximum", uint32(4294967295), "4294967295"}, {"uint maximum on 32-bit", uint(4294967295), "4294967295"}, {"alias Count", CountAlias(-1), "-1"},
		{"byte alias", ByteAlias(0), "0"}, {"rune alias", RuneAlias(0), "0"},
		{"string exact", "0007", "0007"}, {"string plus", "+7", "+7"},
		{"string below integer domain", "-9223372036854775809", "-9223372036854775809"},
		{"string outside integer domain", "9223372036854775808", "9223372036854775808"},
		{"string whitespace", " 7 ", " 7 "}, {"string Unicode", "é7", "é7"},
	}
	if reflect.TypeOf(uint(0)).Bits() == 64 {
		maxInt64 := uint64(math.MaxInt64)
		values = append(values, struct {
			name  string
			value any
			want  string
		}{"uint signed maximum", uint(maxInt64), "9223372036854775807"})
	}
	reg := runtime.NewExecRegistry()
	if err := registerUserForGOOS(reg, "linux"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			for _, route := range []string{"direct", "registry", "structured binder"} {
				t.Run(route, func(t *testing.T) {
					rt, _, runner := newChotherRuntime(t)
					args := &ChOtherArgs{Name: "synthetic", Other: anyValue(tc.value)}
					if route == "structured binder" {
						args = &ChOtherArgs{Name: "synthetic"}
						if err := config.Decode(args, map[string]any{"name": "synthetic", "other": tc.value}, nil); err != nil {
							t.Fatalf("bind structured raw %T: %v", tc.value, err)
						}
					}
					var err error
					if route == "direct" {
						_, err = (chOtherFunc{}).Execute(context.Background(), rt, args)
					} else {
						_, err = reg.Call(context.Background(), rt, "user.chother", args)
					}
					wantGecos := "first,last,room,work"
					if tc.want != "" {
						wantGecos += "," + tc.want
					}
					if err != nil || len(runner.commands) != 1 || runner.commands[0].Args[1] != wantGecos {
						t.Fatalf("%s dispatch of %#v (%T): err=%v command=%+v want GECOS=%q", route, tc.value, tc.value, err, runner.commands, wantGecos)
					}
					if gotOther := splitGecos(runner.commands[0].Args[1])[4]; gotOther != tc.want {
						t.Fatalf("%s normalized fifth field = %q, want %q", route, gotOther, tc.want)
					}
				})
			}
		})
	}

	var typedNil any = (*int)(nil)
	invalidValues := []struct {
		name  string
		value any
		want  string
	}{
		{"float64 zero", float64(0), "user.chother: invalid other type"},
		{"float64 negative", float64(-1), "user.chother: invalid other type"},
		{"NaN", math.NaN(), "user.chother: invalid other type"},
		{"float32", float32(0), "user.chother: invalid other type"},
		{"NaN", math.NaN(), "user.chother: invalid other type"},
		{"positive infinity", math.Inf(1), "user.chother: invalid other type"},
		{"negative infinity", math.Inf(-1), "user.chother: invalid other type"},
		{"bool true", true, "user.chother: invalid other type"}, {"bool false", false, "user.chother: invalid other type"},
		{"json.Number", json.Number("0"), "user.chother: invalid other type"},
		{"out of range uint64", uint64(math.MaxInt64) + 1, "user.chother: other integer out of range"},
		{"maximum uint64", uint64(math.MaxUint64), "user.chother: other integer out of range"},
		{"named integer", NamedCount(0), "user.chother: invalid other type"},
		{"named string", NamedText("x"), "user.chother: invalid other type"},
		{"uintptr", uintptr(0), "user.chother: invalid other type"},
		{"complex64", complex64(0), "user.chother: invalid other type"},
		{"complex128", complex128(0), "user.chother: invalid other type"},
		{"typed nil pointer", typedNil, "user.chother: invalid other type"},
		{"byte slice", []byte("7"), "user.chother: invalid other type"},
		{"list", []any{1}, "user.chother: invalid other type"},
		{"map", map[string]any{}, "user.chother: invalid other type"},
		{"struct", struct{}{}, "user.chother: invalid other type"},
	}
	if reflect.TypeOf(uint(0)).Bits() == 64 {
		overRange := uint64(9223372036854775808)
		invalidValues = append(invalidValues, struct {
			name  string
			value any
			want  string
		}{"uint out of signed range", uint(overRange), "user.chother: other integer out of range"})
	}
	for _, tc := range invalidValues {
		t.Run(tc.name, func(t *testing.T) {
			for _, route := range []string{"direct", "registry", "structured binder"} {
				t.Run(route, func(t *testing.T) {
					rt, fsys, runner := newChotherRuntime(t)
					args := &ChOtherArgs{Name: "synthetic", Other: anyValue(tc.value)}
					if route == "structured binder" {
						args = &ChOtherArgs{Name: "synthetic"}
						if err := config.Decode(args, map[string]any{"name": "synthetic", "other": tc.value}, nil); err != nil {
							t.Fatalf("binder must preserve raw rejected type: %v", err)
						}
					}
					var err error
					if route == "direct" {
						_, err = (chOtherFunc{}).Execute(context.Background(), rt, args)
					} else {
						_, err = reg.Call(context.Background(), rt, "user.chother", args)
					}
					if err == nil || err.Error() != tc.want || fsys.boundedReads != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
						t.Fatalf("%s invalid dispatch: err=%v reads=%d resolver=%v commands=%v", route, err, fsys.boundedReads, runner.resolveCalls, runner.commands)
					}
				})
			}
		})
	}
}

func TestChotherExecNoopAndChangedCommandContract(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	value, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("old")})
	if err != nil || value != true || fsys.boundedReads != 1 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
		t.Fatalf("no-op = %#v, %v; bounded=%d resolve=%v commands=%v", value, err, fsys.boundedReads, runner.resolveCalls, runner.commands)
	}
	if !reflect.DeepEqual(fsys.boundedPaths, []string{passwdPath}) || !reflect.DeepEqual(fsys.boundedLimits, []int64{1 << 20}) || fsys.unboundedRead != 0 {
		t.Fatalf("no-op reads were not bounded passwd-only: paths=%v limits=%v unbounded=%d", fsys.boundedPaths, fsys.boundedLimits, fsys.unboundedRead)
	}

	rt, fsys, runner = newChotherRuntime(t)
	runner.result = process.CommandResult{ExitCode: 0, Stdout: []byte("synthetic output"), Stderr: []byte("different diagnostics")}
	runner.onResolve = func(name string) {
		if name != "usermod" || fsys.boundedReads != 1 {
			t.Errorf("helper resolution occurred before one bounded pre-read: name=%q reads=%d", name, fsys.boundedReads)
		}
	}
	runner.beforeRun = func(process.Command) {
		if fsys.boundedReads != 1 {
			t.Errorf("Runner launch occurred before bounded pre-read: reads=%d", fsys.boundedReads)
		}
	}
	value, err = (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err != nil || value != true {
		t.Fatalf("changed result = %#v, %v", value, err)
	}
	if fsys.boundedReads != 2 || !reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) || len(runner.commands) != 1 {
		t.Fatalf("changed effects: bounded=%d resolve=%v commands=%d", fsys.boundedReads, runner.resolveCalls, len(runner.commands))
	}
	if !reflect.DeepEqual(fsys.boundedPaths, []string{passwdPath, passwdPath}) || !reflect.DeepEqual(fsys.boundedLimits, []int64{1 << 20, 1 << 20}) || fsys.unboundedRead != 0 {
		t.Fatalf("changed reads were not bounded passwd-only: paths=%v limits=%v unbounded=%d", fsys.boundedPaths, fsys.boundedLimits, fsys.unboundedRead)
	}
	cmd := runner.commands[0]
	if cmd.Name != "/usr/sbin/usermod" || !reflect.DeepEqual(cmd.Args, []string{"-c", "first,last,room,work,new", "synthetic"}) || cmd.Dir != "/" ||
		cmd.Shell || cmd.Timeout != 30*time.Second || cmd.MaxStdoutBytes != 4096 || cmd.MaxStderrBytes != 4096 ||
		cmd.PreserveStdout || len(cmd.Stdin) != 0 || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}) {
		t.Fatalf("command contract = %+v", cmd)
	}
	for _, secret := range []string{"synthetic", "new", "first,last,room,work,new"} {
		if !containsString(cmd.Redact, secret) {
			t.Fatalf("redaction list %v omits %q", cmd.Redact, secret)
		}
	}
	if cmd.Args[0] != "-c" || strings.Contains(strings.Join(cmd.Redact, "\x00"), "old") {
		t.Fatalf("unexpected command/redaction content: %+v", cmd)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestChotherOptionLikeCommentRemainsOneArgument(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	setSyntheticGecos(t, fsys, "-u0")
	value, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err != nil || value != true || len(runner.commands) != 1 {
		t.Fatalf("option-like comment result = %#v, %v, commands=%+v", value, err, runner.commands)
	}
	cmd := runner.commands[0]
	if !reflect.DeepEqual(cmd.Args, []string{"-c", "-u0,,,,new", "synthetic"}) || cmd.Shell || cmd.Dir != "/" {
		t.Fatalf("option-like comment command = %+v", cmd)
	}
}

func TestChotherCwdFailureIsFixedAndDoesNotRetryOrReadBack(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	runner.afterRun = nil
	runner.result = process.CommandResult{Err: errors.New("synthetic cwd failure marker")}
	runner.beforeRun = func(cmd process.Command) {
		if cmd.Dir != "/" {
			t.Errorf("chother cwd = %q, want explicit /", cmd.Dir)
		}
	}
	_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err == nil || err.Error() != "user.chother: command failed" || strings.Contains(err.Error(), "synthetic cwd failure marker") {
		t.Fatalf("cwd failure = %v, want fixed command error", err)
	}
	if fsys.boundedReads != 1 || !reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) || len(runner.commands) != 1 || runner.commands[0].Dir != "/" {
		t.Fatalf("cwd failure effects: reads=%d resolver=%v commands=%+v", fsys.boundedReads, runner.resolveCalls, runner.commands)
	}
}

func TestChotherRedactsWholeBuiltGecosBeforeOverlappingInputs(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	setSyntheticGecos(t, fsys, "synthetic,last,room,work,old")
	runner.afterRun = func(cmd process.Command) {
		runner.result.Stdout = process.RedactBytes(cmd.Redact, []byte("captured:"+cmd.Args[1]))
	}
	_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("syn")})
	if err != nil || len(runner.commands) != 1 {
		t.Fatalf("redaction collision dispatch = %v, commands=%+v", err, runner.commands)
	}
	cmd := runner.commands[0]
	if len(cmd.Redact) == 0 || cmd.Redact[0] != cmd.Args[1] {
		t.Fatalf("full built GECOS is not the first redaction value: %+v", cmd.Redact)
	}
	rendered := cmd.RedactedString()
	captured := string(runner.result.Stdout)
	for name, output := range map[string]string{"command": rendered, "captured output": captured} {
		if strings.Contains(output, "last,room,work") || strings.Contains(output, "synthetic,last") || strings.Contains(output, ",syn") {
			t.Errorf("%s exposes part of built GECOS: %q", name, output)
		}
	}
}

func TestChotherFailureAndCancellationDoNotRetryOrReadBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result process.CommandResult
		cancel bool
		want   string
		launch int
	}{
		{"runner error", process.CommandResult{Err: errors.New("synthetic-marker")}, false, "user.chother: command failed", 1},
		{"nonzero", process.CommandResult{ExitCode: 9, Stderr: []byte("synthetic-marker")}, false, "user.chother: command failed", 1},
		{"timeout", process.CommandResult{Err: context.DeadlineExceeded}, false, "user.chother: command timed out", 1},
		{"runner canceled", process.CommandResult{Err: context.Canceled}, false, "user.chother: command canceled", 1},
		{"oversized output", process.CommandResult{ExitCode: 0, Stdout: []byte(strings.Repeat("x", 4097))}, false, "user.chother: command output limit exceeded", 1},
		{"oversized stderr", process.CommandResult{ExitCode: 0, Stderr: []byte(strings.Repeat("x", 4097))}, false, "user.chother: command output limit exceeded", 1},
		{"truncated output", process.CommandResult{ExitCode: 0, StdoutTruncated: true}, false, "user.chother: command output limit exceeded", 1},
		{"canceled before launch", process.CommandResult{ExitCode: 0}, true, "user.chother: command canceled", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newChotherRuntime(t)
			runner.result = tc.result
			ctx := context.Background()
			if tc.cancel {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			}
			_, err := (chOtherFunc{}).Execute(ctx, rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
			if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "synthetic-marker") {
				t.Fatalf("error = %v, want fixed %q", err, tc.want)
			}
			if len(runner.commands) != tc.launch || fsys.boundedReads != 1 {
				t.Fatalf("failure calls = %d, bounded reads=%d; want launch=%d, one pre-read", len(runner.commands), fsys.boundedReads, tc.launch)
			}
			if tc.launch == 1 && len(runner.resolveCalls) != 1 {
				t.Fatalf("resolver calls = %v, want one", runner.resolveCalls)
			}
			if tc.cancel && len(runner.resolveCalls) != 0 {
				t.Fatalf("pre-canceled context reached helper resolution: %v", runner.resolveCalls)
			}
		})
	}
}

func TestChotherCancellationAfterResolvePreventsLaunch(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	runner.onResolve = func(string) { cancel() }
	_, err := (chOtherFunc{}).Execute(ctx, rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err == nil || err.Error() != "user.chother: command canceled" || fsys.boundedReads != 1 ||
		!reflect.DeepEqual(runner.resolveCalls, []string{"usermod"}) || len(runner.commands) != 0 {
		t.Fatalf("post-resolve cancellation = %v reads=%d resolve=%v launches=%v", err, fsys.boundedReads, runner.resolveCalls, runner.commands)
	}
}

func TestChotherResolverAndBoundedFilesystemFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*runtime.Runtime, *trackedUserFS, *usermodTestRunner)
		want  string
	}{
		{"no resolver capability", func(rt *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) { rt.Runner = &fakeRunner{} }, "user.chother: unverified executable"},
		{"resolver error", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) {
			runner.resolveErr = errors.New("synthetic-marker")
		}, "user.chother: trusted helper unavailable"},
		{"empty resolver path", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) { runner.path = "" }, "user.chother: trusted helper unavailable"},
		{"relative resolver path", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) { runner.path = "usermod" }, "user.chother: trusted helper unavailable"},
		{"outside trusted roots", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) { runner.path = "/tmp/usermod" }, "user.chother: trusted helper unavailable"},
		{"unclean path", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) {
			runner.path = "/usr/../tmp/usermod"
		}, "user.chother: trusted helper unavailable"},
		{"NUL path", func(_ *runtime.Runtime, _ *trackedUserFS, runner *usermodTestRunner) {
			runner.path = "/usr/sbin/usermod\x00ignored"
		}, "user.chother: trusted helper unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newChotherRuntime(t)
			tc.setup(rt, fsys, runner)
			_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
			if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "synthetic-marker") {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("untrusted resolver launched commands: %+v", runner.commands)
			}
		})
	}

	rt, fsys, runner := newChotherRuntime(t)
	rt.FS = &unboundedOnlyUserFS{FileSystem: fsys.FileSystem}
	_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err == nil || err.Error() != "user.chother: bounded passwd reads unsupported" || len(runner.commands) != 0 || len(runner.resolveCalls) != 0 {
		t.Fatalf("unsupported bounded FS = %v, resolve=%v commands=%v", err, runner.resolveCalls, runner.commands)
	}
}

func TestChotherReadbackMismatchAndFailureAreExplicit(t *testing.T) {
	rt, fsys, runner := newChotherRuntime(t)
	runner.afterRun = nil // Successful status without a changed local record is a false return.
	value, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err != nil || value != false || fsys.boundedReads != 2 || len(runner.commands) != 1 {
		t.Fatalf("mismatch = %#v, %v, reads=%d launches=%d", value, err, fsys.boundedReads, len(runner.commands))
	}

	rt, fsys, runner = newChotherRuntime(t)
	runner.afterRun = func(process.Command) { fsys.readErr = errors.New("synthetic-marker") }
	_, err = (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err == nil || err.Error() != "user.chother: state unconfirmed" || strings.Contains(err.Error(), "synthetic-marker") || fsys.boundedReads != 2 || len(runner.commands) != 1 {
		t.Fatalf("readback failure = %v, reads=%d launches=%d", err, fsys.boundedReads, len(runner.commands))
	}
}

func TestChotherGecosSplitBuildAndTrailingCommaReadback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		gecos      string
		other      string
		want       string
		wantFields []string
	}{
		{"empty fields padded", "", "fifth", ",,,,fifth", []string{"", "", "", ""}},
		{"intermediate empty fields", "first,,room", "fifth", "first,,room,,fifth", []string{"first", "", "room", ""}},
		{"split at four commas", "a,b,c,d,e,f", "new", "a,b,c,d,new", []string{"a", "b", "c", "d"}},
		{"embedded comma in fifth", "a,b,c,d,old,extra", "new,value", "a,b,c,d,new,value", []string{"a", "b", "c", "d"}},
		{"Unicode fields", "α,β,γ,δ,old", "é,ø", "α,β,γ,δ,é,ø", []string{"α", "β", "γ", "δ"}},
		{"trailing comma stripped", "a,b,c,d,old", "new,", "a,b,c,d,new", []string{"a", "b", "c", "d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parts := splitGecos(tc.gecos)
			if !reflect.DeepEqual(parts[:4], tc.wantFields) {
				t.Fatalf("first four fields = %#v, want %#v", parts[:4], tc.wantFields)
			}
			got, err := buildGecos(tc.gecos, tc.other)
			if err != nil || got != tc.want {
				t.Fatalf("buildGecos(%q,%q) = %q, %v; want %q", tc.gecos, tc.other, got, err, tc.want)
			}
			if gotOther := splitGecos(got)[4]; gotOther == tc.other && strings.HasSuffix(tc.other, ",") {
				t.Fatalf("trailing-comma readback unexpectedly matched %q", tc.other)
			}
		})
	}

	rt, fsys, runner := newChotherRuntime(t)
	value, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new,")})
	if err != nil || value != false || len(runner.commands) != 1 || fsys.boundedReads != 2 {
		t.Fatalf("trailing-comma readback = %#v, %v, launches=%d reads=%d", value, err, len(runner.commands), fsys.boundedReads)
	}
}

func TestChotherStrictLocalPasswdParser(t *testing.T) {
	const valid = "synthetic:x:000:4294967294:first,last,room,work,old:/home/synthetic:/bin/false"
	entry, err := parseLocalPasswd([]byte("\n# synthetic fixture\n"+valid+"\n\n"), "synthetic")
	if err != nil || entry.Name != "synthetic" || entry.UID != "000" || entry.GID != "4294967294" || entry.gecos != "first,last,room,work,old" || entry.Home != "/home/synthetic" || entry.Shell != "/bin/false" {
		t.Fatalf("strict record = %+v, %v", entry, err)
	}
	if _, err := parseLocalPasswd([]byte(valid), "synthetic"); err != nil {
		t.Fatalf("missing final LF must be allowed: %v", err)
	}
	if _, err := parseLocalPasswd([]byte("synthetic:x:1:2:"+strings.Repeat("g", 4096)+":h:s\n"), "synthetic"); err != nil {
		t.Fatalf("4096-byte existing GECOS must pass: %v", err)
	}

	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"missing exact name", "Synthetic:x:1:2:g:h:s\n", "user.chother: account not found"},
		{"duplicate exact target", valid + "\n" + valid + "\n", "user.chother: duplicate account"},
		{"malformed unrelated record", "other:x:1:2:g:h:s\nmalformed\n" + valid + "\n", "user.chother: malformed passwd data"},
		{"six fields", "synthetic:x:1:2:g:h\n", "user.chother: malformed passwd data"},
		{"eight fields", "synthetic:x:1:2:g:h:s:extra\n", "user.chother: malformed passwd data"},
		{"CRLF", valid + "\r\n", "user.chother: malformed passwd data"},
		{"whitespace is not trimmed", " synthetic:x:1:2:g:h:s\n", "user.chother: account not found"},
		{"empty name", ":x:1:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"leading hyphen name", "-synthetic:x:1:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID empty", "synthetic:x::2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID plus sign", "synthetic:x:+1:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID negative", "synthetic:x:-1:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID space", "synthetic:x: 1:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID fraction", "synthetic:x:1.0:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID non-ASCII digit", "synthetic:x:١:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"UID overflow", "synthetic:x:4294967295:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"GID overflow", "synthetic:x:1:4294967296:g:h:s\n", "user.chother: malformed passwd data"},
		{"NUL in password field", "synthetic:x:\x001:2:g:h:s\n", "user.chother: malformed passwd data"},
		{"DEL in record", "synthetic:x:1:2:g\x7f:h:s\n", "user.chother: malformed passwd data"},
		{"invalid UTF-8", "synthetic:x:1:2:\xff:h:s\n", "user.chother: malformed passwd data"},
		{"oversized GECOS", "synthetic:x:1:2:" + strings.Repeat("g", 4097) + ":h:s\n", "user.chother: existing GECOS exceeds limit"},
		{"UID overflow beyond uint32", "synthetic:x:4294967296:2:g:h:s\n", "user.chother: malformed passwd data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLocalPasswd([]byte(tc.data), "synthetic")
			if err == nil || err.Error() != tc.want {
				t.Fatalf("parse error = %v, want %q", err, tc.want)
			}
		})
	}

	for _, id := range []string{"0", "0007", "4294967294"} {
		data := "synthetic:x:" + id + ":" + id + ":g:h:s\n"
		if _, err := parseLocalPasswd([]byte(data), "synthetic"); err != nil {
			t.Fatalf("valid UID/GID %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"", "+1", "-1", " 1", "1.0", "١", "4294967295", "18446744073709551616"} {
		data := "synthetic:x:1:" + id + ":g:h:s\n"
		if _, err := parseLocalPasswd([]byte(data), "synthetic"); err == nil || err.Error() != "user.chother: malformed passwd data" {
			t.Fatalf("invalid GID %q parse error = %v", id, err)
		}
	}

	maxName := strings.Repeat("n", 4096)
	if _, err := parseLocalPasswd([]byte(maxName+":x:0:0:g:h:s\n"), maxName); err != nil {
		t.Fatalf("4096-byte name rejected: %v", err)
	}
	if _, err := parseLocalPasswd([]byte(strings.Repeat("n", 4097)+":x:0:0:g:h:s\n"), strings.Repeat("n", 4097)); err == nil || err.Error() != "user.chother: invalid name" {
		t.Fatalf("4097-byte name error = %v", err)
	}
}

func TestChotherPasswdAndGecosByteLimits(t *testing.T) {
	if err := validateOther(strings.Repeat("x", 4096)); err != nil {
		t.Fatalf("4096-byte input rejected before build: %v", err)
	}
	if err := validateOther(strings.Repeat("x", 4097)); err == nil || err.Error() != "user.chother: other exceeds limit" {
		t.Fatalf("4097-byte input error = %v", err)
	}
	if err := validateOther(strings.Repeat("é", 2048)); err != nil {
		t.Fatalf("4096 UTF-8 bytes rejected: %v", err)
	}
	if err := validateOther(strings.Repeat("é", 2049)); err == nil {
		t.Fatal("4098 UTF-8 bytes must be rejected")
	}

	// The raw 4096-byte value is within its own cap but cannot fit into the
	// complete four-separator GECOS. Its built-output limit is independent.
	rt, fsys, runner := newChotherRuntime(t)
	_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue(strings.Repeat("x", 4096))})
	if err == nil || err.Error() != "user.chother: built GECOS exceeds limit" || fsys.boundedReads != 1 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
		t.Fatalf("raw 4096-byte input result=%v reads=%d resolver=%v commands=%v", err, fsys.boundedReads, runner.resolveCalls, runner.commands)
	}

	// Four thousand and ninety-six built bytes are allowed; one more is
	// rejected before resolver/Runner work.
	const gecosByteLimit = 4096
	const preservedSeparators = ",,,"
	const preservedFourthField = "old"
	const separatorBeforeFifth = ","
	desiredAtLimit := "xxxx"
	firstFieldBytes := gecosByteLimit - len(preservedSeparators) -
		len(preservedFourthField) - len(separatorBeforeFifth) - len(desiredAtLimit)
	firstField := strings.Repeat("a", firstFieldBytes)
	existing := firstField + preservedSeparators + preservedFourthField
	expectedAtLimit := existing + separatorBeforeFifth + desiredAtLimit
	if len(expectedAtLimit) != gecosByteLimit {
		t.Fatalf("test construction length = %d, want %d", len(expectedAtLimit), gecosByteLimit)
	}
	rt, fsys, runner = newChotherRuntime(t)
	setSyntheticGecos(t, fsys, existing)
	value, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue(desiredAtLimit)})
	if err != nil || value != true || len(runner.commands) != 1 ||
		len(runner.commands[0].Args[1]) != gecosByteLimit || runner.commands[0].Args[1] != expectedAtLimit {
		t.Fatalf("exact 4096-byte built GECOS = %#v, %v, command=%+v", value, err, runner.commands)
	}
	desiredOverLimit := "xxxxx"
	expectedOverLimit := existing + separatorBeforeFifth + desiredOverLimit
	if len(expectedOverLimit) != gecosByteLimit+1 {
		t.Fatalf("over-limit test construction length = %d, want %d", len(expectedOverLimit), gecosByteLimit+1)
	}
	rt, fsys, runner = newChotherRuntime(t)
	setSyntheticGecos(t, fsys, existing)
	_, err = (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue(desiredOverLimit)})
	if err == nil || err.Error() != "user.chother: built GECOS exceeds limit" || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
		t.Fatalf("4097-byte built GECOS error=%v resolver=%v commands=%v", err, runner.resolveCalls, runner.commands)
	}

	// A 1 MiB passwd file is accepted; the same file plus one byte is
	// rejected by the bounded read path before any helper resolution.
	record := "synthetic:x:1:2:g:h:s\n"
	padding := strings.Repeat("#", 1<<20-len(record)-1) + "\n"
	if len(padding)+len(record) != 1<<20 {
		t.Fatalf("test construction length = %d", len(padding)+len(record))
	}
	rt, fsys, _ = newChotherRuntime(t)
	if err := fsys.FileSystem.WriteFile(passwdPath, []byte(padding+record), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLocalPasswd(rt, "synthetic"); err != nil {
		t.Fatalf("exact 1 MiB file rejected: %v", err)
	}
	if err := fsys.FileSystem.WriteFile(passwdPath, []byte(padding+record+"#"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
	if err == nil || err.Error() != "user.chother: passwd exceeds limit" {
		t.Fatalf("over-limit passwd error = %v", err)
	}
}

func TestChotherStateReadbackAndNativeFailuresAreValueFree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*runtime.Runtime, *trackedUserFS, *usermodTestRunner)
		want  string
	}{
		{"missing local account", func(_ *runtime.Runtime, fsys *trackedUserFS, _ *usermodTestRunner) {
			_ = fsys.FileSystem.WriteFile(passwdPath, []byte("other:x:1:2:g:h:s\n"), 0o644)
		}, "user.chother: account not found"},
		{"read error", func(_ *runtime.Runtime, fsys *trackedUserFS, _ *usermodTestRunner) {
			fsys.readErr = errors.New("synthetic-marker")
		}, "user.chother: passwd read failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, fsys, runner := newChotherRuntime(t)
			tc.setup(rt, fsys, runner)
			_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue("new")})
			if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), "synthetic-marker") || len(runner.commands) != 0 || len(runner.resolveCalls) != 0 {
				t.Fatalf("read failure = %v, resolve=%v commands=%v", err, runner.resolveCalls, runner.commands)
			}
		})
	}
}

func TestChotherIntOverflowAndUnsupportedValuesHaveZeroEffects(t *testing.T) {
	var typedNil any = (*int)(nil)
	for _, value := range []any{
		uint64(math.MaxInt64) + 1, uint64(math.MaxUint64), json.Number("0"), float64(0), float32(1), true,
		complex128(0), uintptr(0), typedNil, []any{1}, map[string]any{"x": "y"},
	} {
		rt, fsys, runner := newChotherRuntime(t)
		_, err := (chOtherFunc{}).Execute(context.Background(), rt, &ChOtherArgs{Name: "synthetic", Other: anyValue(value)})
		if err == nil || fsys.boundedReads != 0 || len(runner.resolveCalls) != 0 || len(runner.commands) != 0 {
			t.Fatalf("invalid %#v (%T): err=%v bounded=%d resolver=%v commands=%v", value, value, err, fsys.boundedReads, runner.resolveCalls, runner.commands)
		}
	}
}

func TestChotherLinuxRegistrationOnly(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd", "openbsd", "netbsd", "solaris", "aix", "unknown"} {
		t.Run(goos, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := registerUserForGOOS(reg, goos); err != nil {
				t.Fatalf("register for %s: %v", goos, err)
			}
			fn, registered := reg.Get("user.chother")
			if registered != (goos == "linux") {
				t.Fatalf("user.chother registered on %s = %v", goos, registered)
			}
			if !registered {
				return
			}
			if fn.Name() != "user.chother" || !runtime.SupportsPlatform(fn, goos) {
				t.Fatalf("Linux Chother name/platform = %q/%v", fn.Name(), runtime.SupportsPlatform(fn, goos))
			}
			platform, ok := fn.(runtime.PlatformConstrained)
			if !ok || !reflect.DeepEqual(platform.Platforms(), []string{"linux"}) {
				t.Fatalf("Linux Chother Platforms = %v, want [linux]", platform)
			}
			proto := fn.Args()
			argsType := reflect.TypeOf(proto)
			if argsType != reflect.TypeOf(ChOtherArgs{}) {
				t.Fatalf("Linux Chother prototype = %T, want ChOtherArgs", proto)
			}
			otherField, ok := argsType.FieldByName("Other")
			if !ok || otherField.Type != reflect.TypeOf((*any)(nil)) || otherField.Tag.Get("statekit") != "required,name=other" {
				t.Fatalf("Linux Chother Other field = %+v, want required *any", otherField)
			}
		})
	}
}
