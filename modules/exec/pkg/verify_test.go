package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
	pkgprovider "github.com/friz-zy/statekit/providers/pkg"
)

func TestVerifyRegistryProviderMatrix(t *testing.T) {
	// Provider contract mirrors saltstack/salt/modules/rpm_lowpkg.py:159-253;
	// no real package tool is run.
	for _, manager := range []string{"yum", "dnf", "dnf5"} {
		reg := runtime.NewExecRegistry()
		if err := Register(reg); err != nil {
			t.Fatal(err)
		}
		providers := runtime.NewProviderRegistry()
		if err := pkgprovider.Register(providers); err != nil {
			t.Fatal(err)
		}
		r := &verifyExecRunner{result: process.CommandResult{Stdout: []byte(""), ExitCode: 0}}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: r}
		prototype, err := reg.ResolveArgs(rt, "pkg.verify")
		if err != nil || reflect.TypeOf(prototype) != reflect.TypeOf(VerifyArgs{}) {
			t.Fatalf("%s prototype=%T err=%v", manager, prototype, err)
		}
		if names, err := config.ArgumentNames(prototype); err != nil || !reflect.DeepEqual(names, []string{"ignore_types", "names", "root", "verify_options"}) {
			t.Fatalf("%s names=%v err=%v", manager, names, err)
		}
		if caps := reg.ProviderCapabilities("pkg.verify"); !reflect.DeepEqual(caps, []string{"yumpkg", "zypperpkg"}) {
			t.Fatalf("caps=%v", caps)
		}
		got, err := reg.Call(context.Background(), rt, "pkg.verify", &VerifyArgs{})
		if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(r.commands) != 1 {
			t.Fatalf("%s got=%#v err=%v commands=%#v", manager, got, err, r.commands)
		}
		if !reflect.DeepEqual(append([]string{r.commands[0].Name}, r.commands[0].Args...), []string{"rpm", "-Va"}) || r.commands[0].Shell {
			t.Fatalf("argv=%#v", r.commands[0])
		}
	}
	for _, manager := range []string{"apt"} {
		reg := runtime.NewExecRegistry()
		_ = Register(reg)
		providers := runtime.NewProviderRegistry()
		_ = pkgprovider.Register(providers)
		r := &verifyExecRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: r}
		if _, err := reg.ResolveArgs(rt, "pkg.verify"); err == nil {
			t.Fatalf("%s resolved", manager)
		}
		if _, err := reg.Call(context.Background(), rt, "pkg.verify", &VerifyArgs{}); err == nil || len(r.commands) != 0 {
			t.Fatalf("%s err=%v calls=%d", manager, err, len(r.commands))
		}
	}
}

func TestVerifyRegistryRejectsWrongPointer(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	r := &verifyExecRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: r}
	if _, err := reg.Call(context.Background(), rt, "pkg.verify", &struct{}{}); err == nil || len(r.commands) != 0 {
		t.Fatalf("err=%v calls=%d", err, len(r.commands))
	}
}

func TestVerifyRegistryArgumentShapeAndInvocationMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		args VerifyArgs
		argv []string
	}{
		{name: "default", argv: []string{"rpm", "-Va"}},
		{name: "names", args: VerifyArgs{Names: []string{"a", "b"}}, argv: []string{"rpm", "-V", "a", "b"}},
		{name: "root and options", args: VerifyArgs{Root: func() *string { v := "/target"; return &v }(), VerifyOptions: "foo,bar", Names: []string{"a"}}, argv: []string{"rpm", "--root", "/target", "--foo", "--bar", "-V", "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			providers := runtime.NewProviderRegistry()
			if err := pkgprovider.Register(providers); err != nil {
				t.Fatal(err)
			}
			r := &verifyExecRunner{result: process.CommandResult{Stdout: []byte(""), ExitCode: 0}}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "dnf5"}), Providers: providers, Runner: r}
			got, err := reg.Call(context.Background(), rt, "pkg.verify", &tc.args)
			if err != nil || !reflect.DeepEqual(got, map[string]any{}) || len(r.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
			cmd := r.commands[0]
			if !reflect.DeepEqual(append([]string{cmd.Name}, cmd.Args...), tc.argv) || cmd.Shell || cmd.MaxStdoutBytes != 1<<20 || cmd.MaxStderrBytes != 1<<20 {
				t.Fatalf("command=%#v", cmd)
			}
		})
	}
}

func TestVerifyRegistryRejectsMalformedArgsAndProviderBeforeRunner(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	providers := runtime.NewProviderRegistry()
	if err := pkgprovider.Register(providers); err != nil {
		t.Fatal(err)
	}
	for _, manager := range []string{"apt"} {
		r := &verifyExecRunner{}
		rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: manager}), Providers: providers, Runner: r}
		if _, err := reg.ResolveArgs(rt, "pkg.verify"); err == nil {
			t.Fatalf("%s resolved", manager)
		}
		if _, err := reg.Call(context.Background(), rt, "pkg.verify", &VerifyArgs{}); err == nil || len(r.commands) != 0 {
			t.Fatalf("%s err=%v calls=%d", manager, err, len(r.commands))
		}
	}
	r := &verifyExecRunner{}
	rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: r}
	for _, arg := range []any{&struct{}{}, VerifyArgs{}} {
		if _, err := reg.Call(context.Background(), rt, "pkg.verify", arg); err == nil {
			t.Fatalf("accepted %T", arg)
		}
	}
	if len(r.commands) != 0 {
		t.Fatalf("malformed calls=%d", len(r.commands))
	}
}

func TestVerifyRegistryPropagatesRunnerAndContextErrors(t *testing.T) {
	sentinel := errors.New("runner failure")
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		result process.CommandResult
		want   error
	}{
		{name: "runner", ctx: context.Background(), result: process.CommandResult{Err: sentinel}, want: sentinel},
		{name: "cancel", ctx: func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(), result: process.CommandResult{Err: context.Canceled}, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := runtime.NewExecRegistry()
			if err := Register(reg); err != nil {
				t.Fatal(err)
			}
			providers := runtime.NewProviderRegistry()
			if err := pkgprovider.Register(providers); err != nil {
				t.Fatal(err)
			}
			r := &verifyExecRunner{result: tc.result}
			rt := &runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{Package: "yum"}), Providers: providers, Runner: r}
			got, err := reg.Call(tc.ctx, rt, "pkg.verify", &VerifyArgs{})
			if got != nil || !errors.Is(err, tc.want) || len(r.commands) != 1 {
				t.Fatalf("got=%#v err=%v calls=%d", got, err, len(r.commands))
			}
		})
	}
}

type verifyExecRunner struct {
	commands []process.Command
	result   process.CommandResult
}

func (r *verifyExecRunner) Run(_ context.Context, c process.Command) process.CommandResult {
	r.commands = append(r.commands, c)
	return r.result
}
