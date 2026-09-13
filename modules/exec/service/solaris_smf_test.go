package service

// Mock coverage for every public function in the pinned smf_service source.
// The Runner is recording-only and returns pinned svcs/svcadm/svccfg fixtures;
// no Solaris service manager is started.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type smfFakeRunner struct {
	results       map[string][]process.CommandResult
	defaultResult process.CommandResult
	calls         []process.Command
}

func (r *smfFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if queued := r.results[key]; len(queued) > 0 {
		result := queued[0]
		r.results[key] = queued[1:]
		return result
	}
	return r.defaultResult
}

func smfArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertSMFBounded(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != smfCommandTimeout ||
		command.MaxStdoutBytes != smfOutputLimit || command.MaxStderrBytes != smfOutputLimit {
		t.Fatalf("unsafe SMF command: %#v", command)
	}
}

func TestSMFRegistryMatrixAndArgs(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"service.get_running":  {smfNoArgs{}, []string{}},
		"service.get_stopped":  {smfNoArgs{}, []string{}},
		"service.available":    {smfNameArgs{}, []string{"name"}},
		"service.missing":      {smfNameArgs{}, []string{"name"}},
		"service.get_all":      {smfNoArgs{}, []string{}},
		"service.start":        {smfNameArgs{}, []string{"name"}},
		"service.stop":         {smfNameArgs{}, []string{"name"}},
		"service.restart":      {smfNameArgs{}, []string{"name"}},
		"service.reload":       {smfNameArgs{}, []string{"name"}},
		"service.status":       {smfStatusArgs{}, []string{"name", "sig"}},
		"service.enable":       {smfNameKwargsArgs{}, []string{"kwargs", "name"}},
		"service.disable":      {smfNameKwargsArgs{}, []string{"kwargs", "name"}},
		"service.enabled":      {smfNameKwargsArgs{}, []string{"kwargs", "name"}},
		"service.disabled":     {smfNameArgs{}, []string{"name"}},
		"service.get_enabled":  {smfNoArgs{}, []string{}},
		"service.get_disabled": {smfNoArgs{}, []string{}},
	}
	if reg.Len() != len(want) {
		t.Fatalf("registry length=%d want=%d", reg.Len(), len(want))
	}
	for name, row := range want {
		fn, ok := reg.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if reflect.TypeOf(fn.Args()) != reflect.TypeOf(row.prototype) {
			t.Fatalf("%s args type=%T want=%T", name, fn.Args(), row.prototype)
		}
		got, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(got, row.args) {
			t.Fatalf("%s args=%v err=%v want=%v", name, got, err, row.args)
		}
		constrained, ok := fn.(runtime.PlatformConstrained)
		if !ok || !reflect.DeepEqual(constrained.Platforms(), []string{"solaris"}) {
			t.Fatalf("%s platform constraint=%v/%t", name, constrained, ok)
		}
	}
	if err := registerSolaris(reg); err == nil {
		t.Fatal("duplicate Solaris registration accepted")
	}
	decoded := &smfNameKwargsArgs{}
	if err := config.Decode(decoded, map[string]any{
		"name":   "svc:/a",
		"kwargs": map[string]any{"temporary": true},
	}, nil); err != nil {
		t.Fatalf("structured **kwargs decode failed: %v", err)
	}
	if decoded.Name != "svc:/a" || !reflect.DeepEqual(decoded.Kwargs, map[string]any{"temporary": true}) {
		t.Fatalf("decoded kwargs=%#v", decoded)
	}
	if runtime.CurrentGOOS() != "solaris" && len(reg.Names()) != 0 {
		t.Fatalf("Solaris names leaked into Linux Names: %v", reg.Names())
	}
}

func TestSMFRegisterKeepsLinuxServiceSurface(t *testing.T) {
	if runtime.CurrentGOOS() == "solaris" {
		t.Skip("Linux surface assertion does not apply on Solaris")
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service.get_running", "service.get_stopped", "service.get_all", "service.get_enabled", "service.get_disabled"} {
		if _, ok := reg.Get(name); ok {
			t.Fatalf("Linux registry unexpectedly exposes %s", name)
		}
	}
	for _, name := range []string{"service.start", "service.stop", "service.restart", "service.status", "service.enable", "service.disable", "service.enabled"} {
		count := 0
		for _, registered := range reg.Names() {
			if registered == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("Linux %s registration count=%d", name, count)
		}
	}
}

func TestSMFListingAvailabilityAndExactArgv(t *testing.T) {
	ctx := context.Background()
	runner := &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcs -H -o FMRI,STATE -s FMRI": {{Stdout: []byte("svc:/z online\nsvc:/a maintenance\n")}},
		"/usr/bin/svcs -aH -o FMRI,STATE -s FMRI": {
			{Stdout: []byte("svc:/z online\nsvc:/a maintenance\nsvc:/legacy legacy_run\n")},
			{Stdout: []byte("svc:/z online\nsvc:/a maintenance\n")},
			{Stdout: []byte("svc:/z online\nsvc:/a maintenance\n")},
			{Stdout: []byte("svc:/z online\nsvc:/a maintenance\n")},
		},
		"/usr/bin/svcs -H -o FMRI svc:/z":     {{Stdout: []byte("svc:/z\n")}},
		"/usr/bin/svcs -H -o FMRI svc:/ghost": {{Stdout: []byte("svc:/ghost\n")}},
	}}
	rt := &runtime.Runtime{Runner: runner}
	got, err := (smfGetRunningFunc{}).Execute(ctx, rt, smfNoArgs{})
	if err != nil || !reflect.DeepEqual(got, []string{"svc:/z"}) {
		t.Fatalf("get_running=%#v err=%v", got, err)
	}
	got, err = (smfGetStoppedFunc{}).Execute(ctx, rt, smfNoArgs{})
	if err != nil || !reflect.DeepEqual(got, []string{"svc:/a"}) {
		t.Fatalf("get_stopped=%#v err=%v", got, err)
	}
	got, err = (smfGetAllFunc{}).Execute(ctx, rt, smfNoArgs{})
	if err != nil || !reflect.DeepEqual(got, []string{"svc:/a", "svc:/z"}) {
		t.Fatalf("get_all=%#v err=%v", got, err)
	}
	got, err = (smfAvailableFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/z"})
	if err != nil || got != true {
		t.Fatalf("available=%#v err=%v", got, err)
	}
	got, err = (smfMissingFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/ghost"})
	if err != nil || got != true {
		t.Fatalf("missing=%#v err=%v", got, err)
	}
	for _, call := range runner.calls {
		assertSMFBounded(t, call)
	}
	if got := smfArgv(runner.calls[0]); !reflect.DeepEqual(got, []string{"/usr/bin/svcs", "-H", "-o", "FMRI,STATE", "-s", "FMRI"}) {
		t.Fatalf("running argv=%v", got)
	}
}

func TestSMFFnmatchPythonSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"svc:/[!a]", "svc:/b", true},
		{"svc:/[!a]", "svc:/a", false},
		// Python fnmatch recognizes !, but ^ is literal class data.
		{"svc:/[^a]", "svc:/a", true},
		{"svc:/[^a]", "svc:/b", false},
		{"a/b", "a/b", true},
		{"svc:/*", "svc:/a/b", true},
		{"a/?/c", "a/b/c", true},
		{"svc:/[0-9]", "svc:/7", true},
		{"svc:/[0-9]", "svc:/a", false},
		{"svc:/[z-a]", "svc:/a", false},
		{"svc:/[!z-a]", "svc:/a", true},
		{"[--!]", "-", false},
		{"[--!]", "!", false},
		{"[--!]", "a", false},
		{"[!--!]", "-", true},
		{"[!--!]", "!", true},
		{"[!--!]", "a", true},
		{"svc:/[]a]", "svc:/a", true},
		{"svc:/[]a]", "svc:/]", true},
		{"svc:/[]a]", "svc:/b", false},
		{"svc:/[]-a]", "svc:/^", true},
		{"svc:/[]-a]", "svc:/-", false},
		{"svc:/[!]-a]", "svc:/-", true},
		{"svc:/[!]-a]", "svc:/^", false},
		{"svc:/literal[", "svc:/literal[", true},
		{"svc:/[", "svc:/[", true},
		{"svc:/[a*", "svc:/[abc", true},
		{"svc:/[a*", "svc:/abc", false},
	}
	for _, tc := range tests {
		if got := smfGlobMatch(tc.pattern, tc.name); got != tc.want {
			t.Errorf("smfGlobMatch(%q, %q)=%v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"svc:/[]a]", true},
		{"svc:/[]-a]", true},
		{"svc:/[!]-a]", true},
		{"svc:/[--!]", true},
		{"svc:/[!--!]", true},
		{"svc:/[]", false},
		{"svc:/literal[", false},
	} {
		if got := smfContainsGlobbing(tc.name); got != tc.want {
			t.Errorf("smfContainsGlobbing(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
	pattern := strings.Repeat("[", 4096)
	if !smfGlobMatch(pattern, pattern) {
		t.Fatalf("smfGlobMatch(%d-byte malformed pattern, same name)=false, want true", len(pattern))
	}
}

func TestSMFStatusPublicPatternTypesAndArgv(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := registerSolaris(reg); err != nil {
		t.Fatal(err)
	}
	fn, ok := reg.Get("service.status")
	if !ok {
		t.Fatal("service.status is not registered")
	}

	testCases := []struct {
		name   string
		all    string
		states map[string]string
		want   any
		argv   [][]string
	}{
		{
			name:   "svc:/a",
			states: map[string]string{"svc:/a": "online\n"},
			want:   true,
			argv:   [][]string{{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/a"}},
		},
		{
			name: "svc:/[]a]",
			all:  "svc:/a online\nsvc:/] maintenance\nsvc:/^ online\nsvc:/- maintenance\n",
			states: map[string]string{
				"svc:/a": "online\n", "svc:/]": "maintenance\n",
			},
			want: map[string]bool{"svc:/a": true, "svc:/]": false},
			argv: [][]string{
				{"/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/]"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/a"},
			},
		},
		{
			name: "svc:/[]-a]",
			all:  "svc:/a online\nsvc:/] maintenance\nsvc:/^ online\nsvc:/- maintenance\n",
			states: map[string]string{
				"svc:/a": "online\n", "svc:/]": "maintenance\n", "svc:/^": "online\n",
			},
			want: map[string]bool{"svc:/a": true, "svc:/]": false, "svc:/^": true},
			argv: [][]string{
				{"/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/]"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/^"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/a"},
			},
		},
		{
			name:   "svc:/[!]-a]",
			all:    "svc:/a online\nsvc:/] maintenance\nsvc:/^ online\nsvc:/- maintenance\n",
			states: map[string]string{"svc:/-": "maintenance\n"},
			want:   map[string]bool{"svc:/-": false},
			argv: [][]string{
				{"/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/-"},
			},
		},
		{
			name: "svc:/[--!]",
			all:  "svc:/! maintenance\nsvc:/- online\nsvc:/a online\n",
			want: map[string]bool{},
			argv: [][]string{
				{"/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI"},
			},
		},
		{
			name: "svc:/[!--!]",
			all:  "svc:/! maintenance\nsvc:/- online\nsvc:/a online\n",
			states: map[string]string{
				"svc:/!": "maintenance\n", "svc:/-": "online\n", "svc:/a": "online\n",
			},
			want: map[string]bool{"svc:/!": false, "svc:/-": true, "svc:/a": true},
			argv: [][]string{
				{"/usr/bin/svcs", "-aH", "-o", "FMRI,STATE", "-s", "FMRI"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/!"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/-"},
				{"/usr/bin/svcs", "-H", "-o", "STATE", "svc:/a"},
			},
		},
	}
	for _, tests := range testCases {
		t.Run(tests.name, func(t *testing.T) {
			results := map[string][]process.CommandResult{}
			if tests.all != "" {
				results["/usr/bin/svcs -aH -o FMRI,STATE -s FMRI"] = []process.CommandResult{{Stdout: []byte(tests.all)}}
			}
			for serviceName, state := range tests.states {
				results["/usr/bin/svcs -H -o STATE "+serviceName] = []process.CommandResult{{Stdout: []byte(state)}}
			}
			runner := &smfFakeRunner{results: results}
			got, err := fn.Execute(context.Background(), &runtime.Runtime{Runner: runner}, &smfStatusArgs{Name: tests.name})
			if err != nil || !reflect.DeepEqual(got, tests.want) {
				t.Fatalf("status=%#v err=%v want=%#v", got, err, tests.want)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tests.want) {
				t.Fatalf("status type=%T want=%T", got, tests.want)
			}
			if len(runner.calls) != len(tests.argv) {
				t.Fatalf("calls=%d want=%d", len(runner.calls), len(tests.argv))
			}
			for index, call := range runner.calls {
				assertSMFBounded(t, call)
				if gotArgv := smfArgv(call); !reflect.DeepEqual(gotArgv, tests.argv[index]) {
					t.Fatalf("argv[%d]=%v want=%v", index, gotArgv, tests.argv[index])
				}
			}
		})
	}
}

func TestSMFLifecycleRetcodesAndOrder(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		call    func(*runtime.Runtime) (any, error)
		results map[string][]process.CommandResult
		want    any
		argv    [][]string
	}{
		{
			"start-clear-retry",
			func(rt *runtime.Runtime) (any, error) {
				return (smfStartFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/a"})
			},
			map[string][]process.CommandResult{
				"/usr/sbin/svcadm enable -s -t svc:/a": {{ExitCode: 3}, {ExitCode: 0}},
				"/usr/sbin/svcadm clear svc:/a":        {{ExitCode: 1}},
			},
			true,
			[][]string{{"/usr/sbin/svcadm", "enable", "-s", "-t", "svc:/a"}, {"/usr/sbin/svcadm", "clear", "svc:/a"}, {"/usr/sbin/svcadm", "enable", "-s", "-t", "svc:/a"}},
		},
		{
			"stop-failure",
			func(rt *runtime.Runtime) (any, error) {
				return (smfStopFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/a"})
			},
			map[string][]process.CommandResult{"/usr/sbin/svcadm disable -s -t svc:/a": {{ExitCode: 2}}},
			false,
			[][]string{{"/usr/sbin/svcadm", "disable", "-s", "-t", "svc:/a"}},
		},
		{
			"restart-start",
			func(rt *runtime.Runtime) (any, error) {
				return (smfRestartFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/a"})
			},
			map[string][]process.CommandResult{
				"/usr/sbin/svcadm restart svc:/a":      {{ExitCode: 0}},
				"/usr/sbin/svcadm enable -s -t svc:/a": {{ExitCode: 0}},
			},
			true,
			[][]string{{"/usr/sbin/svcadm", "restart", "svc:/a"}, {"/usr/sbin/svcadm", "enable", "-s", "-t", "svc:/a"}},
		},
		{
			"reload-start",
			func(rt *runtime.Runtime) (any, error) {
				return (smfReloadFunc{}).Execute(ctx, rt, &smfNameArgs{Name: "svc:/a"})
			},
			map[string][]process.CommandResult{
				"/usr/sbin/svcadm refresh svc:/a":      {{ExitCode: 0}},
				"/usr/sbin/svcadm enable -s -t svc:/a": {{ExitCode: 0}},
			},
			true,
			[][]string{{"/usr/sbin/svcadm", "refresh", "svc:/a"}, {"/usr/sbin/svcadm", "enable", "-s", "-t", "svc:/a"}},
		},
		{
			"enable",
			func(rt *runtime.Runtime) (any, error) {
				return (smfEnableFunc{}).Execute(ctx, rt, &smfNameKwargsArgs{Name: "svc:/a", Kwargs: map[string]any{"temporary": true}})
			},
			map[string][]process.CommandResult{"/usr/sbin/svcadm enable svc:/a": {{ExitCode: 0}}},
			true,
			[][]string{{"/usr/sbin/svcadm", "enable", "svc:/a"}},
		},
		{
			"disable",
			func(rt *runtime.Runtime) (any, error) {
				return (smfDisableFunc{}).Execute(ctx, rt, &smfNameKwargsArgs{Name: "svc:/a", Kwargs: map[string]any{"temporary": true}})
			},
			map[string][]process.CommandResult{"/usr/sbin/svcadm disable svc:/a": {{ExitCode: 0}}},
			true,
			[][]string{{"/usr/sbin/svcadm", "disable", "svc:/a"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &smfFakeRunner{results: tc.results}
			got, err := tc.call(&runtime.Runtime{Runner: runner})
			if err != nil || got != tc.want {
				t.Fatalf("got=%#v err=%v want=%#v", got, err, tc.want)
			}
			if len(runner.calls) != len(tc.argv) {
				t.Fatalf("calls=%d want=%d", len(runner.calls), len(tc.argv))
			}
			for i, call := range runner.calls {
				assertSMFBounded(t, call)
				if !reflect.DeepEqual(smfArgv(call), tc.argv[i]) {
					t.Fatalf("call[%d]=%v want=%v", i, smfArgv(call), tc.argv[i])
				}
			}
		})
	}
}

func TestSMFStatusEnabledAndAggregates(t *testing.T) {
	runner := &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcs -H -o STATE svc:/a":                    {{Stdout: []byte("online\n")}, {Stdout: []byte("online\n")}},
		"/usr/bin/svcs -aH -o FMRI,STATE -s FMRI":             {{Stdout: []byte("svc:/a online\nsvc:/b maintenance\n")}},
		"/usr/bin/svcs -H -o STATE svc:/b":                    {{Stdout: []byte("maintenance\n")}},
		"/usr/bin/svcs -H -o FMRI svc:/a":                     {{Stdout: []byte("svc:/a\n")}},
		"/usr/bin/svcs -H -o FMRI svc:/b":                     {{Stdout: []byte("svc:/b\n")}},
		"/usr/sbin/svccfg -s svc:/a listprop general/enabled": {{Stdout: []byte("general/enabled boolean true\n")}},
		"/usr/sbin/svccfg -s svc:/b listprop general/enabled": {{Stdout: []byte("general/enabled boolean false\n")}},
		"/usr/bin/svcprop -c -p general/enabled *": {
			{Stdout: []byte("svc:/b:default/:properties/general/enabled boolean false\nsvc:/a:default/:properties/general/enabled boolean true\n")},
			{Stdout: []byte("svc:/b:default/:properties/general/enabled boolean false\nsvc:/a:default/:properties/general/enabled boolean true\n")},
		},
	}}
	rt := &runtime.Runtime{Runner: runner}
	got, err := (smfStatusFunc{}).Execute(context.Background(), rt, &smfStatusArgs{Name: "svc:/a"})
	if err != nil || got != true {
		t.Fatalf("status=%#v err=%v", got, err)
	}
	got, err = (smfStatusFunc{}).Execute(context.Background(), rt, &smfStatusArgs{Name: "svc:/*"})
	if err != nil || !reflect.DeepEqual(got, map[string]bool{"svc:/a": true, "svc:/b": false}) {
		t.Fatalf("glob status=%#v err=%v", got, err)
	}
	got, err = (smfEnabledFunc{}).Execute(context.Background(), rt, &smfNameKwargsArgs{Name: "svc:/a", Kwargs: map[string]any{"temporary": true}})
	if err != nil || got != true {
		t.Fatalf("enabled=%#v err=%v", got, err)
	}
	got, err = (smfDisabledFunc{}).Execute(context.Background(), rt, &smfNameArgs{Name: "svc:/b"})
	if err != nil || got != true {
		t.Fatalf("disabled=%#v err=%v", got, err)
	}
	got, err = (smfGetEnabledFunc{}).Execute(context.Background(), rt, smfNoArgs{})
	if err != nil || !reflect.DeepEqual(got, []string{"svc:/a:default"}) {
		t.Fatalf("get_enabled=%#v err=%v", got, err)
	}
	got, err = (smfGetDisabledFunc{}).Execute(context.Background(), rt, smfNoArgs{})
	if err != nil || !reflect.DeepEqual(got, []string{"svc:/b:default"}) {
		t.Fatalf("get_disabled=%#v err=%v", got, err)
	}
	for _, call := range runner.calls {
		assertSMFBounded(t, call)
	}
}

func TestSMFRunnerBoundariesAndParserErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &smfFakeRunner{}
	if _, err := (smfGetAllFunc{}).Execute(ctx, &runtime.Runtime{Runner: runner}, smfNoArgs{}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("canceled=%v calls=%d", err, len(runner.calls))
	}
	runner = &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcs -aH -o FMRI,STATE -s FMRI": {{Err: errors.New("svcs missing"), ExitCode: -1}},
	}}
	if _, err := (smfGetAllFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, smfNoArgs{}); err == nil || !strings.Contains(err.Error(), "svcs missing") {
		t.Fatalf("missing binary error=%v", err)
	}
	runner = &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcprop -c -p general/enabled *": {{Stdout: []byte("malformed\n")}},
	}}
	if _, err := (smfGetEnabledFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, smfNoArgs{}); err == nil {
		t.Fatal("malformed svcprop accepted")
	}
	runner = &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcs -H -o FMRI svc:/a":                     {{Stdout: []byte("svc:/a\n")}},
		"/usr/sbin/svccfg -s svc:/a listprop general/enabled": {{Stdout: []byte("\n")}},
	}}
	if _, err := (smfEnabledFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, &smfNameKwargsArgs{Name: "svc:/a"}); err == nil {
		t.Fatal("empty enabled property accepted")
	}
	runner = &smfFakeRunner{results: map[string][]process.CommandResult{
		"/usr/bin/svcs -aH -o FMRI,STATE -s FMRI": {{Stdout: []byte("x"), StdoutTruncated: true}},
	}}
	if _, err := (smfGetAllFunc{}).Execute(context.Background(), &runtime.Runtime{Runner: runner}, smfNoArgs{}); !errors.Is(err, process.ErrOutputLimit) {
		t.Fatalf("output limit error=%v", err)
	}
	if smfCommandTimeout != 30*time.Second || smfOutputLimit != 4<<20 {
		t.Fatalf("unexpected bounds timeout=%s output=%d", smfCommandTimeout, smfOutputLimit)
	}
}
