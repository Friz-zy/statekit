package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/cli"
	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

type rabbitmqFakeRunner struct {
	results            []process.CommandResult
	defaultResult      process.CommandResult
	calls              []process.Command
	available          map[string]bool
	availabilityLog    []string
	pluginCommand      string
	pluginResolved     bool
	pluginNeedsPackage bool
	packageVersions    map[string]string
	packageVersionErr  error
	packageVersionLog  []string
	policyVersion      [3]int
	policyResolved     bool
	afterRun           func(call int)
}

type rabbitmqSensitiveRunnerCause struct {
	secret string
}

func (e *rabbitmqSensitiveRunnerCause) Error() string {
	if e.secret != "" {
		return "rabbitmq-private-cause: " + e.secret
	}
	return "rabbitmq-private-cause"
}

type rabbitmqSafeRunnerOuter struct {
	cause error
}

func (*rabbitmqSafeRunnerOuter) Error() string { return "rabbitmq runner diagnostic" }

func (e *rabbitmqSafeRunnerOuter) Unwrap() error { return e.cause }

func TestRabbitMQRedactedErrorChainIsOpaque(t *testing.T) {
	marker := "rabbitmq-chain-secret"
	cause := &rabbitmqSensitiveRunnerCause{secret: marker}
	outer := &rabbitmqSafeRunnerOuter{cause: fmt.Errorf("typed runner cause: %w", cause)}
	err := redactedError(outer, marker)
	if err == nil || err == outer || err.Error() != outer.Error() || strings.Contains(err.Error(), marker) || errors.Unwrap(err) != nil {
		t.Fatalf("redacted error = %v", err)
	}
	var got *rabbitmqSensitiveRunnerCause
	if errors.As(err, &got) || errors.Is(err, cause) {
		t.Fatalf("redacted error exposed raw cause: %v", err)
	}
	for _, tc := range []struct {
		name  string
		cause error
		want  error
	}{
		{name: "canceled", cause: context.Canceled, want: context.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "output", cause: process.ErrOutputLimit, want: process.ErrOutputLimit},
		{name: "input", cause: runtime.ErrCommandInputLimit, want: runtime.ErrCommandInputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := redactedError(&rabbitmqSafeRunnerOuter{cause: tc.cause}, marker)
			if !errors.Is(wrapped, tc.want) || errors.Unwrap(wrapped) != nil || wrapped.Error() != "rabbitmq runner diagnostic" {
				t.Fatalf("identity=%v err=%v", tc.want, wrapped)
			}
		})
	}
}

func (r *rabbitmqFakeRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	command.Redact = append([]string(nil), command.Redact...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	command.Env = append([]string(nil), command.Env...)
	r.calls = append(r.calls, command)
	if r.afterRun != nil {
		r.afterRun(len(r.calls))
	}
	if len(r.results) == 0 {
		return r.defaultResult
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result
}

func (r *rabbitmqFakeRunner) CommandAvailable(name string) bool {
	r.availabilityLog = append(r.availabilityLog, name)
	if r.available == nil {
		return true
	}
	return r.available[name]
}

func (r *rabbitmqFakeRunner) RabbitMQPluginCommand() (string, bool) {
	return r.pluginCommand, r.pluginResolved
}

func (r *rabbitmqFakeRunner) RabbitMQPluginCommandRequiresPackage() bool {
	return r.pluginNeedsPackage
}

func (r *rabbitmqFakeRunner) RabbitMQPackageVersion(_ context.Context, packageName string) (string, error) {
	r.packageVersionLog = append(r.packageVersionLog, packageName)
	if r.packageVersionErr != nil {
		return "", r.packageVersionErr
	}
	if version, ok := r.packageVersions[packageName]; ok {
		return version, nil
	}
	if !r.pluginNeedsPackage && packageName == "rabbitmq-server" {
		return "3.12.0", nil
	}
	return "", nil
}

func (r *rabbitmqFakeRunner) RabbitMQPolicyVersion() (int, int, int, bool) {
	return r.policyVersion[0], r.policyVersion[1], r.policyVersion[2], r.policyResolved
}

func newRabbitRuntime(results ...process.CommandResult) (*runtime.Runtime, *rabbitmqFakeRunner) {
	runner := &rabbitmqFakeRunner{
		results:       results,
		defaultResult: process.CommandResult{ExitCode: 0},
	}
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}, runner
}

func commandArgv(command process.Command) []string {
	return append([]string{command.Name}, command.Args...)
}

func assertRabbitCommand(t *testing.T, command process.Command) {
	t.Helper()
	if command.Shell || command.Timeout != commandTimeout ||
		command.MaxStdoutBytes != outputLimit || command.MaxStderrBytes != outputLimit ||
		len(command.Stdin) != 0 || command.Env != nil {
		t.Fatalf("unsafe RabbitMQ command: %#v", command)
	}
}

func stringPtr(value string) *string { return &value }
func intPtr(value int) *int          { return &value }
func boolPtr(value bool) *bool       { return &value }

func TestRabbitMQRegistrySurfaceAndArguments(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		prototype any
		args      []string
	}{
		"rabbitmq.list_users":             {ListUsersArgs{}, []string{"runas"}},
		"rabbitmq.list_vhosts":            {ListVhostsArgs{}, []string{"runas"}},
		"rabbitmq.list_upstreams":         {ListUpstreamsArgs{}, []string{"runas"}},
		"rabbitmq.user_exists":            {UserExistsArgs{}, []string{"name", "runas"}},
		"rabbitmq.vhost_exists":           {VhostExistsArgs{}, []string{"name", "runas"}},
		"rabbitmq.upstream_exists":        {UpstreamExistsArgs{}, []string{"name", "runas"}},
		"rabbitmq.add_user":               {AddUserArgs{}, []string{"name", "password", "runas"}},
		"rabbitmq.delete_user":            {DeleteUserArgs{}, []string{"name", "runas"}},
		"rabbitmq.change_password":        {ChangePasswordArgs{}, []string{"name", "password", "runas"}},
		"rabbitmq.clear_password":         {ClearPasswordArgs{}, []string{"name", "runas"}},
		"rabbitmq.check_password":         {CheckPasswordArgs{}, []string{"name", "password", "runas"}},
		"rabbitmq.add_vhost":              {AddVhostArgs{}, []string{"runas", "vhost"}},
		"rabbitmq.delete_vhost":           {DeleteVhostArgs{}, []string{"runas", "vhost"}},
		"rabbitmq.set_permissions":        {SetPermissionsArgs{}, []string{"conf", "read", "runas", "user", "vhost", "write"}},
		"rabbitmq.list_permissions":       {ListPermissionsArgs{}, []string{"runas", "vhost"}},
		"rabbitmq.list_user_permissions":  {ListUserPermissionsArgs{}, []string{"name", "runas"}},
		"rabbitmq.set_user_tags":          {SetUserTagsArgs{}, []string{"name", "runas", "tags"}},
		"rabbitmq.status":                 {StatusArgs{}, []string{"runas"}},
		"rabbitmq.cluster_status":         {ClusterStatusArgs{}, []string{"runas"}},
		"rabbitmq.join_cluster":           {JoinClusterArgs{}, []string{"host", "ram_node", "runas", "user"}},
		"rabbitmq.stop_app":               {StopAppArgs{}, []string{"runas"}},
		"rabbitmq.start_app":              {StartAppArgs{}, []string{"runas"}},
		"rabbitmq.reset":                  {ResetArgs{}, []string{"runas"}},
		"rabbitmq.force_reset":            {ForceResetArgs{}, []string{"runas"}},
		"rabbitmq.list_queues":            {ListQueuesArgs{}, []string{"args", "runas"}},
		"rabbitmq.list_queues_vhost":      {ListQueuesVhostArgs{}, []string{"args", "runas", "vhost"}},
		"rabbitmq.list_policies":          {ListPoliciesArgs{}, []string{"runas", "vhost"}},
		"rabbitmq.set_policy":             {SetPolicyArgs{}, []string{"apply_to", "definition", "name", "pattern", "priority", "runas", "vhost"}},
		"rabbitmq.delete_policy":          {DeletePolicyArgs{}, []string{"name", "runas", "vhost"}},
		"rabbitmq.policy_exists":          {PolicyExistsArgs{}, []string{"name", "runas", "vhost"}},
		"rabbitmq.list_available_plugins": {ListAvailablePluginsArgs{}, []string{"runas"}},
		"rabbitmq.list_enabled_plugins":   {ListEnabledPluginsArgs{}, []string{"runas"}},
		"rabbitmq.plugin_is_enabled":      {PluginIsEnabledArgs{}, []string{"name", "runas"}},
		"rabbitmq.enable_plugin":          {EnablePluginArgs{}, []string{"name", "runas"}},
		"rabbitmq.disable_plugin":         {DisablePluginArgs{}, []string{"name", "runas"}},
		"rabbitmq.set_upstream":           {SetUpstreamArgs{}, []string{"ack_mode", "exchange", "expires", "ha_policy", "max_hops", "message_ttl", "name", "prefetch_count", "queue", "reconnect_delay", "runas", "trust_user_id", "uri"}},
		"rabbitmq.delete_upstream":        {DeleteUpstreamArgs{}, []string{"name", "runas"}},
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
			t.Fatalf("%s prototype=%T want=%T", name, fn.Args(), row.prototype)
		}
		got, err := config.ArgumentNames(fn.Args())
		if err != nil || !reflect.DeepEqual(got, row.args) {
			t.Fatalf("%s args=%v err=%v want=%v", name, got, err, row.args)
		}
		if _, constrained := fn.(runtime.PlatformConstrained); constrained {
			t.Fatalf("%s unexpectedly has a platform gate", name)
		}
		if !runtime.SupportsPlatform(fn, "linux") || !runtime.SupportsPlatform(fn, "windows") {
			t.Fatalf("%s must be exposed on Linux and Windows", name)
		}
	}
	if err := Register(reg); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestRabbitMQParsersAndResponseHelpers(t *testing.T) {
	for line, want := range map[string]bool{
		"Listing users...":      false,
		"Listing users\tname":   true,
		"user\t[administrator]": true,
		"...done":               false,
		"WARNING: locale":       false,
		"":                      false,
		" value ":               true,
	} {
		if got := _safe_output(line); got != want {
			t.Fatalf("safe output %q=%t want %t", line, got, want)
		}
	}
	list, err := _output_to_list("WARNING: ignored\nListing users...\nalpha beta\n...done\n")
	if err != nil || !reflect.DeepEqual(list, []string{"alpha", "beta"}) {
		t.Fatalf("list=%#v err=%v", list, err)
	}
	lines, err := _output_lines_to_list(" WARNING: kept?\n\talpha\tbeta \n...done\n")
	if err != nil || !reflect.DeepEqual(lines, []string{"WARNING: kept?", "alpha\tbeta"}) {
		t.Fatalf("lines=%#v err=%v", lines, err)
	}
	dict, err := _output_to_dict("Listing queues...\nq\t1\t2\nkey-only\n...done\n")
	wantDict := map[string]any{"q": []string{"1", "2"}, "key-only": ""}
	if err != nil || !reflect.DeepEqual(dict, wantDict) {
		t.Fatalf("dict=%#v err=%v want=%#v", dict, err, wantDict)
	}
	if _, err := _output_to_dict(map[string]any{"retcode": 1, "stdout": "", "stderr": "synthetic failure"}); err == nil {
		t.Fatal("nonzero response was accepted")
	}
	if _, err := _output_to_dict(""); err != nil {
		t.Fatalf("empty output: %v", err)
	}
	if err := _check_response("Error: synthetic"); err == nil {
		t.Fatal("error text was accepted")
	}
	formatted, err := _format_response(map[string]any{"retcode": 0, "stdout": "ok", "stderr": ""}, "Added")
	if err != nil || !reflect.DeepEqual(formatted, map[string]any{"Added": "ok"}) {
		t.Fatalf("formatted=%#v err=%v", formatted, err)
	}
}

func TestRabbitMQUserVhostPermissionAndStatusSurface(t *testing.T) {
	password := "synthetic-password-91"
	permissionJSON := `[{"user":"alice","vhost":"/","configure":".*","write":".*","read":".*"}]`
	tests := []struct {
		name    string
		call    func(context.Context, *runtime.Runtime) (any, error)
		results []process.CommandResult
		argv    [][]string
		want    any
	}{
		{
			"list_users", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listUsersFunc{}).Execute(ctx, rt, &ListUsersArgs{})
			}, []process.CommandResult{{Stdout: []byte("Listing users...\nalice\t[administrator, monitoring]\n...done\n")}}, [][]string{{"rabbitmqctl", "list_users", "-q"}}, map[string]any{"alice": []string{"administrator", "monitoring"}},
		},
		{
			"list_vhosts", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listVhostsFunc{}).Execute(ctx, rt, &ListVhostsArgs{})
			}, []process.CommandResult{{Stdout: []byte("Listing vhosts...\n/\napp\n...done\n")}}, [][]string{{"rabbitmqctl", "list_vhosts", "-q"}}, []string{"/", "app"},
		},
		{
			"list_upstreams", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listUpstreamsFunc{}).Execute(ctx, rt, &ListUpstreamsArgs{})
			}, []process.CommandResult{{Stdout: []byte("")}}, [][]string{{"rabbitmqctl", "list_parameters", "-q"}}, map[string]any{},
		},
		{
			"user_exists", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (userExistsFunc{}).Execute(ctx, rt, &UserExistsArgs{Name: "alice"})
			}, []process.CommandResult{{Stdout: []byte("alice\t[]\n")}}, [][]string{{"rabbitmqctl", "list_users", "-q"}}, true,
		},
		{
			"vhost_exists", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (vhostExistsFunc{}).Execute(ctx, rt, &VhostExistsArgs{Name: "/"})
			}, []process.CommandResult{{Stdout: []byte("/\n")}}, [][]string{{"rabbitmqctl", "list_vhosts", "-q"}}, true,
		},
		{
			"upstream_exists", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (upstreamExistsFunc{}).Execute(ctx, rt, &UpstreamExistsArgs{Name: "upstream"})
			}, []process.CommandResult{{Stdout: []byte("federation-upstream\tupstream\t{}\n")}}, [][]string{{"rabbitmqctl", "list_parameters", "-q"}}, true,
		},
		{
			"add_user", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (addUserFunc{}).Execute(ctx, rt, &AddUserArgs{Name: "alice", Password: &password})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "add_user", "alice", password}}, map[string]any{"Added": "ok"},
		},
		{
			"delete_user", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (deleteUserFunc{}).Execute(ctx, rt, &DeleteUserArgs{Name: "alice"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "delete_user", "alice"}}, map[string]any{"Deleted": "ok"},
		},
		{
			"change_password", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (changePasswordFunc{}).Execute(ctx, rt, &ChangePasswordArgs{Name: "alice", Password: password})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "change_password", "alice", password}}, map[string]any{"Password Changed": "ok"},
		},
		{
			"clear_password", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (clearPasswordFunc{}).Execute(ctx, rt, &ClearPasswordArgs{Name: "alice"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "clear_password", "alice"}}, map[string]any{"Password Cleared": "ok"},
		},
		{
			"check_password", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (checkPasswordFunc{}).Execute(ctx, rt, &CheckPasswordArgs{Name: "alice", Password: password})
			}, []process.CommandResult{{Stdout: []byte("RabbitMQ version: 3.12.0\n")}, {Stdout: []byte("authenticated")}}, [][]string{{"rabbitmqctl", "status"}, {"rabbitmqctl", "authenticate_user", "alice", password}}, true,
		},
		{
			"add_vhost", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (addVhostFunc{}).Execute(ctx, rt, &AddVhostArgs{Vhost: "/app"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "add_vhost", "/app"}}, map[string]any{"Added": "ok"},
		},
		{
			"delete_vhost", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (deleteVhostFunc{}).Execute(ctx, rt, &DeleteVhostArgs{Vhost: "/app"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "delete_vhost", "/app"}}, map[string]any{"Deleted": "ok"},
		},
		{
			"set_permissions", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (setPermissionsFunc{}).Execute(ctx, rt, &SetPermissionsArgs{Vhost: "/", User: "alice"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "set_permissions", "-p", "/", "alice", ".*", ".*", ".*"}}, map[string]any{"Permissions Set": "ok"},
		},
		{
			"list_permissions", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listPermissionsFunc{}).Execute(ctx, rt, &ListPermissionsArgs{Vhost: "/"})
			}, []process.CommandResult{{Stdout: []byte(permissionJSON)}}, [][]string{{"rabbitmqctl", "list_permissions", "--formatter=json", "-p", "/"}}, map[string]any{"alice": map[string]any{"vhost": "/", "configure": ".*", "write": ".*", "read": ".*"}},
		},
		{
			"list_user_permissions", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listUserPermissionsFunc{}).Execute(ctx, rt, &ListUserPermissionsArgs{Name: "alice"})
			}, []process.CommandResult{{Stdout: []byte(permissionJSON)}}, [][]string{{"rabbitmqctl", "list_user_permissions", "alice", "--formatter=json"}}, map[string]any{"/": map[string]any{"user": "alice", "configure": ".*", "write": ".*", "read": ".*"}},
		},
		{
			"set_user_tags", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (setUserTagsFunc{}).Execute(ctx, rt, &SetUserTagsArgs{Name: "alice", Tags: []string{"administrator", "monitoring"}})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "set_user_tags", "alice", "administrator", "monitoring"}}, map[string]any{"Tag(s) set": "ok"},
		},
		{
			"status", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (statusFunc{}).Execute(ctx, rt, &StatusArgs{})
			}, []process.CommandResult{{Stdout: []byte("status\n")}}, [][]string{{"rabbitmqctl", "status"}}, "status\n",
		},
		{
			"cluster_status", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (clusterStatusFunc{}).Execute(ctx, rt, &ClusterStatusArgs{})
			}, []process.CommandResult{{Stdout: []byte("cluster\n")}}, [][]string{{"rabbitmqctl", "cluster_status"}}, "cluster\n",
		},
		{
			"join_cluster", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (joinClusterFunc{}).Execute(ctx, rt, &JoinClusterArgs{Host: "node.example", RamNode: boolPtr(true)})
			}, []process.CommandResult{{Stdout: []byte("stopped"), Started: true}, {Stdout: []byte("joined")}, {Stdout: []byte("started")}}, [][]string{{"rabbitmqctl", "stop_app"}, {"rabbitmqctl", "join_cluster", "--ram", "rabbit@node.example"}, {"rabbitmqctl", "start_app"}}, map[string]any{"Join": "joined"},
		},
		{
			"stop_app", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (stopAppFunc{}).Execute(ctx, rt, &StopAppArgs{})
			}, []process.CommandResult{{Stdout: []byte("stopped")}}, [][]string{{"rabbitmqctl", "stop_app"}}, "stopped",
		},
		{
			"start_app", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (startAppFunc{}).Execute(ctx, rt, &StartAppArgs{})
			}, []process.CommandResult{{Stdout: []byte("started")}}, [][]string{{"rabbitmqctl", "start_app"}}, "started",
		},
		{
			"reset", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (resetFunc{}).Execute(ctx, rt, &ResetArgs{})
			}, []process.CommandResult{{Stdout: []byte("reset")}}, [][]string{{"rabbitmqctl", "reset"}}, "reset",
		},
		{
			"force_reset", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (forceResetFunc{}).Execute(ctx, rt, &ForceResetArgs{})
			}, []process.CommandResult{{Stdout: []byte("reset")}}, [][]string{{"rabbitmqctl", "force_reset"}}, "reset",
		},
		{
			"list_queues", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listQueuesFunc{}).Execute(ctx, rt, &ListQueuesArgs{Args: []string{"messages", "consumers"}})
			}, []process.CommandResult{{Stdout: []byte("Listing queues...\nq\t1\t2\n...done\n")}}, [][]string{{"rabbitmqctl", "list_queues", "-q", "messages", "consumers"}}, map[string]any{"q": []string{"1", "2"}},
		},
		{
			"list_queues_vhost", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listQueuesVhostFunc{}).Execute(ctx, rt, &ListQueuesVhostArgs{Vhost: "/app", Args: []string{"messages"}})
			}, []process.CommandResult{{Stdout: []byte("q\t1\n")}}, [][]string{{"rabbitmqctl", "list_queues", "-q", "-p", "/app", "messages"}}, map[string]any{"q": []string{"1"}},
		},
		{
			"list_policies", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listPoliciesFunc{}).Execute(ctx, rt, &ListPoliciesArgs{})
			}, []process.CommandResult{{Stdout: []byte("/\tHA\t.*\tall\t{\"ha-mode\":\"all\"}\t0\n")}}, [][]string{{"rabbitmqctl", "list_policies", "-q", "-p", "/"}}, map[string]any{"/": map[string]any{"HA": map[string]any{"pattern": ".*", "apply_to": "all", "definition": "{\"ha-mode\":\"all\"}", "priority": "0"}}},
		},
		{
			"set_policy", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (setPolicyFunc{}).Execute(ctx, rt, &SetPolicyArgs{Vhost: "/", Name: "HA", Pattern: ".*", Definition: map[string]any{"ha-mode": "all"}, Priority: stringPtr("1"), ApplyTo: stringPtr("all")})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "set_policy", "-p", "/", "--priority", "1", "--apply-to", "all", "HA", ".*", `{"ha-mode": "all"}`}}, map[string]any{"Set": "ok"},
		},
		{
			"delete_policy", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (deletePolicyFunc{}).Execute(ctx, rt, &DeletePolicyArgs{Vhost: "/", Name: "HA"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "clear_policy", "-p", "/", "HA"}}, map[string]any{"Deleted": "ok"},
		},
		{
			"policy_exists", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (policyExistsFunc{}).Execute(ctx, rt, &PolicyExistsArgs{Vhost: "/", Name: "HA"})
			}, []process.CommandResult{{Stdout: []byte("/\tHA\t.*\tall\t{}\t0\n")}}, [][]string{{"rabbitmqctl", "list_policies", "-q", "-p", "/"}}, true,
		},
		{
			"list_available_plugins", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listAvailablePluginsFunc{}).Execute(ctx, rt, &ListAvailablePluginsArgs{})
			}, []process.CommandResult{{Stdout: []byte("Listing plugins...\nrabbitmq_management\nrabbitmq_prometheus\n...done\n")}}, [][]string{{"rabbitmq-plugins", "list", "-m"}}, []string{"rabbitmq_management", "rabbitmq_prometheus"},
		},
		{
			"list_enabled_plugins", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (listEnabledPluginsFunc{}).Execute(ctx, rt, &ListEnabledPluginsArgs{})
			}, []process.CommandResult{{Stdout: []byte("rabbitmq_management\n")}}, [][]string{{"rabbitmq-plugins", "list", "-m", "-e"}}, []string{"rabbitmq_management"},
		},
		{
			"plugin_is_enabled", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (pluginIsEnabledFunc{}).Execute(ctx, rt, &PluginIsEnabledArgs{Name: "rabbitmq_management"})
			}, []process.CommandResult{{Stdout: []byte("rabbitmq_management\n")}}, [][]string{{"rabbitmq-plugins", "list", "-m", "-e"}}, true,
		},
		{
			"enable_plugin", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (enablePluginFunc{}).Execute(ctx, rt, &EnablePluginArgs{Name: "rabbitmq_management"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmq-plugins", "enable", "rabbitmq_management"}}, map[string]any{"Enabled": "ok"},
		},
		{
			"disable_plugin", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (disablePluginFunc{}).Execute(ctx, rt, &DisablePluginArgs{Name: "rabbitmq_management"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmq-plugins", "disable", "rabbitmq_management"}}, map[string]any{"Disabled": "ok"},
		},
		{
			"set_upstream", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (setUpstreamFunc{}).Execute(ctx, rt, &SetUpstreamArgs{Name: "upstream", URI: "amqp://host", PrefetchCount: intPtr(10), TrustUserID: boolPtr(true)})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "set_parameter", "federation-upstream", "upstream", `{"uri": "amqp://host", "prefetch-count": 10, "trust-user-id": true}`}}, true,
		},
		{
			"delete_upstream", func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (deleteUpstreamFunc{}).Execute(ctx, rt, &DeleteUpstreamArgs{Name: "upstream"})
			}, []process.CommandResult{{Stdout: []byte("ok")}}, [][]string{{"rabbitmqctl", "clear_parameter", "federation-upstream", "upstream"}}, true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, runner := newRabbitRuntime(tc.results...)
			got, err := tc.call(context.Background(), rt)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("result=%#v want=%#v", got, tc.want)
			}
			if len(runner.calls) != len(tc.argv) {
				t.Fatalf("calls=%d want=%d", len(runner.calls), len(tc.argv))
			}
			for i, command := range runner.calls {
				assertRabbitCommand(t, command)
				if !reflect.DeepEqual(commandArgv(command), tc.argv[i]) {
					t.Fatalf("argv[%d]=%v want=%v", i, commandArgv(command), tc.argv[i])
				}
			}
		})
	}
}

func TestRabbitMQOldPasswordCheckUsesShellFreeEval(t *testing.T) {
	password := `old"secret`
	rt, runner := newRabbitRuntime(
		process.CommandResult{Stdout: []byte(`{rabbit,"RabbitMQ","3.4.2"}`)},
		process.CommandResult{Stdout: []byte("valid")},
	)
	got, err := (checkPasswordFunc{}).Execute(context.Background(), rt, &CheckPasswordArgs{Name: `al"ice`, Password: password})
	if err != nil || got != true {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	wantEval := `rabbit_auth_backend_internal:check_user_login(<<"al\"ice">>, [{password, <<"old\"secret">>}]).`
	if got := commandArgv(runner.calls[1]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "eval", wantEval}) {
		t.Fatalf("eval argv=%v want=%v", got, wantEval)
	}
	if !containsAll(runner.calls[1].Redact, password, `old\"secret`) {
		t.Fatalf("password not fully redacted: %#v", runner.calls[1].Redact)
	}
	if strings.Contains(runner.calls[1].RedactedString(), password) {
		t.Fatal("password appeared in rendered command")
	}
}

func TestRabbitMQWindowsBatchTransportRejectsStructuredAndLegacyValues(t *testing.T) {
	const helper = `C:\RabbitMQ\rabbitmqctl.bat`
	tests := map[string][]string{
		"set_upstream JSON": {
			"set_parameter", "federation-upstream", "upstream", `{"uri": "amqp://host"}`,
		},
		"set_policy JSON": {
			"set_policy", "-p", "/", "HA", ".*", `{"ha-mode":"all"}`,
		},
		"legacy check_password Erlang eval": {
			"eval", `rabbit_auth_backend_internal:check_user_login(<<"alice">>, [{password, <<"secret">>}]).`,
		},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := process.BuildRabbitMQCommand("windows", helper, args); !errors.Is(err, process.ErrInvalidRabbitMQCommand) {
				t.Fatalf("err=%v, want fail-closed ErrInvalidRabbitMQCommand", err)
			}
		})
	}
}

func TestRabbitMQLegacyEvalEscapesBackslashesBeforeQuotes(t *testing.T) {
	password := `back\slash"quote`
	rt, runner := newRabbitRuntime(
		process.CommandResult{Stdout: []byte(`{rabbit,"RabbitMQ","3.4.2"}`)},
		process.CommandResult{Stdout: []byte("valid")},
	)
	if _, err := (checkPasswordFunc{}).Execute(context.Background(), rt, &CheckPasswordArgs{Name: "alice", Password: password}); err != nil {
		t.Fatal(err)
	}
	eval := commandArgv(runner.calls[1])[2]
	if !strings.Contains(eval, `back\\slash\"quote`) || strings.Contains(eval, `back\slash\"quote`) {
		t.Fatalf("legacy Erlang escaping=%q", eval)
	}
}

func containsAll(values []string, want ...string) bool {
	for _, expected := range want {
		found := false
		for _, value := range values {
			if value == expected {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestRabbitMQDefaultsAndNoMutation(t *testing.T) {
	args := ListQueuesArgs{Runas: stringPtr(""), Args: []string{"messages", "consumers"}}
	before := append([]string(nil), args.Args...)
	rt, runner := newRabbitRuntime(process.CommandResult{Stdout: []byte("q\t1\n")})
	if _, err := (listQueuesFunc{}).Execute(context.Background(), rt, &args); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args.Args, before) {
		t.Fatalf("args mutated: before=%v after=%v", before, args.Args)
	}
	if got := commandArgv(runner.calls[0]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "list_queues", "-q", "messages", "consumers"}) {
		t.Fatalf("argv=%v", got)
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("ok")})
	if _, err := (setPermissionsFunc{}).Execute(context.Background(), rt, &SetPermissionsArgs{Vhost: "/", User: "u", Conf: stringPtr(""), Write: stringPtr("write"), Read: stringPtr("read")}); err != nil {
		t.Fatal(err)
	}
	if got := commandArgv(runner.calls[0]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "set_permissions", "-p", "/", "u", "", "write", "read"}) {
		t.Fatalf("explicit empty default was changed: %v", got)
	}
}

func TestRabbitMQEmptyTagsAndPolicyLayouts(t *testing.T) {
	rt, runner := newRabbitRuntime(process.CommandResult{Stdout: []byte("ok")})
	if _, err := (setUserTagsFunc{}).Execute(context.Background(), rt, &SetUserTagsArgs{Name: "alice", Tags: []string{}}); err != nil {
		t.Fatal(err)
	}
	if got := commandArgv(runner.calls[0]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "set_user_tags", "alice"}) {
		t.Fatalf("empty tag argv=%v", got)
	}

	modern, err := parsePolicies("/\tmodern\t^queues\tall\t{}\t0\n")
	if err != nil {
		t.Fatal(err)
	}
	modernPolicy := modern["/"].(map[string]any)["modern"].(map[string]any)
	if modernPolicy["pattern"] != "^queues" || modernPolicy["apply_to"] != "all" {
		t.Fatalf("modern policy=%v", modernPolicy)
	}
	legacy, err := parsePolicies("/\tlegacy\tall\t.*\t{}\t0\n")
	if err != nil {
		t.Fatal(err)
	}
	legacyPolicy := legacy["/"].(map[string]any)["legacy"].(map[string]any)
	if legacyPolicy["pattern"] != ".*" || legacyPolicy["apply_to"] != "all" {
		t.Fatalf("legacy policy=%v", legacyPolicy)
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("/\tlegacy\tall\tqueues\t{}\t0\n")})
	runner.policyVersion = [3]int{3, 6, 0}
	runner.policyResolved = true
	versioned, err := (listPoliciesFunc{}).Execute(context.Background(), rt, &ListPoliciesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	versionedPolicy := versioned.(map[string]any)["/"].(map[string]any)["legacy"].(map[string]any)
	if versionedPolicy["pattern"] != "queues" || versionedPolicy["apply_to"] != "all" {
		t.Fatalf("versioned legacy policy=%v", versionedPolicy)
	}

	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("/\tmodern\tqueues\tall\t{}\t0\n")},
	)
	runner.packageVersions = map[string]string{"rabbitmq-server": "3.12.0-1"}
	resolved, err := (listPoliciesFunc{}).Execute(context.Background(), rt, &ListPoliciesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	resolvedPolicy := resolved.(map[string]any)["/"].(map[string]any)["modern"].(map[string]any)
	if resolvedPolicy["pattern"] != "queues" || resolvedPolicy["apply_to"] != "all" || len(runner.calls) != 1 || !reflect.DeepEqual(runner.packageVersionLog, []string{"rabbitmq-server"}) {
		t.Fatalf("status-resolved policy=%v calls=%d", resolvedPolicy, len(runner.calls))
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("/\tHA\t.*\tall\t{}\t0\n")})
	result, err := (policyExistsFunc{}).Execute(context.Background(), rt, &PolicyExistsArgs{Vhost: "/app", Name: "HA"})
	if err != nil {
		t.Fatal(err)
	}
	if result != false || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{"rabbitmqctl", "list_policies", "-q", "-p", "/"}) {
		t.Fatalf("policy_exists result=%v argv=%v", result, commandArgv(runner.calls[0]))
	}
	if _, err := parsePoliciesForVersion("/\tmodern\t.*\t{}\t0\n", [3]int{3, 12, 0}, true); !errors.Is(err, errRabbitMQPolicyLayout) {
		t.Fatalf("modern five-column policy err=%v", err)
	}
}

func TestRabbitMQErrorsCancellationBoundsAvailabilityAndRunas(t *testing.T) {
	secret := "synthetic-secret-err"
	rt, runner := newRabbitRuntime(process.CommandResult{ExitCode: 1, Stderr: []byte(secret)})
	_, err := (deleteUserFunc{}).Execute(context.Background(), rt, &DeleteUserArgs{Name: "alice"})
	if err == nil || !strings.Contains(err.Error(), "RabbitMQ command failed") || strings.Contains(err.Error(), secret) {
		t.Fatalf("nonzero error=%v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("nonzero call count=%d", len(runner.calls))
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Err: errors.New("runner failure"), ExitCode: -1})
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if err == nil || !strings.Contains(err.Error(), "runner failure") || len(runner.calls) != 1 {
		t.Fatalf("runner error=%v calls=%d", err, len(runner.calls))
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Err: context.DeadlineExceeded, ExitCode: -1})
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if !errors.Is(err, context.DeadlineExceeded) || len(runner.calls) != 1 {
		t.Fatalf("timeout identity err=%v calls=%d", err, len(runner.calls))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("unexpected")})
	_, err = (statusFunc{}).Execute(ctx, rt, &StatusArgs{})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancel err=%v calls=%d", err, len(runner.calls))
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte(strings.Repeat("x", outputLimit+1))})
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if !errors.Is(err, process.ErrOutputLimit) || len(runner.calls) != 1 {
		t.Fatalf("bounds err=%v calls=%d", err, len(runner.calls))
	}

	rt, runner = newRabbitRuntime()
	runner.available = map[string]bool{rabbitmqctlCommand: false}
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{})
	if !errors.Is(err, errRabbitMQCtlUnavailable) || len(runner.calls) != 0 || !reflect.DeepEqual(runner.availabilityLog, []string{rabbitmqctlCommand}) {
		t.Fatalf("availability err=%v calls=%d probes=%v", err, len(runner.calls), runner.availabilityLog)
	}

	rt, runner = newRabbitRuntime()
	runas := "alice"
	_, err = (statusFunc{}).Execute(context.Background(), rt, &StatusArgs{Runas: &runas})
	if !errors.Is(err, errRabbitMQRunas) || len(runner.calls) != 0 {
		t.Fatalf("runas err=%v calls=%d", err, len(runner.calls))
	}

	bad := "bad\x00name"
	rt, runner = newRabbitRuntime()
	_, err = (deleteUserFunc{}).Execute(context.Background(), rt, &DeleteUserArgs{Name: bad})
	if err == nil || len(runner.calls) != 0 {
		t.Fatalf("malformed argument err=%v calls=%d", err, len(runner.calls))
	}
	giantPassword := strings.Repeat("p", runtime.MaxCommandInputBytes)
	rt, runner = newRabbitRuntime()
	_, err = (checkPasswordFunc{}).Execute(context.Background(), rt, &CheckPasswordArgs{Name: "alice", Password: giantPassword})
	if !errors.Is(err, runtime.ErrCommandInputLimit) || len(runner.calls) != 0 {
		t.Fatalf("oversized password preflight err=%v calls=%d", err, len(runner.calls))
	}

	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("nothing\t[]\n")},
		process.CommandResult{Err: errors.New("add never started"), ExitCode: -1},
	)
	_, err = (addUserFunc{}).Execute(context.Background(), rt, &AddUserArgs{Name: "temporary"})
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || len(runner.calls) != 0 {
		t.Fatalf("never-started add recovery err=%v calls=%d", err, len(runner.calls))
	}
	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("nothing\t[]\n")},
		process.CommandResult{ExitCode: 1, Stderr: []byte("add refused")},
	)
	_, err = (addUserFunc{}).Execute(context.Background(), rt, &AddUserArgs{Name: "temporary"})
	if !errors.As(err, &unsupported) || len(runner.calls) != 0 {
		t.Fatalf("failed add recovery err=%v calls=%d", err, len(runner.calls))
	}
	rt, runner = newRabbitRuntime(process.CommandResult{Err: errors.New("stop never started"), ExitCode: -1})
	_, err = (joinClusterFunc{}).Execute(context.Background(), rt, &JoinClusterArgs{Host: "node.example"})
	if err == nil || len(runner.calls) != 1 {
		t.Fatalf("never-started join cleanup err=%v calls=%d", err, len(runner.calls))
	}

	ctx, cancel = context.WithCancel(context.Background())
	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("nothing\t[]\n")},
		process.CommandResult{Stdout: []byte("added"), Started: true},
	)
	runner.afterRun = func(call int) {
		if call == 2 {
			cancel()
		}
	}
	_, err = (addUserFunc{}).Execute(ctx, rt, &AddUserArgs{Name: "temporary"})
	if !errors.As(err, &unsupported) || len(runner.calls) != 0 {
		t.Fatalf("temporary-user cancellation err=%v calls=%d", err, len(runner.calls))
	}
	for _, call := range runner.calls {
		if len(call.Args) > 0 && (call.Args[0] == "clear_password" || call.Args[0] == "delete_user") {
			t.Fatalf("temporary-user cancellation authorized cleanup: %v", commandArgv(call))
		}
	}
}

func TestRabbitMQTemporaryUserRejectsBeforeCreation(t *testing.T) {
	rt, runner := newRabbitRuntime(
		process.CommandResult{Stdout: []byte("nothing\t[]\n")},
		process.CommandResult{Stdout: []byte("added"), Started: true},
		process.CommandResult{Stdout: []byte("temporary\t[]\n")},
		process.CommandResult{Stdout: []byte("RabbitMQ version: 3.12.0")},
		process.CommandResult{Stdout: []byte("authenticated")},
		process.CommandResult{Stdout: []byte("cleared")},
	)
	_, err := (addUserFunc{}).Execute(context.Background(), rt, &AddUserArgs{Name: "temporary"})
	var unsupported *runtime.UnsupportedError
	if !errors.As(err, &unsupported) || len(runner.calls) != 0 {
		t.Fatalf("unsupported workflow must not reach Runner: calls=%d", len(runner.calls))
	}
}

func TestRabbitMQUpstreamCredentialOutputAndCommandRedaction(t *testing.T) {
	rt, runner := newRabbitRuntime(process.CommandResult{Stdout: []byte("federation-upstream\tupstream\t" + `{"uri": "amqp:\/\/alice:sec'ret@broker"}` + "\n")})
	value, err := (listUpstreamsFunc{}).Execute(context.Background(), rt, &ListUpstreamsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	got := value.(map[string]any)["upstream"].(string)
	if strings.Contains(got, "alice:sec'ret") || !strings.Contains(got, "***REDACTED***") {
		t.Fatalf("upstream credential leaked in result=%q", got)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("upstream calls=%d", len(runner.calls))
	}

	uri := "amqp://alice:secret@broker/vhost"
	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("ok")})
	if _, err := (setUpstreamFunc{}).Execute(context.Background(), rt, &SetUpstreamArgs{Name: "upstream", URI: uri}); err != nil {
		t.Fatal(err)
	}
	payload := runner.calls[0].Args[3]
	if !containsAll(runner.calls[0].Redact, uri, payload, "secret") || strings.Contains(runner.calls[0].RedactedString(), "alice:secret") {
		t.Fatalf("upstream redaction=%v command=%q", runner.calls[0].Redact, runner.calls[0].RedactedString())
	}

	unicodeEscaped := `{"uri":"\u0061mqp://alice:secret@broker"}`
	if redacted := redactUpstreamCredentials(unicodeEscaped); strings.Contains(redacted, "alice:secret") || !strings.Contains(redacted, "REDACTED") {
		t.Fatalf("unicode-escaped upstream credential leaked: %q", redacted)
	}
}

func TestRabbitMQTemporaryCleanupNeverAttemptsDelete(t *testing.T) {
	rt, runner := newRabbitRuntime(
		process.CommandResult{Stdout: []byte("nothing\t[]\n")},
		process.CommandResult{Stdout: []byte("added"), Started: true},
		process.CommandResult{Stdout: []byte("temporary\t[]\n")},
		process.CommandResult{Stdout: []byte("RabbitMQ version: 3.12.0")},
		process.CommandResult{Stdout: []byte("authenticated")},
		process.CommandResult{Err: errors.New("clear failure"), ExitCode: -1},
		process.CommandResult{Stdout: []byte("temporary\t[]\n")},
		process.CommandResult{Stdout: []byte("RabbitMQ version: 3.12.0")},
		process.CommandResult{Stdout: []byte("authenticated")},
		process.CommandResult{Err: errors.New("delete failure"), ExitCode: -1},
	)
	err := cleanupTemporaryUser(context.Background(), rt, nil, temporaryUserState{name: "temporary", password: "synthetic", absentBeforeAdd: true, addCompleted: true})
	if err != errRabbitMQRecovery || len(runner.calls) != 0 {
		t.Fatalf("cleanup error=%v calls=%d", err, len(runner.calls))
	}
}

// rabbitmqTemporaryStateRunner models the broker-facing subset needed by the
// temporary-user transaction.  It intentionally mutates state between calls
// so recovery tests do not rely on a fixed result queue.
type rabbitmqTemporaryStateRunner struct {
	user                   bool
	password               string
	addResult              process.CommandResult
	addMutates             bool
	replaceBeforeVerify    bool
	replaceAfterAuth       bool
	clearResult            process.CommandResult
	replaceAfterClearError bool
	deleteResult           process.CommandResult
	calls                  []process.Command
}

func (r *rabbitmqTemporaryStateRunner) CommandAvailable(string) bool { return true }

func (r *rabbitmqTemporaryStateRunner) Run(_ context.Context, command process.Command) process.CommandResult {
	command.Args = append([]string(nil), command.Args...)
	r.calls = append(r.calls, command)
	if len(command.Args) == 0 {
		return process.CommandResult{Err: errors.New("empty state-machine command"), ExitCode: -1}
	}
	switch command.Args[0] {
	case "list_users":
		if !r.user {
			return process.CommandResult{Stdout: []byte("nothing\t[]\n")}
		}
		return process.CommandResult{Stdout: []byte("temporary\t[]\n")}
	case "add_user":
		if r.addMutates && len(command.Args) >= 3 {
			r.user = true
			r.password = command.Args[2]
			if r.replaceBeforeVerify {
				r.password = "concurrent-replacement"
			}
		}
		if rabbitmqCommandResultUnset(r.addResult) {
			return process.CommandResult{Stdout: []byte("added"), Started: true}
		}
		return r.addResult
	case "status":
		return process.CommandResult{Stdout: []byte("RabbitMQ version: 3.12.0")}
	case "authenticate_user":
		if r.user && len(command.Args) >= 3 && command.Args[2] == r.password {
			if r.replaceAfterAuth {
				r.password = "concurrent-replacement"
			}
			return process.CommandResult{Stdout: []byte("authenticated")}
		}
		return process.CommandResult{ExitCode: 1, Stderr: []byte("invalid credentials")}
	case "clear_password":
		if !rabbitmqCommandResultUnset(r.clearResult) {
			if r.replaceAfterClearError {
				r.password = "concurrent-replacement"
			}
			return r.clearResult
		}
		r.password = ""
		return process.CommandResult{Stdout: []byte("cleared")}
	case "delete_user":
		if !rabbitmqCommandResultUnset(r.deleteResult) {
			return r.deleteResult
		}
		r.user = false
		return process.CommandResult{Stdout: []byte("deleted")}
	default:
		return process.CommandResult{Err: fmt.Errorf("unexpected state-machine command %q", command.Args[0]), ExitCode: -1}
	}
}

func rabbitmqCommandResultUnset(result process.CommandResult) bool {
	return result.ExitCode == 0 && !result.Started && result.Duration == 0 && result.Err == nil &&
		len(result.Stdout) == 0 && len(result.Stderr) == 0 && !result.StdoutTruncated && !result.StderrTruncated
}

func temporaryStateRuntime(runner *rabbitmqTemporaryStateRunner) *runtime.Runtime {
	return &runtime.Runtime{Runner: runner, FS: runtime.NewMemoryFS()}
}

func TestRabbitMQTemporaryUserStateMachineRecovery(t *testing.T) {
	tests := []struct {
		name   string
		runner *rabbitmqTemporaryStateRunner
	}{
		{
			name:   "partial add response",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, addResult: process.CommandResult{ExitCode: 1, Stderr: []byte("partial")}},
		},
		{
			name:   "missing completion marker",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, addResult: process.CommandResult{Stdout: []byte("added")}},
		},
		{
			name:   "runner error before completion",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, addResult: process.CommandResult{Err: errors.New("add transport"), ExitCode: -1, Started: true}},
		},
		{
			name:   "cancellation before completion",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, addResult: process.CommandResult{Err: context.Canceled, ExitCode: -1, Started: true}},
		},
		{
			name:   "concurrent replacement",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, replaceBeforeVerify: true},
		},
		{
			name:   "pre-existing user",
			runner: &rabbitmqTemporaryStateRunner{user: true, password: "existing"},
		},
		{
			name:   "cleanup and delete errors",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, clearResult: process.CommandResult{Err: errors.New("clear failure"), ExitCode: -1}, deleteResult: process.CommandResult{Err: errors.New("delete failure"), ExitCode: -1}},
		},
		{
			name:   "replacement blocks delete fallback",
			runner: &rabbitmqTemporaryStateRunner{addMutates: true, clearResult: process.CommandResult{Err: errors.New("clear failure"), ExitCode: -1}, replaceAfterClearError: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := temporaryStateRuntime(tc.runner)
			_, err := (addUserFunc{}).Execute(context.Background(), rt, &AddUserArgs{Name: "temporary"})
			var unsupported *runtime.UnsupportedError
			if !errors.As(err, &unsupported) || len(tc.runner.calls) != 0 {
				t.Fatalf("unsafe temporary workflow reached Runner: calls=%d", len(tc.runner.calls))
			}
		})
	}
}

func TestRabbitMQTemporaryReplacementAfterAuthentication(t *testing.T) {
	for _, afterAuth := range []bool{false, true} {
		runner := &rabbitmqTemporaryStateRunner{user: true, password: "synthetic", replaceAfterAuth: afterAuth}
		rt := temporaryStateRuntime(runner)
		ownership := temporaryUserState{name: "temporary", password: "synthetic", absentBeforeAdd: true, addCompleted: true}
		if err := verifyTemporaryUserOwnership(context.Background(), rt, nil, ownership); err != nil {
			t.Fatal(err)
		}
		if !afterAuth {
			runner.password = "concurrent-replacement"
		}
		before := len(runner.calls)
		if err := cleanupTemporaryUser(context.Background(), rt, nil, ownership); err != errRabbitMQRecovery {
			t.Fatal("recovery error must be stable and contain no reflected data")
		}
		if !runner.user || runner.password != "concurrent-replacement" || len(runner.calls) != before {
			t.Fatal("replacement changed or cleanup called Runner")
		}
	}
}

func runnerArgvFromCommands(commands []process.Command) [][]string {
	argv := make([][]string, 0, len(commands))
	for _, command := range commands {
		argv = append(argv, commandArgv(command))
	}
	return argv
}

func TestRabbitMQJoinValidatesBeforeStopAndRestartsAfterFailure(t *testing.T) {
	host := strings.Repeat("h", runtime.MaxCommandInputBytes)
	rt, runner := newRabbitRuntime()
	_, err := (joinClusterFunc{}).Execute(context.Background(), rt, &JoinClusterArgs{Host: host})
	if err == nil || len(runner.calls) != 0 {
		t.Fatalf("oversized join err=%v calls=%d", err, len(runner.calls))
	}

	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("stopped"), Started: true},
		process.CommandResult{Err: errors.New("join runner failure"), ExitCode: -1, Started: true},
		process.CommandResult{Stdout: []byte("started")},
	)
	_, err = (joinClusterFunc{}).Execute(context.Background(), rt, &JoinClusterArgs{Host: "node.example"})
	if err == nil || !strings.Contains(err.Error(), "join runner failure") || len(runner.calls) != 3 {
		t.Fatalf("join failure err=%v calls=%d", err, len(runner.calls))
	}
	if got := commandArgv(runner.calls[2]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "start_app"}) {
		t.Fatalf("cleanup argv=%v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt, runner = newRabbitRuntime(
		process.CommandResult{Stdout: []byte("stopped"), Started: true},
		process.CommandResult{Stdout: []byte("started")},
	)
	runner.afterRun = func(call int) {
		if call == 1 {
			cancel()
		}
	}
	_, err = (joinClusterFunc{}).Execute(ctx, rt, &JoinClusterArgs{Host: "node.example"})
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 2 {
		t.Fatalf("join cancellation err=%v calls=%d", err, len(runner.calls))
	}
	if got := commandArgv(runner.calls[1]); !reflect.DeepEqual(got, []string{"rabbitmqctl", "start_app"}) {
		t.Fatalf("cancel cleanup argv=%v", got)
	}
}

func TestRabbitMQRedactsCredentialsAndDoesNotMutateSecrets(t *testing.T) {
	password := "synthetic-password-redact"
	args := ChangePasswordArgs{Name: "alice", Password: password}
	before := args
	rt, runner := newRabbitRuntime(process.CommandResult{Stdout: []byte("ok")})
	if _, err := (changePasswordFunc{}).Execute(context.Background(), rt, &args); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, before) {
		t.Fatalf("password args mutated")
	}
	if !containsAll(runner.calls[0].Redact, password) || strings.Contains(runner.calls[0].RedactedString(), password) {
		t.Fatalf("password redaction missing: command=%q redact=%v", runner.calls[0].RedactedString(), runner.calls[0].Redact)
	}
}

func runRabbitCLI(t *testing.T, name, configJSON string, results ...process.CommandResult) (int, *rabbitmqFakeRunner, string) {
	t.Helper()
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	rt, runner := newRabbitRuntime(results...)
	rt.Exec = reg
	app := cli.NewApp("test", func() (*runtime.Runtime, error) { return rt, nil })
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	code := app.Run([]string{"exec", name, "--config", configJSON, "-o", "json"})
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, _ := io.ReadAll(stdoutReader)
	stderr, _ := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	return code, runner, string(stdout) + string(stderr)
}

func TestRabbitMQCLIEveryPublicFunction(t *testing.T) {
	password := "synthetic-cli-password"
	cases := []struct {
		name    string
		config  string
		results []process.CommandResult
	}{
		{"rabbitmq.list_users", `{}`, []process.CommandResult{{Stdout: []byte("alice\t[]\n")}}},
		{"rabbitmq.list_vhosts", `{}`, []process.CommandResult{{Stdout: []byte("/\n")}}},
		{"rabbitmq.list_upstreams", `{}`, []process.CommandResult{{Stdout: []byte("federation-upstream\tupstream\t{}\n")}}},
		{"rabbitmq.user_exists", `{"name":"alice"}`, []process.CommandResult{{Stdout: []byte("alice\t[]\n")}}},
		{"rabbitmq.vhost_exists", `{"name":"/"}`, []process.CommandResult{{Stdout: []byte("/\n")}}},
		{"rabbitmq.upstream_exists", `{"name":"upstream"}`, []process.CommandResult{{Stdout: []byte("federation-upstream\tupstream\t{}\n")}}},
		{"rabbitmq.add_user", `{"name":"alice","password":"` + password + `"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.delete_user", `{"name":"alice"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.change_password", `{"name":"alice","password":"` + password + `"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.clear_password", `{"name":"alice"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.check_password", `{"name":"alice","password":"` + password + `"}`, []process.CommandResult{{Stdout: []byte("RabbitMQ version: 3.12.0")}, {Stdout: []byte("ok")}}},
		{"rabbitmq.add_vhost", `{"vhost":"/app"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.delete_vhost", `{"vhost":"/app"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.set_permissions", `{"vhost":"/","user":"alice"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.list_permissions", `{"vhost":"/"}`, []process.CommandResult{{Stdout: []byte(`[{"user":"alice","vhost":"/"}]`)}}},
		{"rabbitmq.list_user_permissions", `{"name":"alice"}`, []process.CommandResult{{Stdout: []byte(`[{"user":"alice","vhost":"/"}]`)}}},
		{"rabbitmq.set_user_tags", `{"name":"alice","tags":["administrator"]}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.status", `{}`, []process.CommandResult{{Stdout: []byte("status")}}},
		{"rabbitmq.cluster_status", `{}`, []process.CommandResult{{Stdout: []byte("cluster")}}},
		{"rabbitmq.join_cluster", `{"host":"node.example"}`, []process.CommandResult{{Stdout: []byte("stop"), Started: true}, {Stdout: []byte("join")}, {Stdout: []byte("start")}}},
		{"rabbitmq.stop_app", `{}`, []process.CommandResult{{Stdout: []byte("stop")}}},
		{"rabbitmq.start_app", `{}`, []process.CommandResult{{Stdout: []byte("start")}}},
		{"rabbitmq.reset", `{}`, []process.CommandResult{{Stdout: []byte("reset")}}},
		{"rabbitmq.force_reset", `{}`, []process.CommandResult{{Stdout: []byte("reset")}}},
		{"rabbitmq.list_queues", `{}`, []process.CommandResult{{Stdout: []byte("q\t1\n")}}},
		{"rabbitmq.list_queues_vhost", `{"vhost":"/"}`, []process.CommandResult{{Stdout: []byte("q\t1\n")}}},
		{"rabbitmq.list_policies", `{}`, []process.CommandResult{{Stdout: []byte("/\tHA\t.*\tall\t{}\t0\n")}}},
		{"rabbitmq.set_policy", `{"vhost":"/","name":"HA","pattern":".*","definition":"{}"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.delete_policy", `{"vhost":"/","name":"HA"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.policy_exists", `{"vhost":"/","name":"HA"}`, []process.CommandResult{{Stdout: []byte("/\tHA\t.*\tall\t{}\t0\n")}}},
		{"rabbitmq.list_available_plugins", `{}`, []process.CommandResult{{Stdout: []byte("rabbitmq_management\n")}}},
		{"rabbitmq.list_enabled_plugins", `{}`, []process.CommandResult{{Stdout: []byte("rabbitmq_management\n")}}},
		{"rabbitmq.plugin_is_enabled", `{"name":"rabbitmq_management"}`, []process.CommandResult{{Stdout: []byte("rabbitmq_management\n")}}},
		{"rabbitmq.enable_plugin", `{"name":"rabbitmq_management"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.disable_plugin", `{"name":"rabbitmq_management"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.set_upstream", `{"name":"upstream","uri":"amqp://host"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
		{"rabbitmq.delete_upstream", `{"name":"upstream"}`, []process.CommandResult{{Stdout: []byte("ok")}}},
	}
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if len(cases) != reg.Len() {
		t.Fatalf("CLI case count=%d want registered=%d", len(cases), reg.Len())
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, runner, output := runRabbitCLI(t, tc.name, tc.config, tc.results...)
			if code != cli.ExitOK {
				t.Fatalf("exit=%d output=%q calls=%v", code, output, runner.calls)
			}
			if len(runner.calls) != len(tc.results) {
				t.Fatalf("CLI calls=%d want=%d", len(runner.calls), len(tc.results))
			}
			for _, command := range runner.calls {
				assertRabbitCommand(t, command)
			}
			wantArgv := expectedRabbitCLIArgv(tc.name, password)
			if !reflect.DeepEqual(runnerArgv(runner), wantArgv) {
				t.Fatalf("CLI argv=%v want=%v", runnerArgv(runner), wantArgv)
			}
		})
	}
}

func runnerArgv(runner *rabbitmqFakeRunner) [][]string {
	argv := make([][]string, 0, len(runner.calls))
	for _, command := range runner.calls {
		argv = append(argv, commandArgv(command))
	}
	return argv
}

func expectedRabbitCLIArgv(name, password string) [][]string {
	switch name {
	case "rabbitmq.list_users":
		return [][]string{{"rabbitmqctl", "list_users", "-q"}}
	case "rabbitmq.list_vhosts":
		return [][]string{{"rabbitmqctl", "list_vhosts", "-q"}}
	case "rabbitmq.list_upstreams":
		return [][]string{{"rabbitmqctl", "list_parameters", "-q"}}
	case "rabbitmq.user_exists":
		return [][]string{{"rabbitmqctl", "list_users", "-q"}}
	case "rabbitmq.vhost_exists":
		return [][]string{{"rabbitmqctl", "list_vhosts", "-q"}}
	case "rabbitmq.upstream_exists":
		return [][]string{{"rabbitmqctl", "list_parameters", "-q"}}
	case "rabbitmq.add_user":
		return [][]string{{"rabbitmqctl", "add_user", "alice", password}}
	case "rabbitmq.delete_user":
		return [][]string{{"rabbitmqctl", "delete_user", "alice"}}
	case "rabbitmq.change_password":
		return [][]string{{"rabbitmqctl", "change_password", "alice", password}}
	case "rabbitmq.clear_password":
		return [][]string{{"rabbitmqctl", "clear_password", "alice"}}
	case "rabbitmq.check_password":
		return [][]string{{"rabbitmqctl", "status"}, {"rabbitmqctl", "authenticate_user", "alice", password}}
	case "rabbitmq.add_vhost":
		return [][]string{{"rabbitmqctl", "add_vhost", "/app"}}
	case "rabbitmq.delete_vhost":
		return [][]string{{"rabbitmqctl", "delete_vhost", "/app"}}
	case "rabbitmq.set_permissions":
		return [][]string{{"rabbitmqctl", "set_permissions", "-p", "/", "alice", ".*", ".*", ".*"}}
	case "rabbitmq.list_permissions":
		return [][]string{{"rabbitmqctl", "list_permissions", "--formatter=json", "-p", "/"}}
	case "rabbitmq.list_user_permissions":
		return [][]string{{"rabbitmqctl", "list_user_permissions", "alice", "--formatter=json"}}
	case "rabbitmq.set_user_tags":
		return [][]string{{"rabbitmqctl", "set_user_tags", "alice", "administrator"}}
	case "rabbitmq.status":
		return [][]string{{"rabbitmqctl", "status"}}
	case "rabbitmq.cluster_status":
		return [][]string{{"rabbitmqctl", "cluster_status"}}
	case "rabbitmq.join_cluster":
		return [][]string{{"rabbitmqctl", "stop_app"}, {"rabbitmqctl", "join_cluster", "rabbit@node.example"}, {"rabbitmqctl", "start_app"}}
	case "rabbitmq.stop_app":
		return [][]string{{"rabbitmqctl", "stop_app"}}
	case "rabbitmq.start_app":
		return [][]string{{"rabbitmqctl", "start_app"}}
	case "rabbitmq.reset":
		return [][]string{{"rabbitmqctl", "reset"}}
	case "rabbitmq.force_reset":
		return [][]string{{"rabbitmqctl", "force_reset"}}
	case "rabbitmq.list_queues":
		return [][]string{{"rabbitmqctl", "list_queues", "-q"}}
	case "rabbitmq.list_queues_vhost":
		return [][]string{{"rabbitmqctl", "list_queues", "-q", "-p", "/"}}
	case "rabbitmq.list_policies":
		return [][]string{{"rabbitmqctl", "list_policies", "-q", "-p", "/"}}
	case "rabbitmq.set_policy":
		return [][]string{{"rabbitmqctl", "set_policy", "-p", "/", "HA", ".*", "{}"}}
	case "rabbitmq.delete_policy":
		return [][]string{{"rabbitmqctl", "clear_policy", "-p", "/", "HA"}}
	case "rabbitmq.policy_exists":
		return [][]string{{"rabbitmqctl", "list_policies", "-q", "-p", "/"}}
	case "rabbitmq.list_available_plugins":
		return [][]string{{"rabbitmq-plugins", "list", "-m"}}
	case "rabbitmq.list_enabled_plugins":
		return [][]string{{"rabbitmq-plugins", "list", "-m", "-e"}}
	case "rabbitmq.plugin_is_enabled":
		return [][]string{{"rabbitmq-plugins", "list", "-m", "-e"}}
	case "rabbitmq.enable_plugin":
		return [][]string{{"rabbitmq-plugins", "enable", "rabbitmq_management"}}
	case "rabbitmq.disable_plugin":
		return [][]string{{"rabbitmq-plugins", "disable", "rabbitmq_management"}}
	case "rabbitmq.set_upstream":
		return [][]string{{"rabbitmqctl", "set_parameter", "federation-upstream", "upstream", `{"uri": "amqp://host"}`}}
	case "rabbitmq.delete_upstream":
		return [][]string{{"rabbitmqctl", "clear_parameter", "federation-upstream", "upstream"}}
	default:
		return nil
	}
}

func TestRabbitMQDirectHelperAvailabilityForPlugins(t *testing.T) {
	rt, runner := newRabbitRuntime()
	runner.available = map[string]bool{rabbitmqPluginsCommand: false}
	_, err := (listEnabledPluginsFunc{}).Execute(context.Background(), rt, &ListEnabledPluginsArgs{})
	if !errors.Is(err, errRabbitMQPluginsUnavailable) || len(runner.calls) != 0 || !reflect.DeepEqual(runner.availabilityLog, []string{rabbitmqPluginsCommand}) {
		t.Fatalf("plugin availability err=%v calls=%d probes=%v", err, len(runner.calls), runner.availabilityLog)
	}
}

func TestRabbitMQPluginResolverSupportsNonPATHHelper(t *testing.T) {
	rt, runner := newRabbitRuntime(process.CommandResult{Stdout: []byte("ok")})
	runner.pluginCommand = "/opt/rabbitmq/sbin/rabbitmq-plugins.bat"
	runner.pluginResolved = true
	runner.available = map[string]bool{runner.pluginCommand: true}
	if _, err := (enablePluginFunc{}).Execute(context.Background(), rt, &EnablePluginArgs{Name: "rabbitmq_management"}); err != nil {
		t.Fatal(err)
	}
	if got := commandArgv(runner.calls[0]); !reflect.DeepEqual(got, []string{runner.pluginCommand, "enable", "rabbitmq_management"}) {
		t.Fatalf("resolved plugin argv=%v", got)
	}
}

func TestRabbitMQSaltHelperDiscoveryVectorsNoInstallOrBroker(t *testing.T) {
	if got, err := rabbitmqPluginPackagePath("3.12.0-1.el9"); err != nil || got != "/usr/lib/rabbitmq/lib/rabbitmq_server-3.12.0/sbin/rabbitmq-plugins" {
		t.Fatalf("package layout=%q err=%v", got, err)
	}
	for _, version := range []string{"", "not-a-version", "3/12/0-1", "3.12.0\\evil-1"} {
		if _, err := rabbitmqPluginPackagePath(version); !errors.Is(err, errRabbitMQPackageVersion) {
			t.Fatalf("version %q err=%v, want package-version error", version, err)
		}
	}

	// The pinned _get_rabbitmq_plugin fallback uses the exact package version,
	// never a highest-version glob.  This fake has no installation and must not
	// start a broker/helper command while reporting discovery failure.
	rt, runner := newRabbitRuntime()
	runner.pluginNeedsPackage = true
	_, err := (listAvailablePluginsFunc{}).Execute(context.Background(), rt, &ListAvailablePluginsArgs{})
	if !errors.Is(err, errRabbitMQPluginsUnavailable) || len(runner.calls) != 0 || !reflect.DeepEqual(runner.packageVersionLog, []string{"rabbitmq-server"}) {
		t.Fatalf("no-install discovery err=%v calls=%d package=%v", err, len(runner.calls), runner.packageVersionLog)
	}

	rt, runner = newRabbitRuntime(process.CommandResult{Stdout: []byte("rabbitmq_management\n")})
	runner.pluginNeedsPackage = true
	runner.packageVersions = map[string]string{"rabbitmq-server": "3.12.0-1.el9"}
	resolvedPath := "/usr/lib/rabbitmq/lib/rabbitmq_server-3.12.0/sbin/rabbitmq-plugins"
	runner.available = map[string]bool{resolvedPath: true}
	if _, err := (listAvailablePluginsFunc{}).Execute(context.Background(), rt, &ListAvailablePluginsArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(commandArgv(runner.calls[0]), []string{resolvedPath, "list", "-m"}) {
		t.Fatalf("resolved helper argv=%v", commandArgv(runner.calls[0]))
	}

	if got := rabbitmqPolicyPackageName(&runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyFreeBSD}})}); got != "rabbitmq" {
		t.Fatalf("FreeBSD policy package=%q", got)
	}
	if got := rabbitmqPolicyPackageName(&runtime.Runtime{Facts: facts.ForTesting(facts.Overrides{OS: &facts.OSFacts{Family: facts.FamilyDebian}})}); got != "rabbitmq-server" {
		t.Fatalf("non-FreeBSD policy package=%q", got)
	}
}

func TestRabbitMQSaltVersionSourceVectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  [3]int
	}{
		{name: "old status", input: `{rabbit,"RabbitMQ","3.4.2"}`, want: [3]int{3, 4, 2}},
		{name: "new status", input: "RabbitMQ version: 3.5.7", want: [3]int{3, 5, 7}},
		{name: "release suffix", input: "RabbitMQ version: 3.12.0-1", want: [3]int{3, 12, 0}},
		{name: "short status falls back", input: "RabbitMQ version: 3.5", want: [3]int{}},
		{name: "malformed status falls back", input: "RabbitMQ version: unknown", want: [3]int{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rabbitVersion(tc.input); got != tc.want {
				t.Fatalf("rabbitVersion(%q)=%v want %v", tc.input, got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		input string
		want  [3]int
	}{
		{input: "3.7", want: [3]int{3, 7, 0}},
		{input: "3.7.0-1", want: [3]int{3, 7, 0}},
		{input: "3.7.0", want: [3]int{3, 7, 0}},
		{input: "3.7rc1", want: [3]int{3, 6, 0}},
		{input: "3.7.dev1", want: [3]int{3, 6, 0}},
		{input: "3.7rc1+local", want: [3]int{3, 6, 0}},
		{input: "3.7.post1.dev1", want: [3]int{3, 7, 0}},
		{input: "3.7+local", want: [3]int{3, 7, 0}},
		{input: "3.7.0.1.dev1", want: [3]int{3, 7, 0}},
		{input: "3.8rc1", want: [3]int{3, 7, 0}},
		{input: "3", want: [3]int{3, 6, 0}},
		{input: "1!0.dev1", want: [3]int{3, 7, 0}},
		{input: "v03.007.0preview1", want: [3]int{3, 6, 0}},
	} {
		got, err := rabbitmqPolicyVersionFromPackage(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("policy version %q=%v err=%v want %v", tc.input, got, err, tc.want)
		}
		// Exercise the actual helper layout, not just the threshold sentinel.
		row := "/\tpolicy\tqueues\t^orders\t{}\t0\n"
		if tc.want == [3]int{3, 7, 0} {
			row = "/\tpolicy\t^orders\tqueues\t{}\t0\n"
		}
		policies, err := parsePoliciesForVersion(row, got, true)
		if err != nil {
			t.Fatal(err)
		}
		policy := policies["/"].(map[string]any)["policy"].(map[string]any)
		if policy["pattern"] != "^orders" || policy["apply_to"] != "queues" {
			t.Fatal("source version chose incorrect helper layout")
		}
	}
	for _, input := range []string{"", "not-a-version", "3.x", "3.7garbage", "3.7rc1oops", "3.7.dev1x", "3.7+", "3.12.0~rc1-1"} {
		if _, err := rabbitmqPolicyVersionFromPackage(input); !errors.Is(err, errRabbitMQPackageVersion) {
			t.Fatalf("invalid policy version %q err=%v", input, err)
		}
	}
}

func TestRabbitMQCommandBoundsAreFinite(t *testing.T) {
	if commandTimeout <= 0 || commandTimeout > time.Minute {
		t.Fatalf("timeout=%s", commandTimeout)
	}
	if outputLimit <= 0 || outputLimit > process.MaxCaptureLimit {
		t.Fatalf("output limit=%d", outputLimit)
	}
}
