package selinux

// R5.3 policy-surface tests: filetype translation, fcontext policies, and
// port policies, mapped onto saltstack/salt/modules/selinux.py @ pinned
// revision and the parsing fixtures pinned by
// tests/pytests/unit/modules/test_selinux.py. All Runner output is
// scripted; no real semanage/restorecon binary is required.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

// withTools injects the which-guard answer for the named binaries.
func withTools(t *testing.T, tools ...string) {
	t.Helper()
	saved := toolLookup
	toolLookup = func(exe string) bool {
		for _, tool := range tools {
			if exe == tool {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { toolLookup = saved })
}

func out(stdout string) process.CommandResult {
	return process.CommandResult{ExitCode: 0, Stdout: []byte(stdout)}
}

// errRunner fails every command with the given error (cancel/limit paths).
type errRunner struct{ err error }

func (e errRunner) Run(_ context.Context, _ process.Command) process.CommandResult {
	return process.CommandResult{ExitCode: -1, Err: e.err}
}

// capturingRunner records every command for Shell/bounds assertions.
type capturingRunner struct{ commands []process.Command }

func (c *capturingRunner) Run(_ context.Context, cmd process.Command) process.CommandResult {
	c.commands = append(c.commands, cmd)
	return process.CommandResult{ExitCode: 0}
}

// ---------------------------------------------------------------------------
// filetype_id_to_string

func TestFiletypeIdToStringFullMap(t *testing.T) {
	withTools(t) // no binary required; guard must not fire
	vectors := map[string]string{
		"a": "all files",
		"f": "regular file",
		"d": "directory",
		"c": "character device",
		"b": "block device",
		"s": "socket",
		"l": "symbolic link",
		"p": "named pipe",
	}
	for code, want := range vectors {
		got, err := (filetypeIdToStringFunc{}).Execute(context.Background(), nil, &FiletypeIdToStringArgs{Filetype: code})
		if err != nil || got != want {
			t.Fatalf("filetype_id_to_string(%q) = %v, %v; want %q", code, got, err, want)
		}
	}
	// empty argument selects Salt's "a" default
	got, err := (filetypeIdToStringFunc{}).Execute(context.Background(), nil, &FiletypeIdToStringArgs{})
	if err != nil || got != "all files" {
		t.Fatalf("default = %v, %v; want all files", got, err)
	}
}

func TestFiletypeIdToStringInvalidCode(t *testing.T) {
	_, err := (filetypeIdToStringFunc{}).Execute(context.Background(), nil, &FiletypeIdToStringArgs{Filetype: "z"})
	if err == nil || err.Error() != "Invalid file type code 'z'; expected one of: a, f, d, c, b, s, l, p" {
		t.Fatalf("invalid code error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// fcontext_get_policy — pinned parsing fixtures

func TestFcontextGetPolicyPinnedFixtures(t *testing.T) {
	withTools(t, "semanage")
	cases := []struct {
		semanageOut string
		name        string
		filetype    string
		selUser     string
		selRole     string
		selType     string
		selLevel    string
	}{
		{
			semanageOut: "/var/www(/.*)?     all files          " +
				" system_u:object_r:httpd_sys_content_t:s0 ",
			name: "/var/www(/.*)?", filetype: "all files",
			selUser: "system_u", selRole: "object_r", selType: "httpd_sys_content_t", selLevel: "s0",
		},
		{
			semanageOut: "/var/www(/.*)? all files         " +
				" system_u:object_r:httpd_sys_content_t:s0  ",
			name: "/var/www(/.*)?", filetype: "all files",
			selUser: "system_u", selRole: "object_r", selType: "httpd_sys_content_t", selLevel: "s0",
		},
		{
			semanageOut: "/var/lib/dhcp3?                                    directory      " +
				"    system_u:object_r:dhcp_state_t:s0\t",
			name: "/var/lib/dhcp3?", filetype: "directory",
			selUser: "system_u", selRole: "object_r", selType: "dhcp_state_t", selLevel: "s0",
		},
		{
			semanageOut: "/var/lib/dhcp3?  directory         " +
				" system_u:object_r:dhcp_state_t:s0",
			name: "/var/lib/dhcp3?", filetype: "directory",
			selUser: "system_u", selRole: "object_r", selType: "dhcp_state_t", selLevel: "s0",
		},
		{
			semanageOut: "/var/lib/dhcp3? directory         " +
				" system_u:object_r:dhcp_state_t:s0",
			name: "/var/lib/dhcp3?", filetype: "directory",
			selUser: "system_u", selRole: "object_r", selType: "dhcp_state_t", selLevel: "s0",
		},
	}
	for _, tc := range cases {
		rt, runner := newRT()
		runner.script = []process.CommandResult{out(tc.semanageOut)}
		got, err := (fcontextGetPolicyFunc{}).Execute(context.Background(), rt, &FcontextPolicyArgs{Name: tc.name})
		if err != nil {
			t.Fatalf("fcontext_get_policy(%q): %v", tc.name, err)
		}
		want := map[string]any{
			"filespec": tc.name, "filetype": tc.filetype,
			"sel_user": tc.selUser, "sel_role": tc.selRole,
			"sel_type": tc.selType, "sel_level": tc.selLevel,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("fcontext_get_policy(%q) = %#v; want %#v", tc.name, got, want)
		}
	}
}

func TestFcontextGetPolicyFiltersAndMisses(t *testing.T) {
	withTools(t, "semanage")
	listing := "/var/www(/.*)?     all files          system_u:object_r:httpd_sys_content_t:s0\n" +
		"/var/www/html      directory          system_u:object_r:httpd_sys_content_t:s0\n"

	// filetype=d restricts the match to the directory row.
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(listing)}
	got, err := (fcontextGetPolicyFunc{}).Execute(context.Background(), rt,
		&FcontextPolicyArgs{Name: "/var/www/html", Filetype: strPtr("d")})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"filespec": "/var/www/html", "filetype": "directory",
		"sel_user": "system_u", "sel_role": "object_r",
		"sel_type": "httpd_sys_content_t", "sel_level": "s0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered get = %#v; want %#v", got, want)
	}

	// no match -> Python None
	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{out(listing)}
	got2, err2 := (fcontextGetPolicyFunc{}).Execute(context.Background(), rt2, &FcontextPolicyArgs{Name: "/nope"})
	if err2 != nil || got2 != nil {
		t.Fatalf("miss = %v, %v; want nil, nil", got2, err2)
	}

	// sel_type filter as raw regex, like upstream interpolation
	rt3, runner3 := newRT()
	runner3.script = []process.CommandResult{out(listing)}
	got3, err3 := (fcontextGetPolicyFunc{}).Execute(context.Background(), rt3,
		&FcontextPolicyArgs{Name: "/var/www/html", SelType: strPtr("var_t")})
	if err3 != nil || got3 != nil {
		t.Fatalf("sel_type filter miss = %v, %v; want nil, nil", got3, err3)
	}

	// two matching rows cannot parse (first-line re.match fails upstream too)
	rt4, runner4 := newRT()
	dup := "/opt/x all files system_u:object_r:a_t:s0\n/opt/x all files system_u:object_r:b_t:s0\n"
	runner4.script = []process.CommandResult{out(dup)}
	_, err4 := (fcontextGetPolicyFunc{}).Execute(context.Background(), rt4, &FcontextPolicyArgs{Name: "/opt/x"})
	if err4 == nil || err4.Error() != "Output from the fcontext command did not match the expected format" {
		t.Fatalf("multi-match error = %v", err4)
	}
}

// ---------------------------------------------------------------------------
// fcontext_add_policy / fcontext_delete_policy

func TestFcontextAddPolicyRegexPathConvertsToModify(t *testing.T) {
	withTools(t, "semanage")
	cases := []struct{ name, selType string }{
		{"/srv/ssl/ldap/.*[.]key", "slapd_cert_t"},
		{"/srv/ssl/ldap(/.*[.](pem|crt))?", "cert_t"},
	}
	for _, tc := range cases {
		rt, runner := newRT()
		// existing listing: the filespec followed by a space appears -> modify
		runner.script = []process.CommandResult{
			out(tc.name + " all files system_u:object_r:old_t:s0\n"),
			{ExitCode: 0},
		}
		res, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt,
			&FcontextPolicyArgs{Name: tc.name, SelType: &tc.selType})
		if err != nil {
			t.Fatal(err)
		}
		if res.(map[string]any)["retcode"] != 0 {
			t.Fatalf("run_all = %#v", res)
		}
		last := runner.calls[len(runner.calls)-1]
		want := []string{"semanage", "fcontext", "--modify", "--type", tc.selType, tc.name}
		if strings.Join(last, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %v; want %v", last, want)
		}
	}
}

func TestFcontextAddPolicyAbsentStaysAdd(t *testing.T) {
	withTools(t, "semanage")
	ft, st, su, sl := "d", "data_t", "system_u", "s0"
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(""), {ExitCode: 0, Stderr: []byte("")}}
	res, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt,
		&FcontextPolicyArgs{Name: "/opt/data", Filetype: &ft, SelType: &st, SelUser: &su, SelLevel: &sl})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["retcode"] != 0 {
		t.Fatalf("run_all = %#v", res)
	}
	want := []string{"semanage", "fcontext", "--add", "--ftype", "d", "--type", "data_t",
		"--seuser", "system_u", "--range", "s0", "/opt/data"}
	if got := runner.calls[len(runner.calls)-1]; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v; want %v", got, want)
	}

	// a shorter path than an existing entry must not match the filespec grep
	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{
		out("/usr/share/munin/plugins/mysql_queries all files system_u:object_r:munin_t:s0\n"),
		{ExitCode: 0},
	}
	if _, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt2,
		&FcontextPolicyArgs{Name: "/usr/share/munin/plugins/mysql_", SelType: strPtr("t")}); err != nil {
		t.Fatal(err)
	}
	got := runner2.calls[len(runner2.calls)-1]
	if got[2] != "--add" {
		t.Fatalf("shorter path action = %v", got)
	}
}

func TestFcontextAddPolicyFiletypeAIsDefaultAndInvalidRejected(t *testing.T) {
	withTools(t, "semanage")
	a := "a"
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(""), {ExitCode: 0}}
	if _, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt,
		&FcontextPolicyArgs{Name: "/opt/x", Filetype: &a, SelType: strPtr("t")}); err != nil {
		t.Fatal(err)
	}
	got := runner.calls[len(runner.calls)-1]
	if strings.Contains(strings.Join(got, " "), "--ftype") {
		t.Fatalf("filetype a must stay implicit: %v", got)
	}

	rt2, _ := newRT()
	if _, err := (fcontextAddPolicyFunc{}).Execute(context.Background(), rt2,
		&FcontextPolicyArgs{Name: "/opt/x", Filetype: strPtr("z")}); err == nil ||
		!strings.HasPrefix(err.Error(), "Invalid file type code 'z'") {
		t.Fatalf("invalid filetype error = %v", err)
	}
}

func TestFcontextDeletePolicyArgvAndRetcode(t *testing.T) {
	withTools(t, "semanage")
	rt, runner := newRT()
	runner.script = []process.CommandResult{{ExitCode: 1, Stderr: []byte("boom")}}
	res, err := (fcontextDeletePolicyFunc{}).Execute(context.Background(), rt,
		&FcontextPolicyArgs{Name: "/opt/data", SelType: strPtr("data_t")})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["retcode"] != 1 || got["stderr"] != "boom" {
		t.Fatalf("run_all = %#v", got)
	}
	want := []string{"semanage", "fcontext", "--delete", "--type", "data_t", "/opt/data"}
	if argv := runner.calls[len(runner.calls)-1]; strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v; want %v", argv, want)
	}
}

// ---------------------------------------------------------------------------
// fcontext_policy_is_applied / fcontext_apply_policy

func TestFcontextPolicyIsAppliedArgvAndStdout(t *testing.T) {
	withTools(t, "restorecon")
	rt, runner := newRT()
	runner.script = []process.CommandResult{{ExitCode: 1, Stdout: []byte("Would relabel /srv from u:r:t:s0 to u:r:t2:s0\n")}}
	got, err := (fcontextPolicyIsAppliedFunc{}).Execute(context.Background(), rt,
		&FcontextPolicyIsAppliedArgs{Name: "/srv", Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	// stdout is returned even for a nonzero retcode (run_all().get("stdout"))
	if got != "Would relabel /srv from u:r:t:s0 to u:r:t2:s0\n" {
		t.Fatalf("stdout passthrough = %q", got)
	}
	want := []string{"restorecon", "-n", "-v", "-R", "/srv"}
	if argv := runner.calls[len(runner.calls)-1]; strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v; want %v", argv, want)
	}
}

func TestFcontextApplyPolicyPinnedNewStyle(t *testing.T) {
	withTools(t, "restorecon")
	preview := "Would relabel /foo/bar from some_u:some_r:some_t:s0 to" +
		" other_u:other_r:other_t:s0"
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(preview), {ExitCode: 0}}
	res, err := (fcontextApplyPolicyFunc{}).Execute(context.Background(), rt, &FcontextApplyPolicyArgs{Name: "/foo/bar"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["retcode"] != 0 {
		t.Fatalf("retcode = %#v", got)
	}
	wantChanges := map[string]any{
		"/foo/bar": map[string]any{
			"old": map[string]any{"sel_role": "some_r", "sel_type": "some_t", "sel_user": "some_u"},
			"new": map[string]any{"sel_role": "other_r", "sel_type": "other_t", "sel_user": "other_u"},
		},
	}
	if !reflect.DeepEqual(got["changes"], wantChanges) {
		t.Fatalf("changes = %#v; want %#v", got["changes"], wantChanges)
	}
	applyArgv := []string{"restorecon", "-v", "-F", "/foo/bar"}
	if argv := runner.calls[len(runner.calls)-1]; strings.Join(argv, "\x00") != strings.Join(applyArgv, "\x00") {
		t.Fatalf("apply argv = %v", argv)
	}
}

func TestFcontextApplyPolicyPinnedOldStyle(t *testing.T) {
	withTools(t, "restorecon")
	preview := "restorecon reset /foo/bar context" +
		" some_u:some_r:some_t:s0->other_u:other_r:other_t:s0"
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(preview), {ExitCode: 0}}
	res, err := (fcontextApplyPolicyFunc{}).Execute(context.Background(), rt, &FcontextApplyPolicyArgs{Name: "/foo/bar"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	wantChanges := map[string]any{
		"/foo/bar": map[string]any{
			"old": map[string]any{"sel_role": "some_r", "sel_type": "some_t", "sel_user": "some_u"},
			"new": map[string]any{"sel_role": "other_r", "sel_type": "other_t", "sel_user": "other_u"},
		},
	}
	if !reflect.DeepEqual(got["changes"], wantChanges) {
		t.Fatalf("changes = %#v; want %#v", got["changes"], wantChanges)
	}
}

func TestFcontextApplyPolicyPinnedFailure(t *testing.T) {
	withTools(t, "restorecon")
	rt, runner := newRT()
	runner.script = []process.CommandResult{out("And now for something completely different."), {ExitCode: 0}}
	res, err := (fcontextApplyPolicyFunc{}).Execute(context.Background(), rt, &FcontextApplyPolicyArgs{Name: "/foo/bar"})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(map[string]any)
	if got["retcode"] != 1 || got["error"] != "Unrecognized response from restorecon command." {
		t.Fatalf("failure shape = %#v", got)
	}
}

func TestFcontextApplyPolicyMultiLineAndRecursive(t *testing.T) {
	withTools(t, "restorecon")
	preview := "Would relabel /a from u:r:t1:s0 to u:r:t2:s0\n" +
		"Would relabel /b from u:r:t3:s0 to u:r:t3:s0\n"
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(preview), {ExitCode: 0}}
	res, err := (fcontextApplyPolicyFunc{}).Execute(context.Background(), rt,
		&FcontextApplyPolicyArgs{Name: "/a", Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	changes := res.(map[string]any)["changes"].(map[string]any)
	if len(changes) != 2 {
		t.Fatalf("changes = %#v", changes)
	}
	if _, ok := changes["/b"]; !ok {
		t.Fatalf("second relabel missing: %#v", changes)
	}
	// identical old/new collapse to empty dicts (full intersection)
	b := changes["/b"].(map[string]any)
	if len(b["old"].(map[string]any)) != 0 || len(b["new"].(map[string]any)) != 0 {
		t.Fatalf("intersection removal wrong: %#v", b)
	}
	want := []string{"restorecon", "-v", "-F", "-R", "/a"}
	if argv := runner.calls[len(runner.calls)-1]; strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("recursive apply argv = %v", argv)
	}
}

// ---------------------------------------------------------------------------
// _parse_protocol_port and port_get_policy

func TestParseProtocolPortPinnedVectors(t *testing.T) {
	positive := []struct {
		name             string
		protocol, port   *string
		wantProto, wantP string
	}{
		{"tcp/80", nil, nil, "tcp", "80"},
		{"udp/53", nil, nil, "udp", "53"},
		{"tcp_test_dns", strPtr("tcp"), strPtr("53"), "tcp", "53"},
		{"udp_test/dns", strPtr("udp"), strPtr("53"), "udp", "53"},
	}
	for _, tc := range positive {
		proto, port, err := parseProtocolPort(tc.name, tc.protocol, tc.port)
		if err != nil || proto != tc.wantProto || port != tc.wantP {
			t.Fatalf("parse(%q, %v, %v) = %q, %q, %v", tc.name, tc.protocol, tc.port, proto, port, err)
		}
	}
	negative := []struct {
		name           string
		protocol, port *string
	}{
		{"invalid_name_no_args", nil, nil},
		{"invalid_proto/80", strPtr("nottcp"), strPtr("80")},
		{"invalid_port", strPtr("tcp"), strPtr("notaport")},
		{"missing_proto", nil, strPtr("80")},
		{"missing_port", strPtr("udp"), nil},
		{"tcp/8", nil, nil}, // single-digit ports never parse (upstream quirk)
	}
	for _, tc := range negative {
		if _, _, err := parseProtocolPort(tc.name, tc.protocol, tc.port); err == nil {
			t.Fatalf("parse(%q, %v, %v) should fail", tc.name, tc.protocol, tc.port)
		}
	}
	// exact upstream error text
	_, _, err := parseProtocolPort("invalid_name_no_args", nil, nil)
	wantErr := `Invalid name "invalid_name_no_args" format and protocol and port not provided or invalid: "None" "None".`
	if err == nil || err.Error() != wantErr {
		t.Fatalf("error = %v; want %q", err, wantErr)
	}
}

func TestPortGetPolicyPinnedFixtures(t *testing.T) {
	withTools(t, "semanage")
	cases := []struct {
		semanageOut string
		name        string
		expected    map[string]any
	}{
		{
			semanageOut: "cma_port_t                     tcp      1050",
			name:        "tcp/1050",
			expected:    map[string]any{"sel_type": "cma_port_t", "protocol": "tcp", "port": "1050"},
		},
		{
			semanageOut: "cluster_port_t                 tcp      5149, 40040, 50006-50008",
			name:        "tcp/40040",
			expected:    map[string]any{"sel_type": "cluster_port_t", "protocol": "tcp", "port": "5149, 40040, 50006-50008"},
		},
		{
			semanageOut: "http_port_t                    tcp      9008, 8010, 9002-9003, 80," +
				" 81, 443, 488, 8008, 8009, 8443, 9000",
			name:     "tcp/9000",
			expected: map[string]any{"sel_type": "http_port_t", "protocol": "tcp", "port": "9008, 8010, 9002-9003, 80, 81, 443, 488, 8008, 8009, 8443, 9000"},
		},
		{
			semanageOut: "vnc_port_t                     tcp      5985-5999, 5900-5983",
			name:        "tcp/5985-5999",
			expected:    map[string]any{"sel_type": "vnc_port_t", "protocol": "tcp", "port": "5985-5999, 5900-5983"},
		},
		{
			semanageOut: "zebra_port_t                   tcp      2606, 2608-2609, 2600-2604",
			name:        "tcp/2608-2609",
			expected:    map[string]any{"sel_type": "zebra_port_t", "protocol": "tcp", "port": "2606, 2608-2609, 2600-2604"},
		},
		{
			// Upstream's unit test mocks cmd.shell post-grep, so its tcp//
			// name never passes the real filter over a udp row; the pinned
			// parse expectation is preserved with the matching udp name.
			semanageOut: "radius_port_t                  udp      1645, 1812, 18120-18121",
			name:        "udp/18120-18121",
			expected:    map[string]any{"sel_type": "radius_port_t", "protocol": "udp", "port": "1645, 1812, 18120-18121"},
		},
	}
	for _, tc := range cases {
		rt, runner := newRT()
		runner.script = []process.CommandResult{out(tc.semanageOut)}
		got, err := (portGetPolicyFunc{}).Execute(context.Background(), rt, &PortGetPolicyArgs{Name: tc.name})
		if err != nil {
			t.Fatalf("port_get_policy(%q): %v", tc.name, err)
		}
		if !reflect.DeepEqual(got, tc.expected) {
			t.Fatalf("port_get_policy(%q) = %#v; want %#v", tc.name, got, tc.expected)
		}
	}
}

func TestPortGetPolicyProtocolPortArgsAndMisses(t *testing.T) {
	withTools(t, "semanage")
	listing := "cma_port_t                     tcp      1050\n" +
		"radius_port_t                  udp      1645, 1812\n"

	// protocol/port arguments resolve an unformatted name.
	rt, runner := newRT()
	runner.script = []process.CommandResult{out(listing)}
	got, err := (portGetPolicyFunc{}).Execute(context.Background(), rt,
		&PortGetPolicyArgs{Name: "foobar", Protocol: strPtr("tcp"), Port: strPtr("1050")})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"sel_type": "cma_port_t", "protocol": "tcp", "port": "1050"}) {
		t.Fatalf("args-resolved get = %#v", got)
	}

	// tcp name against a udp-only row never matches (real grep semantics).
	rt2, runner2 := newRT()
	runner2.script = []process.CommandResult{out("radius_port_t                  udp      1645, 1812\n")}
	got2, err2 := (portGetPolicyFunc{}).Execute(context.Background(), rt2, &PortGetPolicyArgs{Name: "tcp/1812"})
	if err2 != nil || got2 != nil {
		t.Fatalf("cross-proto miss = %v, %v; want nil, nil", got2, err2)
	}

	// a formatted name wins over contradictory arguments (pinned contract)
	rt3, runner3 := newRT()
	runner3.script = []process.CommandResult{out(listing)}
	got3, err3 := (portGetPolicyFunc{}).Execute(context.Background(), rt3,
		&PortGetPolicyArgs{Name: "tcp/1050", Protocol: strPtr("udp"), Port: strPtr("1645")})
	if err3 != nil {
		t.Fatal(err3)
	}
	if got3.(map[string]any)["protocol"] != "tcp" {
		t.Fatalf("name should win: %#v", got3)
	}
}

// ---------------------------------------------------------------------------
// port_add_policy / port_modify_policy / port_delete_policy

func TestPortPolicyActionArgv(t *testing.T) {
	withTools(t, "semanage")
	cases := []struct {
		label string
		call  func(ctx context.Context, rt *runtime.Runtime) (any, error)
		want  []string
	}{
		{
			label: "add formatted name",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portAddPolicyFunc{}).Execute(ctx, rt, &PortAddPolicyArgs{Name: "tcp/8080", SelType: strPtr("http_port_t")})
			},
			want: []string{"semanage", "port", "--add", "--proto", "tcp", "--type", "http_port_t", "8080"},
		},
		{
			label: "add with protocol and port args",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portAddPolicyFunc{}).Execute(ctx, rt, &PortAddPolicyArgs{
					Name: "foobar", SelType: strPtr("http_port_t"), Protocol: strPtr("tcp"), Port: strPtr("8091")})
			},
			want: []string{"semanage", "port", "--add", "--proto", "tcp", "--type", "http_port_t", "8091"},
		},
		{
			label: "add udp range with sel_range",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portAddPolicyFunc{}).Execute(ctx, rt, &PortAddPolicyArgs{
					Name: "udp/18120-18121", SelType: strPtr("radius_port_t"), SelRange: strPtr("s0")})
			},
			want: []string{"semanage", "port", "--add", "--proto", "udp", "--type", "radius_port_t", "--range", "s0", "18120-18121"},
		},
		{
			label: "modify",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portModifyPolicyFunc{}).Execute(ctx, rt, &PortModifyPolicyArgs{Name: "tcp/8080", SelType: strPtr("http_port_t")})
			},
			want: []string{"semanage", "port", "--modify", "--proto", "tcp", "--type", "http_port_t", "8080"},
		},
		{
			label: "delete has no type or range",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portDeletePolicyFunc{}).Execute(ctx, rt, &PortDeletePolicyArgs{Name: "tcp/8080"})
			},
			want: []string{"semanage", "port", "--delete", "--proto", "tcp", "8080"},
		},
		{
			label: "delete via protocol and port args",
			call: func(ctx context.Context, rt *runtime.Runtime) (any, error) {
				return (portDeletePolicyFunc{}).Execute(ctx, rt, &PortDeletePolicyArgs{Name: "foobar", Protocol: strPtr("tcp"), Port: strPtr("8091")})
			},
			want: []string{"semanage", "port", "--delete", "--proto", "tcp", "8091"},
		},
	}
	for _, tc := range cases {
		rt, runner := newRT()
		runner.script = []process.CommandResult{{ExitCode: 0}}
		res, err := tc.call(context.Background(), rt)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if res.(map[string]any)["retcode"] != 0 {
			t.Fatalf("%s: run_all = %#v", tc.label, res)
		}
		got := runner.calls[len(runner.calls)-1]
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Fatalf("%s: argv = %v; want %v", tc.label, got, tc.want)
		}
	}
}

func TestPortPolicyValidationErrors(t *testing.T) {
	withTools(t, "semanage")
	rt, _ := newRT()
	if _, err := (portAddPolicyFunc{}).Execute(context.Background(), rt, &PortAddPolicyArgs{Name: "tcp/8080"}); err == nil ||
		err.Error() != "SELinux Type is required to add a policy" {
		t.Fatalf("add without type = %v", err)
	}
	if _, err := (portAddPolicyFunc{}).Execute(context.Background(), rt,
		&PortAddPolicyArgs{Name: "oops", SelType: strPtr("t")}); err == nil ||
		!strings.HasPrefix(err.Error(), `Invalid name "oops"`) {
		t.Fatalf("invalid name = %v", err)
	}
	// empty sel_type behaves like a missing one for add
	if _, err := (portAddPolicyFunc{}).Execute(context.Background(), rt,
		&PortAddPolicyArgs{Name: "tcp/8080", SelType: strPtr("")}); err == nil {
		t.Fatal("empty sel_type must fail for add")
	}
}

func strPtr(s string) *string { return &s }
