package logrotate

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/runtime"
)

// Tests pinning the parser and set_ flows read from saltstack/salt/
// modules/logrotate.py @ pinned revision.

func TestParseConfWithScriptBlocks(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS()}
	content := strings.Join([]string{
		"weekly",
		"# comment skipped",
		"/var/log/nginx/*.log {",
		"    daily",
		"    missingok",
		"    prerotate",
		"        invoke-rc.d nginx reload >/dev/null",
		"    endscript",
		"    postrotate",
		"        test ! -f /run/nginx.pid || kill -USR1 `cat /run/nginx.pid`",
		"    endscript",
		"}",
		"",
	}, "\n")
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/logrotate.conf", []byte(content), 0o644)

	conf := parseConf(rt, "/etc/logrotate.conf")
	if conf["weekly"] != true {
		t.Fatalf("weekly = %#v", conf["weekly"])
	}
	stanza := conf["/var/log/nginx/*.log"].(map[string]any)
	if stanza["daily"] != true || stanza["missingok"] != true {
		t.Fatalf("stanza = %#v", stanza)
	}
	pre, ok := stanza["prerotate"].([]string)
	if !ok || len(pre) != 1 ||
		pre[0] != "invoke-rc.d nginx reload >/dev/null" {
		t.Fatalf("prerotate = %#v", stanza["prerotate"])
	}
	post, ok := stanza["postrotate"].([]string)
	if !ok || len(post) != 1 {
		t.Fatalf("postrotate = %#v", post)
	}
}

// Pins issue #68293: a stanza with both prerotate and postrotate must
// round-trip through dictToStanza without losing the second endscript.
func TestDictToStanzaBothScripts(t *testing.T) {
	stanza := map[string]any{
		"daily":      true,
		"prerotate":  []string{"echo pre"},
		"postrotate": []string{"echo post", "echo post2"},
	}
	out := dictToStanza("/var/log/app", stanza)
	for _, piece := range []string{
		"/var/log/app {\n",
		"    daily\n",
		"    prerotate\n",
		"        echo pre\n",
		"    endscript\n",
		"    postrotate\n",
		"        echo post\n",
		"        echo post2\n",
		"    endscript\n}",
	} {
		if !strings.Contains(out, piece) {
			t.Fatalf("stanza output missing %q:\n%s", piece, out)
		}
	}
}

func TestSetScalarLine(t *testing.T) {
	rt := &runtime.Runtime{FS: runtime.NewMemoryFS()}
	rt.FS.MkdirAll("/etc", 0o755)
	rt.FS.WriteFile("/etc/logrotate.conf", []byte("weekly\nrotate 4\n"), 0o644)

	fn := SetFunc{}
	okRaw, err := fn.Execute(context.Background(), rt, &SetArgs{
		Key: "rotate", Value: 6, ConfFile: strPtr("/etc/logrotate.conf"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if okRaw != true {
		t.Fatalf("set = %#v", okRaw)
	}
	data, _ := rt.FS.ReadFile("/etc/logrotate.conf")
	if !strings.Contains(string(data), "rotate 6") {
		t.Fatalf("rotate 6 missing:\n%s", string(data))
	}

	// Idempotent re-set returns true without duplicating lines.
	okRaw, err = fn.Execute(context.Background(), rt, &SetArgs{
		Key: "rotate", Value: 6, ConfFile: strPtr("/etc/logrotate.conf"),
	})
	if err != nil || okRaw != true {
		t.Fatalf("idempotent set = %#v, %v", okRaw, err)
	}
	lines := strings.Count(string(mustRead(t, rt)), "rotate 6")
	if lines != 1 {
		t.Fatalf("duplicated rotate line: %d", lines)
	}

	// Dict target without a declared setting raises the verbatim error.
	rt.FS.WriteFile("/etc/logrotate.conf", []byte(strings.Join([]string{
		"/var/log/wtmp {",
		"    monthly",
		"}",
	}, "\n")), 0o644)
	if _, err := fn.Execute(context.Background(), rt, &SetArgs{
		Key: "/var/log/wtmp", Value: 3, ConfFile: strPtr("/etc/logrotate.conf"),
	}); err == nil || !strings.HasPrefix(err.Error(),
		"Error: /var/log/wtmp includes a dict, and a specific setting inside the dict was not declared") {
		t.Fatalf("dict guard error = %v", err)
	}
}

func mustRead(t *testing.T, rt *runtime.Runtime) []byte {
	t.Helper()
	data, err := rt.FS.ReadFile("/etc/logrotate.conf")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func strPtr(s string) *string { return &s }
