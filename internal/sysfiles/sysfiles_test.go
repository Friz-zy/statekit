package sysfiles

import "testing"

func TestParsePasswd(t *testing.T) {
	content := `root:x:0:0:root:/root:/bin/bash
# comment
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
broken-line
`
	entries := ParsePasswd(content)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	root := entries[0]
	if root.Name != "root" || root.UID != "0" || root.GID != "0" ||
		root.Home != "/root" || root.Shell != "/bin/bash" {
		t.Fatalf("root entry wrong: %+v", root)
	}
}

func TestParseGroup(t *testing.T) {
	content := `root:x:0:
adm:x:4:syslog,alice
empty-members::1001:
`
	entries := ParseGroup(content)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	adm := entries[1]
	if adm.Name != "adm" || adm.GID != "4" {
		t.Fatalf("adm entry wrong: %+v", adm)
	}
	if len(adm.Members) != 2 || adm.Members[0] != "syslog" || adm.Members[1] != "alice" {
		t.Fatalf("members = %v", adm.Members)
	}
}

func TestParseShadow(t *testing.T) {
	content := `root:!:20034:0:99999:7:::
user:$6$hash$rest:20000:5:60:7:14:21000:
`
	entries := ParseShadow(content)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	user := entries[1]
	if user.Passwd != "$6$hash$rest" || user.Lstchg != 20000 || user.Min != 5 ||
		user.Max != 60 || user.Warn != 7 || user.Inact != 14 || user.Expire != 21000 {
		t.Fatalf("user shadow wrong: %+v", user)
	}
	if entries[0].Expire != -1 {
		t.Fatalf("empty optional field must map to -1, got %d", entries[0].Expire)
	}
}
