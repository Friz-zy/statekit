package bootstrap

import "testing"

func TestBuildRuntimeRegistersSQLite3Family(t *testing.T) {
	rt, err := BuildRuntime()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"sqlite3.version",
		"sqlite3.sqlite_version",
		"sqlite3.modify",
		"sqlite3.fetch",
		"sqlite3.tables",
		"sqlite3.indices",
		"sqlite3.indexes",
	} {
		if _, ok := rt.Exec.Get(name); !ok {
			t.Fatalf("BuildRuntime missing %s", name)
		}
	}
	if _, ok := rt.Exec.Get("sqlite3._connect"); ok {
		t.Fatal("BuildRuntime must not expose sqlite3._connect")
	}
}
