package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLiteFamilyUsesRealFileThroughProductionBinary(t *testing.T) {
	bin := buildBinary(t)
	databasePath := filepath.Join(t.TempDir(), "catalog.sqlite")

	run := func(args ...string) (string, string, int) {
		t.Helper()
		command := exec.Command(bin, args...)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("run %v: %v", args, err)
			}
			code = exitErr.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	}

	for _, statement := range []string{
		"CREATE TABLE observations(id INTEGER, value TEXT)",
		"CREATE INDEX observations_value ON observations(value)",
		"INSERT INTO observations(id, value) VALUES (1, 'live')",
	} {
		out, errS, code := run("exec", "sqlite3.modify", "--db", databasePath, "--sql", statement, "-o", "json")
		if code != 0 || errS != "" || strings.TrimSpace(out) != "true" {
			t.Fatalf("modify(%q): code=%d out=%q err=%q", statement, code, out, errS)
		}
	}
	if info, err := os.Stat(databasePath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("database file = %#v, stat error = %v", info, err)
	}

	out, errS, code := run("exec", "sqlite3.fetch", "--db", databasePath,
		"--sql", "SELECT id, value FROM observations ORDER BY id", "-o", "json")
	var rows [][]any
	if code != 0 || errS != "" || json.Unmarshal([]byte(out), &rows) != nil ||
		len(rows) != 1 || rows[0][0] != float64(1) || rows[0][1] != "live" {
		t.Fatalf("fetch: code=%d out=%q err=%q rows=%#v", code, out, errS, rows)
	}

	out, errS, code = run("exec", "sqlite3.tables", "--db", databasePath, "-o", "json")
	if code != 0 || errS != "" || !strings.Contains(out, "observations") {
		t.Fatalf("tables: code=%d out=%q err=%q", code, out, errS)
	}
	out, errS, code = run("exec", "sqlite3.indices", "--db", databasePath, "-o", "json")
	if code != 0 || errS != "" || !strings.Contains(out, "observations_value") {
		t.Fatalf("indices: code=%d out=%q err=%q", code, out, errS)
	}

	// Observe the same file through a separate database/sql connection rather
	// than trusting the production command's serialized result alone.
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var observed string
	if err := db.QueryRow("SELECT value FROM observations WHERE id = 1").Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if observed != "live" {
		t.Fatalf("independent observation = %q, want live", observed)
	}
}
