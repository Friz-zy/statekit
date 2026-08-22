package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOps(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyDocumentParsing(t *testing.T) {
	ops, err := loadOperations([]byte("operations:\n  - state: test.nop\n    args: {name: a}\n"))
	if err != nil || len(ops) != 1 || ops[0].State != "test.nop" || ops[0].Args["name"] != "a" {
		t.Fatalf("object form wrong: %+v %v", ops, err)
	}
	ops, err = loadOperations([]byte("- state: file.managed\n"))
	if err != nil || len(ops) != 1 || ops[0].State != "file.managed" {
		t.Fatalf("bare list form wrong: %+v %v", ops, err)
	}
	if _, err := loadOperations(nil); err == nil {
		t.Fatal("empty document must fail")
	}
	if _, err := loadOperations([]byte("just: text\n")); err == nil {
		t.Fatal("non-operation document must fail")
	}
}

func TestApplyEndToEndViaApp(t *testing.T) {
	path := writeOps(t, `operations:
  - state: file.managed
    args: {name: /stage/a.conf, contents: A}
  - state: test.nop
    args: {name: mid}
`)
	code, out, _ := runApp(t, "apply", path)
	_ = out
	if code != ExitOK {
		t.Fatalf("apply exit = %d", code)
	}
}

func TestApplyStopsOnFailureByDefault(t *testing.T) {
	path := writeOps(t, `operations:
  - state: nosuch.state
    args: {name: x}
  - state: test.nop
    args: {name: never}
`)
	code, _, _ := runApp(t, "apply", path)
	if code != ExitUnsupported {
		t.Fatalf("unsupported operation exit = %d", code)
	}
}

func TestApplyTestModeGlobal(t *testing.T) {
	path := writeOps(t, "operations:\n  - state: test.nop\n    args: {name: a}\n")
	code, out, _ := runApp(t, "apply", path, "--test", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"result": true`) {
		t.Fatalf("global test mode: code=%d out=%q", code, out)
	}
}
