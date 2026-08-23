package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeMiniSaltTree builds a tiny Salt-like tree for end-to-end tool tests.
func writeMiniSaltTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{
		filepath.Join("salt", "modules"),
		filepath.Join("salt", "states"),
		filepath.Join("tests", "unit", "modules"),
		filepath.Join("tests", "pytests", "unit", "modules"),
	} {
		must(os.MkdirAll(filepath.Join(root, dir), 0o755))
	}

	must(os.WriteFile(filepath.Join(root, "salt", "modules", "samplepkg.py"), []byte(`__virtualname__ = "pkg"

def install(name, version=None):
    """Install."""
    return __salt__["cmd.run"](["echo"])
`), 0o644))
	must(os.WriteFile(filepath.Join(root, "salt", "modules", "_private.py"), []byte("def hidden():\n    pass\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "salt", "modules", "__init__.py"), []byte(""), 0o644))
	must(os.WriteFile(filepath.Join(root, "salt", "states", "samplepkg.py"), []byte(`__virtualname__ = "pkg"

def installed(name, version=None):
    """
    Ensure the package is installed.
    """
    return __salt__["pkg.install"](name)
`), 0o644))
	must(os.WriteFile(filepath.Join(root, "tests", "unit", "modules", "test_samplepkg.py"), []byte("def test_install():\n    pass\n\n\ndef test_other():\n    pass\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "tests", "pytests", "unit", "modules", "test_samplepkg.py"), []byte("def test_pytest_side():\n    pass\n"), 0o644))
	return root
}

func TestScanAndMapTests(t *testing.T) {
	root := writeMiniSaltTree(t)

	execDocs, stateDocs, err := scanSaltTree(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(execDocs) != 1 || len(stateDocs) != 1 {
		t.Fatalf("private/init files must be skipped; got %d exec / %d state docs", len(execDocs), len(stateDocs))
	}

	doc := execDocs[0]
	if doc.Module != "pkg" || doc.SourceModule != "samplepkg" || !doc.Virtual {
		t.Fatalf("exec doc = %+v", doc)
	}
	if len(doc.Functions) != 1 || doc.Functions[0].Function != "install" {
		t.Fatalf("functions = %+v", doc.Functions)
	}
	entry := doc.Functions[0]
	if entry.Source.Path != "salt/modules/samplepkg.py" || entry.Source.Symbol != "install" {
		t.Fatalf("source ref = %+v", entry.Source)
	}
	if len(entry.ExecutionDependencies) != 1 || entry.ExecutionDependencies[0] != "cmd.run" {
		t.Fatalf("deps = %v", entry.ExecutionDependencies)
	}
	if len(entry.Tests) != 2 {
		t.Fatalf("test refs = %+v", entry.Tests)
	}
	totalTests := 0
	for _, tr := range entry.Tests {
		totalTests += tr.Functions
	}
	if totalTests != 3 {
		t.Fatalf("mapped test functions = %d, want 3 (%+v)", totalTests, entry.Tests)
	}

	state := stateDocs[0]
	if state.Module != "pkg" || state.Kind != "state" {
		t.Fatalf("state doc = %+v", state)
	}
	if state.Functions[0].Summary != "Ensure the package is installed." {
		t.Fatalf("state summary = %q", state.Functions[0].Summary)
	}
}

func TestRelevanceAndAliases(t *testing.T) {
	doc := ModuleDoc{Module: "pkg", SourceModule: "aptpkg"}
	if !isRelevant(doc) {
		t.Fatal("aptpkg must classify as relevant via alias")
	}
	doc2 := ModuleDoc{Module: "apache", SourceModule: "apache"}
	if isRelevant(doc2) {
		t.Fatal("apache must not be relevant")
	}
	doc3 := ModuleDoc{Module: "sysctl", SourceModule: "linux_sysctl"}
	if !isRelevant(doc3) {
		t.Fatal("linux_sysctl must be relevant via alias")
	}
}

func TestDetectImplemented(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "modules", "exec")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package test

type echoFunc struct{}

func (echoFunc) Name() string { return "test.echo" }
func (echoFunc) Args() any    { return struct{}{} }
`
	if err := os.WriteFile(filepath.Join(dir, "test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	testSrc := `package test

import "testing"

func TestBogus(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "test_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	impl, err := detectImplemented(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(impl.Exec) != 1 || impl.Exec[0] != "test.echo" {
		t.Fatalf("implemented exec = %v", impl.Exec)
	}
}

func TestWriteCatalogAndCoverage(t *testing.T) {
	root := writeMiniSaltTree(t)
	outDir := filepath.Join(t.TempDir(), "catalog")

	ref := ReferenceInfo{Repository: "https://github.com/saltstack/salt", Commit: "abc123", Version: "v3008.2-180-gabc123"}
	execDocs, stateDocs, err := scanSaltTree(root)
	if err != nil {
		t.Fatal(err)
	}
	impl, err := detectImplemented(".")
	if err != nil {
		t.Fatal(err)
	}
	cov := buildCoverage(ref, execDocs, stateDocs, impl)
	if err := writeCatalog(outDir, ref, execDocs, stateDocs, cov, Implemented{}); err != nil {
		t.Fatalf("writeCatalog: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "coverage.yaml"))
	if err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	var covBack Coverage
	if err := yaml.Unmarshal(data, &covBack); err != nil {
		t.Fatalf("parse coverage: %v", err)
	}
	if covBack.Execution.SaltFunctions != 1 || covBack.Execution.RelevantFunctions != 1 {
		t.Fatalf("execution coverage wrong: %+v", covBack.Execution)
	}
	if covBack.State.SaltFunctions != 1 {
		t.Fatalf("state coverage wrong: %+v", covBack.State)
	}
	if _, err := os.Stat(filepath.Join(outDir, "exec", "samplepkg.yaml")); err != nil {
		t.Fatalf("module catalog file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "index.yaml")); err != nil {
		t.Fatalf("index missing: %v", err)
	}
}

func TestWriteSaltLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "references", "salt.lock")
	err := writeSaltLock(path, ReferenceInfo{
		Repository: "https://github.com/saltstack/salt",
		Commit:     "8b63e700637e40d76f80a00d95c60471797c73b9",
		Version:    "v3008.2-180-g8b63e70063",
	})
	if err != nil {
		t.Fatalf("write lock: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var back map[string]string
	if yaml.Unmarshal(data, &back) != nil ||
		back["commit"] != "8b63e700637e40d76f80a00d95c60471797c73b9" ||
		back["version"] != "v3008.2-180-g8b63e70063" {
		t.Fatalf("lock content wrong: %s", data)
	}
}
