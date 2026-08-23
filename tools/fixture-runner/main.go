// Command fixture-runner executes YAML fixtures against a compiled statekit
// binary and emits JUnit XML.
//
// It is the in-container driver referenced by plans/testing.md
// (tests/run-fixtures.sh): containers receive the binary, the fixtures tree,
// and this runner — no Go toolchain required at runtime.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type fixture struct {
	ID             string         `yaml:"id"`
	Command        []string       `yaml:"command"`
	Stdin          string         `yaml:"stdin"`
	Exit           int            `yaml:"exit"`
	Stdout         string         `yaml:"stdout"`
	Contains       []string       `yaml:"contains"`
	StderrContains []string       `yaml:"stderr-contains"`
	JSON           map[string]any `yaml:"json"`
	Tmpdir         bool           `yaml:"tmpdir"`
	RequiresRoot   bool           `yaml:"requires-root"`
}

type result struct {
	id     string
	passed bool
	detail string
}

var suites multiFlag

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	bin := flag.String("bin", "/usr/local/bin/statekit", "path to the statekit binary")
	fixturesDir := flag.String("fixtures", "/fixtures", "fixtures root directory")
	junitPath := flag.String("junit", "", "write a JUnit XML report to this path")
	flag.Var(&suites, "suite", "suite name = fixtures subdirectory; repeatable, default all")
	flag.Parse()

	files, err := collect(*fixturesDir)
	if err != nil {
		fatal(err)
	}

	results := []result{}
	for _, file := range files {
		if len(suites) > 0 && !inSuite(file, *fixturesDir) {
			continue
		}
		results = append(results, runFixture(*bin, file))
	}

	passed := 0
	for _, res := range results {
		status := "FAIL"
		if res.passed {
			status = "PASS"
			passed++
		}
		fmt.Printf("[%s] %s\n", status, res.id)
		if !res.passed {
			fmt.Println(indent(res.detail))
		}
	}
	fmt.Printf("\n%d/%d fixtures passed\n", passed, len(results))

	if *junitPath != "" {
		if err := writeJUnit(*junitPath, results); err != nil {
			fatal(err)
		}
	}
	if passed != len(results) {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "fixture-runner: %v\n", err)
	os.Exit(2)
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = "        " + line
	}
	return strings.Join(out, "\n")
}

func sortStrings(list []string) {
	sort.Strings(list)
}

func collect(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no fixtures under %s", root)
	}
	sort.Strings(files)
	return files, nil
}

func inSuite(path, fixturesRoot string) bool {
	rel, err := filepath.Rel(fixturesRoot, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return false
	}
	suite := parts[0]
	for _, want := range suites {
		if suite == want || want == "all" {
			return true
		}
	}
	return false
}

func runFixture(binPath, path string) result {
	raw, err := os.ReadFile(path)
	if err != nil {
		return result{id: filepath.Base(path), passed: false,
			detail: fmt.Sprintf("read fixture: %v", err)}
	}
	var f fixture
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return result{id: filepath.Base(path), passed: false,
			detail: fmt.Sprintf("parse fixture: %v", err)}
	}
	if f.ID == "" {
		f.ID = filepath.Base(path)
		return result{f.ID, false, "fixture has no id"}
	}
	if f.RequiresRoot && os.Geteuid() != 0 {
		return result{id: f.ID, passed: true,
			detail: "skipped: requires root"}
	}

	command := append([]string{}, f.Command...)
	if f.Tmpdir {
		dir, err := os.MkdirTemp("", "statekit-fixture-")
		if err != nil {
			return result{f.ID, false, fmt.Sprintf("tmpdir: %v", err)}
		}
		defer os.RemoveAll(dir)
		for i, arg := range command {
			command[i] = strings.ReplaceAll(arg, "__TMPDIR__", dir)
		}
		if len(f.JSON) > 0 {
			jsonRaw, _ := json.Marshal(f.JSON)
			var substituted map[string]any
			_ = json.Unmarshal(
				[]byte(strings.ReplaceAll(string(jsonRaw), "__TMPDIR__", dir)),
				&substituted)
			f.JSON = substituted
		}
	}

	cmd := exec.Command(binPath, command...)
	cmd.Stdin = strings.NewReader(f.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return result{f.ID, false, fmt.Sprintf("run: %v", err)}
		}
		exitCode = exitErr.ExitCode()
	}

	problems := []string{}
	if exitCode != f.Exit {
		problems = append(problems,
			fmt.Sprintf("exit=%d want=%d\nstdout:\n%s\nstderr:\n%s",
				exitCode, f.Exit, stdout.String(), stderr.String()))
	}
	for _, want := range f.Contains {
		if !strings.Contains(stdout.String(), want) {
			problems = append(problems,
				fmt.Sprintf("stdout missing %q\ngot:\n%s", want, stdout.String()))
		}
	}
	for _, want := range f.StderrContains {
		if !strings.Contains(stderr.String(), want) {
			problems = append(problems,
				fmt.Sprintf("stderr missing %q\ngot:\n%s", want, stderr.String()))
		}
	}
	if f.Stdout != "" && stdout.String() != f.Stdout {
		problems = append(problems,
			fmt.Sprintf("stdout mismatch\ngot:  %q\nwant: %q", stdout.String(), f.Stdout))
	}
	if len(f.JSON) > 0 {
		var actual map[string]any
		if jerr := json.Unmarshal(stdout.Bytes(), &actual); jerr != nil {
			problems = append(problems,
				fmt.Sprintf("stdout is not JSON: %v\n%s", jerr, stdout.String()))
		} else if bad := subsetMatch(f.JSON, actual); len(bad) > 0 {
			problems = append(problems,
				fmt.Sprintf("json mismatch (%s)\ngot:\n%s",
					strings.Join(bad, "; "), stdout.String()))
		}
	}

	return result{id: f.ID, passed: len(problems) == 0, detail: strings.Join(problems, "\n")}
}

func subsetMatch(expected, actual map[string]any) []string {
	var problems []string
	for key, wantValue := range expected {
		gotValue, present := actual[key]
		if !present {
			problems = append(problems, "missing key "+key)
			continue
		}
		wantMap, wantIsMap := wantValue.(map[string]any)
		gotMap, gotIsMap := gotValue.(map[string]any)
		if wantIsMap && gotIsMap {
			problems = append(problems, subsetMatch(wantMap, gotMap)...)
			continue
		}
		if !reflect.DeepEqual(normalizeNumbers(wantValue), normalizeNumbers(gotValue)) {
			problems = append(problems,
				fmt.Sprintf("%s: got %#v want %#v", key, gotValue, wantValue))
		}
	}
	return problems
}

func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case float32:
		return float64(t)
	default:
		return v
	}
}

func xmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;",
		`"`, "&quot;", "'", "&apos;",
	)
	return replacer.Replace(s)
}

func writeJUnit(path string, results []result) error {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	failures := 0
	for _, res := range results {
		if !res.passed {
			failures++
		}
	}
	fmt.Fprintf(&b,
		"<testsuite name=\"statekit fixtures\" tests=\"%d\" failures=\"%d\">\n",
		len(results), failures)
	for _, res := range results {
		fmt.Fprintf(&b, "\t<testcase name=\"%s\" classname=\"fixtures\">\n", xmlEscape(res.id))
		if !res.passed {
			fmt.Fprintf(&b,
				"\t\t<failure message=\"fixture failed\"><![CDATA[%s]]></failure>\n",
				strings.ReplaceAll(res.detail, "]]>", "]]&gt;"))
		}
		b.WriteString("\t</testcase>\n")
	}
	b.WriteString("</testsuite>\n")

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
