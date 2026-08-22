// Package integration runs the compiled statekit binary against
// language-independent YAML fixtures (plan section 25).
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

const repoRoot = "../.."

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "statekit-bin-")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "statekit")
		var stderr bytes.Buffer
		cmd := exec.Command("go", "build", "-o", out, "./cmd/statekit")
		cmd.Dir = repoRoot
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("build statekit: %v", buildErr)
	}
	return binPath
}

type fixture struct {
	ID             string         `yaml:"id"`
	Command        []string       `yaml:"command"`
	Stdin          string         `yaml:"stdin"`
	Exit           int            `yaml:"exit"`
	Stdout         string         `yaml:"stdout"`
	Contains       []string       `yaml:"contains"`
	StderrContains []string       `yaml:"stderr-contains"`
	JSON           map[string]any `yaml:"json"`
}

func loadFixtures(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(repoRoot, "tests", "fixtures", "*.yaml"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no fixtures found under tests/fixtures")
	}
	return matches
}

func TestFixtures(t *testing.T) {
	bin := buildBinary(t)
	for _, path := range loadFixtures(t) {
		path := path
		name := strings.TrimSuffix(filepath.Base(path), ".yaml")
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var f fixture
			if err := yaml.Unmarshal(data, &f); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			runFixture(t, bin, f)
		})
	}
}

func runFixture(t *testing.T, bin string, f fixture) {
	t.Helper()
	cmd := exec.Command(bin, f.Command...)
	cmd.Stdin = strings.NewReader(f.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run binary: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}

	if exitCode != f.Exit {
		t.Fatalf("exit = %d want %d\nstdout:\n%s\nstderr:\n%s",
			exitCode, f.Exit, stdout.String(), stderr.String())
	}
	for _, want := range f.Contains {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q\ngot:\n%s", want, stdout.String())
		}
	}
	for _, want := range f.StderrContains {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q\ngot:\n%s", want, stderr.String())
		}
	}
	if f.Stdout != "" && stdout.String() != f.Stdout {
		t.Fatalf("stdout mismatch\ngot:  %q\nwant: %q", stdout.String(), f.Stdout)
	}
	if len(f.JSON) > 0 {
		var actual map[string]any
		if jerr := json.Unmarshal(stdout.Bytes(), &actual); jerr != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", jerr, stdout.String())
		}
		if problems := subsetMatch(f.JSON, actual); len(problems) > 0 {
			t.Fatalf("json mismatch (%s)\ngot:\n%s", strings.Join(problems, "; "), stdout.String())
		}
	}
}

// subsetMatch verifies every expected key exists in actual with an equal or
// recursively matching value.
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
		if !valuesEqual(wantValue, gotValue) {
			problems = append(problems, fmt.Sprintf("%s: got %#v want %#v", key, gotValue, wantValue))
		}
	}
	sortStrings(problems)
	return problems
}

func valuesEqual(want, got any) bool {
	return reflect.DeepEqual(normalizeNumbers(want), normalizeNumbers(got))
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

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
