package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/friz-zy/statekit/internal/config"
	"github.com/friz-zy/statekit/internal/output"
	"github.com/friz-zy/statekit/internal/result"
	"gopkg.in/yaml.v3"
)

// operation is one ordered step of an apply document (plan section 36).
type operation struct {
	State string         `yaml:"state" json:"state"`
	Args  map[string]any `yaml:"args" json:"args"`
}

// loadOperations parses an apply document: either a bare list of operations
// or an object with an "operations" key.
func loadOperations(data []byte) ([]operation, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("apply document is empty")
	}

	var asList []operation
	if err := yaml.Unmarshal([]byte(trimmed), &asList); err == nil && len(asList) > 0 {
		return asList, nil
	}

	var asObject struct {
		Operations []operation `yaml:"operations"`
	}
	if err := yaml.Unmarshal([]byte(trimmed), &asObject); err == nil && len(asObject.Operations) > 0 {
		return asObject.Operations, nil
	}

	return nil, fmt.Errorf("apply document must contain a list of operations")
}

const applyUsage = `Usage:
  statekit apply OPERATIONS.yaml [-o json|yaml|text] [--on-failure=stop|continue] [--test]

Applies an ordered, sequential list of state operations (explicitly not SLS:
no requisites, no dependency graph, no templating). On failure execution
stops by default; --on-failure=continue keeps going.
`

// valueFlags take a separate value token; they are kept paired when moving
// flags ahead of positionals so "-" may appear anywhere.
var valueFlags = map[string]bool{"output": true, "o": true, "on-failure": true}

func reorderApplyArgs(argv []string) []string {
	flags := []string{}
	rest := []string{}
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		isFlag := strings.HasPrefix(tok, "-") && tok != "-"
		if !isFlag {
			rest = append(rest, tok)
			continue
		}
		name := strings.TrimLeft(tok, "-")
		if !strings.Contains(tok, "=") && valueFlags[name] && i+1 < len(argv) {
			flags = append(flags, tok, argv[i+1])
			i++
			continue
		}
		flags = append(flags, tok)
	}
	return append(flags, rest...)
}

func (a *App) cmdApply(argv []string) int {
	argv = reorderApplyArgs(argv)
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addOutputFlags(fs)
	onFailure := fs.String("on-failure", "stop", "stop or continue after a failed operation")
	test := fs.Bool("test", false, "global dry-run for every operation without its own test key")
	if !parseOr(fs, argv) {
		return ExitInvalidInput
	}
	switch *onFailure {
	case "stop", "continue":
	default:
		return failf(ExitInvalidInput, "--on-failure must be stop or continue, got %q", *onFailure)
	}
	format, err := formatFrom(fs)
	if err != nil {
		return failf(ExitInvalidInput, "%v", err)
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprint(os.Stderr, applyUsage)
		return ExitInvalidInput
	}

	var data []byte
	if rest[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(rest[0])
	}
	if err != nil {
		return failf(ExitInvalidInput, "%v", err)
	}
	operations, err := loadOperations(data)
	if err != nil {
		return failf(ExitInvalidInput, "%v", err)
	}

	rt, code := a.buildRuntime()
	if rt == nil {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := make([]result.StateResult, 0, len(operations))
	failed := false
	for i, op := range operations {
		name := op.State
		if strings.TrimSpace(name) == "" {
			return failf(ExitInvalidInput, "operation %d has no state function", i)
		}
		template, tcode := resolveTemplate("state", rt, name)
		if template == nil {
			return tcode
		}

		structured := op.Args
		if structured == nil {
			structured = map[string]any{}
		}
		if _, present := structured["test"]; !present && *test {
			structured["test"] = true
		}

		argsPtr, dcode := decodeStructured(name, template, structured)
		if argsPtr == nil {
			return dcode
		}

		started := time.Now()
		res, err := rt.States.Apply(ctx, rt, name, argsPtr)
		if err != nil {
			return execFailure(err)
		}
		res = res.Normalized()
		module, function, _ := splitTarget(name)
		res.Meta = &result.ResultMeta{
			Type:       "state",
			Module:     module,
			Function:   function,
			DurationMS: time.Since(started).Milliseconds(),
		}
		results = append(results, res)

		if res.Result != nil && !*res.Result {
			failed = true
			if *onFailure == "stop" {
				break
			}
		}
	}

	exitCode := ExitOK
	if failed {
		exitCode = ExitFailed
	}
	if format == output.FormatText {
		var b strings.Builder
		for _, res := range results {
			b.WriteString(output.StateResultText(res))
			b.WriteString("---\n")
		}
		io.WriteString(os.Stdout, b.String())
		return exitCode
	}
	return encodeOr(os.Stdout, format, results)
}

// decodeStructured decodes pre-resolved structured arguments into the
// template's type without CLI flags.
func decodeStructured(fullName string, template any, structured map[string]any) (any, int) {
	names, err := config.ArgumentNames(template)
	if err != nil {
		return nil, failf(ExitInternal, "%v", err)
	}
	known := map[string]bool{}
	for _, n := range names {
		known[n] = true
	}
	for key := range structured {
		if !known[key] {
			return nil, failf(ExitInvalidInput, "%s: %v", fullName,
				&config.UnknownArgumentError{Name: key, Known: names})
		}
	}
	argsPtr := reflect.New(reflect.TypeOf(template)).Interface()
	if err := config.Decode(argsPtr, structured, nil); err != nil {
		return nil, failf(ExitInvalidInput, "%s: %v", fullName, err)
	}
	return argsPtr, ExitOK
}
