// Package cli implements the statekit command-line interface.
//
// Canonical forms (plan section 5):
//
//	statekit exec  <module>.<function> [args]
//	statekit state <module>.<function> [args]
//
// plus version and facts commands. Exit codes follow plan section 40:
// 0 success, 1 operation/state failed, 2 invalid invocation/input,
// 3 unsupported function/provider, 4 runtime/internal failure.
package cli

import (
	"context"
	"errors"
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
	"github.com/friz-zy/statekit/internal/runtime"
)

// CLI exit codes (plan section 40).
const (
	ExitOK           = 0
	ExitFailed       = 1
	ExitInvalidInput = 2
	ExitUnsupported  = 3
	ExitInternal     = 4
)

const usageText = `statekit — portable local SaltStack-compatible execution and states

Usage:
  statekit exec <module>.<function> [args] [-o json|yaml|text]
  statekit state <module>.<function> [args] [-o json|yaml|text]
  statekit exec aws.secretsmanager.get (--source-uri URI | --region REGION --resource RESOURCE) [--version-id ID | --version-alias ALIAS] [--format raw|text|json|yaml] [--sink stdout|stderr|unix --target PATH]
  statekit exec aws.ssm.get (--source-uri URI | --region REGION --resource RESOURCE) [--version-id ID] [--format raw|text|json|yaml] [--sink stdout|stderr|unix --target PATH]
  statekit exec gcp.secretmanager.get (--source-uri URI | --region global --resource projects/PROJECT/secrets/SECRET) [--version-id ID | --version-alias latest] [--format raw|text|json|yaml] [--sink stdout|stderr|unix --target PATH]
  statekit exec gcp.parametermanager.get (--source-uri URI | --provider gcp --backend parametermanager --region LOCATION --resource projects/PROJECT/locations/LOCATION/parameters/PARAMETER) [--version-id ID | --version-alias latest] [--format raw|text|json|yaml] [--sink stdout|stderr|unix --target PATH]
  statekit exec azure.keyvault.get (--source-uri URI | --region VAULT --resource SECRET) [--version-id VERSION] [--format raw|json|yaml] [--sink stdout|stderr]
  statekit exec azure.appconfiguration.get (--source-uri URI | --region STORE --resource KEY) --label LABEL [--format raw|json|yaml] [--sink stdout|stderr]

Commands:
  exec <mod>.<fun>   run an execution function
  state <mod>.<fun>  apply a single state function
  exec aws.secretsmanager.get | aws.ssm.get | gcp.secretmanager.get
                     read one AWS or GCP secret value to one sink
  exec gcp.parametermanager.get
                     read raw GCP Parameter Manager configuration (sensitive)
  exec azure.keyvault.get | azure.appconfiguration.get
                     read one Azure secret or explicitly labeled setting (sensitive)
  facts              show detected system facts
  version            show the StateKit version

Each route pins its provider and service: explicit --provider, --backend,
or --source-uri values must match the selected route or the request is
rejected before any credential resolution or fetch.

Parameter Manager: canonical URI is param://gcp/parametermanager/LOCATION/RESOURCE
(percent-encode the complete provider-native resource
projects/{project}/locations/{location}/parameters/{parameter} as exactly one
path segment; literal slash-expanded resource paths are rejected), or all four structured
fields --provider gcp --backend parametermanager --region LOCATION --resource
projects/PROJECT/locations/LOCATION/parameters/PARAMETER. LOCATION is global or
a regional location. Select --version-id ID or --version-alias latest; omitted
selection means mutable latest. There is no application-level retry or fallback
to another secret/parameter version; gRPC may transparently retry/reconnect the same call
at the transport layer.
GCP Secret Manager reads use mutable latest when neither --version-id nor
--version-alias is supplied. Set a numeric --version-id when stable content is needed.
Formats: --format raw|text|json|yaml (default raw); --key-path is RFC6901 and
only valid for JSON/YAML. Sinks: stdout, stderr, or unix with --target PATH;
file sinks are deferred. All parameter payload is sensitive. Only raw
GetParameterVersion is used: no rendering, templates, or __REF__ resolution.
IAM is external and project-scoped: prefer an externally provisioned custom
role containing parametermanager.parameterversions.get where supported;
otherwise roles/parametermanager.parameterViewer also exposes listing and
project-wide reads. StateKit never creates or changes IAM. Rendering/reference
support requires a separate security design; this route supports only raw
global/regional reads using the fixed official endpoints and GCE identity.

Azure routes use managed identity only, through the fixed IMDS endpoint with
the 2018-02-01 API; there is no azidentity chain and no environment, CLI,
profile, or token-file source, and only the Key Vault and App Configuration
audiences are permitted. Only the public authorities <vault>.vault.azure.net
and <store>.azconfig.io are accepted: custom hosts, ports, userinfo, paths,
and private endpoints are rejected, every resolved service address must be
public, proxies and redirects are refused, and TLS hostname verification
always uses the service authority even though the dial targets the validated
IP. Each read builds one per-operation SDK client; Key Vault challenge
resource verification stays enabled and the exact audience is enforced again
at the credential. A Key Vault version may be omitted for latest, and the
concrete version is validated from the response; azure.appconfiguration.get
requires the explicit non-empty --label (or structured label field) naming
the exact setting version, never falls back to an unlabeled setting, and
never resolves Key Vault references. Azure delivery is authorized only for
raw or structured JSON/YAML payloads on the stdout or stderr sinks; the
text format and the unix sink are rejected before any connection,
credential, or fetch.

Common options:
  --list             list available functions (optionally module.<prefix>)
  -o, --output FMT   output format: json, yaml, text
  --config YAMLJSON  inline structured arguments (YAML or JSON object)
  --file PATH        read structured arguments from a YAML/JSON file
  --stdin | -        read structured arguments from stdin

Structured input precedence: defaults < file/stdin/config < CLI flags.
`

// globalFlagNames are injected into every function flag set; templates must
// not declare colliding argument names.
var globalFlagNames = map[string]bool{"output": true, "o": true, "config": true, "file": true, "stdin": true}

// App wires the CLI to a runtime factory so tests can inject fakes.
type App struct {
	Version      string
	BuildRuntime func() (*runtime.Runtime, error)

	// CloudCollect optionally overrides the cloud metadata collector
	// with an offline fake for tests; nil uses cloudmeta.Collect.
	CloudCollect cloudCollectFunc

	// secretFetch injects a synthetic reader in tests; production uses the
	// dedicated AWS instance-profile path.
	secretFetch    secretFetchFunc
	parameterFetch secretFetchFunc
}

// NewApp creates a CLI application bound to the given runtime factory.
func NewApp(version string, build func() (*runtime.Runtime, error)) *App {
	return &App{Version: version, BuildRuntime: build}
}

// Run executes argv (without the program name) and returns the exit code.
func (a *App) Run(argv []string) int {
	code := ExitInternal
	func() {
		defer func() {
			if r := recover(); r != nil {
				if args, ok := secretInvocationArgs(argv); ok {
					if secretSinkHint(args) != "stderr" {
						_, _ = io.WriteString(os.Stderr, "statekit: secret operation failed\n")
					}
					code = ExitFailed
					return
				}
				fmt.Fprintf(os.Stderr, "statekit: internal failure: %v\n", r)
				code = ExitInternal
			}
		}()
		code = a.dispatch(argv)
	}()
	return code
}

func (a *App) dispatch(argv []string) int {
	if len(argv) == 0 {
		usage(os.Stderr)
		return ExitInvalidInput
	}
	switch argv[0] {
	case "version":
		return a.cmdVersion(argv[1:])
	case "facts":
		return a.cmdFacts(argv[1:])
	case "exec":
		for _, route := range secretGetRoutes {
			if args, ok := extractSensitiveGetArgs(argv[1:], route.command); ok {
				return a.cmdRoutedSecretGet(args, route)
			}
		}
		if command, ok := retiredSecretInvocation(argv[1:]); ok {
			// The retired token is matched from the fixed table, so
			// echoing it carries no caller value; rejection precedes
			// every input channel, the runtime, credentials, and fetch.
			return failf(ExitInvalidInput, "retired command %q; use the <provider>.<service>.get form", command)
		}
		return a.cmdFunction("exec", argv[1:])
	case "state":
		return a.cmdFunction("state", argv[1:])
	case "apply":
		return a.cmdApply(argv[1:])
	case "-h", "--help", "help":
		usage(os.Stdout)
		return ExitOK
	default:
		fmt.Fprintf(os.Stderr, "statekit: unknown command %q\n\n", argv[0])
		usage(os.Stderr)
		return ExitInvalidInput
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, usageText)
}

func newNamespaceFlagSet(name string) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addOutputFlags(fs)
	addChannelFlags(fs)
	list := fs.Bool("list", false, "list available functions")
	return fs, list
}

func addOutputFlags(fs *flag.FlagSet) {
	fs.String("output", string(output.FormatText), "output format: json, yaml, text")
	fs.String("o", "", "short form of --output")
}

func formatFrom(fs *flag.FlagSet) (output.Format, error) {
	format := ""
	if out := fs.Lookup("output"); out != nil {
		format = out.Value.String()
	}
	if short := fs.Lookup("o"); short != nil && short.Value.String() != "" {
		format = short.Value.String()
	}
	return output.ParseFormat(format)
}

func encodeOr(w io.Writer, format output.Format, v any) int {
	if err := output.Encode(w, format, v); err != nil {
		fmt.Fprintf(os.Stderr, "statekit: %v\n", err)
		return ExitInternal
	}
	return ExitOK
}

func failf(code int, format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "statekit: "+format+"\n", args...)
	return code
}

func (a *App) buildRuntime() (*runtime.Runtime, int) {
	rt, err := a.BuildRuntime()
	if err != nil {
		return nil, failf(ExitInternal, "%v", err)
	}
	return rt, ExitOK
}

func (a *App) cmdVersion(argv []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addOutputFlags(fs)
	if !parseOr(fs, argv) {
		return ExitInvalidInput
	}
	format, err := formatFrom(fs)
	if err != nil {
		return failf(ExitInvalidInput, "%v", err)
	}
	payload := struct {
		Version string `json:"version" yaml:"version"`
	}{Version: a.Version}
	return encodeOr(os.Stdout, format, payload)
}

func (a *App) cmdFacts(argv []string) int {
	fs := flag.NewFlagSet("facts", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addOutputFlags(fs)
	cloud := fs.Bool("cloud", false, "collect cloud machine metadata (requires --provider)")
	provider := fs.String("provider", "", "cloud provider enum (requires --cloud)")
	if !parseOr(fs, argv) {
		return ExitInvalidInput
	}
	// Cloud flags are detected by explicit presence (fs.Visit), so
	// `--provider=` alone is still a usage error; dispatch additionally
	// requires the parsed --cloud VALUE to be true — an explicit
	// `--cloud=false` (or a repeated flag ending false) with --provider
	// never reaches the collector.
	cloudSet, providerSet := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cloud":
			cloudSet = true
		case "provider":
			providerSet = true
		}
	})
	if cloudSet || providerSet {
		if !cloudSet || !providerSet {
			return failf(ExitInvalidInput, "--cloud and --provider must be used together")
		}
		if !*cloud {
			return failf(ExitInvalidInput, "--cloud must be true to collect cloud metadata")
		}
		if *provider == "" {
			return failf(ExitInvalidInput, "--provider must not be empty")
		}
		if len(fs.Args()) > 0 {
			return failf(ExitInvalidInput, "cloud facts accept no positional arguments")
		}
		if _, ferr := formatFrom(fs); ferr != nil {
			return failf(ExitInvalidInput, "%v", ferr)
		}
		return a.runFactsCloud(*provider)
	}
	format, err := formatFrom(fs)
	if err != nil {
		return failf(ExitInvalidInput, "%v", err)
	}
	rt, code := a.buildRuntime()
	if rt == nil {
		return code
	}
	return encodeOr(os.Stdout, format, rt.Facts)
}

func splitTarget(token string) (module, function string, ok bool) {
	module, function, found := strings.Cut(token, ".")
	return module, function, found && module != "" && function != "" &&
		!strings.Contains(function, ".")
}

// slackTarget reports whether a <module>.<function> dispatch target
// belongs to the slack family, whose inputs are credentials (api keys
// and webhook identifiers; R10.1 SEC-006).
func slackTarget(target string) bool {
	return strings.HasPrefix(target, "slack.")
}

// outputFormatFailure reports an invalid output-format diagnostic on
// the function dispatch path. For slack.* targets the diagnostic is
// value-free (R10.1 SEC-006): the supplied format is raw caller input,
// so a secret pasted as a format value must not reach stderr and one
// fixed category travels instead. Every other target keeps the verbatim
// message; target-less surfaces (version, facts, --list) never resolve
// a dispatch target and keep verbatim diagnostics too.
func outputFormatFailure(target string, err error) int {
	if slackTarget(target) {
		return failf(ExitInvalidInput, "invalid output format")
	}
	return failf(ExitInvalidInput, "%v", err)
}

func (a *App) cmdFunction(kind string, argv []string) int {
	namespaceFS, list := newNamespaceFlagSet(kind)
	if !parseOr(namespaceFS, argv) {
		return ExitInvalidInput
	}
	rest := namespaceFS.Args()

	if *list {
		target := ""
		switch len(rest) {
		case 0:
		case 1:
			target = strings.TrimSuffix(rest[0], ".")
		default:
			return failf(ExitInvalidInput, "--list accepts at most one module prefix")
		}
		format, err := formatFrom(namespaceFS)
		if err != nil {
			return failf(ExitInvalidInput, "%v", err)
		}
		return a.cmdList(kind, target, format)
	}

	if len(rest) < 1 || strings.HasPrefix(rest[0], "-") {
		usage(os.Stderr)
		return ExitInvalidInput
	}

	single := false
	target := rest[0]
	if kind == "state" && target == "single" {
		// Plan section 35: statekit state single <fun> [args]
		single = true
		rest = rest[1:]
		if len(rest) >= 1 && !strings.HasPrefix(rest[0], "-") {
			target = rest[0]
			rest = rest[1:]
		} else {
			// fun may arrive via structured input; resolved after loading.
			target = ""
		}
		if len(rest) == 0 && target == "" {
			usage(os.Stderr)
			return ExitInvalidInput
		}
	}

	functionArgv := rest[1:]
	if single {
		// "single" keyword and optional fun token already consumed above.
		functionArgv = rest
	}

	module, function, ok := splitTarget(target)
	if !ok {
		if single && target == "" {
			// Deferred format boundary: with the function name still
			// unresolved this branch keeps verbatim output-format
			// diagnostics. That scoping holds only while the invariant
			// does: deferred state-single resolution consults the
			// state registry only, and slack is registered exclusively
			// as an exec module, so this branch can never dispatch
			// slack. Introducing slack state registrations would
			// require revisiting the value-free scoping.
			ok = false // deferred to structured "fun" key below
		} else {
			return failf(ExitInvalidInput, "function must be <module>.<function>, got %q", target)
		}
	}

	format, err := formatFrom(namespaceFS)
	if err != nil {
		// The dispatch target is resolved here, so the diagnostic can
		// be scoped: slack targets keep the raw format value off stderr.
		return outputFormatFailure(module+"."+function, err)
	}

	rt, code := a.buildRuntime()
	if rt == nil {
		return code
	}

	fullName := module + "." + function

	var template any
	if ok {
		template, code = resolveTemplate(kind, rt, fullName)
		if template == nil {
			return code
		}
	}

	argsPtr, explicit, structuredFun, code := decodeArgs(kind, fullName, template, functionArgv, channels(namespaceFS), single)
	if argsPtr == nil && code != ExitOK {
		return code
	}
	if structuredFun != "" {
		fullName = structuredFun
		template, code = resolveTemplate(kind, rt, fullName)
		if template == nil {
			return code
		}
		var exp string
		argsPtr, exp, _, code = decodeArgs(kind, fullName, template, functionArgv, channels(namespaceFS), true)
		if argsPtr == nil && code != ExitOK {
			return code
		}
		if exp != "" {
			explicit = exp
		}
	}
	if explicit != "" {
		format, err = output.ParseFormat(explicit)
		if err != nil {
			return outputFormatFailure(fullName, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	if kind == "exec" {
		value, err := rt.Exec.Call(ctx, rt, fullName, argsPtr)
		if err != nil {
			return execFailure(err)
		}
		return encodeOr(os.Stdout, format, value)
	}

	res, err := rt.States.Apply(ctx, rt, fullName, argsPtr)
	if err != nil {
		return execFailure(err)
	}
	res = res.Normalized()
	metaModule, metaFunction, _ := splitTarget(fullName)
	res.Meta = &result.ResultMeta{
		Type:       "state",
		Module:     metaModule,
		Function:   metaFunction,
		DurationMS: time.Since(started).Milliseconds(),
	}

	exitCode := ExitOK
	if res.Result != nil && !*res.Result {
		exitCode = ExitFailed
	}
	rendered := encodeOr(os.Stdout, format, res)
	if rendered != ExitOK {
		return rendered
	}
	return exitCode
}

func resolveTemplate(kind string, rt *runtime.Runtime, fullName string) (any, int) {
	if kind == "exec" {
		template, err := rt.Exec.ResolveArgs(rt, fullName)
		if err != nil {
			return nil, execFailure(err)
		}
		return template, ExitOK
	}
	fn, ok := rt.States.Get(fullName)
	if !ok {
		return nil, failf(ExitUnsupported, "unsupported state %q", fullName)
	}
	return fn.Args(), ExitOK
}

func execFailure(err error) int {
	var unsupported *runtime.UnsupportedError
	if errors.As(err, &unsupported) {
		return failf(ExitUnsupported, "%v", err)
	}
	return failf(ExitFailed, "%v", err)
}

func (a *App) cmdList(kind, target string, format output.Format) int {
	rt, code := a.buildRuntime()
	if rt == nil {
		return code
	}
	names := rt.Exec.Names()
	if kind == "state" {
		names = rt.States.Names()
	}
	if target != "" {
		prefix := target + "."
		filtered := make([]string, 0, len(names))
		for _, name := range names {
			if strings.HasPrefix(name, prefix) {
				filtered = append(filtered, name)
			}
		}
		names = filtered
	}
	if format == output.FormatText {
		for _, name := range names {
			fmt.Println(name)
		}
		return ExitOK
	}
	return encodeOr(os.Stdout, format, names)
}

// parseOr parses argv and reports failures with a visible message.
func parseOr(fs *flag.FlagSet, argv []string) bool {
	return parseOrArgs(fs, argv, false)
}

// parseOrArgs parses argv; when valueFree is set (credential-input
// targets, R10.1 SEC-006) every non-help parse failure reports one
// fixed value-free category, because flag-package errors quote the
// offending token and value — a secret pasted as a malformed or
// unknown flag value must not reach stderr. flag.ErrHelp keeps its
// own value-free text either way.
func parseOrArgs(fs *flag.FlagSet, argv []string, valueFree bool) bool {
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) || !valueFree {
			failf(ExitInvalidInput, "%v", err)
			return false
		}
		failf(ExitInvalidInput, "invalid command-line arguments")
		return false
	}
	return true
}

// decodeArgs parses function-level flags against the template's generated
// flag set, merges namespace-level channel defaults, and decodes every input
// channel into a fresh args pointer. It returns the args pointer, the
// explicitly requested output format (empty when none), and an exit code.
// decodeArgs parses function-level flags against the template's generated
// flag set, merges namespace-level channel defaults, and decodes every input
// channel into a fresh args pointer. For `state single` with a deferred
// function name (template == nil) it only resolves structured channels and
// returns the "fun" key. Returns the args pointer, the explicitly requested
// output format (empty when none), the extracted fun key, and an exit code.
func decodeArgs(kind, fullName string, template any, argv []string, base config.Channels, wantFun bool) (any, string, string, int) {
	boundedQuery := kind == "exec" && fullName == "postgres.psql_query"
	if boundedQuery {
		// Reject oversized flag text before normalization and flag decoding
		// duplicate the caller's SQL. Structured channels are capped below.
		for i, arg := range argv {
			if arg == "--query" && i+1 < len(argv) && len(argv[i+1]) > runtime.MaxCommandInputBytes {
				return nil, "", "", failf(ExitInvalidInput, "postgres.psql_query: query exceeds input limit")
			}
			if strings.HasPrefix(arg, "--query=") && len(arg)-len("--query=") > runtime.MaxCommandInputBytes {
				return nil, "", "", failf(ExitInvalidInput, "postgres.psql_query: query exceeds input limit")
			}
		}
		base.MaxBytes = runtime.MaxCommandInputBytes
	}
	// Slack inputs are credentials (api keys, webhook identifiers), so
	// the family's parse and positional diagnostics are value-free
	// (R10.1 SEC-006). The scope is deliberately slack-only: non-slack
	// families keep the flag package's name-bearing errors because the
	// mysql CLI tests assert that flag-name convention — mysql argument
	// names (for_grants/--for-grants, and the undeclared --table of
	// mysql.grant_add) are module metadata echoed for usability, not
	// credentials, so suppressing them repo-wide would break pinned
	// behavior without a security gain.
	valueFree := slackTarget(fullName)
	if template == nil {
		bare := flag.NewFlagSet("state single", flag.ContinueOnError)
		bare.SetOutput(io.Discard)
		addOutputFlags(bare)
		addChannelFlags(bare)
		if !parseOrArgs(bare, argv, valueFree) {
			return nil, "", "", ExitInvalidInput
		}
		structured, err := mergeChannels(base, bare).Load()
		if err != nil {
			return nil, "", "", failf(ExitInvalidInput, "%v", err)
		}
		fun, _ := structured["fun"].(string)
		if strings.TrimSpace(fun) == "" {
			usage(os.Stderr)
			return nil, "", "", ExitInvalidInput
		}
		return nil, "", fun, ExitOK
	}

	names, err := config.ArgumentNames(template)
	if err != nil {
		return nil, "", "", failf(ExitInternal, "%v", err)
	}
	for _, name := range names {
		if globalFlagNames[name] {
			return nil, "", "", failf(ExitInternal,
				"function %s declares reserved argument name %q", fullName, name)
		}
	}

	argv = canonicalizeFlagSpelling(argv, names)
	normalized, err := config.NormalizeBoolArgs(argv, template)
	if err != nil {
		return nil, "", "", failf(ExitInvalidInput, "%v", err)
	}

	fnFS, err := config.NewFlagSet(fullName, template)
	if err != nil {
		return nil, "", "", failf(ExitInternal, "%v", err)
	}
	addOutputFlags(fnFS)
	addChannelFlags(fnFS)
	if !parseOrArgs(fnFS, normalized, valueFree) {
		return nil, "", "", ExitInvalidInput
	}
	for _, leftover := range fnFS.Args() {
		if leftover != "-" {
			if valueFree {
				// The positional text is raw caller input and must not
				// be echoed into slack diagnostics (R10.1 SEC-006).
				return nil, "", "", failf(ExitInvalidInput, "unexpected positional argument")
			}
			return nil, "", "", failf(ExitInvalidInput, "unexpected positional argument %q", leftover)
		}
	}

	explicit := ""
	short := ""
	fsOutput := ""
	fnFS.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "output":
			fsOutput = f.Value.String()
		case "o":
			short = f.Value.String()
		}
	})
	switch {
	case short != "":
		explicit = short
	case fsOutput != "":
		explicit = fsOutput
	}

	ch := mergeChannels(base, fnFS)
	if boundedQuery {
		ch.MaxBytes = runtime.MaxCommandInputBytes
	}

	structured, err := ch.Load()
	if err != nil {
		return nil, "", "", failf(ExitInvalidInput, "%v", err)
	}

	funKey := ""
	if wantFun {
		if f, ok := structured["fun"].(string); ok && f != "" {
			funKey = f
			delete(structured, "fun")
		}
	}

	argsPtr := reflect.New(reflect.TypeOf(template)).Interface()
	provided := config.ProvidedValues(fnFS)
	for name := range globalFlagNames {
		delete(provided, name)
	}
	if err := config.Decode(argsPtr, structured, provided); err != nil {
		if valueFree {
			var unknown *config.UnknownArgumentError
			if errors.As(err, &unknown) {
				// The rejected structured key is raw caller input — a
				// secret pasted as a JSON/YAML key must not reach
				// stderr — so slack targets report the fixed category
				// without the key. Non-slack families keep Salt's
				// unknown-kwarg echo (rejected key plus known list):
				// the slack-scoped suppression is the smallest change
				// that keeps every other family's diagnostics intact.
				return nil, "", "", failf(ExitInvalidInput, "unknown argument")
			}
		}
		// Remaining decoder diagnostics are value-free by contract
		// (R10.1 SEC-006): quoted argument names come from the
		// function's own template, and scalar-conversion failures
		// report the failure class without the raw caller value.
		return nil, "", "", failf(ExitInvalidInput, "%v", err)
	}
	return argsPtr, explicit, funKey, ExitOK
}

// canonicalizeFlagSpelling accepts the conventional hyphenated CLI spelling
// while retaining underscore names in structured contracts and Go fields.
func canonicalizeFlagSpelling(argv, names []string) []string {
	known := make(map[string]string, len(names))
	for _, name := range names {
		known[strings.ReplaceAll(name, "_", "-")] = name
	}
	out := append([]string(nil), argv...)
	for i, token := range out {
		if !strings.HasPrefix(token, "--") {
			continue
		}
		body := strings.TrimPrefix(token, "--")
		value := ""
		if cut := strings.IndexByte(body, '='); cut >= 0 {
			value, body = body[cut:], body[:cut]
		}
		if name, ok := known[body]; ok {
			out[i] = "--" + name + value
		}
	}
	return out
}

// mergeChannels layers function-level channel values over namespace-level
// defaults; stdin markers combine from both positions.
func mergeChannels(base config.Channels, fnFS *flag.FlagSet) config.Channels {
	fnCh := channels(fnFS)
	merged := base
	if fnCh.Config != "" {
		merged.Config = fnCh.Config
	}
	if fnCh.File != "" {
		merged.File = fnCh.File
	}
	merged.Stdin = merged.Stdin || fnCh.Stdin
	merged.Dash = merged.Dash || fnCh.Dash
	return merged
}

func addChannelFlags(fs *flag.FlagSet) {
	fs.String("config", "", "inline structured arguments (YAML or JSON object)")
	fs.String("file", "", "read structured arguments from a YAML/JSON file")
	fs.Bool("stdin", false, "read structured arguments from stdin")
}

func channels(fnFS *flag.FlagSet) config.Channels {
	ch := config.Channels{}
	if f := fnFS.Lookup("config"); f != nil {
		ch.Config = f.Value.String()
	}
	if f := fnFS.Lookup("file"); f != nil {
		ch.File = f.Value.String()
	}
	if f := fnFS.Lookup("stdin"); f != nil {
		ch.Stdin = f.Value.String() == "true"
	}
	for _, leftover := range fnFS.Args() {
		if leftover == "-" {
			ch.Dash = true
		}
	}
	return ch
}
