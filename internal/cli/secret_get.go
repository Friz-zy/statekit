package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/friz-zy/statekit/internal/cloudsecret"
)

const maxSecretRequestBytes = cloudsecret.MaxPayloadBytes

type secretFetchFunc func(context.Context, cloudsecret.Source) ([]byte, error)

type secretRequest struct {
	source    cloudsecret.Source
	format    cloudsecret.Format
	keyPath   string
	sink      string
	target    string
	targetSet bool
}

type parsedSecretArgs struct {
	values       map[string]string
	present      map[string]bool
	sink         string
	sinkExplicit bool
}

func (a *App) cmdCloudSecretGet(argv []string) (code int) {
	return a.cmdSensitiveGet(argv, false)
}

func (a *App) cmdCloudParameterGet(argv []string) int {
	return a.cmdSensitiveGet(argv, true)
}

func (a *App) cmdSensitiveGet(argv []string, parameter bool) (code int) {
	sink := secretSinkHint(argv)
	defer func() {
		if recover() != nil {
			code = ExitFailed
			if sink != "stderr" {
				_, _ = io.WriteString(os.Stderr, "statekit: secret operation failed\n")
			}
		}
	}()

	parsed, err := parseSecretArgs(argv, os.Stdin)
	if err == nil || parsed.sinkExplicit {
		sink = parsed.sink
	}
	if err != nil {
		return secretFailure(err, sink)
	}
	request, err := makeSensitiveRequest(parsed, parameter)
	if err != nil {
		return secretFailure(err, sink)
	}
	sink = request.sink
	if request.sink == "file" {
		return secretFailure(cloudsecret.ErrDeferredFile, sink)
	}
	if request.source.Provider == "aws" && !cloudsecret.AWSAvailable() || request.source.Provider == "gcp" && !cloudsecret.GCPAvailable() {
		return secretFailure(cloudsecret.ErrUnsupported, sink)
	}
	switch request.sink {
	case "stdout":
		if err := preflightOutputStream(os.Stdout); err != nil {
			return secretFailure(err, sink)
		}
	case "stderr":
		if err := preflightOutputStream(os.Stderr); err != nil {
			return secretFailure(err, sink)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var unix io.WriteCloser
	if request.sink == "unix" {
		dialContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		unix, err = cloudsecret.OpenUnixSink(dialContext, request.target)
		cancel()
		if err != nil {
			return secretFailure(err, sink)
		}
		defer func() {
			if unix != nil {
				_ = unix.Close()
			}
		}()
	}

	fetch := a.secretFetch
	if parameter {
		fetch = a.parameterFetch
	}
	if fetch == nil {
		if parameter {
			fetch = cloudsecret.FetchGCPParameter
		} else {
			switch request.source.Provider {
			case "aws":
				fetch = cloudsecret.FetchAWS
			case "gcp":
				fetch = cloudsecret.FetchGCP
			default:
				return secretFailure(cloudsecret.ErrUnsupported, sink)
			}
		}
	}
	payload, err := fetch(ctx, request.source)
	if err != nil {
		return secretFailure(err, sink)
	}
	formatted, err := cloudsecret.FormatPayload(payload, request.format, request.keyPath)
	if err != nil {
		return secretFailure(err, sink)
	}

	var writer io.Writer
	if unix != nil {
		if deadlineWriter, ok := unix.(interface{ SetWriteDeadline(time.Time) error }); ok {
			if err := deadlineWriter.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return secretFailure(cloudsecret.ErrSink, sink)
			}
		}
		connection := unix
		unix = nil
		if err := cloudsecret.WriteFrameAndClose(connection, formatted); err != nil {
			return secretFailure(err, sink)
		}
		return ExitOK
	}
	if request.sink == "stderr" {
		writer = os.Stderr
	} else {
		writer = os.Stdout
	}
	if err := cloudsecret.WritePayload(writer, formatted); err != nil {
		return secretFailure(err, sink)
	}
	return ExitOK
}

func parseSecretArgs(argv []string, stdin io.Reader) (parsedSecretArgs, error) {
	parsed := parsedSecretArgs{values: make(map[string]string), present: make(map[string]bool), sink: "stdout"}
	channel := ""
	channelValue := ""
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "-" {
			if channel != "" {
				return parsed, cloudsecret.ErrInvalidSource
			}
			channel, channelValue = "stdin", ""
			continue
		}
		if arg == "--stdin" {
			if channel != "" {
				return parsed, cloudsecret.ErrInvalidSource
			}
			channel, channelValue = "stdin", ""
			continue
		}

		name, value, hasInline, ok := secretFlag(arg)
		if !ok || name == "output" {
			return parsed, cloudsecret.ErrInvalidSource
		}
		if name == "config" || name == "file" {
			if channel != "" {
				return parsed, cloudsecret.ErrInvalidSource
			}
			if !hasInline {
				if i+1 >= len(argv) {
					return parsed, cloudsecret.ErrInvalidSource
				}
				i++
				value = argv[i]
			}
			channel, channelValue = name, value
			continue
		}
		if !hasInline {
			if i+1 >= len(argv) {
				return parsed, cloudsecret.ErrInvalidSource
			}
			i++
			value = argv[i]
		}
		if parsed.present[name] {
			return parsed, cloudsecret.ErrInvalidSource
		}
		parsed.present[name] = true
		parsed.values[name] = value
		if name == "sink" {
			parsed.sink = value
			parsed.sinkExplicit = true
		}
	}

	if channel != "" {
		var data []byte
		var err error
		switch channel {
		case "config":
			if len(channelValue) > maxSecretRequestBytes {
				return parsed, cloudsecret.ErrInvalidSource
			}
			data = []byte(channelValue)
		case "file":
			data, err = readSecretRequestFile(channelValue)
		case "stdin":
			data, err = readSecretRequest(stdin)
		}
		if err != nil {
			return parsed, cloudsecret.ErrInvalidSource
		}
		if structuredRequestsStderrSink(data) {
			parsed.sink = "stderr"
			parsed.sinkExplicit = true
		}
		fields, err := cloudsecret.ParseStructuredRequest(data)
		if err != nil {
			return parsed, cloudsecret.ErrInvalidSource
		}
		if fields["sink"] == "stderr" {
			parsed.sink = "stderr"
			parsed.sinkExplicit = true
		}
		for name, value := range fields {
			if parsed.present[name] {
				return parsed, cloudsecret.ErrInvalidSource
			}
			parsed.present[name] = true
			parsed.values[name] = value
			if name == "sink" {
				parsed.sink = value
				parsed.sinkExplicit = true
			}
		}
	}
	return parsed, nil
}

func secretFlag(arg string) (name, value string, inline, ok bool) {
	// Generic output aliases remain distinct from the secret-specific --format.
	if arg == "-o" {
		return "output", "", false, true
	}
	if strings.HasPrefix(arg, "-o=") {
		return "output", strings.TrimPrefix(arg, "-o="), true, true
	}
	if !strings.HasPrefix(arg, "--") {
		return "", "", false, false
	}
	key, value, inline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	switch key {
	case "source-uri", "provider", "backend", "region", "resource", "version-id", "version-alias", "format", "output", "key-path", "sink", "target", "config", "file":
	default:
		return "", "", false, false
	}
	name = strings.ReplaceAll(key, "-", "_")
	return name, value, inline, true
}

func readSecretRequestFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, cloudsecret.ErrInvalidSource
	}
	defer file.Close()
	return readSecretRequest(file)
}

func readSecretRequest(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxSecretRequestBytes+1))
	if err != nil || len(data) > maxSecretRequestBytes {
		return nil, cloudsecret.ErrInvalidSource
	}
	return data, nil
}

func makeSecretRequest(parsed parsedSecretArgs) (secretRequest, error) {
	return makeSensitiveRequest(parsed, false)
}

func makeSensitiveRequest(parsed parsedSecretArgs, parameter bool) (secretRequest, error) {
	parseURI, validate := cloudsecret.ParseSourceURI, cloudsecret.ValidateSource
	if parameter {
		parseURI, validate = cloudsecret.ParseParameterSourceURI, cloudsecret.ValidateParameterSource
	}
	values := parsed.values
	uriPresent := parsed.present["source_uri"]
	structuredSourceCount := 0
	for _, name := range []string{"provider", "backend", "region", "resource"} {
		if parsed.present[name] {
			structuredSourceCount++
		}
	}
	if uriPresent && structuredSourceCount != 0 || !uriPresent && structuredSourceCount != 4 {
		return secretRequest{}, cloudsecret.ErrInvalidSource
	}

	var source cloudsecret.Source
	var err error
	if uriPresent {
		source, err = parseURI(values["source_uri"])
		if err != nil {
			return secretRequest{}, err
		}
	} else {
		source = cloudsecret.Source{
			Provider: values["provider"], Backend: values["backend"],
			Region: values["region"], Resource: values["resource"],
		}
	}
	if parsed.present["version_id"] {
		if values["version_id"] == "" {
			return secretRequest{}, cloudsecret.ErrInvalidSource
		}
		source.VersionID = values["version_id"]
	}
	if parsed.present["version_alias"] {
		if values["version_alias"] == "" {
			return secretRequest{}, cloudsecret.ErrInvalidSource
		}
		source.VersionAlias = values["version_alias"]
	}
	if err := validate(source); err != nil {
		return secretRequest{}, err
	}

	format := cloudsecret.FormatRaw
	if parsed.present["format"] {
		switch values["format"] {
		case "raw":
			format = cloudsecret.FormatRaw
		case "text":
			format = cloudsecret.FormatText
		case "json":
			format = cloudsecret.FormatJSON
		case "yaml":
			format = cloudsecret.FormatYAML
		default:
			return secretRequest{}, cloudsecret.ErrInvalidRequest
		}
	}
	if parsed.present["key_path"] && format != cloudsecret.FormatJSON && format != cloudsecret.FormatYAML {
		return secretRequest{}, cloudsecret.ErrInvalidRequest
	}
	if parsed.present["key_path"] {
		if err := cloudsecret.ValidateKeyPath(values["key_path"]); err != nil {
			return secretRequest{}, err
		}
	}
	sink := parsed.sink
	if parsed.present["sink"] {
		sink = values["sink"]
	}
	if sink == "" {
		return secretRequest{}, cloudsecret.ErrUnsupported
	}
	request := secretRequest{
		source: source, format: format, keyPath: values["key_path"],
		sink:   sink,
		target: values["target"], targetSet: parsed.present["target"],
	}
	switch sink {
	case "stdout", "stderr":
		if request.targetSet {
			return secretRequest{}, cloudsecret.ErrInvalidSource
		}
	case "file":
		return request, cloudsecret.ErrDeferredFile
	case "unix":
		if !request.targetSet || request.target == "" {
			return secretRequest{}, cloudsecret.ErrInvalidSource
		}
		if !filepath.IsAbs(request.target) || filepath.Clean(request.target) != request.target || strings.ContainsRune(request.target, 0) {
			return secretRequest{}, cloudsecret.ErrInvalidSource
		}
	default:
		return secretRequest{}, cloudsecret.ErrUnsupported
	}
	return request, nil
}

func secretFailure(err error, sink string) int {
	code := ExitFailed
	message := "secret operation failed"
	switch {
	case errors.Is(err, cloudsecret.ErrInvalidSource), errors.Is(err, cloudsecret.ErrInvalidRequest):
		code, message = ExitInvalidInput, "invalid secret request"
	case errors.Is(err, cloudsecret.ErrDeferredFile):
		code, message = ExitUnsupported, "file sink deferred by policy"
	case errors.Is(err, cloudsecret.ErrUnsupported):
		code, message = ExitUnsupported, "unsupported secret provider, service, or sink"
	case errors.Is(err, cloudsecret.ErrCredentials):
		code, message = ExitFailed, "secret credentials unavailable"
	case errors.Is(err, cloudsecret.ErrProvider):
		code, message = ExitFailed, "secret provider read failed"
	case errors.Is(err, cloudsecret.ErrInvalidPayload):
		code, message = ExitFailed, "secret payload validation failed"
	case errors.Is(err, cloudsecret.ErrDeliveryUncertain):
		code, message = ExitFailed, "secret delivery outcome uncertain"
	case errors.Is(err, cloudsecret.ErrSink):
		code, message = ExitFailed, "secret sink failed"
	}
	if sink != "stderr" {
		_, _ = fmt.Fprintf(os.Stderr, "statekit: %s\n", message)
	}
	return code
}

func secretSinkHint(argv []string) string {
	sink := "stdout"
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if strings.HasPrefix(arg, "--sink=") {
			sink = strings.TrimPrefix(arg, "--sink=")
			continue
		}
		if arg == "--sink" && i+1 < len(argv) {
			i++
			sink = argv[i]
		}
	}
	return sink
}

func structuredRequestsStderrSink(data []byte) bool {
	text := string(data)
	if strings.Contains(text, "sink: stderr") {
		return true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "sink" {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if value == "stderr" || value == `"stderr"` || value == `'stderr'` {
			return true
		}
	}
	for offset := 0; offset < len(text); {
		index := strings.Index(text[offset:], `"sink"`)
		if index < 0 {
			break
		}
		offset += index + len(`"sink"`)
		rest := strings.TrimLeft(text[offset:], " \t\r\n")
		if !strings.HasPrefix(rest, ":") {
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
		if strings.HasPrefix(rest, `"stderr"`) {
			return true
		}
	}
	return false
}

func secretInvocationArgs(argv []string) ([]string, bool) {
	if len(argv) < 2 || argv[0] != "exec" {
		return nil, false
	}
	if args, ok := extractSecretGetArgs(argv[1:]); ok {
		return args, true
	}
	return extractSensitiveGetArgs(argv[1:], "cloud.param.get")
}

func extractSecretGetArgs(argv []string) ([]string, bool) {
	return extractSensitiveGetArgs(argv, "cloud.secret.get")
}

func extractSensitiveGetArgs(argv []string, command string) ([]string, bool) {
	var prefix []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == command {
			return append(prefix, argv[i+1:]...), true
		}
		if arg == "--stdin" || arg == "-" {
			prefix = append(prefix, arg)
			continue
		}
		name, _, inline, ok := secretFlag(arg)
		if !ok || name != "format" && name != "output" && name != "config" && name != "file" {
			return nil, false
		}
		prefix = append(prefix, arg)
		if !inline {
			if i+1 >= len(argv) {
				return nil, false
			}
			i++
			prefix = append(prefix, argv[i])
		}
	}
	return nil, false
}
