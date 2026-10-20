// Package cloudsecret implements the bounded, sensitive-value path used by
// the dedicated cloud.secret.get CLI command. Its errors are closed sentinels
// so source data and provider diagnostics never become error text.
package cloudsecret

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidSource      = errors.New("cloudsecret: invalid source")
	ErrUnsupported        = errors.New("cloudsecret: unsupported operation")
	ErrCredentials        = errors.New("cloudsecret: credentials unavailable")
	ErrProvider           = errors.New("cloudsecret: provider read failed")
	ErrInvalidRequest     = errors.New("cloudsecret: invalid request")
	ErrInvalidPayload     = errors.New("cloudsecret: invalid payload")
	ErrSink               = errors.New("cloudsecret: sink failed")
	ErrDeliveryUncertain  = errors.New("cloudsecret: delivery outcome uncertain")
	ErrDeferredFile       = errors.New("cloudsecret: file sink deferred by policy")
	errCredentialExpired  = errors.New("cloudsecret: credentials expired")
	errResponseTooLarge   = errors.New("cloudsecret: provider response limit exceeded")
	errUnexpectedEncoding = errors.New("cloudsecret: unexpected content encoding")
)

const (
	MaxPayloadBytes = 1 << 20
	MaxDepth        = 64
	MaxNodes        = 10_000
	MaxScalarBytes  = 256 << 10
	maxSourceBytes  = 4096
)

// Source selects one exact provider service resource. VersionID and
// VersionAlias are mutually exclusive and have backend-specific meanings.
type Source struct {
	Provider     string
	Backend      string
	Region       string
	Resource     string
	VersionID    string
	VersionAlias string
}

// Format selects the explicit byte transformation applied before delivery.
type Format string

const (
	FormatRaw  Format = "raw"
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// ParseSourceURI accepts only the canonical secret://provider/backend/region/resource
// form. The resource is one raw path segment; percent escapes are decoded once.
func ParseSourceURI(value string) (Source, error) {
	return parseSourceURI(value, "secret://", ValidateSource)
}

func parseSourceURI(value, scheme string, validate func(Source) error) (Source, error) {
	if len(value) == 0 || len(value) > maxSourceBytes || !strings.HasPrefix(value, scheme) || strings.ContainsAny(value, "?#") {
		return Source{}, ErrInvalidSource
	}
	parts := strings.Split(strings.TrimPrefix(value, scheme), "/")
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return Source{}, ErrInvalidSource
	}
	if strings.ContainsAny(parts[0], ":@%[]") || !validToken(parts[0]) || !validToken(parts[1]) || !validToken(parts[2]) {
		return Source{}, ErrInvalidSource
	}
	if !canonicalEscapes(parts[3]) {
		return Source{}, ErrInvalidSource
	}
	resource, err := url.PathUnescape(parts[3])
	if err != nil || !utf8.ValidString(resource) || strings.ContainsAny(resource, "%?#\\\x00\r\n") {
		return Source{}, ErrInvalidSource
	}
	source := Source{Provider: parts[0], Backend: parts[1], Region: parts[2], Resource: resource}
	if err := validate(source); err != nil {
		return Source{}, err
	}
	return source, nil
}

// ParseStructuredRequest parses the command's structured YAML or JSON fields.
// Duplicate keys, unknown names, and non-string values are rejected.
func ParseStructuredRequest(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > MaxPayloadBytes {
		return nil, ErrInvalidSource
	}
	value, err := parseJSON(data)
	if err != nil {
		value, err = parseYAML(data)
	}
	if err != nil {
		return nil, ErrInvalidSource
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalidSource
	}
	allowed := map[string]bool{
		"source_uri": true, "provider": true, "backend": true, "region": true, "resource": true,
		"version_id": true, "version_alias": true, "format": true, "key_path": true,
		"sink": true, "target": true,
	}
	result := make(map[string]string, len(fields))
	for name, raw := range fields {
		if !allowed[name] {
			return nil, ErrInvalidSource
		}
		text, ok := raw.(string)
		if !ok {
			return nil, ErrInvalidSource
		}
		result[name] = text
	}
	return result, nil
}

// ValidateSource enforces the provider-specific service contract.
func ValidateSource(source Source) error {
	if !validToken(source.Provider) || !validToken(source.Backend) || !validToken(source.Region) || !validResource(source.Resource) {
		return ErrInvalidSource
	}
	switch source.Provider {
	case "gcp":
		// This slice deliberately supports global resources only. Regional
		// Secret Manager needs a separately reviewed endpoint and identity scope.
		if source.Backend != "secretmanager" {
			return ErrUnsupported
		}
		if source.Region != "global" || isGCPRegionalSecretParent(source.Resource) {
			return ErrUnsupported
		}
		if !validGCPSecretParent(source.Resource) {
			return ErrInvalidSource
		}
		if source.VersionID != "" && source.VersionAlias != "" || !validVersionSelector(source.VersionID) || !validVersionSelector(source.VersionAlias) {
			return ErrInvalidSource
		}
		if source.VersionID != "" && !validGCPVersionID(source.VersionID) || source.VersionAlias != "" && !validGCPVersionAlias(source.VersionAlias) {
			return ErrInvalidSource
		}
		return nil
	case "aws":
	default:
		return ErrUnsupported
	}
	if source.Backend != "secretsmanager" && source.Backend != "ssm" {
		return ErrUnsupported
	}
	if !validRegion(source.Region) {
		return ErrInvalidSource
	}
	if source.VersionID != "" && source.VersionAlias != "" {
		return ErrInvalidSource
	}
	if !validVersionSelector(source.VersionID) || !validVersionSelector(source.VersionAlias) {
		return ErrInvalidSource
	}
	if source.VersionID != "" && len(source.VersionID) > 64 {
		return ErrInvalidSource
	}
	if source.Backend == "secretsmanager" && source.VersionID != "" && len(source.VersionID) < 32 {
		return ErrInvalidSource
	}
	if source.Backend == "ssm" {
		if source.VersionAlias != "" || (source.VersionID != "" && !validSSMVersion(source.VersionID)) || (!isARN(source.Resource) && strings.Contains(source.Resource, ":")) {
			return ErrInvalidSource
		}
		if source.VersionID != "" && len(source.Resource)+1+len(source.VersionID) > 2048 {
			return ErrInvalidSource
		}
	}
	if source.Backend == "secretsmanager" && !isARN(source.Resource) && strings.Contains(source.Resource, ":") {
		return ErrInvalidSource
	}
	if isARN(source.Resource) && !validResourceARN(source) {
		return ErrInvalidSource
	}
	return nil
}

func isGCPRegionalSecretParent(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 6 && parts[0] == "projects" && parts[2] == "locations" && parts[4] == "secrets"
}

func validGCPSecretParent(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "secrets" || !validGCPProject(parts[1]) {
		return false
	}
	secret := parts[3]
	if len(secret) == 0 || len(secret) > 255 {
		return false
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validGCPProject(value string) bool {
	numeric := true
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			numeric = false
			break
		}
	}
	if numeric {
		return len(value) >= 6 && len(value) <= 20
	}
	if len(value) < 6 || len(value) > 30 {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return value[len(value)-1] != '-'
}

func validGCPVersionID(value string) bool {
	if value == "" || len(value) > 19 || value[0] == '0' {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n > 0
}

func validGCPVersionAlias(value string) bool {
	return value == "latest"
}

func canonicalEscapes(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isUpperHex(value[i+1]) || !isUpperHex(value[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func isUpperHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'F'
}

func validToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
		if i == 0 && !(c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

func validRegion(value string) bool {
	if len(value) < 7 || len(value) > 32 {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	lastDash := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '-' {
			if i == 0 || i == len(value)-1 || lastDash {
				return false
			}
			lastDash = true
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
		lastDash = false
	}
	if value[len(value)-1] < '0' || value[len(value)-1] > '9' {
		return false
	}
	return true
}

func validResource(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.ContainsAny(value, "%?#\\\x00\r\n\t ") {
		return false
	}
	for _, r := range value {
		if r > 0x7e || r < 0x21 {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.+/=,@:", r)) {
			return false
		}
	}
	return true
}

func validVersionSelector(value string) bool {
	if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return false
	}
	return true
}

func validSSMVersion(value string) bool {
	if value == "" || len(value) > 19 || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n > 0
}

func isARN(value string) bool { return strings.HasPrefix(value, "arn:") }

func validResourceARN(source Source) bool {
	parts := strings.SplitN(source.Resource, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return false
	}
	partition := parts[1]
	if partition != "aws" && partition != "aws-cn" && partition != "aws-us-gov" && partition != "aws-iso" && partition != "aws-iso-b" {
		return false
	}
	if partition != regionPartition(source.Region) {
		return false
	}
	if parts[2] != source.Backend || parts[3] != source.Region || len(parts[4]) != 12 {
		return false
	}
	for i := 0; i < len(parts[4]); i++ {
		if parts[4][i] < '0' || parts[4][i] > '9' {
			return false
		}
	}
	switch source.Backend {
	case "secretsmanager":
		if !strings.HasPrefix(parts[5], "secret:") || strings.Contains(strings.TrimPrefix(parts[5], "secret:"), ":") {
			return false
		}
		name := strings.TrimPrefix(parts[5], "secret:")
		separator := strings.LastIndexByte(name, '-')
		if separator <= 0 || len(name)-separator-1 != 6 {
			return false
		}
		for i := separator + 1; i < len(name); i++ {
			c := name[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return false
			}
		}
		return true
	case "ssm":
		return strings.HasPrefix(parts[5], "parameter/") && len(parts[5]) > len("parameter/") && !strings.Contains(parts[5], ":")
	default:
		return false
	}
}

func regionPartition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	default:
		return "aws"
	}
}
