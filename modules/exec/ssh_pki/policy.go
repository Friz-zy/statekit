package ssh_pki

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/friz-zy/statekit/internal/runtime"
	"golang.org/x/crypto/ssh"
)

const sshTimeFormat = "2006-01-02 15:04:05"

// timeStringMap mirrors salt.utils.timeutil.timestring_map. The returned
// pointer distinguishes a missing value from an explicit zero.
func timeStringMap(value any) (*float64, error) {
	if value == nil {
		return nil, nil
	}
	switch x := value.(type) {
	case int:
		f := float64(x)
		return &f, nil
	case int64:
		f := float64(x)
		return &f, nil
	case uint64:
		f := float64(x)
		return &f, nil
	case float64:
		f := x
		return &f, nil
	case string:
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return &f, nil
		}
		if len(x) < 2 {
			return nil, fmt.Errorf("Invalid time string format: %s", x)
		}
		unit := x[len(x)-1]
		if !strings.ContainsRune("smhd", rune(unit)) {
			return nil, fmt.Errorf("Invalid time string format: %s", x)
		}
		raw, err := strconv.ParseFloat(x[:len(x)-1], 64)
		if err != nil || raw < 0 {
			return nil, fmt.Errorf("Invalid time string format: %s", x)
		}
		switch unit {
		case 's':
		case 'm':
			raw *= 60
		case 'h':
			raw *= 60 * 60
		case 'd':
			raw *= 24 * 60 * 60
		}
		return &raw, nil
	default:
		return nil, fmt.Errorf("Expected integer, float or time string")
	}
}

func parseSSHTime(value any) (time.Time, error) {
	s, ok := stringValue(value)
	if !ok || s == "" {
		return time.Time{}, fmt.Errorf("invalid SSH certificate time")
	}
	return time.ParseInLocation(sshTimeFormat, s, time.UTC)
}

func formatSSHTime(t time.Time) string { return t.UTC().Format(sshTimeFormat) }

func optionalString(kwargs map[string]any, key string) string {
	if value, ok := kwargs[key]; ok {
		if s, ok := stringValue(value); ok {
			return s
		}
	}
	return ""
}

func optionalBool(kwargs map[string]any, key string) bool {
	value, ok := kwargs[key]
	return ok && boolValue(value)
}

// getSigningPolicy resolves the local pillar/config policy chain. Both
// delegates are optional in the local-only runtime; absent/malformed lookup
// values degrade to the upstream empty policy.
func getSigningPolicy(rt *runtime.Runtime, name string) map[string]any {
	if name == "" {
		return map[string]any{}
	}
	lookup := func(delegate string) map[string]any {
		if rt == nil || rt.Exec == nil {
			return nil
		}
		fn, ok := rt.Exec.Get(delegate)
		if !ok {
			return nil
		}
		res, err := fn.Execute(context.Background(), rt, map[string]any{
			"key": "ssh_signing_policies", "default": map[string]any{},
		})
		if err != nil {
			return nil
		}
		policies := asStringMap(res)
		if policies == nil {
			return nil
		}
		return asStringMap(policies[name])
	}
	if policy := lookup("pillar.get"); policy != nil && len(policy) > 0 {
		return cloneMap(policy)
	}
	if policy := lookup("config.get"); policy != nil && len(policy) > 0 {
		return cloneMap(policy)
	}
	return map[string]any{}
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out, _ := cloneAny(in).(map[string]any)
	return out
}

// mergeSigningPolicy ports sshpki.merge_signing_policy. It mutates the
// request map intentionally, just as the Python helper does.
func mergeSigningPolicy(policy, kwargs map[string]any) map[string]any {
	if len(policy) == 0 {
		return kwargs
	}
	policy = cloneMap(policy)

	forcedOpts := optionsAnyMap(policy["critical_options"])
	defaultOpts := optionsAnyMap(policy["default_critical_options"])
	allowedOpts, hasAllowedOpts := stringSliceValue(policy["allowed_critical_options"])
	if !hasAllowedOpts {
		allowedOpts = []string{"*"}
	}
	forcedExts := optionsAnyMap(policy["extensions"])
	defaultExts := optionsAnyMap(policy["default_extensions"])
	allowedExts, hasAllowedExts := stringSliceValue(policy["allowed_extensions"])
	if !hasAllowedExts {
		allowedExts = []string{"*"}
	}

	finalOpts := cloneAny(defaultOpts).(map[string]any)
	for key, value := range asStringMap(kwargs["critical_options"]) {
		if containsOrAll(allowedOpts, key) {
			finalOpts[key] = value
		}
	}
	for key, value := range forcedOpts {
		finalOpts[key] = value
	}
	if len(finalOpts) > 0 {
		kwargs["critical_options"] = finalOpts
	} else {
		kwargs["critical_options"] = nil
	}

	finalExts := cloneAny(defaultExts).(map[string]any)
	for key, value := range asStringMap(kwargs["extensions"]) {
		if containsOrAll(allowedExts, key) {
			finalExts[key] = value
		}
	}
	for key, value := range forcedExts {
		finalExts[key] = value
	}
	if len(finalExts) > 0 {
		kwargs["extensions"] = finalExts
	} else {
		kwargs["extensions"] = nil
	}

	// Python's nested pop in
	// pop("allowed_valid_principals", pop("valid_principals", None))
	// removes both control keys before the final kwargs.update(policy).
	allowedPrincipals, hasAllowedPrincipals := stringSliceValue(policy["allowed_valid_principals"])
	validPrincipals, hasValidPrincipals := stringSliceValue(policy["valid_principals"])
	delete(policy, "allowed_valid_principals")
	delete(policy, "valid_principals")
	if !hasAllowedPrincipals {
		allowedPrincipals, hasAllowedPrincipals = validPrincipals, hasValidPrincipals
	}
	defaultPrincipals, hasDefaultPrincipals := stringSliceValue(policy["default_valid_principals"])
	delete(policy, "default_valid_principals")
	if !hasDefaultPrincipals {
		defaultPrincipals = append([]string(nil), allowedPrincipals...)
	}
	if hasAllowedPrincipals {
		requested := stringSliceValueOnly(kwargs["valid_principals"])
		if len(requested) > 0 {
			kwargs["valid_principals"] = intersectStrings(allowedPrincipals, requested)
			if len(kwargs["valid_principals"].([]string)) == 0 {
				kwargs["valid_principals"] = defaultPrincipals
			}
		} else if optionalBool(kwargs, "all_principals") {
			kwargs["valid_principals"] = allowedPrincipals
			delete(kwargs, "all_principals")
		} else {
			kwargs["valid_principals"] = defaultPrincipals
		}
	}

	defaultTTL, err := timeStringMap(policy["ttl"])
	if err != nil {
		defaultTTL = nil
	}
	maxTTL, err := timeStringMap(policy["max_ttl"])
	if err != nil || maxTTL == nil {
		maxTTL = defaultTTL
	}
	requestedTTL, err := timeStringMap(kwargs["ttl"])
	if err != nil {
		requestedTTL = nil
	}

	notBefore := time.Now().UTC()
	if value, ok := kwargs["not_before"]; ok && valueTruthy(value) {
		if parsed, perr := parseSSHTime(value); perr == nil {
			notBefore = parsed
		}
		delete(kwargs, "not_before")
	}
	if value, ok := kwargs["not_after"]; ok && valueTruthy(value) {
		if parsed, perr := parseSSHTime(value); perr == nil {
			seconds := parsed.Sub(notBefore).Seconds()
			requestedTTL = &seconds
		}
		delete(kwargs, "not_after")
	}

	var allowedTTL *float64
	switch {
	case requestedTTL == nil:
		if defaultTTL != nil {
			allowedTTL = defaultTTL
		} else {
			allowedTTL = maxTTL
		}
	case maxTTL != nil && *requestedTTL > *maxTTL:
		allowedTTL = maxTTL
	default:
		allowedTTL = requestedTTL
	}
	if allowedTTL != nil {
		kwargs["not_before"] = formatSSHTime(notBefore)
		kwargs["not_after"] = formatSSHTime(notBefore.Add(time.Duration(*allowedTTL * float64(time.Second))))
		kwargs["ttl"] = *allowedTTL
	} else {
		kwargs["ttl"] = nil
	}
	delete(policy, "critical_options")
	delete(policy, "default_critical_options")
	delete(policy, "allowed_critical_options")
	delete(policy, "extensions")
	delete(policy, "default_extensions")
	delete(policy, "allowed_extensions")
	delete(policy, "ttl")
	delete(policy, "max_ttl")

	for key, value := range policy {
		kwargs[key] = value
	}
	return kwargs
}

func optionsAnyMap(value any) map[string]any {
	if value == nil || !valueTruthy(value) {
		return map[string]any{}
	}
	return asStringMap(value)
}

func containsOrAll(values []string, wanted string) bool {
	for _, value := range values {
		if value == "*" || value == wanted {
			return true
		}
	}
	return false
}

func stringSliceValue(value any) ([]string, bool) {
	if value == nil {
		return nil, false
	}
	return stringSliceValueOnly(value), true
}

func stringSliceValueOnly(value any) []string {
	switch x := value.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := stringValue(item); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}

func intersectStrings(allowed, requested []string) []string {
	set := map[string]bool{}
	for _, item := range allowed {
		set[item] = true
	}
	out := make([]string, 0, len(requested))
	for _, item := range requested {
		if set[item] {
			out = append(out, item)
		}
	}
	return out
}

// buildCertificate maps the merged Python kwargs to an OpenSSH certificate
// and its CA signer. It is shared by create_certificate and
// sign_remote_certificate.
func buildCertificate(rt *runtime.Runtime, kwargs map[string]any) (*ssh.Certificate, ssh.Signer, error) {
	certTypeName := optionalString(kwargs, "cert_type")
	var certType uint32
	var defaultTTL float64
	switch certTypeName {
	case "user":
		certType = ssh.UserCert
		defaultTTL = 86400
	case "host":
		certType = ssh.HostCert
		defaultTTL = 2592000
	default:
		return nil, nil, &invocationErr{msg: fmt.Sprintf(
			"Cert type needs to be either `user` or `host`, got '%s'", certTypeName)}
	}

	signingKey, ok := kwargs["signing_private_key"]
	if !ok || !valueTruthy(signingKey) {
		return nil, nil, &invocationErr{msg: "Creating a certificate locally at least requires a signing private key."}
	}
	signingPass := stringPointer(kwargs["signing_private_key_passphrase"])
	signer, err := loadSigner(rt, signingKey, signingPass)
	if err != nil {
		return nil, nil, err
	}

	var public ssh.PublicKey
	if privateKey, ok := kwargs["private_key"]; ok && valueTruthy(privateKey) {
		privatePass := stringPointer(kwargs["private_key_passphrase"])
		privateSigner, perr := loadSigner(rt, privateKey, privatePass)
		if perr != nil {
			return nil, nil, perr
		}
		public = privateSigner.PublicKey()
	} else if publicKey, ok := kwargs["public_key"]; ok && valueTruthy(publicKey) {
		public, err = loadPublicKey(rt, publicKey)
		if err != nil {
			return nil, nil, err
		}
		public = certPublicKey(public)
	} else {
		return nil, nil, &invocationErr{msg: "Need public_key or private_key to derive public key to sign"}
	}

	serial, err := serialNumber(kwargs["serial_number"])
	if err != nil {
		return nil, nil, err
	}
	keyID := optionalString(kwargs, "key_id")
	principals := stringSliceValueOnly(kwargs["valid_principals"])
	allPrincipals := optionalBool(kwargs, "all_principals")
	if len(principals) == 0 && !allPrincipals {
		return nil, nil, &invocationErr{msg: "Must either set all_principals to true or specify principals to allow"}
	}

	now := time.Now().UTC()
	validAfter := now.Unix()
	if value, ok := kwargs["not_before"]; ok && valueTruthy(value) {
		parsed, perr := parseSSHTime(value)
		if perr != nil {
			return nil, nil, perr
		}
		validAfter = parsed.Unix()
	}
	validBefore := int64(0)
	if value, ok := kwargs["not_after"]; ok && valueTruthy(value) {
		parsed, perr := parseSSHTime(value)
		if perr != nil {
			return nil, nil, perr
		}
		validBefore = parsed.Unix()
	} else {
		ttlValue := kwargs["ttl"]
		ttl, terr := timeStringMap(ttlValue)
		if terr != nil {
			return nil, nil, terr
		}
		if ttl == nil {
			ttl = &defaultTTL
		}
		validBefore = now.Unix() + int64(*ttl)
	}
	if validAfter < 0 || validBefore < 0 {
		return nil, nil, fmt.Errorf("SSH certificate validity must be non-negative")
	}

	criticalOptions := optionsMap(kwargs["critical_options"])
	extensions := optionsMap(kwargs["extensions"])
	cert := &ssh.Certificate{
		Serial:          serial,
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter),
		ValidBefore:     uint64(validBefore),
		Key:             public,
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}
	if allPrincipals && len(principals) == 0 {
		cert.ValidPrincipals = nil
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, err
	}
	return cert, signer, nil
}

func stringPointer(value any) *string {
	if value == nil {
		return nil
	}
	if s, ok := stringValue(value); ok {
		return &s
	}
	return nil
}
