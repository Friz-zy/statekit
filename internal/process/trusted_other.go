//go:build !unix

package process

// resolveTrustedDig fails closed on platforms without the unix ownership
// metadata the trust check requires; resolution never falls back to PATH.
func resolveTrustedDig() (string, error) {
	return "", ErrTrustedCommandUnsupported
}

// resolveTrustedUsermod fails closed where unix ownership metadata is
// unavailable; the caller additionally restricts this helper to Linux.
func resolveTrustedUsermod() (string, error) {
	return "", ErrTrustedCommandUnsupported
}
