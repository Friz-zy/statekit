//go:build !unix

package process

// resolveTrustedDig fails closed on platforms without the unix ownership
// metadata the trust check requires; resolution never falls back to PATH.
func resolveTrustedDig() (string, error) {
	return "", ErrTrustedCommandUnsupported
}
