package cloudmeta

import "errors"

// Closed-set, value-free error codes. Every error returned by this package
// is one of these sentinels (or wraps one with identical text): response
// status, body bytes, header values, url.Error text, and parsed values
// must never appear in an error string. Identity is asserted with
// errors.Is.
var (
	ErrUnreachable      = errors.New("cloud_meta_unreachable")
	ErrDeadline         = errors.New("cloud_meta_deadline")
	ErrProtocol         = errors.New("cloud_meta_protocol")
	ErrRedirect         = errors.New("cloud_meta_redirect")
	ErrEncoding         = errors.New("cloud_meta_encoding")
	ErrOversize         = errors.New("cloud_meta_oversize")
	ErrMalformed        = errors.New("cloud_meta_malformed")
	ErrForbiddenPath    = errors.New("cloud_meta_forbidden_path")
	ErrDeferredProvider = errors.New("cloud_meta_deferred_provider")
	ErrBuildDisabled    = errors.New("cloud_meta_build_disabled")
	ErrInvalidProvider  = errors.New("cloud_meta_invalid_provider")
	// ErrInternal is the fixed fallback code for a non-sentinel error at
	// the CLI boundary: raw error text must never reach stderr.
	ErrInternal = errors.New("cloud_meta_internal")
)
