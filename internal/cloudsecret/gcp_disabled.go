//go:build statekit_no_sdk_gcp || statekit_no_sdks

package cloudsecret

import "context"

// GCPAvailable reports whether the GCP Secret Manager adapter was compiled in.
func GCPAvailable() bool { return false }

// FetchGCPParameter remains inert when either GCP or all SDKs are disabled.
func FetchGCPParameter(_ context.Context, source Source) ([]byte, error) {
	if err := ValidateParameterSource(source); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

// FetchGCP preserves the provider interface while remaining inert in disabled builds.
func FetchGCP(_ context.Context, source Source) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
