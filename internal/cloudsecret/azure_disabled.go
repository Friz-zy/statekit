//go:build statekit_no_sdk_azure || statekit_no_sdks

package cloudsecret

import "context"

// AzureAvailable reports whether the Azure SDK adapters were compiled in.
func AzureAvailable() bool { return false }

// FetchAzureKeyVault validates the typed request but never acquires a
// credential or opens a connection: disabled builds fail closed first.
func FetchAzureKeyVault(_ context.Context, source Source) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

// FetchAzureAppConfiguration remains inert when Azure or all SDKs are
// disabled at build time.
func FetchAzureAppConfiguration(_ context.Context, source Source) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
