//go:build statekit_no_sdk_aws || statekit_no_sdks

package cloudsecret

import "context"

// AWSAvailable reports whether the AWS SDK adapter was compiled in.
func AWSAvailable() bool { return false }

// FetchAWS keeps the SDK-free provider interface available while failing closed.
func FetchAWS(_ context.Context, source Source) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
