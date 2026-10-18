//go:build statekit_no_sdk_aws || statekit_no_sdks

package cloudsecret

import (
	"context"
	"errors"
	"testing"
)

func TestAWSAdapterUnavailableWhenOptedOutAtBuildTime(t *testing.T) {
	if AWSAvailable() {
		t.Fatal("AWS SDK adapter must be absent when its opt-out tag is set")
	}
	source := Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: "synthetic"}
	payload, err := FetchAWS(context.Background(), source)
	if !errors.Is(err, ErrUnsupported) || payload != nil {
		t.Fatal("disabled AWS adapter did not fail closed without returning a payload")
	}
}
