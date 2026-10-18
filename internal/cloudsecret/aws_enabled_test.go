//go:build !statekit_no_sdk_aws && !statekit_no_sdks

package cloudsecret

import "testing"

func TestAWSAdapterAvailableInDefaultBuild(t *testing.T) {
	if !AWSAvailable() {
		t.Fatal("AWS SDK adapter should be enabled without opt-out build tags")
	}
}
