//go:build statekit_no_sdk_gcp || statekit_no_sdks

package cloudsecret

import (
	"context"
	"testing"
)

func TestParameterDisabled(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config"}
	if GCPAvailable() {
		t.Fatal("GCP available in disabled profile")
	}
	data, err := FetchGCPParameter(context.Background(), s)
	if data != nil || err != ErrUnsupported {
		t.Fatal("disabled parameter fetch did not fail closed")
	}
}
