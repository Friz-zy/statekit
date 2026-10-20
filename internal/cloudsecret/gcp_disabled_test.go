//go:build statekit_no_sdk_gcp || statekit_no_sdks

package cloudsecret

import (
	"context"
	"testing"
)

func TestGCPDisabledBuildFailsClosedBeforeCredentialLookup(t *testing.T) {
	if GCPAvailable() {
		t.Fatal("GCP SDK was reported available in a disabled build")
	}
	source := Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db"}
	if payload, err := FetchGCP(context.Background(), source); err != ErrUnsupported || payload != nil {
		t.Fatal("disabled GCP adapter did not fail closed without payload")
	}
}
