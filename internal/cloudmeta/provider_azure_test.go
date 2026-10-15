//go:build !statekit_no_metadata_azure && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"errors"
	"net/http"
	"testing"
)

const azureTestQuery = "api-version=2025-04-07&format=text"

func azureFixture() providerFixture {
	return providerFixture{
		provider: "azure",
		happy: []cannedResponse{
			{status: http.StatusOK, body: "33abcd12-90bf-4d8e-a1de-1234567890ab\n"},
			{status: http.StatusOK, body: "westeurope\n"},
			{status: http.StatusOK, body: "2\n"},
			{status: http.StatusOK, body: "Standard_D2s_v5\n"},
		},
		requiredIdx:   0,
		requiredField: fieldInstanceID,
		optionalIdx:   3,
		optionalField: fieldInstanceType,
	}
}

func TestAzureHappyPathExactRequests(t *testing.T) {
	result, err, rt := runProvider("azure", nil, azureFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	metadataHeader := map[string]string{"Metadata": "true"}
	want := []struct {
		method string
		path   string
		query  string
	}{
		{http.MethodGet, "/metadata/instance/compute/vmId", azureTestQuery},
		{http.MethodGet, "/metadata/instance/compute/location", azureTestQuery},
		{http.MethodGet, "/metadata/instance/compute/zone", azureTestQuery},
		{http.MethodGet, "/metadata/instance/compute/vmSize", azureTestQuery},
	}
	if len(rt.calls) != len(want) {
		t.Fatalf("calls=%d, want %d: %+v", len(rt.calls), len(want), rt.calls)
	}
	for i, w := range want {
		assertCall(t, i, rt.calls[i], w.method, w.path, w.query, metadataHeader)
	}
	if result.Provider != "azure" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "33abcd12-90bf-4d8e-a1de-1234567890ab" ||
		result.Region != "westeurope" || result.Zone != "2" ||
		result.InstanceType != "Standard_D2s_v5" || result.ImageID != "" ||
		result.Provenance != "" || result.FieldsNotCollected != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestAzureVMIDShapeEnforced(t *testing.T) {
	for _, vmID := range []string{"not-a-guid\n", "33abcd12-90bf-4d8e-a1de\n", "33abcd12-90bf-4d8e-a1de-1234567890zz\n"} {
		responses := withMutation(azureFixture().happy, 0, func(r *cannedResponse) { r.body = vmID })
		result, err, rt := runProvider("azure", nil, responses...)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("vmId %q: err=%v, want %v", vmID, err, ErrMalformed)
		}
		if result != nil {
			t.Fatalf("vmId %q: result=%+v, want nil", vmID, result)
		}
		if len(rt.calls) != 1 {
			t.Fatalf("vmId %q: calls=%d, want 1", vmID, len(rt.calls))
		}
	}
}

func TestAzureFailureMatrix(t *testing.T) {
	runFailureMatrix(t, azureFixture())
}
