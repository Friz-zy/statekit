//go:build !statekit_no_metadata_do && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"net/http"
	"testing"
)

func doFixture() providerFixture {
	return providerFixture{
		provider: "do",
		happy: []cannedResponse{
			{status: http.StatusOK, body: "175501237\n"},
			{status: http.StatusOK, body: "fra1\n"},
		},
		requiredIdx:   0,
		requiredField: fieldInstanceID,
		optionalIdx:   1,
		optionalField: fieldRegion,
	}
}

func TestDOHappyPathExactRequests(t *testing.T) {
	result, err, rt := runProvider("do", nil, doFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	noHeaders := map[string]string{}
	want := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/metadata/v1/id"},
		{http.MethodGet, "/metadata/v1/region"},
	}
	if len(rt.calls) != len(want) {
		t.Fatalf("calls=%d, want %d: %+v", len(rt.calls), len(want), rt.calls)
	}
	for i, w := range want {
		assertCall(t, i, rt.calls[i], w.method, w.path, "", noHeaders)
	}
	if result.Provider != "do" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "175501237" || result.Region != "fra1" ||
		result.Zone != "" || result.InstanceType != "" || result.ImageID != "" ||
		result.Provenance != "" || result.FieldsNotCollected != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestDOFailureMatrix(t *testing.T) {
	runFailureMatrix(t, doFixture())
}
