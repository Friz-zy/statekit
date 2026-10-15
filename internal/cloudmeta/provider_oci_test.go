//go:build !statekit_no_metadata_oci && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"net/http"
	"testing"
)

// ociForbiddenTripwires pin the tenancy-prefixed AD leaf as never
// requested; the contract uses ociAdName.
var ociForbiddenTripwires = map[string]bool{
	"/opc/v2/instance/availabilityDomain": true,
}

func ociFixture() providerFixture {
	return providerFixture{
		provider: "oci",
		happy: []cannedResponse{
			{status: http.StatusOK, body: "ocid1.instance.oc1..exampleinstance\n"},
			{status: http.StatusOK, body: "eu-frankfurt-1\n"},
			{status: http.StatusOK, body: "EU-FRANKFURT-1-AD-1\n"},
			{status: http.StatusOK, body: "VM.Standard.A1.Flex\n"},
			{status: http.StatusOK, body: "ocid1.image.oc1..exampleimage\n"},
		},
		requiredIdx:   0,
		requiredField: fieldInstanceID,
		optionalIdx:   4,
		optionalField: fieldImageID,
	}
}

func TestOCIHappyPathExactRequests(t *testing.T) {
	result, err, rt := runProvider("oci", ociForbiddenTripwires, ociFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	oracleHeader := map[string]string{"Authorization": "Bearer Oracle"}
	want := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/opc/v2/instance/id"},
		{http.MethodGet, "/opc/v2/instance/canonicalRegionName"},
		{http.MethodGet, "/opc/v2/instance/ociAdName"},
		{http.MethodGet, "/opc/v2/instance/shape"},
		{http.MethodGet, "/opc/v2/instance/image"},
	}
	if len(rt.calls) != len(want) {
		t.Fatalf("calls=%d, want %d: %+v", len(rt.calls), len(want), rt.calls)
	}
	for i, w := range want {
		assertCall(t, i, rt.calls[i], w.method, w.path, "", oracleHeader)
	}
	if rt.violation != "" {
		t.Fatalf("forbidden tripwire fired: %s", rt.violation)
	}
	if result.Provider != "oci" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "ocid1.instance.oc1..exampleinstance" ||
		result.Region != "eu-frankfurt-1" || result.Zone != "EU-FRANKFURT-1-AD-1" ||
		result.InstanceType != "VM.Standard.A1.Flex" ||
		result.ImageID != "ocid1.image.oc1..exampleimage" ||
		result.Provenance != "ociAdName" || result.FieldsNotCollected != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestOCIFailureMatrix(t *testing.T) {
	runFailureMatrix(t, ociFixture())
}
