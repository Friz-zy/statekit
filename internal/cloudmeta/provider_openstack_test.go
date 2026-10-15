//go:build !statekit_no_metadata_openstack && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"net/http"
	"testing"
)

// openstackForbiddenTripwires pin the bulk meta_data.json documents as
// never requested.
var openstackForbiddenTripwires = map[string]bool{
	"/openstack/latest/meta_data.json": true,
	"/latest/meta_data.json":           true,
}

func openstackFixture() providerFixture {
	return providerFixture{
		provider: "openstack",
		happy: []cannedResponse{
			{status: http.StatusOK, body: "i-0000abcd\n"},
			{status: http.StatusOK, body: "nova\n"},
			{status: http.StatusOK, body: "m1.small\n"},
			{status: http.StatusOK, body: "ami-00000042\n"},
		},
		requiredIdx:   0,
		requiredField: fieldInstanceID,
		optionalIdx:   3,
		optionalField: fieldImageID,
	}
}

func TestOpenStackHappyPathExactRequests(t *testing.T) {
	result, err, rt := runProvider("openstack", openstackForbiddenTripwires, openstackFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	noHeaders := map[string]string{}
	want := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/2009-04-04/meta-data/instance-id"},
		{http.MethodGet, "/2009-04-04/meta-data/placement/availability-zone"},
		{http.MethodGet, "/2009-04-04/meta-data/instance-type"},
		{http.MethodGet, "/2009-04-04/meta-data/ami-id"},
	}
	if len(rt.calls) != len(want) {
		t.Fatalf("calls=%d, want %d: %+v", len(rt.calls), len(want), rt.calls)
	}
	for i, w := range want {
		assertCall(t, i, rt.calls[i], w.method, w.path, "", noHeaders)
	}
	if rt.violation != "" {
		t.Fatalf("forbidden tripwire fired: %s", rt.violation)
	}
	if result.Provider != "openstack" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "i-0000abcd" || result.Zone != "nova" ||
		result.InstanceType != "m1.small" || result.ImageID != "ami-00000042" ||
		result.Region != "" || result.Provenance != "ec2_compat" ||
		result.FieldsNotCollected != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestOpenStackFailureMatrix(t *testing.T) {
	runFailureMatrix(t, openstackFixture())
}
