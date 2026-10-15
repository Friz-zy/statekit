//go:build !statekit_no_metadata_gcp && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"errors"
	"net/http"
	"testing"
)

// gcpForbiddenTripwires are the project-identifier leaves that must NEVER
// be requested.
var gcpForbiddenTripwires = map[string]bool{
	"/computeMetadata/v1/instance/zone":         true,
	"/computeMetadata/v1/instance/machine-type": true,
	"/computeMetadata/v1/instance/image":        true,
}

func gcpFixture() providerFixture {
	return providerFixture{
		provider:  "gcp",
		forbidden: gcpForbiddenTripwires,
		happy: []cannedResponse{
			{
				status: http.StatusOK,
				body:   "834170998498\n",
				header: map[string]string{"Metadata-Flavor": "Google"},
			},
		},
		requiredIdx:   0,
		requiredField: fieldInstanceID,
		optionalIdx:   -1,
	}
}

func TestGCPHappyPathIdOnlyNeverRequestsExcludedLeaves(t *testing.T) {
	result, err, rt := runProvider("gcp", gcpForbiddenTripwires, gcpFixture().happy...)
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	if len(rt.calls) != 1 {
		t.Fatalf("calls=%d, want exactly one id request: %+v", len(rt.calls), rt.calls)
	}
	assertCall(t, 0, rt.calls[0], http.MethodGet, "/computeMetadata/v1/instance/id", "",
		map[string]string{"Metadata-Flavor": "Google"})
	if rt.violation != "" {
		t.Fatalf("forbidden tripwire fired: %s", rt.violation)
	}
	if result.Provider != "gcp" || result.Status != statusOK ||
		result.Verification != verificationUnverified ||
		result.InstanceID != "834170998498" || result.Region != "" ||
		result.Zone != "" || result.InstanceType != "" || result.ImageID != "" ||
		result.Provenance != "" {
		t.Fatalf("result=%+v", result)
	}
	want := map[string]string{
		fieldZone:         reasonExcludedIdentifier,
		fieldInstanceType: reasonExcludedIdentifier,
		fieldImageID:      reasonExcludedIdentifier,
	}
	for field, reason := range want {
		if result.FieldsNotCollected[field] != reason {
			t.Fatalf("fields_not_collected[%s]=%q, want %q", field, result.FieldsNotCollected[field], reason)
		}
	}
	if len(result.FieldsNotCollected) != len(want) {
		t.Fatalf("fields_not_collected=%v, want exactly %v", result.FieldsNotCollected, want)
	}
}

// TestGCPMetadataFlavorResponseRequired pins that the id leaf is only
// accepted when the response carries the exact documented flavor marker.
func TestGCPMetadataFlavorResponseRequired(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header map[string]string
	}{
		{"missing", nil},
		{"mismatched", map[string]string{"Metadata-Flavor": "Google Compute Engine"}},
		{"wrong-header", map[string]string{"X-Flavor": "Google"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responses := withMutation(gcpFixture().happy, 0, func(r *cannedResponse) {
				r.header = tc.header
			})
			result, err, rt := runProvider("gcp", gcpForbiddenTripwires, responses...)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v, want %v", err, ErrProtocol)
			}
			if result != nil {
				t.Fatalf("result=%+v, want nil (whole-result discard)", result)
			}
			if len(rt.calls) != 1 {
				t.Fatalf("calls=%d, want 1", len(rt.calls))
			}
		})
	}
}

func TestGCPFailureMatrix(t *testing.T) {
	runFailureMatrix(t, gcpFixture())
}
