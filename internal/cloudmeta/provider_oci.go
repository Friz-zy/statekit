//go:build !statekit_no_metadata_oci && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// ociPlan is the fixed Oracle Cloud IMDS descriptor. The Authorization
// header value "Bearer Oracle" is a documented static protocol marker of
// the metadata service, not a credential. Zone semantics come from
// ociAdName; the tenancy-prefixed availabilityDomain leaf is never
// requested (it is also rejected by the forbidden-path guard). The
// provenance marker records the ociAdName zone semantics in every
// result.
func ociPlan() providerPlan {
	return providerPlan{
		provider:   ProviderOCI,
		headers:    map[string]string{"Authorization": "Bearer Oracle"},
		provenance: "ociAdName",
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/opc/v2/instance/id",
				required: true,
				validate: validateOCIID,
			},
			{field: fieldRegion, path: "/opc/v2/instance/canonicalRegionName", validate: validateOCIRegion},
			{field: fieldZone, path: "/opc/v2/instance/ociAdName", validate: validateOCIADName},
			{field: fieldInstanceType, path: "/opc/v2/instance/shape", validate: validateOCIShape},
			{field: fieldImageID, path: "/opc/v2/instance/image", validate: validateOCIImage},
		},
	}
}

func collectOCI(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, ociPlan())
}
