//go:build !statekit_no_metadata_gcp && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// gcpPlan is the fixed GCP descriptor: instance id only. The zone,
// machine-type, and image leaves transport project identifiers
// (projects/PROJECT_NUM/... per the predefined metadata keys) and are
// never requested; they are reported as not_collected instead, without
// claiming they are unavailable. No prefix trimming is performed
// anywhere. The service must echo the exact Metadata-Flavor response
// marker before the id leaf is accepted.
func gcpPlan() providerPlan {
	return providerPlan{
		provider:            ProviderGCP,
		headers:             map[string]string{"Metadata-Flavor": "Google"},
		requiredRespHeaders: map[string]string{"Metadata-Flavor": "Google"},
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/computeMetadata/v1/instance/id",
				required: true,
				validate: validateGCPInstanceID,
			},
		},
		excluded: map[string]string{
			fieldZone:         reasonExcludedIdentifier,
			fieldInstanceType: reasonExcludedIdentifier,
			fieldImageID:      reasonExcludedIdentifier,
		},
	}
}

func collectGCP(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, gcpPlan())
}
