//go:build !statekit_no_metadata_do && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// doPlan is the fixed DigitalOcean descriptor. Droplet metadata documents
// an id and a region; no size/image leaves exist in the approved subset.
func doPlan() providerPlan {
	return providerPlan{
		provider: ProviderDO,
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/metadata/v1/id",
				required: true,
				validate: validateDOID,
			},
			{field: fieldRegion, path: "/metadata/v1/region", validate: validateDORegion},
		},
	}
}

func collectDO(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, doPlan())
}
