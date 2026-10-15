//go:build !statekit_no_metadata_azure && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// azurePlan is the fixed Azure IMDS descriptor. Every leaf carries the
// pinned api-version and format=text query plus the Metadata header.
// There is no image leaf: image references can embed subscription and
// resource names, so the field is never requested.
func azurePlan() providerPlan {
	return providerPlan{
		provider: ProviderAzure,
		headers:  map[string]string{"Metadata": "true"},
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/metadata/instance/compute/vmId",
				query:    "api-version=2025-04-07&format=text",
				required: true,
				validate: azureVMIDShape,
			},
			{field: fieldRegion, path: "/metadata/instance/compute/location", query: "api-version=2025-04-07&format=text", validate: validateAzureLocation},
			{field: fieldZone, path: "/metadata/instance/compute/zone", query: "api-version=2025-04-07&format=text", validate: validateAzureZone},
			{field: fieldInstanceType, path: "/metadata/instance/compute/vmSize", query: "api-version=2025-04-07&format=text", validate: validateAzureVMSize},
		},
	}
}

func collectAzure(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, azurePlan())
}
