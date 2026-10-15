//go:build !statekit_no_metadata_openstack && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// openstackPlan is the fixed OpenStack descriptor: the dated
// EC2-compatible leaves only, with no headers or query. The identifiers
// are compatibility labels, not Nova/Glance UUIDs, which is why every
// result carries the ec2_compat provenance marker. The bulk
// /openstack/*/meta_data.json document carries project, key, and name
// material and is prohibited (also rejected by the forbidden-path guard).
func openstackPlan() providerPlan {
	return providerPlan{
		provider:   ProviderOpenStack,
		provenance: "ec2_compat",
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/2009-04-04/meta-data/instance-id",
				required: true,
				validate: validateOpenStackInstanceID,
			},
			{field: fieldZone, path: "/2009-04-04/meta-data/placement/availability-zone", validate: validateOpenStackZone},
			{field: fieldInstanceType, path: "/2009-04-04/meta-data/instance-type", validate: validateOpenStackInstanceType},
			{field: fieldImageID, path: "/2009-04-04/meta-data/ami-id", validate: validateOpenStackAMI},
		},
	}
}

func collectOpenStack(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, openstackPlan())
}
