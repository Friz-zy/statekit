//go:build !statekit_no_metadata_aws && !statekit_no_metadata && !statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// awsPlan is the fixed AWS IMDSv2 descriptor. IMDSv2 ONLY: the token PUT
// must succeed or the whole collection fails — no IMDSv1 fallback is ever
// attempted. The token (TTL 30 seconds) is a transient protocol value,
// and no accepted leaf value may echo it.
func awsPlan() providerPlan {
	return providerPlan{
		provider: ProviderAWS,
		token: &tokenSpec{
			method:      http.MethodPut,
			path:        "/latest/api/token",
			ttlHeader:   "x-aws-ec2-metadata-token-ttl-seconds",
			ttlValue:    "30",
			tokenHeader: "x-aws-ec2-metadata-token",
		},
		leaves: []leafSpec{
			{
				field:    fieldInstanceID,
				path:     "/latest/meta-data/instance-id",
				required: true,
				validate: validateAWSInstanceID,
			},
			{field: fieldRegion, path: "/latest/meta-data/placement/region", validate: validateAWSRegion},
			{field: fieldZone, path: "/latest/meta-data/placement/availability-zone", validate: validateAWSZone},
			{field: fieldInstanceType, path: "/latest/meta-data/instance-type", validate: validateAWSInstanceType},
			{field: fieldImageID, path: "/latest/meta-data/ami-id", validate: validateAWSAMI},
		},
	}
}

func collectAWS(ctx context.Context, rt http.RoundTripper) (*Result, error) {
	return newCollector(rt).collectPlan(ctx, awsPlan())
}
