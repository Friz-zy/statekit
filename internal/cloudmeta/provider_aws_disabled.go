//go:build statekit_no_metadata_aws || statekit_no_metadata || statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// collectAWS is compiled out by statekit_no_metadata_aws (or the
// aggregate/cloud-total negative tags). Selection fails closed with
// ErrBuildDisabled before any client or request construction.
func collectAWS(context.Context, http.RoundTripper) (*Result, error) {
	return buildDisabled()
}
