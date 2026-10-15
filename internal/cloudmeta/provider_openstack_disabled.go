//go:build statekit_no_metadata_openstack || statekit_no_metadata || statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// collectOpenStack is compiled out by statekit_no_metadata_openstack (or
// the aggregate/cloud-total negative tags). Selection fails closed with
// ErrBuildDisabled before any client or request construction.
func collectOpenStack(context.Context, http.RoundTripper) (*Result, error) {
	return buildDisabled()
}
