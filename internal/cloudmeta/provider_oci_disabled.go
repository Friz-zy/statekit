//go:build statekit_no_metadata_oci || statekit_no_metadata || statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// collectOCI is compiled out by statekit_no_metadata_oci (or the
// aggregate/cloud-total negative tags). Selection fails closed with
// ErrBuildDisabled before any client or request construction.
func collectOCI(context.Context, http.RoundTripper) (*Result, error) {
	return buildDisabled()
}
