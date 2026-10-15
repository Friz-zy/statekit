//go:build statekit_no_metadata_do || statekit_no_metadata || statekit_no_cloud_extras

package cloudmeta

import (
	"context"
	"net/http"
)

// collectDO is compiled out by statekit_no_metadata_do (or the
// aggregate/cloud-total negative tags). Selection fails closed with
// ErrBuildDisabled before any client or request construction.
func collectDO(context.Context, http.RoundTripper) (*Result, error) {
	return buildDisabled()
}
