// Package cloudmeta collects the bounded HTTP machine-metadata subset
// approved by ADR 0005 amendment 2026-10-14 for six providers (aws, azure,
// gcp, oci, do, openstack) over the link-local metadata endpoint
// 169.254.169.254:80, standard library only.
//
// Security invariants (binding):
//
//   - Every request comes from a fixed compile-time descriptor; there is no
//     user-supplied base URL, path, query, or header anywhere in the API.
//   - The only dialable address is the literal "169.254.169.254:80" over
//     tcp; no DNS, no proxy, no redirects (including same-origin), no
//     compression, no cookies, no retries, no fallbacks.
//   - All responses are bounded (header, per-leaf, token, and aggregate
//     body budgets) and time-bounded (dial, header, per-request, and
//     overall collection deadlines).
//   - Errors are closed-set value-free sentinel codes: response status,
//     body bytes, header values, url.Error text, and parsed values never
//     reach an error string or a log line.
//   - Every collected value passes a documented per-field ASCII grammar
//     validator; generic nonempty-string acceptance is forbidden, and no
//     accepted leaf value may echo the IMDSv2 token.
//   - The AWS IMDSv2 token is a transient protocol value: memory-only for
//     the duration of one collection, used only as a request header, never
//     persisted, logged, or returned.
//   - Collected metadata is an UNVERIFIED PROVIDER CLAIM. It is not
//     attestation of the executing host and must never authorize any
//     action; see Result.
//
// Providers are individually removable at build time with the negative
// tags statekit_no_metadata_<provider>, in aggregate with
// statekit_no_metadata, and together with all cloud extras via
// statekit_no_cloud_extras. A compiled-out provider fails closed with
// ErrBuildDisabled before any client or request construction.
package cloudmeta

import (
	"context"
	"net/http"
)

// Provider is the canonical cloud provider enum. Values are lowercase and
// matched exactly; input is never normalized.
type Provider string

// Implemented providers of the authorized safe subset.
const (
	ProviderAWS       Provider = "aws"
	ProviderAzure     Provider = "azure"
	ProviderGCP       Provider = "gcp"
	ProviderOCI       Provider = "oci"
	ProviderDO        Provider = "do"
	ProviderOpenStack Provider = "openstack"
)

// Recognized but deferred providers: no collection is implemented until
// safe field/transport evidence and any needed authentication design
// exist. A deferred provider is never implied absent.
const (
	ProviderIBM      Provider = "ibm"
	ProviderLinode   Provider = "linode"
	ProviderHetzner  Provider = "hetzner"
	ProviderOVH      Provider = "ovh"
	ProviderScaleway Provider = "scaleway"
	ProviderVultr    Provider = "vultr"
	ProviderVSphere  Provider = "vsphere"
)

// deferredProviders is the closed deferred enum membership.
var deferredProviders = map[Provider]bool{
	ProviderIBM:      true,
	ProviderLinode:   true,
	ProviderHetzner:  true,
	ProviderOVH:      true,
	ProviderScaleway: true,
	ProviderVultr:    true,
	ProviderVSphere:  true,
}

// Collect runs one provider's fixed metadata contract. The provider string
// is matched exactly against the enum: unknown values yield
// ErrInvalidProvider, deferred members yield ErrDeferredProvider, and
// compiled-out members yield ErrBuildDisabled — the latter two before any
// client or request construction. Any collection error discards the whole
// result; only a documented optional leaf's 404/empty may be omitted,
// producing a partial result.
func Collect(ctx context.Context, provider string) (*Result, error) {
	return collectDispatch(ctx, Provider(provider), nil)
}

// collectDispatch is the single enum dispatch seam. A nil rt selects the
// hardened production transport; tests inject a fake RoundTripper. Each
// arm is compiled with its provider's descriptor (the negative tags
// replace the arm body with a build-disabled stub).
func collectDispatch(ctx context.Context, p Provider, rt http.RoundTripper) (*Result, error) {
	if deferredProviders[p] {
		return nil, ErrDeferredProvider
	}
	switch p {
	case ProviderAWS:
		return collectAWS(ctx, rt)
	case ProviderAzure:
		return collectAzure(ctx, rt)
	case ProviderGCP:
		return collectGCP(ctx, rt)
	case ProviderOCI:
		return collectOCI(ctx, rt)
	case ProviderDO:
		return collectDO(ctx, rt)
	case ProviderOpenStack:
		return collectOpenStack(ctx, rt)
	default:
		return nil, ErrInvalidProvider
	}
}
