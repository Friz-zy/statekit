//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"crypto/x509"
	"hash/crc32"
	"strings"

	"cloud.google.com/go/parametermanager/apiv1/parametermanagerpb"
	"google.golang.org/grpc"
)

const gcpParameterMethod = "/google.cloud.parametermanager.v1.ParameterManager/GetParameterVersion"

// Only this generated read method is admitted. Rendering, reference resolution,
// listing, writes and IAM APIs are deliberately absent from this interface.
type gcpParameterAPI interface {
	GetParameterVersion(context.Context, *parametermanagerpb.GetParameterVersionRequest, ...grpc.CallOption) (*parametermanagerpb.ParameterVersion, error)
}

type gcpParameterDependencies struct {
	systemRoots func() (*x509.CertPool, error)
	fetchToken  func(context.Context) (string, error)
	newClient   func(context.Context, string, *x509.CertPool, string) (gcpParameterAPI, func(), error)
}

// FetchGCPParameter reads raw configuration, never rendered secrets. IAM is
// externally managed at project scope. An omitted version selects mutable latest.
func FetchGCPParameter(ctx context.Context, source Source) ([]byte, error) {
	return fetchGCPParameterWith(ctx, source, gcpParameterDependencies{
		systemRoots: x509.SystemCertPool,
		fetchToken:  func(ctx context.Context) (string, error) { return fetchGCPToken(ctx, newGCPMetadataClient()) },
		newClient:   newGCPParameterClient,
	})
}

func newGCPParameterClient(ctx context.Context, token string, roots *x509.CertPool, authority string) (gcpParameterAPI, func(), error) {
	conn, err := newGCPConnection(ctx, token, roots, authority, gcpParameterMethod)
	if err != nil {
		return nil, nil, err
	}
	return parametermanagerpb.NewParameterManagerClient(conn), func() { _ = conn.Close() }, nil
}

func fetchGCPParameterWith(ctx context.Context, source Source, d gcpParameterDependencies) ([]byte, error) {
	if err := ValidateParameterSource(source); err != nil {
		return nil, err
	}
	authority, err := parameterAuthority(source.Region)
	if err != nil {
		return nil, err
	}
	if d.systemRoots == nil || d.fetchToken == nil || d.newClient == nil {
		return nil, ErrProvider
	}
	ctx, cancel := context.WithTimeout(ctx, gcpCallTimeout)
	defer cancel()
	roots, err := d.systemRoots()
	if err != nil || roots == nil {
		return nil, ErrProvider
	}
	token, err := d.fetchToken(ctx)
	if err != nil || token == "" {
		return nil, ErrCredentials
	}
	client, closeClient, err := d.newClient(ctx, token, roots, authority)
	if closeClient != nil {
		defer closeClient()
	}
	if err != nil || client == nil {
		return nil, ErrProvider
	}
	return readGCPParameter(ctx, client, source)
}

func readGCPParameter(ctx context.Context, client gcpParameterAPI, source Source) ([]byte, error) {
	if err := ValidateParameterSource(source); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrProvider
	}
	selector := source.VersionID
	if selector == "" {
		selector = "latest"
	}
	response, err := client.GetParameterVersion(ctx, &parametermanagerpb.GetParameterVersionRequest{Name: source.Resource + "/versions/" + selector, View: parametermanagerpb.View_FULL})
	if err != nil || response == nil || response.Disabled || response.Payload == nil {
		return nil, ErrProvider
	}
	prefix := source.Resource + "/versions/"
	if !strings.HasPrefix(response.Name, prefix) {
		return nil, ErrProvider
	}
	version := strings.TrimPrefix(response.Name, prefix)
	if !validParameterID(version) || version == "latest" || selector != "latest" && version != selector {
		return nil, ErrProvider
	}
	data := response.Payload.Data
	if len(data) > MaxPayloadBytes {
		return nil, ErrInvalidPayload
	}
	if checksum := response.Payload.DataCrc32C; checksum != nil && (*checksum < 0 || uint64(*checksum) > uint64(^uint32(0)) || uint32(*checksum) != crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))) {
		return nil, ErrInvalidPayload
	}
	return data, nil
}
