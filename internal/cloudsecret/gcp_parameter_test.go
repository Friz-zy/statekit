//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cloudsecret

import (
	"context"
	"crypto/x509"
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"cloud.google.com/go/parametermanager/apiv1/parametermanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type parameterConn struct {
	t                  *testing.T
	name, responseName string
	calls              int
	fail               bool
}

type parameterReply struct {
	value *parametermanagerpb.ParameterVersion
}

func (r parameterReply) GetParameterVersion(context.Context, *parametermanagerpb.GetParameterVersionRequest, ...grpc.CallOption) (*parametermanagerpb.ParameterVersion, error) {
	return r.value, nil
}

func TestParameterPayloadBoundsAndIntegrity(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config", VersionID: "v1"}
	checksum := int64(crc32.Checksum([]byte("synthetic"), crc32.MakeTable(crc32.Castagnoli)))
	good := func() *parametermanagerpb.ParameterVersion {
		return &parametermanagerpb.ParameterVersion{Name: s.Resource + "/versions/v1", Payload: &parametermanagerpb.ParameterVersionPayload{Data: []byte("synthetic"), DataCrc32C: &checksum}}
	}
	if data, err := readGCPParameter(context.Background(), parameterReply{good()}, s); err != nil || string(data) != "synthetic" {
		t.Fatal("valid checksum rejected")
	}
	withoutChecksum := good()
	withoutChecksum.Payload.DataCrc32C = nil
	// Parameter Manager marks this checksum optional: absent CRC means transport
	// integrity is authenticated by TLS, without an independent payload checksum.
	if data, err := readGCPParameter(context.Background(), parameterReply{withoutChecksum}, s); err != nil || string(data) != "synthetic" {
		t.Fatal("parameter payload without optional checksum rejected")
	}
	maximum := good()
	maximum.Payload.Data = make([]byte, MaxPayloadBytes)
	maximumChecksum := int64(crc32.Checksum(maximum.Payload.Data, crc32.MakeTable(crc32.Castagnoli)))
	maximum.Payload.DataCrc32C = &maximumChecksum
	if data, err := readGCPParameter(context.Background(), parameterReply{maximum}, s); err != nil || len(data) != MaxPayloadBytes {
		t.Fatal("exact maximum parameter payload rejected")
	}
	badChecksum := good()
	incorrectChecksum := checksum + 1
	badChecksum.Payload.DataCrc32C = &incorrectChecksum
	if data, err := readGCPParameter(context.Background(), parameterReply{badChecksum}, s); err != ErrInvalidPayload || data != nil {
		t.Fatal("parameter payload with incorrect checksum accepted")
	}
	for _, mutate := range []func(*parametermanagerpb.ParameterVersion){
		func(v *parametermanagerpb.ParameterVersion) { v.Disabled = true },
		func(v *parametermanagerpb.ParameterVersion) { v.Payload = nil },
		func(v *parametermanagerpb.ParameterVersion) { v.Payload.Data = make([]byte, MaxPayloadBytes+1) },
		func(v *parametermanagerpb.ParameterVersion) { v.Payload.Data = []byte("corrupt") },
		func(v *parametermanagerpb.ParameterVersion) { v.Name = s.Resource + "/versions/other" },
	} {
		v := good()
		mutate(v)
		if data, err := readGCPParameter(context.Background(), parameterReply{v}, s); err == nil || data != nil {
			t.Fatal("unsafe parameter response accepted")
		}
	}
}

func TestParameterValidationAndClientClose(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "us-central1", Resource: "projects/project-123/locations/us-central1/parameters/config"}
	steps, closed := "", false
	d := gcpParameterDependencies{
		systemRoots: func() (*x509.CertPool, error) { steps += "roots/"; return x509.NewCertPool(), nil },
		fetchToken:  func(context.Context) (string, error) { steps += "identity/"; return "synthetic", nil },
		newClient: func(_ context.Context, _ string, _ *x509.CertPool, authority string) (gcpParameterAPI, func(), error) {
			steps += "client/"
			if authority != "parametermanager.us-central1.rep.googleapis.com:443" {
				t.Fatal("wrong regional endpoint")
			}
			return parameterReply{&parametermanagerpb.ParameterVersion{Name: s.Resource + "/versions/v1", Payload: &parametermanagerpb.ParameterVersionPayload{Data: []byte("synthetic")}}}, func() { closed = true }, nil
		},
	}
	if _, err := fetchGCPParameterWith(context.Background(), s, d); err != nil || steps != "roots/identity/client/" || !closed {
		t.Fatal("identity ordering or connection closure failed")
	}
	steps = ""
	s.Region = "global"
	if _, err := fetchGCPParameterWith(context.Background(), s, d); err == nil || steps != "" {
		t.Fatal("invalid location reached identity")
	}
}

func (c *parameterConn) Invoke(_ context.Context, method string, in, out any, _ ...grpc.CallOption) error {
	c.calls++
	if method != gcpParameterMethod {
		c.t.Fatal("forbidden RPC: render/list/write/IAM")
	}
	r := in.(*parametermanagerpb.GetParameterVersionRequest)
	if r.Name != c.name || r.View != parametermanagerpb.View_FULL {
		c.t.Fatal("wrong raw read selector")
	}
	if c.fail {
		return errors.New("sensitive-canary")
	}
	response := out.(*parametermanagerpb.ParameterVersion)
	response.Name = c.responseName
	response.Payload = &parametermanagerpb.ParameterVersionPayload{Data: []byte("__REF__(unresolved)")}
	return nil
}
func (c *parameterConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	c.t.Fatal("unexpected streaming call")
	return nil, ErrProvider
}

func TestParameterGeneratedRawRead(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config"}
	for _, version := range []string{"", "v_1"} {
		s.VersionID = version
		selector := version
		if selector == "" {
			selector = "latest"
		}
		conn := &parameterConn{t: t, name: s.Resource + "/versions/" + selector, responseName: s.Resource + "/versions/v_1"}
		client := parametermanagerpb.NewParameterManagerClient(conn)
		data, err := readGCPParameter(context.Background(), client, s)
		if err != nil || string(data) != "__REF__(unresolved)" || conn.calls != 1 {
			t.Fatal("raw read did not preserve references")
		}
		conn.fail, conn.calls = true, 0
		if _, err := readGCPParameter(context.Background(), client, s); err != ErrProvider || conn.calls != 1 {
			t.Fatal("read retried, fell back, or leaked provider error")
		}
		conn.fail = false
		conn.responseName = "projects/other-project/locations/global/parameters/config/versions/v_1"
		if _, err := readGCPParameter(context.Background(), client, s); err != ErrProvider {
			t.Fatal("foreign response accepted")
		}
	}
}

func TestParameterExplicitLatestAliasUsesLatestVersion(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config", VersionAlias: "latest"}
	conn := &parameterConn{t: t, name: s.Resource + "/versions/latest", responseName: s.Resource + "/versions/v_1"}
	client := parametermanagerpb.NewParameterManagerClient(conn)
	if _, err := readGCPParameter(context.Background(), client, s); err != nil || conn.calls != 1 {
		t.Fatal("explicit latest alias did not make one latest-version read")
	}
}

func TestParameterEndpointAndCredentialScope(t *testing.T) {
	for location, want := range map[string]string{"global": "parametermanager.googleapis.com:443", "us-central1": "parametermanager.us-central1.rep.googleapis.com:443"} {
		authority, err := parameterAuthority(location)
		if err != nil || authority != want {
			t.Fatal("incorrect endpoint")
		}
		c := gcpTokenCredentials{token: "synthetic", authority: authority, method: gcpParameterMethod}
		ctx := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{Method: gcpParameterMethod})
		audience := "https://" + strings.TrimSuffix(authority, ":443") + "/google.cloud.parametermanager.v1.ParameterManager"
		if _, err := c.GetRequestMetadata(ctx, audience); err != nil {
			t.Fatal("exact scoped credentials rejected")
		}
		if _, err := c.GetRequestMetadata(ctx, gcpAccessAudience); err == nil {
			t.Fatal("token allowed a foreign authority")
		}
		ctx = credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{Method: "/google.cloud.parametermanager.v1.ParameterManager/RenderParameterVersion"})
		if _, err := c.GetRequestMetadata(ctx, audience); err == nil {
			t.Fatal("token allowed rendering")
		}
		if _, err := c.GetRequestMetadata(context.Background(), gcpAccessAudience); err == nil {
			t.Fatal("token allowed another service")
		}
	}
}
