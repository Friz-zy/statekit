//go:build !statekit_no_sdk_gcp && !statekit_no_sdks

package cloudsecret

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/parametermanager/apiv1/parametermanagerpb"
)

func TestParameterPayloadWithoutOptionalCRC32CSucceedsWithoutIndependentChecksum(t *testing.T) {
	source := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config", VersionID: "v1"}
	want := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	response := &parametermanagerpb.ParameterVersion{
		Name: source.Resource + "/versions/v1",
		Payload: &parametermanagerpb.ParameterVersionPayload{
			Data: want,
			// DataCrc32C is absent: the request has no independent payload checksum.
		},
	}
	got, err := readGCPParameter(context.Background(), parameterReply{value: response}, source)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("payload without optional CRC32C was rejected or changed")
	}
}

func TestParameterSourceContract(t *testing.T) {
	s := Source{Provider: "gcp", Backend: "parametermanager", Region: "global", Resource: "projects/project-123/locations/global/parameters/config"}
	for _, version := range []string{"", "v_1", "A-2", strings.Repeat("a", 63)} {
		s.VersionID = version
		if err := ValidateParameterSource(s); err != nil {
			t.Fatal("valid parameter source rejected")
		}
	}
	for _, version := range []string{"-bad", "a/b", strings.Repeat("a", 64)} {
		s.VersionID = version
		if ValidateParameterSource(s) == nil {
			t.Fatal("invalid version accepted")
		}
	}
	s.VersionID = ""
	s.VersionAlias = "latest"
	if ValidateParameterSource(s) != nil {
		t.Fatal("latest rejected")
	}
	s.VersionID = "v1"
	if ValidateParameterSource(s) == nil {
		t.Fatal("mixed selectors accepted")
	}
	s.VersionID, s.VersionAlias = "", "other"
	if ValidateParameterSource(s) == nil {
		t.Fatal("unknown alias accepted")
	}
	s.VersionAlias = ""
	s.Region = "us-central1"
	if ValidateParameterSource(s) == nil {
		t.Fatal("location mismatch accepted")
	}
	s.Resource = "projects/project-123/locations/us-central1/parameters/config"
	if ValidateParameterSource(s) != nil {
		t.Fatal("regional source rejected")
	}
	for _, location := range []string{"us-central1.evil", "-bad", "us--central1", "US-central1", "us-central1:443"} {
		s.Region = location
		if ValidateParameterSource(s) == nil {
			t.Fatal("invalid location accepted")
		}
	}
}

func TestParameterURIScheme(t *testing.T) {
	uri := "param://gcp/parametermanager/global/projects%2Fproject-123%2Flocations%2Fglobal%2Fparameters%2Fconfig"
	if _, err := ParseParameterSourceURI(uri); err != nil {
		t.Fatal("canonical parameter URI rejected")
	}
	if _, err := ParseParameterSourceURI("param://gcp/parametermanager/global/projects/project-123/locations/global/parameters/config"); err == nil {
		t.Fatal("literal slash-expanded resource accepted")
	}
	if _, err := ParseSourceURI(uri); err == nil {
		t.Fatal("secret parser accepted parameter URI")
	}
	if _, err := ParseParameterSourceURI(strings.Replace(uri, "param://", "secret://", 1)); err == nil {
		t.Fatal("parameter parser accepted secret URI")
	}
}
