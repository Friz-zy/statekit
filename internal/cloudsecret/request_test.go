package cloudsecret

import (
	"errors"
	"testing"
)

func TestParseSourceURIStrictComponents(t *testing.T) {
	source, err := ParseSourceURI("secret://aws/ssm/us-east-1/%2Fprod%2Fdatabase")
	if err != nil {
		t.Fatal("valid encoded source URI was rejected")
	}
	if source.Provider != "aws" || source.Backend != "ssm" || source.Region != "us-east-1" || source.Resource != "/prod/database" {
		t.Fatal("source URI components were not decoded exactly once")
	}
}

func TestParseSourceURIRejectsAmbiguousOrUnscopedURIs(t *testing.T) {
	for _, value := range []string{
		"secret://aws:443/ssm/us-east-1/parameter",
		"secret://user@aws/ssm/us-east-1/parameter",
		"secret://aws/ssm/us-east-1/parameter?version=2",
		"secret://aws/ssm/us-east-1/parameter#fragment",
		"secret://aws/ssm/us-east-1/%ZZ",
		"secret://aws/ssm/us-east-1/%252Fprod",
		"secret://aws/ssm/us-east-1/one/two",
	} {
		if _, err := ParseSourceURI(value); !errors.Is(err, ErrInvalidSource) {
			t.Fatal("ambiguous or unscoped URI was not rejected as invalid")
		}
	}
}

func TestValidateSourceRequiresExplicitSourceAndSupportedSelectors(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		want   error
	}{
		{name: "empty", want: ErrInvalidSource},
		{name: "partial", source: Source{Provider: "aws", Backend: "ssm", Region: "us-east-1"}, want: ErrInvalidSource},
		{name: "deferred provider", source: Source{Provider: "oci", Backend: "keyvault", Region: "us-east-1", Resource: "item"}, want: ErrUnsupported},
		{name: "deferred backend", source: Source{Provider: "aws", Backend: "appconfig", Region: "us-east-1", Resource: "app"}, want: ErrUnsupported},
		{name: "aws unsupported backend precedes invalid selector", source: Source{Provider: "aws", Backend: "unknown", Region: "us-east-1", Resource: "/item", VersionID: "bad selector"}, want: ErrUnsupported},
		{name: "two secret selectors", source: Source{Provider: "aws", Backend: "secretsmanager", Region: "us-east-1", Resource: "item", VersionID: "id", VersionAlias: "AWSCURRENT"}, want: ErrInvalidSource},
		{name: "ssm alias", source: Source{Provider: "aws", Backend: "ssm", Region: "us-east-1", Resource: "/item", VersionAlias: "stable"}, want: ErrInvalidSource},
		{name: "ssm numeric version", source: Source{Provider: "aws", Backend: "ssm", Region: "us-east-1", Resource: "/item", VersionID: "8"}},
		{name: "gcp global source", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db"}},
		{name: "gcp numeric project", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/123456789012/secrets/db", VersionID: "12"}},
		{name: "gcp alias", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionAlias: "latest"}},
		{name: "gcp regional location unsupported", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "us-central1", Resource: "projects/project-123/secrets/db"}, want: ErrUnsupported},
		{name: "gcp regional resource unsupported", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/locations/us-central1/secrets/db"}, want: ErrUnsupported},
		{name: "gcp malformed resource", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db/extra"}, want: ErrInvalidSource},
		{name: "gcp invalid project grammar", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/BadProject/secrets/db"}, want: ErrInvalidSource},
		{name: "gcp invalid secret grammar", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/bad.secret"}, want: ErrInvalidSource},
		{name: "gcp leading-zero version", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionID: "01"}, want: ErrInvalidSource},
		{name: "gcp invalid alias", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionAlias: "bad alias"}, want: ErrInvalidSource},
		{name: "gcp custom alias unsupported", source: Source{Provider: "gcp", Backend: "secretmanager", Region: "global", Resource: "projects/project-123/secrets/db", VersionAlias: "stable"}, want: ErrInvalidSource},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSource(test.source)
			if test.want == nil {
				if err != nil {
					t.Fatal("valid source was rejected")
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatal("source validation returned the wrong closed error category")
			}
		})
	}
}

func TestSSMVersionSelectorRequiresCanonicalUnsignedASCIIDecimal(t *testing.T) {
	for _, version := range []string{"", "+1", "-1", "1a", "01", "0", "9223372036854775808"} {
		if validSSMVersion(version) {
			t.Fatal("noncanonical SSM version selector was accepted")
		}
	}
	for _, version := range []string{"1", "12", "9223372036854775807"} {
		if !validSSMVersion(version) {
			t.Fatal("canonical SSM version selector was rejected")
		}
	}
}

func TestParseSourceURIAllowsFullCrossAccountARN(t *testing.T) {
	source, err := ParseSourceURI("secret://aws/secretsmanager/us-east-1/arn%3Aaws%3Asecretsmanager%3Aus-east-1%3A123456789012%3Asecret%3Aprod-AbCdEf")
	if err != nil {
		t.Fatal("full cross-account secret ARN was rejected")
	}
	if source.Resource != "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-AbCdEf" {
		t.Fatal("ARN component did not survive one strict decode")
	}
}

func TestParseStructuredRequestRejectsDuplicatesUnknownAndTypedFields(t *testing.T) {
	for _, input := range []string{
		`{"provider":"aws","provider":"aws"}`,
		"provider: aws\nunknown: value\n",
		`{"provider":"aws","region":1}`,
	} {
		if _, err := ParseStructuredRequest([]byte(input)); !errors.Is(err, ErrInvalidSource) {
			t.Fatal("invalid structured request field was accepted")
		}
	}
	fields, err := ParseStructuredRequest([]byte("provider: aws\nbackend: ssm\nregion: us-east-1\nresource: /prod/key\n"))
	if err != nil || fields["resource"] != "/prod/key" {
		t.Fatal("valid structured source fields were rejected")
	}
}
