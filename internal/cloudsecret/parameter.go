package cloudsecret

import "strings"

// ParseParameterSourceURI accepts only
// param://gcp/parametermanager/<location>/<resource>. The provider-native
// resource path must be percent-encoded as exactly one URI path segment.
func ParseParameterSourceURI(value string) (Source, error) {
	return parseSourceURI(value, "param://", ValidateParameterSource)
}

// ValidateParameterSource is separate from the secret-service contract.
func ValidateParameterSource(source Source) error {
	if !validToken(source.Provider) || !validToken(source.Backend) || !validToken(source.Region) || !validResource(source.Resource) {
		return ErrInvalidSource
	}
	if source.Provider != "gcp" || source.Backend != "parametermanager" {
		return ErrUnsupported
	}
	if !validParameterLocation(source.Region) {
		return ErrInvalidSource
	}
	parts := strings.Split(source.Resource, "/")
	if len(parts) != 6 || parts[0] != "projects" || !validGCPProject(parts[1]) || parts[2] != "locations" || parts[3] != source.Region || parts[4] != "parameters" || !validParameterID(parts[5]) {
		return ErrInvalidSource
	}
	if source.VersionID != "" && source.VersionAlias != "" || source.VersionID != "" && (!validParameterID(source.VersionID) || source.VersionID == "latest") || source.VersionAlias != "" && source.VersionAlias != "latest" {
		return ErrInvalidSource
	}
	return nil
}

func validParameterID(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' {
		return false
	}
	for i := range value {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validParameterLocation(value string) bool {
	return value == "global" || validRegion(value)
}

func parameterAuthority(location string) (string, error) {
	if !validParameterLocation(location) {
		return "", ErrInvalidSource
	}
	if location == "global" {
		return "parametermanager.googleapis.com:443", nil
	}
	return "parametermanager." + location + ".rep.googleapis.com:443", nil
}
