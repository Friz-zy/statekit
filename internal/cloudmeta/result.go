package cloudmeta

// Result status values (closed set).
const (
	statusOK      = "ok"
	statusPartial = "partial"
)

// Closed set of fields_not_collected reasons.
const (
	// reasonExcludedIdentifier marks a field whose leaf is excluded by the
	// approved contract (never requested), e.g. GCP zone/machine-type/image
	// because those leaves transport project identifiers.
	reasonExcludedIdentifier = "excluded_identifier"
	// reasonNotPresent marks a documented optional leaf that answered 404
	// or empty; the field is omitted, not failed.
	reasonNotPresent = "not_present"
)

// verificationUnverified is the fixed Verification marker of every
// result: collected metadata is an unverified provider claim.
const verificationUnverified = "unverified"

// Result is the JSON-serializable outcome of one provider collection.
//
// SECURITY: every value here is an UNVERIFIED PROVIDER CLAIM read from a
// link-local metadata endpoint. A Result describes what the endpoint said;
// it is never attestation of the executing host and MUST NOT be used to
// authorize any action, access decision, or credential use.
type Result struct {
	Provider           string            `json:"provider"`
	Status             string            `json:"status"`
	Verification       string            `json:"verification"`
	InstanceID         string            `json:"instance_id,omitempty"`
	Region             string            `json:"region,omitempty"`
	Zone               string            `json:"zone,omitempty"`
	InstanceType       string            `json:"instance_type,omitempty"`
	ImageID            string            `json:"image_id,omitempty"`
	FieldsNotCollected map[string]string `json:"fields_not_collected,omitempty"`
	Provenance         string            `json:"provenance,omitempty"`
}

// Result field names used by provider descriptors.
const (
	fieldInstanceID   = "instance_id"
	fieldRegion       = "region"
	fieldZone         = "zone"
	fieldInstanceType = "instance_type"
	fieldImageID      = "image_id"
)
