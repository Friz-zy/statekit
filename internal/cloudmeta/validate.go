package cloudmeta

import "regexp"

// Field-specific ASCII grammar validators (security-review remediation,
// 2026-10-14): every collected field has a documented shape — generic
// nonempty-string acceptance is forbidden. Each validator is syntactic
// and value-free: any non-match is exactly ErrMalformed, which discards
// the whole result. The ASCII-anchored patterns implicitly reject
// Unicode, C1, and formatting characters. Length caps beyond the shared
// 1 KiB leaf grammar are pinned per field where the provider documents
// them (azure vmSize ≤ 64) or the pattern bounds imply them.

var (
	awsInstanceIDPattern   = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	awsRegionPattern       = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	awsZonePattern         = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9][a-f]$`) // region base + one AZ letter
	awsInstanceTypePattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9]+)+$`)
	awsAMIPattern          = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)

	azureLocationPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	azureZonePattern     = regexp.MustCompile(`^[0-9]$`)
	azureVMSizePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(_[A-Za-z0-9]+)+$`)

	gcpInstanceIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)

	doIDPattern     = regexp.MustCompile(`^[0-9]{1,20}$`)
	doRegionPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

	ociIDPattern     = regexp.MustCompile(`^ocid1\.instance\.[A-Za-z0-9.]{1,96}$`)
	ociRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)*-[0-9]+$`)
	ociADNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,31}$`) // ociAdName zone semantics; hyphenated AD names (e.g. EU-FRANKFURT-1-AD-1) are valid
	ociShapePattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{1,63}$`)
	ociImagePattern  = regexp.MustCompile(`^ocid1\.image\.[A-Za-z0-9.]{1,96}$`)

	openstackInstanceIDPattern   = regexp.MustCompile(`^i-[0-9a-fA-F]{8,17}$`) // ec2_compat label
	openstackZonePattern         = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	openstackInstanceTypePattern = regexp.MustCompile(`^[A-Za-z0-9_.:]{1,64}$`)
	openstackAMIPattern          = regexp.MustCompile(`^ami-[0-9a-fA-F]{8,17}$`) // ec2_compat label
)

// azureVMSizeMaxLen pins the documented 64-character vmSize bound on top
// of the pattern.
const azureVMSizeMaxLen = 64

// patternValidator returns a value-free validator: a hard length cap and
// an anchored pattern match.
func patternValidator(re *regexp.Regexp, maxLen int) func(string) error {
	return func(value string) error {
		if len(value) > maxLen || !re.MatchString(value) {
			return ErrMalformed
		}
		return nil
	}
}

// Field validators, one per collected leaf value.
var (
	validateAWSInstanceID   = patternValidator(awsInstanceIDPattern, maxLeafValueBytes)
	validateAWSRegion       = patternValidator(awsRegionPattern, maxLeafValueBytes)
	validateAWSZone         = patternValidator(awsZonePattern, maxLeafValueBytes)
	validateAWSInstanceType = patternValidator(awsInstanceTypePattern, maxLeafValueBytes)
	validateAWSAMI          = patternValidator(awsAMIPattern, maxLeafValueBytes)

	validateAzureLocation = patternValidator(azureLocationPattern, maxLeafValueBytes)
	validateAzureZone     = patternValidator(azureZonePattern, maxLeafValueBytes)
	validateAzureVMSize   = patternValidator(azureVMSizePattern, azureVMSizeMaxLen)

	validateGCPInstanceID = patternValidator(gcpInstanceIDPattern, maxLeafValueBytes)

	validateDOID     = patternValidator(doIDPattern, maxLeafValueBytes)
	validateDORegion = patternValidator(doRegionPattern, maxLeafValueBytes)

	validateOCIID     = patternValidator(ociIDPattern, maxLeafValueBytes)
	validateOCIRegion = patternValidator(ociRegionPattern, maxLeafValueBytes)
	validateOCIADName = patternValidator(ociADNamePattern, maxLeafValueBytes)
	validateOCIShape  = patternValidator(ociShapePattern, maxLeafValueBytes)
	validateOCIImage  = patternValidator(ociImagePattern, maxLeafValueBytes)

	validateOpenStackInstanceID   = patternValidator(openstackInstanceIDPattern, maxLeafValueBytes)
	validateOpenStackZone         = patternValidator(openstackZonePattern, maxLeafValueBytes)
	validateOpenStackInstanceType = patternValidator(openstackInstanceTypePattern, maxLeafValueBytes)
	validateOpenStackAMI          = patternValidator(openstackAMIPattern, maxLeafValueBytes)
)
