package cloudmeta

import (
	"bytes"
	"unicode/utf8"
)

// maxLeafValueBytes caps an accepted leaf value (after the single trailing
// newline is trimmed).
const maxLeafValueBytes = 1 << 10 // 1 KiB

// errEmptyLeaf marks the empty-after-trim case with a sentinel identity of
// its own so the optional-leaf omission rule can match it; its text stays
// the value-free malformed code and it never escapes the package.
var errEmptyLeaf = &leafError{}

// leafError reports as cloud_meta_malformed.
type leafError struct{}

func (*leafError) Error() string { return ErrMalformed.Error() }

// parseLeafValue enforces the per-leaf grammar, identical for every
// provider leaf: each documented response carries AT MOST one trailing
// "\n" (trimmed once), and the remainder must be non-empty, free of
// control characters (< 0x20 and 0x7f), valid UTF-8, and at most
// maxLeafValueBytes long. There is no TrimSpace, no basename, and no
// prefix normalization: every other byte is kept verbatim.
func parseLeafValue(body []byte) (string, error) {
	b := body
	if bytes.HasSuffix(b, []byte("\n")) {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return "", errEmptyLeaf
	}
	if len(b) > maxLeafValueBytes {
		return "", ErrOversize
	}
	if !utf8.Valid(b) {
		return "", ErrEncoding
	}
	for _, r := range string(b) {
		if r < 0x20 || r == 0x7f {
			return "", ErrMalformed
		}
	}
	return string(b), nil
}

// azureVMIDShape is the syntactic vmId check: a GUID-shaped token of
// 8-4-4-4-12 hex digits. Shape only — no value semantics.
func azureVMIDShape(s string) error {
	if len(s) != 36 {
		return ErrMalformed
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return ErrMalformed
			}
		default:
			if !isHexDigit(r) {
				return ErrMalformed
			}
		}
	}
	return nil
}

func isHexDigit(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}
