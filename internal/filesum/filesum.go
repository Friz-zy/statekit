// Package filesum provides the checksum algorithms shared by the file and
// cp modules, mirroring salt.utils.hashutils.get_hash @ pinned revision.
package filesum

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// New returns a fresh hash.Hash for one of the six supported forms
// (md5, sha1, sha224, sha256, sha384, sha512) or an error mirroring
// upstream's "Invalid hash type: {form}" ValueError.
func New(form string) (hash.Hash, error) {
	switch form {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha224":
		return sha256.New224(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("Invalid hash type: %s", form)
}
