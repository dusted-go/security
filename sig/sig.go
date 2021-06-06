package sig

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/dusted-go/security/compare"
)

// HashFactory creates a new Hash.
type HashFactory = func() hash.Hash

// Compute calculates a signature for a given hashing function, key and message.
func Compute(hasher HashFactory, key []byte, msg []byte) []byte {
	hmac := hmac.New(hasher, key)
	_, err := hmac.Write(msg)
	if err != nil {
		panic(fmt.Errorf("error generating HMAC hash: %w", err))
	}
	return hmac.Sum(nil)

}

// Validate verifies an existing signature against a given hashing function, key and message.
func Validate(hasher HashFactory, key, msg, signature []byte) bool {
	actualSignature := Compute(hasher, key, msg)
	return compare.Hashes(signature, actualSignature)

}

// ComputeSHA256 calculates a signature for a given key and message.
func ComputeSHA256(key, msg []byte) []byte {
	return Compute(sha256.New, key, msg)
}

// ValidateSHA256 verifies an existing signature against a given key and message.
func ValidateSHA256(key, msg, signature []byte) bool {
	return Validate(sha256.New, key, msg, signature)
}
