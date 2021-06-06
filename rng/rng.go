package rng

import (
	"crypto/rand"
	"fmt"
)

// GenerateBytes generates a random byte array with the given length.
func GenerateBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate %d random bytes: %w", length, err))
	}
	return b
}
