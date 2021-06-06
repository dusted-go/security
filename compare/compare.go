package compare

// Hashes validates two hashes in a secure way which
// will prevent timing attacks by always iterating
// through the entire byte array.
func Hashes(hash1 []byte, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}

	equal := true

	for i, b := range hash1 {
		equal = equal && b == hash2[i]
	}

	return equal
}
