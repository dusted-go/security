package compare

import "testing"

func Test_Compare_WithEqualHashes_ReturnsTrue(t *testing.T) {
	hash1 := []byte{1, 2, 3, 4, 5, 6, 22, 66, 128}
	hash2 := []byte{1, 2, 3, 4, 5, 6, 22, 66, 128}

	if !Hashes(hash1, hash2) {
		t.Error("Compare didn't recognise two identical byte arrays as equal.")
	}
}

func Test_Compare_WithUnequalHashes_ReturnsFalse(t *testing.T) {
	hash1 := []byte{9, 9, 9, 9, 3, 6, 22, 66, 128}
	hash2 := []byte{1, 2, 3, 4, 5, 6, 22, 66, 128}

	if Hashes(hash1, hash2) {
		t.Error("Compare didn't recognise two different byte arrays as unequal.")
	}
}
