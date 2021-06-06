package sig

import (
	"bytes"
	"testing"
)

func Test_HmacSha256_WithEmptyMessageAndEmptyKey_ReturnsCorrectHash(t *testing.T) {
	key := make([]byte, 0)
	msg := make([]byte, 0)
	expected := []byte{
		182, 19, 103, 154, 8, 20, 217, 236,
		119, 47, 149, 215, 120, 195, 95, 197,
		255, 22, 151, 196, 147, 113, 86, 83,
		198, 199, 18, 20, 66, 146, 197, 173}

	actual := ComputeSHA256(key, msg)

	if !bytes.Equal(expected, actual) {
		t.Error("Expected:", expected, "Actual:", actual)
	}
}

func Test_HmacSha256_WithEmptyMessageAndRandomKey_ReturnsCorrectHash(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	msg := make([]byte, 0)
	expected := []byte{
		10, 123, 154, 129, 172, 215, 50, 147,
		103, 212, 95, 251, 185, 17, 178, 112,
		95, 238, 193, 118, 94, 243, 203, 238,
		213, 254, 101, 135, 100, 122, 9, 151}

	actual := ComputeSHA256(key, msg)

	if !bytes.Equal(expected, actual) {
		t.Error("Expected:", expected, "Actual:", actual)
	}
}

func Test_HmacSha256_WithRandomMessageAndRandomKey_ReturnsCorrectHash(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	msg := []byte{250, 240, 230, 100, 80, 1, 50, 40, 140}
	expected := []byte{
		164, 14, 30, 171, 241, 190, 154, 199,
		107, 30, 17, 197, 251, 73, 100, 112,
		96, 206, 79, 246, 40, 65, 123, 115,
		45, 237, 94, 213, 90, 50, 92, 55}

	actual := ComputeSHA256(key, msg)

	if !bytes.Equal(expected, actual) {
		t.Error("Expected:", expected, "Actual:", actual)
	}
}
