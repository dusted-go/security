package aes

import (
	"bytes"
	"testing"
)

func Test_EncryptAndDecrypt_ReturnsInitialMessage(t *testing.T) {
	key := []byte{
		96, 245, 15, 133, 99, 15, 153,
		159, 49, 74, 43, 238, 216, 14,
		67, 167, 96, 245, 15, 133, 99,
		15, 153, 159, 49, 74, 43, 238,
		216, 14, 67, 167}
	plain := []byte{255, 166, 255, 18, 245, 164, 155, 234, 219, 108, 114, 42, 90}

	cipher, err := Encrypt(key, plain)
	if err != nil {
		t.Error("Error when encrypting message.")
	}

	plain2, err := Decrypt(key, cipher)
	if err != nil {
		t.Error("Error when decrypting message.")
	}

	if !bytes.Equal(plain, plain2) {
		t.Error("Expected:", plain, "Actual:", string(plain2))
	}
}

func Test_Decrypt_WithEncryptedMessageFromDotnet_ReturnsCorrectPlainMessage(t *testing.T) {
	key := []byte{
		96, 245, 15, 133, 99, 15, 153, 159,
		49, 74, 43, 238, 216, 14, 67, 167,
		96, 245, 15, 133, 99, 15, 153, 159,
		49, 74, 43, 238, 216, 14, 67, 167}
	cipher := []byte{
		247, 221, 84, 208, 24, 176, 34, 8,
		204, 97, 104, 105, 135, 59, 176, 47,
		198, 159, 180, 111, 229, 139, 35, 0,
		18, 11, 70, 154, 6, 140, 62, 17, 8,
		198, 71, 238, 10, 196, 59, 198, 0, 75,
		219, 223, 197, 145, 88, 40, 181, 196,
		25, 22, 8, 132, 180, 127, 73, 31, 21,
		188, 55, 97, 168, 197}
	expected := "The world is flat, but don't tell anyone."

	plain, err := Decrypt(key, cipher)
	if err != nil {
		t.Error("Error when decrypting message.")
	}

	if expected != string(plain) {
		t.Error("Expected:", expected, "Actual:", string(plain))
	}
}
