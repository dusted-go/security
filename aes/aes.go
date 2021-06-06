package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/dusted-go/security/pkcs7"
	"github.com/dusted-go/security/rng"
)

// Encrypt copmutes a cipher from a plain text message.
func Encrypt(key []byte, plain []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("encryption key must be either 16, 24 or 32 bytes long. Current key length: %v", keyLen)
	}

	// Use PKCS7 padding algorithm to pad the plaintext message:
	paddedPlain, err := pkcs7.Pad(plain, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("error when padding message with PKCS7: %w", err)
	}
	encryptedLen := len(paddedPlain)

	// Generate a random IV which matches the block size in length:
	ivLen := aes.BlockSize
	iv := rng.GenerateBytes(ivLen)

	// Generate a new block using the encryption key:
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error when creating new cipher: %w", err)
	}

	// Encrypt the padded message using CBC mode:
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, encryptedLen)
	mode.CryptBlocks(encrypted, paddedPlain)

	// Prepend the IV to the cipher:
	result := make([]byte, ivLen+encryptedLen)
	copy(result[:ivLen], iv)
	copy(result[ivLen:], encrypted)

	return result, nil
}

// Decrypt reverts a cipher into its original plaintext message.
func Decrypt(key, scrambled []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("encryption key must be either 16, 24 or 32 bytes long")
	}

	ivLen := aes.BlockSize
	iv := scrambled[:ivLen]
	encryptedBytes := scrambled[ivLen:]
	encryptedBytesLen := len(encryptedBytes)

	// Generate a new block using the encryption key:
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error when creating new cipher: %w", err)
	}

	// Decrypt the encrypted message using CBC mode:
	mode := cipher.NewCBCDecrypter(block, iv)
	paddedPlain := make([]byte, encryptedBytesLen)
	mode.CryptBlocks(paddedPlain, encryptedBytes)

	// Unpad the message
	plain, err := pkcs7.Unpad(paddedPlain, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("error when un-padding message with PKCS7: %w", err)
	}

	return plain, nil
}
