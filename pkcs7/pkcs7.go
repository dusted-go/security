package pkcs7

import (
	"bytes"
	"errors"
	"fmt"
)

// Pad adds padding to data.
func Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	}
	// Calculate the padding length
	padLen := blockSize - (len(data) % blockSize)

	// If the block perfectly fits then we still must apply
	// a minimum of one padding
	if padLen == 0 {
		padLen = blockSize
	}

	padding := []byte{byte(padLen)}

	// Repeat
	padding = bytes.Repeat(padding, padLen)

	// Append the padding to the data
	return append(data, padding...), nil
}

// Unpad removes padding from data.
func Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	}
	if len(data)%blockSize != 0 || len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: Invalid data length %d", len(data))
	}

	// The last byte is the length of padding.
	padLen := int(data[len(data)-1])

	// Check padding integrity.
	// All bytes should be the same.
	padding := data[len(data)-padLen:]

	for _, padByte := range padding {
		if padByte != byte(padLen) {
			return nil, errors.New("pkcs7: Invalid padding")
		}
	}

	return data[:len(data)-padLen], nil
}
