package token

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/dusted-go/security/aes"
	"github.com/dusted-go/security/sig"
)

// Validator can validate and decrypt a signed token.
type Validator interface {
	Validate(kind string, token string) (data []byte, err error)
}

type validator struct {
	now           func() time.Time
	encryptionKey []byte
	signingKey    []byte
}

// NewValidator creates a new token validator.
func NewValidator(
	now func() time.Time,
	encryptionKey []byte,
	signingKey []byte) Validator {
	if now == nil {
		panic("now function parameter cannot be nil.")
	}
	if encryptionKey == nil {
		panic("encryptionKey parameter cannot be nil.")
	}
	if signingKey == nil {
		panic("signingKey parameter cannot be nil.")
	}
	return &validator{
		now:           now,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
	}
}

// CreateValidateFunc creates a new `tokens.ValidateFunc` function.
func (v *validator) Validate(kind string, token string) (verifiedData []byte, err error) {
	// 0. Set default return values
	errToken := errors.New("token is missing, invalid or has expired")

	// 1. Check that the token is not empty
	if token == "" {
		return nil, errToken
	}

	// 2. Decompose the token into the two core parts: signature and encrypted data
	expectedTokenParams := 2
	tokenParts := strings.SplitN(token, ".", expectedTokenParams)
	if len(tokenParts) != expectedTokenParams {
		return nil, errToken
	}

	// 3. Base64 decode the signature and data
	signature, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errToken
	}

	cipher, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errToken
	}

	// 4. Validate the signature before anything else
	if !sig.ValidateSHA256(v.signingKey, cipher, signature) {
		return nil, errToken
	}

	// 5. Decrypt the cipher message
	plain, err := aes.Decrypt(v.encryptionKey, cipher)
	if err != nil {
		return nil, errToken
	}

	// 6. Message consists of three parts, the token kind, data and the expiry date
	expectedMsgParams := 3
	msgParts := strings.SplitN(string(plain), ".", expectedMsgParams)
	if len(msgParts) != expectedMsgParams {
		return nil, errToken
	}

	// 7. Validate if the received token kind is the expected kind
	// (e.g. a session token should not pass the validation for a password reset token)
	expectedKind := msgParts[0]
	if err != nil || kind != expectedKind {
		return nil, errToken
	}

	// 8. Validate the expiry of the token
	expiry, err := time.Parse(time.RFC3339, msgParts[2])
	if err != nil {
		return nil, errToken
	}

	if v.now().UTC().After(expiry) {
		return nil, errToken
	}

	// 9. Base64 decode data
	data, err := base64.RawURLEncoding.DecodeString(msgParts[1])
	if err != nil {
		return nil, errToken
	}

	// 10. Return validated result
	return data, nil
}
