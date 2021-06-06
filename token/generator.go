package token

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dusted-go/security/aes"
	"github.com/dusted-go/security/sig"
)

// Generator allows to generate signed and encrypted tokens.
type Generator interface {
	Generate(kind string, data []byte, ttl time.Duration) (token string, err error)
}

type generator struct {
	now           func() time.Time
	encryptionKey []byte
	signingKey    []byte
}

// NewGenerator creates a new token generator.
func NewGenerator(
	now func() time.Time,
	encryptionKey []byte,
	signingKey []byte) Generator {
	if now == nil {
		panic("now function parameter cannot be nil.")
	}
	if encryptionKey == nil {
		panic("encryptionKey parameter cannot be nil.")
	}
	if signingKey == nil {
		panic("signingKey parameter cannot be nil.")
	}
	return &generator{
		now:           now,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
	}
}

func (g *generator) Generate(kind string, data []byte, ttl time.Duration) (string, error) {
	// 1. Generate expiry date
	expiry := g.now().UTC().Add(ttl)

	// 2. Concatenate the token parts
	encodedData := base64.RawURLEncoding.EncodeToString(data)
	plainText := fmt.Sprintf("%s.%s.%s", kind, encodedData, expiry.Format(time.RFC3339))

	// 3. Encrypt the data
	cipher, err := aes.Encrypt(g.encryptionKey, []byte(plainText))
	if err != nil {
		return "", fmt.Errorf("could not generate token: %w", err)
	}

	// 4. Compute a signature
	signature := sig.ComputeSHA256(g.signingKey, cipher)

	// 5. Concatenate signature and data into token
	token := fmt.Sprintf(
		"%s.%s",
		base64.RawURLEncoding.EncodeToString(signature),
		base64.RawURLEncoding.EncodeToString(cipher))

	return token, nil

}
