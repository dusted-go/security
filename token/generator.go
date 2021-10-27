package token

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dusted-go/security/aes"
	"github.com/dusted-go/security/sig"
)

// Generator allows to generate signed and encrypted tokens.
type Generator struct {
	now           func() time.Time
	encryptionKey []byte
	signingKey    []byte
}

// NewGenerator creates a new token generator.
func NewGenerator(
	encryptionKey []byte,
	signingKey []byte) *Generator {
	if encryptionKey == nil {
		panic("encryptionKey cannot be nil.")
	}
	if signingKey == nil {
		panic("signingKey cannot be nil.")
	}
	return &Generator{
		now:           time.Now,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
	}
}

func (g *Generator) Generate(kind string, data []byte, ttl time.Duration) (string, error) {
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
