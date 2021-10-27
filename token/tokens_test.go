package token

import (
	"testing"
	"time"
)

func Test_RoundTrip(t *testing.T) {
	encryptionKey := []byte{
		253, 150, 41, 236, 229, 202, 10, 148,
		19, 143, 142, 173, 2, 221, 195, 68,
		196, 180, 143, 219, 86, 140, 248, 46,
		94, 222, 169, 200, 175, 219, 104, 138}
	signingKey := []byte("some-stupid-secret-key")
	tokenData := "bla bla FOO!BAR" // nolint
	duration, _ := time.ParseDuration("30m")

	generator :=
		NewGenerator(
			encryptionKey,
			signingKey)

	token, err := generator.Generate("1", []byte(tokenData), duration)
	if err != nil {
		t.Error("Unexpected error when generating token:", err.Error())
	}

	validator :=
		NewValidator(
			encryptionKey,
			signingKey)

	verifiedData, err := validator.Validate("1", token)
	if err != nil {
		t.Error("Unexpected error when validating token:", err.Error())
	}
	if string(verifiedData) != tokenData {
		t.Error("Expected:", tokenData, "Actual:", string(verifiedData))
	}
}
