package pwd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func areEqual(t *testing.T, expected interface{}, actual interface{}) {
	if expected != actual {
		t.Error("Expected:", expected, "Actual:", actual)
	}
}

func Test_createPasswordHashingStrategy_WithUnknownStrategy_ReturnsError(t *testing.T) {
	hashFunc, err := createPasswordHashingStrategy("unknown")

	if hashFunc != nil {
		t.Error("createPasswordHashingStrategy should not have instantiated a hashing function.")
	}

	if err == nil {
		t.Error("createPasswordHashingStrategy was expected to return an error.")
	}
}

func Test_createPasswordHashingStrategy_WithKnownStrategy_ReturnsError(t *testing.T) {
	hashFunc, err := createPasswordHashingStrategy("pbkdf2/hmacsha256/1/1")

	if hashFunc == nil {
		t.Error("createPasswordHashingStrategy was expected to create a hashing function.")
	}

	if err != nil {
		t.Error("createPasswordHashingStrategy returned an unexpected error: " + err.Error())
	}
}

func Test_parsePasswordHash_ParsesStringCorrectly(t *testing.T) {
	strategy, salt, hash := "blah", []byte{1, 3, 5}, []byte{9, 5, 0}
	str := fmt.Sprintf(
		"%v.%v.%v",
		strategy,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash))

	passwordHash, err := parsePasswordHash(str)

	if err != nil {
		t.Error("parsePasswordHash returned an unexpected error: " + err.Error())
	}
	areEqual(t, strategy, passwordHash.strategy)

	if !bytes.Equal(salt, passwordHash.salt) {
		t.Error("Expected:", salt, "Actual:", passwordHash.salt)
	}

	if !bytes.Equal(hash, passwordHash.hash) {
		t.Error("Expected:", hash, "Actual:", passwordHash.hash)
	}
}

func Test_ComputePasswordHash_WithPBKDF2_ReturnsCorrectHash(t *testing.T) {
	salt := []byte{
		118, 14, 90, 134, 133, 121, 243,
		223, 197, 125, 68, 206, 135, 80,
		102, 59, 160, 137, 69, 105, 121,
		201, 143, 199, 144, 250, 99, 44,
		46, 202, 71, 35}
	generateSaltMock := func(int) []byte { return salt }
	expected := "pbkdf2/hmacsha256/1S/RS.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.bq49IfnqhTqO0Lqf9s1FAR8GxnG53Ra+IYGdHa6ghu/F8H1zH4qSVTPlP2Nlh1ixkoLaYvvcyhYmbABg+h8Cw+3XIOk1No45h9MAlNs+24YMpk9aTa+F+tNE" // nolint: lll
	strategy := "pbkdf2/hmacsha256/1S/RS"
	computeHash, _ := createPbkdf2Fn(strategy)

	hasher := newHasher(
		generateSaltMock,
		func(string) (hashFunc, error) { return computeHash, nil },
		strategy)
	actual := hasher.ComputeHash("Just4Now!2019")

	areEqual(t, expected, actual)
}

func Test_ComputePasswordHash_WithPBKDF2and5Iterations_ReturnsCorrectHash(t *testing.T) {
	salt := []byte{
		118, 14, 90, 134, 133, 121, 243,
		223, 197, 125, 68, 206, 135, 80,
		102, 59, 160, 137, 69, 105, 121,
		201, 143, 199, 144, 250, 99, 44,
		46, 202, 71, 35}
	generateSaltMock := func(_ int) []byte { return salt }
	expected := "pbkdf2/hmacsha256/1S/5.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.z0OcRkumNrQwYzNk++JjqHPf3M53nfUdRXwG9AvvxWbXDwlIfKQqNpwNfiBtZoFHgxu7vfwZWTsrOIVJjtE7Vf8W6Yda+5kghh8471AMpsbMkm4pQD71Oa/8" // nolint: lll
	strategy := "pbkdf2/hmacsha256/1S/5"
	computeHash, _ := createPbkdf2Fn(strategy)

	hasher := newHasher(
		generateSaltMock,
		func(string) (hashFunc, error) { return computeHash, nil },
		strategy)
	actual := hasher.ComputeHash("Just4Now!2019")

	areEqual(t, expected, actual)
}

func Test_ComputePasswordHash_WithPBKDF2andSmallHashLengthAndLowIterations_ReturnsCorrectHash(t *testing.T) {
	salt := []byte{
		118, 14, 90, 134, 133, 121, 243, 223,
		197, 125, 68, 206, 135, 80, 102, 59,
		160, 137, 69, 105, 121, 201, 143, 199,
		144, 250, 99, 44, 46, 202, 71, 35}
	generateSaltMock := func(int) []byte { return salt }
	expected := "pbkdf2/hmacsha256/A/9.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.4xR4SWrsQI+InQ=="
	strategy := "pbkdf2/hmacsha256/A/9"
	computeHash, _ := createPbkdf2Fn(strategy)

	hasher := newHasher(
		generateSaltMock,
		func(string) (hashFunc, error) { return computeHash, nil },
		strategy)
	actual := hasher.ComputeHash("Just4Now!2019")

	areEqual(t, expected, actual)
}

func Test_ValidatePassword_WithCorrectPassword_ReturnsTrue(t *testing.T) {
	password := "Just4Now!2019"
	pwdHash := "pbkdf2/hmacsha256/12/G8.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.jLyCcDQoSCRAZGQ6epILRXydRYeg6kT+6GsGTuJQe9+iqkxl9cnLrMPtBig4ZuwmEhjP/uye0s0YIw6sS/xcJg==" // nolint
	expectedResult := true
	expectedUpgrade := false

	validator := NewValidator()
	actual, requiresUpgrade := validator.ValidatePassword(password, pwdHash)

	areEqual(t, expectedResult, actual)
	areEqual(t, expectedUpgrade, requiresUpgrade)
}

func Test_ValidatePassword_WithWrongPassword_ReturnsFalse(t *testing.T) {
	password := "wrong-PassWord"
	pwdHash := "pbkdf2/hmacsha256/1S/RS.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.jLyCcDQoSCRAZGQ6epILRXydRYeg6kT+6GsGTuJQe9+iqkxl9cnLrMPtBig4ZuwmEhjP/uye0s0YIw6sS/xcJg==" // nolint: gosec, lll
	expectedResult := false
	expectedUpgrade := false

	validator := NewValidator()
	actual, requiresUpgrade := validator.ValidatePassword(password, pwdHash)

	areEqual(t, expectedResult, actual)
	areEqual(t, expectedUpgrade, requiresUpgrade)
}

func Test_ValidatePassword_WithCorrectPasswordAndOutdatedHash_ReturnsTrueAndTrue(t *testing.T) {
	password := "Just4Now!2019"
	pwdHash := "pbkdf2/hmacsha256/A/9.dg5ahoV589/FfUTOh1BmO6CJRWl5yY/HkPpjLC7KRyM=.4xR4SWrsQI+InQ==" // nolint: gosec
	expectedResult := true
	expectedUpgrade := true

	validator := NewValidator()
	actual, requiresUpgrade := validator.ValidatePassword(password, pwdHash)

	areEqual(t, expectedResult, actual)
	areEqual(t, expectedUpgrade, requiresUpgrade)
}
