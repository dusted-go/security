package pwd

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/dusted-go/security/compare"
	"github.com/dusted-go/security/rng"

	"github.com/dusted-go/encoding/base62"

	"golang.org/x/crypto/pbkdf2"
)

// ------------------
// Private Types
// ------------------

// Function to generate a new salt.
type generateSaltFunc = func(int) []byte

// Password hashing algorithm.
type computeHashFunc = func(password []byte, salt []byte) []byte

// Factory to create a password hashing algorithm.
type computeHashFactoryFunc = func(strategy string) (computeHashFunc, error)

type parsePasswordHashFunc = func(passwordHash string) (*passwordHash, error)

// Type to represent a password hash.
type passwordHash struct {
	salt       []byte
	hash       []byte
	strategy   string
	base64Salt string
	base64Hash string
}

// Type to generate password hashes.
type passwordHasher struct {
	generateSalt generateSaltFunc
	computeHash  computeHashFunc
	strategy     string
}

// Type to validate password hashes.
type passwordValidator struct {
	parsePasswordHash  parsePasswordHashFunc
	computeHashFactory computeHashFactoryFunc
	defaultStrategy    string
}

// ------------------
// Settings
// ------------------

// Current default hashing strategy.
var defaultStrategy string = "pbkdf2/hmacsha256/12/G8"

// Map of currently supported hashing strategies.
var supportedStrategies = map[string]computeHashFactoryFunc{
	"pbkdf2": createPbkdf2Fn}

// ------------------
// Hashing Factories
// ------------------

// Factory method to create the PBKDF2 key stretching algorithm.
func createPbkdf2Fn(strategy string) (computeHashFunc, error) {
	errInvalidStrategy := errors.New("invalid strategy, cannot create PBKDF2 hashing function")

	// PBKDF2 has 4 required parameters:
	// 1. Identifier string (pbkdf2)
	// 2. The underlying hashing algorithm (e.g. SHA256)
	// 3. The length of the resulting hash
	// 4. The number of iterations to stretch the key
	expectedArgs := 4
	args := strings.SplitN(strategy, "/", expectedArgs)
	if len(args) != expectedArgs {
		return nil, errInvalidStrategy
	}

	hashFuncName, encHashLength, encIterations := args[1], args[2], args[3]

	// Currently only HMAC-SHA256 supported:
	if hashFuncName != "hmacsha256" {
		return nil, errInvalidStrategy
	}

	hashFunc := sha256.New
	hashLength := base62.DecodeToInt(encHashLength)
	iterations := base62.DecodeToInt(encIterations)

	computeHash := func(password []byte, salt []byte) []byte {
		return pbkdf2.Key(
			password,
			salt,
			iterations,
			hashLength,
			hashFunc)
	}
	return computeHash, nil
}

// Factory method which generates the correct hashing function based on the given strategy.
func createPasswordHashingStrategy(strategy string) (computeHashFunc, error) {
	errInvalidStrategy := errors.New("invalid strategy, cannot create password hashing function")
	if strategy == "" {
		return nil, errInvalidStrategy
	}

	for key, createHash := range supportedStrategies {
		if strings.HasPrefix(strategy, key) {
			return createHash(strategy)
		}
	}

	return nil, errInvalidStrategy
}

func newHasher(
	generateSalt generateSaltFunc,
	computeHashFactory computeHashFactoryFunc,
	strategy string) *passwordHasher {

	computeHash, err := computeHashFactory(strategy)

	if err != nil {
		panic(fmt.Errorf("failed to create a hash function: %w", err))
	}

	return &passwordHasher{
		generateSalt: generateSalt,
		computeHash:  computeHash,
		strategy:     strategy}
}

func newValidator(
	parsePasswordHash parsePasswordHashFunc,
	computeHashFactory computeHashFactoryFunc,
	defaultStrategy string) *passwordValidator {

	return &passwordValidator{
		parsePasswordHash:  parsePasswordHash,
		computeHashFactory: computeHashFactory,
		defaultStrategy:    defaultStrategy}
}

// ------------------
// Private helper functions
// ------------------

func parsePasswordHash(pwdh string) (*passwordHash, error) {
	errInvalidPwdh := fmt.Errorf("string is not a valid passwordHash: %v", pwdh)

	// If the hash doesn't consist of 3 parts (strategy, salt, hash) then it's invalid
	if pwdh == "" {
		return nil, errInvalidPwdh
	}

	expectedParts := 3
	actualParams := strings.Split(pwdh, ".")
	if len(actualParams) != expectedParts {
		return nil, errInvalidPwdh
	}

	// Get the strategy, encoded salt and encoded hash in the correct order
	strategy, encSalt, encHash := actualParams[0], actualParams[1], actualParams[2]

	// If the salt is not base64 encoded then it's an invalid hash
	salt, err := base64.StdEncoding.DecodeString(encSalt)
	if err != nil {
		return nil, errInvalidPwdh
	}

	// If the hash is not base64 encoded then it's an invalid hash
	hash, err := base64.StdEncoding.DecodeString(encHash)
	if err != nil {
		return nil, errInvalidPwdh
	}

	// Return decomposed passwordHash
	return &passwordHash{
		salt:       salt,
		hash:       hash,
		strategy:   strategy,
		base64Salt: encSalt,
		base64Hash: encHash}, nil
}

// ------------------
// Private type Methods
// ------------------

// Returns the string representation of a passwordHash.
// Use this value to store in a database.
func (pwdh *passwordHash) String() string {
	return fmt.Sprintf(
		"%s.%s.%s",
		pwdh.strategy,
		pwdh.base64Salt,
		pwdh.base64Hash)
}

func (h *passwordHasher) computePasswordHash(password string) *passwordHash {
	salt := h.generateSalt(32)
	hash := h.computeHash([]byte(password), salt)

	return &passwordHash{
		salt:       salt,
		hash:       hash,
		strategy:   h.strategy,
		base64Salt: base64.StdEncoding.EncodeToString(salt),
		base64Hash: base64.StdEncoding.EncodeToString(hash)}
}

func (v *passwordValidator) validatePassword(password string, pwdh *passwordHash) (ok bool, isHashOutdated bool) {
	// Set default return values
	ok = false
	isHashOutdated = false

	// Return early if nothing to compare
	if password == "" || pwdh == nil {
		return
	}

	// Get the hashing function
	computeHash, err := v.computeHashFactory(pwdh.strategy)
	if err != nil {
		return
	}

	// Compute the actual hash
	computedHash := computeHash([]byte(password), pwdh.salt)

	// Set return values and finish
	ok = compare.Hashes(pwdh.hash, computedHash)
	isHashOutdated = ok && pwdh.strategy != v.defaultStrategy
	return
}

// ------------------
// Exported
// ------------------

// Hasher implements password hashing methods.
type Hasher interface {
	ComputeHash(string) string
}

// Validator implements password validation methods.
type Validator interface {
	ValidatePassword(password string, passwordHash string) (ok bool, isHashOutdated bool)
}

func (h *passwordHasher) ComputeHash(password string) string {
	return h.computePasswordHash(password).String()
}

func (v *passwordValidator) ValidatePassword(password string, passwordHash string) (ok bool, isHashOutdated bool) {
	pwdh, err := v.parsePasswordHash(passwordHash)
	if err != nil {
		return false, false
	}
	return v.validatePassword(password, pwdh)
}

// NewHasher creates a new Hasher instance.
func NewHasher() Hasher {
	return newHasher(
		rng.GenerateBytes,
		createPasswordHashingStrategy,
		defaultStrategy)
}

// NewValidator creates a new Validator instance.
func NewValidator() Validator {
	return newValidator(
		parsePasswordHash,
		createPasswordHashingStrategy,
		defaultStrategy)
}
