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

// saltFunc generates a new salt.
type saltFunc = func(int) []byte

// hashFunc computes a hash of a given password and salt.
type hashFunc = func(password []byte, salt []byte) []byte

// hashFuncFactory creates a hashFunc from a given strategy.
type hashFuncFactory = func(strategy string) (hashFunc, error)

// parseHashFunc parsed a password hash.
type parseHashFunc = func(passwordHash string) (*passwordHash, error)

// Type to represent a password hash.
type passwordHash struct {
	salt       []byte
	hash       []byte
	strategy   string
	base64Salt string
	base64Hash string
}

// Returns the string representation of a passwordHash.
// Use this value to store in a database.
func (pwdh *passwordHash) String() string {
	return fmt.Sprintf(
		"%s.%s.%s",
		pwdh.strategy,
		pwdh.base64Salt,
		pwdh.base64Hash)
}

// ------------------
// Settings
// ------------------

// Current default hashing strategy.
var defaultStrategy string = "pbkdf2/hmacsha256/12/G8"

// Map of currently supported hashing strategies.
var supportedStrategies = map[string]hashFuncFactory{
	"pbkdf2": createPbkdf2Fn}

// ------------------
// Private helper functions
// ------------------

// Factory method to create the PBKDF2 key stretching algorithm.
func createPbkdf2Fn(strategy string) (hashFunc, error) {
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
func createPasswordHashingStrategy(strategy string) (hashFunc, error) {
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
// Hash Generator
// ------------------

type Hasher struct {
	generateSalt saltFunc
	computeHash  hashFunc
	strategy     string
}

func newHasher(
	generateSalt saltFunc,
	computeHashFactory hashFuncFactory,
	strategy string) *Hasher {

	computeHash, err := computeHashFactory(strategy)

	if err != nil {
		panic(fmt.Errorf("failed to create a hash function: %w", err))
	}

	return &Hasher{
		generateSalt: generateSalt,
		computeHash:  computeHash,
		strategy:     strategy}
}

func (h *Hasher) computePasswordHash(password string) *passwordHash {
	if h.generateSalt == nil {
		panic("generateSalt cannot be nil")
	}
	if h.computeHash == nil {
		panic("computeHash cannot be nil")
	}

	salt := h.generateSalt(32)
	hash := h.computeHash([]byte(password), salt)

	return &passwordHash{
		salt:       salt,
		hash:       hash,
		strategy:   h.strategy,
		base64Salt: base64.StdEncoding.EncodeToString(salt),
		base64Hash: base64.StdEncoding.EncodeToString(hash)}
}

func (h *Hasher) ComputeHash(password string) string {
	return h.computePasswordHash(password).String()
}

// NewHasher creates a new Hasher instance.
func NewHasher() *Hasher {
	return newHasher(
		rng.GenerateBytes,
		createPasswordHashingStrategy,
		defaultStrategy)
}

// ------------------
// Hash Validator
// ------------------

type Validator struct {
	parseHash          parseHashFunc
	computeHashFactory hashFuncFactory
	defaultStrategy    string
}

func newValidator(
	parseHash parseHashFunc,
	computeHashFactory hashFuncFactory,
	defaultStrategy string) *Validator {

	return &Validator{
		parseHash:          parseHash,
		computeHashFactory: computeHashFactory,
		defaultStrategy:    defaultStrategy}
}

func (v *Validator) validatePassword(p string, pwdh *passwordHash) (ok bool, needsUpgrade bool) {
	if v.computeHashFactory == nil {
		panic("computeHashFactory cannot be nil")
	}
	// Set default return values
	ok = false
	needsUpgrade = false

	// Return early if nothing to compare
	if p == "" || pwdh == nil {
		return
	}

	// Get the hashing function
	computeHash, err := v.computeHashFactory(pwdh.strategy)
	if err != nil {
		return
	}

	// Compute the actual hash
	computedHash := computeHash([]byte(p), pwdh.salt)

	// Set return values and finish
	ok = compare.Hashes(pwdh.hash, computedHash)
	needsUpgrade = ok && pwdh.strategy != v.defaultStrategy
	return
}

func (v *Validator) ValidatePassword(password string, passwordHash string) (ok bool, needsUpgrade bool) {
	if v.parseHash == nil {
		panic("parseHash cannot be nil")
	}
	pwdh, err := v.parseHash(passwordHash)
	if err != nil {
		return false, false
	}
	return v.validatePassword(password, pwdh)
}

// NewValidator creates a new Validator instance.
func NewValidator() *Validator {
	return newValidator(
		parsePasswordHash,
		createPasswordHashingStrategy,
		defaultStrategy)
}
