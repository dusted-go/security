package pwd

import (
	"fmt"
	"unicode"
)

// PolicyFunc validates a password against a set of rules.
type PolicyFunc = func(password string) (ok bool, errMsgs []string)

type matchFunc = func(rune) bool
type validateFunc = func(password string) (ok bool, errMsg string)

func genericValidateFunc(match matchFunc, minCount int, group string) validateFunc {
	return func(password string) (ok bool, errMsg string) {
		ok = true
		errMsg = ""
		count := 0
		for _, r := range password {
			if match(r) {
				count++
			}
		}
		if count < minCount {
			ok = false
			errMsg = fmt.Sprintf("password must have at least %v %v", minCount, group)
		}
		return
	}
}

// UpperCaseCheck validates that a password to contains uppercase letters.
func UpperCaseCheck(minCount int) validateFunc {
	group := "uppercase letter"
	if minCount > 1 {
		group += "s"
	}
	return genericValidateFunc(unicode.IsUpper, minCount, group)
}

// LowerCaseCheck validates that a password to contains lowercase letters.
func LowerCaseCheck(minCount int) validateFunc {
	group := "lowercase letter"
	if minCount > 1 {
		group += "s"
	}
	return genericValidateFunc(unicode.IsLower, minCount, group)
}

// DigitsCheck validates that a password to contains digits.
func DigitsCheck(minCount int) validateFunc {
	group := "digit"
	if minCount > 1 {
		group += "s"
	}
	return genericValidateFunc(unicode.IsDigit, minCount, group)
}

// SpecialCharCheck validates that a password to contains special characters.
func SpecialCharCheck(minCount int) validateFunc {
	special := "!@£$%^&*()_-+={}[]€#:;\"'|\\?/<>,.~`§±"
	check := func(r rune) bool {
		for _, c := range special {
			if r == c {
				return true
			}
		}
		return false
	}
	group := "special character"
	if minCount > 1 {
		group += "s"
	}
	return genericValidateFunc(check, minCount, group)
}

// LengthCheck validates that a password meets a minimum length.
func LengthCheck(minLength int) validateFunc {
	return func(password string) (ok bool, errMsg string) {
		if len(password) < minLength {
			return false, fmt.Sprintf("password does not meet the minimum length of %v characters", minLength)
		}
		return true, ""
	}
}

// Policy combines multiple different password validation functions into a single `PolicyFunc`.
func Policy(funcs ...validateFunc) PolicyFunc {
	return func(password string) (ok bool, errMsgs []string) {
		for _, f := range funcs {
			if ok, errMsg := f(password); !ok {
				errMsgs = append(errMsgs, errMsg)
			}
		}
		return len(errMsgs) == 0, errMsgs
	}
}

// DefaultPolicy creates the default password policy.
var DefaultPolicy PolicyFunc = Policy(
	LengthCheck(8),
	UpperCaseCheck(1),
	LowerCaseCheck(1),
	DigitsCheck(1),
	SpecialCharCheck(1),
)
