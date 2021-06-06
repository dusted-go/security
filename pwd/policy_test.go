package pwd

import "testing"

func Test_SpecialCharCheck(t *testing.T) {
	symbols := "!@£$%^&*()_-+={}[]€#:;\"'|\\?/<>,.~`§±"

	policy := SpecialCharCheck(1)

	for _, r := range symbols {
		s := string(r)
		if ok, _ := policy(s); !ok {
			t.Error("Character was expected to pass special character validation:", s)
		}
	}
}

func Test_Happy(t *testing.T) {
	password := "Just4Now"

	policyCheck := Policy(
		LengthCheck(8),
		DigitsCheck(1),
		LowerCaseCheck(1),
		UpperCaseCheck(1),
	)

	ok, _ := policyCheck(password)

	if !ok {
		t.Error("Password was expected to pass the password policy check:", password)
	}
}

func Test_Unhappy(t *testing.T) {
	invalidPasswords := []string{
		"to0sHo3t",
		"LongButNoDigits",
		"longanddigitsbutnouppercase10",
		"LONGBUTNOLOWERCASE10",
	}

	policyCheck := Policy(
		LengthCheck(10),
		DigitsCheck(1),
		LowerCaseCheck(1),
		UpperCaseCheck(1),
	)

	for _, pw := range invalidPasswords {
		ok, _ := policyCheck(pw)
		if ok {
			t.Error("Password was expected to violate the password policy:", pw)
		}
	}
}
