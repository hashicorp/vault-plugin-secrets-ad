package util

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	for desiredLength := -200; desiredLength < 200; desiredLength++ {

		password1, err := GeneratePassword("", desiredLength)

		if desiredLength < len(PasswordComplexityPrefix)+minimumLengthOfComplexString {
			if err == nil {
				t.Fatalf("desiredLength of %d should yield an error", desiredLength)
			} else {
				// password1 won't be populated, nothing more to check
				continue
			}
		}

		// desired length is appropriate
		if err != nil {
			t.Fatalf("desiredLength of %d generated an err: %s", desiredLength, err)
		}
		if len(password1) != desiredLength {
			t.Fatalf("unexpected password1 length of %d for desired length of %d", len(password1), desiredLength)
		}

		// let's generate a second password1 to ensure it's not the same
		password2, err := GeneratePassword("", desiredLength)
		if err != nil {
			t.Fatalf("desiredLength of %d generated an err: %s", desiredLength, err)
		}

		if password1 == password2 {
			t.Fatalf("received identical passwords of %s, random byte generation is broken", password1)
		}
	}
}

func TestFormatPassword(t *testing.T) {

	desiredLength := len("helloworld") + minimumLengthOfComplexString

	// Test with {{PASSWORD}} in the middle of the formatter.
	password, err := GeneratePassword("hello{{PASSWORD}}world", desiredLength)
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(password) != desiredLength {
		t.Fatalf("unexpected password length of %d in %s", len(password), password)
	}

	// Test with {{PASSWORD}} at the start of the formatter.
	password, err = GeneratePassword("{{PASSWORD}}helloworld", desiredLength)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(password) != desiredLength {
		t.Fatalf("unexpected password length of %d in %s", len(password), password)
	}

	// Test with {{PASSWORD}} at the end of the formatter.
	password, err = GeneratePassword("helloworld{{PASSWORD}}", desiredLength)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(password) != desiredLength {
		t.Fatalf("unexpected password length of %d in %s", len(password), password)
	}

	// Test with {{PASSWORD}} not provided so essentially they're trying to provide an unchanging password,
	// defeating the purpose of Vault.
	password, err = GeneratePassword("helloworld", desiredLength)
	if err == nil {
		t.Fatal("should have received an error because a static password was provided as the formatter")
	}

	// Test normal, non-custom formatting path.
	password, err = GeneratePassword("", desiredLength)
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(password) != desiredLength {
		t.Fatalf("unexpected password length of %d in %s", minimumLengthOfComplexString, password)
	}
	if !strings.HasPrefix(password, PasswordComplexityPrefix) {
		t.Fatalf("%s should have complexity prefix of %s", password, PasswordComplexityPrefix)
	}

	// Test password being provided twice. Should be two different passwords.
	password, err = GeneratePassword("hello{{PASSWORD}}worldhello{{PASSWORD}}world", minimumLengthOfComplexString)
	if err == nil {
		t.Fatal("should have an error because there are multiple pwd template fields")
	}
}
