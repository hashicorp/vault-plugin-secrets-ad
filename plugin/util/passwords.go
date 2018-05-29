package util

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/go-uuid"
)

var (
	pwdFieldTmpl = "{{PASSWORD}}"

	// Per https://en.wikipedia.org/wiki/Password_strength#Guidelines_for_strong_passwords
	minimumLengthOfComplexString = 8

	PasswordComplexityPrefix = "?@09AZ"
	MinimumPasswordLength    = len(PasswordComplexityPrefix) + minimumLengthOfComplexString
)

func GeneratePassword(formatter string, desiredLength int) (string, error) {
	if desiredLength < MinimumPasswordLength {
		return "", fmt.Errorf("it's not possible to generate a _secure_ password of length %d, please boost length to %d, though Vault recommends higher", desiredLength, MinimumPasswordLength)
	}
	result, err := generatePassword(desiredLength)
	if err != nil {
		return "", err
	}
	if formatter == "" {
		result = PasswordComplexityPrefix + result
		return result[:desiredLength], nil
	}
	numPasswordFields := strings.Count(formatter, pwdFieldTmpl)
	if numPasswordFields == 0 {
		return "", fmt.Errorf("%s must contain password replacement field of %s", formatter, pwdFieldTmpl)
	}

	// Use the password generated earlier before generating more.
	formatter = strings.Replace(formatter, pwdFieldTmpl, result[:desiredLength], 1)

	for i := 1; i < numPasswordFields; i++ {
		result, err = generatePassword(desiredLength)
		if err != nil {
			return "", err
		}
		formatter = strings.Replace(formatter, pwdFieldTmpl, result[:desiredLength], 1)
	}
	return formatter, nil
}

func generatePassword(desiredLength int) (string, error) {
	b, err := uuid.GenerateRandomBytes(desiredLength)
	if err != nil {
		return "", err
	}
	result := ""
	// Though the result should immediately be longer than the desiredLength,
	// do this in a loop to ensure there's absolutely no risk of a panic when slicing it down later.
	for len(result) <= desiredLength {
		// Encode to base64 because it's more complex.
		result += base64.StdEncoding.EncodeToString(b)
	}
	return result, nil
}
