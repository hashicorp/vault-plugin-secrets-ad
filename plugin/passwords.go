package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/base62"
)

var (
	// Per https://en.wikipedia.org/wiki/Password_strength#Guidelines_for_strong_passwords
	minimumLengthOfComplexString = 8

	passwordComplexityPrefix = "?@09AZ"
	pwdFieldTmpl             = "{{PASSWORD}}"
)

type passwordGenerator interface {
	GeneratePasswordFromPolicy(ctx context.Context, policyName string) (password string, err error)
}

func GeneratePassword(ctx context.Context, passConf passwordConf, generator passwordGenerator) (password string, err error) {
	err = passConf.validate()
	if err != nil {
		return "", err
	}

	if passConf.PolicyName != "" {
		return generator.GeneratePasswordFromPolicy(ctx, passConf.PolicyName)
	}
	return generateDeprecatedPassword(passConf.Formatter, passConf.Length)
}

func generateDeprecatedPassword(formatter string, totalLength int) (string, error) {
	pwd, err := base62.Random(totalLength)
	if err != nil {
		return "", err
	}
	if formatter == "" {
		pwd = passwordComplexityPrefix + pwd
		return pwd[:totalLength], nil
	}
	return strings.Replace(formatter, pwdFieldTmpl, pwd[:lengthOfPassword(formatter, totalLength)], 1), nil
}

func lengthOfPassword(formatter string, totalLength int) int {
	lengthOfText := len(formatter) - len(pwdFieldTmpl)
	return totalLength - lengthOfText
}
