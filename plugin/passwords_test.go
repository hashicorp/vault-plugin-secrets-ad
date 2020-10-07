package plugin

import (
	"context"
	"fmt"
	"regexp"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	type testCase struct {
		passConf  passwordConf
		generator passwordGenerator

		passwordAssertion func(t *testing.T, password string)
		expectErr         bool
	}

	tests := map[string]testCase{
		"missing configs": {
			passConf: passwordConf{
				Length:         0,
				Formatter:      "",
				PasswordPolicy: "",
			},
			generator: nil,

			passwordAssertion: assertNoPassword,
			expectErr:         true,
		},
		"policy failure": {
			passConf: passwordConf{
				PasswordPolicy: "testpolicy",
			},
			generator:         makePasswordGenerator("", fmt.Errorf("test error")),
			passwordAssertion: assertNoPassword,
			expectErr:         true,
		},
		"successful policy": {
			passConf: passwordConf{
				PasswordPolicy: "testpolicy",
			},
			generator:         makePasswordGenerator("testpassword", nil),
			passwordAssertion: assertPassword("testpassword"),
			expectErr:         false,
		},
		"deprecated with no formatter": {
			passConf: passwordConf{
				Length: 50,
			},
			passwordAssertion: assertPasswordRegex(
				fmt.Sprintf("^%s[a-zA-Z0-9]{%d}$",
					regexp.QuoteMeta(passwordComplexityPrefix),
					50-len(passwordComplexityPrefix),
				),
			),
			expectErr: false,
		},
		"deprecated with formatter prefix": {
			passConf: passwordConf{
				Length:    50,
				Formatter: "foobar{{PASSWORD}}",
			},
			passwordAssertion: assertPasswordRegex("^foobar[a-zA-Z0-9]{44}$"),
			expectErr:         false,
		},
		"deprecated with formatter suffix": {
			passConf: passwordConf{
				Length:    50,
				Formatter: "{{PASSWORD}}foobar",
			},
			passwordAssertion: assertPasswordRegex("^[a-zA-Z0-9]{44}foobar$"),
			expectErr:         false,
		},
		"deprecated with formatter prefix and suffix": {
			passConf: passwordConf{
				Length:    50,
				Formatter: "foo{{PASSWORD}}bar",
			},
			passwordAssertion: assertPasswordRegex("^foo[a-zA-Z0-9]{44}bar$"),
			expectErr:         false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			password, err := GeneratePassword(context.Background(), test.passConf, test.generator)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			test.passwordAssertion(t, password)
		})
	}
}

func assertNoPassword(t *testing.T, password string) {
	t.Helper()
	if password != "" {
		t.Fatalf("password should be empty")
	}
}

func assertPassword(expectedPassword string) func(*testing.T, string) {
	return func(t *testing.T, password string) {
		t.Helper()
		if password != expectedPassword {
			t.Fatalf("Expected password %q but was %q", expectedPassword, password)
		}
	}
}

func assertPasswordRegex(rawRegex string) func(*testing.T, string) {
	re := regexp.MustCompile(rawRegex)
	return func(t *testing.T, password string) {
		t.Helper()
		if !re.MatchString(password) {
			t.Fatalf("Password %q does not match regexp %q", password, rawRegex)
		}
	}
}

type fakeGenerator struct {
	password string
	err      error
}

func (g fakeGenerator) GeneratePasswordFromPolicy(_ context.Context, _ string) (password string, err error) {
	return g.password, g.err
}

func makePasswordGenerator(returnedPass string, returnedErr error) passwordGenerator {
	return fakeGenerator{
		password: returnedPass,
		err:      returnedErr,
	}
}
