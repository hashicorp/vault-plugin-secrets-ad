package plugin

import (
	"bytes"
	"encoding/json"
	"testing"
)

// These json snippets are only used in our internal storage,
// they aren't presented externally.
const (
	samplePreviousConfJson = `{
	  "PasswordConf": {
		"ttl": 1,
		"max_ttl": 1,
		"length": 1,
		"formatter": "something"
	  },
	  "ADConf": {
		"url": "www.somewhere.com",
		"userdn": "userdn",
		"groupdn": "groupdn",
		"groupfilter": "groupFilter",
		"groupattr": "groupattr",
		"upndomain": "upndomain",
		"userattr": "",
		"certificate": "",
		"insecure_tls": false,
		"starttls": false,
		"binddn": "",
		"bindpass": "",
		"deny_null_bind": false,
		"discoverdn": false,
		"tls_min_version": "",
		"tls_max_version": ""
	  }
	}`

	sampleCurrentConfJson = `{
	  "PasswordConf": {
		"ttl": 1,
		"max_ttl": 1,
		"length": 1,
		"formatter": "something"
	  },
	  "ADConf": {
		"url": "www.somewhere.com",
		"userdn": "userdn",
		"groupdn": "groupdn",
		"groupfilter": "groupFilter",
		"groupattr": "groupattr",
		"upndomain": "upndomain",
		"userattr": "",
		"certificate": "",
		"insecure_tls": false,
		"starttls": false,
		"binddn": "",
		"bindpass": "",
		"deny_null_bind": false,
		"discoverdn": false,
		"tls_min_version": "",
		"tls_max_version": "",
		"last_bind_password": "foo"
	  }
	}`
)

func TestCanUnmarshalPreviousConfig(t *testing.T) {
	testConf := &configuration{}
	if err := json.NewDecoder(bytes.NewReader([]byte(samplePreviousConfJson))).Decode(testConf); err != nil {
		t.Fatal(err)
	}
	if testConf.PasswordConf.Formatter != "something" {
		t.Fatal("test failed to unmarshal password conf")
	}
	if testConf.ADConf.Url != "www.somewhere.com" {
		t.Fatal("test failed to unmarshal active directory client conf")
	}
}

func TestCanUnmarshalNewConfig(t *testing.T) {
	testConf := &configuration{}
	if err := json.NewDecoder(bytes.NewReader([]byte(sampleCurrentConfJson))).Decode(testConf); err != nil {
		t.Fatal(err)
	}
	if testConf.ADConf.LastBindPassword != "foo" {
		t.Fatal("test failed to unmarshal bind password information")
	}
}

func TestValidatePasswordConf(t *testing.T) {
	type testCase struct {
		conf      passwordConf
		expectErr bool
	}

	tests := map[string]testCase{
		"default config errors": {
			conf:      passwordConf{},
			expectErr: true,
		},
		"has policy": {
			conf: passwordConf{
				PasswordPolicy: "testpolicy",
			},
			expectErr: false,
		},
		"has policy name and length": {
			conf: passwordConf{
				PasswordPolicy: "testpolicy",
				Length:         20,
			},
			expectErr: true,
		},
		"has policy name and formatter": {
			conf: passwordConf{
				PasswordPolicy: "testpolicy",
				Formatter:      "foo{{PASSWORD}}",
			},
			expectErr: true,
		},
		"has policy name and length and formatter": {
			conf: passwordConf{
				PasswordPolicy: "testpolicy",
				Length:         20,
				Formatter:      "foo{{PASSWORD}}",
			},
			expectErr: true,
		},
		"no formatter, long length": {
			conf: passwordConf{
				Length: minimumLengthOfComplexString + len(passwordComplexityPrefix),
			},
			expectErr: false,
		},
		"no formatter, too short": {
			conf: passwordConf{
				Length: minimumLengthOfComplexString + len(passwordComplexityPrefix) - 1,
			},
			expectErr: true,
		},
		"has formatter, long length": {
			conf: passwordConf{
				Length:    minimumLengthOfComplexString + len("foo"),
				Formatter: "foo{{PASSWORD}}",
			},
			expectErr: false,
		},
		"has formatter, short length": {
			conf: passwordConf{
				Length:    minimumLengthOfComplexString + len("foo") - 1,
				Formatter: "foo{{PASSWORD}}",
			},
			expectErr: true,
		},
		"has formatter, missing PASSWORD field": {
			conf: passwordConf{
				Length:    20,
				Formatter: "abcde",
			},
			expectErr: true,
		},
		"has formatter, too many PASSWORD fields": {
			conf: passwordConf{
				Length:    50,
				Formatter: "foo{{PASSWORD}}{{PASSWORD}}",
			},
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.conf.validate()
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
		})
	}
}
