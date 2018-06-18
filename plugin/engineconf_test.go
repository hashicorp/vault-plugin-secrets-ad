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
