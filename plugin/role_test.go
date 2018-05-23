package plugin

import (
	"testing"
	"time"

	"github.com/hashicorp/vault/logical/framework"
)

var (
	defaultLeaseTTLVal = time.Second * 100
	defaultTTLInt      = int(defaultLeaseTTLVal.Seconds())

	maxLeaseTTLVal = time.Second * 200
	maxTTLInt      = int(maxLeaseTTLVal.Seconds())

	schema = testBackend.pathRoles().Fields
)

func TestOnlyDefaultTTLs(t *testing.T) {
	passwordConf := &passwordConf{
		TTL:    defaultTTLInt,
		MaxTTL: maxTTLInt,
		Length: defaultPasswordLength,
	}

	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{
			"service_account_name": "kibana@example.com",
		},
		Schema: schema,
	}

	ttl, err := getValidatedTTL(passwordConf, fieldData)
	if err != nil {
		t.Fatal(err)
	}

	if ttl != defaultTTLInt {
		t.Fatal("ttl is not defaulting properly")
	}
}

func TestCustomOperatorTTLButDefaultRoleTTL(t *testing.T) {
	passwordConf := &passwordConf{
		TTL:    10,
		MaxTTL: maxTTLInt,
		Length: defaultPasswordLength,
	}

	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{
			"service_account_name": "kibana@example.com",
		},
		Schema: schema,
	}

	ttl, err := getValidatedTTL(passwordConf, fieldData)
	if err != nil {
		t.Fatal(err)
	}

	if ttl != 10 {
		t.Fatal("ttl is not defaulting properly")
	}
}

func TestTTLTooHigh(t *testing.T) {
	passwordConf := &passwordConf{
		TTL:    10,
		MaxTTL: 10,
		Length: defaultPasswordLength,
	}

	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{
			"service_account_name": "kibana@example.com",
			"ttl": 100,
		},
		Schema: schema,
	}

	_, err := getValidatedTTL(passwordConf, fieldData)
	if err == nil {
		t.Fatal("should error when ttl is too high")
	}
}

func TestNegativeTTL(t *testing.T) {
	passwordConf := &passwordConf{
		TTL:    10,
		MaxTTL: maxTTLInt,
		Length: defaultPasswordLength,
	}

	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{
			"service_account_name": "kibana@example.com",
			"ttl": -100,
		},
		Schema: schema,
	}

	_, err := getValidatedTTL(passwordConf, fieldData)
	if err == nil {
		t.Fatal("should error then ttl is negative")
	}
}
