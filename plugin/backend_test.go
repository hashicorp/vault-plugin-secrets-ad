package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/client"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/util"
	"github.com/hashicorp/vault/helper/ldaputil"
	"github.com/hashicorp/vault/logical"
)

var (
	testCtx     = context.Background()
	testStorage = &logical.InmemStorage{}
	testBackend = func() *backend {
		conf := &logical.BackendConfig{
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: defaultLeaseTTLVal,
				MaxLeaseTTLVal:     maxLeaseTTLVal,
			},
		}
		b := newBackend(&fake{})
		b.Setup(context.Background(), conf)
		return b
	}()
)

func TestBackend(t *testing.T) {
	// Exercise all config endpoints.
	t.Run("write config", WriteConfig)
	t.Run("read config", ReadConfig)
	t.Run("delete config", DeleteConfig)

	// Plant a config for further testing.
	t.Run("plant config", PlantConfig)

	// Exercise all role endpoints.
	t.Run("write role", WriteRole)
	t.Run("read role", ReadRole)
	t.Run("list roles", ListRoles)
	t.Run("delete role", DeleteRole)

	// Plant a role for further testing.
	t.Run("plant role", WriteRole)

	// Exercise all cred endpoints.
	t.Run("read cred", ReadCred)
}

func WriteConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   testStorage,
		Data: map[string]interface{}{
			"binddn":      "tester",
			"password":    "pa$$w0rd",
			"url":         "ldap://138.91.247.105",
			"certificate": validCertificate,
			"userdn":      "dc=example,dc=com",
			"formatter":   "mycustom{{PASSWORD}}",
		},
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected no response because Vault generally doesn't return it for posts")
	}
}

func ReadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	// Did we get the response data we expect?
	if resp.Data["certificate"] != "\n-----BEGIN CERTIFICATE-----\nMIIF7zCCA9egAwIBAgIJAOY2qjn64Qq5MA0GCSqGSIb3DQEBCwUAMIGNMQswCQYD\nVQQGEwJVUzEQMA4GA1UECAwHTm93aGVyZTERMA8GA1UEBwwIVGltYnVrdHUxEjAQ\nBgNVBAoMCVRlc3QgRmFrZTENMAsGA1UECwwETm9uZTEPMA0GA1UEAwwGTm9ib2R5\nMSUwIwYJKoZIhvcNAQkBFhZkb25vdHRydXN0QG5vd2hlcmUuY29tMB4XDTE4MDQw\nMzIwNDQwOFoXDTE5MDQwMzIwNDQwOFowgY0xCzAJBgNVBAYTAlVTMRAwDgYDVQQI\nDAdOb3doZXJlMREwDwYDVQQHDAhUaW1idWt0dTESMBAGA1UECgwJVGVzdCBGYWtl\nMQ0wCwYDVQQLDAROb25lMQ8wDQYDVQQDDAZOb2JvZHkxJTAjBgkqhkiG9w0BCQEW\nFmRvbm90dHJ1c3RAbm93aGVyZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\nggIKAoICAQDzQPGErqjaoFcuUV6QFpSMU6w8wO8F0othik+rrlKERmrGonUGsoum\nWqRe6L4ZnxBvCKB6EWjvf894TXOF2cpUnjDAyBePISyPkRBEJS6VS2SEC4AJzmVu\na+P+fZr4Hf7/bEcUr7Ax37yGVZ5i5ByNHgZkBlPxKiGWSmAqIDRZLp9gbu2EkG9q\nNOjNLPU+QI2ov6U/laGS1vbE2LahTYeT5yscu9LpllxzFv4lM1f4wYEaM3HuOxzT\nl86cGmEr9Q2N4PZ2T0O/s6D4but7c6Bz2XPXy9nWb5bqu0n5bJEpbRFrkryW1ozh\nL9uVVz4dyW10pFBJtE42bqA4PRCDQsUof7UfsQF11D1ThrDfKsQa8PxrYdGUHUG9\nGFF1MdTTwaoT90RI582p+6XYV+LNlXcdfyNZO9bMThu9fnCvT7Ey0TKU4MfPrlfT\naIhZmyaHt6mL5p881UPDIvy7paTLgL+C1orLjZAiT//c4Zn+0qG0//Cirxr020UF\n3YiEFk2H0bBVwOHoOGw4w5HrvLdyy0ZLDSPQbzkSZ0RusHb5TjiyhtTk/h9vvJv7\nu1fKJub4MzgrBRi16ejFdiWoVuMXRC6fu/ERy3+9DH6LURerbPrdroYypUmTe9N6\nXPeaF1Tc+WO7O/yW96mV7X/D211qjkOtwboZC5kjogVbaZgGzjHCVwIDAQABo1Aw\nTjAdBgNVHQ4EFgQU2zWT3HeiMBzusz7AggVqVEL5g0UwHwYDVR0jBBgwFoAU2zWT\n3HeiMBzusz7AggVqVEL5g0UwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAgEAwTGcppY86mNRE43uOimeApTfqHJv+lGDTjEoJCZZmzmtxFe6O9+Vk4bH/8/i\ngVQvqzBpaWXRt9OhqlFMK7OkX4ZvqXmnShmxib1dz1XxGhbwSec9ca8bill59Jqa\nbIOq2SXVMcFD0GwFxfJRBVzHHuB6AwV9B2QN61zeB1oxNGJrUOo80jVkB7+MWMyD\nbQqiFCHWGMa6BG4N91KGOTveZCGdBvvVw5j6lt731KjbvL2hB1UHioucOweKLfa4\nQWDImTEjgV68699wKERNL0DCpeD7PcP/L3SY2RJzdyC1CSR7O8yU4lQK7uZGusgB\nMgup+yUaSjxasIqYMebNDDocr5kdwG0+2r2gQdRwc5zLX6YDBn6NLSWjRnY04ZuK\nP1cF68rWteWpzJu8bmkJ5r2cqskqrnVK+zz8xMQyEaj548Bnt51ARLHOftR9jkSU\nNJWh7zOLZ1r2UUKdDlrMoh3GQO3rvnCJJ16NBM1dB7TUyhMhtF6UOE62BSKdHtQn\nd6TqelcRw9WnDsb9IPxRwaXhvGljnYVAgXXlJEI/6nxj2T4wdmL1LWAr6C7DuWGz\n8qIvxc4oAau4DsZs2+BwolCFtYc98OjWGcBStBfZz/YYXM+2hKjbONKFxWdEPxGR\nBeq3QOqp2+dga36IzQybzPQ8QtotrpSJ3q82zztEvyWiJ7E=\n-----END CERTIFICATE-----\n" {
		t.Fatalf("expected certificate to be the given one but received %q", resp.Data["certificate"])
	}

	if resp.Data["userdn"] != "dc=example,dc=com" {
		t.Fatalf("expected dn to be \"dc=example,dc=com\" but received %q", resp.Data["userdn"])
	}

	if resp.Data["insecure_tls"].(bool) {
		t.Fatalf("expected insecure_tls to be false but received true")
	}

	if fmt.Sprintf("%s", resp.Data["url"]) != `ldap://138.91.247.105` {
		t.Fatalf("expected url to be \"ldap://138.91.247.105\" but received %q", fmt.Sprintf("%s", resp.Data["url"]))
	}

	if resp.Data["tls_min_version"].(string) != defaultTLSVersion {
		t.Fatalf("expected tlsminversion to be \""+defaultTLSVersion+"\" but received %q", resp.Data["tlsminversion"])
	}

	if resp.Data["tls_max_version"].(string) != defaultTLSVersion {
		t.Fatalf("expected tlsmaxversion to be \""+defaultTLSVersion+"\" but received %q", resp.Data["tlsmaxversion"])
	}

	if resp.Data["binddn"] != "tester" {
		t.Fatalf("expected username to be \"tester\" but received %q", resp.Data["binddn"])
	}

	if resp.Data["ttl"] != defaultTTLInt {
		t.Fatalf("received unexpected ttl of \"%d\"", resp.Data["ttl"])
	}

	if resp.Data["max_ttl"] != maxTTLInt {
		t.Fatalf("received unexpected max_ttl of \"%d\"", resp.Data["max_ttl"])
	}

	if resp.Data["length"] != defaultPasswordLength {
		t.Fatalf("received unexpected length of \"%d\"", resp.Data["length"])
	}

	if resp.Data["formatter"] != "mycustom{{PASSWORD}}" {
		t.Fatalf("received unexpected formatter of \"%d\"", resp.Data["formatter"])
	}
}

func DeleteConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected a nil resp, to provide a 204 with no body as the outer response")
	}
	entry, err := testStorage.Get(ctx, configStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatal("config should no longer be stored")
	}
}

func PlantConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   testStorage,
		Data: map[string]interface{}{
			"binddn":   "euclid",
			"password": "password",
			"url":      "ldap://ldap.forumsys.com:389",
			"userdn":   "cn=read-only-admin,dc=example,dc=com",
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
}

func WriteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      rolePrefix + "test_role",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_name": "tester@example.com",
			"ttl": 10,
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected no response because Vault generally doesn't return it for posts")
	}
}

func ReadRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      rolePrefix + "test_role",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	// Did we get the response data we expect?
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 items in %s but received %d", resp.Data, len(resp.Data))
	}
	if resp.Data["service_account_name"] != "tester@example.com" {
		t.Fatalf("expected \"tester@example.com\" but received %q", resp.Data["service_account_name"])
	}
	if resp.Data["ttl"] != 10 {
		t.Fatalf("expected \"10\" but received \"%d\"", resp.Data["ttl"])
	}
}

func ListRoles(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      rolePath,
		Storage:   testStorage,
	}

	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	roleList := fmt.Sprintf("%s", resp.Data["keys"])
	if roleList != "[test_role]" {
		t.Fatalf("expected a list of role names like \"[test_role]\" but received %q", roleList)
	}
}

func DeleteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      rolePrefix + "test_role",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected a nil resp, to provide a 204 with no body as the outer response")
	}
	entry, err := testStorage.Get(ctx, roleStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatal("role should no longer be stored")
	}
}

func ReadCred(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credPrefix + "test_role",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	// Did we get the response data we expect?
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 items in %s but received %d", resp.Data, len(resp.Data))
	}
	if resp.Data["username"] != "tester" {
		t.Fatalf("expected \"tester\" but received %q", resp.Data["username"])
	}
	password := resp.Data["current_password"].(string)
	if !strings.HasPrefix(password, util.PasswordComplexityPrefix) {
		t.Fatalf("%s doesn't have the expected complexity prefix of %s", password, util.PasswordComplexityPrefix)
	}
}

const validCertificate = `
-----BEGIN CERTIFICATE-----
MIIF7zCCA9egAwIBAgIJAOY2qjn64Qq5MA0GCSqGSIb3DQEBCwUAMIGNMQswCQYD
VQQGEwJVUzEQMA4GA1UECAwHTm93aGVyZTERMA8GA1UEBwwIVGltYnVrdHUxEjAQ
BgNVBAoMCVRlc3QgRmFrZTENMAsGA1UECwwETm9uZTEPMA0GA1UEAwwGTm9ib2R5
MSUwIwYJKoZIhvcNAQkBFhZkb25vdHRydXN0QG5vd2hlcmUuY29tMB4XDTE4MDQw
MzIwNDQwOFoXDTE5MDQwMzIwNDQwOFowgY0xCzAJBgNVBAYTAlVTMRAwDgYDVQQI
DAdOb3doZXJlMREwDwYDVQQHDAhUaW1idWt0dTESMBAGA1UECgwJVGVzdCBGYWtl
MQ0wCwYDVQQLDAROb25lMQ8wDQYDVQQDDAZOb2JvZHkxJTAjBgkqhkiG9w0BCQEW
FmRvbm90dHJ1c3RAbm93aGVyZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDzQPGErqjaoFcuUV6QFpSMU6w8wO8F0othik+rrlKERmrGonUGsoum
WqRe6L4ZnxBvCKB6EWjvf894TXOF2cpUnjDAyBePISyPkRBEJS6VS2SEC4AJzmVu
a+P+fZr4Hf7/bEcUr7Ax37yGVZ5i5ByNHgZkBlPxKiGWSmAqIDRZLp9gbu2EkG9q
NOjNLPU+QI2ov6U/laGS1vbE2LahTYeT5yscu9LpllxzFv4lM1f4wYEaM3HuOxzT
l86cGmEr9Q2N4PZ2T0O/s6D4but7c6Bz2XPXy9nWb5bqu0n5bJEpbRFrkryW1ozh
L9uVVz4dyW10pFBJtE42bqA4PRCDQsUof7UfsQF11D1ThrDfKsQa8PxrYdGUHUG9
GFF1MdTTwaoT90RI582p+6XYV+LNlXcdfyNZO9bMThu9fnCvT7Ey0TKU4MfPrlfT
aIhZmyaHt6mL5p881UPDIvy7paTLgL+C1orLjZAiT//c4Zn+0qG0//Cirxr020UF
3YiEFk2H0bBVwOHoOGw4w5HrvLdyy0ZLDSPQbzkSZ0RusHb5TjiyhtTk/h9vvJv7
u1fKJub4MzgrBRi16ejFdiWoVuMXRC6fu/ERy3+9DH6LURerbPrdroYypUmTe9N6
XPeaF1Tc+WO7O/yW96mV7X/D211qjkOtwboZC5kjogVbaZgGzjHCVwIDAQABo1Aw
TjAdBgNVHQ4EFgQU2zWT3HeiMBzusz7AggVqVEL5g0UwHwYDVR0jBBgwFoAU2zWT
3HeiMBzusz7AggVqVEL5g0UwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AgEAwTGcppY86mNRE43uOimeApTfqHJv+lGDTjEoJCZZmzmtxFe6O9+Vk4bH/8/i
gVQvqzBpaWXRt9OhqlFMK7OkX4ZvqXmnShmxib1dz1XxGhbwSec9ca8bill59Jqa
bIOq2SXVMcFD0GwFxfJRBVzHHuB6AwV9B2QN61zeB1oxNGJrUOo80jVkB7+MWMyD
bQqiFCHWGMa6BG4N91KGOTveZCGdBvvVw5j6lt731KjbvL2hB1UHioucOweKLfa4
QWDImTEjgV68699wKERNL0DCpeD7PcP/L3SY2RJzdyC1CSR7O8yU4lQK7uZGusgB
Mgup+yUaSjxasIqYMebNDDocr5kdwG0+2r2gQdRwc5zLX6YDBn6NLSWjRnY04ZuK
P1cF68rWteWpzJu8bmkJ5r2cqskqrnVK+zz8xMQyEaj548Bnt51ARLHOftR9jkSU
NJWh7zOLZ1r2UUKdDlrMoh3GQO3rvnCJJ16NBM1dB7TUyhMhtF6UOE62BSKdHtQn
d6TqelcRw9WnDsb9IPxRwaXhvGljnYVAgXXlJEI/6nxj2T4wdmL1LWAr6C7DuWGz
8qIvxc4oAau4DsZs2+BwolCFtYc98OjWGcBStBfZz/YYXM+2hKjbONKFxWdEPxGR
Beq3QOqp2+dga36IzQybzPQ8QtotrpSJ3q82zztEvyWiJ7E=
-----END CERTIFICATE-----
`

type fake struct{}

func (f *fake) Get(conf *ldaputil.ConfigEntry, serviceAccountName string) (*client.Entry, error) {
	entry := &ldap.Entry{}
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
		Name:   client.FieldRegistry.PasswordLastSet.String(),
		Values: []string{"131680504285591921"},
	})
	return client.NewEntry(entry), nil
}

func (f *fake) GetPasswordLastSet(conf *ldaputil.ConfigEntry, serviceAccountName string) (time.Time, error) {
	return time.Time{}, nil
}

func (f *fake) UpdatePassword(conf *ldaputil.ConfigEntry, serviceAccountName string, newPassword string) error {
	return nil
}
