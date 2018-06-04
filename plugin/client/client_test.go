package client

import (
	"testing"

	"github.com/go-ldap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/ldapifc"
	"github.com/hashicorp/vault/helper/ldaputil"
)

func TestSearch(t *testing.T) {
	config := emptyConfig()

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldap: ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.Surname: {"Jones"},
	}

	entries, err := client.Search(config, filters)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("only one entry was provided, but multiple were found: %s", entries)
	}
	entry := entries[0]

	result, _ := entry.GetJoined(FieldRegistry.Surname)
	if result != "Jones" {
		t.Fatalf("expected Surname of \"Jones\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.BadPasswordTime)
	if result != "131653637947737037" {
		t.Fatalf("expected BadPasswordTime of \"131653637947737037\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.PasswordLastSet)
	if result != "0" {
		t.Fatalf("expected PasswordLastSet of \"0\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.PrimaryGroupID)
	if result != "513" {
		t.Fatalf("expected PrimaryGroupID of \"513\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.UserPrincipalName)
	if result != "jim@example.com" {
		t.Fatalf("expected UserPrincipalName of \"jim@example.com\" but received %q", result)
	}

	result, _ = entry.GetJoined(FieldRegistry.ObjectClass)
	if result != "top,person,organizationalPerson,user" {
		t.Fatalf("expected ObjectClass of \"top,person,organizationalPerson,user\" but received %q", result)
	}
}

func TestUpdateEntry(t *testing.T) {
	config := emptyConfig()

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
	}
	conn.ModifyRequestToExpect.Replace("cn", []string{"Blue", "Red"})
	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.Surname: {"Jones"},
	}

	newValues := map[*Field][]string{
		FieldRegistry.CommonName: {"Blue", "Red"},
	}

	if err := client.UpdateEntry(config, filters, newValues); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePassword(t *testing.T) {
	testPass := "hell0$catz*"

	config := emptyConfig()
	config.BindDN = "cats"
	config.BindPassword = "dogs"

	conn := &ldapifc.FakeLDAPConnection{
		SearchRequestToExpect: testSearchRequest(),
		SearchResultToReturn:  testSearchResult(),
	}

	expectedPass, err := formatPassword(testPass)
	if err != nil {
		t.Fatal(err)
	}
	conn.ModifyRequestToExpect = &ldap.ModifyRequest{
		DN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
	}
	conn.ModifyRequestToExpect.Replace("unicodePwd", []string{expectedPass})
	ldapClient := &ldaputil.Client{
		Logger: hclog.NewNullLogger(),
		LDAP:   &ldapifc.FakeLDAPClient{conn},
	}

	client := &Client{ldapClient}

	filters := map[*Field][]string{
		FieldRegistry.Surname: {"Jones"},
	}

	if err := client.UpdatePassword(config, filters, testPass); err != nil {
		t.Fatal(err)
	}
}

func emptyConfig() *ldaputil.ConfigEntry {
	return &ldaputil.ConfigEntry{
		UserDN:       "dc=example,dc=com",
		Url:          "ldap://127.0.0.1",
		BindDN:       "cats",
		BindPassword: "cats",
	}
}

func testSearchRequest() *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN: "dc=example,dc=com",
		Scope:  ldap.ScopeWholeSubtree,
		Filter: "(sn=Jones)",
	}
}

func testSearchResult() *ldap.SearchResult {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "CN=Jim H.. Jones,OU=Vault,OU=Engineering,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   FieldRegistry.Surname.String(),
						Values: []string{"Jones"},
					},
					{
						Name:   FieldRegistry.BadPasswordTime.String(),
						Values: []string{"131653637947737037"},
					},
					{
						Name:   FieldRegistry.PasswordLastSet.String(),
						Values: []string{"0"},
					},
					{
						Name:   FieldRegistry.PrimaryGroupID.String(),
						Values: []string{"513"},
					},
					{
						Name:   FieldRegistry.UserPrincipalName.String(),
						Values: []string{"jim@example.com"},
					},
					{
						Name:   FieldRegistry.ObjectClass.String(),
						Values: []string{"top", "person", "organizationalPerson", "user"},
					},
				},
			},
		},
	}
}
