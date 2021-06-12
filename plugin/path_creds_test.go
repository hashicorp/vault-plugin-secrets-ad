package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/client"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Test_TTLIsRespected(t *testing.T) {
	fakeClient := &thisFake{}
	b := newBackend(fakeClient, nil)
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	logger := hclog.Default()
	logger.SetLevel(hclog.Debug)

	if err := b.Setup(ctx, &logical.BackendConfig{
		Logger: logger,
	}); err != nil {
		t.Fatal(err)
	}

	// Set up the config
	config := &configuration{
		PasswordConf: passwordConf{
			/*
				This differs from the original config posted by the user
				but I have to do it to get a matching TTL on the role.
			*/
			TTL:    7776000,
			MaxTTL: 7776000,
			Length: 14,
		},
		ADConf: &client.ADConf{},
	}
	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	// Set up the role
	createRoleReq := &logical.Request{
		Storage: storage,
	}
	createRoleFieldData := &framework.FieldData{
		Schema: b.pathRoles().Fields,
		Raw: map[string]interface{}{
			"name":                 "test-role",
			"service_account_name": "vault_test2@aaa.bbb.ccc.com",
			"ttl":                  7776000, // This also differs from the original role posted.
		},
	}

	_, err = b.roleUpdateOperation(ctx, createRoleReq, createRoleFieldData)
	if err != nil {
		t.Fatal(err)
	}

	// Get creds the first time
	readCredsFieldData := &framework.FieldData{
		Schema: b.pathCreds().Fields,
		Raw: map[string]interface{}{
			"name": "test-role",
		},
	}
	readCredsReq := &logical.Request{
		Storage: storage,
	}
	_, err = b.credReadOperation(ctx, readCredsReq, readCredsFieldData)
	if err != nil {
		t.Fatal(err)
	}

	// Get creds another time
	_, err = b.credReadOperation(ctx, readCredsReq, readCredsFieldData)
	if err != nil {
		t.Fatal(err)
	}

	if fakeClient.numPasswordUpdates > 1 {
		t.Fatalf("expected 1 password update but received %d", fakeClient.numPasswordUpdates)
	}
}

type thisFake struct {
	numPasswordUpdates int
}

func (f *thisFake) Get(conf *client.ADConf, serviceAccountName string) (*client.Entry, error) {
	entry := &ldap.Entry{}
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
		Name:   client.FieldRegistry.PasswordLastSet.String(),
		Values: []string{"131680504285591921"},
	})
	return client.NewEntry(entry), nil
}

func (f *thisFake) GetPasswordLastSet(conf *client.ADConf, serviceAccountName string) (time.Time, error) {
	f.numPasswordUpdates++
	return time.Date(2019, time.April, 17, 23, 10, 58, 0, time.UTC), nil
}

func (f *thisFake) UpdatePassword(conf *client.ADConf, serviceAccountName string, newPassword string) error {
	return nil
}

func (f *thisFake) UpdateRootPassword(conf *client.ADConf, bindDN string, newPassword string) error {
	return nil
}

func (f *thisFake) EnableAccount(conf *client.ADConf, serviceAccountName string) error {
	return nil
}

func (f *thisFake) DisableAccount(conf *client.ADConf, serviceAccountName string) error {
	return nil
}
