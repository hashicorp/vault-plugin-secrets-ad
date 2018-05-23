package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var (
	ctx     = context.Background()
	storage = &logical.InmemStorage{}
)

func TestCacheReader(t *testing.T) {

	// we should start with no config
	config, err := testBackend.readConfig(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if config != nil {
		t.Fatal("config should be nil")
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
	}

	// submit a minimal config so we can check that we're using safe defaults
	fieldData := &framework.FieldData{
		Schema: testBackend.pathConfig().Fields,
		Raw: map[string]interface{}{
			"binddn":   "tester",
			"password": "pa$$w0rd",
			"urls":     "ldap://138.91.247.105",
			"userdn":   "example,com",
		},
	}

	_, err = testBackend.configUpdateOperation(ctx, req, fieldData)
	if err != nil {
		t.Fatal(err)
	}

	// now that we've updated the config, we should be able to configReadOperation it
	config, err = testBackend.readConfig(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		t.Fatal("config shouldn't be nil")
	}

	if config.ADConf.BindDN != "tester" {
		t.Fatal("returned config is not populated as expected")
	}
	if config.ADConf.TLSMinVersion != defaultTLSVersion {
		t.Fatal("we should be defaulting to " + defaultTLSVersion)
	}
	if config.ADConf.TLSMaxVersion != defaultTLSVersion {
		t.Fatal("we should be defaulting to " + defaultTLSVersion)
	}
	if config.ADConf.InsecureTLS {
		t.Fatal("insecure tls should be off by default")
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   storage,
	}

	_, err = testBackend.configDeleteOperation(ctx, req, nil)
	if err != nil {
		t.Fatal(err)
	}

	// now that we've deleted the config, it should be unset again
	config, err = testBackend.readConfig(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if config != nil {
		t.Fatal("config should be nil")
	}
}
