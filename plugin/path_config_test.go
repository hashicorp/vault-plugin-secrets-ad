package plugin

import (
	"context"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	ctx     = context.Background()
	storage = &logical.InmemStorage{}
)

func TestCacheReader(t *testing.T) {

	// we should start with no config
	config, err := readConfig(ctx, storage)
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
	config, err = readConfig(ctx, storage)
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
	config, err = readConfig(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if config != nil {
		t.Fatal("config should be nil")
	}
}

func TestConfig_PasswordLength(t *testing.T) {

	// we should start with no config
	config, err := readConfig(ctx, storage)
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

	tests := []struct {
		name         string
		rawFieldData map[string]interface{}
		wantErr      bool
	}{
		{
			"length provided",
			map[string]interface{}{
				"length": 32,
			},
			false,
		},
		{
			"password policy provided",
			map[string]interface{}{
				"password_policy": "foo",
			},
			false,
		},
		{
			"no length or password policy provided",
			nil,
			false,
		},
		{
			"both length and password policy provided",
			map[string]interface{}{
				"password_policy": "foo",
				"length":          32,
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start common config fields and append what we need to test against
			fieldData := &framework.FieldData{
				Schema: testBackend.pathConfig().Fields,
				Raw: map[string]interface{}{
					"binddn":   "tester",
					"password": "pa$$w0rd",
					"urls":     "ldap://138.91.247.105",
					"userdn":   "example,com",
				},
			}

			for k, v := range tt.rawFieldData {
				fieldData.Raw[k] = v
			}

			_, err = testBackend.configUpdateOperation(ctx, req, fieldData)
			assert.Equal(t, tt.wantErr, err != nil)

			if tt.wantErr && err != nil {
				return
			}

			config, err := readConfig(ctx, storage)
			assert.NoError(t, err)

			var actual map[string]interface{}

			cfg := &mapstructure.DecoderConfig{
				Result:  &actual,
				TagName: "json",
			}
			decoder, err := mapstructure.NewDecoder(cfg)
			assert.NoError(t, err)
			err = decoder.Decode(config.PasswordConf)
			assert.NoError(t, err)

			for k, v := range tt.rawFieldData {
				assert.Contains(t, actual, k)
				assert.Equal(t, actual[k], v)
			}
		})
	}
}
