module github.com/hashicorp/vault-plugin-secrets-ad

go 1.12

require (
	github.com/armon/go-metrics v0.3.10
	github.com/go-errors/errors v1.4.1
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/vault/api v1.3.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/mitchellh/mapstructure v1.4.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	golang.org/x/text v0.3.7
)
