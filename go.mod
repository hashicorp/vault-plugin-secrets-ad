module github.com/hashicorp/vault-plugin-secrets-ad

go 1.12

require (
	github.com/go-errors/errors v1.0.1
	github.com/go-ldap/ldap v3.0.2+incompatible
	github.com/hashicorp/go-hclog v0.8.0
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/vault/api v1.0.3-0.20190719145648-41d3939b1ff9
	github.com/hashicorp/vault/sdk v0.1.12-0.20190719011625-af0b660abb36
	github.com/patrickmn/go-cache v2.1.0+incompatible
	golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db
)
