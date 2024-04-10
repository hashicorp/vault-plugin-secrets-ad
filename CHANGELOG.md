## Unreleased

### IMPROVEMENTS:
* Updated dependencies:
   * `github.com/hashicorp/go-plugin` v1.5.2 -> v1.6.0 to enable running the plugin in containers

## v0.17.0
### February 1, 2024

### IMPROVEMENTS:
* Updated dependencies:
  *	`github.com/go-errors/errors` v1.5.0 -> v1.5.1
  *	`github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
  *	`github.com/hashicorp/vault/api` v1.10.0 -> v0.10.0
  *	`github.com/hashicorp/vault/api` v1.11.0 -> v0.10.2
  *	`golang.org/x/text` v0.13.0 -> v0.14.0

## v0.16.2
### January 24, 2024

### BUG FIXES:
* Revert back to armon/go-metrics [GH-118](https://github.com/hashicorp/vault-plugin-secrets-ad/pull/118)

## v0.16.1
### September 7, 2023

### IMPROVEMENTS:
* Updated dependencies:
  * `github.com/go-errors/errors` v1.4.2 -> v1.5.0
  * `github.com/hashicorp/vault/api` v1.9.1 -> v1.10.0
  * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.10.0
  * `github.com/stretchr/testify` v1.8.2 -> v1.8.4
  * `golang.org/x/text` v0.9.0 -> v0.13.0

## v0.16.0
### May 24, 2023

### IMPROVEMENTS:

* enable plugin multiplexing [GH-99](https://github.com/hashicorp/vault-plugin-secrets-ad/pull/99)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1
  * `github.com/hashicorp/vault/sdk` v0.9.0
  * `golang.org/x/text` v0.9.0
  * `golang.org/x/net` v0.7.0

## v0.15.0
### February 7, 2023

* Plugin release milestone

## v0.14.1
### December 1, 2022

### BUG FIXES:

* Fix bug where updates to config would fail if password isn't provided [GH-91](https://github.com/hashicorp/vault-plugin-secrets-ad/pull/91)

## v0.14.0
### September 19, 2022

* Plugin release milestone

## v0.13.1
### June 22, 2022

### IMPROVEMENTS:

* config: set default length only if password policy is missing [GH-85](https://github.com/hashicorp/vault-plugin-secrets-ad/pull/85)
