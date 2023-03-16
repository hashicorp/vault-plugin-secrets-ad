# Vault Plugin: Active Directory Secrets Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides Active Directory functionality to Vault.

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
- Vault Website: https://www.vaultproject.io
- Active Directory Docs: https://developer.hashicorp.com/vault/docs/secrets/ad
- Main Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins).

## Usage

Please see [documentation for the plugin](https://developer.hashicorp.com/vault/docs/secrets/ad)
on the Vault website.

This plugin is currently built into Vault and by default is accessed
at `ad`. To enable this in a running Vault server:

```sh
$ vault secrets enable ad
Success! Enabled the ad secrets engine at: ad/
```

Additionally starting with Vault 0.10 this backend is by default mounted
at `secret/`.

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine
(version 1.17+ is *required*).

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```hcl
plugin_directory = "path/to/plugin/directory"
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-catalog):

```sh
$ vault plugin register \
        -sha256=<SHA256 Hex value of the plugin binary> \
        -command="vault-plugin-secrets-active-directory" \
        secret \
        custom-ad
```

Note you should generate a new sha256 checksum if you have made changes
to the plugin. Example using openssl:

```sh
openssl dgst -sha256 $GOPATH/vault-plugin-secrets-ad
...
SHA256(.../go/bin/vault-plugin-secrets-ad)= 896c13c0f5305daed381952a128322e02bc28a57d0c862a78cbc2ea66e8c6fa1
```

Enable the secrets plugin backend using the secrets enable plugin command:

```sh
$ vault secrets enable custom-ad
...

Successfully enabled 'plugin' at 'custom-ad'!
```

#### Tests

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the tests.

To run the tests, run the following:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```
