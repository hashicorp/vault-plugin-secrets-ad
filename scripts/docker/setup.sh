#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

${DIR?}/cleanup.sh

set -e

docker run \
  --name=ad \
  --hostname=ad \
  --privileged \
  -p 389:389 \
  -p 636:636 \
  -e SAMBA_DC_REALM="corp.example.net" \
  -e SAMBA_DC_DOMAIN="EXAMPLE" \
  -e SAMBA_DC_ADMIN_PASSWD="SuperSecretPassw0rd" \
  -e SAMBA_DC_DNS_BACKEND="SAMBA_INTERNAL" \
  --detach "laslabs/alpine-samba-dc" samba

sleep 30

LDAPTLS_REQCERT=never ldapadd -h 127.0.0.1 -Z -p 389 -w "SuperSecretPassw0rd" -D "CN=Administrator,CN=Users,DC=corp,DC=example,DC=net" -f user.ldif
