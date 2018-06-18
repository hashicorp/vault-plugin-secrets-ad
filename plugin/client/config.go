package client

import (
	"github.com/hashicorp/vault/helper/ldaputil"
	"time"
)

type ADConf struct {
	*ldaputil.ConfigEntry
	LastBindPassword         string
	LastBindPasswordRotation time.Time
}
