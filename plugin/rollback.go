package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	rotateCredentialWAL = "rotateCredentialWAL"
)

// rotateCredentialWAL is used to store information in a WAL that can retry a
// credential rotation in the event of partial failure.
type rotateCredentialEntry struct {
	LastVaultRotation  time.Time `json:"last_vault_rotation"`
	LastPassword       string    `json:"last_password"`
	CurrentPassword    string    `json:"current_password"`
	RoleName           string    `json:"name"`
	ServiceAccountName string    `json:"service_account_name"`
	TTL                int       `json:"ttl"`
	walID              string
}

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case rotateCredentialWAL:
		return b.handleRotateCredentialRollback(ctx, req.Storage, data)
	default:
		return fmt.Errorf("unknown WAL entry kind %q", kind)
	}
}

func (b *backend) handleRotateCredentialRollback(ctx context.Context, storage logical.Storage, data interface{}) error {
	var wal rotateCredentialEntry
	if err := mapstructure.WeakDecode(data, &wal); err != nil {
		return err
	}

	role := &backendRole{
		ServiceAccountName: wal.ServiceAccountName,
		TTL:                wal.TTL,
		LastVaultRotation:  wal.LastVaultRotation,
	}

	if err := b.writeRoleToStorage(ctx, storage, wal.RoleName, role); err != nil {
		return err
	}

	// Although a service account name is typically my_app@example.com,
	// the username it uses is just my_app, or everything before the @.
	username, err := getUsername(role.ServiceAccountName)
	if err != nil {
		return err
	}

	cred := map[string]interface{}{
		"username":         username,
		"current_password": wal.CurrentPassword,
		"last_password":    wal.LastPassword,
	}

	// Cache and save the cred.
	entry, err := logical.StorageEntryJSON(storageKey+"/"+wal.RoleName, cred)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}
