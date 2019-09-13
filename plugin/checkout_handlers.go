package plugin

import (
	"context"
	"errors"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/util"
	"github.com/hashicorp/vault/sdk/framework"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

var CurrentlyCheckedOut = errors.New("currently checked out")

type CheckOut struct {
	BorrowerEntityID    string        `json:"borrower_entity_id"`
	BorrowerClientToken string        `json:"borrower_client_token"`
	LendingPeriod       time.Duration `json:"lending_period"`
	Due                 time.Time     `json:"due"`
}

type CheckOutHandler interface {
	CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error
	CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error
	Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error
	Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error)
}

type PasswordHandler struct {
	client secretsClient
	child  CheckOutHandler
}

func (h *PasswordHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	// Nothing needs to be done with passwords when they're being checked out.
	return h.child.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

func (h *PasswordHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	// On check-ins, a new AD password is generated, updated in AD, and stored.
	engineConf, err := readConfig(ctx, storage)
	if err != nil {
		return err
	}
	if engineConf == nil {
		return errors.New("the config is currently unset")
	}
	newPassword, err := util.GeneratePassword(engineConf.PasswordConf.Formatter, engineConf.PasswordConf.Length)
	if err != nil {
		return err
	}
	// In case any of this fails, place a WAL about what we intend to do so we can retry.
	walID, err := framework.PutWAL(ctx, storage, "password-update", map[string]string{
		"service_account_name": serviceAccountName,
		"new_password":         newPassword,
	})
	if err != nil {
		return err
	}
	if err := h.client.UpdatePassword(engineConf.ADConf, serviceAccountName, newPassword); err != nil {
		return err
	}
	entry, err := logical.StorageEntryJSON("password/"+serviceAccountName, newPassword)
	if err != nil {
		return err
	}
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	// We have succeeded, we don't need the WAL anymore.
	if err := framework.DeleteWAL(ctx, storage, walID); err != nil {
		return err
	}
	return h.child.CheckIn(ctx, storage, serviceAccountName)
}

func (h *PasswordHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := storage.Delete(ctx, "password/"+serviceAccountName); err != nil {
		return err
	}
	return h.child.Delete(ctx, storage, serviceAccountName)
}

func (h *PasswordHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	return h.child.Status(ctx, storage, serviceAccountName)
}

// retrievePassword is a utility function for grabbing a service account's password from storage.
func retrievePassword(ctx context.Context, storage logical.Storage, serviceAccountName string) (string, error) {
	entry, err := storage.Get(ctx, "password/"+serviceAccountName)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}
	password := ""
	if err := entry.DecodeJSON(&password); err != nil {
		return "", err
	}
	return password, nil
}

// retryFailedPasswordUpdates is a callback because we need to add a client to the mix.
func retryFailedPasswordUpdates(client secretsClient) func(context.Context, *logical.Request) error {
	return func(ctx context.Context, req *logical.Request) error {
		engineConf, err := readConfig(ctx, req.Storage)
		if err != nil {
			return err
		}
		if engineConf == nil {
			return errors.New("the config is currently unset")
		}

		walIDs, err := framework.ListWAL(ctx, req.Storage)
		if err != nil {
			return err
		}
		for _, walID := range walIDs {
			walEntry, err := framework.GetWAL(ctx, req.Storage, walID)
			if err != nil {
				return err
			}
			passwordUpdate := walEntry.Data.(map[string]interface{})
			serviceAccountName := passwordUpdate["service_account_name"].(string)
			newPassword := passwordUpdate["new_password"].(string)

			if err := client.UpdatePassword(engineConf.ADConf, serviceAccountName, newPassword); err != nil {
				return err
			}
			entry, err := logical.StorageEntryJSON("password/"+serviceAccountName, newPassword)
			if err != nil {
				return err
			}
			if err := req.Storage.Put(ctx, entry); err != nil {
				return err
			}
			// We have succeeded, we don't need the WAL anymore.
			if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
				return err
			}
		}
		return nil
	}
}

type StorageHandler struct{}

func (h *StorageHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	// Check if the service account is currently checked out.
	if entry, err := storage.Get(ctx, "library/"+serviceAccountName); err != nil {
		return err
	} else if entry != nil {
		return CurrentlyCheckedOut
	}
	// Since it's not, store the new check-out.
	entry, err := logical.StorageEntryJSON("library/"+serviceAccountName, checkOut)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (h *StorageHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	// We simply take checkouts out of storage when they're checked in.
	return h.Delete(ctx, storage, serviceAccountName)
}

func (h *StorageHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	return storage.Delete(ctx, "library/"+serviceAccountName)
}

func (h *StorageHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	entry, err := storage.Get(ctx, "library/"+serviceAccountName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	checkOut := &CheckOut{}
	if err := entry.DecodeJSON(checkOut); err != nil {
		return nil, err
	}
	return checkOut, nil
}
