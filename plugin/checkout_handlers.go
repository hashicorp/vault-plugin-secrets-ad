package plugin

import (
	"context"
	"errors"
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
