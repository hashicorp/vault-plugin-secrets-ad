package plugin

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const checkoutStoragePrefix = "library/"

var ErrCurrentlyCheckedOut = errors.New("currently checked out")

type CheckOut struct {
	BorrowerEntityID    string        `json:"borrower_entity_id"`
	BorrowerClientToken string        `json:"borrower_client_token"`
	LendingPeriod       time.Duration `json:"lending_period"`
	Due                 time.Time     `json:"due"`
}

type CheckOutHandler interface {
	// CheckOut attempts to check out a service account. If the account is unavailable, it returns
	// ErrCurrentlyCheckedOut.
	CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error

	// CheckIn attempts to check in a service account. If an error occurs, the account remains checked out
	// and can either be retried by the caller, or eventually may be checked in if it has a lending period
	// that ends.
	CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error

	// Status returns either:
	//  - A *CheckOut and nil error if the serviceAccountName is currently checked out.
	//  - A nil *CheckOut and nil error if the serviceAccountName is not currently checked out.
	//  - A nil *CheckOut and populated err if the state cannot be determined.
	Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error)
}

type StorageHandler struct{}

func (h *StorageHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	if err := validateInputs(ctx, storage, serviceAccountName, checkOut, true); err != nil {
		return err
	}
	// Check if the service account is currently checked out.
	if entry, err := storage.Get(ctx, checkoutStoragePrefix+serviceAccountName); err != nil {
		return err
	} else if entry != nil {
		return ErrCurrentlyCheckedOut
	}
	// Since it's not, store the new check-out.
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountName, checkOut)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (h *StorageHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	// We simply take checkouts out of storage when they're checked in.
	return storage.Delete(ctx, checkoutStoragePrefix+serviceAccountName)
}

func (h *StorageHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return nil, err
	}
	entry, err := storage.Get(ctx, checkoutStoragePrefix+serviceAccountName)
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

// validateInputs is a helper function for ensuring that a caller has satisfied all required arguments.
func validateInputs(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut, checkOutRequired bool) error {
	if ctx == nil {
		return errors.New("ctx is required")
	}
	if storage == nil {
		return errors.New("storage is required")
	}
	if serviceAccountName == "" {
		return errors.New("serviceAccountName is required")
	}
	if checkOutRequired && checkOut == nil {
		return errors.New("checkOut is required")
	}
	return nil
}
