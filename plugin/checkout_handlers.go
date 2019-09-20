package plugin

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
)

const checkoutStoragePrefix = "library/"

var (
	// ErrCurrentlyCheckedOut is returned when a check-out request is received
	// for a service account that's already checked out.
	ErrCurrentlyCheckedOut = errors.New("currently checked out")

	// ErrNotFound is used when a requested item doesn't exist.
	ErrNotFound = errors.New("not found")
)

// CheckOut provides information for a service account that is currently
// checked out.
type CheckOut struct {
	BorrowerEntityID    string        `json:"borrower_entity_id"`
	BorrowerClientToken string        `json:"borrower_client_token"`
	LendingPeriod       time.Duration `json:"lending_period"`
	Due                 time.Time     `json:"due"`
}

// CheckOutHandler is an interface used to break down tasks involved in managing checkouts. These tasks
// are many and can be complex, so it helps to break them down into small, easily testable units
// that help us build our confidence in the code.
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

	// Delete cleans up anything we were tracking from the service account that we will no longer need.
	Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error
}

// NewServiceAccountLocker is the preferable way to instantiate a ServiceAccountLocker
// because it populates the map of locks for you.
func NewServiceAccountLocker(child CheckOutHandler) *ServiceAccountLocker {
	return &ServiceAccountLocker{
		locks:   &sync.Map{},
		wrapped: child,
	}
}

// ServiceAccountLocker protects against races.
type ServiceAccountLocker struct {
	// This is, in effect, being used as a map[string]*sync.RWMutex
	locks   *sync.Map
	wrapped CheckOutHandler
}

// CheckOut holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	if err := validateInputs(ctx, storage, serviceAccountName, checkOut, true); err != nil {
		return err
	}
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.wrapped.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

// CheckIn holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.wrapped.CheckIn(ctx, storage, serviceAccountName)
}

// Delete holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.wrapped.Delete(ctx, storage, serviceAccountName)
}

// Status holds a read-only lock for the duration of the work to be done.
func (l *ServiceAccountLocker) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return nil, err
	}
	lock := l.getOrCreateLock(serviceAccountName)
	lock.RLock()
	defer lock.RUnlock()
	return l.wrapped.Status(ctx, storage, serviceAccountName)
}

func (l *ServiceAccountLocker) getOrCreateLock(serviceAccountName string) *sync.RWMutex {
	lockIfc, ok := l.locks.Load(serviceAccountName)
	if ok {
		return lockIfc.(*sync.RWMutex)
	}
	lock := &sync.RWMutex{}
	l.locks.Store(serviceAccountName, lock)
	return lock
}

// PasswordHandler is responsible for rolling and storing a service account's password upon check-in.
type PasswordHandler struct {
	client  secretsClient
	wrapped CheckOutHandler
}

// CheckOut requires no further action from the password handler other than passing along the request.
func (h *PasswordHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	return h.wrapped.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

// CheckIn rotates the service account's password remotely and stores it locally.
// If this process fails part-way through:
// 		- An error will be returned.
//		- The account will remain checked out.
//		- The client may (or may not) retry the check-in.
// 		- The overdue watcher will still check it in if its lending period runs out.
func (h *PasswordHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
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
	return h.wrapped.CheckIn(ctx, storage, serviceAccountName)
}

// Delete simply deletes the password from storage so it's not stored unnecessarily.
func (h *PasswordHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	if err := storage.Delete(ctx, "password/"+serviceAccountName); err != nil {
		return err
	}
	return h.wrapped.Delete(ctx, storage, serviceAccountName)
}

// Status doesn't need any password work.
func (h *PasswordHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	return h.wrapped.Status(ctx, storage, serviceAccountName)
}

// retrievePassword is a utility function for grabbing a service account's password from storage.
// retrievePassword will return:
//  - "password", nil if it was successfully able to retrieve the password.
//  - ErrNotFound if there's no password presently.
//  - Some other err if it was unable to complete successfully.
func retrievePassword(ctx context.Context, storage logical.Storage, serviceAccountName string) (string, error) {
	entry, err := storage.Get(ctx, "password/"+serviceAccountName)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", ErrNotFound
	}
	password := ""
	if err := entry.DecodeJSON(&password); err != nil {
		return "", err
	}
	return password, nil
}

// StorageHandler's sole responsibility is to communicate with storage regarding check-outs.
type StorageHandler struct{}

// CheckOut will return:
//  - Nil if it was successfully able to perform the requested check out.
//  - ErrCurrentlyCheckedOut if the account was already checked out.
//  - Some other err if it was unable to complete successfully.
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

// CheckIn will return nil error if it was able to successfully check in an account.
// If the account was already checked in, it still returns no error.
func (h *StorageHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	// We simply delete checkouts from storage when they're checked in.
	return h.Delete(ctx, storage, serviceAccountName)
}

// Status returns either:
//  - A *CheckOut and nil error if the serviceAccountName is currently checked out.
//  - A nil *CheckOut and nil error if the serviceAccountName is not currently checked out.
//  - A nil *CheckOut and populated err if the state cannot be determined.
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

func (h *StorageHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	return storage.Delete(ctx, checkoutStoragePrefix+serviceAccountName)
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
