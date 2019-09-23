package plugin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
)

const checkoutStoragePrefix = "checkout/"

var (
	// ErrCurrentlyCheckedOut is returned when a check-out request is received
	// for a service account that's already checked out.
	ErrCurrentlyCheckedOut = errors.New("currently checked out")

	// ErrNotCurrentlyCheckedOut is returned when a renewal request is received
	// for a service account that's not checked out.
	ErrNotCurrentlyCheckedOut = errors.New("not currently checked out")

	// ErrNotFound is used when a requested item doesn't exist.
	ErrNotFound = errors.New("not found")
)

// CheckOut provides information for a service account that is currently
// checked out.
type CheckOut struct {
	BorrowerEntityID    string        `json:"borrower_entity_id"`
	BorrowerClientToken string        `json:"borrower_client_token"`
	LendingPeriod       time.Duration `json:"lending_period"`

	// For unlimited lending periods, due should be set to a time in the distant
	// future (like 100,00 years from now). This simplifies logic significantly.
	Due time.Time `json:"due"`
}

// NewCheckOutHandler instantiates a stack of checkout handlers appropriate for this type of instance.
func NewCheckOutHandler(ctx context.Context, forLeader bool, logger hclog.Logger, storage logical.Storage, client secretsClient) (CheckOutHandler, error) {
	// Generally speaking, calls will flow from the
	// InputValidator -> OverdueWatcher -> ServiceAccountLocker -> PasswordHandler -> StorageHandler
	// but some of these objects are only needed on the leader.
	// Leader instances handle reads and writes, so all calls available
	// on the CheckOutHandlers will be directly called.
	// Follower instances handle reads only, so only the "Status" call
	// will be directly called. Underlying storage will be updated via
	// WAL replication.

	var handlerStack CheckOutHandler

	// The StorageHandler is needed on all types of instances to serve
	// reads and writes.
	handlerStack = &StorageHandler{}

	// The PasswordHandler isn't needed on followers, since they will only
	// call "Status", and the PasswordHandler is essentially a no-op on those.
	if forLeader {
		handlerStack = &PasswordHandler{
			client:          client,
			CheckOutHandler: handlerStack,
		}
	}

	// The ServiceAccountLocker has RWMutexes that will keep the plugin
	// thread-safe regardless of which type of server it is.
	handlerStack = NewServiceAccountLocker(handlerStack)

	if !forLeader {
		// We're all set up for Status calls on followers now.
		return &InputValidator{handlerStack}, nil
	}

	// The OverdueWatcher should only run on the leader because we only
	// want it initiating check-ins in one place.
	overdueWatcher := NewOverdueWatcher(logger, storage, handlerStack)
	handlerStack = overdueWatcher

	// On leaders, we now need to go through all the checkOuts. For ones
	// whose lending period has expired, we need to check them in. We
	// need to start watching the rest.
	reserveNames, err := storage.List(ctx, reserveStoragePrefix)
	if err != nil {
		return nil, err
	}

	for _, reserveName := range reserveNames {
		entry, err := storage.Get(ctx, reserveStoragePrefix+reserveName)
		if err != nil {
			return nil, err
		}
		reserve := &libraryReserve{}
		if err := entry.DecodeJSON(reserve); err != nil {
			return nil, err
		}
		for _, serviceAccountName := range reserve.ServiceAccountNames {
			checkOut, err := handlerStack.Status(ctx, storage, serviceAccountName)
			if err != nil {
				return nil, err
			}
			if checkOut == nil {
				continue
			}
			if !checkOut.Due.After(time.Now()) {
				if err := handlerStack.CheckIn(ctx, storage, serviceAccountName); err != nil {
					return nil, err
				}
			} else {
				overdueWatcher.startWatching(serviceAccountName, checkOut.Due)
			}
		}
	}
	return &InputValidator{handlerStack}, nil
}

// CheckOutHandler is an interface used to break down tasks involved in managing checkouts. These tasks
// are many and can be complex, so it helps to break them down into small, easily testable units
// that help us build our confidence in the code.
type CheckOutHandler interface {
	// CheckOut attempts to check out a service account. If the account is unavailable, it returns
	// ErrCurrentlyCheckedOut.
	CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error

	// RenewCheckOut will renew a present checkOut. If the account is not currently checked out, it returns
	// ErrNotCurrentlyCheckedOut.
	RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error

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

// InputValidator will be the first object called in the stack of handlers, to ensure items
// expected in the signature are present, and to handle any other validation logic.
type InputValidator struct {
	CheckOutHandler
}

// CheckOut ensures all inputs in the signature are present.
func (v *InputValidator) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	if err := v.validateInputs(ctx, storage, serviceAccountName, checkOut, true); err != nil {
		return err
	}
	return v.CheckOutHandler.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

// CheckIn ensures all inputs in the signature are present.
func (v *InputValidator) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := v.validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	return v.CheckOutHandler.CheckIn(ctx, storage, serviceAccountName)
}

// Status ensures all inputs in the signature are present.
func (v *InputValidator) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	if err := v.validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return nil, err
	}
	return v.CheckOutHandler.Status(ctx, storage, serviceAccountName)
}

// Delete ensures all inputs in the signature are present.
func (v *InputValidator) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := v.validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		return err
	}
	return v.CheckOutHandler.Delete(ctx, storage, serviceAccountName)
}

// validateInputs is a helper function for ensuring that a caller has satisfied all required arguments.
func (v *InputValidator) validateInputs(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut, checkOutRequired bool) error {
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

// NewOverdueWatcher creates an OverdueWatcher.
func NewOverdueWatcher(logger hclog.Logger, origStorage logical.Storage, child CheckOutHandler) *OverdueWatcher {
	return &OverdueWatcher{
		storageMutex:  &sync.RWMutex{},
		latestStorage: origStorage,
		logger:        logger,
		mapMutex:      &sync.RWMutex{},
		renewalChans:  make(map[string]chan time.Time),
		child:         child,
	}
}

// OverdueWatcher automatically checks things in when they're due.
type OverdueWatcher struct {
	// We always hold onto the last storage we've seen, and a mutex for it, so that the background process that's
	// checking in overdue service accounts will use the latest storage configured.
	storageMutex  *sync.RWMutex
	latestStorage logical.Storage

	logger       hclog.Logger
	mapMutex     *sync.RWMutex
	renewalChans map[string]chan time.Time
	child        CheckOutHandler
}

// CheckOut fires off a goroutine to check the service account back in when it's due. This can be cancelled
// by calling check-in or delete.
func (w *OverdueWatcher) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	w.updateStorage(storage)
	if err := w.child.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		return err
	}
	go w.startWatching(serviceAccountName, checkOut.Due)
	return nil
}

// RenewCheckOut extends the time until the service account will be automatically checked in.
func (w *OverdueWatcher) RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	w.updateStorage(storage)
	if err := w.child.RenewCheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		return err
	}
	w.mapMutex.RLock()
	renewalChan, ok := w.renewalChans[serviceAccountName]
	w.mapMutex.RUnlock()
	if !ok {
		// We should never get here because if an account isn't currently checked out,
		// we will have errored earlier. Just in case, let's error.
		return errors.New("missing renewal channel")
	}
	renewalChan <- checkOut.Due
	return nil
}

// CheckIn checks a service account in, exiting the goroutine watching for its time due.
func (w *OverdueWatcher) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	w.updateStorage(storage)
	if err := w.child.CheckIn(ctx, storage, serviceAccountName); err != nil {
		return err
	}
	w.stopWatching(serviceAccountName)
	return nil
}

// Status simply passes status requests through.
func (w *OverdueWatcher) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	w.updateStorage(storage)
	return w.child.Status(ctx, storage, serviceAccountName)
}

// Delete deletes a service account, exiting the goroutine watching for its time due.
func (w *OverdueWatcher) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	w.updateStorage(storage)
	if err := w.child.Delete(ctx, storage, serviceAccountName); err != nil {
		return err
	}
	w.stopWatching(serviceAccountName)
	return nil
}

// updateStorage just stores the last storage we've seen in memory so it can be used by the overdue watcher to check
// things back in.
func (w *OverdueWatcher) updateStorage(storage logical.Storage) {
	// If storage hasn't changed, we only need a read lock, which is way easier to get.
	w.storageMutex.RLock()
	if reflect.DeepEqual(storage, w.latestStorage) {
		w.storageMutex.RUnlock()
		return
	}
	// If it has changed, we'll need a write lock.
	w.storageMutex.RUnlock()
	w.storageMutex.Lock()
	w.latestStorage = storage
	w.storageMutex.Unlock()
}

// startWatching is intended to be fired off as a goroutine. It will live in the background
// until either:
//  - The lending period ends and it successfully checks the account back in, OR
//  - It receives a signal from the enclosing environment that it doesn't need to watch this account anymore.
// It is exported so can be called directly on startup for accounts that are already checked out.
func (w *OverdueWatcher) startWatching(serviceAccountName string, due time.Time) {
	renewalChan := make(chan time.Time, 1)
	w.mapMutex.Lock()
	w.renewalChans[serviceAccountName] = renewalChan
	w.mapMutex.Unlock()
	lendingPeriodTimer := time.NewTimer(due.Sub(time.Now()))
	for {
		select {
		case updatedDue, stillOpen := <-renewalChan:
			if !stillOpen {
				// The renewal channel was closed, signifying that we no longer need to watch
				// this service account.
				w.logger.Debug(fmt.Sprintf("%s was checked in", serviceAccountName))
				return
			}
			// A new due date was sent, update how long we're waiting.
			lendingPeriodTimer = time.NewTimer(updatedDue.Sub(time.Now()))
			continue
		case <-lendingPeriodTimer.C:
			w.logger.Debug(fmt.Sprintf("%s was due at %s, attempting to check it in", serviceAccountName, due))
			w.storageMutex.RLock()
			err := w.child.CheckIn(context.Background(), w.latestStorage, serviceAccountName)
			w.storageMutex.RUnlock()
			if err != nil {
				w.logger.Warn(fmt.Sprintf("couldn't check %s back in due to %s, will try again in a minute", serviceAccountName, err))
				lendingPeriodTimer = time.NewTimer(time.Minute)
				continue
			}
			w.logger.Debug(fmt.Sprintf("successfully checked %s in", serviceAccountName))
			w.stopWatching(serviceAccountName)
			return
		}
	}
}

// stopWatching cancels the goroutine waiting to check items in when they're due
// and cleans everything up.
func (w *OverdueWatcher) stopWatching(serviceAccountName string) {
	w.mapMutex.RLock()
	renewalChan, ok := w.renewalChans[serviceAccountName]
	w.mapMutex.RUnlock()
	if !ok {
		return
	}
	close(renewalChan)
	w.mapMutex.Lock()
	delete(w.renewalChans, serviceAccountName)
	w.mapMutex.Unlock()
}

// NewServiceAccountLocker is the preferable way to instantiate a ServiceAccountLocker
// because it populates the map of locks for you.
func NewServiceAccountLocker(wrapped CheckOutHandler) *ServiceAccountLocker {
	return &ServiceAccountLocker{
		locks:           &sync.Map{},
		CheckOutHandler: wrapped,
	}
}

// ServiceAccountLocker protects against races.
type ServiceAccountLocker struct {
	// This is, in effect, being used as a map[string]*sync.RWMutex
	locks *sync.Map
	CheckOutHandler
}

// CheckOut holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.CheckOutHandler.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

func (l *ServiceAccountLocker) RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.CheckOutHandler.RenewCheckOut(ctx, storage, serviceAccountName, checkOut)
}

// CheckIn holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.CheckOutHandler.CheckIn(ctx, storage, serviceAccountName)
}

// Delete holds a write lock for the duration of the work to be done.
func (l *ServiceAccountLocker) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	lock := l.getOrCreateLock(serviceAccountName)
	lock.Lock()
	defer lock.Unlock()
	return l.CheckOutHandler.Delete(ctx, storage, serviceAccountName)
}

// Status holds a read-only lock for the duration of the work to be done.
func (l *ServiceAccountLocker) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	lock := l.getOrCreateLock(serviceAccountName)
	lock.RLock()
	defer lock.RUnlock()
	return l.CheckOutHandler.Status(ctx, storage, serviceAccountName)
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
	client secretsClient
	CheckOutHandler
}

// CheckOut requires no further action from the password handler other than passing along the request.
func (h *PasswordHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	return h.CheckOutHandler.CheckOut(ctx, storage, serviceAccountName, checkOut)
}

// RenewCheckOut requires no further action from the password handler other than passing along the request.
func (h *PasswordHandler) RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	return h.CheckOutHandler.RenewCheckOut(ctx, storage, serviceAccountName, checkOut)
}

// CheckIn rotates the service account's password remotely and stores it locally.
// If this process fails part-way through:
// 		- An error will be returned.
//		- The account will remain checked out.
//		- The client may (or may not) retry the check-in.
// 		- The overdue watcher will still check it in if its lending period runs out.
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
	return h.CheckOutHandler.CheckIn(ctx, storage, serviceAccountName)
}

// Delete simply deletes the password from storage so it's not stored unnecessarily.
func (h *PasswordHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if err := storage.Delete(ctx, "password/"+serviceAccountName); err != nil {
		return err
	}
	return h.CheckOutHandler.Delete(ctx, storage, serviceAccountName)
}

// Status doesn't need any password work.
func (h *PasswordHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	return h.CheckOutHandler.Status(ctx, storage, serviceAccountName)
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

// RenewCheckOut will return:
//  - Nil if it was successfully able to perform the requested renewal.
//  - ErrNotCurrentlyCheckedOut if the account wasn't already checked out.
//  - Some other err if it was unable to complete successfully.
func (h *StorageHandler) RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	// Check if the service account is currently checked out.
	if entry, err := storage.Get(ctx, checkoutStoragePrefix+serviceAccountName); err != nil {
		return err
	} else if entry == nil {
		return ErrNotCurrentlyCheckedOut
	}
	// Store the new check-out.
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
	return storage.Delete(ctx, checkoutStoragePrefix+serviceAccountName)
}
