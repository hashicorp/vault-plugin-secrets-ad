package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const libraryPrefix = "library/"

type librarySet struct {
	ServiceAccountNames       []string      `json:"service_account_names"`
	TTL                       time.Duration `json:"ttl"`
	MaxTTL                    time.Duration `json:"max_ttl"`
	DisableCheckInEnforcement bool          `json:"disable_check_in_enforcement"`
}

// Validates ensures that a set meets our code assumptions that TTLs are set in
// a way that makes sense, and that there's at least one service account.
func (l *librarySet) Validate() error {
	if len(l.ServiceAccountNames) < 1 {
		return fmt.Errorf(`at least one service account must be configured`)
	}
	if l.MaxTTL > 0 {
		if l.MaxTTL < l.TTL {
			return fmt.Errorf(`max_ttl (%d seconds) may not be less than ttl (%d seconds)`, l.MaxTTL, l.TTL)
		}
	}
	return nil
}

func (b *backend) pathListSets() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + "?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.setListOperation,
			},
		},
		HelpSynopsis:    pathListSetsHelpSyn,
		HelpDescription: pathListSetsHelpDesc,
	}
}

func (b *backend) setListOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, libraryPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (b *backend) pathSets() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the set.",
				Required:    true,
			},
			"service_account_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The username/logon name for the service accounts with which this set will be associated.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "In seconds, the amount of time a check-out should last. Defaults to 24 hours.",
				Default:     24 * 60 * 60, // 24 hours
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "In seconds, the max amount of time a check-out's renewals should last. Defaults to 24 hours.",
				Default:     24 * 60 * 60, // 24 hours
			},
			"disable_check_in_enforcement": {
				Type:        framework.TypeBool,
				Description: "Disable the default behavior of requiring that check-ins are performed by the entity that checked them out.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.operationSetCreate,
				Summary:  "Create a library set.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.operationSetUpdate,
				Summary:  "Update a library set.",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationSetRead,
				Summary:  "Read a library set.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationSetDelete,
				Summary:  "Delete a library set.",
			},
		},
		ExistenceCheck:  b.operationSetExistenceCheck,
		HelpSynopsis:    setHelpSynopsis,
		HelpDescription: setHelpDescription,
	}
}

func (b *backend) operationSetExistenceCheck(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (bool, error) {
	set, err := readSet(ctx, req.Storage, fieldData.Get("name").(string))
	if err != nil {
		return false, err
	}
	return set != nil, nil
}

func (b *backend) operationSetCreate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	serviceAccountNames := fieldData.Get("service_account_names").([]string)
	ttl := time.Duration(fieldData.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(fieldData.Get("max_ttl").(int)) * time.Second
	disableCheckInEnforcement := fieldData.Get("disable_check_in_enforcement").(bool)

	if len(serviceAccountNames) == 0 {
		return logical.ErrorResponse(`"service_account_names" must be provided`), nil
	}
	// Ensure these service accounts aren't already managed by another check-out set.
	var userErrs error
	var resultingServiceAccountNames []string
	for _, serviceAccountName := range serviceAccountNames {
		if isUserErr, err := b.checkInNewServiceAccount(ctx, req.Storage, serviceAccountName); err != nil {
			if isUserErr {
				userErrs = multierror.Append(userErrs, err)
				continue
			}
			return nil, err
		}
		resultingServiceAccountNames = append(resultingServiceAccountNames, serviceAccountName)
	}

	set := &librarySet{
		ServiceAccountNames:       resultingServiceAccountNames,
		TTL:                       ttl,
		MaxTTL:                    maxTTL,
		DisableCheckInEnforcement: disableCheckInEnforcement,
	}
	if err := set.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := storeSet(ctx, req.Storage, setName, set); err != nil {
		return nil, err
	}
	if userErrs != nil {
		// Let's return 400 here because we need to flag the user's attention
		// that we didn't complete every requested action.
		return logical.ErrorResponse(userErrs.Error()), nil
	}
	return nil, nil
}

func (b *backend) operationSetUpdate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	newServiceAccountNamesRaw, newServiceAccountNamesSent := fieldData.GetOk("service_account_names")
	var newServiceAccountNames []string
	if newServiceAccountNamesSent {
		newServiceAccountNames = newServiceAccountNamesRaw.([]string)
	}

	ttlRaw, ttlSent := fieldData.GetOk("ttl")
	if !ttlSent {
		ttlRaw = fieldData.Schema["ttl"].Default
	}
	ttl := time.Duration(ttlRaw.(int)) * time.Second

	maxTTLRaw, maxTTLSent := fieldData.GetOk("max_ttl")
	if !maxTTLSent {
		maxTTLRaw = fieldData.Schema["max_ttl"].Default
	}
	maxTTL := time.Duration(maxTTLRaw.(int)) * time.Second

	disableCheckInEnforcementRaw, enforcementSent := fieldData.GetOk("disable_check_in_enforcement")
	if !enforcementSent {
		disableCheckInEnforcementRaw = false
	}
	disableCheckInEnforcement := disableCheckInEnforcementRaw.(bool)

	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, setName), nil
	}

	var userErrs error
	if newServiceAccountNamesSent {

		// For new service accounts we receive, we need to check them in so it'll be evident they're being
		// managed by this set.
		beingAdded := strutil.Difference(newServiceAccountNames, set.ServiceAccountNames, true)
		for _, newServiceAccountName := range beingAdded {
			if isUserErr, err := b.checkInNewServiceAccount(ctx, req.Storage, newServiceAccountName); err != nil {
				if isUserErr {
					// The user added this because they wanted this service account to be managed by this set,
					// but we're unable to do that so we need to remove it from the set of ones managed here.
					newServiceAccountNames = strutil.StrListDelete(newServiceAccountNames, newServiceAccountName)
					userErrs = multierror.Append(userErrs, err)
					continue
				}
				return nil, err
			}
		}

		// For service accounts we won't be handling anymore, we need to remove their passwords and delete them
		// from storage.
		beingDeleted := strutil.Difference(set.ServiceAccountNames, newServiceAccountNames, true)
		for _, prevServiceAccountName := range beingDeleted {
			if isUserErr, err := b.deleteSetServiceAccount(ctx, req.Storage, prevServiceAccountName); err != nil {
				if isUserErr {
					// The user left this out because they were trying to delete it from being managed here,
					// but we're unable to delete it so we need to keep it in this set.
					newServiceAccountNames = append(newServiceAccountNames, prevServiceAccountName)
					userErrs = multierror.Append(userErrs, err)
					continue
				}
				return nil, err
			}
		}

		set.ServiceAccountNames = newServiceAccountNames
	}
	if ttlSent {
		set.TTL = ttl
	}
	if maxTTLSent {
		set.MaxTTL = maxTTL
	}
	if enforcementSent {
		set.DisableCheckInEnforcement = disableCheckInEnforcement
	}
	if err := set.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := storeSet(ctx, req.Storage, setName, set); err != nil {
		return nil, err
	}
	if userErrs != nil {
		return logical.ErrorResponse(userErrs.Error()), nil
	}
	return nil, nil
}

func (b *backend) operationSetRead(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.RLock()
	defer lock.RUnlock()

	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"service_account_names":        set.ServiceAccountNames,
			"ttl":                          int64(set.TTL.Seconds()),
			"max_ttl":                      int64(set.MaxTTL.Seconds()),
			"disable_check_in_enforcement": set.DisableCheckInEnforcement,
		},
	}, nil
}

func (b *backend) operationSetDelete(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, nil
	}
	// We need to remove all the items we'd stored for these service accounts.
	var deletionErrs error
	for _, serviceAccountName := range set.ServiceAccountNames {
		if isUserErr, err := b.deleteSetServiceAccount(ctx, req.Storage, serviceAccountName); err != nil {
			if isUserErr {
				deletionErrs = multierror.Append(deletionErrs, err)
				continue
			}
			return nil, err
		}
	}
	if deletionErrs != nil {
		// We can't complete this deletion because we can't delete all the service accounts.
		return logical.ErrorResponse(deletionErrs.Error()), nil
	}
	if err := req.Storage.Delete(ctx, libraryPrefix+setName); err != nil {
		return nil, err
	}
	return nil, nil
}

// readSet is a helper method for reading a set from storage by name.
// It's intended to be used anywhere in the plugin. It may return nil, nil if
// a librarySet doesn't currently exist for a given setName.
func readSet(ctx context.Context, storage logical.Storage, setName string) (*librarySet, error) {
	entry, err := storage.Get(ctx, libraryPrefix+setName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	set := &librarySet{}
	if err := entry.DecodeJSON(set); err != nil {
		return nil, err
	}
	return set, nil
}

// storeSet stores a librarySet.
func storeSet(ctx context.Context, storage logical.Storage, setName string, set *librarySet) error {
	entry, err := logical.StorageEntryJSON(libraryPrefix+setName, set)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (b *backend) checkInNewServiceAccount(ctx context.Context, storage logical.Storage, serviceAccountName string) (isUserErr bool, err error) {
	_, err = b.checkOutHandler.Status(ctx, storage, serviceAccountName)
	if err == nil {
		// We actually want to receive ErrNotFound here because that would indicate
		// we're not already managing the potential to check this service account out
		// through another set.
		return true, fmt.Errorf("%s is already managed by another set, please remove it and try again", serviceAccountName)
	}
	if err != ErrNotFound {
		return false, err
	}

	// All is well.
	// Check in the service account so it'll be listed as managed by this
	// plugin and available.
	if err := b.checkOutHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		return false, err
	}
	// Success.
	return false, nil
}

// deleteSetServiceAccount errors if an account can't presently be deleted, or deletes it.
func (b *backend) deleteSetServiceAccount(ctx context.Context, storage logical.Storage, serviceAccountName string) (isUserErr bool, err error) {
	checkOut, err := b.checkOutHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		if err == ErrNotFound {
			// Nothing else to do here.
			return false, nil
		}
		return false, err
	}
	if !checkOut.IsAvailable {
		return true, fmt.Errorf(`"%s" can't be deleted because it is currently checked out'`, serviceAccountName)
	}
	if err := b.checkOutHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		return false, err
	}
	return false, nil
}

const (
	setHelpSynopsis = `
Manage sets to build a library of service accounts that can be checked out.
`
	setHelpDescription = `
This endpoint allows you to read, write, and delete individual sets that are used for checking out service accounts.

Deleting a set can only be performed if all of its service accounts are currently checked in.
`
	pathListSetsHelpSyn = `
List the name of each set currently stored.
`
	pathListSetsHelpDesc = `
To learn which service accounts are being managed by Vault, list the set names using
this endpoint. Then read any individual set by name to learn more.
`
)
