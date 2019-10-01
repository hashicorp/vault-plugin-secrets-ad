package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// TODO need to address raciness, this is planned for a subsequent PR when the CheckOutHandler model is finalized.
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

func (b *backend) pathListReserves() *framework.Path {
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

func (b *backend) pathReserves() *framework.Path {
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
				Callback: b.operationReserveCreate,
				Summary:  "Create a library set.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.operationReserveUpdate,
				Summary:  "Update a library set.",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationReserveRead,
				Summary:  "Read a library set.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationReserveDelete,
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

func (b *backend) operationReserveCreate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)
	serviceAccountNames := fieldData.Get("service_account_names").([]string)
	ttl := time.Duration(fieldData.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(fieldData.Get("max_ttl").(int)) * time.Second
	disableCheckInEnforcement := fieldData.Get("disable_check_in_enforcement").(bool)

	if len(serviceAccountNames) == 0 {
		return logical.ErrorResponse(`"service_account_names" must be provided`), nil
	}
	// Ensure these service accounts aren't already managed by another check-out set.
	var alreadyManagedErr error
	for _, serviceAccountName := range serviceAccountNames {
		if _, err := b.checkOutHandler.Status(ctx, req.Storage, serviceAccountName); err != nil {
			if err == ErrNotFound {
				// This is what we want to see.
				continue
			}
			// There is a more persistent error reaching storage.
			return nil, err
		}
		// If we reach here, the error is nil. That means there's an existing CheckOut for this
		// service account.
		alreadyManagedErr = multierror.Append(alreadyManagedErr, fmt.Errorf("%s is already managed by another set, please remove it and try again", serviceAccountName))
	}
	if alreadyManagedErr != nil {
		return logical.ErrorResponse(alreadyManagedErr.Error()), nil
	}

	// Now we need to check in all these service accounts so they'll be listed as managed by this
	// plugin and available.
	for _, serviceAccountName := range serviceAccountNames {
		if err := b.checkOutHandler.CheckIn(ctx, req.Storage, serviceAccountName); err != nil {
			return nil, err
		}
	}

	set := &librarySet{
		ServiceAccountNames:       serviceAccountNames,
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
	return nil, nil
}

func (b *backend) operationReserveUpdate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

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
	if newServiceAccountNamesSent {
		beingAdded := strutil.Difference(newServiceAccountNames, set.ServiceAccountNames, true)

		// For new service accounts, we need to make sure they're not already handled by another set.
		var alreadyManagedErr error
		for _, newServiceAccountName := range beingAdded {
			if _, err := b.checkOutHandler.Status(ctx, req.Storage, newServiceAccountName); err != nil {
				if err == ErrNotFound {
					// This is what we want to see.
					continue
				}
				// There is a more persistent error reaching storage.
				return nil, err
			}
			// If we reach here, the error is nil. That means there's an existing CheckOut for this
			// service account.
			alreadyManagedErr = multierror.Append(alreadyManagedErr, fmt.Errorf("%s is already managed by another set, please remove it and try again", newServiceAccountName))
		}
		if alreadyManagedErr != nil {
			return logical.ErrorResponse(alreadyManagedErr.Error()), nil
		}

		// Now we need to check in all these service accounts so they'll be listed as managed by this
		// plugin and available.
		for _, newServiceAccountName := range beingAdded {
			if err := b.checkOutHandler.CheckIn(ctx, req.Storage, newServiceAccountName); err != nil {
				return nil, err
			}
		}

		// For service accounts we won't be handling anymore, we need to remove their passwords and delete them
		// from storage.
		beingDeleted := strutil.Difference(set.ServiceAccountNames, newServiceAccountNames, true)
		var deletionErrs error
		for _, prevServiceAccountName := range beingDeleted {
			if err := b.deleteSetServiceAccount(ctx, req.Storage, prevServiceAccountName); err != nil {
				deletionErrs = multierror.Append(deletionErrs, err)
			}
		}
		if deletionErrs != nil {
			return nil, deletionErrs
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
	return nil, nil
}

func (b *backend) operationReserveRead(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)
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

func (b *backend) operationReserveDelete(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)
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
		if err := b.deleteSetServiceAccount(ctx, req.Storage, serviceAccountName); err != nil {
			deletionErrs = multierror.Append(deletionErrs, err)
		}
	}
	if deletionErrs != nil {
		return nil, deletionErrs
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

// deleteSetServiceAccount errors if an account can't presently be deleted, or deletes it.
func (b *backend) deleteSetServiceAccount(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	checkOut, err := b.checkOutHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		if err == ErrNotFound {
			// Nothing else to do here.
			return nil
		}
		return err
	}
	if !checkOut.IsAvailable {
		return fmt.Errorf(`"%s" can't be deleted because it is currently checked out'`, serviceAccountName)
	}
	if err := b.checkOutHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		return err
	}
	return nil
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
