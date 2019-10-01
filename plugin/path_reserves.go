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

type libraryReserve struct {
	ServiceAccountNames       []string      `json:"service_account_names"`
	TTL                       time.Duration `json:"ttl"`
	MaxTTL                    time.Duration `json:"max_ttl"`
	DisableCheckInEnforcement bool          `json:"disable_check_in_enforcement"`
}

func (b *backend) pathListReserves() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + "?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.reserveListOperation,
			},
		},
		HelpSynopsis:    pathListReservesHelpSyn,
		HelpDescription: pathListReservesHelpDesc,
	}
}

func (b *backend) reserveListOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
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
				Description: "Name of the reserve",
				Required:    true,
			},
			"service_account_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The username/logon name for the service accounts with which this reserve will be associated.",
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
				Summary:  "Create a library reserve.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.operationReserveUpdate,
				Summary:  "Update a library reserve.",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationReserveRead,
				Summary:  "Read a library reserve.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationReserveDelete,
				Summary:  "Delete a library reserve.",
			},
		},
		ExistenceCheck:  b.operationReserveExistenceCheck,
		HelpSynopsis:    reserveHelpSynopsis,
		HelpDescription: reserveHelpDescription,
	}
}

func (b *backend) operationReserveExistenceCheck(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (bool, error) {
	reserve, err := readReserve(ctx, req.Storage, fieldData.Get("name").(string))
	if err != nil {
		return false, err
	}
	return reserve != nil, nil
}

func (b *backend) operationReserveCreate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	reserveName := fieldData.Get("name").(string)
	serviceAccountNames := fieldData.Get("service_account_names").([]string)
	ttl := time.Duration(fieldData.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(fieldData.Get("max_ttl").(int)) * time.Second
	disableCheckInEnforcement := fieldData.Get("disable_check_in_enforcement").(bool)

	if len(serviceAccountNames) == 0 {
		return logical.ErrorResponse(`"service_account_names" must be provided`), nil
	}
	// Ensure these service accounts aren't already managed by another reserve.
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
		alreadyManagedErr = multierror.Append(alreadyManagedErr, fmt.Errorf("%s is already managed by another reserve, please remove it and try again", serviceAccountName))
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

	reserve := &libraryReserve{
		ServiceAccountNames:       serviceAccountNames,
		TTL:                       ttl,
		MaxTTL:                    maxTTL,
		DisableCheckInEnforcement: disableCheckInEnforcement,
	}
	if err := storeReserve(ctx, req.Storage, reserveName, reserve); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) operationReserveUpdate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	reserveName := fieldData.Get("name").(string)

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

	reserve, err := readReserve(ctx, req.Storage, reserveName)
	if err != nil {
		return nil, err
	}
	if reserve == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, reserveName), nil
	}
	if newServiceAccountNamesSent {
		beingAdded := strutil.Difference(newServiceAccountNames, reserve.ServiceAccountNames, true)

		// For new service accounts, we need to make sure they're not already handled by another reserve.
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
			alreadyManagedErr = multierror.Append(alreadyManagedErr, fmt.Errorf("%s is already managed by another reserve, please remove it and try again", newServiceAccountName))
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
		beingDeleted := strutil.Difference(reserve.ServiceAccountNames, newServiceAccountNames, true)
		var deletionErrs error
		for _, prevServiceAccountName := range beingDeleted {
			if err := b.deleteReserveServiceAccount(ctx, req.Storage, prevServiceAccountName); err != nil {
				deletionErrs = multierror.Append(deletionErrs, err)
			}
		}
		if deletionErrs != nil {
			return nil, deletionErrs
		}
		reserve.ServiceAccountNames = newServiceAccountNames
	}
	if ttlSent {
		reserve.TTL = ttl
	}
	if maxTTLSent {
		reserve.MaxTTL = maxTTL
	}
	if enforcementSent {
		reserve.DisableCheckInEnforcement = disableCheckInEnforcement
	}
	if err := storeReserve(ctx, req.Storage, reserveName, reserve); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) operationReserveRead(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	reserveName := fieldData.Get("name").(string)
	reserve, err := readReserve(ctx, req.Storage, reserveName)
	if err != nil {
		return nil, err
	}
	if reserve == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"service_account_names":        reserve.ServiceAccountNames,
			"ttl":                          int64(reserve.TTL.Seconds()),
			"max_ttl":                      int64(reserve.MaxTTL.Seconds()),
			"disable_check_in_enforcement": reserve.DisableCheckInEnforcement,
		},
	}, nil
}

func (b *backend) operationReserveDelete(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	reserveName := fieldData.Get("name").(string)
	reserve, err := readReserve(ctx, req.Storage, reserveName)
	if err != nil {
		return nil, err
	}
	if reserve == nil {
		return nil, nil
	}
	// We need to remove all the items we'd stored for these service accounts.
	var deletionErrs error
	for _, serviceAccountName := range reserve.ServiceAccountNames {
		if err := b.deleteReserveServiceAccount(ctx, req.Storage, serviceAccountName); err != nil {
			deletionErrs = multierror.Append(deletionErrs, err)
		}
	}
	if deletionErrs != nil {
		return nil, deletionErrs
	}
	if err := req.Storage.Delete(ctx, libraryPrefix+reserveName); err != nil {
		return nil, err
	}
	return nil, nil
}

// readReserve is a helper method for reading a reserve from storage by name.
// It's intended to be used anywhere in the plugin. It may return nil, nil if
// a libraryReserve doesn't currently exist for a given reserveName.
func readReserve(ctx context.Context, storage logical.Storage, reserveName string) (*libraryReserve, error) {
	entry, err := storage.Get(ctx, libraryPrefix+reserveName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	reserve := &libraryReserve{}
	if err := entry.DecodeJSON(reserve); err != nil {
		return nil, err
	}
	return reserve, nil
}

// storeReserve stores a library reserve.
func storeReserve(ctx context.Context, storage logical.Storage, reserveName string, reserve *libraryReserve) error {
	entry, err := logical.StorageEntryJSON(libraryPrefix+reserveName, reserve)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// deleteReserveServiceAccount errors if an account can't presently be deleted, or deletes it.
func (b *backend) deleteReserveServiceAccount(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	checkOut, err := b.checkOutHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		return err
	}
	if checkOut == nil {
		// Nothing further to do here.
		return nil
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
	reserveHelpSynopsis = `
Manage reserves to build a library of service accounts that can be checked out.
`
	reserveHelpDescription = `
This endpoint allows you to read, write, and delete individual reserves that are used for checking out service accounts.

Deleting a reserve can only be performed if all of its service accounts are currently checked in.
`
	pathListReservesHelpSyn = `
List the name of each reserve currently stored.
`
	pathListReservesHelpDesc = `
To learn which service accounts are being managed by Vault, list the reserve names using
this endpoint. Then read any individual reserve by name to learn more.
`
)
