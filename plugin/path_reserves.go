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

const libraryPrefix = "library/"

type libraryReserve struct {
	ServiceAccountNames []string      `json:"service_account_names"`
	LendingPeriod       time.Duration `json:"lending_period"`
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
			"lending_period": {
				Type:        framework.TypeDurationSecond,
				Description: "In seconds, the default length of time before check-outs will expire.",
				Default:     24 * 60 * 60, // 24 hours
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
	lendingPeriodRaw, lendingPeriodSent := fieldData.GetOk("lending_period")
	if !lendingPeriodSent {
		lendingPeriodRaw = fieldData.Schema["lending_period"].Default
	}
	lendingPeriod := time.Duration(lendingPeriodRaw.(int)) * time.Second

	if len(serviceAccountNames) == 0 {
		return logical.ErrorResponse(`"service_account_names" must be provided`), nil
	}
	if err := ensureNotInAnotherReserve(ctx, req.Storage, serviceAccountNames); err != nil {
		return nil, err
	}
	reserve := &libraryReserve{
		ServiceAccountNames: serviceAccountNames,
		LendingPeriod:       lendingPeriod,
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

	lendingPeriodRaw, lendingPeriodSent := fieldData.GetOk("lending_period")
	if !lendingPeriodSent {
		lendingPeriodRaw = fieldData.Schema["lending_period"].Default
	}
	lendingPeriod := time.Duration(lendingPeriodRaw.(int)) * time.Second

	reserve, err := readReserve(ctx, req.Storage, reserveName)
	if err != nil {
		return nil, err
	}
	if reserve == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, reserveName), nil
	}
	if newServiceAccountNamesSent {
		// For new service accounts, we need to make sure they're not already handled by another reserve.
		var beingAdded []string
		for _, newServiceAccountName := range newServiceAccountNames {
			if strutil.StrListContains(reserve.ServiceAccountNames, newServiceAccountName) {
				// It's not new.
				continue
			}
			beingAdded = append(beingAdded, newServiceAccountName)
		}
		if len(beingAdded) > 0 {
			if err := ensureNotInAnotherReserve(ctx, req.Storage, beingAdded); err != nil {
				return nil, err
			}
		}
		// For service accounts we won't be handling anymore, we need to remove their passwords
		// from storage.
		var deletionErrs error
		for _, prevServiceAccountName := range reserve.ServiceAccountNames {
			if strutil.StrListContains(newServiceAccountNames, prevServiceAccountName) {
				// This previous account isn't being deleted.
				continue
			}
			if err := b.deleteReserveServiceAccount(ctx, req.Storage, prevServiceAccountName); err != nil {
				deletionErrs = multierror.Append(deletionErrs, err)
			}
		}
		if deletionErrs != nil {
			return nil, deletionErrs
		}
		reserve.ServiceAccountNames = newServiceAccountNames
	}
	if lendingPeriodSent {
		reserve.LendingPeriod = lendingPeriod
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
			"service_account_names": reserve.ServiceAccountNames,
			"lending_period":        int64(reserve.LendingPeriod.Seconds()),
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
	// We need to remove all the passwords we'd stored for these service accounts.
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

// storeReserve is only intended to be used inside path_reserves.go, because this is the only place
// that is intended to be editing reserves.
func storeReserve(ctx context.Context, storage logical.Storage, reserveName string, reserve *libraryReserve) error {
	entry, err := logical.StorageEntryJSON(libraryPrefix+reserveName, reserve)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// ensureNotInAnotherReserve is a helper method for checking that new service accounts aren't already being
// managed by another reserve. This is because we would experience a lot of unexpected behavior if the same
// service account were being checked in (with its password rolled) at different times through another
// reserve, and it could be difficult to debug because it'd be happening outside the times we'd be looking
// at in the logs.
func ensureNotInAnotherReserve(ctx context.Context, storage logical.Storage, newServiceAccountNames []string) error {
	// Gather up all the service accounts currently being managed.
	preExistingReserveNames, err := storage.List(ctx, libraryPrefix)
	if err != nil {
		return err
	}
	preExistingServiceAccountNames := make(map[string]bool)
	for _, preExistingReserveName := range preExistingReserveNames {
		preExistingReserve, err := readReserve(ctx, storage, preExistingReserveName)
		if err != nil {
			return err
		}
		for _, preExistingServiceAccountName := range preExistingReserve.ServiceAccountNames {
			preExistingServiceAccountNames[preExistingServiceAccountName] = true
		}
	}

	// Check through the new ones to make sure they're not already in another reserve.
	var preExistenceErrs error
	for _, newServiceAccountName := range newServiceAccountNames {
		if _, exists := preExistingServiceAccountNames[newServiceAccountName]; exists {
			preExistenceErrs = multierror.Append(preExistenceErrs, fmt.Errorf(`can't append %s because it's already managed by another reserve`, newServiceAccountName))
		}
	}
	return preExistenceErrs
}

// deleteReserveServiceAccount errors if an account can't presently be deleted, or deletes it.
func (b *backend) deleteReserveServiceAccount(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	if checkOut, err := b.checkOutHandler.Status(ctx, storage, serviceAccountName); err != nil {
		return err
	} else if checkOut != nil {
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
