package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretAccessKeyType = "creds"

func (b *backend) pathSetCheckOut() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + framework.GenericNameRegex("name") + "/check-out$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the set",
				Required:    true,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The length of time before the check-out will expire, in seconds.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationSetCheckOut,
				Summary:  "Check a service account out from the library.",
			},
		},
		HelpSynopsis: `Check a service account out from the library.`,
	}
}

func (b *backend) operationSetCheckOut(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	ttlPeriodRaw, ttlPeriodSent := fieldData.GetOk("ttl")
	if !ttlPeriodSent {
		ttlPeriodRaw = 0
	}
	requestedTTL := time.Duration(ttlPeriodRaw.(int)) * time.Second

	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, setName), nil
	}

	// Prepare the check-out we'd like to execute.
	ttl := set.TTL
	if ttlPeriodSent {
		switch {
		case set.TTL <= 0 && requestedTTL > 0:
			// The set's TTL is infinite and the caller requested a finite TTL.
			ttl = requestedTTL
		case set.TTL > 0 && requestedTTL < set.TTL:
			// The set's TTL isn't infinite and the caller requested a shorter TTL.
			ttl = requestedTTL
		}
	}
	newCheckOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    req.EntityID,
		BorrowerClientToken: req.ClientToken,
	}

	// Check out the first service account available.
	for _, serviceAccountName := range set.ServiceAccountNames {
		password, err := b.checkOut(ctx, req.Storage, serviceAccountName, newCheckOut)
		if err == ErrCheckedOut {
			continue
		}
		if err != nil {
			return nil, err
		}
		respData := map[string]interface{}{
			"service_account_name": serviceAccountName,
			"password":             password,
		}
		internalData := map[string]interface{}{
			"service_account_name": serviceAccountName,
		}
		resp := b.Backend.Secret(secretAccessKeyType).Response(respData, internalData)
		resp.Secret.Renewable = true
		resp.Secret.TTL = ttl
		resp.Secret.MaxTTL = set.MaxTTL
		return resp, nil
	}

	// If we arrived here, it's because we never had a hit for a service account that was available.
	return logical.RespondWithStatusCode(&logical.Response{
		Warnings: []string{"No service accounts available for check-out."},
	}, req, 429)
}

func (b *backend) checkOut(ctx context.Context, storage logical.Storage, serviceAccountName string, newCheckOut *CheckOut) (string, error) {
	lock := locksutil.LockForKey(b.checkOutLocks, serviceAccountName)
	lock.Lock()
	defer lock.Unlock()

	if err := b.checkOutHandler.CheckOut(ctx, storage, serviceAccountName, newCheckOut); err != nil {
		return "", err
	}
	password, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		return "", err
	}
	return password, nil
}

func (b *backend) secretAccessKeys() *framework.Secret {
	return &framework.Secret{
		Type: secretAccessKeyType,
		Fields: map[string]*framework.FieldSchema{
			"service_account_name": {
				Type:        framework.TypeString,
				Description: "Service account name",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password",
			},
		},
		Renew:  b.renewCheckOut,
		Revoke: b.endCheckOut,
	}
}

func (b *backend) renewCheckOut(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	serviceAccountName := req.Secret.InternalData["service_account_name"].(string)

	lock := locksutil.LockForKey(b.checkOutLocks, serviceAccountName)
	lock.Lock()
	defer lock.Unlock()

	checkOut, err := b.checkOutHandler.Status(ctx, req.Storage, serviceAccountName)
	if err != nil {
		return nil, err
	}
	if checkOut.IsAvailable {
		// It's possible that this renewal could be attempted after a check-in occurred either by this entity or by
		// another user with access to the "manage check-ins" endpoint that forcibly checked it back in.
		return logical.ErrorResponse(fmt.Sprintf("%s is already checked in, please call check-out to regain it", serviceAccountName)), nil
	}
	return &logical.Response{Secret: req.Secret}, nil
}

func (b *backend) endCheckOut(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	serviceAccountName := req.Secret.InternalData["service_account_name"].(string)

	lock := locksutil.LockForKey(b.checkOutLocks, serviceAccountName)
	lock.Lock()
	defer lock.Unlock()

	if err := b.checkOutHandler.CheckIn(ctx, req.Storage, serviceAccountName); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathSetCheckIn() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + framework.GenericNameRegex("name") + "/check-in$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the set.",
				Required:    true,
			},
			"service_account_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The username/logon name for the service accounts to check in.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationCheckIn(false),
				Summary:  "Check service accounts in to the library.",
			},
		},
		HelpSynopsis: `Check service accounts in to the library.`,
	}
}

func (b *backend) pathSetManageCheckIn() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + "manage/" + framework.GenericNameRegex("name") + "/check-in$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the set.",
				Required:    true,
			},
			"service_account_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The username/logon name for the service accounts to check in.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationCheckIn(true),
				Summary:  "Check service accounts in to the library.",
			},
		},
		HelpSynopsis: `Force checking service accounts in to the library.`,
	}
}

func (b *backend) operationCheckIn(overrideCheckInEnforcement bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
		setName := fieldData.Get("name").(string)

		serviceAccountNamesRaw, serviceAccountNamesSent := fieldData.GetOk("service_account_names")
		var serviceAccountNames []string
		if serviceAccountNamesSent {
			serviceAccountNames = serviceAccountNamesRaw.([]string)
		}

		set, err := readSet(ctx, req.Storage, setName)
		if err != nil {
			return nil, err
		}
		if set == nil {
			return logical.ErrorResponse(`"%s" doesn't exist`, setName), nil
		}

		// If check-in enforcement is overridden or disabled at the set level, we should consider it disabled.
		disableCheckInEnforcement := overrideCheckInEnforcement || set.DisableCheckInEnforcement

		// Track the service accounts we check in so we can include it in our response.
		var checkIns []string

		// Build and validate a list of service account names that we will be checking in.
		var cantCheckInErrs error
		if len(serviceAccountNames) == 0 {
			// It's okay if the caller doesn't tell us which service accounts they
			// want to check in as long as they only have one checked out.
			// We'll assume that's the one they want to check in.
			toCheckIn := make(map[string]*locksutil.LockEntry)
			for _, setServiceAccount := range set.ServiceAccountNames {
				// This is called in a func to avoid calling defer in a loop.
				if err := func() error {
					lock := locksutil.LockForKey(b.checkOutLocks, setServiceAccount)
					lock.Lock()
					releaseLock := true
					defer func() {
						if releaseLock {
							lock.Unlock()
						}
					}()

					checkOut, err := b.checkOutHandler.Status(ctx, req.Storage, setServiceAccount)
					if err != nil {
						return err
					}
					if checkOut.IsAvailable {
						return nil
					}
					if !disableCheckInEnforcement && !checkinAuthorized(req, checkOut) {
						return nil
					}
					releaseLock = false
					toCheckIn[setServiceAccount] = lock
					return nil
				}(); err != nil {
					return nil, err
				}
			}
			defer func() {
				for _, lock := range toCheckIn {
					lock.Unlock()
				}
			}()
			switch len(toCheckIn) {
			case 0:
				// Everything's already currently checked in, nothing else to do here.
			case 1:
				// This is what we need to continue with the check-in process.
				for serviceAccountName, _ := range toCheckIn {
					if err := b.checkOutHandler.CheckIn(ctx, req.Storage, serviceAccountName); err != nil {
						return nil, err
					}
					checkIns = append(checkIns, serviceAccountName)
				}
			default:
				return logical.ErrorResponse(`when multiple service accounts are checked out, the "service_account_names" to check in must be provided`), nil
			}
		} else {
			for _, serviceAccountName := range serviceAccountNames {
				// This is in a func to resolve the problem of calling defer in a loop.
				if err := func() error {
					lock := locksutil.LockForKey(b.checkOutLocks, serviceAccountName)
					lock.Lock()
					defer lock.Unlock()

					checkOut, err := b.checkOutHandler.Status(ctx, req.Storage, serviceAccountName)
					if err != nil {
						return err
					}
					if checkOut.IsAvailable {
						// Nothing further to do here.
						return nil
					}
					if !disableCheckInEnforcement && !checkinAuthorized(req, checkOut) {
						cantCheckInErrs = multierror.Append(cantCheckInErrs, fmt.Errorf(`"%s" can't be checked in because it wasn't checked out by the caller`, serviceAccountName))
						// This isn't a stop-the-show error.
						return nil
					}
					if err := b.checkOutHandler.CheckIn(ctx, req.Storage, serviceAccountName); err != nil {
						return err
					}
					checkIns = append(checkIns, serviceAccountName)
					return nil
				}(); err != nil {
					return nil, err
				}
			}
		}
		if cantCheckInErrs != nil {
			// Let's return a 400 so the caller doesn't assume everything is OK. Their requested
			// work is only partially done.
			return logical.ErrorResponse(cantCheckInErrs.Error()), nil
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"check_ins": checkIns,
			},
		}, nil
	}
}

func (b *backend) pathSetStatus() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + framework.GenericNameRegex("name") + "/status$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the set.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationSetStatus,
				Summary:  "Check the status of the service accounts in a library set.",
			},
		},
		HelpSynopsis: `Check the status of the service accounts in a library.`,
	}
}

func (b *backend) operationSetStatus(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, setName), nil
	}
	respData := make(map[string]interface{})

	// We don't worry about grabbing read locks for these because we expect this
	// call to be rare and initiates by humans, and it's okay if it's not perfectly
	// consistent since it's not performing any changes.
	for _, serviceAccountName := range set.ServiceAccountNames {
		checkOut, err := b.checkOutHandler.Status(ctx, req.Storage, serviceAccountName)
		if err != nil {
			return nil, err
		}

		status := map[string]interface{}{
			"available": checkOut.IsAvailable,
		}
		if checkOut.IsAvailable {
			// We only omit all other fields if the checkout is currently available,
			// because they're only relevant to accounts that aren't checked out.
			respData[serviceAccountName] = status
			continue
		}
		if checkOut.BorrowerClientToken != "" {
			status["borrower_client_token"] = checkOut.BorrowerClientToken
		}
		if checkOut.BorrowerEntityID != "" {
			status["borrower_entity_id"] = checkOut.BorrowerEntityID
		}
		respData[serviceAccountName] = status
	}
	return &logical.Response{
		Data: respData,
	}, nil
}

func checkinAuthorized(req *logical.Request, checkOut *CheckOut) bool {
	if checkOut.BorrowerEntityID != "" && req.EntityID != "" {
		if checkOut.BorrowerEntityID == req.EntityID {
			return true
		}
	}
	if checkOut.BorrowerClientToken != "" && req.ClientToken != "" {
		if checkOut.BorrowerClientToken == req.ClientToken {
			return true
		}
	}
	return false
}
