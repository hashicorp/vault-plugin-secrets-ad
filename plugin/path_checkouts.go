package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathReserveStatus() *framework.Path {
	return &framework.Path{
		Pattern: libraryPrefix + framework.GenericNameRegex("name") + "/status$",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the reserve",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationReserveStatus,
				Summary:  "Check the status of the service accounts in a library reserve.",
			},
		},
		HelpSynopsis: `Check the status of the service accounts in a library.`,
	}
}

func (b *backend) operationReserveStatus(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	reserveName := fieldData.Get("name").(string)
	reserve, err := readReserve(ctx, req.Storage, reserveName)
	if err != nil {
		return nil, err
	}
	if reserve == nil {
		return logical.ErrorResponse(`"%s" doesn't exist`, reserveName), nil
	}
	respData := make(map[string]interface{})
	for _, serviceAccountName := range reserve.ServiceAccountNames {
		checkOut, err := b.checkOutHandler.Status(ctx, req.Storage, serviceAccountName)
		if err != nil {
			return nil, err
		}
		if checkOut == nil {
			// This should never happen because for every service account, it should have
			// been checked in when it was first created.
			b.Logger().Warn(fmt.Sprintf("%s should have been checked in, but wasn't, checking it in now", serviceAccountName))
			if err := b.checkOutHandler.CheckIn(ctx, req.Storage, serviceAccountName); err != nil {
				return nil, err
			}
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
		status["lending_period"] = int64(checkOut.LendingPeriod.Seconds())
		status["due"] = checkOut.Due.Format(time.RFC3339Nano)
		if checkOut.BorrowerClientToken != "" {
			status["borrower_client_token"] = checkOut.BorrowerClientToken
		} else {
			status["borrower_entity_id"] = checkOut.BorrowerEntityID
		}
		respData[serviceAccountName] = status
	}
	return &logical.Response{
		Data: respData,
	}, nil
}
